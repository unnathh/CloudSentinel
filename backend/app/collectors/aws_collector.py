import boto3
from botocore.exceptions import ClientError
import logging
from typing import Dict, Any, List

logger = logging.getLogger("cloudsentinel.collector")

class AWSCollector:
    def __init__(self, access_key_id: str = None, secret_access_key: str = None, role_arn: str = None, default_region: str = "us-east-1"):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.role_arn = role_arn
        self.default_region = default_region
        self._session = None

    def get_session(self) -> boto3.Session:
        if self._session:
            return self._session

        if self.role_arn:
            # Assume role using base credentials (e.g. EC2 instance profile or specific credentials)
            sts_client = boto3.client(
                "sts",
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.default_region
            )
            try:
                assumed_role = sts_client.assume_role(
                    RoleArn=self.role_arn,
                    RoleSessionName="CloudSentinelScanSession"
                )
                credentials = assumed_role["Credentials"]
                self._session = boto3.Session(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                    region_name=self.default_region
                )
            except Exception as e:
                logger.error(f"Failed to assume role {self.role_arn}: {e}")
                raise e
        elif self.access_key_id and self.secret_access_key:
            self._session = boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.default_region
            )
        else:
            # Fallback to local default profile (useful for local development on AWS-authenticated shells)
            self._session = boto3.Session(region_name=self.default_region)
        return self._session

    def validate_connection(self) -> Dict[str, Any]:
        try:
            session = self.get_session()
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return {
                "success": True,
                "account_id": identity["Account"],
                "arn": identity["Arn"],
                "user_id": identity["UserId"]
            }
        except Exception as e:
            logger.error(f"Connection validation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def collect_all(self) -> Dict[str, Any]:
        """Collects configuration across all supported AWS services."""
        session = self.get_session()
        data = {
            "account_id": self.validate_connection().get("account_id", "unknown"),
            "iam": self._collect_iam(session),
            "s3": self._collect_s3(session),
            "ec2": self._collect_ec2(session),
            "vpc": self._collect_vpc(session),
            "cloudtrail": self._collect_cloudtrail(session),
            "kms": self._collect_kms(session),
            "lambda": self._collect_lambda(session),
            "rds": self._collect_rds(session),
            "ebs": self._collect_ebs(session)
        }
        return data

    def _collect_iam(self, session: boto3.Session) -> Dict[str, Any]:
        client = session.client("iam")
        result = {
            "users": [], "roles": [], "groups": [], "policies": [],
            "mfa_status": {}, "password_policy": {}
        }
        try:
            # Users and MFA
            users = client.list_users()["Users"]
            for user in users:
                user_name = user["UserName"]
                try:
                    mfa = client.list_mfa_devices(UserName=user_name)["MFADevices"]
                    user["MFAEnabled"] = len(mfa) > 0
                except ClientError:
                    user["MFAEnabled"] = False

                # Access Keys
                try:
                    keys = client.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
                    user["AccessKeys"] = keys
                except ClientError:
                    user["AccessKeys"] = []

                # Attached User Policies
                try:
                    attached = client.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
                    user["AttachedPolicies"] = attached
                except ClientError:
                    user["AttachedPolicies"] = []

                # Inline Policies
                try:
                    inline = client.list_user_policies(UserName=user_name)["PolicyNames"]
                    user["InlinePolicies"] = []
                    for p_name in inline:
                        policy_doc = client.get_user_policy(UserName=user_name, PolicyName=p_name)["PolicyDocument"]
                        user["InlinePolicies"].append({"PolicyName": p_name, "PolicyDocument": policy_doc})
                except ClientError:
                    user["InlinePolicies"] = []

                result["users"].append(user)
        except ClientError as e:
            logger.warning(f"Could not collect IAM Users: {e}")

        try:
            # Roles
            roles = client.list_roles()["Roles"]
            for role in roles:
                role_name = role["RoleName"]
                try:
                    attached = client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
                    role["AttachedPolicies"] = attached
                except ClientError:
                    role["AttachedPolicies"] = []

                try:
                    inline = client.list_role_policies(RoleName=role_name)["PolicyNames"]
                    role["InlinePolicies"] = []
                    for p_name in inline:
                        policy_doc = client.get_role_policy(RoleName=role_name, PolicyName=p_name)["PolicyDocument"]
                        role["InlinePolicies"].append({"PolicyName": p_name, "PolicyDocument": policy_doc})
                except ClientError:
                    role["InlinePolicies"] = []

                result["roles"].append(role)
        except ClientError as e:
            logger.warning(f"Could not collect IAM Roles: {e}")

        try:
            # Password Policy
            result["password_policy"] = client.get_account_password_policy().get("PasswordPolicy", {})
        except ClientError:
            result["password_policy"] = {}

        return result

    def _collect_s3(self, session: boto3.Session) -> List[Dict[str, Any]]:
        s3 = session.client("s3")
        buckets_out = []
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            for b in buckets:
                name = b["Name"]
                b_info = {"Name": name, "CreationDate": b["CreationDate"].isoformat() if b.get("CreationDate") else None}

                # Public Access Block
                try:
                    b_info["PublicAccessBlock"] = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                except ClientError:
                    b_info["PublicAccessBlock"] = {}

                # Bucket Policy
                try:
                    b_info["Policy"] = s3.get_bucket_policy(Bucket=name).get("Policy", "")
                except ClientError:
                    b_info["Policy"] = ""

                # Encryption
                try:
                    b_info["Encryption"] = s3.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration", {})
                except ClientError:
                    b_info["Encryption"] = {}

                # Versioning
                try:
                    b_info["Versioning"] = s3.get_bucket_versioning(Bucket=name)
                except ClientError:
                    b_info["Versioning"] = {}

                # Logging
                try:
                    b_info["Logging"] = s3.get_bucket_logging(Bucket=name)
                except ClientError:
                    b_info["Logging"] = {}

                # ACL
                try:
                    b_info["ACL"] = s3.get_bucket_acl(Bucket=name)
                except ClientError:
                    b_info["ACL"] = {}

                buckets_out.append(b_info)
        except ClientError as e:
            logger.warning(f"Could not list S3 buckets: {e}")
        return buckets_out

    def _collect_ec2(self, session: boto3.Session) -> List[Dict[str, Any]]:
        ec2 = session.client("ec2")
        instances_out = []
        try:
            reservations = ec2.describe_instances().get("Reservations", [])
            for res in reservations:
                for inst in res.get("Instances", []):
                    inst_info = {
                        "InstanceId": inst["InstanceId"],
                        "InstanceType": inst["InstanceType"],
                        "State": inst["State"]["Name"],
                        "PublicIpAddress": inst.get("PublicIpAddress"),
                        "PrivateIpAddress": inst.get("PrivateIpAddress"),
                        "SubnetId": inst.get("SubnetId"),
                        "VpcId": inst.get("VpcId"),
                        "SecurityGroups": inst.get("SecurityGroups", []),
                        "IamInstanceProfile": inst.get("IamInstanceProfile"),
                        "MetadataOptions": inst.get("MetadataOptions", {})
                    }
                    instances_out.append(inst_info)
        except ClientError as e:
            logger.warning(f"Could not describe EC2 instances: {e}")
        return instances_out

    def _collect_vpc(self, session: boto3.Session) -> Dict[str, Any]:
        ec2 = session.client("ec2")
        result = {"vpcs": [], "security_groups": [], "route_tables": [], "nacls": []}
        try:
            result["vpcs"] = ec2.describe_vpcs().get("Vpcs", [])
            result["security_groups"] = ec2.describe_security_groups().get("SecurityGroups", [])
            result["route_tables"] = ec2.describe_route_tables().get("RouteTables", [])
            result["nacls"] = ec2.describe_network_acls().get("NetworkAcls", [])
        except ClientError as e:
            logger.warning(f"Could not describe VPC resources: {e}")
        return result

    def _collect_cloudtrail(self, session: boto3.Session) -> List[Dict[str, Any]]:
        ct = session.client("cloudtrail")
        trails_out = []
        try:
            trails = ct.describe_trails().get("trailList", [])
            for t in trails:
                name = t["Name"]
                try:
                    status = ct.get_trail_status(Name=name)
                    t["Status"] = {
                        "IsLogging": status.get("IsLogging"),
                        "LatestDeliveryTime": status.get("LatestDeliveryTime").isoformat() if status.get("LatestDeliveryTime") else None
                    }
                except ClientError:
                    t["Status"] = {}
                trails_out.append(t)
        except ClientError as e:
            logger.warning(f"Could not describe CloudTrail: {e}")
        return trails_out

    def _collect_kms(self, session: boto3.Session) -> List[Dict[str, Any]]:
        kms = session.client("kms")
        keys_out = []
        try:
            keys = kms.list_keys().get("Keys", [])
            for key in keys:
                key_id = key["KeyId"]
                try:
                    desc = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                    # Check rotation
                    try:
                        rot = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                        desc["KeyRotationEnabled"] = rot
                    except ClientError:
                        desc["KeyRotationEnabled"] = False
                    keys_out.append(desc)
                except ClientError:
                    continue
        except ClientError as e:
            logger.warning(f"Could not list KMS keys: {e}")
        return keys_out

    def _collect_lambda(self, session: boto3.Session) -> List[Dict[str, Any]]:
        lmb = session.client("lambda")
        funcs_out = []
        try:
            funcs = lmb.list_functions().get("Functions", [])
            for f in funcs:
                f_info = {
                    "FunctionName": f["FunctionName"],
                    "FunctionArn": f["FunctionArn"],
                    "Role": f["Role"],
                    "Runtime": f.get("Runtime"),
                    "Handler": f.get("Handler")
                }
                # Check for public URLs (Function URLs)
                try:
                    urls = lmb.list_function_url_configs(FunctionName=f["FunctionName"]).get("FunctionUrlConfigs", [])
                    f_info["FunctionUrls"] = urls
                except ClientError:
                    f_info["FunctionUrls"] = []
                # Environment variables
                f_info["EnvironmentVariables"] = f.get("Environment", {}).get("Variables", {})
                funcs_out.append(f_info)
        except ClientError as e:
            logger.warning(f"Could not list Lambda functions: {e}")
        return funcs_out

    def _collect_rds(self, session: boto3.Session) -> List[Dict[str, Any]]:
        rds = session.client("rds")
        instances_out = []
        try:
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                instances_out.append({
                    "DBInstanceIdentifier": db["DBInstanceIdentifier"],
                    "DBInstanceClass": db["DBInstanceClass"],
                    "Engine": db["Engine"],
                    "PubliclyAccessible": db["PubliclyAccessible"],
                    "StorageEncrypted": db["StorageEncrypted"],
                    "BackupRetentionPeriod": db["BackupRetentionPeriod"],
                    "KmsKeyId": db.get("KmsKeyId")
                })
        except ClientError as e:
            logger.warning(f"Could not describe RDS instances: {e}")
        return instances_out

    def _collect_ebs(self, session: boto3.Session) -> Dict[str, Any]:
        ec2 = session.client("ec2")
        result = {"volumes": [], "snapshots": []}
        try:
            vols = ec2.describe_volumes().get("Volumes", [])
            for v in vols:
                result["volumes"].append({
                    "VolumeId": v["VolumeId"],
                    "Encrypted": v["Encrypted"],
                    "Size": v["Size"],
                    "State": v["State"],
                    "KmsKeyId": v.get("KmsKeyId")
                })
            # Snapshots (just own snapshots to avoid huge listings)
            snaps = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
            for s in snaps:
                result["snapshots"].append({
                    "SnapshotId": s["SnapshotId"],
                    "VolumeId": s["VolumeId"],
                    "Encrypted": s["Encrypted"],
                    "VolumeSize": s["VolumeSize"]
                })
        except ClientError as e:
            logger.warning(f"Could not describe EBS volumes/snapshots: {e}")
        return result
