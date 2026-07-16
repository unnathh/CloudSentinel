import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.rules.base import SecurityRule

class RuleRootMfa(SecurityRule):
    rule_id = "CIS-1.1"
    name = "Root Account MFA Enabled"
    severity = "Critical"
    category = "IAM"
    description = "Ensure Multi-Factor Authentication (MFA) is enabled for all IAM users and root account."
    remediation = "Log in to the AWS console as the root account, navigate to IAM console, and enable MFA under the Security Credentials tab."
    mitre_technique_id = "T1556"
    mitre_technique_name = "Modify Authentication Process"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        users = data.get("iam", {}).get("users", [])
        for u in users:
            if u.get("UserName") == "root" and not u.get("MFAEnabled", False):
                findings.append({
                    "resource_id": "arn:aws:iam::account:root",
                    "region": "global",
                    "evidence": "Root account MFA status: Disabled",
                })
        return findings


class RuleRootKeys(SecurityRule):
    rule_id = "CIS-1.4"
    name = "Root Account Access Keys Disabled"
    severity = "Critical"
    category = "IAM"
    description = "Ensure no access keys exist for the root account."
    remediation = "Delete all access keys belonging to the root account. Create IAM users with specific permissions instead."
    mitre_technique_id = "T1078.004"
    mitre_technique_name = "Valid Accounts: Cloud Accounts"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        users = data.get("iam", {}).get("users", [])
        for u in users:
            if u.get("UserName") == "root":
                keys = u.get("AccessKeys", [])
                active_keys = [k for k in keys if k.get("Status") == "Active"]
                if active_keys:
                    findings.append({
                        "resource_id": "arn:aws:iam::account:root",
                        "region": "global",
                        "evidence": f"Found {len(active_keys)} active access keys on root account.",
                    })
        return findings


class RulePasswordPolicy(SecurityRule):
    rule_id = "CIS-1.9"
    name = "Strong Password Policy Configured"
    severity = "Medium"
    category = "IAM"
    description = "Ensure IAM password policy requires minimum length of 14, uppercase, lowercase, numbers, and symbols."
    remediation = "Navigate to IAM -> Account Settings and set a strong password policy requiring length >= 14 and all character types."
    mitre_technique_id = "T1589"
    mitre_technique_name = "Gather Victim Identity Information"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        policy = data.get("iam", {}).get("password_policy", {})
        if not policy:
            findings.append({
                "resource_id": "arn:aws:iam::account:password-policy",
                "region": "global",
                "evidence": "No IAM password policy is configured.",
            })
            return findings

        reasons = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            reasons.append(f"Min length is {policy.get('MinimumPasswordLength')} (should be >= 14)")
        if not policy.get("RequireSymbols", False):
            reasons.append("Symbols not required")
        if not policy.get("RequireNumbers", False):
            reasons.append("Numbers not required")
        if not policy.get("RequireUppercaseCharacters", False):
            reasons.append("Uppercase characters not required")
        if not policy.get("RequireLowercaseCharacters", False):
            reasons.append("Lowercase characters not required")

        if reasons:
            findings.append({
                "resource_id": "arn:aws:iam::account:password-policy",
                "region": "global",
                "evidence": "Weak password policy: " + ", ".join(reasons),
            })
        return findings


class RuleUserMfa(SecurityRule):
    rule_id = "CIS-1.2"
    name = "IAM Users MFA Enabled"
    severity = "High"
    category = "IAM"
    description = "Ensure MFA is enabled for all IAM users that have console access or active passwords."
    remediation = "Navigate to the IAM console, click Users, and assign an MFA device to each user."
    mitre_technique_id = "T1556"
    mitre_technique_name = "Modify Authentication Process"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        users = data.get("iam", {}).get("users", [])
        for u in users:
            if u.get("UserName") != "root" and not u.get("MFAEnabled", False):
                # If they have access keys or are just users
                findings.append({
                    "resource_id": f"arn:aws:iam::account:user/{u.get('UserName')}",
                    "region": "global",
                    "evidence": f"IAM User '{u.get('UserName')}' has no MFA device enabled.",
                })
        return findings


class RuleUnusedAccessKeys(SecurityRule):
    rule_id = "CIS-1.14"
    name = "Unused Access Keys Rotated / Disabled"
    severity = "Medium"
    category = "IAM"
    description = "Ensure active access keys created more than 90 days ago are deactivated or deleted."
    remediation = "Identify older access keys, verify with the owner, and deactivate (set status to Inactive) or delete them."
    mitre_technique_id = "T1078.004"
    mitre_technique_name = "Valid Accounts: Cloud Accounts"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        users = data.get("iam", {}).get("users", [])
        now = datetime.now(timezone.utc)
        for u in users:
            keys = u.get("AccessKeys", [])
            for k in keys:
                if k.get("Status") == "Active":
                    created_str = k.get("CreateDate")
                    try:
                        # Parse ISO date string
                        created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        age_days = (now - created_dt).days
                        if age_days > 90:
                            findings.append({
                                "resource_id": f"AccessKey:{k.get('AccessKeyId')}",
                                "region": "global",
                                "evidence": f"Access Key '{k.get('AccessKeyId')}' owned by '{u.get('UserName')}' is {age_days} days old (limit 90 days).",
                            })
                    except Exception:
                        pass
        return findings


class RuleWildcardPolicies(SecurityRule):
    rule_id = "CIS-1.16"
    name = "IAM Policies Wildcard Check"
    severity = "High"
    category = "IAM"
    description = "Ensure IAM policies do not allow unrestricted actions ('*') on unrestricted resources ('*')."
    remediation = "Scope down IAM policy statements to grant only the minimum necessary permissions on specific resources."
    mitre_technique_id = "T1098"
    mitre_technique_name = "Account Manipulation"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        
        # Check inline policies of users
        users = data.get("iam", {}).get("users", [])
        for u in users:
            for p in u.get("InlinePolicies", []):
                doc = p.get("PolicyDocument", {})
                if self._has_wildcard(doc):
                    findings.append({
                        "resource_id": f"arn:aws:iam::account:user/{u.get('UserName')}",
                        "region": "global",
                        "evidence": f"User '{u.get('UserName')}' has inline policy '{p.get('PolicyName')}' allowing Action '*' on Resource '*'.",
                    })

        # Check inline policies of roles
        roles = data.get("iam", {}).get("roles", [])
        for r in roles:
            for p in r.get("InlinePolicies", []):
                doc = p.get("PolicyDocument", {})
                if self._has_wildcard(doc):
                    findings.append({
                        "resource_id": f"arn:aws:iam::account:role/{r.get('RoleName')}",
                        "region": "global",
                        "evidence": f"Role '{r.get('RoleName')}' has inline policy '{p.get('PolicyName')}' allowing Action '*' on Resource '*'.",
                    })

        # Check customer managed policies
        policies = data.get("iam", {}).get("policies", [])
        for p in policies:
            doc = p.get("PolicyVersion", {}).get("Document", {})
            if self._has_wildcard(doc):
                findings.append({
                    "resource_id": p.get("Arn", "unknown"),
                    "region": "global",
                    "evidence": f"Customer policy '{p.get('PolicyName')}' allows Action '*' on Resource '*'.",
                })

        return findings

    def _has_wildcard(self, doc: Dict[str, Any]) -> bool:
        if not doc or not isinstance(doc, dict):
            return False
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            effect = stmt.get("Effect")
            action = stmt.get("Action", [])
            resource = stmt.get("Resource", [])

            if effect == "Allow":
                # Check for * actions
                actions_list = [action] if isinstance(action, str) else action
                resources_list = [resource] if isinstance(resource, str) else resource

                has_star_action = "*" in actions_list
                has_star_resource = "*" in resources_list
                if has_star_action and has_star_resource:
                    return True
        return False


class RuleAdminAttached(SecurityRule):
    rule_id = "RULE-IAM-ADMIN"
    name = "AdministratorAccess directly attached to Users"
    severity = "High"
    category = "IAM"
    description = "Ensure AdministratorAccess is not directly attached to IAM users to maintain separation of privilege."
    remediation = "Remove AdministratorAccess from the user and assign it to an IAM group or role with conditional switch capability."
    mitre_technique_id = "T1078.004"
    mitre_technique_name = "Valid Accounts: Cloud Accounts"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        users = data.get("iam", {}).get("users", [])
        for u in users:
            attached = u.get("AttachedPolicies", [])
            for p in attached:
                if p.get("PolicyName") == "AdministratorAccess":
                    findings.append({
                        "resource_id": f"arn:aws:iam::account:user/{u.get('UserName')}",
                        "region": "global",
                        "evidence": f"User '{u.get('UserName')}' has AdministratorAccess policy directly attached.",
                    })
        return findings


class RulePublicS3Bucket(SecurityRule):
    rule_id = "CIS-2.1.1"
    name = "Public S3 Buckets Prohibited"
    severity = "Critical"
    category = "S3"
    description = "Ensure S3 buckets do not allow public access via policies or ACLs."
    remediation = "Enable Block Public Access setting on the bucket and remove any public bucket policies or wildcard ACL grants."
    mitre_technique_id = "T1530"
    mitre_technique_name = "Data from Cloud Storage Object"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        buckets = data.get("s3", [])
        for b in buckets:
            name = b.get("Name")
            is_public = False
            reasons = []

            # 1. Block Public Access Config Check
            pab = b.get("PublicAccessBlock", {})
            if not pab or not pab.get("BlockPublicAcls", True) or not pab.get("BlockPublicPolicy", True):
                is_public = True
                reasons.append("Block Public Access is disabled or partially disabled")

            # 2. ACL Check
            acl = b.get("ACL", {})
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                ]:
                    is_public = True
                    reasons.append(f"Bucket ACL allows access to group '{grantee.get('URI').split('/')[-1]}'")

            # 3. Bucket Policy Check
            policy = b.get("Policy", "")
            if policy:
                try:
                    p_doc = json.loads(policy)
                    statements = p_doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        effect = stmt.get("Effect")
                        principal = stmt.get("Principal")
                        if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                            is_public = True
                            reasons.append("Bucket policy grants access to everyone (Principal: '*')")
                except Exception:
                    pass

            if is_public:
                findings.append({
                    "resource_id": name,
                    "region": "global",
                    "evidence": f"Bucket '{name}' is public: " + ", ".join(reasons),
                })
        return findings


class RuleS3Encryption(SecurityRule):
    rule_id = "CIS-2.1.2"
    name = "S3 Buckets Server-Side Encryption Enabled"
    severity = "Medium"
    category = "S3"
    description = "Ensure S3 buckets are encrypted by default."
    remediation = "Navigate to S3, select properties of the bucket, and enable Default Encryption using SSE-S3 or SSE-KMS."
    mitre_technique_id = "T1530"
    mitre_technique_name = "Data from Cloud Storage Object"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        buckets = data.get("s3", [])
        for b in buckets:
            enc = b.get("Encryption", {})
            if not enc or not enc.get("Rules"):
                findings.append({
                    "resource_id": b.get("Name"),
                    "region": "global",
                    "evidence": f"Bucket '{b.get('Name')}' does not have default server-side encryption enabled.",
                })
        return findings


class RuleS3Logging(SecurityRule):
    rule_id = "RULE-S3-LOGGING"
    name = "S3 Bucket Logging Enabled"
    severity = "Low"
    category = "S3"
    description = "Ensure server access logging is enabled on S3 buckets for audit trail tracking."
    remediation = "Configure S3 server access logging in S3 properties to deliver access logs to a designated logging bucket."
    mitre_technique_id = "T1036"
    mitre_technique_name = "Masquerading"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        buckets = data.get("s3", [])
        for b in buckets:
            log = b.get("Logging", {})
            if not log or not log.get("LoggingEnabled"):
                # Exempt logging buckets to avoid infinite loops, but for general demo, check all
                findings.append({
                    "resource_id": b.get("Name"),
                    "region": "global",
                    "evidence": f"S3 Bucket '{b.get('Name')}' server access logging is disabled.",
                })
        return findings


class RuleS3Versioning(SecurityRule):
    rule_id = "RULE-S3-VERSIONING"
    name = "S3 Bucket Versioning Enabled"
    severity = "Low"
    category = "S3"
    description = "Ensure S3 bucket versioning is enabled to protect against accidental deletes or ransomware."
    remediation = "Enable versioning under S3 properties for the bucket."
    mitre_technique_id = "T1485"
    mitre_technique_name = "Data Destruction"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        buckets = data.get("s3", [])
        for b in buckets:
            ver = b.get("Versioning", {})
            status = ver.get("Status")
            if status != "Enabled":
                findings.append({
                    "resource_id": b.get("Name"),
                    "region": "global",
                    "evidence": f"S3 Bucket '{b.get('Name')}' versioning is not enabled (status: '{status or 'Disabled'}').",
                })
        return findings


class RuleSecurityGroupOpenSSH(SecurityRule):
    rule_id = "CIS-4.1"
    name = "Security Groups Do Not Allow Ingress to Port 22 from Anywhere"
    severity = "High"
    category = "VPC"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (SSH)."
    remediation = "Restrict port 22 ingress rules to trusted CIDR blocks (e.g. corporate VPN) instead of 0.0.0.0/0."
    mitre_technique_id = "T1133"
    mitre_technique_name = "External Remote Services"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        groups = data.get("vpc", {}).get("security_groups", [])
        for g in groups:
            for perm in g.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                
                # TCP Port 22
                is_ssh = (from_port is None and to_port is None) or \
                         (from_port is not None and to_port is not None and from_port <= 22 <= to_port)
                
                if is_ssh and perm.get("IpProtocol") in ["tcp", "-1"]:
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            findings.append({
                                "resource_id": g.get("GroupId"),
                                "region": g.get("VpcId", "global"),
                                "evidence": f"Security group '{g.get('GroupName')}' ({g.get('GroupId')}) allows SSH (port 22) access from 0.0.0.0/0.",
                            })
                            break
        return findings


class RuleSecurityGroupOpenRDP(SecurityRule):
    rule_id = "CIS-4.2"
    name = "Security Groups Do Not Allow Ingress to Port 3389 from Anywhere"
    severity = "High"
    category = "VPC"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (RDP)."
    remediation = "Restrict port 3389 ingress rules to trusted subnet ranges or VPN links instead of 0.0.0.0/0."
    mitre_technique_id = "T1133"
    mitre_technique_name = "External Remote Services"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        groups = data.get("vpc", {}).get("security_groups", [])
        for g in groups:
            for perm in g.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                
                # TCP Port 3389
                is_rdp = (from_port is None and to_port is None) or \
                         (from_port is not None and to_port is not None and from_port <= 3389 <= to_port)
                
                if is_rdp and perm.get("IpProtocol") in ["tcp", "-1"]:
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            findings.append({
                                "resource_id": g.get("GroupId"),
                                "region": g.get("VpcId", "global"),
                                "evidence": f"Security group '{g.get('GroupName')}' ({g.get('GroupId')}) allows RDP (port 3389) access from 0.0.0.0/0.",
                            })
                            break
        return findings


class RuleSecurityGroupOpenHttp(SecurityRule):
    rule_id = "RULE-SG-HTTP"
    name = "Security Groups HTTP Port 80 Open to World"
    severity = "Medium"
    category = "VPC"
    description = "Identify security groups allowing cleartext HTTP (port 80) access from 0.0.0.0/0."
    remediation = "Ensure all web traffic is redirected to HTTPS (port 443) and close port 80 or restrict access."
    mitre_technique_id = "T1133"
    mitre_technique_name = "External Remote Services"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        groups = data.get("vpc", {}).get("security_groups", [])
        for g in groups:
            for perm in g.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                is_http = (from_port is None and to_port is None) or \
                          (from_port is not None and to_port is not None and from_port <= 80 <= to_port)
                if is_http and perm.get("IpProtocol") in ["tcp", "-1"]:
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            findings.append({
                                "resource_id": g.get("GroupId"),
                                "region": g.get("VpcId", "global"),
                                "evidence": f"Security group '{g.get('GroupName')}' ({g.get('GroupId')}) allows cleartext HTTP (port 80) from 0.0.0.0/0.",
                            })
                            break
        return findings


class RuleUnencryptedEBS(SecurityRule):
    rule_id = "RULE-EBS-ENCRYPTION"
    name = "EBS Volumes Encrypted at Rest"
    severity = "Medium"
    category = "EC2"
    description = "Ensure EBS volumes are encrypted at rest to protect corporate data."
    remediation = "Enable encryption when creating EBS volumes. Use KMS Customer Managed Keys for customization."
    mitre_technique_id = "T1486"
    mitre_technique_name = "Data Encrypted for Impact"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        vols = data.get("ebs", {}).get("volumes", [])
        for v in vols:
            if not v.get("Encrypted", False):
                findings.append({
                    "resource_id": v.get("VolumeId"),
                    "region": "global",
                    "evidence": f"EBS Volume '{v.get('VolumeId')}' is unencrypted.",
                })
        return findings


class RuleCloudTrailDisabled(SecurityRule):
    rule_id = "CIS-3.1"
    name = "CloudTrail Logging Enabled"
    severity = "High"
    category = "CloudTrail"
    description = "Ensure CloudTrail is enabled and active in all regions."
    remediation = "Create a multi-region trail in CloudTrail and verify that logging is active."
    mitre_technique_id = "T1562.001"
    mitre_technique_name = "Impair Defenses: Disable or Modify Tools"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        trails = data.get("cloudtrail", [])
        if not trails:
            findings.append({
                "resource_id": "arn:aws:cloudtrail:account:trails",
                "region": "global",
                "evidence": "No CloudTrail trails exist in the account.",
            })
            return findings

        logging_trails = [t for t in trails if t.get("Status", {}).get("IsLogging") is True]
        if not logging_trails:
            findings.append({
                "resource_id": "arn:aws:cloudtrail:account:trails",
                "region": "global",
                "evidence": "CloudTrail exists, but no trails are actively logging events.",
            })
        return findings


class RuleCloudTrailNotMultiRegion(SecurityRule):
    rule_id = "CIS-3.1.2"
    name = "CloudTrail Multi-Region Enabled"
    severity = "Medium"
    category = "CloudTrail"
    description = "Ensure CloudTrail trails are configured to collect logs from all AWS regions."
    remediation = "Update the CloudTrail configuration to enable Multi-Region Trail logging."
    mitre_technique_id = "T1562.001"
    mitre_technique_name = "Impair Defenses: Disable or Modify Tools"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        trails = data.get("cloudtrail", [])
        if not trails:
            return findings

        non_multi = [t for t in trails if not t.get("IsMultiRegionTrail", False)]
        if len(non_multi) == len(trails):
            findings.append({
                "resource_id": "arn:aws:cloudtrail:account:trails",
                "region": "global",
                "evidence": "No CloudTrail trail is configured as a Multi-Region trail.",
            })
        return findings


class RuleKmsRotationDisabled(SecurityRule):
    rule_id = "CIS-2.8"
    name = "KMS Customer Key Rotation Enabled"
    severity = "Low"
    category = "KMS"
    description = "Ensure KMS customer master keys (CMK) have automatic annual rotation enabled."
    remediation = "Navigate to KMS console, select the key, go to the Key Rotation tab, and check 'Automatically rotate this KMS key'."
    mitre_technique_id = "T1098"
    mitre_technique_name = "Account Manipulation"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        keys = data.get("kms", [])
        for k in keys:
            if k.get("Enabled") is True and not k.get("KeyRotationEnabled", False):
                findings.append({
                    "resource_id": k.get("KeyId"),
                    "region": "global",
                    "evidence": f"KMS Key '{k.get('KeyId')}' has key rotation disabled.",
                })
        return findings


class RulePublicRDS(SecurityRule):
    rule_id = "RULE-RDS-PUBLIC"
    name = "RDS Database Instances Are Private"
    severity = "High"
    category = "RDS"
    description = "Ensure RDS databases do not have a public IP and are not publicly accessible."
    remediation = "Modify the RDS instance to set Publicly Accessible to False, and place it in private subnets."
    mitre_technique_id = "T1528"
    mitre_technique_name = "Steal Application Access Token"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        rds_instances = data.get("rds", [])
        for r in rds_instances:
            if r.get("PubliclyAccessible", False):
                findings.append({
                    "resource_id": r.get("DBInstanceIdentifier"),
                    "region": "global",
                    "evidence": f"RDS DB instance '{r.get('DBInstanceIdentifier')}' is configured to be Publicly Accessible.",
                })
        return findings


class RulePublicLambda(SecurityRule):
    rule_id = "RULE-LAMBDA-PUBLIC-URL"
    name = "Lambda Function URLs Authentication Enabled"
    severity = "High"
    category = "Lambda"
    description = "Ensure Lambda Function URLs require IAM authentication and are not open to the public."
    remediation = "Configure Lambda Function URL AuthType to AWS_IAM, or secure the public endpoint with API Gateway."
    mitre_technique_id = "T1190"
    mitre_technique_name = "Exploit Public-Facing Application"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        funcs = data.get("lambda", [])
        for f in funcs:
            for url_cfg in f.get("FunctionUrls", []):
                if url_cfg.get("AuthType") == "NONE":
                    findings.append({
                        "resource_id": f.get("FunctionName"),
                        "region": "global",
                        "evidence": f"Lambda function '{f.get('FunctionName')}' has a public Function URL configured without auth: {url_cfg.get('FunctionUrl')}",
                    })
        return findings
