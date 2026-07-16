from typing import Dict, Any
from datetime import datetime

class MockAWSCollector:
    def __init__(self, account_name: str = "demo-aws-account"):
        self.account_name = account_name
        self.account_id = "123456789012"

    def validate_connection(self) -> Dict[str, Any]:
        return {
            "success": True,
            "account_id": self.account_id,
            "arn": f"arn:aws:iam::{self.account_id}:root",
            "user_id": "AIDAZ2WFS62L1AHK_ROOT"
        }

    def collect_all(self) -> Dict[str, Any]:
        """Generates realistic misconfigured AWS resource data for demo and evaluation."""
        return {
            "account_id": self.account_id,
            "iam": self._collect_iam(),
            "s3": self._collect_s3(),
            "ec2": self._collect_ec2(),
            "vpc": self._collect_vpc(),
            "cloudtrail": self._collect_cloudtrail(),
            "kms": self._collect_kms(),
            "lambda": self._collect_lambda(),
            "rds": self._collect_rds(),
            "ebs": self._collect_ebs()
        }

    def _collect_iam(self) -> Dict[str, Any]:
        return {
            "users": [
                {
                    "UserName": "root",
                    "UserId": "AIDAZ2WFS62L1AHK_ROOT",
                    "CreateDate": "2020-01-01T00:00:00Z",
                    "MFAEnabled": False,  # Root account MFA disabled (CIS 1.1)
                    "AccessKeys": [
                        {
                            "AccessKeyId": "AKIAZ2WFS62L1AHK_ROOTKEY",
                            "Status": "Active",
                            "CreateDate": "2020-01-01T00:00:00Z"
                        }
                    ],
                    "AttachedPolicies": [],
                    "InlinePolicies": []
                },
                {
                    "UserName": "dev-user",
                    "UserId": "AIDAZ2WFS62L1AHK_DEV",
                    "CreateDate": "2024-02-15T12:00:00Z",
                    "MFAEnabled": True,
                    "AccessKeys": [
                        {
                            "AccessKeyId": "AKIAZ2WFS62L1AHK_DEV1",
                            "Status": "Active",
                            "CreateDate": "2024-02-15T12:00:00Z"
                        }
                    ],
                    "AttachedPolicies": [
                        {
                            "PolicyName": "Policy_DevDeploy",
                            "PolicyArn": f"arn:aws:iam::{self.account_id}:policy/Policy_DevDeploy"
                        }
                    ],
                    "InlinePolicies": []
                },
                {
                    "UserName": "audit-viewer",
                    "UserId": "AIDAZ2WFS62L1AHK_AUDIT",
                    "CreateDate": "2023-05-10T09:00:00Z",
                    "MFAEnabled": False,  # IAM User MFA disabled (CIS 1.2)
                    "AccessKeys": [
                        {
                            "AccessKeyId": "AKIAZ2WFS62L1AHK_AUDIT1",
                            "Status": "Active",
                            "CreateDate": "2023-05-10T09:00:00Z"  # Old active access key
                        }
                    ],
                    "AttachedPolicies": [
                        {
                            "PolicyName": "ReadOnlyAccess",
                            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
                        }
                    ],
                    "InlinePolicies": []
                },
                {
                    "UserName": "contractor-temp",
                    "UserId": "AIDAZ2WFS62L1AHK_TEMP",
                    "CreateDate": "2025-01-10T14:30:00Z",
                    "MFAEnabled": False,
                    "AccessKeys": [
                        {
                            "AccessKeyId": "AKIAZ2WFS62L1AHK_TEMP1",
                            "Status": "Active",
                            "CreateDate": "2025-01-10T14:30:00Z"  # Active key unused (>90 days)
                        }
                    ],
                    "AttachedPolicies": [],
                    "InlinePolicies": [
                        {
                            "PolicyName": "ContractorAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "*",  # Wildcard IAM actions (CIS 1.16)
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }
                    ]
                }
            ],
            "roles": [
                {
                    "RoleName": "Role_CloudSentinelAdmin",
                    "Arn": f"arn:aws:iam::{self.account_id}:role/Role_CloudSentinelAdmin",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "AttachedPolicies": [
                        {
                            "PolicyName": "AdministratorAccess",
                            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
                        }
                    ],
                    "InlinePolicies": []
                },
                {
                    "RoleName": "Role_SupportEngineer",
                    "Arn": f"arn:aws:iam::{self.account_id}:role/Role_SupportEngineer",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{self.account_id}:user/dev-user"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "AttachedPolicies": [],
                    "InlinePolicies": [
                        {
                            "PolicyName": "SupportPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "iam:CreatePolicyVersion",
                                            "iam:SetDefaultPolicyVersion"
                                        ],
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }
                    ]
                }
            ],
            "groups": [],
            "policies": [
                {
                    "PolicyName": "Policy_DevDeploy",
                    "Arn": f"arn:aws:iam::{self.account_id}:policy/Policy_DevDeploy",
                    "PolicyVersion": {
                        "Document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "ec2:RunInstances",
                                        "iam:PassRole"
                                    ],
                                    "Resource": "*"
                                }
                            ]
                        }
                    }
                }
            ],
            "password_policy": {
                "MinimumPasswordLength": 8,
                "RequireSymbols": False,  # Weak password policy (CIS 1.9)
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "PasswordReusePrevention": 3
            }
        }

    def _collect_s3(self) -> list:
        return [
            {
                "Name": "cloudsentinel-public-data-bucket",
                "CreationDate": "2022-04-18T10:00:00Z",
                "PublicAccessBlock": {
                    "BlockPublicAcls": False,  # S3 Public Block missing (CIS 2.1.1)
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                },
                "ACL": {
                    "Grants": [
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                            },
                            "Permission": "READ"
                        }
                    ]
                },
                "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"PublicRead\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::cloudsentinel-public-data-bucket/*\"}]}",
                "Encryption": {},  # S3 bucket encryption disabled (CIS 2.1.2)
                "Versioning": {"Status": "Suspended"},  # Versioning disabled
                "Logging": {}  # Logging disabled
            },
            {
                "Name": "cloudsentinel-secure-audit-logs",
                "CreationDate": "2022-04-18T10:05:00Z",
                "PublicAccessBlock": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True
                },
                "ACL": {},
                "Policy": "",
                "Encryption": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                                "KMSMasterKeyId": "arn:aws:kms:us-east-1:123456789012:key/some-kms-key-uuid"
                            }
                        }
                    ]
                },
                "Versioning": {"Status": "Enabled"},
                "Logging": {
                    "LoggingEnabled": {
                        "TargetBucket": "cloudsentinel-access-logs",
                        "TargetPrefix": "audit/"
                    }
                }
            }
        ]

    def _collect_ec2(self) -> list:
        return [
            {
                "InstanceId": "i-0a1b2c3d4e5f6g7h8",
                "InstanceType": "t3.medium",
                "State": "running",
                "PublicIpAddress": "54.210.12.34",
                "PrivateIpAddress": "10.0.1.15",
                "SubnetId": "subnet-0123456789abcdef0",
                "VpcId": "vpc-0123456789abcdef0",
                "SecurityGroups": [
                    {"GroupId": "sg-0123456789abcdef0", "GroupName": "ssh-open-sg"}
                ],
                "IamInstanceProfile": {
                    "Arn": f"arn:aws:iam::{self.account_id}:instance-profile/EC2AdminProfile",
                    "Id": "AIPAZ2WFS62L1AHK_EC2ADMIN"
                },
                "MetadataOptions": {
                    "HttpTokens": "optional",  # IMDSv1 enabled (vulnerable to SSRF / Credential theft)
                    "HttpPutResponseHopLimit": 1
                }
            }
        ]

    def _collect_vpc(self) -> Dict[str, Any]:
        return {
            "vpcs": [
                {
                    "VpcId": "vpc-0123456789abcdef0",
                    "IsDefault": True,
                    "CidrBlock": "172.31.0.0/16"
                }
            ],
            "security_groups": [
                {
                    "GroupId": "sg-0123456789abcdef0",
                    "GroupName": "ssh-open-sg",
                    "Description": "Allow SSH from anywhere",
                    "VpcId": "vpc-0123456789abcdef0",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH Open"}]  # SSH open to world (CIS 4.1)
                        },
                        {
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "RDP Open"}]  # RDP open to world (CIS 4.2)
                        }
                    ]
                }
            ],
            "route_tables": [],
            "nacls": []
        }

    def _collect_cloudtrail(self) -> list:
        return [
            {
                "Name": "SingleRegionTrail",
                "HomeRegion": "us-east-1",
                "IsMultiRegionTrail": False,  # CloudTrail not multi-region (CIS 3.1)
                "LogFileValidationEnabled": False,  # CloudTrail log validation disabled (CIS 3.2)
                "Status": {
                    "IsLogging": True,
                    "LatestDeliveryTime": "2026-07-11T09:00:00Z"
                }
            }
        ]

    def _collect_kms(self) -> list:
        return [
            {
                "KeyId": "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
                "Description": "Demo Key for App Secrets",
                "Enabled": True,
                "KeyRotationEnabled": False  # Key rotation disabled (CIS 2.8)
            }
        ]

    def _collect_lambda(self) -> list:
        return [
            {
                "FunctionName": "demo-public-api-lambda",
                "FunctionArn": f"arn:aws:lambda:us-east-1:{self.account_id}:function:demo-public-api-lambda",
                "Role": f"arn:aws:iam::{self.account_id}:role/Role_CloudSentinelAdmin",  # High-privilege role
                "Runtime": "python3.11",
                "Handler": "index.handler",
                "FunctionUrls": [
                    {
                        "FunctionUrl": "https://randomstring.lambda-url.us-east-1.on.aws/",
                        "AuthType": "NONE"  # Public Lambda URL without auth
                    }
                ],
                "EnvironmentVariables": {
                    "DB_PASSWORD": "SuperSecretDbPassword123!",  # Hardcoded secret in env variables
                    "ENVIRONMENT": "production"
                }
            }
        ]

    def _collect_rds(self) -> list:
        return [
            {
                "DBInstanceIdentifier": "demo-public-rds",
                "DBInstanceClass": "db.t3.micro",
                "Engine": "postgres",
                "PubliclyAccessible": True,  # RDS is public
                "StorageEncrypted": False,  # RDS not encrypted
                "BackupRetentionPeriod": 0,  # No backups enabled
                "KmsKeyId": None
            }
        ]

    def _collect_ebs(self) -> Dict[str, Any]:
        return {
            "volumes": [
                {
                    "VolumeId": "vol-0123456789volume1",
                    "Encrypted": False,  # Unencrypted EBS volume
                    "Size": 20,
                    "State": "in-use",
                    "KmsKeyId": None
                }
            ],
            "snapshots": [
                {
                    "SnapshotId": "snap-0123456789snap1",
                    "VolumeId": "vol-0123456789volume1",
                    "Encrypted": False,  # Unencrypted snapshot
                    "VolumeSize": 20
                }
            ]
        }
