from app.rules.cis_benchmark import RulePublicS3Bucket, RuleRootMfa

def test_rule_public_s3_bucket_evaluation():
    data = {
        "s3": [
            {
                "Name": "public-bucket",
                "PublicAccessBlock": {
                    "BlockPublicAcls": False,
                    "BlockPublicPolicy": False
                },
                "ACL": {},
                "Policy": "",
                "Encryption": {},
                "Versioning": {},
                "Logging": {}
            },
            {
                "Name": "private-bucket",
                "PublicAccessBlock": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True
                },
                "ACL": {},
                "Policy": "",
                "Encryption": {},
                "Versioning": {},
                "Logging": {}
            }
        ]
    }
    
    rule = RulePublicS3Bucket()
    findings = rule.check(data)
    
    assert len(findings) == 1
    assert findings[0]["resource_id"] == "public-bucket"
    assert "public" in findings[0]["evidence"].lower()

def test_rule_root_mfa_evaluation():
    data = {
        "iam": {
            "users": [
                {
                    "UserName": "root",
                    "MFAEnabled": False
                }
            ]
        }
    }
    
    rule = RuleRootMfa()
    findings = rule.check(data)
    
    assert len(findings) == 1
    assert findings[0]["resource_id"] == "arn:aws:iam::account:root"
    assert "disabled" in findings[0]["evidence"].lower()
