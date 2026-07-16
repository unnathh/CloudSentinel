from app.analyzers.iam_analyzer import IAMAnalyzer

def test_iam_analyzer_wildcard_detection():
    iam_data = {
        "users": [
            {
                "UserName": "wildcard-user",
                "AttachedPolicies": [],
                "InlinePolicies": [
                    {
                        "PolicyName": "WildcardPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*"
                                }
                            ]
                        }
                    }
                ]
            }
        ],
        "roles": [],
        "policies": []
    }
    
    analyzer = IAMAnalyzer(iam_data)
    results = analyzer.analyze_permissions()
    
    arn = "arn:aws:iam::account:user/wildcard-user"
    assert arn in results
    assert results[arn]["is_admin"] is True
    assert results[arn]["has_wildcard_action"] is True
    assert "iam:PassRole" in results[arn]["dangerous_actions"]
    assert "ec2:RunInstances" in results[arn]["dangerous_actions"]

def test_iam_analyzer_specific_privilege():
    iam_data = {
        "users": [],
        "roles": [
            {
                "RoleName": "operator-role",
                "Arn": "arn:aws:iam::123456789012:role/operator-role",
                "AttachedPolicies": [],
                "InlinePolicies": [
                    {
                        "PolicyName": "LimitedPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "iam:PassRole",
                                        "ec2:RunInstances"
                                    ],
                                    "Resource": "*"
                                }
                            ]
                        }
                    }
                ]
            }
        ],
        "policies": []
    }
    
    analyzer = IAMAnalyzer(iam_data)
    results = analyzer.analyze_permissions()
    
    arn = "arn:aws:iam::123456789012:role/operator-role"
    assert arn in results
    assert results[arn]["is_admin"] is False
    assert "iam:PassRole" in results[arn]["dangerous_actions"]
    assert "ec2:RunInstances" in results[arn]["dangerous_actions"]
    assert len(results[arn]["dangerous_actions"]) == 2
