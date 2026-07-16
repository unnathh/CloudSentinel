from app.analyzers.graph_analyzer import GraphAnalyzer

def test_graph_attack_path_finding():
    # Setup data with a clear escalation path: dev-user -> PassRole + RunInstances -> Role_CloudSentinelAdmin (is_admin)
    data = {
        "iam": {
            "users": [
                {
                    "UserName": "dev-user",
                    "AttachedPolicies": [
                        {
                            "PolicyName": "Policy_DevDeploy",
                            "PolicyArn": "arn:aws:iam::123456789012:policy/Policy_DevDeploy"
                        }
                    ],
                    "InlinePolicies": []
                }
            ],
            "roles": [
                {
                    "RoleName": "Role_CloudSentinelAdmin",
                    "Arn": "arn:aws:iam::123456789012:role/Role_CloudSentinelAdmin",
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
                }
            ],
            "policies": [
                {
                    "PolicyName": "Policy_DevDeploy",
                    "Arn": "arn:aws:iam::123456789012:policy/Policy_DevDeploy",
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
            ]
        },
        "ec2": []
    }
    
    analyzer = GraphAnalyzer(data)
    G = analyzer.build_graph()
    
    # Assert nodes exist
    assert "arn:aws:iam::account:user/dev-user" in G
    assert "arn:aws:iam::123456789012:role/Role_CloudSentinelAdmin" in G
    
    # Assert the exploit edge is created
    assert G.has_edge("arn:aws:iam::account:user/dev-user", "arn:aws:iam::123456789012:role/Role_CloudSentinelAdmin")
    
    paths = analyzer.find_attack_paths(G)
    assert len(paths) == 1
    assert "dev-user" in paths[0]["path_name"]
    assert "Role_CloudSentinelAdmin" in paths[0]["path_name"]
    assert paths[0]["risk_level"] == "Critical"
