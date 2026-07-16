from typing import Dict, Any, List

class SecurityRule:
    rule_id: str = ""
    name: str = ""
    severity: str = "Low"  # Critical, High, Medium, Low, Info
    category: str = "General"  # S3, EC2, IAM, KMS, Lambda, RDS, VPC, CloudTrail
    description: str = ""
    remediation: str = ""
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    reference: str = "CIS AWS Foundations Benchmark"

    def check(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs the check on the complete resource dataset.
        Returns a list of dict objects describing resource findings:
        [
            {
                "resource_id": str,
                "region": str,
                "evidence": str,
                "description": str (optional override)
            }
        ]
        """
        raise NotImplementedError
