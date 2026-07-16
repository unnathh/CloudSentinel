from typing import List, Dict, Any
import logging
from app.rules.base import SecurityRule
from app.rules.cis_benchmark import (
    RuleRootMfa, RuleRootKeys, RulePasswordPolicy, RuleUserMfa,
    RuleUnusedAccessKeys, RuleWildcardPolicies, RuleAdminAttached,
    RulePublicS3Bucket, RuleS3Encryption, RuleS3Logging, RuleS3Versioning,
    RuleSecurityGroupOpenSSH, RuleSecurityGroupOpenRDP, RuleSecurityGroupOpenHttp,
    RuleUnencryptedEBS, RuleCloudTrailDisabled, RuleCloudTrailNotMultiRegion,
    RuleKmsRotationDisabled, RulePublicRDS, RulePublicLambda
)

logger = logging.getLogger("cloudsentinel.rules")

# Instantiate all defined rules
ALL_RULES: List[SecurityRule] = [
    RuleRootMfa(),
    RuleRootKeys(),
    RulePasswordPolicy(),
    RuleUserMfa(),
    RuleUnusedAccessKeys(),
    RuleWildcardPolicies(),
    RuleAdminAttached(),
    RulePublicS3Bucket(),
    RuleS3Encryption(),
    RuleS3Logging(),
    RuleS3Versioning(),
    RuleSecurityGroupOpenSSH(),
    RuleSecurityGroupOpenRDP(),
    RuleSecurityGroupOpenHttp(),
    RuleUnencryptedEBS(),
    RuleCloudTrailDisabled(),
    RuleCloudTrailNotMultiRegion(),
    RuleKmsRotationDisabled(),
    RulePublicRDS(),
    RulePublicLambda()
]

def run_all_rules(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    for rule in ALL_RULES:
        try:
            results = rule.check(data)
            for res in results:
                # Merge rule metadata and specific resource evaluation finding
                finding = {
                    "rule_id": rule.rule_id,
                    "title": rule.name,
                    "severity": rule.severity,
                    "service": rule.category,
                    "resource_id": res["resource_id"],
                    "region": res.get("region", "global"),
                    "description": res.get("description", rule.description),
                    "evidence": res.get("evidence", ""),
                    "recommendation": rule.remediation,
                    "mitre_technique_id": rule.mitre_technique_id,
                    "mitre_technique_name": rule.mitre_technique_name,
                    "status": "open"
                }
                findings.append(finding)
        except Exception as e:
            logger.error(f"Rule {rule.rule_id} ({rule.name}) crashed during execution: {e}", exc_info=True)
    return findings
