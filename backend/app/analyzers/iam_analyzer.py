from typing import Dict, Any, List, Set
import json
import logging

logger = logging.getLogger("cloudsentinel.iam_analyzer")

# Dangerous permissions that can lead to privilege escalation
DANGEROUS_ACTIONS = {
    "iam:PassRole",
    "sts:AssumeRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "iam:AddUserToGroup",
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "cloudformation:CreateStack"
}

class IAMAnalyzer:
    def __init__(self, iam_data: Dict[str, Any]):
        self.iam_data = iam_data
        self.users = iam_data.get("users", [])
        self.roles = iam_data.get("roles", [])
        self.policies = iam_data.get("policies", [])

    def analyze_permissions(self) -> Dict[str, Dict[str, Any]]:
        """
        Analyzes permissions for all users and roles, listing:
        - Allowed actions (resolved)
        - Dangerous actions allowed
        - Whether they have Admin privileges
        """
        analysis = {}

        # 1. Analyze Users
        for u in self.users:
            arn = f"arn:aws:iam::account:user/{u.get('UserName')}"
            u_permissions = self._resolve_entity_permissions(u)
            analysis[arn] = u_permissions

        # 2. Analyze Roles
        for r in self.roles:
            arn = r.get("Arn")
            r_permissions = self._resolve_entity_permissions(r)
            analysis[arn] = r_permissions

        return analysis

    def _resolve_entity_permissions(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        """Resolves attached and inline policies to identify allowed and dangerous actions."""
        allowed_actions: Set[str] = set()
        dangerous_actions: Set[str] = set()
        is_admin = False
        has_wildcard_action = False
        has_wildcard_resource = False

        # Helper to parse policy documents
        def parse_doc(doc: Dict[str, Any]):
            nonlocal is_admin, has_wildcard_action, has_wildcard_resource
            if not doc or not isinstance(doc, dict):
                return
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                effect = stmt.get("Effect")
                action = stmt.get("Action", [])
                resource = stmt.get("Resource", [])

                if effect == "Allow":
                    actions_list = [action] if isinstance(action, str) else action
                    resources_list = [resource] if isinstance(resource, str) else resource

                    # Check for absolute admin
                    if "*" in actions_list and "*" in resources_list:
                        is_admin = True
                        has_wildcard_action = True
                        has_wildcard_resource = True

                    # Add allowed actions and check for dangerous ones
                    for act in actions_list:
                        allowed_actions.add(act)
                        if act == "*":
                            has_wildcard_action = True
                            dangerous_actions.update(DANGEROUS_ACTIONS)
                        else:
                            # Direct check or wildcard prefix match e.g. iam:*
                            if act in DANGEROUS_ACTIONS:
                                dangerous_actions.add(act)
                            elif act.endswith("*"):
                                prefix = act[:-1]
                                for da in DANGEROUS_ACTIONS:
                                    if da.startswith(prefix):
                                        dangerous_actions.add(da)

                    if "*" in resources_list:
                        has_wildcard_resource = True

        # Process Attached Policies
        for p in entity.get("AttachedPolicies", []):
            p_name = p.get("PolicyName")
            if p_name == "AdministratorAccess":
                is_admin = True
                allowed_actions.add("*")
                dangerous_actions.update(DANGEROUS_ACTIONS)
                has_wildcard_action = True
                has_wildcard_resource = True
            
            # Find the policy document in customer policies if present
            found_policy = next((cp for cp in self.policies if cp.get("Arn") == p.get("PolicyArn")), None)
            if found_policy:
                doc = found_policy.get("PolicyVersion", {}).get("Document", {})
                parse_doc(doc)

        # Process Inline Policies
        for p in entity.get("InlinePolicies", []):
            doc = p.get("PolicyDocument", {})
            parse_doc(doc)

        return {
            "name": entity.get("UserName") or entity.get("RoleName"),
            "type": "user" if "UserName" in entity else "role",
            "is_admin": is_admin,
            "has_wildcard_action": has_wildcard_action,
            "has_wildcard_resource": has_wildcard_resource,
            "allowed_actions": sorted(list(allowed_actions)),
            "dangerous_actions": sorted(list(dangerous_actions))
        }
