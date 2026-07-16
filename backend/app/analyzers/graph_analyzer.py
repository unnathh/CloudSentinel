import networkx as nx
import logging
from typing import Dict, Any, List, Tuple
from app.analyzers.iam_analyzer import IAMAnalyzer, DANGEROUS_ACTIONS

logger = logging.getLogger("cloudsentinel.graph_analyzer")

class GraphAnalyzer:
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.iam_data = data.get("iam", {})
        self.users = self.iam_data.get("users", [])
        self.roles = self.iam_data.get("roles", [])
        self.policies = self.iam_data.get("policies", [])
        self.ec2_instances = data.get("ec2", [])
        self.lambda_funcs = data.get("lambda", [])
        self.iam_analyzer = IAMAnalyzer(self.iam_data)

    def build_graph(self) -> nx.DiGraph:
        """Constructs a directed graph representing IAM structure and security transitions."""
        G = nx.DiGraph()
        
        # 1. Resolve IAM Entity Permissions
        entity_permissions = self.iam_analyzer.analyze_permissions()

        # 2. Add IAM User Nodes
        for u in self.users:
            name = u.get("UserName")
            u_arn = f"arn:aws:iam::account:user/{name}"
            perm_info = entity_permissions.get(u_arn, {})
            G.add_node(
                u_arn,
                id=u_arn,
                label=name,
                type="user",
                is_admin=perm_info.get("is_admin", False),
                dangerous_actions=perm_info.get("dangerous_actions", []),
                risk_score=90.0 if perm_info.get("is_admin") else (50.0 if perm_info.get("dangerous_actions") else 10.0)
            )

        # 3. Add IAM Role Nodes
        for r in self.roles:
            name = r.get("RoleName")
            r_arn = r.get("Arn")
            perm_info = entity_permissions.get(r_arn, {})
            
            # Check if trust policy allows anyone specific to assume this role
            G.add_node(
                r_arn,
                id=r_arn,
                label=name,
                type="role",
                is_admin=perm_info.get("is_admin", False),
                dangerous_actions=perm_info.get("dangerous_actions", []),
                risk_score=95.0 if perm_info.get("is_admin") else (60.0 if perm_info.get("dangerous_actions") else 15.0)
            )

            # Analyze Assume Role Trust Policy
            trust_doc = r.get("AssumeRolePolicyDocument", {})
            statements = trust_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                effect = stmt.get("Effect")
                principal = stmt.get("Principal", {})
                action = stmt.get("Action", [])

                if effect == "Allow" and "sts:AssumeRole" in (action if isinstance(action, list) else [action]):
                    # Check AWS trust relationship (e.g. User ARN can assume Role)
                    aws_principal = principal.get("AWS")
                    if aws_principal:
                        principals_list = [aws_principal] if isinstance(aws_principal, str) else aws_principal
                        for pr in principals_list:
                            # Add assume role edge from principal to role
                            # Avoid self-loops or wildcard principals for simple demo pathing
                            if pr != "*" and pr != r_arn:
                                G.add_edge(
                                    pr,
                                    r_arn,
                                    label="sts:AssumeRole",
                                    type="assume_role",
                                    description=f"Trust policy allows assumption by principal {pr.split('/')[-1]}"
                                )

        # 4. Add EC2 Instance Nodes & compute Instance Profile assumptions
        for inst in self.ec2_instances:
            inst_id = inst.get("InstanceId")
            profile = inst.get("IamInstanceProfile", {})
            G.add_node(
                inst_id,
                id=inst_id,
                label=f"EC2: {inst_id}",
                type="ec2",
                risk_score=40.0
            )

            if profile:
                profile_arn = profile.get("Arn", "")
                # An EC2 instance profile contains a role. Find role in data matching profile_arn or similar
                # Simple demo logic: link EC2 to its role via assume_role
                role_name = profile_arn.split("/")[-1] if profile_arn else ""
                role_node = next((r.get("Arn") for r in self.roles if r.get("RoleName") == role_name or role_name in r.get("Arn")), None)
                
                if role_node:
                    G.add_edge(
                        inst_id,
                        role_node,
                        label="EC2 Instance Profile",
                        type="profile",
                        description=f"EC2 instance runs with permissions of {role_name}"
                    )

        # 5. Add Lambda Function Nodes
        for f in self.lambda_funcs:
            f_arn = f.get("FunctionArn")
            f_name = f.get("FunctionName")
            role_arn = f.get("Role")
            G.add_node(
                f_arn,
                id=f_arn,
                label=f"Lambda: {f_name}",
                type="lambda",
                risk_score=35.0
            )
            if role_arn:
                G.add_edge(
                    f_arn,
                    role_arn,
                    label="Lambda Execution Role",
                    type="execution_role",
                    description=f"Lambda function executes with permissions of {role_arn.split('/')[-1]}"
                )

        # 6. Analyze privilege escalation paths & add exploit edges
        # We process each user/role node to see if they possess capabilities to assume another role indirectly.
        nodes = list(G.nodes(data=True))
        for node_id, node_attrs in nodes:
            dang_actions = node_attrs.get("dangerous_actions", [])
            node_type = node_attrs.get("type")
            if not dang_actions or node_type not in ["user", "role"]:
                continue

            # Case A: PassRole + RunInstances
            if "iam:PassRole" in dang_actions and "ec2:RunInstances" in dang_actions:
                # User can launch an EC2 instance and attach ANY role.
                # In real AWS, they could attach any role that has a trust policy with EC2.
                # Let's add exploit edges to all roles trusted by EC2 service.
                for target_id, target_attrs in nodes:
                    if target_attrs.get("type") == "role":
                        # Check if role can be assumed by EC2 service
                        role_data = next((r for r in self.roles if r.get("Arn") == target_id), None)
                        if role_data:
                            trust_doc = role_data.get("AssumeRolePolicyDocument", {})
                            statements = trust_doc.get("Statement", [])
                            if isinstance(statements, dict):
                                statements = [statements]
                            
                            is_ec2_trusted = False
                            for stmt in statements:
                                service = stmt.get("Principal", {}).get("Service", [])
                                service_list = [service] if isinstance(service, str) else service
                                if "ec2.amazonaws.com" in service_list:
                                    is_ec2_trusted = True
                                    break
                            
                            if is_ec2_trusted:
                                # Edge representing privilege escalation
                                G.add_edge(
                                    node_id,
                                    target_id,
                                    label="PassRole + RunInstances",
                                    type="exploit_passrole",
                                    description=(
                                        f"Escalation: {node_attrs.get('label')} can run an EC2 instance with "
                                        f"role {target_attrs.get('label')} and extract credentials via metadata service (IMDS)."
                                    )
                                )

            # Case B: CreatePolicyVersion self-escalation
            if "iam:CreatePolicyVersion" in dang_actions:
                # User can modify a policy. If they can modify their own policy or another they are attached to,
                # they can add 'AdministratorAccess' to escalate to admin.
                G.add_edge(
                    node_id,
                    node_id,
                    label="CreatePolicyVersion (Self-Escalate)",
                    type="exploit_policy",
                    description=f"Self-Escalation: {node_attrs.get('label')} can update their own policy version to grant administrator permissions."
                )

            # Case C: CreateAccessKey on users
            if "iam:CreateAccessKey" in dang_actions:
                # Can create access key for other users. Let's add exploit paths to all other users
                for target_id, target_attrs in nodes:
                    if target_attrs.get("type") == "user" and target_id != node_id:
                        G.add_edge(
                            node_id,
                            target_id,
                            label="iam:CreateAccessKey",
                            type="exploit_key",
                            description=f"Privilege Escalation: Can create API access keys for target user {target_attrs.get('label')}."
                        )

            # Case D: UpdateAssumeRolePolicy (trust relationship modification)
            if "iam:UpdateAssumeRolePolicy" in dang_actions:
                # Can modify who is allowed to assume a role. Can make themselves the trusted principal.
                for target_id, target_attrs in nodes:
                    if target_attrs.get("type") == "role" and target_id != node_id:
                        G.add_edge(
                            node_id,
                            target_id,
                            label="iam:UpdateAssumeRolePolicy",
                            type="exploit_trust",
                            description=f"Privilege Escalation: Can update trust policy of role {target_attrs.get('label')} to allow assumption."
                        )

        return G

    def find_attack_paths(self, G: nx.DiGraph) -> List[Dict[str, Any]]:
        """Scans the graph for paths from low-privilege users to admin-level nodes."""
        attack_paths = []
        
        # 1. Identify low privilege users (entry points)
        entry_points = [node for node, attr in G.nodes(data=True) if attr.get("type") == "user" and not attr.get("is_admin", False)]
        
        # 2. Identify high privilege roles/users (target points)
        targets = [node for node, attr in G.nodes(data=True) if attr.get("is_admin", False)]

        # 3. Perform path finding
        for entry in entry_points:
            for target in targets:
                if entry == target:
                    continue
                try:
                    # Find all simple paths up to length 4 to capture intermediate nodes (e.g. EC2, trust policies)
                    paths = list(nx.all_simple_paths(G, source=entry, target=target, cutoff=4))
                    for path in paths:
                        # Construct narrative explanation of the path
                        steps = []
                        for i in range(len(path) - 1):
                            edge_data = G.get_edge_data(path[i], path[i+1])
                            label = edge_data.get("label", "Allows transition")
                            desc = edge_data.get("description", "")
                            src_name = G.nodes[path[i]].get("label")
                            tgt_name = G.nodes[path[i+1]].get("label")
                            steps.append(f"Step {i+1}: {src_name} triggers '{label}' to transition to {tgt_name}. ({desc})")

                        path_name = f"Privilege Escalation: {G.nodes[entry].get('label')} -> {G.nodes[target].get('label')}"
                        attack_paths.append({
                            "path_name": path_name,
                            "node_chain": path,
                            "risk_level": "Critical",
                            "description": "\n".join(steps)
                        })
                except nx.NetworkXNoPath:
                    continue
                except Exception as e:
                    logger.error(f"Error tracing path from {entry} to {target}: {e}")
                    
        return attack_paths

    def serialize_to_cytoscape(self, G: nx.DiGraph) -> Dict[str, List[Dict[str, Any]]]:
        """Serializes the NetworkX graph into elements readable by Cytoscape.js."""
        elements = {"nodes": [], "edges": []}
        
        # Serialize Nodes
        for node_id, attrs in G.nodes(data=True):
            elements["nodes"].append({
                "data": {
                    "id": node_id,
                    "label": attrs.get("label", node_id),
                    "type": attrs.get("type", "unknown"),
                    "is_admin": attrs.get("is_admin", False),
                    "risk_score": attrs.get("risk_score", 10.0),
                    "dangerous_actions": attrs.get("dangerous_actions", [])
                }
            })

        # Serialize Edges
        edge_counter = 0
        for src, dst, attrs in G.edges(data=True):
            edge_counter += 1
            elements["edges"].append({
                "data": {
                    "id": f"edge_{edge_counter}",
                    "source": src,
                    "target": dst,
                    "label": attrs.get("label", ""),
                    "type": attrs.get("type", "unknown"),
                    "description": attrs.get("description", "")
                }
            })
            
        return elements
