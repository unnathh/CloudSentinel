export interface User {
  id: number;
  email: string;
  role: 'Admin' | 'Analyst' | 'Viewer';
  is_active: boolean;
  created_at: string;
}

export interface AWSAccount {
  id: number;
  name: string;
  account_id: string;
  auth_type: 'keys' | 'role';
  role_arn?: string;
  region: string;
  last_scanned?: string;
  created_at: string;
}

export interface ScanResult {
  id: number;
  account_id: number;
  started_at: string;
  completed_at?: string;
  status: 'running' | 'completed' | 'failed';
  risk_score: number;
  compliance_score: number;
}

export interface Finding {
  id: number;
  scan_id: number;
  rule_id: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  service: string;
  resource_id: string;
  region: string;
  description: string;
  evidence?: string;
  recommendation: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  status: 'open' | 'resolved' | 'ignored';
  created_at: string;
}

export interface ResourceInventory {
  id: number;
  scan_id: number;
  service: string;
  resource_type: string;
  resource_id: string;
  resource_name: string;
  configuration: any;
}

export interface AttackPath {
  id: number;
  scan_id: number;
  path_name: string;
  node_chain: string[];
  risk_level: string;
  description: string;
}
