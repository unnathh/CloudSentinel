import React, { useState, useEffect } from 'react';
import { useActiveAccount } from '../contexts/AccountContext';
import { findingsApi } from '../services/api';
import { Finding } from '../types';
import { 
  Search, Filter, ShieldAlert, X, Copy, Check, 
  ChevronRight, AlertOctagon, Terminal, FileCode 
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const Findings: React.FC = () => {
  const { latestScan } = useActiveAccount();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [serviceFilter, setServiceFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('open');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedText, setCopiedText] = useState<'cli' | 'tf' | null>(null);

  const loadFindings = async () => {
    if (!latestScan) return;
    setIsLoading(true);
    try {
      const data = await findingsApi.getFindings({
        scan_id: latestScan.id,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        service: serviceFilter === 'ALL' ? undefined : serviceFilter,
        status: statusFilter === 'ALL' ? undefined : statusFilter,
      });
      setFindings(data);
      // Auto update active selection detail panel if open
      if (selectedFinding) {
        const updated = data.find((f: any) => f.id === selectedFinding.id);
        setSelectedFinding(updated || null);
      }
    } catch (error) {
      console.error('Failed to load findings:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [latestScan, severityFilter, serviceFilter, statusFilter]);

  const handleUpdateStatus = async (findingId: number, nextStatus: string) => {
    try {
      await findingsApi.updateFindingStatus(findingId, nextStatus);
      await loadFindings();
    } catch (error) {
      console.error('Failed to update status:', error);
    }
  };

  // Copy code utility
  const copyToClipboard = (text: string, type: 'cli' | 'tf') => {
    navigator.clipboard.writeText(text);
    setCopiedText(type);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Generate dynamic CLI & Terraform codes based on finding rule
  const getRemediationCodes = (finding: Finding) => {
    const resId = finding.resource_id.split('/').pop() || 'RESOURCE_ID';
    
    switch (finding.rule_id) {
      case 'CIS-2.1.1': // Public S3
        return {
          cli: `aws s3api put-public-access-block \\\n  --bucket ${resId} \\\n  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`,
          tf: `resource "aws_s3_bucket_public_access_block" "remediation" {\n  bucket = "${resId}"\n\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`
        };
      case 'CIS-2.1.2': // S3 Encryption
        return {
          cli: `aws s3api put-bucket-encryption \\\n  --bucket ${resId} \\\n  --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'`,
          tf: `resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {\n  bucket = "${resId}"\n\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}`
        };
      case 'CIS-4.1': // Security Group 22
      case 'CIS-4.2': // Security Group 3389
        return {
          cli: `aws ec2 revoke-security-group-ingress \\\n  --group-id ${resId} \\\n  --protocol tcp \\\n  --port ${finding.rule_id === 'CIS-4.1' ? '22' : '3389'} \\\n  --cidr 0.0.0.0/0`,
          tf: `# Replace wildcard rule in security group configuration\nresource "aws_security_group_rule" "ssh_ingress_restricted" {\n  type              = "ingress"\n  from_port         = ${finding.rule_id === 'CIS-4.1' ? '22' : '3389'}\n  to_port           = ${finding.rule_id === 'CIS-4.1' ? '22' : '3389'}\n  protocol          = "tcp"\n  cidr_blocks       = ["YOUR_OFFICE_VPN_IP/32"] # Restricted\n  security_group_id = "${resId}"\n}`
        };
      case 'CIS-2.8': // KMS Rotation
        return {
          cli: `aws kms enable-key-rotation \\\n  --key-id ${resId}`,
          tf: `resource "aws_kms_key" "remediation" {\n  description             = "KMS Key"\n  deletion_window_in_days = 10\n  enable_key_rotation     = true # Set rotation enabled\n}`
        };
      case 'RULE-RDS-PUBLIC': // RDS Public
        return {
          cli: `aws rds modify-db-instance \\\n  --db-instance-identifier ${resId} \\\n  --no-publicly-accessible \\\n  --apply-immediately`,
          tf: `# Set publicly_accessible to false in aws_db_instance\nresource "aws_db_instance" "remediation" {\n  identifier          = "${resId}"\n  # ... other configurations\n  publicly_accessible = false\n}`
        };
      default:
        return {
          cli: `# Consult AWS security documentation for rule ID ${finding.rule_id}\naws secure-remediate --resource ${resId}`,
          tf: `# No template config generated for ${finding.rule_id}.\n# Use least-privilege standards.`
        };
    }
  };

  // Filter list by search term
  const filteredFindings = findings.filter(f => 
    f.title.toLowerCase().includes(search.toLowerCase()) ||
    f.resource_id.toLowerCase().includes(search.toLowerCase()) ||
    f.rule_id.toLowerCase().includes(search.toLowerCase())
  );

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'Critical': return 'bg-rose-500/10 border-rose-500/30 text-cyber-critical';
      case 'High': return 'bg-orange-500/10 border-orange-500/30 text-cyber-high';
      case 'Medium': return 'bg-yellow-500/10 border-yellow-500/30 text-cyber-medium';
      case 'Low': return 'bg-blue-500/10 border-blue-500/30 text-cyber-low';
      default: return 'bg-cyan-500/10 border-cyan-500/30 text-cyber-info';
    }
  };

  return (
    <div className="space-y-6 relative min-h-[80vh]">
      {/* Title */}
      <div>
        <h2 className="text-2xl font-bold text-white tracking-wide">Security Posture Findings</h2>
        <p className="text-sm text-cyber-muted mt-1">Audit results of security checks and vulnerability states.</p>
      </div>

      {/* Filter panel */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-4 flex flex-col md:flex-row items-center justify-between gap-4 shadow-lg">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-cyber-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search finding, ID, resource..."
            className="w-full bg-slate-950 border border-cyber-border rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-rose-500/40"
          />
        </div>

        {/* Dropdowns */}
        <div className="flex flex-wrap items-center gap-4 w-full md:w-auto">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-cyber-border rounded-lg text-xs text-white px-2 py-1.5 focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider">Service:</span>
            <select
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
              className="bg-slate-950 border border-cyber-border rounded-lg text-xs text-white px-2 py-1.5 focus:outline-none"
            >
              <option value="ALL">All Services</option>
              <option value="S3">S3</option>
              <option value="EC2">EC2</option>
              <option value="IAM">IAM</option>
              <option value="VPC">VPC</option>
              <option value="CloudTrail">CloudTrail</option>
              <option value="KMS">KMS</option>
              <option value="Lambda">Lambda</option>
              <option value="RDS">RDS</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-cyber-border rounded-lg text-xs text-white px-2 py-1.5 focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="ignored">Ignored</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden shadow-lg">
        {isLoading ? (
          <div className="p-12 flex flex-col items-center justify-center">
            <div className="w-8 h-8 border-4 border-rose-500/20 border-t-cyber-critical rounded-full animate-spin mb-3" />
            <span className="text-xs text-cyber-muted">Loading finding list...</span>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-16 text-center text-xs text-cyber-muted">
            No security findings matching active filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border bg-slate-950/40 text-[10px] font-bold text-cyber-muted uppercase tracking-wider">
                  <th className="py-4 px-6">Rule / Finding</th>
                  <th className="py-4 px-6">Severity</th>
                  <th className="py-4 px-6">Service</th>
                  <th className="py-4 px-6">Resource ID</th>
                  <th className="py-4 px-6">Status</th>
                  <th className="py-4 px-6"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 text-xs font-medium">
                {filteredFindings.map((finding) => (
                  <tr 
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    className="hover:bg-slate-900/20 cursor-pointer transition-colors"
                  >
                    <td className="py-4 px-6">
                      <p className="font-semibold text-white truncate max-w-[240px]">{finding.title}</p>
                      <p className="text-[10px] text-cyber-muted mt-0.5">{finding.rule_id}</p>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-block px-2.5 py-1 text-[10px] font-bold rounded-lg border uppercase tracking-wider ${getSeverityBadge(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-slate-300">{finding.service}</td>
                    <td className="py-4 px-6 font-mono text-cyber-muted truncate max-w-[200px]" title={finding.resource_id}>
                      {finding.resource_id.split('/').pop()}
                    </td>
                    <td className="py-4 px-6">
                      <span className={`
                        capitalize text-[10px] font-semibold px-2 py-0.5 rounded
                        ${finding.status === 'open' ? 'text-cyber-critical bg-rose-500/10' : (finding.status === 'resolved' ? 'text-cyber-success bg-emerald-500/10' : 'text-cyber-muted bg-slate-800')}
                      `}>
                        {finding.status}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-right">
                      <ChevronRight size={16} className="text-cyber-muted inline" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-out drawer detail panel */}
      <AnimatePresence>
        {selectedFinding && (
          <>
            {/* Overlay background */}
            <motion.div 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 0.5 }} 
              exit={{ opacity: 0 }}
              onClick={() => setSelectedFinding(null)}
              className="fixed inset-0 bg-black z-40 cursor-pointer"
            />
            {/* Drawer */}
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'tween', duration: 0.3 }}
              className="fixed inset-y-0 right-0 w-full max-w-2xl bg-cyber-card border-l border-cyber-border z-50 flex flex-col shadow-2xl h-screen overflow-hidden"
            >
              {/* Drawer Header */}
              <div className="p-6 border-b border-cyber-border flex items-center justify-between bg-slate-950/40">
                <div className="min-w-0">
                  <span className={`inline-block px-2 py-0.5 text-[9px] font-bold border uppercase tracking-wider rounded ${getSeverityBadge(selectedFinding.severity)}`}>
                    {selectedFinding.severity}
                  </span>
                  <h3 className="text-base font-bold text-white mt-2 truncate" title={selectedFinding.title}>{selectedFinding.title}</h3>
                  <p className="text-[10px] text-cyber-muted mt-0.5">{selectedFinding.rule_id} | AWS Region: {selectedFinding.region}</p>
                </div>
                <button 
                  onClick={() => setSelectedFinding(null)}
                  className="p-2 hover:bg-slate-800 text-cyber-muted hover:text-white rounded-lg transition-colors shrink-0"
                >
                  <X size={20} />
                </button>
              </div>

              {/* Drawer Body Scrollable */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6">
                {/* Status Toggle Card */}
                <div className="bg-slate-950/60 border border-cyber-border rounded-xl p-4 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-cyber-muted font-bold uppercase tracking-wider block">Finding Status:</span>
                    <span className="capitalize text-xs font-semibold text-white mt-1 inline-block">{selectedFinding.status}</span>
                  </div>
                  <div className="flex gap-2">
                    {selectedFinding.status !== 'resolved' && (
                      <button 
                        onClick={() => handleUpdateStatus(selectedFinding.id, 'resolved')}
                        className="px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-cyber-success rounded-lg text-xs font-semibold transition-colors"
                      >
                        Resolve
                      </button>
                    )}
                    {selectedFinding.status !== 'ignored' && (
                      <button 
                        onClick={() => handleUpdateStatus(selectedFinding.id, 'ignored')}
                        className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-cyber-border text-cyber-muted rounded-lg text-xs font-semibold transition-colors"
                      >
                        Snooze / Ignore
                      </button>
                    )}
                    {selectedFinding.status !== 'open' && (
                      <button 
                        onClick={() => handleUpdateStatus(selectedFinding.id, 'open')}
                        className="px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-cyber-critical rounded-lg text-xs font-semibold transition-colors"
                      >
                        Re-open
                      </button>
                    )}
                  </div>
                </div>

                {/* Description */}
                <div>
                  <h4 className="text-xs font-bold text-cyber-muted uppercase tracking-wider mb-2">Description</h4>
                  <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/30 border border-cyber-border/40 p-3 rounded-lg">{selectedFinding.description}</p>
                </div>

                {/* Evidence */}
                {selectedFinding.evidence && (
                  <div>
                    <h4 className="text-xs font-bold text-cyber-muted uppercase tracking-wider mb-2">Collected Evidence</h4>
                    <pre className="text-[10px] font-mono text-cyan-400 bg-slate-950 p-4 rounded-lg overflow-x-auto border border-cyber-border max-h-[160px]">
                      {selectedFinding.evidence}
                    </pre>
                  </div>
                )}

                {/* MITRE ATT&CK Mapping */}
                {selectedFinding.mitre_technique_id && (
                  <div className="bg-orange-500/5 border border-orange-500/15 rounded-xl p-4 flex items-start gap-3">
                    <AlertOctagon size={18} className="text-cyber-high shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-xs font-bold text-white">MITRE ATT&CK Mapping</h4>
                      <p className="text-xs text-slate-300 mt-1">
                        <span className="font-semibold text-cyber-high">{selectedFinding.mitre_technique_id}</span> – {selectedFinding.mitre_technique_name}
                      </p>
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                <div>
                  <h4 className="text-xs font-bold text-cyber-muted uppercase tracking-wider mb-2">Actionable Recommendations</h4>
                  <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/30 border border-cyber-border/40 p-3 rounded-lg">{selectedFinding.recommendation}</p>
                </div>

                {/* Remediation code blocks */}
                <div>
                  <h4 className="text-xs font-bold text-cyber-muted uppercase tracking-wider mb-3">Remediation Code Snippets</h4>
                  
                  {/* CLI command */}
                  <div className="bg-slate-950 border border-cyber-border rounded-xl overflow-hidden mb-4">
                    <div className="flex items-center justify-between bg-slate-900/60 px-4 py-2 border-b border-cyber-border">
                      <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider flex items-center gap-1"><Terminal size={12} /> AWS CLI command</span>
                      <button 
                        onClick={() => copyToClipboard(getRemediationCodes(selectedFinding).cli, 'cli')}
                        className="text-cyber-muted hover:text-white transition-colors"
                      >
                        {copiedText === 'cli' ? <Check size={12} className="text-cyber-success" /> : <Copy size={12} />}
                      </button>
                    </div>
                    <pre className="p-4 text-[10px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
                      {getRemediationCodes(selectedFinding).cli}
                    </pre>
                  </div>

                  {/* Terraform block */}
                  <div className="bg-slate-950 border border-cyber-border rounded-xl overflow-hidden">
                    <div className="flex items-center justify-between bg-slate-900/60 px-4 py-2 border-b border-cyber-border">
                      <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider flex items-center gap-1"><FileCode size={12} /> Terraform Block (HCL)</span>
                      <button 
                        onClick={() => copyToClipboard(getRemediationCodes(selectedFinding).tf, 'tf')}
                        className="text-cyber-muted hover:text-white transition-colors"
                      >
                        {copiedText === 'tf' ? <Check size={12} className="text-cyber-success" /> : <Copy size={12} />}
                      </button>
                    </div>
                    <pre className="p-4 text-[10px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
                      {getRemediationCodes(selectedFinding).tf}
                    </pre>
                  </div>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
};
