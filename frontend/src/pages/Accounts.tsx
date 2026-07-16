import React, { useState, useEffect } from 'react';
import { useActiveAccount } from '../contexts/AccountContext';
import { accountsApi } from '../services/api';
import { AWSAccount, ScanResult } from '../types';
import { 
  Cloud, Plus, Trash2, Play, RefreshCw, 
  CheckCircle, AlertCircle, Calendar, ShieldCheck 
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export const Accounts: React.FC = () => {
  const { user } = useAuth();
  const { accounts, selectedAccount, latestScan, selectAccount, refresh } = useActiveAccount();
  
  // Form states
  const [name, setName] = useState('');
  const [accountId, setAccountId] = useState('');
  const [authType, setAuthType] = useState<'keys' | 'role'>('keys');
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [region, setRegion] = useState('us-east-1');
  
  const [formOpen, setFormOpen] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  // Selected account scan history states
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const loadScanHistory = async () => {
    if (!selectedAccount) return;
    setHistoryLoading(true);
    try {
      const data = await accountsApi.getScans(selectedAccount.id);
      setScanHistory(data);
    } catch (err) {
      console.error('Failed to load scan history:', err);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadScanHistory();
  }, [selectedAccount, latestScan]);

  // Poller setup to check if scans are running
  useEffect(() => {
    let intervalId: any;
    const isScanRunning = scanHistory.some(s => s.status === 'running');
    
    if (isScanRunning && selectedAccount) {
      intervalId = setInterval(async () => {
        const data = await accountsApi.getScans(selectedAccount.id);
        setScanHistory(data);
        // Also sync the global account context to update the top bar state
        refresh();
      }, 4000);
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [scanHistory, selectedAccount]);

  const handleRegisterAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsLoading(true);

    try {
      const payload = {
        name,
        account_id: accountId,
        auth_type: authType,
        access_key_id: authType === 'keys' ? accessKeyId : undefined,
        secret_access_key: authType === 'keys' ? secretAccessKey : undefined,
        role_arn: authType === 'role' ? roleArn : undefined,
        region,
      };

      await accountsApi.createAccount(payload);
      setSuccess('AWS account successfully connected!');
      // Reset form
      setName('');
      setAccountId('');
      setAccessKeyId('');
      setSecretAccessKey('');
      setRoleArn('');
      setFormOpen(false);
      
      // Reload accounts lists
      await refresh();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to connect AWS account. Verify configurations.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteAccount = async (acctId: number) => {
    if (!window.confirm('Are you sure you want to delete this AWS account connection? This will wipe all historical scan inventory and findings.')) {
      return;
    }
    try {
      await accountsApi.deleteAccount(acctId);
      await refresh();
    } catch (err) {
      console.error('Delete failed:', err);
    }
  };

  const handleTriggerScan = async (acctId: number) => {
    try {
      await accountsApi.triggerScan(acctId);
      await refresh();
      await loadScanHistory();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to trigger scan.');
    }
  };

  const canEdit = user?.role === 'Admin' || user?.role === 'Analyst';

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-wide">AWS Cloud Connection Management</h2>
          <p className="text-sm text-cyber-muted mt-1">Configure and scan AWS accounts using read-only IAM connections.</p>
        </div>
        {canEdit && !formOpen && (
          <button 
            onClick={() => setFormOpen(true)}
            className="flex items-center gap-2 px-4 py-2.5 bg-cyber-critical hover:bg-rose-600 rounded-xl text-xs font-bold text-white shadow-lg shadow-rose-500/10 hover:shadow-rose-500/25 transition-all"
          >
            <Plus size={16} /> Link AWS Account
          </button>
        )}
      </div>

      {/* Register Form */}
      {formOpen && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-xl space-y-6 max-w-2xl">
          <div className="flex items-center justify-between border-b border-cyber-border/40 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Cloud size={16} className="text-cyber-critical" /> Connect New AWS Account
            </h3>
            <button onClick={() => setFormOpen(false)} className="text-xs text-cyber-muted hover:text-white uppercase">Cancel</button>
          </div>

          {error && (
            <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-cyber-critical text-xs flex items-center gap-3">
              <AlertCircle size={16} className="shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleRegisterAccount} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">Account Alias Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="production-aws-main"
                  className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-2 text-xs text-white placeholder-slate-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">AWS Account ID (12 digits)</label>
                <input
                  type="text"
                  required
                  pattern="\d{12}"
                  maxLength={12}
                  value={accountId}
                  onChange={(e) => setAccountId(e.target.value)}
                  placeholder="123456789012"
                  className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-2 text-xs text-white placeholder-slate-600 focus:outline-none"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">Default Region to Scan</label>
                <select
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  className="w-full bg-slate-950 border border-cyber-border rounded-xl px-3 py-2.5 text-xs text-white focus:outline-none"
                >
                  <option value="us-east-1">US East (N. Virginia)</option>
                  <option value="us-west-2">US West (Oregon)</option>
                  <option value="eu-west-1">Europe (Ireland)</option>
                  <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">Authentication Mechanism</label>
                <div className="flex gap-4 mt-2">
                  <label className="flex items-center gap-2 text-xs text-cyber-text cursor-pointer">
                    <input
                      type="radio"
                      checked={authType === 'keys'}
                      onChange={() => setAuthType('keys')}
                      className="accent-rose-500"
                    /> IAM User Access Keys
                  </label>
                  <label className="flex items-center gap-2 text-xs text-cyber-text cursor-pointer">
                    <input
                      type="radio"
                      checked={authType === 'role'}
                      onChange={() => setAuthType('role')}
                      className="accent-rose-500"
                    /> IAM Cross-Account Role
                  </label>
                </div>
              </div>
            </div>

            {authType === 'keys' ? (
              <div className="grid grid-cols-2 gap-4 bg-slate-950/40 p-4 rounded-xl border border-cyber-border/40">
                <div>
                  <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">AWS Access Key ID</label>
                  <input
                    type="text"
                    required
                    value={accessKeyId}
                    onChange={(e) => setAccessKeyId(e.target.value)}
                    placeholder="AKIA..."
                    className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-2 text-xs text-white placeholder-slate-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">AWS Secret Access Key</label>
                  <input
                    type="password"
                    required
                    value={secretAccessKey}
                    onChange={(e) => setSecretAccessKey(e.target.value)}
                    placeholder="••••••••••••••••••••••••"
                    className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-2 text-xs text-white placeholder-slate-600 focus:outline-none"
                  />
                </div>
              </div>
            ) : (
              <div className="bg-slate-950/40 p-4 rounded-xl border border-cyber-border/40">
                <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">Trust Role ARN</label>
                <input
                  type="text"
                  required
                  value={roleArn}
                  onChange={(e) => setRoleArn(e.target.value)}
                  placeholder="arn:aws:iam::123456789012:role/CloudSentinelReadOnlyAccess"
                  className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-600 focus:outline-none"
                />
                <p className="text-[10px] text-cyber-muted mt-1.5 leading-relaxed">
                  Provide an IAM role ARN configured to grant read-only actions and trusting the platform account principal. Bypasses keys requirement.
                </p>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 bg-cyber-critical hover:bg-rose-600 text-xs font-bold text-white rounded-xl shadow-lg transition-colors flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                'Save Connection'
              )}
            </button>
          </form>
        </div>
      )}

      {/* Account List and Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Accounts list */}
        <div className="lg:col-span-1 space-y-4">
          <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider block">Linked Accounts ({accounts.length})</span>
          {accounts.map((acct) => {
            const active = selectedAccount?.id === acct.id;
            return (
              <div
                key={acct.id}
                onClick={() => selectAccount(acct.id)}
                className={`
                  p-4 rounded-2xl border transition-all duration-150 cursor-pointer flex flex-col relative
                  ${active 
                    ? 'bg-cyber-card border-rose-500/40 text-white shadow-lg shadow-rose-500/5' 
                    : 'bg-cyber-card border-cyber-border text-cyber-text hover:border-slate-700'}
                `}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="font-bold text-sm text-white">{acct.name}</h4>
                    <p className="text-[10px] text-cyber-muted mt-0.5 font-mono">ID: {acct.account_id}</p>
                  </div>
                  <div className="flex gap-2">
                    {canEdit && (
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          handleTriggerScan(acct.id);
                        }}
                        title="Trigger Audit Scan"
                        className="p-1.5 bg-slate-950 hover:bg-slate-800 border border-cyber-border hover:border-cyber-medium text-cyber-muted hover:text-cyber-medium rounded-lg transition-colors"
                      >
                        <Play size={12} fill="currentColor" className="text-cyber-medium" />
                      </button>
                    )}
                    {user?.role === 'Admin' && acct.name !== 'demo-aws-account' && (
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteAccount(acct.id);
                        }}
                        title="Delete Connection"
                        className="p-1.5 bg-slate-950 hover:bg-rose-950/20 border border-cyber-border hover:border-cyber-critical text-cyber-muted hover:text-cyber-critical rounded-lg transition-colors"
                      >
                        <Trash2 size={12} />
                      </button>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[10px] text-cyber-muted mt-4 border-t border-cyber-border/40 pt-3">
                  <p>Region: <span className="text-slate-300 font-semibold">{acct.region}</span></p>
                  <p>Auth: <span className="text-slate-300 capitalize">{acct.auth_type}</span></p>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: Scan history for selected account */}
        <div className="lg:col-span-2 bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-lg flex flex-col h-full min-h-[360px]">
          <div className="flex items-center justify-between border-b border-cyber-border/40 pb-4 mb-4 shrink-0">
            <div>
              <h4 className="font-bold text-sm text-white">Scan Audits History</h4>
              <p className="text-xs text-cyber-muted mt-0.5">Historical scans for {selectedAccount?.name || 'select account'}</p>
            </div>
            <button 
              onClick={loadScanHistory}
              className="p-2 bg-slate-900 border border-cyber-border text-cyber-muted hover:text-white rounded-lg transition-colors"
            >
              <RefreshCw size={12} />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto">
            {historyLoading ? (
              <div className="h-full flex flex-col items-center justify-center p-8">
                <div className="w-6 h-6 border-4 border-rose-500/20 border-t-cyber-critical rounded-full animate-spin mb-3" />
                <span className="text-xs text-cyber-muted">Fetching audit history...</span>
              </div>
            ) : scanHistory.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-8">
                <Calendar size={32} className="text-cyber-muted mb-2" />
                <span className="text-xs text-cyber-muted">No scan reports found. Trigger a scan above to start auditing.</span>
              </div>
            ) : (
              <div className="space-y-3">
                {scanHistory.map((scan) => (
                  <div 
                    key={scan.id}
                    className="p-4 bg-slate-950/60 border border-cyber-border/40 rounded-xl flex items-center justify-between gap-4"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-white">Scan ID: #{scan.id}</span>
                        <span className={`
                          text-[9px] font-bold px-2 py-0.5 rounded capitalize
                          ${scan.status === 'completed' ? 'text-cyber-success bg-emerald-500/10' : (scan.status === 'running' ? 'text-cyber-medium bg-amber-500/10 animate-pulse' : 'text-cyber-critical bg-rose-500/10')}
                        `}>
                          {scan.status}
                        </span>
                      </div>
                      <p className="text-[10px] text-cyber-muted mt-1">
                        Started: {new Date(scan.started_at).toLocaleString()}
                      </p>
                    </div>

                    {scan.status === 'completed' && (
                      <div className="flex items-center gap-6 text-right shrink-0">
                        <div>
                          <span className="text-[9px] font-bold text-cyber-muted uppercase tracking-wider block">Compliance</span>
                          <span className="text-xs font-bold text-cyber-success">{scan.compliance_score}%</span>
                        </div>
                        <div>
                          <span className="text-[9px] font-bold text-cyber-muted uppercase tracking-wider block">Risk factor</span>
                          <span className="text-xs font-bold text-cyber-critical">{scan.risk_score}</span>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
