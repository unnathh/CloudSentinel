import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useActiveAccount } from '../contexts/AccountContext';
import { reportsApi } from '../services/api';
import { 
  Settings as SettingsIcon, FileJson, FileText, 
  FileCheck, Shield, HelpCircle, ArrowDownToLine, Check 
} from 'lucide-react';

export const Settings: React.FC = () => {
  const { user } = useAuth();
  const { selectedAccount, latestScan } = useActiveAccount();
  const [downloading, setDownloading] = useState<'json' | 'csv' | 'pdf' | null>(null);

  const triggerDownload = async (type: 'json' | 'csv' | 'pdf') => {
    if (!latestScan) return;
    setDownloading(type);
    try {
      const data = await reportsApi.downloadReport(type, latestScan.id);
      const mime = type === 'json' ? 'application/json' : (type === 'csv' ? 'text/csv' : 'application/pdf');
      const blob = new Blob([data], { type: mime });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `cloudsentinel_report_${selectedAccount?.name}_scan${latestScan.id}.${type}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error(`Download of ${type} report failed:`, error);
      alert('Report download failed. Please ensure the scan has completed and try again.');
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Title */}
      <div>
        <h2 className="text-2xl font-bold text-white tracking-wide">Workspace Settings & Compliance Reports</h2>
        <p className="text-sm text-cyber-muted mt-1">Export security findings and review portal configurations.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Profile Details */}
        <div className="md:col-span-1 bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-lg space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-cyber-border/40">
            <Shield size={16} className="text-cyber-critical" />
            <h4 className="font-bold text-xs text-white uppercase tracking-wider">User Session Information</h4>
          </div>
          
          <div className="space-y-3 text-xs leading-relaxed text-cyber-muted">
            <p><span className="font-semibold text-slate-400 block mb-0.5">Email Identity:</span> <span className="text-white font-mono">{user?.email}</span></p>
            <p><span className="font-semibold text-slate-400 block mb-0.5">Access Role:</span> <span className="inline-block px-2 py-0.5 mt-0.5 bg-rose-500/10 border border-rose-500/20 text-cyber-critical text-[10px] font-bold rounded uppercase">{user?.role}</span></p>
            <p><span className="font-semibold text-slate-400 block mb-0.5">Status:</span> <span className="text-cyber-success font-semibold">Active</span></p>
          </div>
        </div>

        {/* Reports Download cards */}
        <div className="md:col-span-2 bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-lg space-y-6">
          <div className="flex items-center gap-2 pb-3 border-b border-cyber-border/40">
            <ArrowDownToLine size={16} className="text-cyber-info" />
            <h4 className="font-bold text-xs text-white uppercase tracking-wider">Download Posture Reports</h4>
          </div>

          {!latestScan ? (
            <div className="text-center py-6 text-xs text-cyber-muted">
              Select an account with a completed scan to export findings.
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-xs text-cyber-muted leading-relaxed">
                Export the results of scan <span className="text-slate-300 font-bold">#{latestScan.id}</span> for AWS account <span className="text-slate-300 font-bold">{selectedAccount?.name}</span>.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {/* JSON CARD */}
                <button
                  onClick={() => triggerDownload('json')}
                  disabled={downloading !== null}
                  className="p-4 bg-slate-950/60 hover:bg-slate-900 border border-cyber-border rounded-xl text-left hover:border-slate-700 transition-all flex flex-col items-start gap-3 w-full group"
                >
                  <FileJson className="text-cyber-info" size={24} />
                  <div>
                    <h5 className="font-bold text-xs text-white">JSON Format</h5>
                    <span className="text-[10px] text-cyber-muted block mt-0.5">Full metadata raw dump</span>
                  </div>
                  <span className="text-[10px] font-semibold text-cyber-info group-hover:underline mt-auto">
                    {downloading === 'json' ? 'Downloading...' : 'Export JSON'}
                  </span>
                </button>

                {/* CSV CARD */}
                <button
                  onClick={() => triggerDownload('csv')}
                  disabled={downloading !== null}
                  className="p-4 bg-slate-950/60 hover:bg-slate-900 border border-cyber-border rounded-xl text-left hover:border-slate-700 transition-all flex flex-col items-start gap-3 w-full group"
                >
                  <FileText className="text-cyber-high" size={24} />
                  <div>
                    <h5 className="font-bold text-xs text-white">CSV Spreadsheet</h5>
                    <span className="text-[10px] text-cyber-muted block mt-0.5">Failing items list grid</span>
                  </div>
                  <span className="text-[10px] font-semibold text-cyber-high group-hover:underline mt-auto">
                    {downloading === 'csv' ? 'Downloading...' : 'Export CSV'}
                  </span>
                </button>

                {/* PDF CARD */}
                <button
                  onClick={() => triggerDownload('pdf')}
                  disabled={downloading !== null}
                  className="p-4 bg-slate-950/60 hover:bg-slate-900 border border-cyber-border rounded-xl text-left hover:border-slate-700 transition-all flex flex-col items-start gap-3 w-full group"
                >
                  <FileCheck className="text-cyber-critical" size={24} />
                  <div>
                    <h5 className="font-bold text-xs text-white">Executive PDF</h5>
                    <span className="text-[10px] text-cyber-muted block mt-0.5">CIS scorecard summary</span>
                  </div>
                  <span className="text-[10px] font-semibold text-cyber-critical group-hover:underline mt-auto">
                    {downloading === 'pdf' ? 'Downloading...' : 'Export PDF'}
                  </span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Compliance Standard summaries info */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-lg">
        <div className="flex items-center gap-2 pb-3 border-b border-cyber-border/40 mb-4">
          <HelpCircle size={16} className="text-cyber-medium" />
          <h4 className="font-bold text-xs text-white uppercase tracking-wider font-sans">Compliance Standards Reference</h4>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs leading-relaxed text-cyber-muted">
          <div>
            <h5 className="font-bold text-white mb-1.5">CIS AWS Foundations Benchmark</h5>
            <p>
              The Center for Internet Security (CIS) AWS Foundations Benchmark is a set of security configuration guidelines for AWS. It provides industry-accepted best practices for securing IAM identities, logging structures, monitoring alarms, networking controls, and resource cryptography.
            </p>
          </div>
          <div>
            <h5 className="font-bold text-white mb-1.5">MITRE ATT&CK Cloud Matrix</h5>
            <p>
              MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. CloudSentinel maps security misconfigurations and dangerous privileges to MITRE ATT&CK techniques (e.g. Valid Accounts, Account Manipulation, Privilege Escalation) to contextualize threats.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
