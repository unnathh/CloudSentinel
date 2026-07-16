import React, { useState, useEffect } from 'react';
import { useActiveAccount } from '../contexts/AccountContext';
import { findingsApi, graphApi, resourcesApi } from '../services/api';
import { Finding, AttackPath } from '../types';
import { 
  ShieldAlert, ShieldCheck, AlertOctagon, AlertTriangle, 
  Layers, Zap, Info, ArrowUpRight 
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line 
} from 'recharts';
import { motion } from 'framer-motion';

export const Dashboard: React.FC = () => {
  const { selectedAccount, latestScan, scans } = useActiveAccount();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [resourcesCount, setResourcesCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  useEffect(() => {
    const loadDashboardData = async () => {
      if (!latestScan) {
        setFindings([]);
        setPaths([]);
        setResourcesCount(0);
        return;
      }
      setIsLoading(true);
      try {
        const [findingsData, pathsData, resourcesData] = await Promise.all([
          findingsApi.getFindings({ scan_id: latestScan.id }),
          graphApi.getAttackPaths(latestScan.id),
          resourcesApi.getResources({ scan_id: latestScan.id })
        ]);
        setFindings(findingsData);
        setPaths(pathsData);
        setResourcesCount(resourcesData.length);
      } catch (error) {
        console.error('Failed to load dashboard data:', error);
      } finally {
        setIsLoading(false);
      }
    };
    loadDashboardData();
  }, [latestScan]);

  if (!selectedAccount) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-6">
        <div className="p-4 bg-slate-900 border border-cyber-border rounded-full mb-4">
          <Layers size={48} className="text-cyber-muted" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">No Connected AWS Accounts</h2>
        <p className="text-sm text-cyber-muted max-w-md mb-6">
          To begin analyzing cloud security postures, connect your AWS account credentials (keys or trust role) first.
        </p>
        <a href="/accounts" className="px-5 py-2.5 bg-cyber-critical text-sm font-semibold rounded-lg hover:bg-rose-600 transition-colors shadow-lg shadow-rose-500/10">
          Connect AWS Account
        </a>
      </div>
    );
  }

  if (!latestScan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-6">
        <div className="p-4 bg-slate-900 border border-cyber-border rounded-full mb-4 animate-pulse">
          <ShieldAlert size={48} className="text-cyber-medium" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Scan Required</h2>
        <p className="text-sm text-cyber-muted max-w-md mb-6">
          An initial security assessment is required. Switch to the Accounts page to run a posture scan.
        </p>
        <a href="/accounts" className="px-5 py-2.5 bg-cyber-critical text-sm font-semibold rounded-lg hover:bg-rose-600 transition-colors">
          Go to AWS Accounts
        </a>
      </div>
    );
  }

  // Calculate stats
  const criticalCount = findings.filter(f => f.severity === 'Critical').length;
  const highCount = findings.filter(f => f.severity === 'High').length;
  const mediumCount = findings.filter(f => f.severity === 'Medium').length;
  const lowCount = findings.filter(f => f.severity === 'Low').length;

  // Chart 1: Severity Pie
  const severityChartData = [
    { name: 'Critical', value: criticalCount, color: '#f43f5e' },
    { name: 'High', value: highCount, color: '#f97316' },
    { name: 'Medium', value: mediumCount, color: '#eab308' },
    { name: 'Low', value: lowCount, color: '#3b82f6' },
  ].filter(item => item.value > 0);

  // Chart 2: Findings by Service
  const serviceCounts: { [key: string]: number } = {};
  findings.forEach(f => {
    serviceCounts[f.service] = (serviceCounts[f.service] || 0) + 1;
  });
  const serviceChartData = Object.keys(serviceCounts).map(svc => ({
    name: svc,
    findings: serviceCounts[svc]
  })).sort((a, b) => b.findings - a.findings);

  // Chart 3: Historical Compliance Scan Scores
  const historyChartData = scans
    .filter(s => s.status === 'completed')
    .map(s => ({
      date: new Date(s.started_at).toLocaleDateString(undefined, {month: 'short', day: 'numeric'}),
      compliance: s.compliance_score,
      risk: s.risk_score
    }))
    .reverse();

  // Get Risk level style
  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-cyber-critical';
    if (score >= 40) return 'text-cyber-high';
    if (score >= 15) return 'text-cyber-medium';
    return 'text-cyber-success';
  };

  const getComplianceColor = (score: number) => {
    if (score >= 85) return 'text-cyber-success';
    if (score >= 60) return 'text-cyber-medium';
    return 'text-cyber-critical';
  };

  return (
    <div className="space-y-8">
      {/* Page Title */}
      <div>
        <h2 className="text-2xl font-bold text-white tracking-wide">Security Posture Dashboard</h2>
        <p className="text-sm text-cyber-muted mt-1">AWS Account: <span className="font-semibold text-slate-300">{selectedAccount.name}</span> | Region: {selectedAccount.region}</p>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}
          className="bg-cyber-card border border-cyber-border rounded-2xl p-5 flex items-center justify-between shadow-lg">
          <div>
            <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider">Scanned Inventory</span>
            <h3 className="text-2xl font-bold text-white mt-1">{resourcesCount}</h3>
            <p className="text-[10px] text-cyber-muted mt-0.5">Total AWS resources mapped</p>
          </div>
          <div className="p-3 bg-slate-900 border border-cyber-border rounded-xl">
            <Layers size={22} className="text-cyber-info" />
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2, delay: 0.05 }}
          className="bg-cyber-card border border-cyber-border rounded-2xl p-5 flex items-center justify-between shadow-lg">
          <div>
            <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider">Total Findings</span>
            <h3 className="text-2xl font-bold text-white mt-1">{findings.length}</h3>
            <p className="text-[10px] text-cyber-muted mt-0.5">Failing configuration rules</p>
          </div>
          <div className="p-3 bg-slate-900 border border-cyber-border rounded-xl">
            <ShieldAlert size={22} className="text-cyber-high" />
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2, delay: 0.1 }}
          className="bg-cyber-card border border-cyber-border rounded-2xl p-5 flex items-center justify-between shadow-lg">
          <div>
            <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider">Postural Risk Score</span>
            <h3 className={`text-2xl font-bold mt-1 ${getRiskColor(latestScan.risk_score)}`}>{latestScan.risk_score} <span className="text-xs text-cyber-muted">/100</span></h3>
            <p className="text-[10px] text-cyber-muted mt-0.5">Composite AWS threat factor</p>
          </div>
          <div className="p-3 bg-slate-900 border border-cyber-border rounded-xl">
            <AlertOctagon size={22} className={getRiskColor(latestScan.risk_score)} />
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2, delay: 0.15 }}
          className="bg-cyber-card border border-cyber-border rounded-2xl p-5 flex items-center justify-between shadow-lg">
          <div>
            <span className="text-[10px] font-bold text-cyber-muted uppercase tracking-wider">Compliance Index</span>
            <h3 className={`text-2xl font-bold mt-1 ${getComplianceColor(latestScan.compliance_score)}`}>{latestScan.compliance_score}%</h3>
            <p className="text-[10px] text-cyber-muted mt-0.5">CIS Foundations Benchmark score</p>
          </div>
          <div className="p-3 bg-slate-900 border border-cyber-border rounded-xl">
            <ShieldCheck size={22} className={getComplianceColor(latestScan.compliance_score)} />
          </div>
        </motion.div>
      </div>

      {/* Alarm Banner if Attack Paths exist */}
      {paths.length > 0 && (
        <motion.div initial={{ scale: 0.98, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ duration: 0.3 }}
          className="bg-rose-500/10 border border-rose-500/30 rounded-2xl p-5 flex items-start gap-4 glow-critical">
          <div className="p-2.5 bg-rose-500/20 border border-rose-500/30 rounded-xl text-cyber-critical shrink-0">
            <Zap size={22} className="animate-bounce" />
          </div>
          <div className="flex-1">
            <h4 className="font-bold text-white text-sm">Critical Privilege Escalation Vector Discovered</h4>
            <p className="text-xs text-cyber-muted mt-1 leading-relaxed">
              CloudSentinel discovered {paths.length} active directed path(s) in your IAM permission structure that allow low-privilege users to assume full administrative control (AdministratorAccess). Investigate the Attack Graph to remediate.
            </p>
            <a href="/graph" className="inline-flex items-center gap-1.5 mt-3 text-xs font-semibold text-cyber-critical hover:text-rose-400 transition-colors">
              Inspect Attack Paths <ArrowUpRight size={14} />
            </a>
          </div>
        </motion.div>
      )}

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity chart */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-lg flex flex-col min-h-[320px]">
          <h4 className="font-bold text-sm text-white mb-4">Findings by Severity</h4>
          <div className="flex-1 relative">
            {severityChartData.length === 0 ? (
              <div className="absolute inset-0 flex items-center justify-center text-xs text-cyber-muted">No failing findings</div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={severityChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {severityChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0b0f19', border: '1px solid #1e293b', borderRadius: '8px' }}
                    labelStyle={{ color: '#f8fafc' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
          {/* Legend indicator list */}
          <div className="grid grid-cols-2 gap-3 text-xs font-medium text-cyber-muted mt-4 border-t border-cyber-border/40 pt-4">
            <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded bg-cyber-critical"></span> Critical ({criticalCount})</div>
            <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded bg-cyber-high"></span> High ({highCount})</div>
            <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded bg-cyber-medium"></span> Medium ({mediumCount})</div>
            <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded bg-cyber-low"></span> Low ({lowCount})</div>
          </div>
        </div>

        {/* Findings by service chart */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-lg lg:col-span-2 flex flex-col min-h-[320px]">
          <h4 className="font-bold text-sm text-white mb-4">Findings by AWS Service</h4>
          <div className="flex-1">
            {serviceChartData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-cyber-muted">No services found with failures</div>
            ) : (
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={serviceChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0b0f19', border: '1px solid #1e293b', borderRadius: '8px' }}
                    labelStyle={{ color: '#f8fafc' }}
                  />
                  <Bar dataKey="findings" fill="#3b82f6" radius={[4, 4, 0, 0]}>
                    {serviceChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={index === 0 ? '#f43f5e' : (index === 1 ? '#f97316' : '#3b82f6')} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Grid: Trends & Attack paths */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Compliance trend */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-lg flex flex-col">
          <h4 className="font-bold text-sm text-white mb-4">Scan History Trend</h4>
          <div className="flex-1 min-h-[220px]">
            {historyChartData.length <= 1 ? (
              <div className="h-full flex items-center justify-center text-xs text-cyber-muted">
                Run more scans to populate historical trend charts.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={historyChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0b0f19', border: '1px solid #1e293b', borderRadius: '8px' }}
                  />
                  <Line type="monotone" dataKey="compliance" name="Compliance %" stroke="#10b981" strokeWidth={2} dot={{ fill: '#10b981' }} />
                  <Line type="monotone" dataKey="risk" name="Risk Score" stroke="#f43f5e" strokeWidth={2} dot={{ fill: '#f43f5e' }} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top Risks and Escalations */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 shadow-lg flex flex-col">
          <h4 className="font-bold text-sm text-white mb-4">Security Remediation Backlog</h4>
          <div className="flex-1 space-y-3 overflow-y-auto max-h-[240px]">
            {findings.length === 0 ? (
              <div className="text-xs text-cyber-muted text-center py-6">All rules passing. No backlog checks.</div>
            ) : (
              findings.slice(0, 5).map((f) => (
                <div key={f.id} className="p-3 bg-slate-950/60 border border-cyber-border/40 rounded-xl flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className={`
                      w-2 h-2 rounded-full shrink-0
                      ${f.severity === 'Critical' ? 'bg-cyber-critical' : (f.severity === 'High' ? 'bg-cyber-high' : 'bg-cyber-medium')}
                    `}></span>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-white truncate">{f.title}</p>
                      <p className="text-[10px] text-cyber-muted mt-0.5">{f.service} | Resource: {f.resource_id.split('/').pop()}</p>
                    </div>
                  </div>
                  <a href="/findings" className="text-[10px] font-bold text-cyber-info hover:underline shrink-0">Remediate</a>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
