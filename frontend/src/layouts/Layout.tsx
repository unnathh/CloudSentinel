import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useActiveAccount } from '../contexts/AccountContext';
import { 
  LayoutDashboard, ShieldAlert, Network, Database, Cloud, 
  Settings, Users, LogOut, Menu, X, Shield, RefreshCw 
} from 'lucide-react';

export const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, logout } = useAuth();
  const { accounts, selectedAccount, latestScan, selectAccount, refresh } = useActiveAccount();
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/accounts', label: 'AWS Accounts', icon: Cloud },
    { path: '/findings', label: 'Findings', icon: ShieldAlert },
    { path: '/graph', label: 'Attack Graph', icon: Network },
    { path: '/resources', label: 'Resources', icon: Database },
    { path: '/settings', label: 'Settings', icon: Settings },
  ];

  // Admin/Analyst only links
  if (user && (user.role === 'Admin' || user.role === 'Analyst')) {
    navItems.splice(5, 0, { path: '/users', label: 'Users', icon: Users });
  }

  const isActive = (path: string) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(path);
  };

  return (
    <div className="min-h-screen bg-cyber-bg text-cyber-text flex flex-col md:flex-row">
      {/* Mobile Top Bar */}
      <div className="md:hidden flex items-center justify-between p-4 bg-cyber-card border-b border-cyber-border">
        <div className="flex items-center gap-2">
          <Shield className="text-cyber-critical animate-pulse" size={24} />
          <span className="font-bold text-lg tracking-wider bg-gradient-to-r from-cyber-text via-cyber-muted to-cyber-critical bg-clip-text text-transparent">CLOUDSENTINEL</span>
        </div>
        <button onClick={() => setMobileMenuOpen(!mobileMenuOpen)} className="p-1 hover:bg-slate-800 rounded">
          {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>

      {/* Sidebar */}
      <aside className={`
        fixed md:static inset-y-0 left-0 z-50 w-64 bg-cyber-card border-r border-cyber-border flex flex-col transition-transform duration-300 transform
        ${mobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
      `}>
        {/* Logo Section */}
        <div className="p-6 border-b border-cyber-border flex items-center gap-3">
          <div className="p-2 bg-rose-500/10 rounded-lg border border-rose-500/30 glow-critical">
            <Shield className="text-cyber-critical" size={24} />
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-wider text-white">CloudSentinel</h1>
            <span className="text-[10px] text-cyber-muted tracking-widest uppercase">Enterprise CSPM</span>
          </div>
        </div>

        {/* Nav Links */}
        <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setMobileMenuOpen(false)}
                className={`
                  flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-150 group
                  ${active 
                    ? 'bg-gradient-to-r from-rose-500/10 to-transparent text-cyber-critical border-l-2 border-cyber-critical font-semibold' 
                    : 'text-cyber-muted hover:text-white hover:bg-slate-900/40'}
                `}
              >
                <Icon size={18} className={active ? 'text-cyber-critical' : 'text-cyber-muted group-hover:text-white'} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* User Card & Logout */}
        <div className="p-4 border-t border-cyber-border bg-slate-950/40">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-cyber-critical to-rose-600 flex items-center justify-center font-bold text-white shadow-md">
              {user?.email[0].toUpperCase()}
            </div>
            <div className="flex-1 overflow-hidden">
              <p className="text-xs font-semibold text-white truncate">{user?.email}</p>
              <span className="inline-block px-2 py-0.5 mt-0.5 text-[9px] font-bold uppercase tracking-wider bg-rose-950/60 border border-rose-800/40 text-cyber-critical rounded">
                {user?.role}
              </span>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-lg bg-slate-900 border border-cyber-border text-xs font-medium text-cyber-muted hover:text-white hover:bg-rose-950/20 hover:border-rose-900/40 transition-colors"
          >
            <LogOut size={14} />
            Logout Session
          </button>
        </div>
      </aside>

      {/* Main Container */}
      <div className="flex-1 flex flex-col min-w-0 overflow-x-hidden">
        {/* Top Header Bar */}
        <header className="h-16 bg-cyber-card/65 backdrop-blur-md border-b border-cyber-border px-6 flex items-center justify-between sticky top-0 z-40">
          {/* Account Selector */}
          <div className="flex items-center gap-4">
            <span className="text-xs font-bold text-cyber-muted uppercase tracking-wider hidden sm:inline">Active Scope:</span>
            <select
              value={selectedAccount?.id || ''}
              onChange={(e) => selectAccount(Number(e.target.value))}
              className="bg-slate-900 border border-cyber-border text-xs font-medium text-white px-3 py-1.5 rounded-lg focus:outline-none focus:border-rose-500/40 focus:ring-1 focus:ring-rose-500/40"
            >
              {accounts.length === 0 ? (
                <option value="">No Accounts Connected</option>
              ) : (
                accounts.map((acct) => (
                  <option key={acct.id} value={acct.id}>
                    {acct.name} ({acct.account_id})
                  </option>
                ))
              )}
            </select>

            <button 
              onClick={refresh}
              title="Sync Scope Accounts"
              className="p-1.5 bg-slate-900 hover:bg-slate-800 text-cyber-muted hover:text-white border border-cyber-border rounded-lg transition-colors"
            >
              <RefreshCw size={12} />
            </button>
          </div>

          {/* Scan Status Banner */}
          <div className="flex items-center gap-4">
            {latestScan && latestScan.status === 'running' && (
              <div className="flex items-center gap-2 px-3 py-1 bg-amber-500/10 border border-amber-500/30 text-cyber-medium rounded-full animate-pulse text-[11px] font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-medium animate-ping"></span>
                AWS Scan In Progress
              </div>
            )}
            {latestScan && latestScan.status === 'completed' && (
              <span className="text-[10px] text-cyber-muted hidden md:inline">
                Last scan: {new Date(latestScan.completed_at || '').toLocaleString()}
              </span>
            )}
          </div>
        </header>

        {/* Content Body */}
        <main className="flex-1 p-6 md:p-8 overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
};
