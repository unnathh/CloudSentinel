import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Shield, AlertCircle } from 'lucide-react';

export const Login: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    
    try {
      await login(email, password);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed. Please check your credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4">
      {/* Background radial gradient to give cybersecurity atmosphere */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(244,63,94,0.03)_0%,transparent_70%)] pointer-events-none" />

      <div className="w-full max-w-md z-10">
        {/* Brand header */}
        <div className="flex flex-col items-center mb-8">
          <div className="p-3 bg-rose-500/10 rounded-2xl border border-rose-500/30 glow-critical mb-4">
            <Shield className="text-cyber-critical" size={36} />
          </div>
          <h2 className="text-2xl font-bold tracking-wider text-white">CLOUDSENTINEL</h2>
          <p className="text-xs text-cyber-muted uppercase tracking-widest mt-1">Cloud Security Posture Management</p>
        </div>

        {/* Login form Card */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-8 shadow-xl">
          <h3 className="text-lg font-bold text-white mb-6">Sign In to Dashboard</h3>

          {error && (
            <div className="mb-6 p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start gap-3 text-cyber-critical text-sm">
              <AlertCircle size={18} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-xs font-bold text-cyber-muted uppercase tracking-wider mb-2">Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@cloudsentinel.local"
                className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-rose-500/40 focus:ring-1 focus:ring-rose-500/40 transition-colors"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-cyber-muted uppercase tracking-wider mb-2">Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-rose-500/40 focus:ring-1 focus:ring-rose-500/40 transition-colors"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3 bg-cyber-critical hover:bg-rose-600 text-sm font-bold text-white rounded-xl shadow-lg shadow-rose-500/15 hover:shadow-rose-500/25 transition-all duration-150 flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                'Access Workspace'
              )}
            </button>
          </form>
        </div>

        {/* Seeding credentials guidance card */}
        <div className="mt-6 bg-slate-950/40 border border-cyber-border rounded-xl p-4 text-xs text-cyber-muted">
          <p className="font-bold text-slate-300 mb-2 uppercase tracking-wide">Demo Accounts (Auto-Seeded):</p>
          <div className="grid grid-cols-3 gap-2">
            <div className="bg-slate-900/60 p-2 rounded border border-slate-800/40">
              <span className="font-bold text-cyber-critical">Admin Role:</span>
              <p className="mt-1 truncate">admin@cloudsentinel.local</p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">adminpassword</p>
            </div>
            <div className="bg-slate-900/60 p-2 rounded border border-slate-800/40">
              <span className="font-bold text-cyber-high">Analyst:</span>
              <p className="mt-1 truncate">analyst@cloudsentinel.local</p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">analystpassword</p>
            </div>
            <div className="bg-slate-900/60 p-2 rounded border border-slate-800/40">
              <span className="font-bold text-cyber-low">Viewer:</span>
              <p className="mt-1 truncate">viewer@cloudsentinel.local</p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">viewerpassword</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
