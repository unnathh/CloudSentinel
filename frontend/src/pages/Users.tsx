import React, { useState, useEffect } from 'react';
import { authApi } from '../services/api';
import { User } from '../types';
import { 
  Users as UsersIcon, Plus, Trash2, Shield, 
  Mail, AlertCircle, CheckCircle 
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export const Users: React.FC = () => {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'Admin' | 'Analyst' | 'Viewer'>('Analyst');
  
  const [formOpen, setFormOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [listLoading, setListLoading] = useState(false);

  const loadUsers = async () => {
    setListLoading(true);
    try {
      const data = await authApi.getUsers();
      setUsers(data);
    } catch (err) {
      console.error('Failed to load users list:', err);
    } finally {
      setListLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleRegisterUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsLoading(true);

    try {
      await authApi.register({ email, password, role });
      setSuccess(`Successfully registered new user: ${email}`);
      setEmail('');
      setPassword('');
      setFormOpen(false);
      await loadUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create user. Verify email is unique.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteUser = async (userId: number, emailStr: string) => {
    if (currentUser?.id === userId) {
      alert('You cannot delete your own session account.');
      return;
    }
    if (!window.confirm(`Are you sure you want to delete user ${emailStr}?`)) {
      return;
    }
    try {
      await authApi.deleteUser(userId);
      await loadUsers();
    } catch (err) {
      console.error('Failed to delete user:', err);
    }
  };

  const isAdmin = currentUser?.role === 'Admin';

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-wide">Workspace User Administration</h2>
          <p className="text-sm text-cyber-muted mt-1">Manage tenant users, dashboard permission roles, and analyst access.</p>
        </div>
        {isAdmin && !formOpen && (
          <button 
            onClick={() => setFormOpen(true)}
            className="flex items-center gap-2 px-4 py-2.5 bg-cyber-critical hover:bg-rose-600 rounded-xl text-xs font-bold text-white shadow-lg transition-colors"
          >
            <Plus size={16} /> Invite Analyst / Viewer
          </button>
        )}
      </div>

      {/* Invite Form */}
      {formOpen && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-xl space-y-6 max-w-md">
          <div className="flex items-center justify-between border-b border-cyber-border/40 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <UsersIcon size={16} className="text-cyber-critical" /> Register User Account
            </h3>
            <button onClick={() => setFormOpen(false)} className="text-xs text-cyber-muted hover:text-white uppercase">Cancel</button>
          </div>

          {error && (
            <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-cyber-critical text-xs flex items-center gap-3">
              <AlertCircle size={16} className="shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleRegisterUser} className="space-y-4">
            <div>
              <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">User Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@cloudsentinel.local"
                className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-2 text-xs text-white placeholder-slate-600 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">Initial Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-cyber-border rounded-xl px-4 py-2 text-xs text-white placeholder-slate-600 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[10px] font-bold text-cyber-muted uppercase tracking-wider mb-1.5">Authorization Role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as any)}
                className="w-full bg-slate-950 border border-cyber-border rounded-xl px-3 py-2 text-xs text-white focus:outline-none"
              >
                <option value="Analyst">Security Analyst (Read/Write scans)</option>
                <option value="Viewer">Viewer (Read-only access)</option>
                <option value="Admin">Administrator (Full tenant access)</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 bg-cyber-critical hover:bg-rose-600 text-xs font-bold text-white rounded-xl shadow-lg transition-colors flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                'Create User'
              )}
            </button>
          </form>
        </div>
      )}

      {success && (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-cyber-success text-xs flex items-center gap-3 max-w-xl">
          <CheckCircle size={16} className="shrink-0" />
          <span>{success}</span>
        </div>
      )}

      {/* Users Table */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden shadow-lg">
        {listLoading ? (
          <div className="p-12 flex flex-col items-center justify-center">
            <div className="w-8 h-8 border-4 border-rose-500/20 border-t-cyber-critical rounded-full animate-spin mb-3" />
            <span className="text-xs text-cyber-muted">Loading tenant users...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border bg-slate-950/40 text-[10px] font-bold text-cyber-muted uppercase tracking-wider">
                  <th className="py-4 px-6">Email Identity</th>
                  <th className="py-4 px-6">Access Role</th>
                  <th className="py-4 px-6">Created On</th>
                  <th className="py-4 px-6"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 text-xs font-medium">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-900/10 transition-colors">
                    <td className="py-4 px-6 font-mono text-white">{u.email}</td>
                    <td className="py-4 px-6">
                      <span className={`
                        inline-block px-2 py-0.5 text-[9px] font-bold uppercase rounded border tracking-wider
                        ${u.role === 'Admin' ? 'bg-rose-500/15 border-rose-500/30 text-cyber-critical' : (u.role === 'Analyst' ? 'bg-orange-500/15 border-orange-500/30 text-cyber-high' : 'bg-blue-500/15 border-blue-500/30 text-cyber-low')}
                      `}>
                        {u.role}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-cyber-muted">
                      {new Date(u.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-4 px-6 text-right">
                      {isAdmin && u.id !== currentUser?.id && (
                        <button
                          onClick={() => handleDeleteUser(u.id, u.email)}
                          className="p-1 text-cyber-muted hover:text-cyber-critical rounded transition-colors"
                          title="Revoke User Access"
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
