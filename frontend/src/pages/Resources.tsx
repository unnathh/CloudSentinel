import React, { useState, useEffect } from 'react';
import { useActiveAccount } from '../contexts/AccountContext';
import { resourcesApi } from '../services/api';
import { ResourceInventory } from '../types';
import { Search, Database, X, Code, ShieldAlert, Layers } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const Resources: React.FC = () => {
  const { latestScan } = useActiveAccount();
  const [resources, setResources] = useState<ResourceInventory[]>([]);
  const [selectedResource, setSelectedResource] = useState<ResourceInventory | null>(null);
  const [search, setSearch] = useState('');
  const [serviceFilter, setServiceFilter] = useState('ALL');
  const [isLoading, setIsLoading] = useState(false);

  const loadResources = async () => {
    if (!latestScan) return;
    setIsLoading(true);
    try {
      const data = await resourcesApi.getResources({
        scan_id: latestScan.id,
        service: serviceFilter === 'ALL' ? undefined : serviceFilter,
      });
      setResources(data);
    } catch (error) {
      console.error('Failed to load resources:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadResources();
  }, [latestScan, serviceFilter]);

  // Filter list by search term
  const filteredResources = resources.filter(r => 
    r.resource_name.toLowerCase().includes(search.toLowerCase()) ||
    r.resource_id.toLowerCase().includes(search.toLowerCase()) ||
    r.resource_type.toLowerCase().includes(search.toLowerCase())
  );

  const services = ['ALL', 'IAM', 'S3', 'EC2', 'VPC', 'CLOUDTRAIL', 'KMS', 'LAMBDA', 'RDS', 'EBS'];

  return (
    <div className="space-y-6 relative min-h-[80vh]">
      {/* Title */}
      <div>
        <h2 className="text-2xl font-bold text-white tracking-wide">Scanned Resource Inventory</h2>
        <p className="text-sm text-cyber-muted mt-1">Catalog of cloud resources collected during security scans.</p>
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
            placeholder="Search name, ID, type..."
            className="w-full bg-slate-950 border border-cyber-border rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-600 focus:outline-none"
          />
        </div>

        {/* Service buttons */}
        <div className="flex flex-wrap items-center gap-1.5 w-full md:w-auto">
          {services.map((svc) => (
            <button
              key={svc}
              onClick={() => setServiceFilter(svc)}
              className={`
                px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors
                ${serviceFilter === svc 
                  ? 'bg-cyber-critical text-white' 
                  : 'bg-slate-900 border border-cyber-border text-cyber-muted hover:text-white'}
              `}
            >
              {svc}
            </button>
          ))}
        </div>
      </div>

      {/* Resources Table */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden shadow-lg">
        {isLoading ? (
          <div className="p-12 flex flex-col items-center justify-center">
            <div className="w-8 h-8 border-4 border-rose-500/20 border-t-cyber-critical rounded-full animate-spin mb-3" />
            <span className="text-xs text-cyber-muted">Fetching resource inventory...</span>
          </div>
        ) : filteredResources.length === 0 ? (
          <div className="p-16 text-center text-xs text-cyber-muted">
            No scanned cloud resources found for active filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border bg-slate-950/40 text-[10px] font-bold text-cyber-muted uppercase tracking-wider">
                  <th className="py-4 px-6">Resource Name</th>
                  <th className="py-4 px-6">Type</th>
                  <th className="py-4 px-6">Service</th>
                  <th className="py-4 px-6">AWS Resource Identifier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 text-xs font-medium">
                {filteredResources.map((res) => (
                  <tr 
                    key={res.id}
                    onClick={() => setSelectedResource(res)}
                    className="hover:bg-slate-900/20 cursor-pointer transition-colors"
                  >
                    <td className="py-4 px-6 font-semibold text-white">{res.resource_name}</td>
                    <td className="py-4 px-6">
                      <span className="px-2 py-0.5 bg-slate-900 border border-cyber-border text-slate-300 rounded font-semibold text-[10px]">
                        {res.resource_type}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-cyber-info">{res.service}</td>
                    <td className="py-4 px-6 font-mono text-cyber-muted truncate max-w-[360px]" title={res.resource_id}>
                      {res.resource_id}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-out drawer configuration viewer */}
      <AnimatePresence>
        {selectedResource && (
          <>
            {/* Overlay background */}
            <motion.div 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 0.5 }} 
              exit={{ opacity: 0 }}
              onClick={() => setSelectedResource(null)}
              className="fixed inset-0 bg-black z-40 cursor-pointer"
            />
            {/* Drawer */}
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'tween', duration: 0.3 }}
              className="fixed inset-y-0 right-0 w-full max-w-xl bg-cyber-card border-l border-cyber-border z-50 flex flex-col shadow-2xl h-screen overflow-hidden"
            >
              {/* Drawer Header */}
              <div className="p-6 border-b border-cyber-border flex items-center justify-between bg-slate-950/40">
                <div className="min-w-0">
                  <span className="px-2 py-0.5 bg-slate-900 border border-cyber-border text-slate-300 rounded font-bold text-[9px] uppercase">
                    {selectedResource.resource_type}
                  </span>
                  <h3 className="text-base font-bold text-white mt-2 truncate">{selectedResource.resource_name}</h3>
                  <p className="text-[10px] text-cyber-muted mt-0.5">Service: {selectedResource.service}</p>
                </div>
                <button 
                  onClick={() => setSelectedResource(null)}
                  className="p-2 hover:bg-slate-800 text-cyber-muted hover:text-white rounded-lg transition-colors shrink-0"
                >
                  <X size={20} />
                </button>
              </div>

              {/* Drawer Body Scrollable */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6">
                <div>
                  <h4 className="text-xs font-bold text-cyber-muted uppercase tracking-wider mb-2">Resource Details</h4>
                  <div className="bg-slate-950/60 p-4 border border-cyber-border rounded-xl space-y-2 text-xs text-cyber-muted leading-relaxed">
                    <p><span className="font-semibold text-slate-400">AWS Resource ID:</span> <span className="font-mono text-slate-300">{selectedResource.resource_id}</span></p>
                    <p><span className="font-semibold text-slate-400">Scanned Service:</span> <span className="text-cyber-info font-semibold">{selectedResource.service}</span></p>
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-cyber-muted uppercase tracking-wider mb-2 flex items-center gap-1.5"><Code size={14} /> Collected Config State (JSON)</h4>
                  <pre className="p-4 text-[10px] font-mono text-cyan-400 bg-slate-950 border border-cyber-border rounded-xl overflow-x-auto max-h-[500px]">
                    {JSON.stringify(selectedResource.configuration, null, 2)}
                  </pre>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
};
