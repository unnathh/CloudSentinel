import React, { useEffect, useRef, useState } from 'react';
import { useActiveAccount } from '../contexts/AccountContext';
import { graphApi } from '../services/api';
import { AttackPath } from '../types';
import cytoscape from 'cytoscape';
import { 
  Network, AlertTriangle, HelpCircle, ZoomIn, 
  ZoomOut, Maximize2, ShieldCheck, User, Zap 
} from 'lucide-react';
import { motion } from 'framer-motion';

export const AttackGraph: React.FC = () => {
  const { latestScan } = useActiveAccount();
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  // Load attack paths list
  useEffect(() => {
    const loadPaths = async () => {
      if (!latestScan) return;
      try {
        const pathData = await graphApi.getAttackPaths(latestScan.id);
        setPaths(pathData);
      } catch (error) {
        console.error('Failed to load attack paths:', error);
      }
    };
    loadPaths();
  }, [latestScan]);

  // Load graph and initialize Cytoscape
  useEffect(() => {
    const initGraph = async () => {
      if (!latestScan || !containerRef.current) return;
      setIsLoading(true);
      try {
        const graphData = await graphApi.getSecurityGraph(latestScan.id);
        
        // Destroy existing instance if any
        if (cyRef.current) {
          cyRef.current.destroy();
        }

        // Initialize Cytoscape
        const cy = cytoscape({
          container: containerRef.current,
          elements: {
            nodes: graphData.nodes,
            edges: graphData.edges
          },
          style: [
            {
              selector: 'node',
              style: {
                'label': 'data(label)',
                'font-size': '10px',
                'color': '#f8fafc',
                'text-valign': 'bottom',
                'text-margin-y': 6,
                'background-color': '#1e293b',
                'border-width': '2px',
                'border-color': '#475569',
                'width': '32px',
                'height': '32px',
                'transition-property': 'background-color, border-color, border-width, opacity',
                'transition-duration': 0.2
              }
            },
            {
              selector: 'node[type="user"]',
              style: {
                'shape': 'ellipse',
                'background-color': '#1e40af', // Slate Blue
                'border-color': '#3b82f6',
              }
            },
            {
              selector: 'node[type="role"]',
              style: {
                'shape': 'round-rectangle',
                'background-color': '#7c2d12', // Rust Red
                'border-color': '#f97316',
              }
            },
            {
              selector: 'node[is_admin=true]',
              style: {
                'shape': 'hexagon',
                'background-color': '#9f1239', // Rose Critical Red
                'border-color': '#f43f5e',
                'width': '40px',
                'height': '40px',
              }
            },
            {
              selector: 'node[type="ec2"]',
              style: {
                'shape': 'triangle',
                'background-color': '#854d0e', // Yellow Gold
                'border-color': '#eab308',
              }
            },
            {
              selector: 'node[type="lambda"]',
              style: {
                'shape': 'diamond',
                'background-color': '#581c87', // Indigo
                'border-color': '#a855f7',
              }
            },
            {
              selector: 'edge',
              style: {
                'width': 1.5,
                'line-color': '#334155',
                'target-arrow-color': '#334155',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'label': 'data(label)',
                'font-size': '8px',
                'color': '#64748b',
                'text-background-opacity': 0.8,
                'text-background-color': '#020617',
                'text-background-padding': '2px',
                'transition-property': 'line-color, target-arrow-color, width, opacity',
                'transition-duration': 0.2
              }
            },
            {
              selector: 'edge[type^="exploit"]',
              style: {
                'line-color': '#f43f5e',
                'target-arrow-color': '#f43f5e',
                'width': 2.5,
                'line-style': 'dashed'
              }
            },
            // Highlighting and fading helpers
            {
              selector: '.highlighted',
              style: {
                'background-color': '#f43f5e',
                'border-color': '#f43f5e',
                'border-width': '4px',
                'line-color': '#f43f5e',
                'target-arrow-color': '#f43f5e',
                'width': 3.5,
                'opacity': 1
              }
            },
            {
              selector: '.faded',
              style: {
                'opacity': 0.15
              }
            }
          ],
          layout: {
            name: 'cose', // Force directed layout
            idealEdgeLength: () => 100,
            nodeOverlap: 20,
            refresh: 20,
            fit: true,
            padding: 30,
            randomize: false,
            componentSpacing: 100,
            nodeRepulsion: () => 400000,
            edgeElasticity: () => 100,
            nestingFactor: 5,
            gravity: 80,
            numIter: 1000,
            initialTemp: 200,
            coolingFactor: 0.95,
            minTemp: 1.0
          }
        });

        // Click element handlers
        cy.on('tap', 'node', (evt) => {
          const node = evt.target;
          setSelectedNode(node.data());
        });

        cy.on('tap', (evt) => {
          if (evt.target === cy) {
            setSelectedNode(null);
          }
        });

        cyRef.current = cy;
      } catch (error) {
        console.error('Failed to load security graph:', error);
      } finally {
        setIsLoading(false);
      }
    };
    initGraph();

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [latestScan]);

  // Handle path highlighting
  const handleSelectPath = (path: AttackPath | null) => {
    setSelectedPath(path);
    const cy = cyRef.current;
    if (!cy) return;

    if (!path) {
      // Clear highlight styles
      cy.elements().removeClass('highlighted faded');
      return;
    }

    const chain = path.node_chain;
    
    // Set all elements to faded first
    cy.elements().addClass('faded').removeClass('highlighted');

    // Highlight path nodes and edges connecting them
    chain.forEach((nodeId, idx) => {
      const node = cy.getElementById(nodeId);
      node.removeClass('faded').addClass('highlighted');

      if (idx < chain.length - 1) {
        const nextNodeId = chain[idx + 1];
        // Find connecting edge
        const edge = node.edgesTo(cy.getElementById(nextNodeId));
        edge.removeClass('faded').addClass('highlighted');
      }
    });
  };

  // Zoom/Center utilities
  const zoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.2);
  const zoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const fitGraph = () => {
    cyRef.current?.fit();
    cyRef.current?.center();
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h2 className="text-2xl font-bold text-white tracking-wide">Privilege Escalation Attack Graph</h2>
        <p className="text-sm text-cyber-muted mt-1">IAM relationship mapping and discovered exploitation chains.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 h-[72vh]">
        {/* Left column: Path Selector panel */}
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-4 flex flex-col overflow-hidden shadow-lg h-full">
          <div className="flex items-center gap-2 mb-4 shrink-0">
            <AlertTriangle className="text-cyber-critical" size={16} />
            <h4 className="font-bold text-xs text-white uppercase tracking-wider">Attack Chains ({paths.length})</h4>
          </div>

          <div className="flex-1 overflow-y-auto space-y-3 pr-1">
            {paths.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-4">
                <ShieldCheck className="text-cyber-success mb-2" size={32} />
                <span className="text-[11px] text-cyber-muted leading-relaxed">No credential exploit paths found. All evaluated nodes are secured.</span>
              </div>
            ) : (
              paths.map((p) => {
                const active = selectedPath?.id === p.id;
                return (
                  <button
                    key={p.id}
                    onClick={() => handleSelectPath(active ? null : p)}
                    className={`
                      w-full text-left p-3 rounded-xl border text-xs leading-relaxed transition-all duration-150 block
                      ${active 
                        ? 'bg-rose-500/10 border-rose-500/40 text-rose-300 shadow-md glow-critical' 
                        : 'bg-slate-950/40 border-cyber-border text-cyber-muted hover:border-slate-700 hover:text-white'}
                    `}
                  >
                    <span className="font-bold block text-white mb-1 truncate">{p.path_name.split(':').pop()}</span>
                    <span className="text-[9px] font-mono text-slate-500 block truncate">{p.node_chain.join(' → ')}</span>
                  </button>
                );
              })
            )}
          </div>
          
          {selectedPath && (
            <div className="border-t border-cyber-border/60 pt-4 mt-4 shrink-0 bg-slate-950/20 p-3 rounded-xl">
              <span className="text-[10px] font-bold text-cyber-critical flex items-center gap-1 uppercase tracking-wider mb-2">
                <Zap size={12} /> Exploit Narrative
              </span>
              <p className="text-[10px] text-cyber-muted leading-relaxed max-h-[140px] overflow-y-auto whitespace-pre-line">
                {selectedPath.description}
              </p>
            </div>
          )}
        </div>

        {/* Center: Graph canvas */}
        <div className="lg:col-span-3 bg-cyber-card border border-cyber-border rounded-2xl overflow-hidden relative shadow-lg flex flex-col h-full">
          {/* Canvas Viewport */}
          <div className="flex-1 relative">
            {isLoading && (
              <div className="absolute inset-0 bg-cyber-bg/70 z-10 flex flex-col items-center justify-center">
                <div className="w-8 h-8 border-4 border-rose-500/20 border-t-cyber-critical rounded-full animate-spin mb-3" />
                <span className="text-xs text-cyber-muted">Building relationship graph...</span>
              </div>
            )}
            <div ref={containerRef} className="w-full h-full cy-container" />

            {/* Float HUD Controls */}
            <div className="absolute bottom-6 right-6 flex items-center gap-2 bg-slate-950/80 border border-cyber-border p-2 rounded-xl backdrop-blur">
              <button onClick={zoomIn} title="Zoom In" className="p-2 bg-slate-900 border border-cyber-border rounded-lg text-cyber-muted hover:text-white hover:bg-slate-800 transition-colors">
                <ZoomIn size={14} />
              </button>
              <button onClick={zoomOut} title="Zoom Out" className="p-2 bg-slate-900 border border-cyber-border rounded-lg text-cyber-muted hover:text-white hover:bg-slate-800 transition-colors">
                <ZoomOut size={14} />
              </button>
              <button onClick={fitGraph} title="Auto Fit Center" className="p-2 bg-slate-900 border border-cyber-border rounded-lg text-cyber-muted hover:text-white hover:bg-slate-800 transition-colors">
                <Maximize2 size={14} />
              </button>
            </div>

            {/* Float HUD Info Card */}
            {selectedNode && (
              <motion.div 
                initial={{ opacity: 0, y: 10 }} 
                animate={{ opacity: 1, y: 0 }}
                className="absolute top-6 left-6 w-72 bg-slate-950/95 border border-cyber-border rounded-xl p-4 shadow-2xl backdrop-blur z-20 text-xs"
              >
                <div className="flex items-center justify-between border-b border-cyber-border/40 pb-2 mb-2">
                  <span className="font-bold text-white uppercase tracking-wide truncate pr-3">{selectedNode.label}</span>
                  <span className={`px-2 py-0.5 text-[8px] font-bold uppercase rounded ${
                    selectedNode.type === 'user' ? 'bg-blue-500/20 text-cyber-low' : (selectedNode.type === 'role' ? 'bg-orange-500/20 text-cyber-high' : 'bg-yellow-500/20 text-cyber-medium')
                  }`}>
                    {selectedNode.type}
                  </span>
                </div>

                <div className="space-y-2 leading-relaxed text-cyber-muted">
                  <p className="truncate"><span className="font-semibold text-slate-400">ARN:</span> <span className="font-mono text-[10px]">{selectedNode.id}</span></p>
                  <p><span className="font-semibold text-slate-400">Node Risk:</span> <span className={selectedNode.risk_score >= 70 ? 'text-cyber-critical font-bold' : 'text-cyber-success'}>{selectedNode.risk_score}</span></p>
                  
                  {selectedNode.dangerous_actions && selectedNode.dangerous_actions.length > 0 && (
                    <div>
                      <span className="font-semibold text-slate-400 block mb-1">Key Permissions:</span>
                      <div className="flex flex-wrap gap-1">
                        {selectedNode.dangerous_actions.slice(0, 4).map((a: string) => (
                          <span key={a} className="text-[8px] font-mono bg-slate-900 border border-slate-800 text-cyan-400 px-1 py-0.5 rounded">{a.split(':').pop()}</span>
                        ))}
                        {selectedNode.dangerous_actions.length > 4 && (
                          <span className="text-[8px] text-slate-500">+{selectedNode.dangerous_actions.length - 4} more</span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {/* Float Legend panel */}
            <div className="absolute top-6 right-6 hidden md:block bg-slate-950/80 border border-cyber-border p-3 rounded-xl backdrop-blur text-[10px] font-medium text-cyber-muted space-y-1.5 z-20">
              <p className="font-bold text-white uppercase tracking-wider text-[9px] mb-1.5 border-b border-cyber-border/40 pb-1">Legend</p>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-blue-600 border border-blue-400"></span> IAM User</div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded bg-orange-600 border border-orange-400"></span> IAM Role</div>
              <div className="flex items-center gap-2"><span className="w-3.5 h-3 bg-rose-800 border border-rose-500 rounded"></span> Admin Role (Hexagon)</div>
              <div className="flex items-center gap-2"><span className="w-0 h-0 border-l-[5px] border-l-transparent border-r-[5px] border-r-transparent border-b-[9px] border-b-yellow-600"></span> EC2 Instance</div>
              <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rotate-45 bg-purple-700 border border-purple-400"></span> Lambda Function</div>
              <div className="flex items-center gap-2"><span className="w-4 h-0.5 border-t border-t-slate-500"></span> Standard Permission</div>
              <div className="flex items-center gap-2"><span className="w-4 h-0.5 border-t border-t-rose-500 border-dashed"></span> Exploitable Edge</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
