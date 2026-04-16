"use client";

import { useEffect, useState } from "react";
import { Map, ShieldCheck, ShieldAlert, Zap, RadioReceiver, Activity, Globe2, ScanLine } from "lucide-react";
import { Skeleton } from "../components/Skeleton";

export default function HeatmapPage() {
  const [data, setData] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);

  useEffect(() => {
    fetch("/api/heatmap")
      .then((res) => res.json())
      .then((resData) => setData(resData));
  }, []);

  if (!data) return (
    <div className="w-full max-w-[90rem] mx-auto p-10 flex flex-col gap-6">
      <Skeleton className="h-[200px] rounded-3xl" />
      <Skeleton className="h-[600px] rounded-[3rem]" />
    </div>
  );

  return (
    <div className="w-full max-w-[95rem] mx-auto flex flex-col gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* Header section */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-10 relative overflow-hidden flex flex-col md:flex-row items-center justify-between gap-8">
        <div className="absolute top-0 right-0 w-full h-full bg-gradient-to-l from-red-500/10 via-transparent to-transparent pointer-events-none" />
        <div className="absolute -top-48 -left-48 w-96 h-96 bg-red-500/20 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 w-full md:w-2/3">
          <h1 className="text-4xl sm:text-5xl font-black tracking-tight text-foreground flex items-center gap-4 mb-4">
            <Map className="w-10 h-10 text-red-500" />
            HNDL Exposure Heatmap
          </h1>
          <p className="text-card-foreground/70 text-lg font-semibold max-w-2xl">
            Live topological matrix rendered from the AI Endpoint Classifier. Identifies gateways highly susceptible to <span className="text-red-500 font-bold tracking-tight">Hack Now, Decrypt Later</span> intelligence harvesting.
          </p>
        </div>

        <div className="relative z-10 flex gap-4 shrink-0">
          <div className="flex flex-col items-center p-4 bg-white/50 dark:bg-black/40 border border-input-border/50 rounded-2xl shadow-sm min-w-[120px]">
            <span className="text-3xl font-black text-red-500">{data.nodes.filter((n: any) => n.hndlScore >= 70).length}</span>
            <span className="text-xs font-bold text-card-foreground/70 uppercase">High Risk</span>
          </div>
          <div className="flex flex-col items-center p-4 bg-white/50 dark:bg-black/40 border border-input-border/50 rounded-2xl shadow-sm min-w-[120px]">
            <span className="text-3xl font-black text-emerald-500">{data.nodes.filter((n: any) => n.pqcReady).length}</span>
            <span className="text-xs font-bold text-card-foreground/70 uppercase">PQC Secured</span>
          </div>
        </div>
      </div>

      {/* Heatmap Canvas */}
      <div className="flex flex-col lg:flex-row gap-6">
        
        <div className="lg:w-3/4 bg-black border border-white/10 rounded-[3rem] h-[750px] relative overflow-hidden shadow-2xl flex items-center justify-center group">
          
          {/* Grid Background */}
          <div className="absolute inset-0 opacity-[0.15]" style={{
            backgroundImage: `linear-gradient(rgba(255,255,255,0.2) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.2) 1px, transparent 1px)`,
            backgroundSize: '50px 50px'
          }} />

          {/* Radar Sweep Effect */}
          <div className="absolute top-1/2 left-1/2 w-[150%] h-[150%] -translate-x-1/2 -translate-y-1/2 bg-[conic-gradient(from_0deg,transparent_0deg,rgba(239,68,68,0.1)_90deg,transparent_120deg)] animate-spin opacity-50 pointer-events-none" style={{ animationDuration: '4s' }} />
          
          <div className="absolute top-4 left-6 flex items-center gap-2 text-white/50 font-mono text-xs z-10">
            <RadioReceiver className="w-4 h-4 animate-pulse text-red-500" />
            LIVE SENSOR GRID [A-1]
          </div>

          {/* Nodes plotting */}
          {data.nodes.map((node: any, idx: number) => {
            const isRed = node.hndlScore >= 70;
            const isYellow = node.hndlScore >= 40 && node.hndlScore < 70;
            const isGreen = node.hndlScore < 40;

            const glowClass = isRed ? "shadow-red-500/50" : isYellow ? "shadow-yellow-500/50" : "shadow-emerald-500/50";
            const bgClass = isRed ? "bg-red-500" : isYellow ? "bg-yellow-500" : "bg-emerald-500";
            
            // Reposition using the synthetic hash slightly constrained
            const left = `${10 + (idx * 27) % 80}%`;
            const top = `${15 + (idx * 33) % 70}%`;

            return (
              <div 
                key={node.id}
                className="absolute flex flex-col items-center group/node cursor-crosshair z-20"
                style={{ left, top }}
                onClick={() => setSelectedNode(node)}
              >
                {/* Node Ring Animation */}
                {isRed && (
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-20 h-20 rounded-full border border-red-500/30 animate-ping opacity-75 pointer-events-none" />
                )}

                <div className={`w-8 h-8 rounded-full ${bgClass} shadow-[0_0_30px_rgba(0,0,0,0.5)] flex items-center justify-center hover:scale-125 transition-transform relative z-10`}>
                  <Globe2 className="w-4 h-4 text-white" />
                </div>
                
                <div className="mt-2 text-white font-mono text-xs bg-black/80 px-2 py-1 rounded opacity-0 group-hover/node:opacity-100 transition-opacity border border-white/20 whitespace-nowrap backdrop-blur-sm">
                  {node.hostname}
                </div>
              </div>
            );
          })}
        </div>

        {/* Side Inspector Panel */}
        <div className="lg:w-1/4 bg-card-background/80 backdrop-blur-xl border border-white/20 rounded-[3rem] p-6 shadow-xl flex flex-col relative h-[750px]">
          <h3 className="font-extrabold text-xl mb-6 flex items-center gap-2 border-b border-input-border/50 pb-4">
            <Activity className="w-5 h-5 text-indigo-500" />
            Tactical Inspector
          </h3>

          {selectedNode ? (
            <div className="flex flex-col gap-6 animate-in slide-in-from-right-4 fade-in">
              <div className="flex flex-col gap-1">
                <span className="text-xs font-bold text-card-foreground/50 uppercase tracking-widest">Target Host</span>
                <span className="text-xl font-black font-mono break-all">{selectedNode.hostname}</span>
              </div>
              
              <div className="flex flex-col gap-1">
                <span className="text-xs font-bold text-card-foreground/50 uppercase tracking-widest">Network IP</span>
                <span className="text-sm font-semibold text-primary">{selectedNode.ip}</span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-black/5 dark:bg-white/5 p-4 rounded-2xl border border-input-border/50">
                  <div className="text-xs font-bold text-card-foreground/50 uppercase">HNDL Score</div>
                  <div className={`text-3xl font-black mt-1 ${selectedNode.hndlScore >= 70 ? 'text-red-500' : selectedNode.hndlScore >= 40 ? 'text-yellow-500' : 'text-emerald-500'}`}>
                    {selectedNode.hndlScore}
                  </div>
                </div>
                <div className="bg-black/5 dark:bg-white/5 p-4 rounded-2xl border border-input-border/50">
                  <div className="text-xs font-bold text-card-foreground/50 uppercase">Crypto Grade</div>
                  <div className={`text-3xl font-black mt-1 ${['D','F'].includes(selectedNode.grade) ? 'text-red-500' : 'text-emerald-500'}`}>
                    {selectedNode.grade}
                  </div>
                </div>
              </div>

              <div className="flex flex-col gap-2 mt-4">
                <span className="text-xs font-bold text-card-foreground/50 uppercase tracking-widest">AI Classification</span>
                <div className="flex items-center gap-3 p-4 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/50">
                  <Zap className="w-5 h-5 text-indigo-500" />
                  <span className="font-bold text-sm">{selectedNode.type} Node</span>
                </div>
              </div>

              {selectedNode.hndlScore >= 70 && (
                <div className="mt-auto p-4 bg-red-500/10 border border-red-500/30 rounded-2xl">
                  <div className="flex items-center gap-2 text-red-600 dark:text-red-400 font-bold mb-2">
                    <ShieldAlert className="w-4 h-4" /> Critical Exposure
                  </div>
                  <p className="text-xs text-red-600/80 dark:text-red-400/80 font-semibold leading-relaxed">
                    This endpoint is highly susceptible to intelligence harvesting and Harvest Now, Decrypt Later attacks. Migrate to Hybrid PQC immediately.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center px-4 opacity-50">
              <ScanLine className="w-16 h-16 text-card-foreground/30 mb-4" />
              <p className="text-sm font-bold">Select a node from the radar sweep to view deep diagnostics.</p>
            </div>
          )}
        </div>
      </div>
      
    </div>
  );
}
