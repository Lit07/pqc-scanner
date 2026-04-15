"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { Search, Globe, Network, Cpu, Lock, ZoomIn, ZoomOut, Maximize2 } from "lucide-react";
import { Skeleton } from "../components/Skeleton";

export default function DiscoveryPage() {
  const [data, setData] = useState<any>(null);
  const [activeTab, setActiveTab] = useState("Domains");
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/discovery/sc_MOCK123")
      .then((res) => res.json())
      .then((resData) => setData(resData));
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    setIsPanning(true);
    setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isPanning) return;
    setPan({ x: e.clientX - panStart.x, y: e.clientY - panStart.y });
  }, [isPanning, panStart]);

  const handleMouseUp = useCallback(() => {
    setIsPanning(false);
  }, []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom(prev => Math.max(0.3, Math.min(3, prev + delta)));
  }, []);

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  if (!data) return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-6 animate-in fade-in p-10">
      <Skeleton className="h-40 rounded-[2.5rem] mb-4" />
      <Skeleton className="h-[600px] rounded-[2rem]" />
    </div>
  );

  // Spread nodes out more for better visibility
  const canvasWidth = 1600;
  const canvasHeight = 1000;

  return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* Header Panel */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-8 relative overflow-hidden flex justify-between items-center flex-wrap gap-6">
        <div className="absolute -bottom-48 -left-48 w-96 h-96 bg-indigo-500/20 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 flex items-center gap-4">
          <div className="w-16 h-16 bg-gradient-to-br from-indigo-500 to-blue-600 rounded-2xl flex items-center justify-center text-white shadow-xl shadow-indigo-500/30">
            <Search className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tight text-foreground">
              Asset Discovery Graph
            </h1>
            <p className="font-semibold text-card-foreground/70 mt-1">
              Topological relationship map of all external network vectors. Drag to pan, scroll to zoom.
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="relative z-10 flex bg-black/5 dark:bg-white/5 p-1.5 rounded-2xl border border-input-border/50 overflow-x-auto max-w-full">
          {[
            { name: "Domains", icon: Globe },
            { name: "SSL/TLS", icon: Lock },
            { name: "IP/Subnets", icon: Network },
            { name: "Software", icon: Cpu }
          ].map((tab) => (
            <button
              key={tab.name}
              onClick={() => setActiveTab(tab.name)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold transition-all whitespace-nowrap ${
                activeTab === tab.name 
                  ? 'bg-white dark:bg-black text-indigo-500 shadow-sm border border-input-border/50' 
                  : 'text-card-foreground/60 hover:text-foreground hover:bg-white/50 dark:hover:bg-black/20'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.name}
            </button>
          ))}
        </div>
      </div>

      {/* Interactive Graph Canvas */}
      <div className="relative">
        {/* Zoom controls */}
        <div className="absolute top-4 right-4 z-30 flex flex-col gap-2">
          <button onClick={() => setZoom(z => Math.min(3, z + 0.2))} className="w-10 h-10 bg-card-background/90 backdrop-blur-sm border border-input-border/50 rounded-xl flex items-center justify-center hover:bg-card-background transition-colors shadow-lg">
            <ZoomIn className="w-5 h-5" />
          </button>
          <button onClick={() => setZoom(z => Math.max(0.3, z - 0.2))} className="w-10 h-10 bg-card-background/90 backdrop-blur-sm border border-input-border/50 rounded-xl flex items-center justify-center hover:bg-card-background transition-colors shadow-lg">
            <ZoomOut className="w-5 h-5" />
          </button>
          <button onClick={resetView} className="w-10 h-10 bg-card-background/90 backdrop-blur-sm border border-input-border/50 rounded-xl flex items-center justify-center hover:bg-card-background transition-colors shadow-lg">
            <Maximize2 className="w-5 h-5" />
          </button>
          <div className="text-center text-xs font-bold text-card-foreground/50 mt-1">{Math.round(zoom * 100)}%</div>
        </div>

        <div 
          ref={containerRef}
          className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-xl rounded-[2rem] overflow-hidden h-[650px] relative select-none"
          style={{ cursor: isPanning ? 'grabbing' : 'grab' }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onWheel={handleWheel}
        >
          <div className="absolute inset-0 opacity-10" style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, currentColor 1px, transparent 0)', backgroundSize: '40px 40px' }} />
          
          {/* Pannable + Zoomable inner layer */}
          <div 
            className="absolute inset-0 origin-center transition-transform duration-75"
            style={{ 
              transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
              width: canvasWidth,
              height: canvasHeight,
            }}
          >
            {/* Edges */}
            <svg className="absolute inset-0 pointer-events-none" width={canvasWidth} height={canvasHeight}>
              {data.edges.map((edge: any, i: number) => {
                const source = data.nodes.find((n: any) => n.id === edge.source);
                const target = data.nodes.find((n: any) => n.id === edge.target);
                if (!source || !target) return null;

                if (activeTab === "Domains" && (source.type === "leaf" || target.type === "leaf")) return null;
                if (activeTab === "Software" && source.type !== "leaf" && target.type !== "leaf") return null;

                return (
                  <line 
                    key={i}
                    x1={`${source.x}%`} 
                    y1={`${source.y}%`} 
                    x2={`${target.x}%`} 
                    y2={`${target.y}%`} 
                    stroke="currentColor" 
                    strokeWidth="2"
                    className="opacity-20"
                  />
                );
              })}
            </svg>

            {/* Nodes */}
            {data.nodes.map((node: any) => {
              if (activeTab === "Domains" && node.type === "leaf") return null;
              if (activeTab === "Software" && node.type !== "leaf") return null;

              return (
                <div 
                  key={node.id}
                  className="absolute flex flex-col items-center justify-center -translate-x-1/2 -translate-y-1/2 transition-transform hover:scale-125 cursor-pointer group hover:z-50"
                  style={{ left: `${node.x}%`, top: `${node.y}%` }}
                >
                  <div className={`rounded-2xl flex items-center justify-center shadow-2xl border-2 backdrop-blur-md transition-all ${
                    node.type === 'hub' ? 'bg-indigo-500/20 border-indigo-500 text-indigo-500 w-20 h-20 shadow-indigo-500/30' :
                    node.type === 'node' ? 'bg-blue-500/20 border-blue-500 text-blue-500 w-14 h-14 shadow-blue-500/30' :
                    'bg-emerald-500/20 border-emerald-500 text-emerald-500 w-12 h-12 shadow-emerald-500/30'
                  }`}>
                    {node.type === 'hub' ? <Globe className="w-10 h-10"/> : node.type === 'node' ? <Network className="w-6 h-6"/> : <Cpu className="w-5 h-5"/>}
                  </div>
                  <div className="mt-3 px-3 py-1.5 bg-black/90 dark:bg-white/90 text-white dark:text-black rounded-lg text-xs font-bold font-mono opacity-0 group-hover:opacity-100 transition-opacity absolute top-[110%] whitespace-nowrap shadow-xl">
                    {node.label}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
