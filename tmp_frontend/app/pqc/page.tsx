"use client";

import { useEffect, useState } from "react";
import { Hourglass, ShieldAlert, Cpu, Download, ArrowRight } from "lucide-react";
import { Skeleton } from "../components/Skeleton";
import { PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer, Legend } from "recharts";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

export default function PQCPage() {
  const [data, setData] = useState<any>(null);
  const [clockTick, setClockTick] = useState<number>(0);

  useEffect(() => {
    fetch("/api/pqc/posture")
      .then((res) => res.json())
      .then((resData) => setData(resData));
      
    // Dramatic countdown timer interval
    const interval = setInterval(() => {
      setClockTick(prev => prev + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const formatCountdown = (totalSeconds: number) => {
    const s = Math.max(0, totalSeconds - clockTick);
    const d = Math.floor(s / (3600 * 24));
    const h = Math.floor((s % (3600 * 24)) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${d}d ${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${sec.toString().padStart(2, '0')}`;
  };

  const exportPDF = () => {
    if (!data) return;
    const doc = new jsPDF();
    doc.text(`PQC Compliance Posture`, 14, 15);
    autoTable(doc, {
      startY: 25,
      head: [['Asset', 'Tier', 'Cipher', 'Quantum Threat Countdown']],
      body: data.assets.map((r: any) => [r.name, r.tier, r.cipher, formatCountdown(r.quantumClockSeconds)]),
      theme: 'grid',
    });
    doc.save(`PQC_Posture.pdf`);
  };

  if (!data) return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-6 animate-in fade-in p-10">
      <Skeleton className="h-40 rounded-[2.5rem] mb-4" />
      <Skeleton className="h-[600px] rounded-[2rem]" />
    </div>
  );

  const pieData = [
    { name: "Elite (ML-KEM)", value: data.breakdown.elite, fill: "#8b5cf6" },
    { name: "Standard (AES)", value: data.breakdown.standard, fill: "#3b82f6" },
    { name: "Legacy (RSA)", value: data.breakdown.legacy, fill: "#f59e0b" },
    { name: "Critical (DES)", value: data.breakdown.critical, fill: "#ef4444" },
  ];

  return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* Header Panel */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-8 relative overflow-hidden flex justify-between items-center flex-wrap gap-6">
        <div className="absolute -top-48 -right-48 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 flex items-center gap-4">
          <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl flex items-center justify-center text-white shadow-xl shadow-purple-500/30">
            <Hourglass className="w-8 h-8 animate-pulse" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tight text-foreground">
              Quantum Posture Compliance
            </h1>
            <p className="font-semibold text-card-foreground/70 mt-1">
              Cryptographic readiness against Shor's algorithm and HNDL attacks.
            </p>
          </div>
        </div>
        
        <button 
          onClick={exportPDF}
          className="relative z-10 flex items-center gap-2 px-6 py-3 font-bold bg-white/50 dark:bg-black/20 border-2 border-primary/30 hover:border-primary hover:bg-white dark:hover:bg-black/50 transition-colors rounded-xl shadow-sm"
        >
          <Download className="w-5 h-5 text-primary" />
          Export Posture PDF
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Tier Distribution */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg h-[400px] flex flex-col">
          <h3 className="font-extrabold text-lg mb-2 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-500" />
            Cryptographic Tier Breakdown
          </h3>
          <p className="text-xs text-card-foreground/60 mb-4 font-semibold">Distribution of deployed algorithms across the network.</p>
          <div className="flex-1 w-full min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} innerRadius={80} outerRadius={120} paddingAngle={4} dataKey="value" stroke="none">
                  {pieData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.fill} />)}
                </Pie>
                <RechartsTooltip contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(5,5,5,0.85)', color: 'white', backdropFilter: 'blur(10px)' }} />
                <Legend iconType="circle" />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Actionable Recommendations */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg h-[400px] overflow-y-auto">
          <h3 className="font-extrabold text-lg mb-6 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-orange-500" />
            Remediation Targets
          </h3>
          <div className="flex flex-col gap-4">
            {data.recommendations.map((rec: any, i: number) => (
              <div key={i} className="p-5 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/50 flex flex-col gap-2 relative overflow-hidden group hover:bg-white/60 dark:hover:bg-black/40 transition-colors">
                <div className={`absolute top-0 left-0 w-1.5 h-full ${rec.impact === 'Critical' ? 'bg-red-500' : rec.impact === 'High' ? 'bg-orange-500' : 'bg-yellow-500'}`} />
                <div className="flex justify-between items-start">
                  <div className="font-bold text-sm text-card-foreground/70 leading-relaxed pr-4">Trigger: {rec.trigger}</div>
                  <span className={`px-2.5 py-1 rounded-md text-[10px] font-black uppercase whitespace-nowrap border border-current ${rec.impact === 'Critical' ? 'bg-red-500/10 text-red-500' : 'bg-orange-500/10 text-orange-500'}`}>
                    {rec.impact} Impact
                  </span>
                </div>
                <div className="font-black text-foreground mt-2 flex items-start gap-3">
                  <ArrowRight className="w-4 h-4 mt-0.5 text-primary shrink-0 transition-transform group-hover:translate-x-1" />
                  {rec.action}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Asset Table with Quantum Clock */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-xl rounded-[2rem] overflow-hidden">
        <div className="bg-black/5 dark:bg-white/5 p-5 border-b border-input-border/50">
          <h3 className="font-extrabold text-lg flex items-center gap-2"><Hourglass className="w-5 h-5 text-primary" /> Asset Quantum Expiry Matrix</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[800px]">
            <thead>
              <tr className="bg-black/5 dark:bg-white/5">
                <th className="p-5 text-sm font-black border-b border-input-border/50 tracking-wide">Asset Identity</th>
                <th className="p-5 text-sm font-black border-b border-input-border/50 tracking-wide">Classification Tier</th>
                <th className="p-5 text-sm font-black border-b border-input-border/50 tracking-wide">Identified Cipher</th>
                <th className="p-5 text-sm font-black border-b border-input-border/50 text-right tracking-wide">Quantum Security Lifespan</th>
              </tr>
            </thead>
            <tbody>
              {data.assets.map((record: any) => (
                <tr key={record.id} className="border-b border-input-border/30 last:border-0 hover:bg-black/5 dark:hover:bg-white/5 transition-colors">
                  <td className="p-5 font-bold font-mono text-sm">{record.name}</td>
                  <td className="p-5">
                    <span className={`px-3 py-1.5 rounded-lg text-xs font-bold shadow-sm ${
                      record.tier === 'Critical' ? 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20' :
                      record.tier === 'Legacy' ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20' :
                      record.tier === 'Standard' ? 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20' :
                      'bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20'
                    }`}>
                      {record.tier} Level
                    </span>
                  </td>
                  <td className="p-5 font-bold text-sm bg-black/10 dark:bg-white/10 inline-flex px-3 py-1 m-4 rounded-lg border border-input-border/30">{record.cipher}</td>
                  <td className="p-5 text-right">
                    <div className="font-mono text-xl md:text-2xl font-black bg-black text-red-500 px-4 py-2 rounded-xl inline-flex tracking-widest shadow-inner shadow-red-500/20 border border-red-500/30">
                      {formatCountdown(record.quantumClockSeconds)}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
