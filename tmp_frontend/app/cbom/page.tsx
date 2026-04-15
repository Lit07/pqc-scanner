"use client";

import React, { useEffect, useState } from "react";
import { Box, Download, Search, AlertTriangle, ShieldCheck, ChevronDown, ChevronUp, Activity, PieChart as PieChartIcon } from "lucide-react";
import { Skeleton } from "../components/Skeleton";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend, BarChart, Bar, XAxis, YAxis } from "recharts";

export default function CBOMPage() {
  const [data, setData] = useState<any>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    fetch("/api/cbom/stats")
      .then((res) => res.json())
      .then((resData) => setData(resData));
  }, []);

  const exportPDF = () => {
    if (!data) return;
    const doc = new jsPDF();
    doc.text(`Cryptographic Bill of Materials (CBOM) Global Report`, 14, 15);
    
    autoTable(doc, {
      startY: 25,
      head: [['Asset', 'Key Length', 'Cipher Suite', 'TLS', 'PQC Status', 'Risk']],
      body: data.cbomRecords.map((r: any) => [r.asset, r.keyLength, r.cipherSuite, r.tlsVersion, r.pqcStatus, r.riskScore]),
      theme: 'grid',
      headStyles: { fillColor: [139, 92, 246] }
    });
    
    doc.save(`CBOM_Global_Report.pdf`);
  };

  if (!data) return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-6 animate-in fade-in p-10">
      <Skeleton className="h-40 rounded-[2.5rem] mb-4" />
      <Skeleton className="h-[400px] rounded-[2rem]" />
      <Skeleton className="h-[600px] rounded-[2rem]" />
    </div>
  );

  const filteredRecords = data.cbomRecords?.filter((r: any) => 
    r.asset.toLowerCase().includes(searchTerm.toLowerCase()) || 
    r.cipherSuite.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* Header Panel */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-8 relative overflow-hidden flex justify-between items-center flex-wrap gap-6">
        <div className="absolute -bottom-48 -left-48 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 flex items-center gap-4">
          <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl flex items-center justify-center text-white shadow-xl shadow-purple-500/30">
            <Box className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tight text-foreground">
              Cryptographic Bill of Materials (CBOM)
            </h1>
            <p className="font-semibold text-card-foreground/70 mt-1 flex items-center gap-2">
              Topological insight into enterprise-wide cryptographic dependencies.
            </p>
          </div>
        </div>

        <button 
          onClick={exportPDF}
          className="relative z-10 flex items-center gap-2 px-6 py-3 font-bold bg-white/50 dark:bg-black/20 border-2 border-primary/30 hover:border-primary hover:bg-white dark:hover:bg-black/50 transition-colors rounded-xl shadow-sm"
        >
          <Download className="w-5 h-5 text-primary" />
          Export Global CBOM PDF
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
         {[
           { label: "Total Apps", value: data.stats.total_apps },
           { label: "Sites Surveyed", value: data.stats.sites_surveyed },
           { label: "Active Certs", value: data.stats.active_certs },
           { label: "Weak Crypto", value: data.stats.weak_crypto, color: "text-red-500" },
           { label: "Cert Issues", value: data.stats.cert_issues, color: "text-orange-500" },
         ].map((stat, i) => (
           <div key={i} className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg relative overflow-hidden group">
             <div className={`text-4xl font-black ${stat.color || "text-foreground"}`}>{stat.value}</div>
             <div className="text-sm font-bold text-card-foreground/70 mt-1">{stat.label}</div>
           </div>
         ))}
      </div>

      {/* Visual Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-[2rem] shadow-lg h-[350px] flex flex-col">
          <h3 className="font-extrabold text-lg flex items-center gap-2 mb-2"><PieChartIcon className="w-5 h-5 text-purple-500"/> Key Lengths</h3>
          <p className="text-xs text-card-foreground/50 font-semibold mb-2">Deployed cryptographic key sizes across enterprise.</p>
          <div className="flex-1 w-full min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={data.key_lengths} innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" stroke="none">
                  {data.key_lengths.map((entry: any, index: number) => (
                    <Cell key={`cell-${index}`} fill={['#8b5cf6', '#6366f1', '#ec4899', '#14b8a6', '#f59e0b'][index % 5]} />
                  ))}
                </Pie>
                <RechartsTooltip contentStyle={{ borderRadius: '16px', background: 'rgba(0,0,0,0.8)' }} />
                <Legend iconType="circle" />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-[2rem] shadow-lg h-[350px] flex flex-col">
          <h3 className="font-extrabold text-lg flex items-center gap-2 mb-2"><Activity className="w-5 h-5 text-indigo-500"/> Cipher Suites</h3>
          <p className="text-xs text-card-foreground/50 font-semibold mb-2">Most prevalent encryption protocol combinations.</p>
          <div className="flex-1 w-full min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.ciphers} layout="vertical" margin={{ left: 0 }}>
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" width={100} fontSize={10} tickLine={false} axisLine={false} tick={{fill: '#888'}} />
                <RechartsTooltip cursor={{ fill: 'rgba(99, 102, 241, 0.1)' }} contentStyle={{ borderRadius: '16px', background: 'rgba(0,0,0,0.8)' }} />
                <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} barSize={20} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-[2rem] shadow-lg h-[350px] flex flex-col">
          <h3 className="font-extrabold text-lg flex items-center gap-2 mb-2"><ShieldCheck className="w-5 h-5 text-emerald-500"/> Top Authorities</h3>
          <p className="text-xs text-card-foreground/50 font-semibold mb-2">Certificate issuers authenticating network endpoints.</p>
          <div className="flex-1 w-full min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={data.authorities} innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" stroke="none">
                  {data.authorities.map((entry: any, index: number) => (
                    <Cell key={`cell-${index}`} fill={['#10b981', '#3b82f6', '#f59e0b', '#ef4444'][index % 4]} />
                  ))}
                </Pie>
                <RechartsTooltip contentStyle={{ borderRadius: '16px', background: 'rgba(0,0,0,0.8)' }} />
                <Legend iconType="circle" />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-xl rounded-[2rem] overflow-hidden">
        
        {/* Toolbar */}
        <div className="bg-black/5 dark:bg-white/5 p-4 flex justify-between items-center border-b border-input-border/50">
          <div className="relative w-full max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-card-foreground/40" />
            <input 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search assets or ciphers..."
              className="w-full bg-white/40 dark:bg-black/40 border-[2px] border-input-border/60 rounded-xl py-2.5 pl-9 pr-4 outline-none focus:border-purple-500 font-semibold text-sm transition-colors shadow-inner"
            />
          </div>
          <div className="text-sm font-bold text-card-foreground/70 hidden sm:block mr-2">
            Showing {filteredRecords.length} identities
          </div>
        </div>

        {/* Data Matrix */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[900px]">
            <thead>
              <tr className="bg-black/5 dark:bg-white/5">
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">Asset Identity</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">Key Size</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">TLS / Protocol</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">PQC Readiness</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">Risk Score</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50 w-10"></th>
              </tr>
            </thead>
            <tbody>
              {filteredRecords.length === 0 ? (
                <tr><td colSpan={6} className="text-center p-8 font-bold text-card-foreground/50">No CBOM records found. Run a scan.</td></tr>
              ) : null}
              {filteredRecords.map((record: any) => (
                <React.Fragment key={record.id}>
                  <tr 
                    onClick={() => setExpanded(expanded === record.id ? null : record.id)}
                    className="border-b border-input-border/30 last:border-0 hover:bg-black/5 dark:hover:bg-white/5 transition-colors cursor-pointer group"
                  >
                    <td className="p-5 font-bold font-mono text-sm">{record.asset}</td>
                    <td className="p-5 font-bold text-sm bg-purple-500/10 text-purple-600 dark:text-purple-400 w-24 border-x border-purple-500/20">{record.keyLength}</td>
                    <td className="p-5">
                      <div className="font-bold text-xs bg-black/10 dark:bg-white/10 inline-flex px-2 py-1 rounded-md shadow-sm">
                        {record.tlsVersion}
                      </div>
                    </td>
                    <td className="p-5">
                      <div className="flex items-center gap-2">
                        {record.pqcStatus === 'Quantum Resistant' ? (
                          <ShieldCheck className="w-4 h-4 text-emerald-500" />
                        ) : record.pqcStatus === 'Non-Compliant' ? (
                          <AlertTriangle className="w-4 h-4 text-red-500" />
                        ) : (
                          <div className="w-2 h-2 rounded-full bg-orange-500 ml-1 mr-1 shadow-md shadow-orange-500/50" />
                        )}
                        <span className="font-bold text-sm text-card-foreground/80">{record.pqcStatus}</span>
                      </div>
                    </td>
                    <td className="p-5">
                      <div className="w-32 bg-input-border/40 rounded-full h-2.5 overflow-hidden shadow-inner flex items-center">
                        <div 
                          className={`h-full rounded-full shadow-sm ${
                            record.riskScore > 75 ? 'bg-red-500' :
                            record.riskScore > 40 ? 'bg-orange-500' :
                            'bg-emerald-500'
                          }`}
                          style={{ width: `${record.riskScore}%` }}
                        />
                      </div>
                    </td>
                    <td className="p-5 text-card-foreground/40 group-hover:text-primary transition-colors">
                      {expanded === record.id ? <ChevronUp className="w-5 h-5"/> : <ChevronDown className="w-5 h-5"/>}
                    </td>
                  </tr>
                  
                  {/* Expanded Row Details */}
                  {expanded === record.id && (
                    <tr className="bg-primary/5 dark:bg-primary/10 border-b border-input-border/30">
                      <td colSpan={6} className="p-6">
                        <div className="flex flex-col gap-4 animate-in fade-in slide-in-from-top-2">
                          <h4 className="font-black text-xs uppercase tracking-wider text-primary">Cryptographic Deep Inspection ({record.id.slice(0,8)})</h4>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <div className="bg-white/50 dark:bg-black/40 p-4 rounded-xl border border-input-border/30 shadow-sm">
                              <div className="text-xs font-bold text-card-foreground/50 mb-1">Cipher Suite Base</div>
                              <div className="font-mono font-bold text-xs break-all">{record.cipherSuite}</div>
                            </div>
                            <div className="bg-white/50 dark:bg-black/40 p-4 rounded-xl border border-input-border/30 shadow-sm">
                              <div className="text-xs font-bold text-card-foreground/50 mb-1">Certificate Authority</div>
                              <div className="font-bold text-sm">{record.ca}</div>
                            </div>
                            <div className="bg-white/50 dark:bg-black/40 p-4 rounded-xl border border-input-border/30 shadow-sm">
                              <div className="text-xs font-bold text-card-foreground/50 mb-1">Shor's Algorithm Threat</div>
                              <div className="font-bold text-sm text-red-500">{record.pqcStatus === 'Non-Compliant' ? 'High Probability' : 'Low / Resistant'}</div>
                            </div>
                            <div className="bg-white/50 dark:bg-black/40 p-4 rounded-xl border border-input-border/30 shadow-sm">
                              <div className="text-xs font-bold text-card-foreground/50 mb-1">Recommendation</div>
                              <div className="font-bold text-sm text-indigo-500">{record.pqcStatus === 'Non-Compliant' ? 'Migrate to ML-KEM' : 'Maintain Standard'}</div>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>

      </div>
    </div>
  );
}
