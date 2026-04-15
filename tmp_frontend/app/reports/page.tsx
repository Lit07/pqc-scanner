"use client";

import { useEffect, useState } from "react";
import { FileText, Download, Clock, ShieldCheck, AlertTriangle, TrendingUp, Loader2, RefreshCw, BarChart3 } from "lucide-react";
import { Skeleton } from "../components/Skeleton";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

export default function ReportsPage() {
  const [data, setData] = useState<any>(null);
  const [generating, setGenerating] = useState(false);

  const fetchData = () => {
    setData(null);
    fetch("/api/reports")
      .then((res) => res.json())
      .then((resData) => setData(resData));
  };

  useEffect(() => {
    fetchData();
  }, []);

  const generateExecutivePDF = () => {
    if (!data) return;
    setGenerating(true);

    const doc = new jsPDF();
    const d = data.dashboard;
    const r = data.rating;
    const c = data.cbom;
    
    // Title page
    doc.setFontSize(28);
    doc.setTextColor(59, 130, 246);
    doc.text("PQC Scanner", 14, 30);
    doc.setFontSize(18);
    doc.setTextColor(0, 0, 0);
    doc.text("Executive Security Report", 14, 42);
    doc.setFontSize(10);
    doc.setTextColor(120, 120, 120);
    doc.text(`Generated: ${new Date(data.generatedAt).toLocaleString()}`, 14, 52);
    doc.text("Classification: CONFIDENTIAL", 14, 58);
    
    doc.setDrawColor(59, 130, 246);
    doc.setLineWidth(0.5);
    doc.line(14, 64, 196, 64);
    
    // Enterprise Rating Summary
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text("1. Enterprise Cyber Rating", 14, 76);
    
    if (r) {
      autoTable(doc, {
        startY: 82,
        head: [['Metric', 'Value']],
        body: [
          ['Enterprise Score', `${r.score} / ${r.maxScore}`],
          ['Industry Tier', r.tier],
          ...r.components.map((c: any) => [c.name, `${c.score} / ${r.maxScore}`])
        ],
        theme: 'striped',
        headStyles: { fillColor: [16, 185, 129] },
        styles: { fontSize: 10 }
      });
    }
    
    // Dashboard stats
    const afterRating = (doc as any).lastAutoTable?.finalY || 130;
    doc.setFontSize(14);
    doc.text("2. Asset & Risk Summary", 14, afterRating + 14);
    
    if (d) {
      autoTable(doc, {
        startY: afterRating + 20,
        head: [['Metric', 'Value']],
        body: [
          ['Total Assets', `${d.stats.totalAssets}`],
          ['High Risk Assets', `${d.stats.highRiskAssets}`],
          ['Expiring Certificates', `${d.stats.expiringCerts}`],
          ['Active Scans', `${d.stats.activeScans}`],
          ['Critical Findings', `${d.stats.criticalFindings}`],
          ['Average PQC Score', `${d.stats.pqcScore}`],
        ],
        theme: 'striped',
        headStyles: { fillColor: [59, 130, 246] },
        styles: { fontSize: 10 }
      });
    }
    
    // New page for CBOM
    doc.addPage();
    doc.setFontSize(14);
    doc.text("3. Cryptographic Bill of Materials (CBOM)", 14, 20);
    
    if (c && c.cbomRecords?.length) {
      autoTable(doc, {
        startY: 28,
        head: [['Asset', 'Key Size', 'TLS', 'PQC Status', 'Risk %']],
        body: c.cbomRecords.map((rec: any) => [rec.asset, rec.keyLength, rec.tlsVersion, rec.pqcStatus, `${rec.riskScore}%`]),
        theme: 'grid',
        headStyles: { fillColor: [139, 92, 246] },
        styles: { fontSize: 9 }
      });
    }
    
    // HNDL Analysis
    const afterCbom = (doc as any).lastAutoTable?.finalY || 60;
    doc.setFontSize(14);
    doc.text("4. HNDL Threat Forecast", 14, afterCbom + 14);
    
    if (r?.hndlExposureTimeline?.length) {
      autoTable(doc, {
        startY: afterCbom + 20,
        head: [['Year', 'Risk Probability (%)']],
        body: r.hndlExposureTimeline.map((h: any) => [h.date, `${h.risk}%`]),
        theme: 'striped',
        headStyles: { fillColor: [239, 68, 68] },
        styles: { fontSize: 10 }
      });
    }
    
    // Footer
    const pages = doc.getNumberOfPages();
    for (let i = 1; i <= pages; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(150);
      doc.text(`Page ${i} of ${pages} | PQC Scanner Executive Report | CONFIDENTIAL`, 14, 290);
    }
    
    doc.save(`PQC_Executive_Report_${new Date().toISOString().split('T')[0]}.pdf`);
    setGenerating(false);
  };

  if (!data) return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-6 animate-in fade-in p-10">
      <Skeleton className="h-40 rounded-[2.5rem] mb-4" />
      <Skeleton className="h-[300px] rounded-[2rem]" />
    </div>
  );

  const d = data.dashboard;
  const r = data.rating;
  const c = data.cbom;

  return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* Header */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-8 relative overflow-hidden flex justify-between items-center flex-wrap gap-6">
        <div className="absolute -bottom-48 -right-48 w-96 h-96 bg-violet-500/20 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 flex items-center gap-4">
          <div className="w-16 h-16 bg-gradient-to-br from-violet-500 to-fuchsia-600 rounded-2xl flex items-center justify-center text-white shadow-xl shadow-violet-500/30">
            <FileText className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tight text-foreground">
              Executive Reports
            </h1>
            <p className="font-semibold text-card-foreground/70 mt-1">
              Generate comprehensive PDF reports for audit, compliance, and stakeholder review.
            </p>
          </div>
        </div>

        <div className="relative z-10 flex items-center gap-3">
          <button 
            onClick={fetchData}
            className="flex items-center gap-2 px-5 py-3 font-bold bg-white/50 dark:bg-black/20 border-2 border-input-border/50 hover:border-primary transition-colors rounded-xl shadow-sm"
          >
            <RefreshCw className="w-5 h-5 text-primary" />
            Refresh Data
          </button>
          <button 
            onClick={generateExecutivePDF}
            disabled={generating}
            className="flex items-center gap-2 px-6 py-3 font-bold bg-gradient-to-r from-violet-500 to-fuchsia-600 text-white hover:shadow-xl hover:shadow-violet-500/30 hover:-translate-y-0.5 transition-all rounded-xl shadow-md disabled:opacity-50"
          >
            {generating ? <Loader2 className="w-5 h-5 animate-spin" /> : <Download className="w-5 h-5" />}
            {generating ? "Generating..." : "Download Executive PDF"}
          </button>
        </div>
      </div>

      {/* Report Preview Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Enterprise Rating Card */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 rounded-[2rem] p-6 shadow-lg flex flex-col gap-4">
          <div className="flex items-center gap-3 border-b border-input-border/40 pb-4">
            <div className="w-10 h-10 bg-emerald-500/10 rounded-xl flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-emerald-500" />
            </div>
            <div>
              <h3 className="font-extrabold text-lg">Enterprise Rating</h3>
              <p className="text-xs text-card-foreground/50 font-semibold">Section 1 of Report</p>
            </div>
          </div>
          
          {r ? (
            <div className="flex flex-col gap-3">
              <div className="flex justify-between items-center">
                <span className="font-bold text-card-foreground/70">Score</span>
                <span className="text-3xl font-black text-emerald-500">{r.score}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="font-bold text-card-foreground/70">Tier</span>
                <span className="font-black text-lg text-foreground">{r.tier}</span>
              </div>
              {r.components?.map((comp: any, i: number) => (
                <div key={i} className="flex justify-between items-center text-sm">
                  <span className="font-semibold text-card-foreground/60">{comp.name}</span>
                  <span className="font-bold">{comp.score}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-card-foreground/50 font-semibold text-sm">No rating data. Run a scan first.</p>
          )}
        </div>
        
        {/* Risk Summary Card */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 rounded-[2rem] p-6 shadow-lg flex flex-col gap-4">
          <div className="flex items-center gap-3 border-b border-input-border/40 pb-4">
            <div className="w-10 h-10 bg-blue-500/10 rounded-xl flex items-center justify-center">
              <BarChart3 className="w-5 h-5 text-blue-500" />
            </div>
            <div>
              <h3 className="font-extrabold text-lg">Risk Summary</h3>
              <p className="text-xs text-card-foreground/50 font-semibold">Section 2 of Report</p>
            </div>
          </div>
          
          {d ? (
            <div className="flex flex-col gap-3">
              {[
                { label: "Total Assets", value: d.stats.totalAssets, color: "text-foreground" },
                { label: "High Risk", value: d.stats.highRiskAssets, color: "text-red-500" },
                { label: "Expiring Certs", value: d.stats.expiringCerts, color: "text-orange-500" },
                { label: "Critical Findings", value: d.stats.criticalFindings, color: "text-red-500" },
                { label: "Avg PQC Score", value: d.stats.pqcScore, color: "text-blue-500" },
              ].map((item, i) => (
                <div key={i} className="flex justify-between items-center">
                  <span className="font-semibold text-card-foreground/60 text-sm">{item.label}</span>
                  <span className={`font-black text-lg ${item.color}`}>{item.value}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-card-foreground/50 font-semibold text-sm">No dashboard data available.</p>
          )}
        </div>
        
        {/* HNDL Forecast Card */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 rounded-[2rem] p-6 shadow-lg flex flex-col gap-4">
          <div className="flex items-center gap-3 border-b border-input-border/40 pb-4">
            <div className="w-10 h-10 bg-red-500/10 rounded-xl flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-500" />
            </div>
            <div>
              <h3 className="font-extrabold text-lg">HNDL Forecast</h3>
              <p className="text-xs text-card-foreground/50 font-semibold">Section 4 of Report</p>
            </div>
          </div>
          
          {r?.hndlExposureTimeline?.length ? (
            <div className="flex flex-col gap-3">
              {r.hndlExposureTimeline.map((h: any, i: number) => (
                <div key={i} className="flex justify-between items-center">
                  <span className="font-semibold text-card-foreground/60 text-sm">{h.date}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-20 bg-input-border/40 rounded-full h-2 overflow-hidden">
                      <div className={`h-full rounded-full ${h.risk >= 70 ? 'bg-red-500' : h.risk >= 40 ? 'bg-orange-500' : 'bg-emerald-500'}`} style={{ width: `${h.risk}%` }} />
                    </div>
                    <span className={`font-black text-sm ${h.risk >= 70 ? 'text-red-500' : 'text-card-foreground/70'}`}>{h.risk}%</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-card-foreground/50 font-semibold text-sm">No HNDL data. Run scans to generate forecast.</p>
          )}
        </div>
      </div>

      {/* CBOM Preview */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 rounded-[2rem] p-6 shadow-lg">
        <div className="flex items-center gap-3 border-b border-input-border/40 pb-4 mb-4">
          <div className="w-10 h-10 bg-violet-500/10 rounded-xl flex items-center justify-center">
            <TrendingUp className="w-5 h-5 text-violet-500" />
          </div>
          <div>
            <h3 className="font-extrabold text-lg">CBOM Summary</h3>
            <p className="text-xs text-card-foreground/50 font-semibold">Section 3 of Report — Cryptographic asset inventory</p>
          </div>
        </div>

        {c?.cbomRecords?.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left min-w-[700px]">
              <thead>
                <tr className="bg-black/5 dark:bg-white/5">
                  <th className="p-3 text-xs tracking-wide font-black border-b border-input-border/50">Asset</th>
                  <th className="p-3 text-xs tracking-wide font-black border-b border-input-border/50">Key Size</th>
                  <th className="p-3 text-xs tracking-wide font-black border-b border-input-border/50">TLS</th>
                  <th className="p-3 text-xs tracking-wide font-black border-b border-input-border/50">PQC Status</th>
                  <th className="p-3 text-xs tracking-wide font-black border-b border-input-border/50">Risk</th>
                </tr>
              </thead>
              <tbody>
                {c.cbomRecords.map((rec: any, i: number) => (
                  <tr key={i} className="border-b border-input-border/20">
                    <td className="p-3 font-mono font-bold text-sm">{rec.asset}</td>
                    <td className="p-3 font-bold text-sm">{rec.keyLength}</td>
                    <td className="p-3 text-sm font-semibold">{rec.tlsVersion}</td>
                    <td className="p-3">
                      <span className={`px-2 py-1 rounded text-xs font-bold ${rec.pqcStatus === 'Non-Compliant' ? 'bg-red-500/10 text-red-500' : rec.pqcStatus === 'Quantum Resistant' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-orange-500/10 text-orange-500'}`}>
                        {rec.pqcStatus}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-sm">{rec.riskScore}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-card-foreground/50 font-semibold text-sm p-4">No CBOM data available. Run scans to generate.</p>
        )}
      </div>

      {/* Generated Timestamp */}
      <div className="flex items-center justify-center gap-2 text-card-foreground/40 text-sm font-semibold">
        <Clock className="w-4 h-4" />
        Report data fetched at {new Date(data.generatedAt).toLocaleString()}
      </div>
    </div>
  );
}
