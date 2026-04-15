"use client";

import { useState } from "react";
import { Search, Loader2, ShieldCheck, Download, AlertTriangle, CheckCircle } from "lucide-react";
import { Button } from "../components/Button";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

export default function ScanPage() {
  const [urls, setUrls] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState("");
  const [scanId, setScanId] = useState<string | null>(null);
  const [results, setResults] = useState<any>(null);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urls.trim()) return;

    setIsScanning(true);
    setProgress(0);
    setResults(null);
    setCurrentStage("Initializing Scanner Payload...");

    const res = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    
    const data = await res.json();
    setScanId(data.scan_id);

    // Start Websocket / Polling Simulation
    let stepNumber = 0;
    
    const pollInterval = setInterval(async () => {
      try {
        const statusRes = await fetch(`/api/scan/${data.scan_id}/status?step=${stepNumber}`);
        const statusData = await statusRes.json();
        
        setCurrentStage(statusData.label);
        setProgress(statusData.progress);
        
        if (statusData.complete) {
          clearInterval(pollInterval);
          
          // Fetch final results
          const resultsRes = await fetch(`/api/scan/${data.scan_id}/results`);
          const resultsData = await resultsRes.json();
          setResults(resultsData);
          setIsScanning(false);
        }
        stepNumber++;
      } catch (e) {
        clearInterval(pollInterval);
        setCurrentStage("Connection Error - Simulated WebSocket Dropped");
        setIsScanning(false);
      }
    }, 1500); // Poll every 1.5 seconds for dramatic effect
  };

  const exportPDF = () => {
    if (!results) return;
    const doc = new jsPDF();
    doc.text(`Vulnerability Scan Report - ID: ${scanId}`, 14, 15);
    doc.text(`Target: ${urls}`, 14, 25);
    
    autoTable(doc, {
      startY: 35,
      head: [['ID', 'Asset', 'Severity', 'Vulnerability Detail']],
      body: results.findings.map((f: any) => [f.id, f.asset, f.severity, f.detail]),
      theme: 'grid',
      headStyles: { fillColor: [99, 102, 241] }
    });
    
    doc.save(`Scan_Report_${scanId}.pdf`);
  };

  return (
    <div className="w-full max-w-5xl mx-auto flex flex-col gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* Search Console */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-8 sm:p-12 relative overflow-hidden">
        <div className="absolute -top-48 -right-48 w-96 h-96 bg-primary/20 rounded-full blur-3xl pointer-events-none" />
        
        <div className="text-center mb-10 relative z-10">
          <div className="w-20 h-20 bg-gradient-to-br from-primary to-indigo-500 rounded-3xl mx-auto flex items-center justify-center mb-6 shadow-xl shadow-primary/30 text-white">
            <Search className="w-10 h-10" />
          </div>
          <h1 className="text-4xl md:text-5xl font-black tracking-tight text-foreground bg-clip-text">
            PQC Asset Scanner
          </h1>
          <p className="text-card-foreground/70 font-semibold text-lg max-w-xl mx-auto mt-4">
            Enter a domain, IP address, or CIDR block to automatically map attack surfaces and intercept legacy cryptographic dependencies.
          </p>
        </div>

        <form onSubmit={startScan} className="relative z-10 w-full max-w-3xl mx-auto">
          <div className="relative group">
            <input 
              disabled={isScanning}
              value={urls}
              onChange={(e) => setUrls(e.target.value)}
              className="w-full bg-input-background/80 border-[3px] border-input-border/70 text-foreground font-black text-lg md:text-xl rounded-[2rem] px-8 py-6 sm:pr-[12rem] transition-all duration-300 outline-none shadow-xl shadow-black/5 focus:bg-white dark:focus:bg-slate-900 focus:border-primary focus:ring-8 focus:ring-primary/20 disabled:opacity-50"
              placeholder="e.g. pnb.in, 192.168.1.0/24"
            />
            <Button 
              type="submit" 
              disabled={isScanning || !urls.trim()}
              className="mt-4 sm:mt-0 sm:absolute right-3 top-3 bottom-3 w-full sm:w-44 shadow-none text-base bg-gradient-to-r from-primary to-blue-500 hover:from-primary hover:to-indigo-500 rounded-[1.5rem]"
            >
              {isScanning ? (
                <><Loader2 className="w-5 h-5 animate-spin mr-2"/> Scanning</>
              ) : (
                <><ShieldCheck className="w-5 h-5 mr-2"/> Start Scan</>
              )}
            </Button>
          </div>
        </form>

        {/* Live Progression Websocket Simulation */}
        {isScanning && (
          <div className="mt-12 w-full max-w-3xl mx-auto bg-black/5 dark:bg-white/5 p-6 rounded-[2rem] border border-input-border/50">
            <div className="flex justify-between items-center mb-4">
              <span className="font-bold text-sm text-primary flex items-center gap-2">
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-primary"></span>
                </span>
                Live Socket Connection: [ACTIVE]
              </span>
              <span className="font-black text-xl">{progress}%</span>
            </div>
            
            <div className="w-full bg-input-border/40 rounded-full h-4 mb-4 overflow-hidden border border-input-border/30 shadow-inner">
              <div 
                className="bg-primary h-4 rounded-full transition-all duration-1000 ease-out shadow-lg" 
                style={{ width: `${progress}%` }}
              ></div>
            </div>
            
            <div className="text-center font-bold text-card-foreground/80 animate-pulse mt-2">
              [SYSTEM] {currentStage}
            </div>
          </div>
        )}
      </div>

      {/* Results Output Canvas */}
      {results && !isScanning && (
        <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-8 sm:p-12 animate-in slide-in-from-bottom-8 fade-in flex flex-col gap-8">
          
          <div className="flex justify-between items-center flex-wrap gap-4">
            <div>
              <h2 className="text-3xl font-black mb-2 flex items-center gap-2">
                <CheckCircle className="w-8 h-8 text-emerald-500" />
                Scan Completed
              </h2>
              <p className="font-semibold text-card-foreground/70">Scan ID: <span className="font-mono text-xs p-1 bg-black/10 dark:bg-white/10 rounded-md ml-1">{scanId}</span></p>
            </div>
            <button 
              onClick={exportPDF}
              className="flex items-center gap-2 px-5 py-3 font-bold bg-white/50 dark:bg-black/20 border-2 border-input-border hover:bg-white dark:hover:bg-black/50 transition-colors rounded-xl shadow-sm"
            >
              <Download className="w-5 h-5 text-indigo-500" />
              Export as PDF
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/50 shadow-sm text-center">
              <div className="text-4xl font-black text-primary mb-2">{results.identifiedAssets}</div>
              <div className="font-bold text-sm text-card-foreground/70">Assets Identified</div>
            </div>
            <div className="p-6 bg-red-500/10 rounded-2xl border border-red-500/20 shadow-sm text-center">
              <div className="text-4xl font-black text-red-600 dark:text-red-400 mb-2">{results.criticalVulnerabilities}</div>
              <div className="font-bold text-sm text-red-600/70 dark:text-red-400/70">Critical PQC Vulnerabilities</div>
            </div>
            <div className="p-6 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/50 shadow-sm text-center">
              <div className="text-4xl font-black text-emerald-500 mb-2">{results.overallScore}</div>
              <div className="font-bold text-sm text-card-foreground/70">Cyber Threat Score</div>
            </div>
          </div>

          <div className="mt-4">
            <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-500" />
              Risk Findings
            </h3>
            <div className="border border-input-border/50 rounded-2xl overflow-hidden shadow-sm bg-white/20 dark:bg-black/10">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-black/5 dark:bg-white/5 border-b border-input-border/50">
                    <th className="p-4 font-black">Asset</th>
                    <th className="p-4 font-black w-32">Severity</th>
                    <th className="p-4 font-black">Vulnerability Type</th>
                  </tr>
                </thead>
                <tbody>
                  {results.error ? (
                    <tr>
                      <td colSpan={3} className="p-8 text-center text-red-500 font-bold bg-red-500/10">
                        Scan Failed: {results.error}
                      </td>
                    </tr>
                  ) : (
                    results.findings?.map((finding: any, idx: number) => (
                      <tr key={idx} className="border-b border-input-border/30 last:border-0 hover:bg-white/40 dark:hover:bg-black/30 transition-colors">
                        <td className="p-4 font-bold font-mono text-sm">{finding.asset}</td>
                        <td className="p-4">
                          <span className={`px-3 py-1 rounded-lg text-xs font-bold ${
                            finding.severity === 'Critical' ? 'bg-red-500/20 text-red-600 dark:text-red-400 border border-red-500/20' :
                            finding.severity === 'High' ? 'bg-orange-500/20 text-orange-600 dark:text-orange-400 border border-orange-500/20' :
                            'bg-yellow-500/20 text-yellow-600 dark:text-yellow-400 border border-yellow-500/20'
                          }`}>
                            {finding.severity}
                          </span>
                        </td>
                        <td className="p-4">
                          <div className="font-bold">{finding.type}</div>
                          <div className="text-xs text-card-foreground/70 mt-1 font-medium">{finding.detail}</div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* AI Risk Narrative */}
          {results.aiNarrative && !results.error && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
              <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg flex flex-col relative overflow-hidden">
                <h3 className="font-extrabold text-xl mb-4 flex items-center gap-2 relative z-10">
                  <span className="bg-indigo-500 text-white w-8 h-8 rounded-full flex items-center justify-center font-black">AI</span>
                  Executive Summary
                </h3>
                <p className="text-foreground/80 leading-relaxed font-semibold relative z-10">
                  {results.aiNarrative.executive_summary}
                </p>
                <div className="mt-4 pt-4 border-t border-input-border/30 relative z-10">
                  <div className="text-sm font-bold text-card-foreground/50 mb-2 uppercase tracking-widest">Risk Story</div>
                  <p className="text-sm text-foreground/70 italic">"{results.aiNarrative.risk_story}"</p>
                </div>
              </div>

              <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg flex flex-col relative overflow-hidden h-full">
                <h3 className="font-extrabold text-xl mb-4 flex items-center gap-2 relative z-10">
                  <ShieldCheck className="w-6 h-6 text-emerald-500" />
                  HNDL & PQC Assessment
                </h3>
                
                <div className="grid grid-cols-2 gap-4 h-full">
                  <div className="p-4 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/40 flex flex-col justify-center">
                    <div className="text-xs font-bold text-card-foreground/60 uppercase">HNDL Threat Level</div>
                    <div className={`font-black text-2xl mt-1 ${results.pqcTracker?.hndl_threat_level === 'Minimal' ? 'text-emerald-500' : 'text-orange-500'}`}>
                      {results.pqcTracker?.hndl_threat_level || "Unknown"}
                    </div>
                  </div>
                  <div className="p-4 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/40 flex flex-col justify-center">
                    <div className="text-xs font-bold text-card-foreground/60 uppercase">Q-Day Decrypt Year</div>
                    <div className="font-black text-2xl mt-1 text-red-500 font-mono">
                      {results.pqcTracker?.estimated_decrypt_year || "Safe"}
                    </div>
                  </div>
                  <div className="col-span-2 p-4 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/40 flex items-center justify-between">
                    <div className="text-xs font-bold text-card-foreground/60 uppercase">Compliance Class</div>
                    <div className="text-sm font-black bg-indigo-500/10 text-indigo-500 px-3 py-1 rounded-md border border-indigo-500/20">
                      {results.pqcTracker?.classification || "Evaluation Required"}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* AI Recommendations */}
          {results.recommendations && results.recommendations.length > 0 && (
            <div className="mt-2 bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border border-indigo-500/20 rounded-3xl p-6 sm:p-8">
               <h3 className="font-extrabold text-xl mb-6 flex items-center gap-2 text-indigo-500">
                Actionable Next Steps
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {results.recommendations.map((rec: any, idx: number) => (
                  <div key={idx} className="flex gap-4 p-4 bg-white/60 dark:bg-black/40 rounded-2xl shadow-sm border border-input-border/40 relative overflow-hidden group hover:-translate-y-1 transition-transform">
                     <div className={`absolute top-0 left-0 w-1.5 h-full ${rec.impact === 'Critical' ? 'bg-red-500' : 'bg-indigo-500'}`}></div>
                     <div className="flex-1">
                        <div className="font-black text-sm text-foreground mb-1">{rec.action || rec.recommendation}</div>
                        <div className="font-semibold text-xs text-card-foreground/70">{rec.trigger || "Remediation Phase"}</div>
                     </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
}
