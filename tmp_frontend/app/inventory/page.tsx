"use client";

import { useEffect, useState } from "react";
import { Database, Download, Search, Filter, Plus, PlayCircle, X, Loader2 } from "lucide-react";
import { Skeleton } from "../components/Skeleton";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

export default function AssetInventoryPage() {
  const [data, setData] = useState<any>(null);
  const [filter, setFilter] = useState("All");
  const [searchTerm, setSearchTerm] = useState("");
  const [showAddModal, setShowAddModal] = useState(false);
  const [addHostname, setAddHostname] = useState("");
  const [addType, setAddType] = useState("Web Application");
  const [addOwner, setAddOwner] = useState("");
  const [addLoading, setAddLoading] = useState(false);
  const [addError, setAddError] = useState("");
  const [scanningAll, setScanningAll] = useState(false);
  const [scanAllStatus, setScanAllStatus] = useState("");

  const fetchAssets = () => {
    fetch("/api/assets")
      .then((res) => res.json())
      .then((resData) => setData(resData));
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleAddAsset = async () => {
    if (!addHostname.trim()) {
      setAddError("Hostname is required");
      return;
    }
    setAddLoading(true);
    setAddError("");
    try {
      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";
      const res = await fetch(`${backendUrl}/api/v1/assets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hostname: addHostname.trim(),
          asset_type: addType,
          owner: addOwner.trim() || null
        })
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to add asset");
      }
      setShowAddModal(false);
      setAddHostname("");
      setAddOwner("");
      fetchAssets();
    } catch (err: any) {
      setAddError(err.message);
    } finally {
      setAddLoading(false);
    }
  };

  const handleScanAll = async () => {
    if (!data?.assets?.length) return;
    setScanningAll(true);
    setScanAllStatus("Starting batch scan...");
    
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";
    let completed = 0;
    const total = data.assets.length;
    
    for (const asset of data.assets) {
      setScanAllStatus(`Scanning ${asset.name} (${completed + 1}/${total})...`);
      try {
        await fetch(`${backendUrl}/api/v1/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ hostname: asset.name })
        });
      } catch {
        // Continue scanning even if one fails
      }
      completed++;
    }
    
    setScanAllStatus(`✅ Completed ${completed}/${total} scans`);
    fetchAssets();
    setTimeout(() => {
      setScanningAll(false);
      setScanAllStatus("");
    }, 3000);
  };

  const exportPDF = () => {
    if (!data) return;
    const doc = new jsPDF();
    doc.text(`Asset Inventory Report`, 14, 15);
    
    autoTable(doc, {
      startY: 25,
      head: [['Asset', 'Type', 'IP Address', 'Risk Tier', 'PQC Ready', 'Cert Valid (Days)']],
      body: data.assets.map((r: any) => [r.name, r.type, r.ip, r.riskTier, r.pqcReady ? 'Yes' : 'No', r.certValidDays]),
      theme: 'grid',
      headStyles: { fillColor: [59, 130, 246] }
    });
    
    doc.save(`Asset_Inventory.pdf`);
  };

  if (!data) return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-6 animate-in fade-in p-10">
      <Skeleton className="h-40 rounded-[2.5rem] mb-4" />
      <Skeleton className="h-[600px] rounded-[2rem]" />
    </div>
  );

  const filteredAssets = (data.assets || [])
    .filter((a: any) => {
      if (filter === "All") return true;
      if (filter === "PQC Ready") return a.pqcReady;
      return a.riskTier === filter;
    })
    .filter((a: any) => 
      a.name?.toLowerCase().includes(searchTerm.toLowerCase()) || 
      a.ip?.toLowerCase().includes(searchTerm.toLowerCase())
    );

  return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* Header Panel */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-8 relative overflow-hidden flex justify-between items-center flex-wrap gap-6">
        <div className="absolute -bottom-48 -left-48 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 flex items-center gap-4">
          <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl flex items-center justify-center text-white shadow-xl shadow-blue-500/30">
            <Database className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tight text-foreground">
              Asset Inventory
            </h1>
            <p className="font-semibold text-card-foreground/70 mt-1">
              Comprehensive list of all discovered and registered digital assets.
            </p>
          </div>
        </div>

        <div className="relative z-10 flex items-center gap-3 flex-wrap">
          <button 
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-5 py-3 font-bold bg-gradient-to-r from-blue-500 to-indigo-600 text-white hover:shadow-xl hover:shadow-blue-500/30 hover:-translate-y-0.5 transition-all rounded-xl shadow-md"
          >
            <Plus className="w-5 h-5" />
            Add Asset
          </button>
          <button 
            onClick={handleScanAll}
            disabled={scanningAll}
            className="flex items-center gap-2 px-5 py-3 font-bold bg-gradient-to-r from-emerald-500 to-teal-600 text-white hover:shadow-xl hover:shadow-emerald-500/30 hover:-translate-y-0.5 transition-all rounded-xl shadow-md disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {scanningAll ? <Loader2 className="w-5 h-5 animate-spin" /> : <PlayCircle className="w-5 h-5" />}
            {scanningAll ? "Scanning..." : "Scan All"}
          </button>
          <button 
            onClick={exportPDF}
            className="flex items-center gap-2 px-5 py-3 font-bold bg-white/50 dark:bg-black/20 border-2 border-primary/30 hover:border-primary hover:bg-white dark:hover:bg-black/50 transition-colors rounded-xl shadow-sm"
          >
            <Download className="w-5 h-5 text-primary" />
            Export PDF
          </button>
        </div>
      </div>

      {/* Scan All Status Banner */}
      {scanAllStatus && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-2xl p-4 flex items-center gap-3 animate-in fade-in">
          {scanningAll && <Loader2 className="w-5 h-5 text-emerald-500 animate-spin" />}
          <span className="font-bold text-emerald-600 dark:text-emerald-400">{scanAllStatus}</span>
        </div>
      )}

      {/* Main Table */}
      <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-xl rounded-[2rem] overflow-hidden">
        
        {/* Toolbar */}
        <div className="bg-black/5 dark:bg-white/5 p-4 flex justify-between items-center border-b border-input-border/50 flex-wrap gap-4">
          <div className="relative w-full max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-card-foreground/40" />
            <input 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by IP or name..."
              className="w-full bg-white/40 dark:bg-black/40 border-[2px] border-input-border/60 rounded-xl py-2.5 pl-9 pr-4 outline-none focus:border-blue-500 font-semibold text-sm transition-colors shadow-inner"
            />
          </div>
          
          <div className="flex items-center gap-2 overflow-x-auto pb-2 sm:pb-0 scrollbar-hide flex-nowrap">
            <Filter className="w-4 h-4 text-card-foreground/50 mr-2 shrink-0" />
            {["All", "Critical", "High", "Medium", "PQC Ready"].map(f => (
              <button 
                key={f}
                onClick={() => setFilter(f)}
                className={`px-4 py-1.5 rounded-lg text-sm font-bold transition-colors whitespace-nowrap ${
                  filter === f 
                    ? 'bg-blue-500 text-white shadow-md shadow-blue-500/20' 
                    : 'bg-white/50 dark:bg-black/20 text-card-foreground/70 hover:bg-white dark:hover:bg-black/40 border border-input-border/50'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* Data Matrix */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[900px]">
            <thead>
              <tr className="bg-black/5 dark:bg-white/5">
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">Asset Name</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">Type & IP</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">Risk Tier</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">PQC Ready</th>
                <th className="p-5 text-sm tracking-wide font-black border-b border-input-border/50">Cert Expiry</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.length === 0 ? (
                <tr><td colSpan={5} className="text-center p-10 font-bold text-card-foreground/50">No assets found. Click "Add Asset" to register one.</td></tr>
              ) : null}
              {filteredAssets.map((record: any) => (
                <tr key={record.id} className="border-b border-input-border/30 last:border-0 hover:bg-black/5 dark:hover:bg-white/5 transition-colors">
                  <td className="p-5 font-bold font-mono text-sm">{record.name}</td>
                  <td className="p-5">
                    <div className="font-bold text-sm bg-black/10 dark:bg-white/10 px-2 py-0.5 rounded-md inline-flex border border-input-border/30">{record.type}</div>
                    <div className="text-xs text-card-foreground/50 font-mono mt-2 pl-1">{record.ip}</div>
                  </td>
                  <td className="p-5">
                    <span className={`px-3 py-1.5 rounded-lg text-xs font-bold shadow-sm ${
                      record.riskTier === 'Critical' ? 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20' :
                      record.riskTier === 'High' ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20' :
                      record.riskTier === 'Medium' ? 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border border-yellow-500/20' :
                      'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                    }`}>
                      {record.riskTier}
                    </span>
                  </td>
                  <td className="p-5 font-bold text-sm text-card-foreground/70">
                    {record.pqcReady ? <span className="text-emerald-500">True</span> : <span className="text-red-500">False</span>}
                  </td>
                  <td className="p-5 font-bold text-sm">
                    {record.certValidDays} Days
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Asset Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-[999] flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in" onClick={() => setShowAddModal(false)}>
          <div className="bg-card-background border border-input-border/50 rounded-3xl p-8 shadow-2xl w-full max-w-lg mx-4 animate-in zoom-in-95 slide-in-from-bottom-4" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-black flex items-center gap-3">
                <Plus className="w-6 h-6 text-blue-500" />
                Register New Asset
              </h2>
              <button onClick={() => setShowAddModal(false)} className="p-2 rounded-xl hover:bg-input-border/30 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="flex flex-col gap-5">
              <div>
                <label className="text-sm font-bold text-card-foreground/70 mb-2 block">Hostname / URL *</label>
                <input 
                  value={addHostname}
                  onChange={(e) => setAddHostname(e.target.value)}
                  placeholder="e.g. www.google.com"
                  className="w-full bg-white/40 dark:bg-black/40 border-[2px] border-input-border/60 rounded-xl py-3 px-4 outline-none focus:border-blue-500 font-semibold text-sm transition-colors shadow-inner"
                />
              </div>
              <div>
                <label className="text-sm font-bold text-card-foreground/70 mb-2 block">Asset Type</label>
                <select 
                  value={addType}
                  onChange={(e) => setAddType(e.target.value)}
                  className="w-full bg-white/40 dark:bg-black/40 border-[2px] border-input-border/60 rounded-xl py-3 px-4 outline-none focus:border-blue-500 font-semibold text-sm transition-colors shadow-inner"
                >
                  <option>Web Application</option>
                  <option>API Endpoint</option>
                  <option>Mail Server</option>
                  <option>Database</option>
                  <option>CDN</option>
                  <option>Other</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-bold text-card-foreground/70 mb-2 block">Owner (optional)</label>
                <input 
                  value={addOwner}
                  onChange={(e) => setAddOwner(e.target.value)}
                  placeholder="e.g. Security Team"
                  className="w-full bg-white/40 dark:bg-black/40 border-[2px] border-input-border/60 rounded-xl py-3 px-4 outline-none focus:border-blue-500 font-semibold text-sm transition-colors shadow-inner"
                />
              </div>
              
              {addError && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-red-600 dark:text-red-400 font-bold text-sm">
                  {addError}
                </div>
              )}
              
              <button 
                onClick={handleAddAsset}
                disabled={addLoading}
                className="w-full py-3.5 bg-gradient-to-r from-blue-500 to-indigo-600 text-white font-bold rounded-xl shadow-lg shadow-blue-500/30 hover:shadow-xl hover:-translate-y-0.5 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {addLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Plus className="w-5 h-5" />}
                {addLoading ? "Registering..." : "Register Asset"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
