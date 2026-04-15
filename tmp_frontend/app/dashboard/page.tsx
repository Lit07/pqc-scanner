"use client";

import { useEffect, useState } from "react";
import { Activity, ShieldAlert, Key, Globe, Radio, Shield, MapPin, Search } from "lucide-react";
import { Skeleton } from "../components/Skeleton";
import { 
  PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, AreaChart, Area
} from "recharts";

export default function DashboardPage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    fetch("/api/dashboard/summary")
      .then((res) => res.json())
      .then((data) => setData(data));
  }, []);

  if (!data) return <DashboardSkeleton />;

  return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* 6 Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        {[
          { label: "Total Assets", value: data.stats.totalAssets, icon: Globe, color: "text-blue-500", shadow: "shadow-blue-500/20" },
          { label: "High Risk", value: data.stats.highRiskAssets, icon: ShieldAlert, color: "text-orange-500", shadow: "shadow-orange-500/20" },
          { label: "Critical Findings", value: data.stats.criticalFindings, icon: Activity, color: "text-red-500", shadow: "shadow-red-500/20" },
          { label: "Expiring Certs", value: data.stats.expiringCerts, icon: Key, color: "text-yellow-500", shadow: "shadow-yellow-500/20" },
          { label: "Cyber Score", value: `${data.stats.pqcScore}/1000`, icon: Shield, color: "text-emerald-500", shadow: "shadow-emerald-500/20" },
          { label: "Active Scans", value: data.stats.activeScans, icon: Radio, color: "text-purple-500", shadow: "shadow-purple-500/20" }
        ].map((stat, i) => (
          <div key={i} className={`bg-card-background/60 backdrop-blur-3xl border border-white/20 p-6 rounded-3xl shadow-xl ${stat.shadow} relative overflow-hidden group hover:-translate-y-1 transition-transform`}>
            <div className={`absolute -right-4 -bottom-4 w-16 h-16 rounded-full opacity-10 bg-current ${stat.color} transition-transform group-hover:scale-[2]`} />
            <div className="flex justify-between items-start mb-4">
              <span className={`p-2.5 rounded-2xl bg-white/50 dark:bg-black/20 shadow-sm ${stat.color} border border-input-border/50`}>
                <stat.icon className="w-6 h-6" />
              </span>
            </div>
            <div className="text-3xl font-black">{stat.value}</div>
            <div className="text-sm font-bold text-card-foreground/70 mt-1">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* 3 Charts Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg h-[400px] flex flex-col">
          <h3 className="font-extrabold text-lg mb-2">Asset Risk Distribution</h3>
          <p className="text-xs text-card-foreground/60 mb-4 font-semibold">Semantic risk categorization based on CVE payload analysis.</p>
          <div className="flex-1 w-full min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={data.charts.riskDistribution} innerRadius={70} outerRadius={110} paddingAngle={4} dataKey="value" stroke="none">
                  {data.charts.riskDistribution.map((entry: any, index: number) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <RechartsTooltip contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(5,5,5,0.85)', color: 'white', backdropFilter: 'blur(10px)' }} />
                <Legend iconType="circle" />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg h-[400px] flex flex-col">
          <h3 className="font-extrabold text-lg mb-2">Cipher Usage Distribution</h3>
          <p className="text-xs text-card-foreground/60 mb-4 font-semibold">Cryptographic suites mapped across discovered endpoints.</p>
          <div className="flex-1 w-full min-h-0 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.charts.cipherUsage}>
                <XAxis dataKey="name" fontSize={11} tickLine={false} axisLine={false} tick={{fill: '#888'}} />
                <YAxis fontSize={11} tickLine={false} axisLine={false} tick={{fill: '#888'}} width={35} />
                <RechartsTooltip cursor={{ fill: 'rgba(99, 102, 241, 0.1)', radius: 8 }} contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(5,5,5,0.85)', color: 'white', backdropFilter: 'blur(10px)' }} />
                <Bar dataKey="count" fill="#6366f1" radius={[6, 6, 0, 0]} barSize={40} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg h-[400px] flex flex-col">
          <h3 className="font-extrabold text-lg mb-2">Certificate Expiry Timeline</h3>
          <p className="text-xs text-card-foreground/60 mb-4 font-semibold">Forecasted vulnerabilities stemming from identity expiration.</p>
          <div className="flex-1 w-full min-h-0 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.charts.expiryTimeline}>
                <defs>
                  <linearGradient id="colorExp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="month" fontSize={11} tickLine={false} axisLine={false} tick={{fill: '#888'}} />
                <YAxis fontSize={11} tickLine={false} axisLine={false} tick={{fill: '#888'}} width={25} />
                <RechartsTooltip contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(5,5,5,0.85)', color: 'white', backdropFilter: 'blur(10px)' }} />
                <Area type="monotone" dataKey="expiring" stroke="#ef4444" strokeWidth={3} fillOpacity={1} fill="url(#colorExp)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Section: Activity & Geography */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Activity Feed */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-6 rounded-3xl shadow-lg h-full">
          <h3 className="font-extrabold text-xl mb-6 flex items-center gap-2"><Search className="w-5 h-5 text-primary"/> Recent Scan Activity</h3>
          <div className="flex flex-col gap-4">
            {data.activity.map((act: any) => (
              <div key={act.id} className="flex items-center justify-between p-4 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/40 hover:border-primary/40 transition-colors shadow-sm">
                <div>
                  <div className="font-black text-[0.95rem]">{act.target}</div>
                  <div className="text-xs font-bold text-card-foreground/70 mt-0.5">{act.action} <span className="mx-1">•</span> {act.time}</div>
                </div>
                <div className={`px-4 py-1.5 rounded-xl text-xs font-black shadow-sm ${
                  act.status === 'Critical' ? 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20' :
                  act.status === 'Success' ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20' :
                  'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20'
                }`}>
                  {act.status}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Geographic Distribution */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-8 rounded-3xl shadow-lg h-full relative overflow-hidden">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 opacity-5 pointer-events-none">
            <Globe className="w-[30rem] h-[30rem]" />
          </div>
          <h3 className="font-extrabold text-xl mb-6 flex items-center gap-2 relative z-10"><MapPin className="w-5 h-5 text-emerald-500"/> Geographic Origin Vectors</h3>
          <div className="flex flex-col gap-6 relative z-10 w-full mt-4">
            {data.geography.map((geo: any, i: number) => (
              <div key={i} className="flex flex-col gap-2.5">
                <div className="flex justify-between text-sm font-bold">
                  <span>{geo.region}</span>
                  <span className="text-card-foreground/70">{geo.count} Discovered Nodes</span>
                </div>
                <div className="h-3 w-full bg-input-border/40 rounded-full overflow-hidden shadow-inner border border-input-border/30">
                  <div 
                    className={`h-full rounded-full shadow-md ${geo.status === 'Warning' ? 'bg-orange-500' : 'bg-emerald-500'}`} 
                    style={{ width: `${Math.min((geo.count / 500) * 100, 100)}%` }} 
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-6 animate-in fade-in">
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        {[1,2,3,4,5,6].map((i) => <Skeleton key={i} className="h-40 rounded-3xl" />)}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {[1,2,3].map((i) => <Skeleton key={i} className="h-[400px] rounded-3xl" />)}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Skeleton className="h-[400px] rounded-3xl" />
        <Skeleton className="h-[400px] rounded-3xl" />
      </div>
    </div>
  );
}
