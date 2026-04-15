"use client";

import { useEffect, useState } from "react";
import { Gauge, ShieldAlert, TrendingUp } from "lucide-react";
import { Skeleton } from "../components/Skeleton";
import { AreaChart, Area, XAxis, Tooltip as RechartsTooltip, ResponsiveContainer } from "recharts";

export default function CyberRatingPage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    fetch("/api/rating")
      .then((res) => res.json())
      .then((resData) => setData(resData));
  }, []);

  if (!data) return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-6 animate-in fade-in p-10">
      <Skeleton className="h-[300px] rounded-[2.5rem] mb-4" />
      <Skeleton className="h-[500px] rounded-[2rem]" />
    </div>
  );

  // Gamified dial math (circumference of semi circle)
  const radius = 130;
  const stroke = 24;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * Math.PI;
  const strokeDashoffset = Math.max(0, circumference - ((data.score / data.maxScore) * circumference));

  return (
    <div className="w-full max-w-[90rem] mx-auto flex flex-col gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-20">
      
      {/* Top Section: Score Dial & Badge */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-2xl rounded-[2.5rem] p-8 sm:p-14 relative overflow-hidden flex flex-col md:flex-row items-center justify-between gap-12 h-full">
          <div className="absolute -top-48 -left-48 w-96 h-96 bg-emerald-500/20 rounded-full blur-3xl pointer-events-none" />
          
          <div className="relative z-10 w-full md:w-3/5">
            <h1 className="text-4xl sm:text-5xl font-black tracking-tight text-foreground mb-6 flex items-center gap-4">
              <Gauge className="w-10 h-10 text-emerald-500" />
              Cyber Rating
            </h1>
            <p className="font-semibold text-card-foreground/70 text-lg sm:text-xl leading-relaxed">
              Enterprise security posture score compiled from real-time asset scans, strict compliance tests, and deep cryptographic audits.
            </p>
          </div>

          <div className="relative z-10 w-72 h-36 flex justify-center overflow-hidden shrink-0 mt-8 md:mt-0">
            <svg height={radius * 2} width={radius * 2} className="rotate-180 drop-shadow-2xl">
              <circle
                stroke="rgba(16, 185, 129, 0.1)"
                fill="transparent"
                strokeWidth={stroke}
                strokeDasharray={`${circumference} ${circumference}`}
                style={{ strokeDashoffset: 0 }}
                r={normalizedRadius}
                cx={radius}
                cy={radius}
                strokeLinecap="round"
              />
              <circle
                stroke="#10b981"
                fill="transparent"
                strokeWidth={stroke}
                strokeDasharray={`${circumference} ${circumference}`}
                style={{ strokeDashoffset, transition: "stroke-dashoffset 2s cubic-bezier(0.4, 0, 0.2, 1)" }}
                r={normalizedRadius}
                cx={radius}
                cy={radius}
                className="animate-in fade-in duration-1000"
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute bottom-2 left-1/2 -translate-x-1/2 text-center flex flex-col items-center">
              <div className="text-6xl font-black text-emerald-500 tabular-nums tracking-tighter">{data.score}</div>
              <div className="text-xs font-black text-card-foreground/50 uppercase tracking-[0.3em] mt-1 ml-1">/ {data.maxScore}</div>
            </div>
          </div>
        </div>

        <div className="bg-card-background/60 backdrop-blur-3xl border border-white/20 shadow-xl rounded-[2.5rem] p-10 flex flex-col items-center justify-center text-center relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/10 to-blue-500/10 opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="text-sm font-bold text-card-foreground/70 mb-4 uppercase tracking-[0.2em]">Industry Tier</div>
          <div className="text-[6rem] font-black text-foreground bg-clip-text bg-gradient-to-br from-emerald-400 to-indigo-500 text-transparent drop-shadow-lg leading-none mb-2">
            {data.tier}
          </div>
          <div className="mt-6 px-5 py-2.5 bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 font-bold text-sm rounded-xl border border-emerald-500/20 shadow-sm">
            Top 15% Score Vector
          </div>
        </div>
      </div>

      {/* Exposure Timeline & Component Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* HNDL Timeline Chart */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-8 rounded-3xl shadow-lg h-[480px] flex flex-col relative overflow-hidden">
          <h3 className="font-extrabold text-2xl mb-2 flex items-center gap-2 relative z-10">
            <ShieldAlert className="w-6 h-6 text-red-500" />
            HNDL Threat Exposure Forecast
          </h3>
          <p className="text-sm text-card-foreground/60 mb-6 font-semibold relative z-10">
            Predicted risk probability of "Hack Now, Decrypt Later" intelligence harvesting leading up to Q-Day (2030).
          </p>
          <div className="flex-1 w-full min-h-0 relative z-10 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.hndlExposureTimeline}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" fontSize={12} tickLine={false} axisLine={false} tick={{fill: '#888', fontWeight: 'bold'}} />
                <RechartsTooltip cursor={{ stroke: 'rgba(255,255,255,0.1)' }} contentStyle={{ borderRadius: '16px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(5,5,5,0.85)', color: 'white', backdropFilter: 'blur(10px)' }} />
                <Area type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={5} fillOpacity={1} fill="url(#colorRisk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Component Breakdown Table */}
        <div className="bg-card-background/60 backdrop-blur-3xl border border-input-border/50 p-8 rounded-3xl shadow-lg h-[480px] overflow-y-auto">
          <h3 className="font-extrabold text-2xl mb-8 flex items-center gap-2">
            <TrendingUp className="w-6 h-6 text-indigo-500" />
            Component Metrics Breakdown
          </h3>
          <div className="flex flex-col gap-6">
            {data.components.map((comp: any, i: number) => (
              <div key={i} className="flex flex-col gap-3 p-5 bg-white/40 dark:bg-black/20 rounded-2xl border border-input-border/40 hover:shadow-md hover:-translate-y-1 transition-all">
                <div className="flex justify-between font-black text-lg">
                  <span className="text-foreground">{comp.name}</span>
                  <span className={`${comp.score < 500 ? 'text-red-500' : comp.score < 800 ? 'text-orange-500' : 'text-emerald-500'}`}>
                    {comp.score} <span className="text-xs text-card-foreground/50">/ {data.maxScore}</span>
                  </span>
                </div>
                <div className="h-3 w-full bg-input-border/60 rounded-full overflow-hidden shadow-inner border border-input-border/30">
                  <div 
                    className={`h-full rounded-full shadow-md ${
                      comp.score < 500 ? 'bg-red-500' : 
                      comp.score < 800 ? 'bg-orange-500' : 
                      'bg-emerald-500'
                    }`}
                    style={{ width: `${(comp.score / data.maxScore) * 100}%` }} 
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
