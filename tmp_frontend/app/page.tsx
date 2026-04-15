import { Button } from "./components/Button";
import Link from "next/link";
import { ArrowRight, Code2, ShieldCheck, Radar, CheckCircle2 } from "lucide-react";

export default function LandingPage() {
  const highlights = [
    "Surface legacy cryptography and exposed endpoints before they become migration blockers.",
    "Give security, infrastructure, and leadership teams one shared view of risk and readiness.",
    "Keep the experience grounded in banking operations instead of generic dashboard filler.",
  ];

  const features = [
    {
      icon: Radar,
      title: "Find what is exposed",
      desc: "Map public-facing services, certificates, and protocol posture from one cleaner starting point.",
    },
    {
      icon: ShieldCheck,
      title: "Prioritize with context",
      desc: "Turn scan output into a review flow that makes sense for teams handling real environments.",
    },
    {
      icon: Code2,
      title: "Built to feel usable",
      desc: "The flow stays simple, direct, and readable so the product feels closer to a real platform than a demo shell.",
    },
  ];

  return (
    <div className="flex w-full max-w-6xl flex-col gap-12 pt-6 md:pt-10">
      <section className="grid gap-8 lg:grid-cols-[1.15fr_0.85fr] lg:items-center">
        <div className="text-left">
          <div className="mb-6 inline-flex items-center rounded-full border border-primary/15 bg-primary/8 px-4 py-2 text-sm font-semibold text-primary shadow-sm backdrop-blur">
            PNB Hackathon submission
          </div>

          <h1 className="max-w-3xl text-4xl font-black tracking-tight text-foreground sm:text-5xl lg:text-6xl">
            A clearer way to review cryptographic risk across banking infrastructure.
          </h1>

          <p className="mt-6 max-w-2xl text-lg leading-8 text-card-foreground/75 sm:text-xl">
            This prototype helps teams discover exposed assets, inspect current cryptographic posture, and begin post-quantum planning without wading through noisy dashboards.
          </p>

          <div className="mt-8 flex flex-col gap-4 sm:flex-row">
            <Link href="/register" className="w-full sm:w-auto">
              <Button className="h-14 w-full px-8 sm:w-auto">
                Create an account
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
            </Link>
            <Link href="/login" className="w-full sm:w-auto">
              <button className="flex h-14 w-full items-center justify-center rounded-2xl border border-input-border/70 bg-white/70 px-8 text-base font-semibold text-foreground transition hover:bg-white dark:bg-slate-950/35 dark:hover:bg-slate-900/55 sm:w-auto">
                Sign in
              </button>
            </Link>
          </div>

          <div className="mt-8 grid gap-3">
            {highlights.map((item) => (
              <div
                key={item}
                className="flex items-start gap-3 rounded-2xl border border-white/55 bg-white/55 px-4 py-3 text-sm text-card-foreground/80 shadow-sm backdrop-blur dark:border-white/8 dark:bg-slate-950/30"
              >
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                <span>{item}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative overflow-hidden rounded-[2rem] border border-white/60 bg-[linear-gradient(145deg,rgba(255,255,255,0.9),rgba(232,240,255,0.72))] p-6 shadow-[0_30px_80px_-40px_rgba(37,99,235,0.45)] dark:border-white/10 dark:bg-[linear-gradient(145deg,rgba(15,23,42,0.82),rgba(30,41,59,0.58))]">
          <div className="absolute inset-x-0 top-0 h-28 bg-linear-to-b from-primary/12 to-transparent" />
          <div className="relative space-y-5">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.22em] text-primary/75">
                Product snapshot
              </p>
              <h2 className="mt-2 text-2xl font-bold tracking-tight text-foreground">
                Security telemetry that reads like a working product, not just a demo.
              </h2>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-white/60 bg-white/72 p-4 dark:border-white/10 dark:bg-slate-950/35">
                <p className="text-sm text-card-foreground/65">Visibility</p>
                <p className="mt-2 text-2xl font-bold">360 deg</p>
              </div>
              <div className="rounded-2xl border border-white/60 bg-white/72 p-4 dark:border-white/10 dark:bg-slate-950/35">
                <p className="text-sm text-card-foreground/65">Focus</p>
                <p className="mt-2 text-2xl font-bold">PQC-ready</p>
              </div>
              <div className="rounded-2xl border border-white/60 bg-white/72 p-4 dark:border-white/10 dark:bg-slate-950/35">
                <p className="text-sm text-card-foreground/65">Output</p>
                <p className="mt-2 text-2xl font-bold">Actionable</p>
              </div>
            </div>

            <div className="rounded-[1.75rem] border border-primary/12 bg-slate-950 px-5 py-5 text-slate-50 shadow-xl shadow-slate-950/15">
              <div className="flex items-center justify-between text-sm text-slate-300">
                <span>Exposure summary</span>
                <span>Updated just now</span>
              </div>
              <div className="mt-5 space-y-4">
                <div>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span>Internet-facing services mapped</span>
                    <span className="font-semibold">82%</span>
                  </div>
                  <div className="h-2 rounded-full bg-white/10">
                    <div className="h-2 w-[82%] rounded-full bg-linear-to-r from-sky-400 to-cyan-300" />
                  </div>
                </div>
                <div>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span>Legacy crypto flagged for review</span>
                    <span className="font-semibold">31%</span>
                  </div>
                  <div className="h-2 rounded-full bg-white/10">
                    <div className="h-2 w-[31%] rounded-full bg-linear-to-r from-amber-400 to-orange-300" />
                  </div>
                </div>
                <div>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span>Migration planning coverage</span>
                    <span className="font-semibold">64%</span>
                  </div>
                  <div className="h-2 rounded-full bg-white/10">
                    <div className="h-2 w-[64%] rounded-full bg-linear-to-r from-emerald-400 to-lime-300" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-5 md:grid-cols-3">
        {features.map((feature) => (
          <div
            key={feature.title}
            className="rounded-[1.75rem] border border-white/55 bg-card-background/72 p-7 shadow-[0_18px_45px_-35px_rgba(15,23,42,0.55)] backdrop-blur-xl"
          >
            <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10 text-primary">
              <feature.icon className="h-6 w-6" />
            </div>
            <h3 className="text-xl font-bold tracking-tight">{feature.title}</h3>
            <p className="mt-3 text-sm leading-7 text-card-foreground/72">{feature.desc}</p>
          </div>
        ))}
      </section>
    </div>
  );
}
