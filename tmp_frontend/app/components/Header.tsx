"use client";

import { useTheme } from "next-themes";
import {
  Moon,
  Sun,
  LogOut,
  LayoutDashboard,
  Database,
  Search,
  ShieldCheck,
  Box,
  Hourglass,
  Gauge,
  Map,
  FileText,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
import { useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import Image from "next/image";

const NAV_LINKS = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "Inventory", href: "/inventory", icon: Database },
  { name: "Discovery", href: "/discovery", icon: Search },
  { name: "Scan", href: "/scan", icon: ShieldCheck },
  { name: "CBOM", href: "/cbom", icon: Box },
  { name: "PQC", href: "/pqc", icon: Hourglass },
  { name: "Heatmap", href: "/heatmap", icon: Map },
  { name: "Rating", href: "/rating", icon: Gauge },
  { name: "Reports", href: "/reports", icon: FileText },
];

export function Header({ isLoggedIn = false }: { isLoggedIn?: boolean }) {
  const { theme, setTheme } = useTheme();
  const [isNavOpen, setIsNavOpen] = useState(false);
  const pathname = usePathname();

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/";
  };

  return (
    <header className="sticky top-0 z-50 w-full px-4 pt-4">
      <div className="mx-auto flex w-full max-w-[90rem] flex-col gap-3 rounded-[1.75rem] border border-white/55 bg-card-background/88 p-3 shadow-[0_18px_50px_-32px_rgba(15,23,42,0.45)] backdrop-blur-xl dark:border-white/10">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            {isLoggedIn && (
              <button
                type="button"
                onClick={() => setIsNavOpen((open) => !open)}
                className="flex h-11 w-11 items-center justify-center rounded-2xl border border-input-border/50 bg-white/65 text-card-foreground shadow-sm transition hover:border-primary/35 hover:text-primary xl:hidden dark:bg-slate-950/40"
                aria-label={isNavOpen ? "Close navigation" : "Open navigation"}
                aria-expanded={isNavOpen}
              >
                {isNavOpen ? <PanelLeftClose className="h-5 w-5" /> : <PanelLeftOpen className="h-5 w-5" />}
              </button>
            )}

            <Link href="/" className="min-w-0">
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-linear-to-br from-primary to-sky-500 text-sm font-black text-white shadow-lg shadow-primary/20">
                  PQ
                </div>
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold uppercase tracking-[0.24em] text-primary/75">
                    PQC Scanner
                  </p>
                  <p className="truncate text-base font-bold tracking-tight text-foreground">
                    Banking crypto visibility platform
                  </p>
                </div>
              </div>
            </Link>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className="relative h-11 w-11 rounded-2xl border border-input-border/40 bg-white/65 transition-colors hover:bg-white dark:bg-slate-950/40 dark:hover:bg-slate-900/70"
              aria-label="Toggle theme"
            >
              <Sun className="absolute top-1/2 left-1/2 h-5 w-5 -translate-x-1/2 -translate-y-1/2 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
              <Moon className="absolute top-1/2 left-1/2 h-5 w-5 -translate-x-1/2 -translate-y-1/2 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
            </button>
            {isLoggedIn && (
              <button
                onClick={handleLogout}
                className="group hidden h-11 items-center gap-2 rounded-2xl border border-red-500/20 bg-red-500/8 px-4 text-sm font-semibold text-red-600 transition hover:bg-red-500 hover:text-white md:flex dark:text-red-300"
              >
                <LogOut className="h-4 w-4 transition-transform group-hover:-translate-x-0.5" />
                Sign out
              </button>
            )}
          </div>
        </div>

        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="hidden items-center rounded-2xl border border-black/8 bg-[#fcf8ec] px-4 py-2 shadow-sm dark:border-white/10 dark:bg-white lg:flex">
            <div className="flex items-center gap-3 opacity-90">
              <Image src="/assets/dfs.png" alt="DFS" width={52} height={26} className="h-6 w-auto object-contain" />
              <div className="h-6 w-px bg-black/15" />
              <Image src="/assets/iba.png" alt="IBA" width={52} height={26} className="h-7 w-auto object-contain" />
              <div className="h-6 w-px bg-black/15" />
              <Image src="/assets/pnb.png" alt="PNB" width={52} height={26} className="h-6 w-auto object-contain" />
              <div className="h-6 w-px bg-black/15" />
              <Image src="/assets/iitkp.png" alt="IIT Kanpur" width={52} height={26} className="h-7 w-auto object-contain" />
            </div>
          </div>

          {isLoggedIn && (
            <nav
              className={`${
                isNavOpen ? "flex" : "hidden"
              } flex-col gap-2 rounded-2xl border border-input-border/45 bg-white/70 p-2 shadow-sm xl:flex xl:flex-row xl:flex-wrap xl:justify-end xl:border-0 xl:bg-transparent xl:p-0 xl:shadow-none dark:bg-slate-950/45`}
            >
              {NAV_LINKS.map((link) => {
                const isActive = pathname.startsWith(link.href);
                const Icon = link.icon;

                return (
                  <Link
                    key={link.href}
                    href={link.href}
                    onClick={() => setIsNavOpen(false)}
                    className={`flex items-center gap-2 rounded-2xl px-3.5 py-2.5 text-sm font-medium transition-all ${
                      isActive
                        ? "bg-primary text-white shadow-md shadow-primary/25"
                        : "text-card-foreground/72 hover:bg-foreground/5 hover:text-foreground"
                    }`}
                  >
                    <Icon className={`h-4 w-4 ${isActive ? "text-white" : "text-primary/80"}`} />
                    {link.name}
                  </Link>
                );
              })}

              <button
                onClick={handleLogout}
                className="flex items-center gap-2 rounded-2xl border border-red-500/20 bg-red-500/8 px-3.5 py-2.5 text-sm font-medium text-red-600 transition hover:bg-red-500 hover:text-white md:hidden dark:text-red-300"
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </button>
            </nav>
          )}
        </div>
      </div>
    </header>
  );
}
