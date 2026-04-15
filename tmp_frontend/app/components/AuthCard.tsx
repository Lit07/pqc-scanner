"use client";

import { motion } from "framer-motion";

export const AuthCard = ({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 30, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      className="mx-auto w-full max-w-md"
    >
      <div className="relative overflow-hidden rounded-[2rem] border border-white/50 bg-card-background/88 p-8 shadow-[0_24px_60px_-36px_rgba(15,23,42,0.45)] backdrop-blur-3xl dark:border-white/8 sm:p-10">
        <div className="pointer-events-none absolute -top-24 -right-24 h-48 w-48 rounded-full bg-primary/18 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-24 -left-24 h-48 w-48 rounded-full bg-sky-500/10 blur-3xl" />

        <div className="text-center mb-8 relative z-10">
          <motion.div
            initial={{ scale: 0.5, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.1, duration: 0.5, type: "spring" }}
            className="group relative mx-auto mb-6 flex h-16 w-16 items-center justify-center overflow-hidden rounded-[1.25rem] bg-linear-to-br from-primary to-sky-500 shadow-xl shadow-primary/25"
          >
            <div className="absolute inset-0 bg-white/20 group-hover:bg-white/30 transition-colors" />
            <div className="w-8 h-8 rounded-full border-[3px] border-white/90 border-t-white/20 animate-[spin_3s_linear_infinite]" />
          </motion.div>
          
          <h1 className="text-3xl font-bold tracking-tight text-foreground">
            {title}
          </h1>
          {subtitle && (
            <p className="mx-auto mt-3 max-w-sm text-sm leading-6 text-card-foreground/72">
              {subtitle}
            </p>
          )}
        </div>
        <div className="relative z-10">{children}</div>
      </div>
    </motion.div>
  );
};
