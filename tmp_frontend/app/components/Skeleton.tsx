export function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div className={`animate-pulse bg-white/20 dark:bg-black/20 rounded-xl ${className}`} />
  );
}
