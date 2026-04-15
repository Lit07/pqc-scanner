"use client";

import { HTMLMotionProps, motion } from "framer-motion";
import { Loader2 } from "lucide-react";
import * as React from "react";

interface ButtonProps extends HTMLMotionProps<"button"> {
  isLoading?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, children, isLoading, disabled, ...props }, ref) => {
    return (
      <motion.button
        ref={ref}
        whileHover={{ scale: 1.01, y: -1 }}
        whileTap={{ scale: 0.98 }}
        disabled={isLoading || disabled}
        className={`
          relative w-full h-14 rounded-2xl bg-linear-to-r from-primary to-sky-500
          flex items-center justify-center overflow-hidden text-white shadow-lg shadow-primary/20
          transition-all duration-300 hover:shadow-primary/30
          disabled:opacity-70 disabled:cursor-not-allowed
          animate-gradient bg-size-[200%_auto]
          ${className || ""}
        `}
        {...props}
      >
        <div className="absolute inset-0 bg-white/10 opacity-0 hover:opacity-100 transition-opacity duration-300 mix-blend-overlay" />
        
        {isLoading ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center justify-center"
          >
            <Loader2 className="w-6 h-6 animate-spin" />
            <span className="ml-2 font-semibold tracking-wide">Please wait...</span>
          </motion.div>
        ) : (
          <span className="relative z-10 flex w-full items-center justify-center text-base font-semibold tracking-[0.01em]">
            {children as React.ReactNode}
          </span>
        )}
      </motion.button>
    );
  }
);
Button.displayName = "Button";
