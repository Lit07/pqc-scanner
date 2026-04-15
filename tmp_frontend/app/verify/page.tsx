"use client";

import * as React from "react";
import { AuthCard } from "../components/AuthCard";
import { Button } from "../components/Button";
import { ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";

export default function VerifyPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [otp, setOtp] = React.useState<string[]>(Array(6).fill(""));
  const inputRefs = React.useRef<(HTMLInputElement | null)[]>([]);

  React.useEffect(() => {
    const savedEmail = localStorage.getItem("verifyEmail");
    if (savedEmail) {
      setEmail(savedEmail);
    } else {
      router.push("/login"); // fallback if no email found
    }
  }, [router]);

  const handleChange = (index: number, value: string) => {
    if (isNaN(Number(value))) return;

    const newOtp = [...otp];
    if (value.length > 1) {
      const pastedData = value.slice(0, 6).split("");
      for (let i = 0; i < pastedData.length; i++) {
        if (index + i < 6) newOtp[index + i] = pastedData[i];
      }
      setOtp(newOtp);
      const nextIndex = Math.min(index + pastedData.length, 5);
      inputRefs.current[nextIndex]?.focus();
      return;
    }

    newOtp[index] = value;
    setOtp(newOtp);

    if (value !== "" && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && index > 0 && otp[index] === "") {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    const otpValue = otp.join("");
    if (otpValue.length !== 6) return;

    setIsLoading(true);
    setError("");
    
    try {
      const res = await fetch("/api/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otp: otpValue }),
      });
      
      const data = await res.json();
      
      if (!res.ok) {
        throw new Error(data.error || "Invalid OTP");
      }
      
      localStorage.removeItem("verifyEmail");
      
      window.location.href = "/dashboard";
      
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    alert("In a full app, this will trigger the OTP generator again.");
  };

  return (
    <AuthCard 
      title="Verify Account" 
      subtitle={`We've sent a 6-digit one-time password to ${email || "your email"}.`}
    >
      {error && <div className="p-3 bg-red-500/10 border border-red-500/50 rounded-lg text-red-500 text-sm font-semibold">{error}</div>}
      <form onSubmit={handleVerify} className="flex flex-col gap-6 mt-2 items-center w-full">
        <div className="flex gap-2 sm:gap-3 justify-center w-full my-4">
          {otp.map((digit, index) => (
            <input
              key={index}
              ref={(el) => {
                inputRefs.current[index] = el;
              }}
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={digit}
              onChange={(e) => handleChange(index, e.target.value)}
              onKeyDown={(e) => handleKeyDown(index, e)}
              className="w-12 h-14 sm:w-14 sm:h-16 text-center text-xl sm:text-2xl font-black bg-[var(--input-background)] border-2 border-[var(--input-border)] rounded-xl text-[var(--card-foreground)] transition-all focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/20 shadow-inner"
            />
          ))}
        </div>

        <Button 
          type="submit" 
          isLoading={isLoading} 
          disabled={otp.join("").length !== 6}
          className="w-full"
        >
          <ShieldCheck className="mr-2 h-5 w-5" />
          Verify Code
        </Button>

        <div className="text-center text-sm font-semibold text-[var(--card-foreground)]/70">
          Didn&apos;t receive the code?{" "}
          <button type="button" onClick={handleResend} className="text-primary font-bold hover:underline transition-all ml-1">
            Resend
          </button>
        </div>
      </form>
    </AuthCard>
  );
}
