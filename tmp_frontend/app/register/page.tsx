"use client";

import * as React from "react";
import { AuthCard } from "../components/AuthCard";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { User, Mail, Lock, Phone } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

export default function RegisterPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const handleRegister = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    const formData = new FormData(e.currentTarget);
    const fullName = formData.get("fullName");
    const email = formData.get("email");
    const phone = formData.get("phone") as string;
    const password = formData.get("password") as string;

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+\-=\[\]{};':"\\|,.<>\/])\S{8,15}$/;
    if (!passwordRegex.test(password)) {
      setError("Password must be 8-15 chars, no spaces, with at least 1 uppercase, 1 lowercase, 1 number, and 1 special character.");
      setIsLoading(false);
      return;
    }

    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fullName, email, phone, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to register");
      }

      // Successfully registered and OTP generated
      localStorage.setItem("verifyEmail", email as string);
      router.push("/verify");

    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthCard
      title="Create Account"
      subtitle="Set up access for the dashboard and continue to verification."
    >
      {error && <div className="rounded-2xl border border-red-500/35 bg-red-500/8 p-3 text-sm font-medium text-red-600">{error}</div>}
      <form onSubmit={handleRegister} className="flex flex-col gap-3 mt-2">
        <Input label="Full Name" name="fullName" type="text" placeholder="Ayush Ranjan" icon={User} required />
        <Input label="Email Address" name="email" type="email" placeholder="name@organization.com" icon={Mail} required />
        <Input label="Phone Number" name="phone" type="tel" placeholder="+91 0000000000" icon={Phone} required />
        <Input label="Password" name="password" type="password" placeholder="Create a strong password" icon={Lock} required />

        <Button type="submit" isLoading={isLoading} className="mt-4">
          Continue to verification
        </Button>
      </form>

      <div className="mt-8 text-center text-sm font-medium text-[var(--card-foreground)]/70">
        Already have an account?{" "}
        <Link href="/login" className="text-primary font-bold hover:underline transition-all">
          Sign in
        </Link>
      </div>
    </AuthCard>
  );
}
