"use client";

import * as React from "react";
import { AuthCard } from "../components/AuthCard";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { Mail, Lock, ArrowRight } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const handleLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    const formData = new FormData(e.currentTarget);
    const email = formData.get("email") as string;
    const password = formData.get("password") as string;

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+\-=\[\]{};':"\\|,.<>\/])\S{8,15}$/;
    if (!passwordRegex.test(password)) {
      setError("Invalid password format. Must be 8-15 chars containing uppercase, lowercase, numbers, and special characters.");
      setIsLoading(false);
      return;
    }

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to login");
      }

      if (data.unverified) {
        localStorage.setItem("verifyEmail", email);
        router.push("/verify");
      } else {
        window.location.href = "/dashboard";
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthCard
      title="Welcome Back"
      subtitle="Sign in to continue reviewing assets, scan results, and migration priorities."
    >
      {error && <div className="rounded-2xl border border-red-500/35 bg-red-500/8 p-3 text-sm font-medium text-red-600">{error}</div>}
      <form onSubmit={handleLogin} className="mt-4 flex flex-col gap-3">
        <Input
          label="Email Address"
          name="email"
          type="email"
          placeholder="name@organization.com"
          icon={Mail}
          required
        />
        <div>
          <Input
            label="Password"
            name="password"
            type="password"
            placeholder="Enter your password"
            icon={Lock}
            required
          />
          <div className="mb-2 mt-1 flex justify-end">
            <Link href="#" className="text-sm font-semibold text-primary transition-all hover:underline">
              Forgot password?
            </Link>
          </div>
        </div>

        <Button type="submit" isLoading={isLoading} className="group mt-2">
          Sign In
          <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
        </Button>
      </form>

      <div className="mt-8 text-center text-sm font-medium text-[var(--card-foreground)]/70">
        Don&apos;t have an account?{" "}
        <Link href="/register" className="font-bold text-primary transition-all hover:underline">
          Create one
        </Link>
      </div>
    </AuthCard>
  );
}
