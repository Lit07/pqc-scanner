import type { Metadata } from "next";
import { Plus_Jakarta_Sans } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "./components/ThemeProvider";
import { Header } from "./components/Header";
import { cookies } from "next/headers";

const jakarta = Plus_Jakarta_Sans({
  subsets: ["latin"],
  variable: "--font-jakarta",
});

export const metadata: Metadata = {
  title: "PQC Scanner",
  description: "Banking-focused cryptographic discovery and post-quantum readiness dashboard.",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const cookieStore = await cookies();
  const isLoggedIn = cookieStore.has("auth_token");

  return (
    <html lang="en" suppressHydrationWarning className={`${jakarta.variable} h-full antialiased`}>
      <body className="font-sans min-h-full flex flex-col items-center transition-colors duration-500 overflow-x-hidden">
        <ThemeProvider attribute="class" defaultTheme="light" enableSystem={false}>
          <Header isLoggedIn={isLoggedIn} />
          <main className="relative z-10 mx-auto mb-8 flex w-full max-w-7xl flex-1 flex-col items-center px-4 pb-4 pt-6 md:px-6">
            {children}
          </main>
        </ThemeProvider>
      </body>
    </html>
  );
}
