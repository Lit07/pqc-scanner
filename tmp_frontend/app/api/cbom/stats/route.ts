import { NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";
    
    const response = await fetch(`${backendUrl}/api/v1/cbom/stats/global`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      }
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }

    const data = await response.json();
    return NextResponse.json(data);

  } catch (error) {
    console.error("Failed to fetch global cbom stats:", error);
    return NextResponse.json({
        stats: { total_apps: 0, sites_surveyed: 0, active_certs: 0, weak_crypto: 0, cert_issues: 0 },
        key_lengths: [],
        ciphers: [],
        authorities: []
    });
  }
}
