import { NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";
    console.log("Fetching live dashboard summary from:", `${backendUrl}/api/v1/results/dashboard/summary`);
    
    const response = await fetch(`${backendUrl}/api/v1/results/dashboard/summary`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      // Short cache for dashboard responsiveness
      next: { revalidate: 10 } 
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }

    const liveData = await response.json();
    return NextResponse.json(liveData);

  } catch (error) {
    console.error("Failed to fetch live dashboard data, falling back to empty state:", error);
    
    // Return empty graceful fallback if backend is down
    return NextResponse.json({
        stats: { totalAssets: 0, highRiskAssets: 0, expiringCerts: 0, pqcScore: 0, activeScans: 0, criticalFindings: 0 },
        charts: {
            riskDistribution: [],
            cipherUsage: [],
            expiryTimeline: []
        },
        activity: [],
        geography: []
    });
  }
}
