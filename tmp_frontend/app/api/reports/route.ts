import { NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";
    
    // Fetch all the data we need for the executive report
    const [dashRes, ratingRes, cbomRes] = await Promise.all([
      fetch(`${backendUrl}/api/v1/results/dashboard/summary`),
      fetch(`${backendUrl}/api/v1/results/rating/enterprise`),
      fetch(`${backendUrl}/api/v1/cbom/stats/global`),
    ]);

    const dashboard = dashRes.ok ? await dashRes.json() : null;
    const rating = ratingRes.ok ? await ratingRes.json() : null;
    const cbom = cbomRes.ok ? await cbomRes.json() : null;

    return NextResponse.json({
      generatedAt: new Date().toISOString(),
      dashboard,
      rating,
      cbom
    });

  } catch (error) {
    console.error("Failed to fetch report data:", error);
    return NextResponse.json({
      generatedAt: new Date().toISOString(),
      dashboard: null,
      rating: null,
      cbom: null
    });
  }
}
