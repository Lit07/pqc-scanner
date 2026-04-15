import { NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";
    
    const response = await fetch(`${backendUrl}/api/v1/results/rating/enterprise`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      }
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }

    const liveData = await response.json();
    return NextResponse.json(liveData);

  } catch (error) {
    console.error("Failed to fetch live rating data:", error);
    
    return NextResponse.json({
      score: 0,
      maxScore: 1000,
      tier: "Unrated",
      hndlExposureTimeline: [],
      components: [
        { name: "Network Security", score: 0 },
        { name: "Application Security", score: 0 },
        { name: "Cryptographic Posture", score: 0 },
        { name: "Patch Management", score: 0 },
      ]
    });
  }
}
