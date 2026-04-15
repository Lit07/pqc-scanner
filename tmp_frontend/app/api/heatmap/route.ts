import { NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";
    
    console.log(`Fetching heatmap from: ${backendUrl}/api/v1/assets/heatmap`);
    const response = await fetch(`${backendUrl}/api/v1/assets/heatmap`, {
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
    console.error("Failed to fetch heatmap data:", error);
    return NextResponse.json({ nodes: [] });
  }
}
