import { NextResponse } from "next/server";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export async function POST(req: Request) {
  try {
    const { urls } = await req.json();
    
    // The FastAPI backend expects 'hostname' and 'port' 
    // in the ScanRequest pydantic model for POST /api/v1/scan
    const response = await fetch(`${BACKEND_URL}/api/v1/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ 
        hostname: urls, 
        port: 443 
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return NextResponse.json(
        { error: "Backend rejected scan submission", details: errorText }, 
        { status: response.status }
      );
    }

    const data = await response.json();
    // The FastAPI returns: { job_id: "...", status: "...", message: "..." }
    // The Frontend currently looks for scan_id: "..."
    return NextResponse.json({ 
      scan_id: data.job_id, 
      status: data.status, 
      target: urls 
    });

  } catch (error) {
    console.error("Scan submission error:", error);
    return NextResponse.json({ error: "Failed connecting to backend API." }, { status: 500 });
  }
}
