import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export async function GET(
  req: NextRequest, 
  context: { params: Promise<{ id: string }> }
) {
  const { id } = await context.params;

  try {
    const response = await fetch(`${BACKEND_URL}/api/v1/scan/${id}`, {
      method: "GET",
      cache: "no-store"
    });

    if (!response.ok) {
      return NextResponse.json({ error: "Job not found" }, { status: response.status });
    }

    const data = await response.json();
    
    // Status mapping from backend (pending, running, completed, failed)
    const isComplete = data.status === "completed" || data.status === "failed";
    
    // Create a fake progress bar just for UI UX if it's still running
    let progress = 50; 
    let label = "Analyzing Cryptographic Surfaces...";
    
    if (data.status === "pending") {
      progress = 10;
      label = "Queued for processing...";
    } else if (data.status === "completed") {
      progress = 100;
      label = "Scan Finalized";
    } else if (data.status === "failed") {
      progress = 100;
      label = `Scan Failed: ${data.error || "Unknown Error"}`;
    }

    return NextResponse.json({ 
      scan_id: id, 
      label, 
      progress, 
      status: data.status, 
      complete: isComplete,
      result_id: data.scan_result_id 
    });

  } catch (error) {
    console.error("Status polling error:", error);
    return NextResponse.json({ error: "Failed to connect to backend", complete: true });
  }
}
