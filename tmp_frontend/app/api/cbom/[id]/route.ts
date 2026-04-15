import { NextRequest, NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const { id } = await context.params;

  try {
    // Fetch the real analytical aggregate from backend, replacing placeholder mocks
    const res = await fetch(`${BACKEND_URL}/api/v1/cbom/stats/global`, { cache: 'no-store' });
    if (!res.ok) throw new Error("Could not load CBOM stats from backend");
    
    const cbomData = await res.json();
    const records = cbomData.cbomRecords || [];

    if (records.length === 0) {
      return NextResponse.json({
         scan_id: id,
         cbomRecords: [{ id: "empty-01", asset: "No Assets Scanned Yet", keyLength: "-", cipherSuite: "-", tlsVersion: "-", ca: "-", pqcStatus: "-", riskScore: 0, statusKey: "Empty" }]
      });
    }

    const mappedRecords = records.map((r: any) => ({
      ...r,
      // Status key calculates healthy thresholds for UI colors
      statusKey: r.riskScore > 75 ? "Healthy" : (r.riskScore < 50 ? "Critical" : "Standard")
    }));

    return NextResponse.json({
      scan_id: id,
      generatedAt: new Date().toISOString(),
      cbomRecords: mappedRecords
    });

  } catch (error) {
    console.error("CBOM fetch error:", error);
    return NextResponse.json({ error: "Failed to connect to backend api." }, { status: 500 });
  }
}