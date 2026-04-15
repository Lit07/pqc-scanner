import { NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export async function GET() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/assets`, { cache: 'no-store' });
    if (!res.ok) throw new Error("Could not fetch assets from backend");

    const data = await res.json();
    const assetsList = data.assets || [];

    const mappedAssets = assetsList.map((a: any) => ({
      id: a.id,
      name: a.hostname,
      type: a.asset_type || "Domain",
      ip: a.ip || "Unknown",
      riskTier: a.latest_tier || "Standard",
      pqcReady: a.latest_pqc_classification === 'Elite',
      certValidDays: a.cert_expiry_days !== null && a.cert_expiry_days !== undefined ? a.cert_expiry_days : "Unknown"
    }));

    return NextResponse.json({
      assets: mappedAssets.length > 0 ? mappedAssets : [
        { id: "ast-m", name: "No mapped assets yet", type: "", ip: "", riskTier: "Low", pqcReady: true, certValidDays: 0 }
      ]
    });

  } catch (error) {
    console.error("Assets fetch error:", error);
    return NextResponse.json({ error: "Failed connecting to API" }, { status: 500 });
  }
}
