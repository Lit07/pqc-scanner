import { NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export async function GET() {
  try {
    const postureRes = await fetch(`${BACKEND_URL}/api/v1/pqc/posture`, { cache: "no-store" });

    if (!postureRes.ok) {
      throw new Error("Backend connection failed.");
    }

    const posture = await postureRes.json();
    const assetsData = posture.detailed_assets || [];

    return NextResponse.json({
      breakdown: {
        elite: posture.elite_count || 0,
        standard: posture.standard_count || 0,
        legacy: posture.legacy_count || 0,
        critical: posture.critical_count || 0,
      },
      recommendations: [
        { trigger: `Found ${posture.legacy_count} legacy assets`, action: "Migrate to ML-KEM-768 or hybrid ECDSA/Dilithium.", impact: "High" },
        { trigger: `Found ${posture.critical_count} critical assets`, action: "Enforce TLS 1.3 minimum floor across ingress gateways.", impact: "Critical" },
        { trigger: "HNDL Exposure Risk", action: "Rotate session keys hourly to mitigate payload hoarding.", impact: "Medium" }
      ],
      assets: assetsData.length > 0 ? assetsData : [
        // Fallback demo asset if DB is totally empty
        { id: "1", name: "No assets scanned", tier: "Elite", cipher: "N/A", quantumClockSeconds: 864000000 }
      ]
    });

  } catch (error) {
    console.error("PQC Posture error:", error);
    return NextResponse.json({ error: "Failed connecting to API" }, { status: 500 });
  }
}
