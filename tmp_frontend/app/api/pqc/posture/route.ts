import { NextResponse } from "next/server";

export const dynamic = 'force-dynamic';

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export async function GET() {
  try {
    const [postureRes, assetsRes] = await Promise.all([
      fetch(`${BACKEND_URL}/api/v1/pqc/posture`, { cache: "no-store" }),
      fetch(`${BACKEND_URL}/api/v1/assets`, { cache: "no-store" })
    ]);

    if (!postureRes.ok || !assetsRes.ok) {
      throw new Error("Backend connection failed.");
    }

    const posture = await postureRes.json();
    const assetsData = await assetsRes.json();

    const mappedAssets = (assetsData.assets || []).map((a: any) => {
      // Basic heuristics for visual display based on the Tier
      let seconds = 157680000;
      let mockCipher = "AES-256";
      
      if (a.latest_tier === "Critical") { seconds = 3888000; mockCipher = "RSA-1024"; }
      if (a.latest_tier === "Legacy") { seconds = 63072000; mockCipher = "RSA-2048"; }
      if (a.latest_tier === "Elite") { seconds = 864000000; mockCipher = "Kyber-768"; }

      return {
        id: a.id,
        name: a.hostname,
        tier: a.latest_tier || "Standard",
        cipher: mockCipher,
        quantumClockSeconds: seconds
      };
    });

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
      assets: mappedAssets.length > 0 ? mappedAssets : [
        // Fallback demo asset if DB is totally empty
        { id: "1", name: "No assets scanned", tier: "Elite", cipher: "N/A", quantumClockSeconds: 864000000 }
      ]
    });

  } catch (error) {
    console.error("PQC Posture error:", error);
    return NextResponse.json({ error: "Failed connecting to API" }, { status: 500 });
  }
}
