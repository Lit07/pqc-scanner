import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8000";

export async function GET(
  req: NextRequest, 
  context: { params: Promise<{ id: string }> }
) {
  const { id } = await context.params;

  try {
    // 1. Fetch the job status to get the actual result UUID
    const jobRes = await fetch(`${BACKEND_URL}/api/v1/scan/${id}`);
    if (!jobRes.ok) throw new Error("Job not found");
    const jobData = await jobRes.json();
    
    if (!jobData.scan_result_id) {
      return NextResponse.json({ error: "Results not ready or job failed" }, { status: 400 });
    }

    // 2. Fetch the actual full scan report from FastAPI
    const resultId = jobData.scan_result_id;
    const res = await fetch(`${BACKEND_URL}/api/v1/results/${resultId}/report`);
    if (!res.ok) throw new Error("Result not found");
    
    const reportData = await res.json();
    
    // Map FastAPI report groupings back to the frontend's expected properties
    const rules = reportData.risk_details?.triggered_rules || [];
    const mappedFindings = rules.map((rule: any) => ({
      id: rule.id || rule.rule_id || "VULN",
      type: rule.name || rule.rule_name || "Unknown Risk",
      severity: rule.severity || "Medium",
      asset: reportData.target?.hostname || "Unknown",
      detail: rule.message || "Vulnerability detected in cryptographic layer"
    }));

    return NextResponse.json({
      scan_id: id,
      identifiedAssets: reportData.executive_summary?.shadow_asset_count || 1,
      criticalVulnerabilities: reportData.executive_summary?.critical_findings || 0,
      overallScore: reportData.executive_summary?.final_score || 0,
      pqcCompliant: reportData.executive_summary?.pqc_tier === "Elite" || reportData.executive_summary?.pqc_tier === "Standard",
      
      // Original Findings List
      findings: mappedFindings.length > 0 ? mappedFindings : [
        { id: "NONE", type: "No Vulnerabilities", severity: "Low", asset: reportData.target?.hostname || "Unknown", detail: "Asset appears fully compliant." }
      ],

      // NEW ADVANCED AI PAYLOADS 👇
      aiNarrative: {
        executive_summary: reportData.risk_explanation?.executive_summary || "Scan generated positive compliance results.",
        risk_story: reportData.risk_explanation?.risk_story || "No significant attack paths discovered in this network vector.",
      },
      pqcTracker: {
        hndl_threat_level: reportData.hndl_assessment?.hndl_threat_level || "Minimal",
        estimated_decrypt_year: reportData.hndl_assessment?.estimated_decrypt_year || "Unknown",
        harvest_window_open: reportData.hndl_assessment?.harvest_window_open || false,
        quantum_risk_year: reportData.pqc_assessment?.estimated_quantum_risk_year || "Safe",
        classification: reportData.pqc_assessment?.pqc_classification || "Standard Compliance",
      },
      recommendations: (reportData.recommendations?.recommendations || []).map((r: any) => ({
        action: r.title || r.type || "System Recommendation",
        trigger: r.reason || "Cryptographic Remediation Required",
        impact: r.impact || "Medium"
      }))
    });

  } catch (error) {
    console.error("Results fetch error:", error);
    return NextResponse.json({ error: "Failed to load scan results" }, { status: 500 });
  }
}
