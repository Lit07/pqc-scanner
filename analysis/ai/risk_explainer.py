import datetime

SEVERITY_NARRATIVES = {
    "CRITICAL": "poses an immediate and severe threat",
    "HIGH":     "represents a significant security concern",
    "MEDIUM":   "indicates a moderate security gap",
    "LOW":      "is a minor security consideration"
}

TIER_NARRATIVES = {
    "Elite":    "demonstrates strong cryptographic hygiene with modern best practices",
    "Standard": "meets acceptable enterprise security standards but requires PQC planning",
    "Legacy":   "shows signs of cryptographic debt requiring remediation",
    "Critical": "is in an immediately exploitable state requiring urgent intervention"
}


def explain_risk(
    risk_engine_result: dict,
    pqc_result: dict = None,
    hndl_result: dict = None,
    endpoint_result: dict = None
) -> dict:
    result = {
        "hostname": risk_engine_result.get("hostname"),
        "explained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "executive_summary": None,
        "technical_summary": None,
        "risk_story": None,
        "key_findings": [],
        "positive_findings": [],
        "worst_finding": None,
        "best_finding": None,
        "overall_grade": None,
        "grade_color": None,
        "one_liner": None
    }

    score_result = risk_engine_result.get("risk_score", {})
    final_score = score_result.get("final_score", 0)
    pqc_tier = score_result.get("pqc_tier", "Critical")
    triggered = risk_engine_result.get("triggered_rules", [])
    tls_data = risk_engine_result.get("tls_data", {})
    cert_data = risk_engine_result.get("cert_data", {})
    key_analysis = risk_engine_result.get("key_analysis", {})

    result["overall_grade"] = _calculate_grade(final_score)
    result["grade_color"] = _grade_color(result["overall_grade"])
    result["one_liner"] = _build_one_liner(
        risk_engine_result.get("hostname"),
        final_score,
        pqc_tier,
        tls_data.get("version"),
        cert_data.get("key_type")
    )

    result["executive_summary"] = _build_executive_summary(
        risk_engine_result, score_result, pqc_result, hndl_result, endpoint_result
    )
    result["technical_summary"] = _build_technical_summary(
        tls_data, cert_data, key_analysis, score_result
    )
    result["risk_story"] = _build_risk_story(
        risk_engine_result, pqc_result, hndl_result
    )

    critical_rules = [r for r in triggered if r.get("severity") == "CRITICAL"]
    positive = _identify_positives(tls_data, cert_data)

    result["key_findings"] = [
        {
            "finding": r["name"],
            "severity": r["severity"],
            "narrative": f"This asset {SEVERITY_NARRATIVES.get(r['severity'], 'has an issue')} — {r['message']}"
        }
        for r in triggered[:5]
    ]

    result["positive_findings"] = positive
    result["worst_finding"] = critical_rules[0]["name"] if critical_rules else None
    result["best_finding"] = positive[0]["finding"] if positive else None

    return result


def _calculate_grade(score: int) -> str:
    if score >= 900: return "A+"
    if score >= 800: return "A"
    if score >= 700: return "B+"
    if score >= 600: return "B"
    if score >= 500: return "C+"
    if score >= 400: return "C"
    if score >= 300: return "D"
    return "F"


def _grade_color(grade: str) -> str:
    colors = {
        "A+": "#00FF88", "A": "#00CC44",
        "B+": "#88FF00", "B": "#CCFF00",
        "C+": "#FFCC00", "C": "#FF8800",
        "D": "#FF4400",  "F": "#FF0000"
    }
    return colors.get(grade, "#FFCC00")


def _build_one_liner(
    hostname: str,
    score: int,
    tier: str,
    tls_version: str,
    key_type: str
) -> str:
    return (
        f"{hostname} scores {score}/1000 ({tier}) "
        f"using {tls_version or 'unknown TLS'} "
        f"with {key_type or 'unknown'} keys — "
        f"{'quantum vulnerable, migration required' if tier in ['Critical', 'Legacy'] else 'acceptable posture, PQC planning needed'}."
    )


def _build_executive_summary(
    risk_result: dict,
    score_result: dict,
    pqc_result: dict,
    hndl_result: dict,
    endpoint_result: dict
) -> str:
    hostname = risk_result.get("hostname", "This asset")
    score = score_result.get("final_score", 0)
    tier = score_result.get("pqc_tier", "Critical")
    critical_count = score_result.get("critical_count", 0)
    hndl_level = hndl_result.get("hndl_threat_level", "UNKNOWN") if hndl_result else "UNKNOWN"
    endpoint_type = endpoint_result.get("endpoint_type", "unknown") if endpoint_result else "unknown"
    sensitivity = endpoint_result.get("sensitivity", "UNKNOWN") if endpoint_result else "UNKNOWN"

    summary = (
        f"{hostname} has been assessed with a security score of {score}/1000, "
        f"placing it in the {tier} tier. "
        f"The asset {TIER_NARRATIVES.get(tier, 'requires attention')}. "
    )
    if critical_count > 0:
        summary += (
            f"{critical_count} critical security finding{'s' if critical_count > 1 else ''} "
            f"require immediate attention. "
        )
    if hndl_level in ["CRITICAL", "HIGH"]:
        summary += (
            f"The Harvest Now Decrypt Later risk is {hndl_level}, "
            f"meaning encrypted traffic from this {endpoint_type} endpoint "
            f"handling {sensitivity} data may already be collected by adversaries. "
        )
    summary += (
        f"Immediate migration to NIST post-quantum cryptography standards "
        f"is {'urgently ' if tier in ['Critical', 'Legacy'] else ''}recommended."
    )
    return summary


def _build_technical_summary(
    tls_data: dict,
    cert_data: dict,
    key_analysis: dict,
    score_result: dict
) -> str:
    tls_version = tls_data.get("version", "Unknown")
    cipher = tls_data.get("cipher_name", "Unknown")
    key_type = cert_data.get("key_type", "Unknown")
    key_size = cert_data.get("key_size", "Unknown")
    issuer = cert_data.get("issuer_cn", "Unknown")
    expiry = cert_data.get("not_after", "Unknown")
    score = score_result.get("final_score", 0)
    penalty = score_result.get("penalty_total", 0)

    return (
        f"Protocol: {tls_version} | Cipher: {cipher} | "
        f"Key: {key_type}-{key_size} | Issuer: {issuer} | "
        f"Expires: {expiry} | Score: {score}/1000 | "
        f"Total penalty deducted: {penalty} points across "
        f"{score_result.get('critical_count', 0)} critical, "
        f"{score_result.get('high_count', 0)} high, "
        f"{score_result.get('medium_count', 0)} medium findings."
    )


def _build_risk_story(
    risk_result: dict,
    pqc_result: dict,
    hndl_result: dict
) -> str:
    hostname = risk_result.get("hostname", "This asset")
    cert_data = risk_result.get("cert_data", {})
    tls_data = risk_result.get("tls_data", {})
    key_type = cert_data.get("key_type", "unknown")
    tls_version = tls_data.get("version", "unknown")

    story = f"{hostname} is currently protected by {key_type} cryptography over {tls_version}. "

    if pqc_result:
        classification = pqc_result.get("pqc_classification", "Unknown")
        year_data = pqc_result.get("estimated_quantum_risk_year", {})
        year = year_data.get("year") if year_data else None
        story += (
            f"From a post-quantum perspective, this asset is classified as {classification}. "
        )
        if year:
            story += (
                f"Current cryptographic protections are estimated to become "
                f"quantum-breakable around {year}. "
            )

    if hndl_result:
        level = hndl_result.get("hndl_threat_level", "UNKNOWN")
        forward = hndl_result.get("forward_secrecy", False)
        if level in ["CRITICAL", "HIGH"] and not forward:
            story += (
                f"Without forward secrecy, nation-state adversaries may already "
                f"be recording and storing this asset's encrypted traffic, "
                f"waiting for quantum computers to decrypt it. "
                f"This is the harvest now decrypt later threat model "
                f"and it represents a real, present-day risk to this asset's data."
            )

    return story


def _identify_positives(tls_data: dict, cert_data: dict) -> list:
    positives = []
    if tls_data.get("version") == "TLSv1.3":
        positives.append({
            "finding": "TLS 1.3 in use",
            "note": "Modern protocol with improved security defaults"
        })
    if not cert_data.get("is_expired"):
        positives.append({
            "finding": "Certificate is valid",
            "note": "Certificate has not expired"
        })
    if not cert_data.get("is_self_signed"):
        positives.append({
            "finding": "Trusted CA signed certificate",
            "note": "Certificate issued by a recognized certificate authority"
        })
    if cert_data.get("key_size", 0) >= 4096:
        positives.append({
            "finding": "Strong key size",
            "note": "4096-bit key provides stronger classical security"
        })
    return positives