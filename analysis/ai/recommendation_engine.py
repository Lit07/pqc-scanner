from utils.constants import NIST_PQC_ALGORITHMS, CRYPTO_KNOWLEDGE_BASE
import datetime

RECOMMENDATION_TEMPLATES = {
    "ENABLE_FORWARD_SECRECY": {
        "title": "Enable Forward Secrecy Immediately",
        "effort": "LOW",
        "impact": "HIGH",
        "timeframe": "1-3 days",
        "category": "cipher"
    },
    "UPGRADE_TLS": {
        "title": "Upgrade TLS Protocol Version",
        "effort": "MEDIUM",
        "impact": "HIGH",
        "timeframe": "1-2 weeks",
        "category": "protocol"
    },
    "REPLACE_WEAK_KEY": {
        "title": "Replace Weak Cryptographic Key",
        "effort": "MEDIUM",
        "impact": "CRITICAL",
        "timeframe": "1 week",
        "category": "key"
    },
    "DEPLOY_HYBRID_PQC": {
        "title": "Deploy Hybrid PQC Key Exchange",
        "effort": "HIGH",
        "impact": "CRITICAL",
        "timeframe": "3-6 months",
        "category": "pqc"
    },
    "MIGRATE_TO_DILITHIUM": {
        "title": "Migrate Signatures to CRYSTALS-Dilithium",
        "effort": "HIGH",
        "impact": "CRITICAL",
        "timeframe": "6-12 months",
        "category": "pqc"
    },
    "MIGRATE_TO_KYBER": {
        "title": "Migrate Key Exchange to CRYSTALS-Kyber",
        "effort": "HIGH",
        "impact": "CRITICAL",
        "timeframe": "6-12 months",
        "category": "pqc"
    },
    "RENEW_CERTIFICATE": {
        "title": "Renew Expiring Certificate",
        "effort": "LOW",
        "impact": "CRITICAL",
        "timeframe": "Immediate",
        "category": "certificate"
    },
    "GENERATE_CBOM": {
        "title": "Generate Cryptographic Bill of Materials",
        "effort": "LOW",
        "impact": "HIGH",
        "timeframe": "1 day",
        "category": "inventory"
    },
    "UPGRADE_TO_AES256": {
        "title": "Upgrade Symmetric Encryption to AES-256",
        "effort": "LOW",
        "impact": "MEDIUM",
        "timeframe": "1 week",
        "category": "cipher"
    },
    "DISABLE_WEAK_CIPHERS": {
        "title": "Disable Weak Cipher Suites",
        "effort": "LOW",
        "impact": "HIGH",
        "timeframe": "1-2 days",
        "category": "cipher"
    }
}


def generate_recommendations(
    scan_data: dict,
    risk_result: dict = None,
    pqc_result: dict = None
) -> dict:
    result = {
        "hostname": scan_data.get("hostname"),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "recommendations": [],
        "quick_wins": [],
        "long_term": [],
        "total_count": 0,
        "critical_count": 0,
        "estimated_total_effort": None
    }

    recs = []

    if scan_data.get("is_expired") or \
       (scan_data.get("days_to_expiry") or 999) < 30:
        recs.append(_build_rec("RENEW_CERTIFICATE", "CRITICAL",
            "Certificate expired or expiring within 30 days", 1))

    if not scan_data.get("forward_secrecy"):
        recs.append(_build_rec("ENABLE_FORWARD_SECRECY", "CRITICAL",
            "No forward secrecy — HNDL risk active", 2))

    if any(w in (scan_data.get("cipher_name") or "")
           for w in ["DES", "RC4", "NULL", "EXPORT"]):
        recs.append(_build_rec("DISABLE_WEAK_CIPHERS", "CRITICAL",
            "Critically weak cipher suite in use", 3))

    if scan_data.get("tls_version") in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
        recs.append(_build_rec("UPGRADE_TLS", "HIGH",
            f"Deprecated protocol {scan_data.get('tls_version')} in use", 4))

    key_type = scan_data.get("key_type")
    key_size = scan_data.get("key_size", 0) or 0

    if key_type == "RSA" and key_size < 2048:
        recs.append(_build_rec("REPLACE_WEAK_KEY", "CRITICAL",
            f"RSA-{key_size} is critically weak", 5))

    if "AES128" in (scan_data.get("cipher_name") or "") or \
       "AES_128" in (scan_data.get("cipher_name") or ""):
        recs.append(_build_rec("UPGRADE_TO_AES256", "MEDIUM",
            "AES-128 has halved security under Grover's algorithm", 6))

    recs.append(_build_rec("GENERATE_CBOM", "HIGH",
        "Generate CBOM to map all cryptographic dependencies", 7))

    if scan_data.get("tls_version") == "TLSv1.3":
        recs.append(_build_rec("DEPLOY_HYBRID_PQC", "HIGH",
            "TLS 1.3 supports hybrid PQC — deploy CRYSTALS-Kyber", 8))
    else:
        recs.append(_build_rec("UPGRADE_TLS", "HIGH",
            "Upgrade to TLS 1.3 to enable hybrid PQC extensions", 8))

    if key_type in ["RSA", "EC", "DSA"]:
        recs.append(_build_rec("MIGRATE_TO_DILITHIUM", "HIGH",
            f"Migrate {key_type} signatures to CRYSTALS-Dilithium (FIPS 204)", 9))
        recs.append(_build_rec("MIGRATE_TO_KYBER", "HIGH",
            f"Migrate {key_type} key exchange to CRYSTALS-Kyber (FIPS 203)", 10))

    seen = set()
    unique_recs = []
    for r in recs:
        if r["type"] not in seen:
            seen.add(r["type"])
            unique_recs.append(r)

    result["recommendations"] = sorted(unique_recs, key=lambda x: x["priority"])
    result["quick_wins"] = [r for r in unique_recs if r["effort"] == "LOW"]
    result["long_term"] = [r for r in unique_recs if r["effort"] == "HIGH"]
    result["total_count"] = len(unique_recs)
    result["critical_count"] = len([r for r in unique_recs if r["impact"] == "CRITICAL"])
    result["estimated_total_effort"] = _estimate_effort(unique_recs)

    return result


def _build_rec(rec_type: str, impact: str, reason: str, priority: int) -> dict:
    template = RECOMMENDATION_TEMPLATES.get(rec_type, {})
    return {
        "type": rec_type,
        "title": template.get("title", rec_type),
        "impact": impact,
        "effort": template.get("effort", "MEDIUM"),
        "timeframe": template.get("timeframe", "TBD"),
        "category": template.get("category", "general"),
        "reason": reason,
        "priority": priority
    }


def _estimate_effort(recommendations: list) -> str:
    effort_scores = {"LOW": 1, "MEDIUM": 3, "HIGH": 8}
    total = sum(effort_scores.get(r.get("effort", "MEDIUM"), 3)
                for r in recommendations)
    if total <= 5:
        return "1-2 weeks"
    elif total <= 15:
        return "1-3 months"
    elif total <= 30:
        return "3-6 months"
    return "6-12 months"