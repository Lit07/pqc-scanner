from utils.constants import CRYPTO_KNOWLEDGE_BASE
import datetime

HNDL_THREAT_LEVELS = {
    "CRITICAL": {"score": 100, "color": "#FF0000"},
    "HIGH":     {"score": 75,  "color": "#FF8800"},
    "MEDIUM":   {"score": 50,  "color": "#FFCC00"},
    "LOW":      {"score": 25,  "color": "#00CC44"},
    "MINIMAL":  {"score": 10,  "color": "#00FF88"}
}

QUANTUM_READINESS_YEARS = {
    "optimistic": 2029,
    "moderate":   2033,
    "conservative": 2038
}

def assess_hndl_risk(scan_data: dict, endpoint_classification: dict = None) -> dict:
    result = {
        "hostname": scan_data.get("hostname"),
        "assessed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hndl_threat_level": None,
        "hndl_score": None,
        "hndl_color": None,
        "forward_secrecy": scan_data.get("forward_secrecy", False),
        "harvest_window_open": False,
        "harvest_window_since": None,
        "estimated_decrypt_year": None,
        "exposure_factors": [],
        "hndl_narrative": None,
        "recommended_actions": [],
        "endpoint_multiplier": 1.0,
        "adjusted_hndl_score": None,
        "data_at_risk_classification": None,
        "regulatory_breach_risk": []
    }

    factors = []
    base_score = 0
    # --- HARDWARE-LEVEL HYBRID PQC SENSING ---
    if scan_data.get("hybrid_mode_supported"):
        hostname = scan_data.get("hostname", "")
        result["hndl_score"] = 15
        result["adjusted_hndl_score"] = 15
        result["hndl_threat_level"] = "MINIMAL"
        result["hndl_color"] = HNDL_THREAT_LEVELS["MINIMAL"]["color"]
        result["estimated_decrypt_year"] = None
        result["exposure_factors"] = [{
            "factor": "Detected ML-KEM/Kyber Hybrid Key Exchange",
            "impact": "POSITIVE",
            "reason": "Traffic mathematically secured against both classical and quantum adversaries."
        }]
        result["hndl_narrative"] = f"{hostname} has bleeding-edge PQC defenses active. Harvest Now Decrypt Later risk is completely mitigated."
        return result
    # --------------------------------------------------

    key_type = scan_data.get("key_type")
    key_size = scan_data.get("key_size", 0) or 0

    if key_type in CRYPTO_KNOWLEDGE_BASE:
        kb = CRYPTO_KNOWLEDGE_BASE[key_type]
        hndl_risk = kb.get("hndl_risk", "MEDIUM")
        base_score += HNDL_THREAT_LEVELS.get(hndl_risk, {}).get("score", 50)
        factors.append({
            "factor": f"{key_type} key algorithm",
            "impact": hndl_risk,
            "reason": kb.get("hndl_reason", "Quantum vulnerable algorithm")
        })

    if not scan_data.get("forward_secrecy"):
        base_score += 30
        result["harvest_window_open"] = True
        factors.append({
            "factor": "No forward secrecy",
            "impact": "CRITICAL",
            "reason": "All recorded sessions permanently at risk"
        })
    else:
        base_score -= 20
        factors.append({
            "factor": "Forward secrecy enabled",
            "impact": "POSITIVE",
            "reason": "Past sessions protected even if key compromised"
        })

    tls = scan_data.get("tls_version", "")
    if tls in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
        base_score += 20
        factors.append({
            "factor": f"Deprecated protocol {tls}",
            "impact": "HIGH",
            "reason": "Weak protocol increases harvest feasibility"
        })

    if key_type == "RSA":
        if key_size < 2048:
            base_score += 25
            factors.append({
                "factor": f"RSA-{key_size} critically weak",
                "impact": "CRITICAL",
                "reason": "May be classically harvestable today"
            })
        elif key_size == 2048:
            base_score += 10
            factors.append({
                "factor": "RSA-2048 marginal",
                "impact": "MEDIUM",
                "reason": "Minimum acceptable, quantum breakable"
            })

    days_to_expiry = scan_data.get("days_to_expiry", 365) or 365
    if days_to_expiry > 365:
        base_score += 15
        factors.append({
            "factor": "Long-lived certificate",
            "impact": "HIGH",
            "reason": f"Certificate valid for {days_to_expiry} more days increases harvest window"
        })

    if endpoint_classification:
        multiplier = endpoint_classification.get("hndl_multiplier", 1.0)
        result["endpoint_multiplier"] = multiplier
        result["data_at_risk_classification"] = endpoint_classification.get("data_classification")
        result["regulatory_breach_risk"] = endpoint_classification.get("regulatory_scope", [])

    base_score = max(0, min(100, base_score))
    result["hndl_score"] = base_score
    adjusted = min(100, round(base_score * result["endpoint_multiplier"]))
    result["adjusted_hndl_score"] = adjusted

    if adjusted >= 80:
        result["hndl_threat_level"] = "CRITICAL"
    elif adjusted >= 60:
        result["hndl_threat_level"] = "HIGH"
    elif adjusted >= 40:
        result["hndl_threat_level"] = "MEDIUM"
    elif adjusted >= 20:
        result["hndl_threat_level"] = "LOW"
    else:
        result["hndl_threat_level"] = "MINIMAL"

    result["hndl_color"] = HNDL_THREAT_LEVELS.get(
        result["hndl_threat_level"], {}
    ).get("color", "#FFCC00")

    result["estimated_decrypt_year"] = QUANTUM_READINESS_YEARS["moderate"]
    result["exposure_factors"] = factors
    result["recommended_actions"] = _build_recommendations(scan_data, result)
    result["hndl_narrative"] = _build_narrative(result, scan_data)

    return result


def _build_recommendations(scan_data: dict, result: dict) -> list:
    actions = []
    if not scan_data.get("forward_secrecy"):
        actions.append({
            "priority": 1,
            "action": "Enable ECDHE cipher suites immediately",
            "impact": "Closes harvest window for future sessions"
        })
    if scan_data.get("key_type") in ["RSA", "EC", "DSA"]:
        actions.append({
            "priority": 2,
            "action": "Begin CRYSTALS-Kyber hybrid key exchange deployment",
            "impact": "Provides quantum-resistant key exchange"
        })
    if scan_data.get("tls_version") != "TLSv1.3":
        actions.append({
            "priority": 3,
            "action": "Upgrade to TLS 1.3",
            "impact": "Enables hybrid PQC extensions"
        })
    actions.append({
        "priority": 4,
        "action": "Reduce certificate lifetime to maximum 1 year",
        "impact": "Reduces harvest window duration"
    })
    return actions


def _build_narrative(result: dict, scan_data: dict) -> str:
    level = result["hndl_threat_level"]
    year = result["estimated_decrypt_year"]
    hostname = result["hostname"]
    data = result.get("data_at_risk_classification", "sensitive data")
    forward = result["forward_secrecy"]

    narrative = f"{hostname} has a {level} HNDL risk profile. "
    if not forward:
        narrative += (
            f"With no forward secrecy, adversaries recording traffic today "
            f"can decrypt {data} once quantum computers reach sufficient power, "
            f"estimated around {year}. "
        )
    else:
        narrative += (
            f"Forward secrecy limits exposure to active sessions only. "
            f"However the underlying {scan_data.get('key_type')} algorithm "
            f"remains quantum vulnerable by approximately {year}. "
        )
    if result.get("regulatory_breach_risk"):
        narrative += (
            f"A successful harvest-decrypt attack would constitute a breach "
            f"under {', '.join(result['regulatory_breach_risk'])}."
        )
    return narrative