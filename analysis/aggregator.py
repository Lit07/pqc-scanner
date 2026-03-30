import datetime
from scanner.tls_scanner import scan_tls
from analysis.crypto.cert_parser import parse_cert
from analysis.crypto.cipher_parser import parse_cipher
from analysis.crypto.key_analyzer import analyze_key
from analysis.risk.risk_engine import run_risk_engine
from analysis.pqc.pqc_classifier import classify_pqc_posture
from analysis.pqc.migration_planner import generate_migration_plan
from analysis.pqc.quantum_heatmap import generate_asset_heatmap_point
from analysis.ai.endpoint_classifier import classify_endpoint
from analysis.ai.hndl_risk_model import assess_hndl_risk
from analysis.ai.quantum_timeline import generate_quantum_timeline
from analysis.ai.shadow_asset_detector import detect_shadow_assets
from analysis.ai.anomaly_detector import detect_anomalies
from analysis.ai.recommendation_engine import generate_recommendations
from analysis.ai.risk_explainer import explain_risk
from analysis.pqc.cipher_regression import detect_cipher_regression
from analysis.cbom.cbom_builder import build_cbom


def run_full_scan(
    hostname: str,
    port: int = 443,
    previous_scan: dict = None,
    scan_history: list = None,
    probe_shadow: bool = False
) -> dict:
    result = {
        "hostname": hostname,
        "port": port,
        "scan_id": _generate_scan_id(hostname),
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "completed_at": None,
        "status": "running",
        "tls_scan": {},
        "cert_analysis": {},
        "cipher_analysis": {},
        "key_analysis": {},
        "risk_engine": {},
        "pqc_classification": {},
        "migration_plan": {},
        "heatmap_point": {},
        "endpoint_classification": {},
        "hndl_assessment": {},
        "quantum_timeline": {},
        "shadow_assets": {},
        "anomalies": {},
        "recommendations": {},
        "risk_explanation": {},
        "cipher_regression": {},
        "cbom": {},
        "summary": {},
        "error": None
    }

    tls_result = scan_tls(hostname, port)
    result["tls_scan"] = tls_result

    if tls_result.get("error"):
        result["status"] = "failed"
        result["error"] = tls_result["error"]
        result["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result["summary"] = _build_failed_summary(hostname, tls_result["error"])
        return result

    der_bytes = tls_result.get("der_cert_bytes")
    cert_data = {}
    if der_bytes:
        cert_data = parse_cert(der_bytes)
        result["cert_analysis"] = cert_data

    cipher_data = parse_cipher(
        cipher_name=tls_result.get("cipher_name", ""),
        tls_version=tls_result.get("tls_version", ""),
        key_bits=tls_result.get("cipher_bits", 0)
    )
    result["cipher_analysis"] = cipher_data

    key_data = {}
    if cert_data.get("key_type"):
        key_data = analyze_key(
            key_type=cert_data["key_type"],
            key_size=cert_data.get("key_size", 0),
            curve_name=cert_data.get("curve_name")
        )
        result["key_analysis"] = key_data

    combined = _build_combined(tls_result, cert_data, cipher_data, key_data)

    risk_result = run_risk_engine(tls_result, der_bytes)
    result["risk_engine"] = risk_result

    endpoint_result = classify_endpoint(
        hostname=hostname,
        scan_data=combined,
        san_domains=cert_data.get("san_domains", [])
    )
    result["endpoint_classification"] = endpoint_result

    pqc_result = classify_pqc_posture(combined)
    result["pqc_classification"] = pqc_result

    migration_result = generate_migration_plan(combined, risk_result)
    result["migration_plan"] = migration_result

    hndl_result = assess_hndl_risk(combined, endpoint_result)
    result["hndl_assessment"] = hndl_result

    timeline_result = generate_quantum_timeline(combined)
    result["quantum_timeline"] = timeline_result

    shadow_result = detect_shadow_assets(
        primary_hostname=hostname,
        san_domains=cert_data.get("san_domains", []),
        probe_subdomains=probe_shadow
    )
    result["shadow_assets"] = shadow_result

    anomaly_result = detect_anomalies(combined, previous_scan, scan_history)
    result["anomalies"] = anomaly_result

    rec_result = generate_recommendations(combined, risk_result, pqc_result)
    result["recommendations"] = rec_result

    explanation = explain_risk(risk_result, pqc_result, hndl_result, endpoint_result)
    result["risk_explanation"] = explanation

    regression_result = detect_cipher_regression(combined, scan_history or [])
    result["cipher_regression"] = regression_result

    heatmap_point = generate_asset_heatmap_point(combined, pqc_result)
    result["heatmap_point"] = heatmap_point

    cbom_result = build_cbom(hostname, tls_result, cert_data, cipher_data, key_data)
    result["cbom"] = cbom_result

    result["summary"] = _build_summary(
        hostname, risk_result, pqc_result,
        hndl_result, endpoint_result, explanation,
        shadow_result, anomaly_result
    )

    result["status"] = "completed"
    result["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return result


def _generate_scan_id(hostname: str) -> str:
    import hashlib
    import time
    raw = f"{hostname}{time.time()}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def _build_combined(
    tls: dict,
    cert: dict,
    cipher: dict,
    key: dict
) -> dict:
    return {
        "hostname": tls.get("hostname"),
        "ip": tls.get("ip"),
        "port": tls.get("port"),
        "tls_version": tls.get("tls_version"),
        "cipher_name": tls.get("cipher_name"),
        "cipher_bits": tls.get("cipher_bits"),
        "forward_secrecy": cipher.get("forward_secrecy", False),
        "classical_vulnerable": cipher.get("classical_vulnerable", False),
        "is_expired": cert.get("is_expired", False),
        "days_to_expiry": cert.get("days_to_expiry"),
        "key_type": cert.get("key_type"),
        "key_size": cert.get("key_size"),
        "curve_name": cert.get("curve_name"),
        "signature_algorithm": cert.get("signature_algorithm"),
        "is_self_signed": cert.get("is_self_signed", False),
        "basic_constraints_ca": cert.get("basic_constraints_ca", False),
        "ocsp_urls": cert.get("ocsp_urls", []),
        "is_wildcard": cert.get("is_wildcard", False),
        "san_domains": cert.get("san_domains", []),
        "subject_cn": cert.get("subject_cn"),
        "issuer_cn": cert.get("issuer_cn"),
        "not_after": cert.get("not_after"),
        "hndl_risk": key.get("hndl_risk"),
        "priority_score": key.get("priority_score"),
        "nist_replacements": key.get("nist_replacements", []),
        "final_score": None,
        "scanned_at": tls.get("scanned_at")
    }


def _build_summary(
    hostname: str,
    risk_result: dict,
    pqc_result: dict,
    hndl_result: dict,
    endpoint_result: dict,
    explanation: dict,
    shadow_result: dict,
    anomaly_result: dict
) -> dict:
    score_data = risk_result.get("risk_score", {})
    return {
        "hostname": hostname,
        "final_score": score_data.get("final_score"),
        "pqc_tier": score_data.get("pqc_tier"),
        "tier_label": score_data.get("tier_label"),
        "grade": explanation.get("overall_grade"),
        "grade_color": explanation.get("grade_color"),
        "one_liner": explanation.get("one_liner"),
        "executive_summary": explanation.get("executive_summary"),
        "pqc_score": pqc_result.get("pqc_score"),
        "pqc_classification": pqc_result.get("pqc_classification"),
        "hndl_threat_level": hndl_result.get("hndl_threat_level"),
        "hndl_score": hndl_result.get("adjusted_hndl_score"),
        "endpoint_type": endpoint_result.get("endpoint_type"),
        "sensitivity": endpoint_result.get("sensitivity"),
        "regulatory_scope": endpoint_result.get("regulatory_scope", []),
        "shadow_asset_count": shadow_result.get("total_shadow_count", 0),
        "critical_shadows": len(shadow_result.get("critical_shadows", [])),
        "anomaly_count": anomaly_result.get("anomaly_count", 0),
        "has_regression": anomaly_result.get("has_regression", False),
        "critical_findings": score_data.get("critical_count", 0),
        "high_findings": score_data.get("high_count", 0),
        "medium_findings": score_data.get("medium_count", 0),
        "low_findings": score_data.get("low_count", 0),
        "immediate_actions": len(pqc_result.get("immediate_actions", [])),
        "estimated_break_year": pqc_result.get(
            "estimated_quantum_risk_year", {}
        ).get("year") if pqc_result.get("estimated_quantum_risk_year") else None,
        "nist_replacements": pqc_result.get("nist_replacements", []),
        "migration_priority": risk_result.get(
            "risk_score", {}
        ).get("final_score", 0)
    }


def _build_failed_summary(hostname: str, error: str) -> dict:
    return {
        "hostname": hostname,
        "final_score": 0,
        "pqc_tier": "Critical",
        "tier_label": "Scan Failed",
        "grade": "F",
        "grade_color": "#FF0000",
        "one_liner": f"{hostname} could not be scanned — {error}",
        "executive_summary": f"Scan failed for {hostname}: {error}",
        "pqc_score": 0,
        "pqc_classification": "Critical",
        "hndl_threat_level": "UNKNOWN",
        "hndl_score": 0,
        "endpoint_type": "unknown",
        "sensitivity": "UNKNOWN",
        "regulatory_scope": [],
        "shadow_asset_count": 0,
        "critical_shadows": 0,
        "anomaly_count": 0,
        "has_regression": False,
        "critical_findings": 1,
        "high_findings": 0,
        "medium_findings": 0,
        "low_findings": 0,
        "immediate_actions": 0,
        "estimated_break_year": None,
        "nist_replacements": [],
        "migration_priority": 0,
        "error": error
    }