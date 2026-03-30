from analysis.crypto.cert_parser import parse_cert
from analysis.crypto.cipher_parser import parse_cipher
from analysis.crypto.key_analyzer import analyze_key
from analysis.risk.scoring import calculate_score
from analysis.risk.rules import evaluate_rules
import datetime


def run_risk_engine(tls_scan_result: dict, der_cert_bytes: bytes = None) -> dict:
    result = {
        "hostname": tls_scan_result.get("hostname"),
        "ip": tls_scan_result.get("ip"),
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tls_data": {},
        "cert_data": {},
        "cipher_data": {},
        "key_analysis": {},
        "risk_score": {},
        "triggered_rules": [],
        "summary": {},
        "error": None
    }

    if tls_scan_result.get("error"):
        result["error"] = tls_scan_result["error"]
        result["summary"] = _build_error_summary(tls_scan_result)
        return result

    result["tls_data"] = {
        "version": tls_scan_result.get("tls_version"),
        "cipher_name": tls_scan_result.get("cipher_name"),
        "cipher_bits": tls_scan_result.get("cipher_bits"),
        "cert_expiry": tls_scan_result.get("cert_expiry"),
        "cert_expired": tls_scan_result.get("cert_expired"),
        "san": tls_scan_result.get("san", [])
    }

    cipher_data = parse_cipher(
        cipher_name=tls_scan_result.get("cipher_name", ""),
        tls_version=tls_scan_result.get("tls_version", ""),
        key_bits=tls_scan_result.get("cipher_bits", 0)
    )
    result["cipher_data"] = cipher_data

    cert_data = {}
    key_analysis = {}

    if der_cert_bytes:
        cert_data = parse_cert(der_cert_bytes)
        result["cert_data"] = cert_data

        if cert_data.get("key_type"):
            key_analysis = analyze_key(
                key_type=cert_data["key_type"],
                key_size=cert_data.get("key_size", 0),
                curve_name=cert_data.get("curve_name")
            )
            result["key_analysis"] = key_analysis

    combined = _build_combined_scan_data(
        tls_scan_result,
        cert_data,
        cipher_data,
        key_analysis
    )

    score_result = calculate_score(combined)
    result["risk_score"] = score_result
    result["triggered_rules"] = score_result.get("triggered_rules", [])
    result["summary"] = _build_summary(result, score_result)

    return result


def _build_combined_scan_data(
    tls: dict,
    cert: dict,
    cipher: dict,
    key: dict
) -> dict:
    return {
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
        "hndl_risk": key.get("hndl_risk"),
        "priority_score": key.get("priority_score"),
    }


def _build_summary(result: dict, score_result: dict) -> dict:
    return {
        "hostname": result["hostname"],
        "ip": result["ip"],
        "final_score": score_result.get("final_score"),
        "pqc_tier": score_result.get("pqc_tier"),
        "tier_label": score_result.get("tier_label"),
        "critical_count": score_result.get("critical_count", 0),
        "high_count": score_result.get("high_count", 0),
        "medium_count": score_result.get("medium_count", 0),
        "low_count": score_result.get("low_count", 0),
        "pqc_impact_count": score_result.get("pqc_impact_count", 0),
        "tls_version": result["tls_data"].get("version"),
        "cipher_name": result["tls_data"].get("cipher_name"),
        "key_type": result["cert_data"].get("key_type"),
        "key_size": result["cert_data"].get("key_size"),
        "cert_expiry": result["tls_data"].get("cert_expiry"),
        "is_expired": result["tls_data"].get("cert_expired"),
        "hndl_risk": result["key_analysis"].get("hndl_risk"),
        "nist_replacements": result["key_analysis"].get("nist_replacements", []),
        "scanned_at": result["scanned_at"]
    }


def _build_error_summary(tls_scan_result: dict) -> dict:
    return {
        "hostname": tls_scan_result.get("hostname"),
        "ip": tls_scan_result.get("ip"),
        "final_score": 0,
        "pqc_tier": "Critical",
        "tier_label": "Unreachable / Scan Failed",
        "critical_count": 1,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "pqc_impact_count": 0,
        "tls_version": None,
        "cipher_name": None,
        "key_type": None,
        "key_size": None,
        "cert_expiry": None,
        "is_expired": None,
        "hndl_risk": None,
        "nist_replacements": [],
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "error": tls_scan_result.get("error")
    }