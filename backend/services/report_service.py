import datetime
from db.models import ScanResult
from analysis.cbom.cbom_formatter import format_cbom_as_json, format_cbom_summary
from utils.logger import get_logger

logger = get_logger(__name__)


def generate_json_report(scan_result: ScanResult) -> dict:
    full = scan_result.full_result or {}

    summary = full.get("summary", {})
    risk = full.get("risk_engine", {})
    pqc = full.get("pqc_classification", {})
    hndl = full.get("hndl_assessment", {})
    migration = full.get("migration_plan", {})
    recommendations = full.get("recommendations", {})
    explanation = full.get("risk_explanation", {})
    cbom = full.get("cbom", {})

    report = {
        "report_metadata": {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "report_type": "full_scan_report",
            "scanner_version": "1.0.0",
            "scan_id": scan_result.id,
            "scan_job_id": scan_result.scan_job_id
        },
        "target": {
            "hostname": scan_result.hostname,
            "ip": scan_result.ip,
            "port": full.get("port", 443),
            "scanned_at": scan_result.scanned_at.isoformat()
                if scan_result.scanned_at else None
        },
        "executive_summary": {
            "grade": summary.get("grade"),
            "grade_color": summary.get("grade_color"),
            "final_score": summary.get("final_score"),
            "one_liner": summary.get("one_liner"),
            "executive_summary": summary.get("executive_summary"),
            "pqc_tier": summary.get("pqc_tier"),
            "tier_label": summary.get("tier_label"),
            "hndl_threat_level": summary.get("hndl_threat_level"),
            "endpoint_type": summary.get("endpoint_type"),
            "critical_findings": summary.get("critical_findings", 0),
            "high_findings": summary.get("high_findings", 0),
            "medium_findings": summary.get("medium_findings", 0),
            "low_findings": summary.get("low_findings", 0)
        },
        "tls_configuration": {
            "tls_version": scan_result.tls_version,
            "cipher_name": scan_result.cipher_name,
            "cipher_bits": scan_result.cipher_bits,
            "forward_secrecy": scan_result.forward_secrecy
        },
        "certificate": {
            "key_type": scan_result.key_type,
            "key_size": scan_result.key_size,
            "curve_name": scan_result.curve_name,
            "is_expired": scan_result.is_expired,
            "days_to_expiry": scan_result.days_to_expiry,
            "is_self_signed": scan_result.is_self_signed,
            "is_wildcard": scan_result.is_wildcard
        },
        "pqc_assessment": {
            "pqc_score": pqc.get("pqc_score"),
            "pqc_classification": pqc.get("pqc_classification"),
            "classification_description": pqc.get("classification_description"),
            "pqc_ready": pqc.get("pqc_ready"),
            "hybrid_mode_possible": pqc.get("hybrid_mode_possible"),
            "estimated_quantum_risk_year": pqc.get("estimated_quantum_risk_year"),
            "overall_verdict": pqc.get("overall_verdict"),
            "immediate_actions": pqc.get("immediate_actions", []),
            "nist_replacements": pqc.get("nist_replacements", [])
        },
        "hndl_assessment": {
            "hndl_threat_level": hndl.get("hndl_threat_level"),
            "hndl_score": hndl.get("adjusted_hndl_score"),
            "harvest_window_open": hndl.get("harvest_window_open"),
            "estimated_decrypt_year": hndl.get("estimated_decrypt_year"),
            "hndl_narrative": hndl.get("hndl_narrative")
        },
        "risk_details": {
            "risk_score": risk.get("risk_score", {}),
            "triggered_rules": risk.get("triggered_rules", [])
        },
        "migration_plan": {
            "phases": migration.get("phases", []),
            "immediate_actions": migration.get("immediate_actions", []),
            "estimated_total_days": migration.get("estimated_total_days"),
            "priority_score": migration.get("priority_score")
        },
        "recommendations": {
            "recommendations": recommendations.get("recommendations", []),
            "quick_wins": recommendations.get("quick_wins", []),
            "long_term": recommendations.get("long_term", []),
            "total_count": recommendations.get("total_count", 0)
        },
        "risk_explanation": {
            "executive_summary": explanation.get("executive_summary"),
            "technical_summary": explanation.get("technical_summary"),
            "risk_story": explanation.get("risk_story"),
            "key_findings": explanation.get("key_findings", []),
            "positive_findings": explanation.get("positive_findings", [])
        }
    }

    return report


def generate_executive_summary(scan_result: ScanResult) -> dict:
    full = scan_result.full_result or {}
    summary = full.get("summary", {})
    explanation = full.get("risk_explanation", {})

    return {
        "hostname": scan_result.hostname,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "executive_summary": explanation.get("executive_summary"),
        "technical_summary": explanation.get("technical_summary"),
        "risk_score": summary.get("final_score"),
        "grade": summary.get("grade"),
        "pqc_classification": summary.get("pqc_classification"),
        "one_liner": summary.get("one_liner"),
        "recommendations": full.get("recommendations", {}).get("recommendations", []),
        "immediate_actions": full.get("pqc_classification", {}).get("immediate_actions", [])
    }


def generate_cbom_export(scan_result: ScanResult) -> dict:
    full = scan_result.full_result or {}
    cbom = full.get("cbom", {})

    if not cbom:
        return {
            "hostname": scan_result.hostname,
            "error": "No CBOM data available for this scan"
        }

    return format_cbom_as_json(cbom)


def generate_cbom_summary_export(scan_result: ScanResult) -> dict:
    full = scan_result.full_result or {}
    cbom = full.get("cbom", {})

    if not cbom:
        return {
            "hostname": scan_result.hostname,
            "error": "No CBOM data available for this scan"
        }

    return format_cbom_summary(cbom)
