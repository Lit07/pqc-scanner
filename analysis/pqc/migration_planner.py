from utils.constants import CRYPTO_KNOWLEDGE_BASE, NIST_PQC_ALGORITHMS
from analysis.pqc.pqc_rules import evaluate_pqc_rules, get_immediate_actions
import datetime

MIGRATION_PHASES = {
    "PHASE_1": {
        "name": "Emergency Remediation",
        "timeframe": "0-30 days",
        "description": "Address critical classical and quantum vulnerabilities immediately"
    },
    "PHASE_2": {
        "name": "Protocol Hardening",
        "timeframe": "30-90 days",
        "description": "Upgrade protocols and cipher suites to modern standards"
    },
    "PHASE_3": {
        "name": "PQC Preparation",
        "timeframe": "90-180 days",
        "description": "Inventory cryptographic assets and begin hybrid PQC testing"
    },
    "PHASE_4": {
        "name": "Hybrid PQC Deployment",
        "timeframe": "180-365 days",
        "description": "Deploy hybrid classical and PQC cipher suites in production"
    },
    "PHASE_5": {
        "name": "Full PQC Migration",
        "timeframe": "1-3 years",
        "description": "Complete migration to NIST standardized PQC algorithms"
    }
}

ALGORITHM_MIGRATION_PATHS = {
    "RSA": {
        "signature_replacement": "CRYSTALS-Dilithium",
        "key_exchange_replacement": "CRYSTALS-Kyber",
        "interim_step": "Upgrade to RSA-3072 minimum while planning PQC migration",
        "nist_standards": ["FIPS 203", "FIPS 204"],
        "estimated_effort_days": 90,
        "complexity": "MEDIUM",
        "breaking_change": True
    },
    "EC": {
        "signature_replacement": "CRYSTALS-Dilithium",
        "key_exchange_replacement": "CRYSTALS-Kyber",
        "interim_step": "Enable TLS 1.3 with ECDHE as bridge to hybrid PQC",
        "nist_standards": ["FIPS 203", "FIPS 204"],
        "estimated_effort_days": 75,
        "complexity": "MEDIUM",
        "breaking_change": True
    },
    "DSA": {
        "signature_replacement": "CRYSTALS-Dilithium",
        "key_exchange_replacement": None,
        "interim_step": "Migrate to ECDSA immediately as DSA is classically deprecated",
        "nist_standards": ["FIPS 204"],
        "estimated_effort_days": 30,
        "complexity": "LOW",
        "breaking_change": True
    },
    "Ed25519": {
        "signature_replacement": "CRYSTALS-Dilithium",
        "key_exchange_replacement": "CRYSTALS-Kyber",
        "interim_step": "Continue using Ed25519 classically while preparing PQC stack",
        "nist_standards": ["FIPS 203", "FIPS 204"],
        "estimated_effort_days": 60,
        "complexity": "LOW",
        "breaking_change": False
    },
    "Ed448": {
        "signature_replacement": "CRYSTALS-Dilithium",
        "key_exchange_replacement": "CRYSTALS-Kyber",
        "interim_step": "Continue using Ed448 classically while preparing PQC stack",
        "nist_standards": ["FIPS 203", "FIPS 204"],
        "estimated_effort_days": 60,
        "complexity": "LOW",
        "breaking_change": False
    }
}


def generate_migration_plan(scan_data: dict, risk_engine_result: dict = None) -> dict:
    result = {
        "hostname": scan_data.get("hostname"),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "key_type": scan_data.get("key_type"),
        "current_posture_summary": None,
        "migration_path": None,
        "phases": [],
        "immediate_actions": [],
        "interim_steps": [],
        "full_migration_steps": [],
        "estimated_total_days": None,
        "nist_standards_applicable": [],
        "breaking_changes": False,
        "hybrid_mode_recommended": False,
        "priority_score": None
    }

    triggered_pqc = evaluate_pqc_rules(scan_data)
    immediate = get_immediate_actions(triggered_pqc)
    result["immediate_actions"] = _build_immediate_actions(immediate, scan_data)

    key_type = scan_data.get("key_type")
    if key_type and key_type in ALGORITHM_MIGRATION_PATHS:
        path = ALGORITHM_MIGRATION_PATHS[key_type]
        result["migration_path"] = path
        result["nist_standards_applicable"] = path.get("nist_standards", [])
        result["breaking_changes"] = path.get("breaking_change", False)
        result["estimated_total_days"] = path.get("estimated_effort_days")
        result["interim_steps"] = _build_interim_steps(key_type, scan_data, path)

    result["phases"] = _build_phases(scan_data, triggered_pqc, key_type)
    result["full_migration_steps"] = _build_full_migration_steps(key_type, scan_data)
    result["hybrid_mode_recommended"] = scan_data.get("tls_version") == "TLSv1.3"
    result["current_posture_summary"] = _build_posture_summary(scan_data, triggered_pqc)
    result["priority_score"] = _calculate_migration_priority(scan_data, triggered_pqc)

    return result


def _build_immediate_actions(immediate_rules: list, scan_data: dict) -> list:
    actions = []

    for rule in immediate_rules:
        actions.append({
            "action": rule["nist_action"],
            "reason": rule["pqc_message"],
            "urgency": "IMMEDIATE",
            "rule_id": rule["id"]
        })

    if scan_data.get("is_expired"):
        actions.insert(0, {
            "action": "Renew expired certificate immediately",
            "reason": "Expired certificate causes untrusted connections",
            "urgency": "IMMEDIATE",
            "rule_id": "CERT_EXPIRED"
        })

    if scan_data.get("basic_constraints_ca"):
        actions.insert(0, {
            "action": "Remove CA certificate from public-facing endpoint",
            "reason": "CA certificate exposure is a critical misconfiguration",
            "urgency": "IMMEDIATE",
            "rule_id": "CA_CERT_EXPOSED"
        })

    return actions


def _build_interim_steps(key_type: str, scan_data: dict, path: dict) -> list:
    steps = []

    steps.append({
        "step": 1,
        "action": path.get("interim_step"),
        "phase": "PHASE_2",
        "effort": "LOW",
        "description": "Immediate classical hardening before full PQC migration"
    })

    if not scan_data.get("forward_secrecy"):
        steps.append({
            "step": 2,
            "action": "Enable ECDHE cipher suites to establish forward secrecy",
            "phase": "PHASE_2",
            "effort": "LOW",
            "description": "Critical for reducing HNDL exposure window immediately"
        })

    if scan_data.get("tls_version") in ["TLSv1.0", "TLSv1.1"]:
        steps.append({
            "step": len(steps) + 1,
            "action": "Upgrade TLS stack to support TLS 1.2 minimum, TLS 1.3 preferred",
            "phase": "PHASE_2",
            "effort": "MEDIUM",
            "description": "Required before hybrid PQC extensions can be deployed"
        })

    key_size = scan_data.get("key_size") or 0
    if scan_data.get("key_type") == "RSA" and key_size < 3072:
        steps.append({
            "step": len(steps) + 1,
            "action": f"Replace RSA-{scan_data.get('key_size')} certificate with RSA-3072 as interim measure",
            "phase": "PHASE_2",
            "effort": "MEDIUM",
            "description": "Strengthens classical posture while PQC migration is planned"
        })

    return steps


def _build_phases(scan_data: dict, triggered_pqc: list, key_type: str) -> list:
    phases = []

    for phase_id, phase_info in MIGRATION_PHASES.items():
        phase_steps = _get_phase_steps(phase_id, scan_data, key_type)
        if phase_steps:
            phases.append({
                "phase_id": phase_id,
                "name": phase_info["name"],
                "timeframe": phase_info["timeframe"],
                "description": phase_info["description"],
                "steps": phase_steps,
                "step_count": len(phase_steps)
            })

    return phases


def _get_phase_steps(phase_id: str, scan_data: dict, key_type: str) -> list:
    steps = []

    if phase_id == "PHASE_1":
        if scan_data.get("is_expired"):
            steps.append("Renew expired certificate")
        if scan_data.get("tls_version") in ["SSLv2", "SSLv3"]:
            steps.append("Disable SSLv2 and SSLv3 immediately")
        if scan_data.get("basic_constraints_ca"):
            steps.append("Remove CA certificate from public endpoint")
        if any(w in (scan_data.get("cipher_name") or "")
               for w in ["DES", "RC4", "NULL", "EXPORT"]):
            steps.append("Disable critically weak cipher suites")

    elif phase_id == "PHASE_2":
        if not scan_data.get("forward_secrecy"):
            steps.append("Enable ECDHE for forward secrecy")
        if scan_data.get("tls_version") in ["TLSv1.0", "TLSv1.1"]:
            steps.append("Upgrade to TLS 1.2 minimum")
        if key_type == "DSA":
            steps.append("Migrate from DSA to ECDSA immediately")
        steps.append("Standardise on AES-256-GCM cipher suites")

    elif phase_id == "PHASE_3":
        steps.append("Complete cryptographic asset inventory using CBOM")
        steps.append("Identify all RSA and ECC dependencies across systems")
        steps.append("Evaluate CRYSTALS-Kyber and CRYSTALS-Dilithium in test environment")
        steps.append("Engage certificate authority for PQC certificate roadmap")

    elif phase_id == "PHASE_4":
        if scan_data.get("tls_version") == "TLSv1.3":
            steps.append("Deploy hybrid ECDHE plus CRYSTALS-Kyber key exchange")
        else:
            steps.append("Upgrade to TLS 1.3 then deploy hybrid PQC key exchange")
        steps.append("Test hybrid PQC with major browsers and clients")
        steps.append("Monitor performance impact of PQC algorithms")

    elif phase_id == "PHASE_5":
        if key_type in ALGORITHM_MIGRATION_PATHS:
            path = ALGORITHM_MIGRATION_PATHS[key_type]
            if path.get("signature_replacement"):
                steps.append(
                    f"Replace {key_type} signatures with "
                    f"{path['signature_replacement']} ({path['nist_standards'][0] if path['nist_standards'] else ''})"
                )
            if path.get("key_exchange_replacement"):
                steps.append(
                    f"Replace key exchange with {path['key_exchange_replacement']} (FIPS 203)"
                )
        steps.append("Decommission all classical-only cryptographic configurations")
        steps.append("Validate full PQC compliance against NIST standards")

    return steps


def _build_full_migration_steps(key_type: str, scan_data: dict) -> list:
    steps = []
    step_num = 1
    
    days_to_expiry = scan_data.get("days_to_expiry")
    if days_to_expiry is None:
        days_to_expiry = 999

    if scan_data.get("is_expired") or days_to_expiry < 30:
        steps.append({
            "step": step_num,
            "action": "Renew certificate",
            "priority": "CRITICAL",
            "effort": "LOW",
            "phase": "PHASE_1"
        })
        step_num += 1

    if not scan_data.get("forward_secrecy"):
        steps.append({
            "step": step_num,
            "action": "Enable ECDHE cipher suites for forward secrecy",
            "priority": "HIGH",
            "effort": "LOW",
            "phase": "PHASE_2"
        })
        step_num += 1

    if scan_data.get("tls_version") not in ["TLSv1.2", "TLSv1.3"]:
        steps.append({
            "step": step_num,
            "action": "Upgrade TLS to 1.2 or 1.3",
            "priority": "HIGH",
            "effort": "MEDIUM",
            "phase": "PHASE_2"
        })
        step_num += 1

    steps.append({
        "step": step_num,
        "action": "Generate CBOM for full cryptographic dependency mapping",
        "priority": "HIGH",
        "effort": "LOW",
        "phase": "PHASE_3"
    })
    step_num += 1

    if key_type in ALGORITHM_MIGRATION_PATHS:
        path = ALGORITHM_MIGRATION_PATHS[key_type]
        if path.get("signature_replacement"):
            steps.append({
                "step": step_num,
                "action": f"Migrate signatures to {path['signature_replacement']}",
                "priority": "HIGH",
                "effort": path.get("complexity", "MEDIUM"),
                "phase": "PHASE_5",
                "nist_standard": path["nist_standards"][0] if path["nist_standards"] else None
            })
            step_num += 1

        if path.get("key_exchange_replacement"):
            steps.append({
                "step": step_num,
                "action": f"Migrate key exchange to {path['key_exchange_replacement']}",
                "priority": "HIGH",
                "effort": path.get("complexity", "MEDIUM"),
                "phase": "PHASE_5",
                "nist_standard": "FIPS 203"
            })
            step_num += 1

    steps.append({
        "step": step_num,
        "action": "Validate full PQC compliance and update CBOM",
        "priority": "MEDIUM",
        "effort": "LOW",
        "phase": "PHASE_5"
    })

    return steps


def _build_posture_summary(scan_data: dict, triggered_pqc: list) -> str:
    key_type = scan_data.get("key_type", "Unknown")
    key_size = scan_data.get("key_size", "Unknown")
    tls = scan_data.get("tls_version", "Unknown")
    count = len(triggered_pqc)

    return (
        f"Asset using {key_type}-{key_size} with {tls}. "
        f"{count} PQC rules triggered. "
        f"{'Forward secrecy enabled.' if scan_data.get('forward_secrecy') else 'No forward secrecy — HNDL risk active.'}"
    )


def _calculate_migration_priority(scan_data: dict, triggered_pqc: list) -> int:
    score = 0

    immediate_count = len([r for r in triggered_pqc if r.get("urgency") == "IMMEDIATE"])
    harvest_count = len([r for r in triggered_pqc if r.get("harvest_risk")])

    score += immediate_count * 25
    score += harvest_count * 15

    if not scan_data.get("forward_secrecy"):
        score += 20
    if scan_data.get("tls_version") in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
        score += 15
    if scan_data.get("is_expired"):
        score += 20

    return min(100, score)