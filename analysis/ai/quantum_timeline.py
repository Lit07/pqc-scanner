import datetime
from utils.constants import CRYPTO_KNOWLEDGE_BASE

QUANTUM_MILESTONES = [
    {"year": 2025, "qubits": 1000,  "capability": "Early NISQ era, no cryptographic threat"},
    {"year": 2027, "qubits": 4000,  "capability": "RSA-512 theoretically breakable"},
    {"year": 2029, "qubits": 10000, "capability": "RSA-1024 and EC-256 at risk"},
    {"year": 2031, "qubits": 50000, "capability": "RSA-2048 becoming vulnerable"},
    {"year": 2033, "qubits": 100000,"capability": "RSA-2048 breakable, EC-384 at risk"},
    {"year": 2036, "qubits": 500000,"capability": "RSA-3072 breakable"},
    {"year": 2038, "qubits": 1000000,"capability": "RSA-4096 breakable, full classical PKI compromised"},
]

KEY_BREAK_ESTIMATES = {
    "RSA": {
        512:  2027, 1024: 2029,
        2048: 2033, 3072: 2036, 4096: 2038
    },
    "EC": {
        224: 2028, 256: 2029,
        384: 2032, 521: 2035
    },
    "DSA": {1024: 2028, 2048: 2032},
    "Ed25519": {256: 2030},
    "Ed448":   {448: 2034}
}


def generate_quantum_timeline(scan_data: dict) -> dict:
    key_type = scan_data.get("key_type")
    key_size = scan_data.get("key_size", 0) or 0
    current_year = datetime.datetime.now().year

    result = {
        "hostname": scan_data.get("hostname"),
        "key_type": key_type,
        "key_size": key_size,
        "current_year": current_year,
        "estimated_break_year": None,
        "years_until_break": None,
        "urgency_level": None,
        "countdown_message": None,
        "milestones": QUANTUM_MILESTONES,
        "asset_milestone": None,
        "nist_deadline": 2035,
        "migration_deadline_message": None,
        "timeline_events": []
    }

    if key_type and key_type in KEY_BREAK_ESTIMATES:
        estimates = KEY_BREAK_ESTIMATES[key_type]
        closest = min(estimates.keys(), key=lambda k: abs(k - key_size))
        break_year = estimates[closest]
        result["estimated_break_year"] = break_year
        years_left = break_year - current_year
        result["years_until_break"] = years_left

        if years_left <= 3:
            result["urgency_level"] = "CRITICAL"
        elif years_left <= 6:
            result["urgency_level"] = "HIGH"
        elif years_left <= 10:
            result["urgency_level"] = "MEDIUM"
        else:
            result["urgency_level"] = "LOW"

        result["countdown_message"] = (
            f"This {key_type}-{key_size} key is estimated to be "
            f"quantum-breakable by {break_year} — "
            f"{years_left} years from now."
        )

        result["asset_milestone"] = next(
            (m for m in QUANTUM_MILESTONES if m["year"] >= break_year),
            QUANTUM_MILESTONES[-1]
        )

    result["migration_deadline_message"] = (
        f"NIST recommends completing PQC migration by 2035. "
        f"You have {2035 - current_year} years to migrate."
    )

    result["timeline_events"] = _build_timeline_events(
        current_year,
        result.get("estimated_break_year"),
        scan_data.get("forward_secrecy", False)
    )

    return result


def _build_timeline_events(
    current_year: int,
    break_year: int,
    forward_secrecy: bool
) -> list:
    events = []

    events.append({
        "year": current_year,
        "event": "Current state — adversaries begin harvesting encrypted traffic",
        "type": "warning" if not forward_secrecy else "info"
    })
    events.append({
        "year": 2026,
        "event": "NIST FIPS 203/204/205/206 fully operational — PQC standards available",
        "type": "milestone"
    })
    events.append({
        "year": 2028,
        "event": "Expected widespread quantum computing research breakthroughs",
        "type": "warning"
    })
    if break_year:
        events.append({
            "year": break_year,
            "event": f"Estimated year this asset's encryption becomes quantum-breakable",
            "type": "critical"
        })
    events.append({
        "year": 2035,
        "event": "NIST recommended deadline for full PQC migration",
        "type": "deadline"
    })

    return sorted(events, key=lambda e: e["year"])