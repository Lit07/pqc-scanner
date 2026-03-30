from utils.constants import CRYPTO_KNOWLEDGE_BASE, NIST_PQC_ALGORITHMS

def analyze_key(key_type: str, key_size: int, curve_name: str = None) -> dict:
    key_size = key_size or 0
    result = {
        "key_type": key_type,
        "key_size": key_size,
        "curve_name": curve_name,
        "quantum_vulnerable": True,
        "vulnerability_level": None,
        "attack_algorithm": None,
        "vulnerability_reason": None,
        "classical_strength": None,
        "quantum_broken_at_qubit_estimate": None,
        "hndl_risk": None,
        "hndl_reason": None,
        "nist_replacements": [],
        "migration_complexity": None,
        "priority_score": None,
        "key_size_classical_status": None,
    }

    if key_type not in CRYPTO_KNOWLEDGE_BASE:
        result["vulnerability_reason"] = f"Unknown key type {key_type}"
        return result

    kb = CRYPTO_KNOWLEDGE_BASE[key_type]

    result["quantum_vulnerable"] = kb["quantum_vulnerable"]
    result["vulnerability_level"] = kb["vulnerability_level"]
    result["attack_algorithm"] = kb["attack_algorithm"]
    result["vulnerability_reason"] = kb["reason"]
    result["quantum_broken_at_qubit_estimate"] = kb.get("quantum_broken_at_qubit_estimate")
    result["hndl_risk"] = kb.get("hndl_risk")
    result["hndl_reason"] = kb.get("hndl_reason")
    result["nist_replacements"] = kb.get("nist_replacements", [])

    result["classical_strength"] = _assess_classical_strength(key_type, key_size, curve_name)
    result["key_size_classical_status"] = _assess_key_size(key_type, key_size)
    result["migration_complexity"] = _assess_migration_complexity(key_type, key_size)
    result["priority_score"] = _calculate_priority_score(
        kb["vulnerability_level"],
        result["hndl_risk"],
        result["key_size_classical_status"],
        result["migration_complexity"]
    )

    if curve_name and key_type == "EC":
        curve_data = kb.get("curves", {}).get(curve_name, {})
        if curve_data:
            result["curve_quantum_risk"] = curve_data.get("quantum_risk")

    return result


def _assess_classical_strength(key_type: str, key_size: int, curve_name: str) -> str:
    if key_type == "RSA":
        if key_size < 1024:
            return "CRITICALLY_WEAK"
        elif key_size == 1024:
            return "WEAK"
        elif key_size == 2048:
            return "ACCEPTABLE"
        elif key_size == 3072:
            return "STRONG"
        elif key_size >= 4096:
            return "VERY_STRONG"

    elif key_type == "EC":
        if key_size < 224:
            return "CRITICALLY_WEAK"
        elif key_size < 256:
            return "WEAK"
        elif key_size == 256:
            return "ACCEPTABLE"
        elif key_size == 384:
            return "STRONG"
        elif key_size >= 521:
            return "VERY_STRONG"

    elif key_type == "DSA":
        if key_size < 1024:
            return "CRITICALLY_WEAK"
        elif key_size == 1024:
            return "WEAK"
        else:
            return "ACCEPTABLE"

    elif key_type in ["Ed25519", "Ed448"]:
        return "STRONG"

    return "UNKNOWN"


def _assess_key_size(key_type: str, key_size: int) -> str:
    if key_type == "RSA":
        safe_sizes = CRYPTO_KNOWLEDGE_BASE["RSA"].get("safe_key_sizes_classical", [])
        unsafe_sizes = CRYPTO_KNOWLEDGE_BASE["RSA"].get("unsafe_key_sizes", [])
        if key_size in unsafe_sizes or key_size < 2048:
            return "UNSAFE"
        elif key_size in safe_sizes:
            return "SAFE_CLASSICAL"
        return "MARGINAL"

    elif key_type == "EC":
        if key_size < 256:
            return "UNSAFE"
        elif key_size >= 256:
            return "SAFE_CLASSICAL"

    elif key_type == "DSA":
        if key_size < 2048:
            return "UNSAFE"
        return "MARGINAL"

    elif key_type in ["Ed25519", "Ed448"]:
        return "SAFE_CLASSICAL"

    return "UNKNOWN"


def _assess_migration_complexity(key_type: str, key_size: int) -> str:
    if key_type == "DSA":
        return "LOW"
    elif key_type == "RSA":
        if key_size <= 1024:
            return "HIGH"
        return "MEDIUM"
    elif key_type == "EC":
        return "MEDIUM"
    elif key_type in ["Ed25519", "Ed448"]:
        return "LOW"
    return "MEDIUM"


def _calculate_priority_score(
    vulnerability_level: str,
    hndl_risk: str,
    key_size_status: str,
    migration_complexity: str
) -> int:
    score = 0

    vuln_weights = {
        "CRITICAL": 40,
        "HIGH": 30,
        "MEDIUM": 20,
        "LOW": 10
    }
    score += vuln_weights.get(vulnerability_level, 0)

    hndl_weights = {
        "CRITICAL": 30,
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 5
    }
    score += hndl_weights.get(hndl_risk, 0)

    size_weights = {
        "UNSAFE": 20,
        "MARGINAL": 10,
        "SAFE_CLASSICAL": 5,
        "UNKNOWN": 15
    }
    score += size_weights.get(key_size_status, 0)

    complexity_weights = {
        "LOW": 10,
        "MEDIUM": 7,
        "HIGH": 3
    }
    score += complexity_weights.get(migration_complexity, 0)

    return score