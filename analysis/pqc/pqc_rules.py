from utils.constants import (
    CRYPTO_KNOWLEDGE_BASE,
    CIPHER_KNOWLEDGE_BASE,
    TLS_VERSION_KNOWLEDGE,
    NIST_PQC_ALGORITHMS
)

PQC_RULES = [
    {
        "id": "PQC001",
        "name": "RSA key quantum vulnerable",
        "tier_impact": "CRITICAL",
        "category": "key_algorithm",
        "condition": lambda data: data.get("key_type") == "RSA",
        "pqc_message": "RSA is completely broken by Shor's algorithm on a sufficiently powerful quantum computer.",
        "quantum_attack": "Shor's Algorithm",
        "nist_action": "Migrate to CRYSTALS-Dilithium (FIPS 204) for signatures and CRYSTALS-Kyber (FIPS 203) for key exchange.",
        "urgency": "HIGH",
        "harvest_risk": True,
        "score_impact": 40
    },
    {
        "id": "PQC002",
        "name": "ECC key quantum vulnerable",
        "tier_impact": "CRITICAL",
        "category": "key_algorithm",
        "condition": lambda data: data.get("key_type") == "EC",
        "pqc_message": "Elliptic curve cryptography is broken faster than RSA by Shor's algorithm.",
        "quantum_attack": "Shor's Algorithm",
        "nist_action": "Migrate to CRYSTALS-Kyber (FIPS 203) for key exchange and CRYSTALS-Dilithium (FIPS 204) for signatures.",
        "urgency": "HIGH",
        "harvest_risk": True,
        "score_impact": 40
    },
    {
        "id": "PQC003",
        "name": "DSA key quantum vulnerable",
        "tier_impact": "CRITICAL",
        "category": "key_algorithm",
        "condition": lambda data: data.get("key_type") == "DSA",
        "pqc_message": "DSA is deprecated classically and fully broken by Shor's algorithm.",
        "quantum_attack": "Shor's Algorithm",
        "nist_action": "Immediate migration to CRYSTALS-Dilithium (FIPS 204).",
        "urgency": "IMMEDIATE",
        "harvest_risk": True,
        "score_impact": 50
    },
    {
        "id": "PQC004",
        "name": "AES-128 Grover vulnerable",
        "tier_impact": "MEDIUM",
        "category": "symmetric_cipher",
        "condition": lambda data: "AES128" in (data.get("cipher_name") or "") or
                                  "AES_128" in (data.get("cipher_name") or ""),
        "pqc_message": "Grover's algorithm halves effective AES-128 security to 64 bits.",
        "quantum_attack": "Grover's Algorithm",
        "nist_action": "Upgrade to AES-256 for quantum resistance.",
        "urgency": "MEDIUM",
        "harvest_risk": False,
        "score_impact": 15
    },
    {
        "id": "PQC005",
        "name": "No forward secrecy HNDL critical",
        "tier_impact": "CRITICAL",
        "category": "hndl",
        "condition": lambda data: (
            data.get("forward_secrecy") is False and
            data.get("key_type") in ["RSA", "EC", "DSA"]
        ),
        "pqc_message": "Without forward secrecy, all past and future sessions are permanently vulnerable to harvest now decrypt later attacks.",
        "quantum_attack": "Harvest Now Decrypt Later",
        "nist_action": "Enable ECDHE immediately. Begin hybrid PQC key exchange deployment.",
        "urgency": "IMMEDIATE",
        "harvest_risk": True,
        "score_impact": 45
    },
    {
        "id": "PQC006",
        "name": "TLS 1.0 or 1.1 no PQC path",
        "tier_impact": "CRITICAL",
        "category": "protocol",
        "condition": lambda data: data.get("tls_version") in ["TLSv1.0", "TLSv1.1"],
        "pqc_message": "TLS 1.0/1.1 cannot support PQC cipher suites. Full protocol upgrade required.",
        "quantum_attack": "Protocol Limitation",
        "nist_action": "Upgrade to TLS 1.3 which supports hybrid PQC extensions.",
        "urgency": "HIGH",
        "harvest_risk": True,
        "score_impact": 35
    },
    {
        "id": "PQC007",
        "name": "TLS 1.2 limited PQC support",
        "tier_impact": "MEDIUM",
        "category": "protocol",
        "condition": lambda data: data.get("tls_version") == "TLSv1.2",
        "pqc_message": "TLS 1.2 has limited PQC extension support. TLS 1.3 is preferred for PQC hybrid mode.",
        "quantum_attack": "Protocol Limitation",
        "nist_action": "Plan upgrade to TLS 1.3 to enable hybrid PQC cipher suites.",
        "urgency": "MEDIUM",
        "harvest_risk": False,
        "score_impact": 15
    },
    {
        "id": "PQC008",
        "name": "RSA key size below quantum safe threshold",
        "tier_impact": "CRITICAL",
        "category": "key_size",
        "condition": lambda data: (
            data.get("key_type") == "RSA" and
            data.get("key_size") is not None and
            data.get("key_size") < 3072
        ),
        "pqc_message": "RSA keys below 3072 bits offer insufficient classical security and no quantum resistance.",
        "quantum_attack": "Shor's Algorithm",
        "nist_action": "Replace with RSA-3072 minimum as interim step or migrate directly to CRYSTALS-Dilithium.",
        "urgency": "HIGH",
        "harvest_risk": True,
        "score_impact": 30
    },
    {
        "id": "PQC009",
        "name": "SHA-1 signature hash quantum weak",
        "tier_impact": "HIGH",
        "category": "hash_algorithm",
        "condition": lambda data: "sha1" in (data.get("signature_algorithm") or "").lower(),
        "pqc_message": "SHA-1 is classically broken and provides no quantum resistance.",
        "quantum_attack": "Grover's Algorithm",
        "nist_action": "Replace with SHA-256 minimum. SHA-384 preferred for PQC context.",
        "urgency": "HIGH",
        "harvest_risk": False,
        "score_impact": 25
    },
    {
        "id": "PQC010",
        "name": "No PQC hybrid mode detected",
        "tier_impact": "MEDIUM",
        "category": "pqc_readiness",
        "condition": lambda data: data.get("tls_version") == "TLSv1.3" and
                                  data.get("key_type") in ["RSA", "EC"],
        "pqc_message": "TLS 1.3 in use but no hybrid PQC key exchange detected. Asset is PQC-unready.",
        "quantum_attack": "Future Quantum Threat",
        "nist_action": "Implement hybrid key exchange combining ECDHE with CRYSTALS-Kyber.",
        "urgency": "MEDIUM",
        "harvest_risk": False,
        "score_impact": 20
    },
    {
        "id": "PQC011",
        "name": "Ed25519 or Ed448 quantum vulnerable",
        "tier_impact": "HIGH",
        "category": "key_algorithm",
        "condition": lambda data: data.get("key_type") in ["Ed25519", "Ed448"],
        "pqc_message": "Edwards curve keys are quantum vulnerable despite strong classical security.",
        "quantum_attack": "Shor's Algorithm",
        "nist_action": "Migrate to CRYSTALS-Dilithium (FIPS 204) for signature use cases.",
        "urgency": "MEDIUM",
        "harvest_risk": True,
        "score_impact": 25
    },
    {
        "id": "PQC012",
        "name": "Long lived certificate high HNDL exposure",
        "tier_impact": "HIGH",
        "category": "hndl",
        "condition": lambda data: (
            data.get("days_to_expiry") is not None and
            data.get("days_to_expiry") > 365 and
            data.get("key_type") in ["RSA", "EC", "DSA"]
        ),
        "pqc_message": "Long-lived certificate increases HNDL exposure window. Traffic encrypted under this cert is at risk for longer.",
        "quantum_attack": "Harvest Now Decrypt Later",
        "nist_action": "Reduce certificate lifetime. Begin PQC migration planning.",
        "urgency": "MEDIUM",
        "harvest_risk": True,
        "score_impact": 20
    },
]


def evaluate_pqc_rules(scan_data: dict) -> list:
    triggered = []
    for rule in PQC_RULES:
        try:
            if rule["condition"](scan_data):
                triggered.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "tier_impact": rule["tier_impact"],
                    "category": rule["category"],
                    "pqc_message": rule["pqc_message"],
                    "quantum_attack": rule["quantum_attack"],
                    "nist_action": rule["nist_action"],
                    "urgency": rule["urgency"],
                    "harvest_risk": rule["harvest_risk"],
                    "score_impact": rule["score_impact"]
                })
        except Exception:
            continue
    return triggered


def get_harvest_risk_rules(triggered: list) -> list:
    return [r for r in triggered if r.get("harvest_risk") is True]


def get_immediate_actions(triggered: list) -> list:
    return [r for r in triggered if r.get("urgency") == "IMMEDIATE"]


def get_pqc_score(triggered: list) -> int:
    total_impact = sum(r["score_impact"] for r in triggered)
    return max(0, 100 - total_impact)