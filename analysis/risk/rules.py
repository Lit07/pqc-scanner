RISK_RULES = [
    {
        "id": "R001",
        "name": "SSLv2 or SSLv3 in use",
        "severity": "CRITICAL",
        "category": "protocol",
        "score_penalty": 200,
        "pqc_impact": True,
        "condition": lambda data: data.get("tls_version") in ["SSLv2", "SSLv3"],
        "message": "SSLv2/SSLv3 is critically broken and must be disabled immediately"
    },
    {
        "id": "R002",
        "name": "TLS 1.0 or 1.1 deprecated",
        "severity": "HIGH",
        "category": "protocol",
        "score_penalty": 120,
        "pqc_impact": True,
        "condition": lambda data: data.get("tls_version") in ["TLSv1.0", "TLSv1.1"],
        "message": "TLS 1.0/1.1 deprecated by RFC 8996, upgrade to TLS 1.2+ required"
    },
    {
        "id": "R003",
        "name": "Weak cipher suite detected",
        "severity": "CRITICAL",
        "category": "cipher",
        "score_penalty": 180,
        "pqc_impact": False,
        "condition": lambda data: any(
            w in (data.get("cipher_name") or "")
            for w in ["DES", "RC4", "NULL", "EXPORT", "anon"]
        ),
        "message": "Critically weak cipher suite in use — classically breakable"
    },
    {
        "id": "R004",
        "name": "No forward secrecy",
        "severity": "CRITICAL",
        "category": "cipher",
        "score_penalty": 150,
        "pqc_impact": True,
        "condition": lambda data: data.get("forward_secrecy") is False,
        "message": "No forward secrecy — all sessions vulnerable to future key compromise and HNDL attacks"
    },
    {
        "id": "R005",
        "name": "Certificate expired",
        "severity": "CRITICAL",
        "category": "certificate",
        "score_penalty": 200,
        "pqc_impact": False,
        "condition": lambda data: data.get("is_expired") is True,
        "message": "Certificate has expired — connections will be rejected by browsers"
    },
    {
        "id": "R006",
        "name": "Certificate expiring within 30 days",
        "severity": "HIGH",
        "category": "certificate",
        "score_penalty": 80,
        "pqc_impact": False,
        "condition": lambda data: (
            data.get("days_to_expiry") is not None and
            0 < data.get("days_to_expiry", 999) <= 30
        ),
        "message": "Certificate expiring within 30 days — renew immediately"
    },
    {
        "id": "R007",
        "name": "Self-signed certificate",
        "severity": "HIGH",
        "category": "certificate",
        "score_penalty": 100,
        "pqc_impact": False,
        "condition": lambda data: data.get("is_self_signed") is True,
        "message": "Self-signed certificate — not trusted by public CAs"
    },
    {
        "id": "R008",
        "name": "RSA key below 2048 bits",
        "severity": "CRITICAL",
        "category": "key_strength",
        "score_penalty": 180,
        "pqc_impact": True,
        "condition": lambda data: (
            data.get("key_type") == "RSA" and
            data.get("key_size") is not None and
            data.get("key_size") < 2048
        ),
        "message": "RSA key below 2048 bits — classically weak and quantum vulnerable"
    },
    {
        "id": "R009",
        "name": "RSA key quantum vulnerable",
        "severity": "HIGH",
        "category": "pqc",
        "score_penalty": 100,
        "pqc_impact": True,
        "condition": lambda data: data.get("key_type") == "RSA",
        "message": "RSA key is fully broken by Shor's algorithm on quantum computers"
    },
    {
        "id": "R010",
        "name": "ECC key quantum vulnerable",
        "severity": "HIGH",
        "category": "pqc",
        "score_penalty": 100,
        "pqc_impact": True,
        "condition": lambda data: data.get("key_type") == "EC",
        "message": "Elliptic curve key is quantum vulnerable via Shor's algorithm"
    },
    {
        "id": "R011",
        "name": "DSA key deprecated and quantum vulnerable",
        "severity": "CRITICAL",
        "category": "pqc",
        "score_penalty": 150,
        "pqc_impact": True,
        "condition": lambda data: data.get("key_type") == "DSA",
        "message": "DSA is deprecated classically and fully broken by quantum computers"
    },
    {
        "id": "R012",
        "name": "Weak cipher bits",
        "severity": "MEDIUM",
        "category": "cipher",
        "score_penalty": 60,
        "pqc_impact": False,
        "condition": lambda data: (
            data.get("cipher_bits") is not None and
            data.get("cipher_bits") < 128
        ),
        "message": "Cipher key length below 128 bits — insufficient security"
    },
    {
        "id": "R013",
        "name": "CA certificate exposed on public endpoint",
        "severity": "CRITICAL",
        "category": "certificate",
        "score_penalty": 150,
        "pqc_impact": False,
        "condition": lambda data: data.get("basic_constraints_ca") is True,
        "message": "CA certificate should not be exposed on public endpoint"
    },
    {
        "id": "R014",
        "name": "No OCSP stapling",
        "severity": "LOW",
        "category": "certificate",
        "score_penalty": 20,
        "pqc_impact": False,
        "condition": lambda data: len(data.get("ocsp_urls", [])) == 0,
        "message": "No OCSP URLs found — revocation checking may be limited"
    },
    {
        "id": "R015",
        "name": "Wildcard certificate in use",
        "severity": "MEDIUM",
        "category": "certificate",
        "score_penalty": 30,
        "pqc_impact": False,
        "condition": lambda data: data.get("is_wildcard") is True,
        "message": "Wildcard certificate increases blast radius if private key is compromised"
    },
    {
        "id": "R016",
        "name": "HNDL risk active",
        "severity": "HIGH",
        "category": "pqc",
        "score_penalty": 80,
        "pqc_impact": True,
        "condition": lambda data: (
            data.get("hndl_risk") in ["CRITICAL", "HIGH"] and
            data.get("forward_secrecy") is False
        ),
        "message": "Harvest Now Decrypt Later risk is active — encrypted traffic at risk of future decryption"
    },
    {
        "id": "R017",
        "name": "Ed25519/Ed448 quantum vulnerable",
        "severity": "MEDIUM",
        "category": "pqc",
        "score_penalty": 60,
        "pqc_impact": True,
        "condition": lambda data: data.get("key_type") in ["Ed25519", "Ed448"],
        "message": "Edwards curve keys are quantum vulnerable despite strong classical security"
    },
    {
        "id": "R018",
        "name": "AES-128 Grover risk",
        "severity": "LOW",
        "category": "pqc",
        "score_penalty": 25,
        "pqc_impact": True,
        "condition": lambda data: (
            "AES128" in (data.get("cipher_name") or "") or
            "AES_128" in (data.get("cipher_name") or "")
        ),
        "message": "AES-128 effective security halved to 64-bit by Grover's algorithm"
    },
    {
        "id": "R019",
        "name": "Long-lived certificate",
        "severity": "MEDIUM",
        "category": "certificate",
        "score_penalty": 40,
        "pqc_impact": True,
        "condition": lambda data: (
            data.get("days_to_expiry") is not None and
            data.get("days_to_expiry") > 397
        ),
        "message": "Certificate lifetime exceeds industry best practice of 397 days"
    },
    {
        "id": "R020",
        "name": "Classical vulnerability detected",
        "severity": "CRITICAL",
        "category": "cipher",
        "score_penalty": 160,
        "pqc_impact": False,
        "condition": lambda data: data.get("classical_vulnerable") is True,
        "message": "Cipher suite has known classical vulnerabilities"
    }
]


def evaluate_rules(scan_data: dict) -> list:
    triggered = []
    for rule in RISK_RULES:
        try:
            if rule["condition"](scan_data):
                triggered.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "score_penalty": rule["score_penalty"],
                    "pqc_impact": rule["pqc_impact"],
                    "message": rule["message"]
                })
        except Exception:
            continue
    return triggered
