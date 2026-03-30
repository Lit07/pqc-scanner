CRYPTO_KNOWLEDGE_BASE = {
    "RSA": {
        "type": "asymmetric",
        "quantum_vulnerable": True,
        "attack_algorithm": "Shor's Algorithm",
        "vulnerability_level": "CRITICAL",
        "reason": "Shor's algorithm solves integer factorization in polynomial time, completely breaking RSA",
        "safe_key_sizes_classical": [2048, 3072, 4096],
        "unsafe_key_sizes": [512, 768, 1024],
        "quantum_broken_at_qubit_estimate": 4096,
        "nist_replacements": [
            {
                "algorithm": "CRYSTALS-Kyber",
                "nist_standard": "FIPS 203",
                "use_case": "Key Encapsulation / Key Exchange",
                "security_level": "Level 1/3/5",
                "drop_in_replacement": False,
                "migration_complexity": "Medium",
                "notes": "Primary NIST recommendation for key exchange replacing RSA-KEM"
            },
            {
                "algorithm": "CRYSTALS-Dilithium",
                "nist_standard": "FIPS 204",
                "use_case": "Digital Signatures",
                "security_level": "Level 2/3/5",
                "drop_in_replacement": False,
                "migration_complexity": "Medium",
                "notes": "Primary NIST recommendation for signatures replacing RSA signatures"
            },
            {
                "algorithm": "SPHINCS+",
                "nist_standard": "FIPS 205",
                "use_case": "Digital Signatures",
                "security_level": "Level 1/3/5",
                "drop_in_replacement": False,
                "migration_complexity": "High",
                "notes": "Hash-based, conservative choice, larger signature sizes"
            }
        ],
        "hndl_risk": "CRITICAL",
        "hndl_reason": "RSA encrypted traffic captured today can be decrypted once ~4000 qubit quantum computers exist"
    },

    "EC": {
        "type": "asymmetric",
        "quantum_vulnerable": True,
        "attack_algorithm": "Shor's Algorithm",
        "vulnerability_level": "CRITICAL",
        "reason": "Shor's algorithm solves elliptic curve discrete logarithm problem",
        "curves": {
            "secp256r1": {"bits": 256, "quantum_risk": "HIGH"},
            "secp384r1": {"bits": 384, "quantum_risk": "HIGH"},
            "secp521r1": {"bits": 521, "quantum_risk": "HIGH"},
            "prime256v1": {"bits": 256, "quantum_risk": "HIGH"}
        },
        "quantum_broken_at_qubit_estimate": 2048,
        "nist_replacements": [
            {
                "algorithm": "CRYSTALS-Kyber",
                "nist_standard": "FIPS 203",
                "use_case": "Key Exchange replacing ECDH",
                "migration_complexity": "Medium"
            },
            {
                "algorithm": "CRYSTALS-Dilithium",
                "nist_standard": "FIPS 204",
                "use_case": "Signatures replacing ECDSA",
                "migration_complexity": "Medium"
            },
            {
                "algorithm": "FALCON",
                "nist_standard": "FIPS 206",
                "use_case": "Signatures, smaller size than Dilithium",
                "migration_complexity": "High"
            }
        ],
        "hndl_risk": "CRITICAL",
        "hndl_reason": "ECC is broken faster than RSA on quantum computers due to smaller key sizes"
    },

    "DSA": {
        "type": "asymmetric",
        "quantum_vulnerable": True,
        "attack_algorithm": "Shor's Algorithm",
        "vulnerability_level": "CRITICAL",
        "reason": "DSA relies on discrete logarithm problem which Shor's solves",
        "additional_flag": "DSA is also deprecated by NIST classically — double red flag",
        "nist_replacements": [
            {
                "algorithm": "CRYSTALS-Dilithium",
                "nist_standard": "FIPS 204",
                "use_case": "Digital Signatures",
                "migration_complexity": "Low",
                "notes": "Direct drop-in for signature use cases"
            }
        ],
        "hndl_risk": "CRITICAL"
    },

    "Ed25519": {
        "type": "asymmetric",
        "quantum_vulnerable": True,
        "attack_algorithm": "Shor's Algorithm",
        "vulnerability_level": "HIGH",
        "reason": "Based on elliptic curve Curve25519, quantum vulnerable despite classical strength",
        "nist_replacements": [
            {
                "algorithm": "CRYSTALS-Dilithium",
                "nist_standard": "FIPS 204",
                "use_case": "Signatures",
                "migration_complexity": "Low"
            }
        ],
        "hndl_risk": "HIGH"
    },

    "Ed448": {
        "type": "asymmetric",
        "quantum_vulnerable": True,
        "attack_algorithm": "Shor's Algorithm",
        "vulnerability_level": "HIGH",
        "reason": "Based on elliptic curve Curve448, quantum vulnerable",
        "nist_replacements": [
            {
                "algorithm": "CRYSTALS-Dilithium",
                "nist_standard": "FIPS 204",
                "use_case": "Signatures",
                "migration_complexity": "Low"
            }
        ],
        "hndl_risk": "HIGH"
    }
}

CIPHER_KNOWLEDGE_BASE = {
    "TLS_AES_256_GCM_SHA384": {
        "tls_version": "TLS 1.3",
        "key_exchange": "Integrated in TLS 1.3",
        "symmetric": "AES-256-GCM",
        "hash": "SHA-384",
        "forward_secrecy": True,
        "quantum_vulnerable": "PARTIAL",
        "reason": "AES-256 is Grover-resistant but key exchange is still classical",
        "classical_strength": "STRONG",
        "pqc_tier": "Tier-2"
    },
    "TLS_AES_128_GCM_SHA256": {
        "tls_version": "TLS 1.3",
        "symmetric": "AES-128-GCM",
        "hash": "SHA-256",
        "forward_secrecy": True,
        "quantum_vulnerable": "PARTIAL",
        "reason": "AES-128 security halved by Grover's algorithm to 64-bit effective strength",
        "classical_strength": "ACCEPTABLE",
        "pqc_tier": "Tier-2"
    },
    "ECDHE-RSA-AES256-GCM-SHA384": {
        "tls_version": "TLS 1.2",
        "key_exchange": "ECDHE",
        "auth": "RSA",
        "symmetric": "AES-256-GCM",
        "hash": "SHA-384",
        "forward_secrecy": True,
        "quantum_vulnerable": True,
        "reason": "ECDHE and RSA auth both broken by Shor's algorithm",
        "classical_strength": "STRONG",
        "pqc_tier": "Tier-2"
    },
    "TLS_RSA_WITH_DES_CBC_SHA": {
        "tls_version": "TLS 1.0/1.1",
        "key_exchange": "RSA",
        "symmetric": "DES-CBC",
        "hash": "SHA-1",
        "forward_secrecy": False,
        "quantum_vulnerable": True,
        "classical_vulnerable": True,
        "reason": "DES is classically broken, no forward secrecy, SHA-1 deprecated",
        "classical_strength": "CRITICAL",
        "pqc_tier": "Critical"
    },
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": {
        "tls_version": "TLS 1.0/1.1",
        "key_exchange": "RSA",
        "symmetric": "3DES",
        "hash": "SHA-1",
        "forward_secrecy": False,
        "quantum_vulnerable": True,
        "classical_vulnerable": True,
        "reason": "3DES vulnerable to SWEET32 attack, no forward secrecy",
        "classical_strength": "CRITICAL",
        "pqc_tier": "Critical"
    }
}

TLS_VERSION_KNOWLEDGE = {
    "TLSv1.3": {
        "quantum_vulnerable": "PARTIAL",
        "classical_secure": True,
        "pqc_tier": "Tier-1",
        "notes": "Best classical option, PQC extensions available via hybrid mode"
    },
    "TLSv1.2": {
        "quantum_vulnerable": True,
        "classical_secure": True,
        "pqc_tier": "Tier-2",
        "notes": "Acceptable if strong ciphers used, upgrade path to TLS 1.3"
    },
    "TLSv1.1": {
        "quantum_vulnerable": True,
        "classical_secure": False,
        "pqc_tier": "Tier-3",
        "notes": "Deprecated by RFC 8996, remediation required"
    },
    "TLSv1.0": {
        "quantum_vulnerable": True,
        "classical_secure": False,
        "pqc_tier": "Tier-3",
        "notes": "Deprecated by RFC 8996, remediation required"
    },
    "SSLv3": {
        "quantum_vulnerable": True,
        "classical_secure": False,
        "pqc_tier": "Critical",
        "notes": "POODLE vulnerable, immediately block"
    },
    "SSLv2": {
        "quantum_vulnerable": True,
        "classical_secure": False,
        "pqc_tier": "Critical",
        "notes": "Completely broken, immediately block"
    }
}

NIST_PQC_ALGORITHMS = {
    "CRYSTALS-Kyber": {
        "nist_standard": "FIPS 203",
        "type": "Key Encapsulation Mechanism",
        "replaces": ["RSA-KEM", "ECDH", "DH"],
        "security_levels": [512, 768, 1024],
        "standardized": True,
        "year": 2024
    },
    "CRYSTALS-Dilithium": {
        "nist_standard": "FIPS 204",
        "type": "Digital Signature",
        "replaces": ["RSA", "ECDSA", "DSA", "Ed25519"],
        "security_levels": [2, 3, 5],
        "standardized": True,
        "year": 2024
    },
    "FALCON": {
        "nist_standard": "FIPS 206",
        "type": "Digital Signature",
        "replaces": ["RSA", "ECDSA"],
        "security_levels": [512, 1024],
        "standardized": True,
        "year": 2024
    },
    "SPHINCS+": {
        "nist_standard": "FIPS 205",
        "type": "Digital Signature",
        "replaces": ["RSA", "ECDSA"],
        "security_levels": [128, 192, 256],
        "standardized": True,
        "year": 2024,
        "notes": "Conservative hash-based, no known quantum attacks on hash functions"
    }
}