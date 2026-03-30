import datetime
import hashlib
from utils.constants import CRYPTO_KNOWLEDGE_BASE, NIST_PQC_ALGORITHMS, TLS_VERSION_KNOWLEDGE


CBOM_SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"


def build_cbom(
    hostname: str,
    tls_result: dict,
    cert_data: dict,
    cipher_data: dict,
    key_data: dict
) -> dict:
    components = []
    dependencies = []

    tls_component = _build_tls_protocol_component(tls_result)
    if tls_component:
        components.append(tls_component)

    cipher_component = _build_cipher_suite_component(tls_result, cipher_data)
    if cipher_component:
        components.append(cipher_component)
        if tls_component:
            dependencies.append({
                "ref": cipher_component["bom_ref"],
                "depends_on": [tls_component["bom_ref"]]
            })

    key_component = _build_key_algorithm_component(cert_data, key_data)
    if key_component:
        components.append(key_component)

    hash_component = _build_hash_algorithm_component(cert_data, cipher_data)
    if hash_component:
        components.append(hash_component)

    cert_component = _build_certificate_component(cert_data)
    if cert_component:
        components.append(cert_component)
        if key_component:
            dependencies.append({
                "ref": cert_component["bom_ref"],
                "depends_on": [key_component["bom_ref"]]
            })

    vulnerable_count = sum(
        1 for c in components if c.get("properties", {}).get("pqc_vulnerable")
    )
    total_count = len(components)

    cbom = {
        "bom_format": BOM_FORMAT,
        "spec_version": CBOM_SPEC_VERSION,
        "version": 1,
        "serial_number": _generate_serial(hostname),
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": f"pqc-scan-{hostname}",
                "version": "1.0.0"
            },
            "tools": [
                {
                    "vendor": "PQC Scanner",
                    "name": "pqc-scanner",
                    "version": "1.0.0"
                }
            ]
        },
        "components": components,
        "dependencies": dependencies,
        "summary": {
            "total_components": total_count,
            "vulnerable_components": vulnerable_count,
            "safe_components": total_count - vulnerable_count,
            "pqc_ready": vulnerable_count == 0,
            "hostname": hostname
        }
    }

    return cbom


def _generate_serial(hostname: str) -> str:
    import time
    raw = f"urn:uuid:{hostname}:{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:36]


def _build_tls_protocol_component(tls_result: dict) -> dict:
    tls_version = tls_result.get("tls_version")
    if not tls_version:
        return None

    tls_knowledge = TLS_VERSION_KNOWLEDGE.get(tls_version, {})
    pqc_vulnerable = tls_knowledge.get("quantum_vulnerable", True)
    classical_secure = tls_knowledge.get("classical_secure", False)

    return {
        "type": "cryptographic-asset",
        "bom_ref": f"crypto-protocol-{tls_version}",
        "name": "TLS Protocol",
        "version": tls_version,
        "description": f"Transport Layer Security protocol version {tls_version}",
        "crypto_properties": {
            "asset_type": "protocol",
            "algorithm_properties": {
                "variant": tls_version
            }
        },
        "properties": {
            "pqc_vulnerable": pqc_vulnerable if isinstance(pqc_vulnerable, bool) else True,
            "classical_secure": classical_secure,
            "pqc_tier": tls_knowledge.get("pqc_tier"),
            "notes": tls_knowledge.get("notes", ""),
            "nist_replacement": "TLS 1.3 with hybrid PQC key exchange"
                if tls_version != "TLSv1.3" else "Enable hybrid PQC extensions",
            "quantum_attack": "Protocol Limitation"
        }
    }


def _build_cipher_suite_component(tls_result: dict, cipher_data: dict) -> dict:
    cipher_name = tls_result.get("cipher_name")
    if not cipher_name:
        return None

    pqc_vulnerable = cipher_data.get("quantum_vulnerable", True)
    classical_vulnerable = cipher_data.get("classical_vulnerable", False)
    forward_secrecy = cipher_data.get("forward_secrecy", False)

    return {
        "type": "cryptographic-asset",
        "bom_ref": f"crypto-cipher-{cipher_name}",
        "name": "Cipher Suite",
        "version": cipher_name,
        "description": f"TLS cipher suite: {cipher_name}",
        "crypto_properties": {
            "asset_type": "algorithm",
            "algorithm_properties": {
                "variant": cipher_name,
                "primitive": "cipher",
                "parameter_set_identifier": str(tls_result.get("cipher_bits", ""))
            }
        },
        "properties": {
            "pqc_vulnerable": pqc_vulnerable if isinstance(pqc_vulnerable, bool) else True,
            "classical_vulnerable": classical_vulnerable,
            "forward_secrecy": forward_secrecy,
            "key_exchange": cipher_data.get("key_exchange"),
            "symmetric": cipher_data.get("symmetric"),
            "hash_algo": cipher_data.get("hash_algo"),
            "pqc_tier": cipher_data.get("pqc_tier"),
            "nist_replacement": "AES-256-GCM with hybrid PQC key exchange",
            "quantum_attack": "Shor's Algorithm (key exchange)"
                if not forward_secrecy else "Grover's Algorithm (symmetric)"
        }
    }


def _build_key_algorithm_component(cert_data: dict, key_data: dict) -> dict:
    key_type = cert_data.get("key_type")
    if not key_type:
        return None

    key_size = cert_data.get("key_size", 0)
    curve_name = cert_data.get("curve_name")

    kb = CRYPTO_KNOWLEDGE_BASE.get(key_type, {})
    replacements = kb.get("nist_replacements", [])
    primary_replacement = replacements[0]["algorithm"] if replacements else "CRYSTALS-Dilithium"
    primary_standard = replacements[0].get("nist_standard", "") if replacements else "FIPS 204"

    version_str = f"{key_type}-{key_size}"
    if curve_name:
        version_str = f"{key_type}-{curve_name}-{key_size}"

    return {
        "type": "cryptographic-asset",
        "bom_ref": f"crypto-key-{key_type}-{key_size}",
        "name": "Public Key Algorithm",
        "version": version_str,
        "description": f"Certificate public key: {version_str}",
        "crypto_properties": {
            "asset_type": "algorithm",
            "algorithm_properties": {
                "variant": key_type,
                "primitive": "public-key",
                "parameter_set_identifier": str(key_size),
                "curve": curve_name
            }
        },
        "properties": {
            "pqc_vulnerable": kb.get("quantum_vulnerable", True),
            "vulnerability_level": kb.get("vulnerability_level"),
            "attack_algorithm": kb.get("attack_algorithm"),
            "hndl_risk": kb.get("hndl_risk"),
            "quantum_broken_at_qubit_estimate": kb.get("quantum_broken_at_qubit_estimate"),
            "nist_replacement": f"{primary_replacement} ({primary_standard})",
            "all_replacements": replacements,
            "migration_complexity": key_data.get("migration_complexity"),
            "quantum_attack": kb.get("attack_algorithm", "Shor's Algorithm")
        }
    }


def _build_hash_algorithm_component(cert_data: dict, cipher_data: dict) -> dict:
    sig_algo = cert_data.get("signature_algorithm", "")
    hash_algo = cipher_data.get("hash_algo")

    if not sig_algo and not hash_algo:
        return None

    hash_name = hash_algo or "Unknown"

    is_sha1 = "sha1" in sig_algo.lower() if sig_algo else False
    is_md5 = hash_name == "MD5"

    pqc_vulnerable = is_sha1 or is_md5

    return {
        "type": "cryptographic-asset",
        "bom_ref": f"crypto-hash-{hash_name}",
        "name": "Hash Algorithm",
        "version": hash_name,
        "description": f"Hash algorithm used: {hash_name}",
        "crypto_properties": {
            "asset_type": "algorithm",
            "algorithm_properties": {
                "variant": hash_name,
                "primitive": "hash"
            }
        },
        "properties": {
            "pqc_vulnerable": pqc_vulnerable,
            "classical_vulnerable": is_sha1 or is_md5,
            "nist_replacement": "SHA-384 or SHA-512"
                if pqc_vulnerable else "Current hash is acceptable",
            "quantum_attack": "Grover's Algorithm"
                if pqc_vulnerable else "Limited quantum impact"
        }
    }


def _build_certificate_component(cert_data: dict) -> dict:
    subject_cn = cert_data.get("subject_cn")
    if not subject_cn:
        return None

    return {
        "type": "cryptographic-asset",
        "bom_ref": f"crypto-cert-{subject_cn}",
        "name": "X.509 Certificate",
        "version": cert_data.get("serial_number", "unknown"),
        "description": f"TLS certificate for {subject_cn}",
        "crypto_properties": {
            "asset_type": "certificate",
            "certificate_properties": {
                "subject_name": subject_cn,
                "issuer_name": cert_data.get("issuer_cn"),
                "not_valid_before": cert_data.get("not_before"),
                "not_valid_after": cert_data.get("not_after"),
                "signature_algorithm_ref": cert_data.get("signature_algorithm")
            }
        },
        "properties": {
            "pqc_vulnerable": True,
            "is_expired": cert_data.get("is_expired", False),
            "is_self_signed": cert_data.get("is_self_signed", False),
            "is_wildcard": cert_data.get("is_wildcard", False),
            "days_to_expiry": cert_data.get("days_to_expiry"),
            "san_count": len(cert_data.get("san_domains", [])),
            "nist_replacement": "PQC-signed certificate (CRYSTALS-Dilithium)",
            "quantum_attack": "Certificate signature forgery via Shor's Algorithm"
        }
    }
