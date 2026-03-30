from utils.constants import CIPHER_KNOWLEDGE_BASE, TLS_VERSION_KNOWLEDGE

def parse_cipher(cipher_name: str, tls_version: str, key_bits: int) -> dict:
    result = {
        "cipher_name": cipher_name,
        "tls_version": tls_version,
        "key_bits": key_bits,
        "forward_secrecy": False,
        "quantum_vulnerable": True,
        "classical_vulnerable": False,
        "classical_strength": None,
        "pqc_tier": None,
        "tls_version_secure": False,
        "tls_version_tier": None,
        "key_exchange": None,
        "symmetric": None,
        "hash_algo": None,
        "known_cipher": False,
        "flags": [],
        "raw_components": {}
    }

    if cipher_name in CIPHER_KNOWLEDGE_BASE:
        kb = CIPHER_KNOWLEDGE_BASE[cipher_name]
        result["known_cipher"] = True
        result["forward_secrecy"] = kb.get("forward_secrecy", False)
        result["quantum_vulnerable"] = kb.get("quantum_vulnerable", True)
        result["classical_vulnerable"] = kb.get("classical_vulnerable", False)
        result["classical_strength"] = kb.get("classical_strength")
        result["pqc_tier"] = kb.get("pqc_tier")
        result["key_exchange"] = kb.get("key_exchange")
        result["symmetric"] = kb.get("symmetric")
        result["hash_algo"] = kb.get("hash")
    else:
        result["raw_components"] = _parse_cipher_string(cipher_name)
        result["forward_secrecy"] = cipher_name.startswith("ECDHE") or \
                                    cipher_name.startswith("DHE") or \
                                    "ECDHE" in cipher_name
        result["classical_vulnerable"] = any(w in cipher_name for w in [
            "DES", "RC4", "NULL", "EXPORT", "anon", "MD5"
        ])
        result["pqc_tier"] = _infer_pqc_tier(cipher_name, tls_version)

    if tls_version in TLS_VERSION_KNOWLEDGE:
        tv = TLS_VERSION_KNOWLEDGE[tls_version]
        result["tls_version_secure"] = tv.get("classical_secure", False)
        result["tls_version_tier"] = tv.get("pqc_tier")
    
    result["flags"] = _generate_flags(result, tls_version, key_bits)

    return result


def _parse_cipher_string(cipher_name: str) -> dict:
    components = {"raw": cipher_name}
    parts = cipher_name.split("_") if "_" in cipher_name else cipher_name.split("-")

    if "ECDHE" in parts or "ECDHE" in cipher_name:
        components["key_exchange"] = "ECDHE"
    elif "DHE" in parts or "DHE" in cipher_name:
        components["key_exchange"] = "DHE"
    elif "RSA" in parts:
        components["key_exchange"] = "RSA"
    elif "ECDH" in parts:
        components["key_exchange"] = "ECDH"

    if "AES256" in cipher_name or "AES_256" in cipher_name:
        components["symmetric"] = "AES-256"
    elif "AES128" in cipher_name or "AES_128" in cipher_name:
        components["symmetric"] = "AES-128"
    elif "3DES" in cipher_name:
        components["symmetric"] = "3DES"
    elif "DES" in cipher_name:
        components["symmetric"] = "DES"
    elif "RC4" in cipher_name:
        components["symmetric"] = "RC4"
    elif "CHACHA20" in cipher_name or "CHACHA" in cipher_name:
        components["symmetric"] = "ChaCha20"

    if "GCM" in cipher_name:
        components["mode"] = "GCM"
    elif "CBC" in cipher_name:
        components["mode"] = "CBC"
    elif "CCM" in cipher_name:
        components["mode"] = "CCM"

    if "SHA384" in cipher_name:
        components["hash"] = "SHA-384"
    elif "SHA256" in cipher_name:
        components["hash"] = "SHA-256"
    elif "SHA" in cipher_name:
        components["hash"] = "SHA-1"
    elif "MD5" in cipher_name:
        components["hash"] = "MD5"

    return components


def _infer_pqc_tier(cipher_name: str, tls_version: str) -> str:
    if tls_version in ["SSLv2", "SSLv3"]:
        return "Critical"
    if any(w in cipher_name for w in ["DES", "RC4", "NULL", "EXPORT", "MD5"]):
        return "Critical"
    if tls_version in ["TLSv1.0", "TLSv1.1"]:
        return "Tier-3"
    if "ECDHE" in cipher_name or "DHE" in cipher_name:
        if "AES_256" in cipher_name or "AES256" in cipher_name:
            return "Tier-2"
    return "Tier-3"


def _generate_flags(result: dict, tls_version: str, key_bits: int) -> list:
    flags = []

    if not result["forward_secrecy"]:
        flags.append("NO_FORWARD_SECRECY")
    if result["classical_vulnerable"]:
        flags.append("CLASSICALLY_VULNERABLE")
    if tls_version in ["TLSv1.0", "TLSv1.1"]:
        flags.append("DEPRECATED_TLS_VERSION")
    if tls_version in ["SSLv2", "SSLv3"]:
        flags.append("CRITICALLY_INSECURE_PROTOCOL")
    if key_bits and key_bits < 2048:
        flags.append("WEAK_KEY_SIZE")
    if key_bits and key_bits == 1024:
        flags.append("CRITICALLY_WEAK_KEY")
    if result["quantum_vulnerable"]:
        flags.append("QUANTUM_VULNERABLE")
    if not result["tls_version_secure"]:
        flags.append("INSECURE_TLS_VERSION")

    return flags