import datetime

CIPHER_STRENGTH_RANKS = {
    "TLS_AES_256_GCM_SHA384":          10,
    "TLS_AES_128_GCM_SHA256":          8,
    "TLS_CHACHA20_POLY1305_SHA256":    9,
    "ECDHE-RSA-AES256-GCM-SHA384":    7,
    "ECDHE-RSA-AES128-GCM-SHA256":    6,
    "ECDHE-ECDSA-AES256-GCM-SHA384":  7,
    "ECDHE-RSA-AES256-SHA384":        5,
    "ECDHE-RSA-AES128-SHA256":        4,
    "AES256-GCM-SHA384":              5,
    "AES128-GCM-SHA256":              4,
    "AES256-SHA256":                  3,
    "AES128-SHA256":                  2,
    "AES256-SHA":                     2,
    "AES128-SHA":                     1,
    "DES-CBC3-SHA":                   -5,
    "RC4-SHA":                        -10,
    "RC4-MD5":                        -10,
    "NULL-SHA":                       -20,
    "EXP-RC4-MD5":                    -20,
}

TLS_VERSION_RANKS = {
    "TLSv1.3": 5,
    "TLSv1.2": 4,
    "TLSv1.1": 2,
    "TLSv1.0": 1,
    "SSLv3":   -5,
    "SSLv2":   -10
}


def detect_cipher_regression(
    current_scan: dict,
    historical_scans: list
) -> dict:
    result = {
        "hostname": current_scan.get("hostname"),
        "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "regression_detected": False,
        "regression_type": [],
        "severity": None,
        "cipher_regression": None,
        "tls_regression": None,
        "key_size_regression": None,
        "forward_secrecy_regression": None,
        "historical_comparison": [],
        "regression_timeline": [],
        "recommendations": []
    }

    if not historical_scans:
        result["severity"] = "NO_HISTORY"
        return result

    last_scan = historical_scans[-1]

    cipher_reg = _check_cipher_regression(current_scan, last_scan)
    if cipher_reg:
        result["regression_detected"] = True
        result["cipher_regression"] = cipher_reg
        result["regression_type"].append("CIPHER_DOWNGRADE")

    tls_reg = _check_tls_regression(current_scan, last_scan)
    if tls_reg:
        result["regression_detected"] = True
        result["tls_regression"] = tls_reg
        result["regression_type"].append("TLS_DOWNGRADE")

    key_reg = _check_key_size_regression(current_scan, last_scan)
    if key_reg:
        result["regression_detected"] = True
        result["key_size_regression"] = key_reg
        result["regression_type"].append("KEY_SIZE_REDUCTION")

    fs_reg = _check_forward_secrecy_regression(current_scan, last_scan)
    if fs_reg:
        result["regression_detected"] = True
        result["forward_secrecy_regression"] = fs_reg
        result["regression_type"].append("FORWARD_SECRECY_LOST")

    result["severity"] = _determine_regression_severity(result["regression_type"])
    result["historical_comparison"] = _build_historical_comparison(
        current_scan, historical_scans
    )
    result["regression_timeline"] = _build_regression_timeline(
        current_scan, historical_scans
    )

    if result["regression_detected"]:
        result["recommendations"] = _build_regression_recommendations(
            result["regression_type"]
        )

    return result


def _check_cipher_regression(current: dict, previous: dict) -> dict:
    current_cipher = current.get("cipher_name", "")
    previous_cipher = previous.get("cipher_name", "")

    if not current_cipher or not previous_cipher:
        return None
    if current_cipher == previous_cipher:
        return None

    current_rank = CIPHER_STRENGTH_RANKS.get(current_cipher, 3)
    previous_rank = CIPHER_STRENGTH_RANKS.get(previous_cipher, 3)

    if current_rank < previous_rank:
        return {
            "previous_cipher": previous_cipher,
            "current_cipher": current_cipher,
            "previous_rank": previous_rank,
            "current_rank": current_rank,
            "rank_drop": previous_rank - current_rank,
            "message": f"Cipher downgraded from {previous_cipher} to {current_cipher}"
        }
    return None


def _check_tls_regression(current: dict, previous: dict) -> dict:
    current_tls = current.get("tls_version", "")
    previous_tls = previous.get("tls_version", "")

    if not current_tls or not previous_tls:
        return None
    if current_tls == previous_tls:
        return None

    current_rank = TLS_VERSION_RANKS.get(current_tls, 0)
    previous_rank = TLS_VERSION_RANKS.get(previous_tls, 0)

    if current_rank < previous_rank:
        return {
            "previous_tls": previous_tls,
            "current_tls": current_tls,
            "previous_rank": previous_rank,
            "current_rank": current_rank,
            "message": f"TLS downgraded from {previous_tls} to {current_tls}"
        }
    return None


def _check_key_size_regression(current: dict, previous: dict) -> dict:
    current_size = current.get("key_size") or 0
    previous_size = previous.get("key_size") or 0

    if not current_size or not previous_size:
        return None
    if current_size >= previous_size:
        return None

    return {
        "previous_size": previous_size,
        "current_size": current_size,
        "reduction": previous_size - current_size,
        "message": f"Key size reduced from {previous_size} to {current_size} bits"
    }


def _check_forward_secrecy_regression(current: dict, previous: dict) -> dict:
    if previous.get("forward_secrecy") is True and \
       current.get("forward_secrecy") is False:
        return {
            "message": "Forward secrecy was present but is now disabled",
            "hndl_impact": "All future and past sessions now at risk"
        }
    return None


def _determine_regression_severity(regression_types: list) -> str:
    if not regression_types:
        return "NONE"
    if "FORWARD_SECRECY_LOST" in regression_types or \
       "TLS_DOWNGRADE" in regression_types:
        return "CRITICAL"
    if "CIPHER_DOWNGRADE" in regression_types:
        return "HIGH"
    if "KEY_SIZE_REDUCTION" in regression_types:
        return "HIGH"
    return "MEDIUM"


def _build_historical_comparison(
    current: dict,
    historical: list
) -> list:
    comparison = []
    for scan in historical[-5:]:
        comparison.append({
            "scanned_at": scan.get("scanned_at"),
            "cipher_name": scan.get("cipher_name"),
            "tls_version": scan.get("tls_version"),
            "key_size": scan.get("key_size"),
            "forward_secrecy": scan.get("forward_secrecy"),
            "final_score": scan.get("final_score")
        })
    comparison.append({
        "scanned_at": current.get("scanned_at", "current"),
        "cipher_name": current.get("cipher_name"),
        "tls_version": current.get("tls_version"),
        "key_size": current.get("key_size"),
        "forward_secrecy": current.get("forward_secrecy"),
        "final_score": current.get("final_score"),
        "is_current": True
    })
    return comparison


def _build_regression_timeline(
    current: dict,
    historical: list
) -> list:
    events = []
    for i, scan in enumerate(historical):
        if i == 0:
            continue
        prev = historical[i - 1]
        prev_rank = TLS_VERSION_RANKS.get(prev.get("tls_version", ""), 0)
        curr_rank = TLS_VERSION_RANKS.get(scan.get("tls_version", ""), 0)
        if curr_rank < prev_rank:
            events.append({
                "date": scan.get("scanned_at"),
                "event": f"TLS downgrade detected: {prev.get('tls_version')} → {scan.get('tls_version')}",
                "severity": "CRITICAL"
            })
        prev_cipher_rank = CIPHER_STRENGTH_RANKS.get(prev.get("cipher_name", ""), 3)
        curr_cipher_rank = CIPHER_STRENGTH_RANKS.get(scan.get("cipher_name", ""), 3)
        if curr_cipher_rank < prev_cipher_rank:
            events.append({
                "date": scan.get("scanned_at"),
                "event": f"Cipher downgrade: {prev.get('cipher_name')} → {scan.get('cipher_name')}",
                "severity": "HIGH"
            })
    return events


def _build_regression_recommendations(regression_types: list) -> list:
    recs = []
    if "FORWARD_SECRECY_LOST" in regression_types:
        recs.append({
            "priority": 1,
            "action": "Re-enable ECDHE cipher suites immediately",
            "reason": "Forward secrecy regression is a critical security incident"
        })
    if "TLS_DOWNGRADE" in regression_types:
        recs.append({
            "priority": 2,
            "action": "Investigate TLS configuration change and revert",
            "reason": "TLS downgrade may indicate misconfiguration or compromise"
        })
    if "CIPHER_DOWNGRADE" in regression_types:
        recs.append({
            "priority": 3,
            "action": "Review cipher suite configuration and restore strong ciphers",
            "reason": "Cipher regression weakens security posture"
        })
    if "KEY_SIZE_REDUCTION" in regression_types:
        recs.append({
            "priority": 4,
            "action": "Replace certificate with stronger key size",
            "reason": "Key size reduction reduces classical and quantum security"
        })
    return recs