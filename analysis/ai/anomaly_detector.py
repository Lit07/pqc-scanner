import datetime
from typing import List

ANOMALY_RULES = [
    {
        "id": "AN001",
        "name": "Cipher downgrade detected",
        "check": lambda current, previous: (
            previous is not None and
            current.get("cipher_name") != previous.get("cipher_name") and
            _cipher_strength_score(current.get("cipher_name", "")) <
            _cipher_strength_score(previous.get("cipher_name", ""))
        ),
        "severity": "CRITICAL",
        "message": "Cipher suite has been downgraded since last scan"
    },
    {
        "id": "AN002",
        "name": "TLS version downgrade detected",
        "check": lambda current, previous: (
            previous is not None and
            _tls_rank(current.get("tls_version", "")) <
            _tls_rank(previous.get("tls_version", ""))
        ),
        "severity": "CRITICAL",
        "message": "TLS version has been downgraded since last scan"
    },
    {
        "id": "AN003",
        "name": "Key size reduction detected",
        "check": lambda current, previous: (
            previous is not None and
            current.get("key_size") is not None and
            previous.get("key_size") is not None and
            current.get("key_size") < previous.get("key_size")
        ),
        "severity": "HIGH",
        "message": "Certificate key size has been reduced since last scan"
    },
    {
        "id": "AN004",
        "name": "Forward secrecy lost",
        "check": lambda current, previous: (
            previous is not None and
            previous.get("forward_secrecy") is True and
            current.get("forward_secrecy") is False
        ),
        "severity": "CRITICAL",
        "message": "Forward secrecy was present in last scan but is now missing"
    },
    {
        "id": "AN005",
        "name": "Certificate issuer changed",
        "check": lambda current, previous: (
            previous is not None and
            current.get("issuer_cn") != previous.get("issuer_cn") and
            previous.get("issuer_cn") is not None
        ),
        "severity": "HIGH",
        "message": "Certificate authority has changed since last scan"
    },
    {
        "id": "AN006",
        "name": "Self signed cert appeared",
        "check": lambda current, previous: (
            previous is not None and
            current.get("is_self_signed") is True and
            previous.get("is_self_signed") is False
        ),
        "severity": "CRITICAL",
        "message": "Certificate changed to self-signed since last scan"
    },
    {
        "id": "AN007",
        "name": "New SAN domains appeared",
        "check": lambda current, previous: (
            previous is not None and
            len(set(current.get("san_domains", [])) -
                set(previous.get("san_domains", []))) > 0
        ),
        "severity": "MEDIUM",
        "message": "New domains appeared in certificate SAN since last scan"
    },
    {
        "id": "AN008",
        "name": "Score dropped significantly",
        "check": lambda current, previous: (
            previous is not None and
            current.get("final_score") is not None and
            previous.get("final_score") is not None and
            (previous.get("final_score") - current.get("final_score")) >= 100
        ),
        "severity": "HIGH",
        "message": "Security score dropped by 100 or more points since last scan"
    },
    {
        "id": "AN009",
        "name": "IP address changed",
        "check": lambda current, previous: (
            previous is not None and
            current.get("ip") != previous.get("ip") and
            previous.get("ip") is not None
        ),
        "severity": "MEDIUM",
        "message": "Asset IP address has changed since last scan"
    },
    {
        "id": "AN010",
        "name": "Port changed",
        "check": lambda current, previous: (
            previous is not None and
            current.get("port") != previous.get("port") and
            previous.get("port") is not None
        ),
        "severity": "MEDIUM",
        "message": "Service port has changed since last scan"
    }
]


def detect_anomalies(
    current_scan: dict,
    previous_scan: dict = None,
    scan_history: list = None
) -> dict:
    result = {
        "hostname": current_scan.get("hostname"),
        "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "anomalies": [],
        "anomaly_count": 0,
        "critical_anomalies": 0,
        "has_regression": False,
        "regression_details": [],
        "trend": None,
        "first_seen": None,
        "scan_count": len(scan_history) if scan_history else 1
    }

    for rule in ANOMALY_RULES:
        try:
            if rule["check"](current_scan, previous_scan):
                anomaly = {
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "message": rule["message"],
                    "detected_at": result["detected_at"]
                }
                result["anomalies"].append(anomaly)
                if rule["severity"] == "CRITICAL":
                    result["critical_anomalies"] += 1
                    result["has_regression"] = True
                    result["regression_details"].append(rule["message"])
        except Exception:
            continue

    result["anomaly_count"] = len(result["anomalies"])
    result["trend"] = _calculate_trend(current_scan, scan_history)

    if scan_history:
        result["first_seen"] = scan_history[0].get("scanned_at") \
            if scan_history else current_scan.get("scanned_at")

    return result


def _cipher_strength_score(cipher_name: str) -> int:
    if not cipher_name:
        return 0
    if "AES_256" in cipher_name or "AES256" in cipher_name:
        if "GCM" in cipher_name:
            return 90
        return 70
    if "AES_128" in cipher_name or "AES128" in cipher_name:
        return 60
    if "CHACHA20" in cipher_name:
        return 85
    if "3DES" in cipher_name:
        return 20
    if "DES" in cipher_name:
        return 5
    if "RC4" in cipher_name:
        return 5
    if "NULL" in cipher_name:
        return 0
    return 40


def _tls_rank(tls_version: str) -> int:
    ranks = {
        "TLSv1.3": 5,
        "TLSv1.2": 4,
        "TLSv1.1": 3,
        "TLSv1.0": 2,
        "SSLv3": 1,
        "SSLv2": 0
    }
    return ranks.get(tls_version, 0)


def _calculate_trend(current_scan: dict, scan_history: list) -> str:
    if not scan_history or len(scan_history) < 2:
        return "INSUFFICIENT_DATA"

    scores = [s.get("final_score", 0) for s in scan_history[-5:]]
    scores.append(current_scan.get("final_score", 0))

    if len(scores) < 2:
        return "INSUFFICIENT_DATA"

    avg_recent = sum(scores[-3:]) / len(scores[-3:])
    avg_older = sum(scores[:-3]) / len(scores[:-3]) if len(scores) > 3 else scores[0]

    if avg_recent > avg_older + 50:
        return "IMPROVING"
    elif avg_recent < avg_older - 50:
        return "DEGRADING"
    return "STABLE"