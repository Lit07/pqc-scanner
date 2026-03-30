import datetime
from typing import List

HEATMAP_RISK_MATRIX = {
    ("CRITICAL", "IMMEDIATE"): {"color": "#FF0000", "intensity": 1.0, "label": "Maximum Risk"},
    ("CRITICAL", "HIGH"):      {"color": "#FF2200", "intensity": 0.9, "label": "Critical Risk"},
    ("CRITICAL", "MEDIUM"):    {"color": "#FF4400", "intensity": 0.8, "label": "Severe Risk"},
    ("HIGH", "IMMEDIATE"):     {"color": "#FF6600", "intensity": 0.75, "label": "High Risk"},
    ("HIGH", "HIGH"):          {"color": "#FF8800", "intensity": 0.65, "label": "Elevated Risk"},
    ("HIGH", "MEDIUM"):        {"color": "#FFAA00", "intensity": 0.55, "label": "Moderate-High Risk"},
    ("MEDIUM", "HIGH"):        {"color": "#FFCC00", "intensity": 0.45, "label": "Moderate Risk"},
    ("MEDIUM", "MEDIUM"):      {"color": "#FFDD00", "intensity": 0.35, "label": "Low-Moderate Risk"},
    ("MEDIUM", "LOW"):         {"color": "#FFEE00", "intensity": 0.25, "label": "Low Risk"},
    ("LOW", "LOW"):            {"color": "#00CC44", "intensity": 0.1,  "label": "Minimal Risk"},
}

ALGORITHM_POSITIONS = {
    "RSA":     {"x": 0.9, "y": 0.9, "quadrant": "critical"},
    "EC":      {"x": 0.85, "y": 0.8, "quadrant": "critical"},
    "DSA":     {"x": 0.95, "y": 0.95, "quadrant": "critical"},
    "Ed25519": {"x": 0.6, "y": 0.55, "quadrant": "high"},
    "Ed448":   {"x": 0.55, "y": 0.5, "quadrant": "high"},
    "AES256":  {"x": 0.2, "y": 0.3, "quadrant": "low"},
    "AES128":  {"x": 0.4, "y": 0.45, "quadrant": "medium"},
    "UNKNOWN": {"x": 0.5, "y": 0.5, "quadrant": "medium"},
}

QUADRANT_DEFINITIONS = {
    "critical": {
        "label": "Quantum Critical",
        "description": "Broken by Shor's algorithm. Immediate migration required.",
        "x_range": (0.7, 1.0),
        "y_range": (0.7, 1.0),
        "color": "#FF0000"
    },
    "high": {
        "label": "Quantum High Risk",
        "description": "Significant quantum vulnerability. Migration planning required.",
        "x_range": (0.4, 0.7),
        "y_range": (0.4, 0.7),
        "color": "#FF8800"
    },
    "medium": {
        "label": "Quantum Medium Risk",
        "description": "Partial quantum vulnerability. Monitor and plan.",
        "x_range": (0.2, 0.4),
        "y_range": (0.2, 0.4),
        "color": "#FFCC00"
    },
    "low": {
        "label": "Quantum Low Risk",
        "description": "Limited quantum vulnerability. Standard monitoring.",
        "x_range": (0.0, 0.2),
        "y_range": (0.0, 0.2),
        "color": "#00CC44"
    }
}


def generate_asset_heatmap_point(scan_data: dict, pqc_classification: dict) -> dict:
    key_type = scan_data.get("key_type", "UNKNOWN")
    tls_version = scan_data.get("tls_version", "")
    forward_secrecy = scan_data.get("forward_secrecy", False)
    pqc_score = pqc_classification.get("pqc_score", 50)
    classification = pqc_classification.get("pqc_classification", "Legacy")
    immediate_actions = pqc_classification.get("immediate_actions", [])
    harvest_rules = pqc_classification.get("harvest_risk_rules", [])

    position = ALGORITHM_POSITIONS.get(key_type, ALGORITHM_POSITIONS["UNKNOWN"])

    x = _calculate_x_position(scan_data, position["x"])
    y = _calculate_y_position(pqc_score, forward_secrecy, harvest_rules)

    urgency = "IMMEDIATE" if immediate_actions else \
              "HIGH" if harvest_rules else \
              "MEDIUM" if classification in ["Legacy", "Critical"] else "LOW"

    tier_impact = "CRITICAL" if classification == "Critical" else \
                  "HIGH" if classification == "Legacy" else \
                  "MEDIUM" if classification == "Standard" else "LOW"

    risk_key = (tier_impact, urgency)
    risk_data = HEATMAP_RISK_MATRIX.get(
        risk_key,
        {"color": "#FFAA00", "intensity": 0.5, "label": "Moderate Risk"}
    )

    quadrant = _determine_quadrant(x, y)

    return {
        "hostname": scan_data.get("hostname"),
        "ip": scan_data.get("ip"),
        "x": round(x, 3),
        "y": round(y, 3),
        "quadrant": quadrant,
        "quadrant_info": QUADRANT_DEFINITIONS.get(quadrant, {}),
        "color": risk_data["color"],
        "intensity": risk_data["intensity"],
        "risk_label": risk_data["label"],
        "key_type": key_type,
        "pqc_score": pqc_score,
        "pqc_classification": classification,
        "tls_version": tls_version,
        "forward_secrecy": forward_secrecy,
        "immediate_action_count": len(immediate_actions),
        "harvest_risk_count": len(harvest_rules),
        "tooltip": _build_tooltip(scan_data, pqc_classification, risk_data)
    }


def generate_enterprise_heatmap(asset_points: list) -> dict:
    if not asset_points:
        return {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_assets": 0,
            "quadrant_summary": {},
            "risk_distribution": {},
            "hotspots": [],
            "safezones": [],
            "overall_heat_index": 0,
            "points": []
        }

    quadrant_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    risk_distribution = {}

    for point in asset_points:
        q = point.get("quadrant", "medium")
        if q in quadrant_summary:
            quadrant_summary[q] += 1

        label = point.get("risk_label", "Unknown")
        risk_distribution[label] = risk_distribution.get(label, 0) + 1

    hotspots = sorted(
        [p for p in asset_points if p.get("quadrant") == "critical"],
        key=lambda p: p.get("intensity", 0),
        reverse=True
    )[:5]

    safezones = sorted(
        [p for p in asset_points if p.get("quadrant") == "low"],
        key=lambda p: p.get("pqc_score", 0),
        reverse=True
    )[:5]

    total_intensity = sum(p.get("intensity", 0) for p in asset_points)
    overall_heat_index = round(
        (total_intensity / len(asset_points)) * 100, 2
    ) if asset_points else 0

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_assets": len(asset_points),
        "quadrant_summary": quadrant_summary,
        "risk_distribution": risk_distribution,
        "hotspots": hotspots,
        "safezones": safezones,
        "overall_heat_index": overall_heat_index,
        "points": asset_points,
        "quadrant_definitions": QUADRANT_DEFINITIONS
    }


def _calculate_x_position(scan_data: dict, base_x: float) -> float:
    x = base_x

    tls = scan_data.get("tls_version", "")
    if tls == "TLSv1.3":
        x -= 0.05
    elif tls in ["TLSv1.0", "TLSv1.1"]:
        x += 0.05
    elif tls in ["SSLv2", "SSLv3"]:
        x += 0.1

    key_size = scan_data.get("key_size", 0) or 0
    key_type = scan_data.get("key_type", "")
    if key_type == "RSA":
        if key_size >= 4096:
            x -= 0.05
        elif key_size < 2048:
            x += 0.05

    return max(0.0, min(1.0, x))


def _calculate_y_position(
    pqc_score: int,
    forward_secrecy: bool,
    harvest_rules: list
) -> float:
    y = 1.0 - (pqc_score / 100)

    if not forward_secrecy:
        y += 0.1
    if harvest_rules:
        y += 0.05 * min(len(harvest_rules), 3)

    return max(0.0, min(1.0, y))


def _determine_quadrant(x: float, y: float) -> str:
    avg = (x + y) / 2
    if avg >= 0.7:
        return "critical"
    elif avg >= 0.4:
        return "high"
    elif avg >= 0.2:
        return "medium"
    return "low"


def _build_tooltip(scan_data: dict, pqc_classification: dict, risk_data: dict) -> str:
    hostname = scan_data.get("hostname", "Unknown")
    key_type = scan_data.get("key_type", "Unknown")
    key_size = scan_data.get("key_size", "Unknown")
    tls = scan_data.get("tls_version", "Unknown")
    score = pqc_classification.get("pqc_score", 0)
    classification = pqc_classification.get("pqc_classification", "Unknown")
    risk_label = risk_data.get("label", "Unknown")

    return (
        f"{hostname} | "
        f"{key_type}-{key_size} | "
        f"{tls} | "
        f"PQC Score: {score} | "
        f"{classification} | "
        f"{risk_label}"
    )