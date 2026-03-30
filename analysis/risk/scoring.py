from analysis.risk.rules import evaluate_rules

BASE_SCORE = 1000

SEVERITY_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.5,
    "LOW": 0.25
}

CATEGORY_MULTIPLIERS = {
    "protocol": 1.2,
    "cipher": 1.15,
    "key_strength": 1.1,
    "certificate": 1.0,
    "pqc": 1.25
}

PQC_TIER_THRESHOLDS = {
    "Elite": (701, 1000),
    "Standard": (400, 700),
    "Legacy": (200, 399),
    "Critical": (0, 199)
}


def calculate_score(scan_data: dict) -> dict:
    result = {
        "base_score": BASE_SCORE,
        "final_score": BASE_SCORE,
        "penalty_total": 0,
        "pqc_tier": None,
        "tier_label": None,
        "triggered_rules": [],
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "pqc_impact_count": 0,
        "score_breakdown": []
    }

    triggered = evaluate_rules(scan_data)
    result["triggered_rules"] = triggered

    for rule in triggered:
        severity = rule["severity"]
        category = rule["category"]
        base_penalty = rule["score_penalty"]

        severity_weight = SEVERITY_WEIGHTS.get(severity, 1.0)
        category_multiplier = CATEGORY_MULTIPLIERS.get(category, 1.0)

        adjusted_penalty = base_penalty * severity_weight * category_multiplier

        result["score_breakdown"].append({
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": severity,
            "category": category,
            "base_penalty": base_penalty,
            "adjusted_penalty": round(adjusted_penalty, 2)
        })

        result["penalty_total"] += adjusted_penalty

        if severity == "CRITICAL":
            result["critical_count"] += 1
        elif severity == "HIGH":
            result["high_count"] += 1
        elif severity == "MEDIUM":
            result["medium_count"] += 1
        elif severity == "LOW":
            result["low_count"] += 1

        if rule.get("pqc_impact"):
            result["pqc_impact_count"] += 1

    raw_score = BASE_SCORE - result["penalty_total"]
    result["final_score"] = max(0, min(1000, round(raw_score)))
    result["penalty_total"] = round(result["penalty_total"], 2)
    result["pqc_tier"], result["tier_label"] = _determine_tier(result["final_score"])

    return result


def _determine_tier(score: int) -> tuple:
    for tier, (low, high) in PQC_TIER_THRESHOLDS.items():
        if low <= score <= high:
            return tier, _get_tier_label(tier)
    return "Critical", "Insecure / Exploitable"


def _get_tier_label(tier: str) -> str:
    labels = {
        "Elite": "Modern best-practice crypto posture",
        "Standard": "Acceptable enterprise configuration",
        "Legacy": "Weak but still operational",
        "Critical": "Insecure / Exploitable"
    }
    return labels.get(tier, "Unknown")


def calculate_enterprise_score(asset_scores: list) -> dict:
    if not asset_scores:
        return {
            "enterprise_score": 0,
            "pqc_tier": "Critical",
            "tier_label": "Insecure / Exploitable",
            "total_assets": 0,
            "elite_count": 0,
            "standard_count": 0,
            "legacy_count": 0,
            "critical_count": 0,
            "average_score": 0
        }

    total = sum(a["final_score"] for a in asset_scores)
    average = total / len(asset_scores)

    tier_counts = {"Elite": 0, "Standard": 0, "Legacy": 0, "Critical": 0}
    for asset in asset_scores:
        t = asset.get("pqc_tier", "Critical")
        if t in tier_counts:
            tier_counts[t] += 1

    weights = {"Elite": 1.0, "Standard": 0.75, "Legacy": 0.5, "Critical": 0.25}
    weighted_sum = sum(
        a["final_score"] * weights.get(a.get("pqc_tier", "Critical"), 0.25)
        for a in asset_scores
    )
    weighted_avg = weighted_sum / len(asset_scores)
    enterprise_score = round(min(1000, weighted_avg))

    tier, label = _determine_tier(enterprise_score)

    return {
        "enterprise_score": enterprise_score,
        "pqc_tier": tier,
        "tier_label": label,
        "total_assets": len(asset_scores),
        "elite_count": tier_counts["Elite"],
        "standard_count": tier_counts["Standard"],
        "legacy_count": tier_counts["Legacy"],
        "critical_count": tier_counts["Critical"],
        "average_score": round(average, 2)
    }