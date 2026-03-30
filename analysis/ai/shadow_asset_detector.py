import re
import dns.resolver
from scanner.tls_scanner import scan_tls

SHADOW_PATTERNS = [
    r"^dev\.", r"^test\.", r"^staging\.", r"^uat\.", r"^qa\.",
    r"^sandbox\.", r"^old\.", r"^legacy\.", r"^backup\.",
    r"^admin\.", r"^internal\.", r"^private\.", r"^corp\.",
    r"^api\.", r"^api2\.", r"^api-", r"^v2\.", r"^v3\.",
    r"^postman\.", r"^swagger\.", r"^docs\.",
    r"^upload\.", r"^uploads\.", r"^files\.",
    r"^mail\.", r"^smtp\.", r"^mx\.",
    r"^vpn\.", r"^remote\.", r"^access\.",
    r"^monitor\.", r"^status\.", r"^health\.",
    r"^cdn\.", r"^static\.", r"^assets\.",
    r"^proxy\.", r"^gateway\.",
    r"^jenkins\.", r"^gitlab\.", r"^github\.",
    r"^kibana\.", r"^grafana\.", r"^prometheus\."
]

SHADOW_RISK_LEVELS = {
    "dev": "HIGH", "test": "HIGH", "staging": "HIGH",
    "uat": "HIGH", "qa": "HIGH", "sandbox": "HIGH",
    "admin": "CRITICAL", "internal": "CRITICAL",
    "postman": "CRITICAL", "swagger": "CRITICAL",
    "jenkins": "CRITICAL", "gitlab": "HIGH",
    "vpn": "CRITICAL", "proxy": "HIGH",
    "upload": "HIGH", "backup": "CRITICAL",
    "old": "HIGH", "legacy": "HIGH"
}


def detect_shadow_assets(
    primary_hostname: str,
    san_domains: list = None,
    probe_subdomains: bool = False
) -> dict:
    result = {
        "primary_hostname": primary_hostname,
        "base_domain": _extract_base_domain(primary_hostname),
        "shadow_assets_found": [],
        "san_discovered": [],
        "total_shadow_count": 0,
        "critical_shadows": [],
        "risk_summary": {}
    }

    if san_domains:
        for domain in san_domains:
            if domain != primary_hostname and not domain.startswith("*."):
                shadow_info = _classify_shadow_asset(domain)
                if shadow_info:
                    result["san_discovered"].append(shadow_info)
                    result["shadow_assets_found"].append(shadow_info)

    if probe_subdomains:
        base = result["base_domain"]
        common_prefixes = [
            "api", "admin", "dev", "test", "staging", "uat",
            "upload", "postman", "vpn", "mail", "portal",
            "internal", "backup", "old", "legacy", "proxy"
        ]
        for prefix in common_prefixes:
            candidate = f"{prefix}.{base}"
            if _domain_resolves(candidate):
                shadow_info = _classify_shadow_asset(candidate)
                if shadow_info:
                    result["shadow_assets_found"].append(shadow_info)

    result["critical_shadows"] = [
        s for s in result["shadow_assets_found"]
        if s.get("risk_level") == "CRITICAL"
    ]
    result["total_shadow_count"] = len(result["shadow_assets_found"])
    result["risk_summary"] = _build_risk_summary(result["shadow_assets_found"])

    return result


def _extract_base_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _classify_shadow_asset(domain: str) -> dict:
    prefix = domain.split(".")[0].lower()
    risk_level = "MEDIUM"

    for key, level in SHADOW_RISK_LEVELS.items():
        if key in prefix:
            risk_level = level
            break

    is_shadow = any(
        re.match(pattern, domain, re.IGNORECASE)
        for pattern in SHADOW_PATTERNS
    )

    if not is_shadow and risk_level == "MEDIUM":
        return None

    flags = []
    if any(x in prefix for x in ["dev", "test", "staging", "uat", "qa"]):
        flags.append("NON_PRODUCTION_PUBLICLY_EXPOSED")
    if any(x in prefix for x in ["admin", "internal", "private"]):
        flags.append("INTERNAL_SYSTEM_EXPOSED")
    if any(x in prefix for x in ["postman", "swagger", "docs", "api-doc"]):
        flags.append("API_TOOLING_EXPOSED")
    if any(x in prefix for x in ["jenkins", "gitlab", "github"]):
        flags.append("DEVOPS_TOOLING_EXPOSED")
    if any(x in prefix for x in ["backup", "old", "legacy"]):
        flags.append("LEGACY_SYSTEM_EXPOSED")
    if any(x in prefix for x in ["vpn", "remote", "access"]):
        flags.append("NETWORK_ACCESS_EXPOSED")

    return {
        "domain": domain,
        "prefix": prefix,
        "risk_level": risk_level,
        "flags": flags,
        "discovery_method": "SAN" if "." in domain else "PROBE",
        "recommended_action": _get_recommendation(risk_level, flags)
    }


def _domain_resolves(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except Exception:
        return False


def _get_recommendation(risk_level: str, flags: list) -> str:
    if "NON_PRODUCTION_PUBLICLY_EXPOSED" in flags:
        return "Restrict access to non-production environment immediately"
    if "INTERNAL_SYSTEM_EXPOSED" in flags:
        return "Move behind VPN or firewall — internal system should not be public"
    if "API_TOOLING_EXPOSED" in flags:
        return "Remove API documentation from public access — exposes attack surface"
    if "DEVOPS_TOOLING_EXPOSED" in flags:
        return "DevOps tooling must not be publicly accessible"
    if "LEGACY_SYSTEM_EXPOSED" in flags:
        return "Decommission or isolate legacy system immediately"
    if risk_level == "CRITICAL":
        return "Immediate investigation required"
    return "Review if public exposure is intentional"


def _build_risk_summary(shadow_assets: list) -> dict:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for asset in shadow_assets:
        level = asset.get("risk_level", "MEDIUM")
        if level in summary:
            summary[level] += 1
    return summary