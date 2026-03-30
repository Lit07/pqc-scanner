import re

ENDPOINT_PATTERNS = {
    "financial": {
        "patterns": [
            r"(bank|payment|pay|finance|trading|invest|wallet|checkout|billing)",
            r"(stripe|paypal|braintree|adyen|square)",
            r"(treasury|ledger|accounting|invoice)"
        ],
        "sensitivity": "CRITICAL",
        "sensitivity_score": 95,
        "data_classification": "Financial / PCI",
        "regulatory_scope": ["PCI-DSS", "SOX", "GLBA"],
        "hndl_multiplier": 1.5,
        "attack_surface": "HIGH",
        "exposure_level": "PUBLIC"
    },
    "healthcare": {
        "patterns": [
            r"(health|medical|patient|clinic|hospital|pharmacy|hipaa)",
            r"(ehr|emr|dicom|hl7|fhir)",
            r"(doctor|nurse|diagnosis|prescription)"
        ],
        "sensitivity": "CRITICAL",
        "sensitivity_score": 95,
        "data_classification": "Protected Health Information",
        "regulatory_scope": ["HIPAA", "HITECH"],
        "hndl_multiplier": 1.5,
        "attack_surface": "HIGH",
        "exposure_level": "PUBLIC"
    },
    "government": {
        "patterns": [
            r"\.gov(\.[a-z]{2})?$",
            r"\.mil$",
            r"(government|federal|agency|census|irs|dod)"
        ],
        "sensitivity": "CRITICAL",
        "sensitivity_score": 100,
        "data_classification": "Government / Classified",
        "regulatory_scope": ["FISMA", "FedRAMP", "CMMC", "NIST-800-171"],
        "hndl_multiplier": 2.0,
        "attack_surface": "CRITICAL",
        "exposure_level": "PUBLIC"
    },
    "authentication": {
        "patterns": [
            r"(auth|login|sso|oauth|identity|idp|saml|oidc)",
            r"(signup|register|account|session|token)",
            r"(keycloak|okta|auth0|cognito)"
        ],
        "sensitivity": "HIGH",
        "sensitivity_score": 85,
        "data_classification": "Authentication Credentials",
        "regulatory_scope": ["SOC2", "ISO-27001"],
        "hndl_multiplier": 1.4,
        "attack_surface": "HIGH",
        "exposure_level": "PUBLIC"
    },
    "api": {
        "patterns": [
            r"^api\.",
            r"^api-",
            r"(graphql|rest|grpc|websocket)",
            r"(gateway|proxy|edge)"
        ],
        "sensitivity": "HIGH",
        "sensitivity_score": 75,
        "data_classification": "API / Service Data",
        "regulatory_scope": ["SOC2"],
        "hndl_multiplier": 1.3,
        "attack_surface": "HIGH",
        "exposure_level": "PUBLIC"
    },
    "email": {
        "patterns": [
            r"(mail|smtp|imap|pop3|exchange|mx)",
            r"(postfix|sendgrid|mailgun|ses)"
        ],
        "sensitivity": "HIGH",
        "sensitivity_score": 80,
        "data_classification": "Email Communications",
        "regulatory_scope": ["GDPR", "SOC2"],
        "hndl_multiplier": 1.4,
        "attack_surface": "MEDIUM",
        "exposure_level": "PUBLIC"
    },
    "database": {
        "patterns": [
            r"(db|database|sql|mysql|postgres|mongo|redis|elastic)",
            r"(dynamo|cassandra|cockroach|supabase)"
        ],
        "sensitivity": "CRITICAL",
        "sensitivity_score": 90,
        "data_classification": "Database / Persistent Storage",
        "regulatory_scope": ["SOC2", "GDPR"],
        "hndl_multiplier": 1.5,
        "attack_surface": "CRITICAL",
        "exposure_level": "INTERNAL"
    },
    "cdn": {
        "patterns": [
            r"(cdn|static|assets|media|images|cache)",
            r"(cloudfront|akamai|fastly|cloudflare)"
        ],
        "sensitivity": "LOW",
        "sensitivity_score": 25,
        "data_classification": "Static Content",
        "regulatory_scope": [],
        "hndl_multiplier": 0.8,
        "attack_surface": "LOW",
        "exposure_level": "PUBLIC"
    },
    "ecommerce": {
        "patterns": [
            r"(shop|store|cart|product|catalog|order|merchant)",
            r"(shopify|woocommerce|magento|bigcommerce)"
        ],
        "sensitivity": "HIGH",
        "sensitivity_score": 80,
        "data_classification": "Customer / Transaction Data",
        "regulatory_scope": ["PCI-DSS", "GDPR", "CCPA"],
        "hndl_multiplier": 1.4,
        "attack_surface": "HIGH",
        "exposure_level": "PUBLIC"
    },
    "generic": {
        "patterns": [],
        "sensitivity": "MEDIUM",
        "sensitivity_score": 50,
        "data_classification": "General Purpose",
        "regulatory_scope": ["SOC2"],
        "hndl_multiplier": 1.0,
        "attack_surface": "MEDIUM",
        "exposure_level": "PUBLIC"
    }
}


def classify_endpoint(
    hostname: str,
    scan_data: dict = None,
    san_domains: list = None
) -> dict:
    result = {
        "hostname": hostname,
        "endpoint_type": None,
        "sensitivity": None,
        "sensitivity_score": None,
        "data_classification": None,
        "regulatory_scope": [],
        "hndl_multiplier": 1.0,
        "adjusted_priority": 0,
        "confidence": None,
        "ai_flags": [],
        "attack_surface": None,
        "exposure_level": None,
        "risk_narrative": None,
        "matched_patterns": [],
        "san_analysis": {}
    }

    endpoint_type, confidence, matched = _match_endpoint_type(hostname)

    if confidence == "LOW" and san_domains:
        for domain in san_domains:
            san_type, san_conf, san_matched = _match_endpoint_type(domain)
            if san_conf in ["HIGH", "MEDIUM"]:
                endpoint_type = san_type
                confidence = san_conf
                matched = san_matched
                break

    profile = ENDPOINT_PATTERNS.get(endpoint_type, ENDPOINT_PATTERNS["generic"])

    result["endpoint_type"] = endpoint_type
    result["sensitivity"] = profile["sensitivity"]
    result["sensitivity_score"] = profile["sensitivity_score"]
    result["data_classification"] = profile["data_classification"]
    result["regulatory_scope"] = profile["regulatory_scope"]
    result["hndl_multiplier"] = profile["hndl_multiplier"]
    result["confidence"] = confidence
    result["attack_surface"] = profile["attack_surface"]
    result["exposure_level"] = profile["exposure_level"]
    result["matched_patterns"] = matched

    flags = _generate_ai_flags(hostname, scan_data, profile)
    result["ai_flags"] = flags

    priority = _calculate_priority(profile, scan_data)
    result["adjusted_priority"] = priority

    result["risk_narrative"] = _build_risk_narrative(
        hostname, endpoint_type, profile, confidence
    )

    if san_domains:
        result["san_analysis"] = _analyze_san_domains(san_domains)

    return result


def _match_endpoint_type(hostname: str) -> tuple:
    hostname_lower = hostname.lower()
    best_match = "generic"
    best_confidence = "LOW"
    best_patterns = []

    for etype, profile in ENDPOINT_PATTERNS.items():
        if etype == "generic":
            continue
        matched_patterns = []
        for pattern in profile["patterns"]:
            if re.search(pattern, hostname_lower):
                matched_patterns.append(pattern)
        if matched_patterns:
            if len(matched_patterns) >= 2:
                confidence = "HIGH"
            else:
                confidence = "MEDIUM"
            confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
            if confidence_rank.get(confidence, 0) > confidence_rank.get(best_confidence, 0):
                best_match = etype
                best_confidence = confidence
                best_patterns = matched_patterns

    return best_match, best_confidence, best_patterns


def _generate_ai_flags(hostname: str, scan_data: dict, profile: dict) -> list:
    flags = []

    if profile["sensitivity"] == "CRITICAL":
        flags.append("HIGH_VALUE_TARGET")

    if profile.get("hndl_multiplier", 1.0) >= 1.4:
        flags.append("ELEVATED_HNDL_RISK")

    if scan_data:
        if not scan_data.get("forward_secrecy"):
            if profile["sensitivity"] in ["CRITICAL", "HIGH"]:
                flags.append("SENSITIVE_ENDPOINT_NO_FS")

        if scan_data.get("is_expired"):
            flags.append("EXPIRED_CERT_ON_SENSITIVE_ENDPOINT")

        if scan_data.get("tls_version") in ["TLSv1.0", "TLSv1.1"]:
            flags.append("DEPRECATED_TLS_ON_SENSITIVE_ENDPOINT")

    if profile.get("regulatory_scope"):
        flags.append("REGULATORY_SCOPE_ACTIVE")

    return flags


def _calculate_priority(profile: dict, scan_data: dict) -> int:
    base = profile.get("sensitivity_score", 50)
    multiplier = profile.get("hndl_multiplier", 1.0)

    priority = int(base * multiplier)

    if scan_data:
        if not scan_data.get("forward_secrecy"):
            priority += 15
        if scan_data.get("is_expired"):
            priority += 20
        if scan_data.get("tls_version") in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
            priority += 10

    return min(100, priority)


def _build_risk_narrative(
    hostname: str,
    endpoint_type: str,
    profile: dict,
    confidence: str
) -> str:
    sensitivity = profile["sensitivity"]
    data_class = profile["data_classification"]
    regs = profile.get("regulatory_scope", [])

    narrative = (
        f"{hostname} has been classified as a {endpoint_type} endpoint "
        f"with {confidence} confidence. "
        f"This asset handles {data_class} with {sensitivity} sensitivity. "
    )

    if regs:
        narrative += (
            f"It falls under regulatory frameworks: {', '.join(regs)}. "
        )

    if profile.get("hndl_multiplier", 1.0) >= 1.4:
        narrative += (
            "The data handled by this endpoint has long-term confidentiality "
            "requirements, making it a prime candidate for Harvest Now Decrypt "
            "Later attacks. PQC migration should be prioritized."
        )

    return narrative


def _analyze_san_domains(san_domains: list) -> dict:
    analysis = {
        "total_san_count": len(san_domains),
        "wildcard_count": sum(1 for d in san_domains if d.startswith("*.")),
        "unique_base_domains": len(set(
            ".".join(d.split(".")[-2:]) for d in san_domains if "." in d
        )),
        "has_wildcards": any(d.startswith("*.") for d in san_domains)
    }
    return analysis
