import json
import datetime


def format_cbom_as_json(cbom: dict) -> dict:
    formatted = {
        "bomFormat": cbom.get("bom_format", "CycloneDX"),
        "specVersion": cbom.get("spec_version", "1.6"),
        "version": cbom.get("version", 1),
        "serialNumber": cbom.get("serial_number"),
        "metadata": cbom.get("metadata", {}),
        "components": _format_components(cbom.get("components", [])),
        "dependencies": cbom.get("dependencies", [])
    }
    return formatted


def format_cbom_summary(cbom: dict) -> dict:
    components = cbom.get("components", [])
    summary = cbom.get("summary", {})

    vulnerable = []
    safe = []
    replacements_needed = []

    for comp in components:
        props = comp.get("properties", {})
        entry = {
            "name": comp.get("name"),
            "version": comp.get("version"),
            "type": comp.get("crypto_properties", {}).get("asset_type", "unknown"),
            "bom_ref": comp.get("bom_ref")
        }

        if props.get("pqc_vulnerable"):
            vulnerable.append(entry)
            replacement = props.get("nist_replacement")
            if replacement:
                replacements_needed.append({
                    "current": f"{comp.get('name')} ({comp.get('version')})",
                    "replacement": replacement,
                    "attack_vector": props.get("quantum_attack", "Unknown")
                })
        else:
            safe.append(entry)

    return {
        "hostname": summary.get("hostname"),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_components": len(components),
        "vulnerable_count": len(vulnerable),
        "safe_count": len(safe),
        "pqc_ready": len(vulnerable) == 0,
        "vulnerable_components": vulnerable,
        "safe_components": safe,
        "replacements_needed": replacements_needed,
        "replacement_count": len(replacements_needed)
    }


def format_cbom_for_db(cbom: dict, scan_result_id: str) -> list:
    entries = []
    components = cbom.get("components", [])

    for comp in components:
        props = comp.get("properties", {})
        crypto_props = comp.get("crypto_properties", {})
        algo_props = crypto_props.get("algorithm_properties", {})
        cert_props = crypto_props.get("certificate_properties", {})

        entry = {
            "scan_result_id": scan_result_id,
            "hostname": cbom.get("summary", {}).get("hostname"),
            "component_type": crypto_props.get("asset_type", "unknown"),
            "algorithm": comp.get("version", ""),
            "key_size": _safe_int(algo_props.get("parameter_set_identifier")),
            "tls_version": algo_props.get("variant")
                if crypto_props.get("asset_type") == "protocol" else None,
            "cipher_suite": comp.get("version")
                if crypto_props.get("asset_type") == "algorithm"
                and algo_props.get("primitive") == "cipher" else None,
            "certificate_authority": cert_props.get("issuer_name"),
            "is_pqc_vulnerable": props.get("pqc_vulnerable", True),
            "nist_replacement": props.get("nist_replacement")
        }
        entries.append(entry)

    return entries


def format_cbom_download(cbom: dict) -> str:
    formatted = format_cbom_as_json(cbom)
    return json.dumps(formatted, indent=2, default=str)


def _format_components(components: list) -> list:
    formatted = []
    for comp in components:
        formatted_comp = {
            "type": comp.get("type", "cryptographic-asset"),
            "bom-ref": comp.get("bom_ref"),
            "name": comp.get("name"),
            "version": comp.get("version"),
            "description": comp.get("description"),
            "cryptoProperties": _format_crypto_properties(
                comp.get("crypto_properties", {})
            ),
            "properties": _format_properties(comp.get("properties", {}))
        }
        formatted.append(formatted_comp)
    return formatted


def _format_crypto_properties(crypto_props: dict) -> dict:
    result = {
        "assetType": crypto_props.get("asset_type")
    }

    algo_props = crypto_props.get("algorithm_properties")
    if algo_props:
        result["algorithmProperties"] = {
            "variant": algo_props.get("variant"),
            "primitive": algo_props.get("primitive"),
            "parameterSetIdentifier": algo_props.get("parameter_set_identifier"),
            "curve": algo_props.get("curve")
        }

    cert_props = crypto_props.get("certificate_properties")
    if cert_props:
        result["certificateProperties"] = {
            "subjectName": cert_props.get("subject_name"),
            "issuerName": cert_props.get("issuer_name"),
            "notValidBefore": cert_props.get("not_valid_before"),
            "notValidAfter": cert_props.get("not_valid_after"),
            "signatureAlgorithmRef": cert_props.get("signature_algorithm_ref")
        }

    return result


def _format_properties(props: dict) -> list:
    return [
        {"name": key, "value": str(value)}
        for key, value in props.items()
        if value is not None
    ]


def _safe_int(value) -> int:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
