import re

HOSTNAME_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
IP_REGEX = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
SCAN_ID_REGEX = re.compile(
    r"^[a-f0-9\-]{8,36}$"
)


def validate_hostname(hostname: str) -> str:
    if not hostname:
        raise ValueError("Hostname cannot be empty")

    hostname = hostname.strip().lower()

    if len(hostname) > 253:
        raise ValueError("Hostname exceeds maximum length of 253 characters")

    if hostname.startswith("http://") or hostname.startswith("https://"):
        hostname = hostname.split("://", 1)[1]

    if "/" in hostname:
        hostname = hostname.split("/")[0]

    if ":" in hostname:
        hostname = hostname.split(":")[0]

    if not HOSTNAME_REGEX.match(hostname) and not IP_REGEX.match(hostname):
        raise ValueError(
            f"Invalid hostname: {hostname}. "
            "Must be a valid domain name or IP address"
        )

    return hostname


def validate_port(port: int) -> int:
    if not isinstance(port, int):
        try:
            port = int(port)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid port: {port}. Must be an integer")

    if port < 1 or port > 65535:
        raise ValueError(
            f"Invalid port: {port}. Must be between 1 and 65535"
        )

    return port


def validate_scan_id(scan_id: str) -> str:
    if not scan_id:
        raise ValueError("Scan ID cannot be empty")

    scan_id = scan_id.strip()

    if not SCAN_ID_REGEX.match(scan_id):
        raise ValueError(
            f"Invalid scan ID format: {scan_id}. "
            "Must be a valid UUID or hex string"
        )

    return scan_id


def validate_hostnames_list(hostnames: list) -> list:
    if not hostnames:
        raise ValueError("Hostnames list cannot be empty")

    validated = []
    for hostname in hostnames:
        validated.append(validate_hostname(hostname))

    return validated
