import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

def parse_cert(der_bytes: bytes) -> dict:
    result = {
        "subject_cn": None,
        "subject_org": None,
        "issuer_cn": None,
        "issuer_org": None,
        "serial_number": None,
        "not_before": None,
        "not_after": None,
        "is_expired": False,
        "days_to_expiry": None,
        "key_type": None,
        "key_size": None,
        "curve_name": None,
        "signature_algorithm": None,
        "san_domains": [],
        "is_wildcard": False,
        "is_ev": False,
        "is_self_signed": False,
        "extended_key_usage": [],
        "basic_constraints_ca": False,
        "ocsp_urls": [],
        "crl_urls": [],
    }

    cert = x509.load_der_x509_certificate(der_bytes, default_backend())
    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        result["subject_cn"] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        pass

    try:
        result["subject_org"] = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except IndexError:
        pass

    try:
        result["issuer_cn"] = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        pass

    try:
        result["issuer_org"] = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except IndexError:
        pass

    result["serial_number"] = hex(cert.serial_number)
    result["not_before"] = cert.not_valid_before_utc.isoformat()
    result["not_after"] = cert.not_valid_after_utc.isoformat()
    result["is_expired"] = now > cert.not_valid_after_utc
    result["days_to_expiry"] = (cert.not_valid_after_utc - now).days
    result["is_self_signed"] = cert.issuer == cert.subject
    result["signature_algorithm"] = cert.signature_algorithm_oid.dotted_string

    pub_key = cert.public_key()

    if isinstance(pub_key, rsa.RSAPublicKey):
        result["key_type"] = "RSA"
        result["key_size"] = pub_key.key_size

    elif isinstance(pub_key, ec.ECPublicKey):
        result["key_type"] = "EC"
        result["key_size"] = pub_key.key_size
        result["curve_name"] = pub_key.curve.name

    elif isinstance(pub_key, dsa.DSAPublicKey):
        result["key_type"] = "DSA"
        result["key_size"] = pub_key.key_size

    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        result["key_type"] = "Ed25519"
        result["key_size"] = 256

    elif isinstance(pub_key, ed448.Ed448PublicKey):
        result["key_type"] = "Ed448"
        result["key_size"] = 448

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        domains = san_ext.value.get_values_for_type(x509.DNSName)
        result["san_domains"] = domains
        result["is_wildcard"] = any(d.startswith("*.") for d in domains)
    except x509.ExtensionNotFound:
        pass

    try:
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        result["extended_key_usage"] = [oid.dotted_string for oid in eku_ext.value]
        if ExtendedKeyUsageOID.SERVER_AUTH.dotted_string in result["extended_key_usage"]:
            result["is_ev"] = "ev" in (result["issuer_cn"] or "").lower() or \
                              "extended validation" in (result["issuer_org"] or "").lower()
    except x509.ExtensionNotFound:
        pass

    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        result["basic_constraints_ca"] = bc_ext.value.ca
    except x509.ExtensionNotFound:
        pass

    try:
        aia_ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for access in aia_ext.value:
            if access.access_method == x509.AuthorityInformationAccessOID.OCSP:
                result["ocsp_urls"].append(access.access_location.value)
            elif access.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                result["crl_urls"].append(access.access_location.value)
    except x509.ExtensionNotFound:
        pass

    return result