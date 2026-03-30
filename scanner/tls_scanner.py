import ssl
import socket
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def scan_tls(hostname: str, port: int = 443) -> dict:
    result = {
        "hostname": hostname,
        "port": port,
        "ip": None,
        "tls_version": None,
        "cipher_name": None,
        "cipher_bits": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_expired": False,
        "key_size": None,
        "key_type": None,
        "san": [],
        "error": None
    }

    try:
        result["ip"] = socket.gethostbyname(hostname)

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=10),
            server_hostname=hostname
        ) as tls:
            result["tls_version"] = tls.version()
            cipher = tls.cipher()
            result["cipher_name"] = cipher[0]
            result["cipher_bits"] = cipher[2]

            der_cert = tls.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        result["cert_expiry"] = cert.not_valid_after_utc.isoformat()
        result["cert_expired"] = datetime.datetime.now(datetime.timezone.utc) > cert.not_valid_after_utc

        result["cert_subject"] = cert.subject.rfc4514_string()
        result["cert_issuer"] = cert.issuer.rfc4514_string()

        pub_key = cert.public_key()
        result["key_type"] = type(pub_key).__name__

        if hasattr(pub_key, "key_size"):
            result["key_size"] = pub_key.key_size

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            result["san"] = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {str(e)}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {str(e)}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except socket.gaierror:
        result["error"] = "DNS resolution failed"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result