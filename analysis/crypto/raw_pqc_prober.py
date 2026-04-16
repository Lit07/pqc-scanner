import socket
import struct
from utils.logger import get_logger

logger = get_logger(__name__)

def build_client_hello(hostname: str) -> bytes:
    ext_sni = (b'\x00\x00' + struct.pack('!H', len(hostname) + 5) + 
               struct.pack('!H', len(hostname) + 3) + b'\x00' + 
               struct.pack('!H', len(hostname)) + hostname.encode('ascii'))
    
    # Supported Groups: ML-KEM-768(0x11ec), Kyber768(0x6399), X25519(0x001d), secp256r1(0x0017)
    groups = b'\x11\xec\x63\x99\x00\x1d\x00\x17'
    ext_groups = (b'\x00\x0a' + struct.pack('!H', len(groups) + 2) + struct.pack('!H', len(groups)) + groups)
    sigs = b'\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01'
    ext_sigs = (b'\x00\x0d' + struct.pack('!H', len(sigs) + 2) + struct.pack('!H', len(sigs)) + sigs)
    vers = b'\x03\x04'
    ext_vers = (b'\x00\x2b' + struct.pack('!H', len(vers) + 1) + struct.pack('!B', len(vers)) + vers)
    
    # Empty Key Share (forces HelloRetryRequest)
    ks = b'\x00\x00'
    ext_ks = (b'\x00\x33' + struct.pack('!H', len(ks)) + ks)
    
    extensions = ext_sni + ext_groups + ext_sigs + ext_vers + ext_ks
    ext_length = struct.pack('!H', len(extensions))
    
    ciphers = b'\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30'
    client_hello = (b'\x03\x03' + (b'\xaa' * 32) + b'\x00' + struct.pack('!H', len(ciphers)) + ciphers + 
                    b'\x01\x00' + ext_length + extensions)
    
    handshake = b'\x01' + struct.pack('!I', len(client_hello))[1:] + client_hello
    return b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake


def parse_hrr_group(resp: bytes) -> str:
    try:
        idx = 5 + 1 + 3 + 2 + 32
        sess_len = resp[idx]
        idx += 1 + sess_len
        idx += 3
        ext_len = struct.unpack('!H', resp[idx:idx+2])[0]
        idx += 2
        
        end = idx + ext_len
        while idx < end:
            ext_type, e_len = struct.unpack('!HH', resp[idx:idx+4])
            idx += 4
            if ext_type == 51:
                group_id = struct.unpack('!H', resp[idx:idx+2])[0]
                if group_id == 0x11ec: return "ML-KEM-768/X25519 (0x11EC)"
                if group_id == 0x6399: return "Kyber768Draft00/X25519 (0x6399)"
                if group_id == 0x001d: return "X25519 (0x001D)"
                if group_id == 0x0017: return "secp256r1 (0x0017)"
                return hex(group_id)
            idx += e_len
    except:
        pass
    return "Unknown"


def scan_pqc_hybrid_support(hostname: str, port: int = 443) -> dict:
    """
    Executes a raw TLS 1.3 ClientHello against the target, offering ML-KEM/Kyber.
    Forces server to respond with a HelloRetryRequest to organically prove quantum readiness.
    """
    result = {
        "hybrid_mode_supported": False,
        "negotiated_group": None,
        "error": None
    }
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((hostname, port))
        s.sendall(build_client_hello(hostname))
        resp = s.recv(4096)
        
        if len(resp) >= 5 and resp[0] == 22 and resp[5] == 2:
            hrr_random = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
            if resp[11:11+32] == hrr_random:
                group = parse_hrr_group(resp)
                result["negotiated_group"] = group
                if "0x11EC" in group or "0x6399" in group:
                    result["hybrid_mode_supported"] = True
                logger.info(f"[RawPQC] {hostname} HRR parsing completed. Group: {group}")
            else:
                logger.info(f"[RawPQC] {hostname} returned standard ServerHello rather than HRR. No Kyber negotiation.")
        else:
            logger.info(f"[RawPQC] {hostname} dropped connection or sent invalid handshake type.")
            
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"[RawPQC] Probe failed on {hostname}: {e}")
    finally:
        s.close()
        
    return result
