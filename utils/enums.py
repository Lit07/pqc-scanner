from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PQCTier(str, Enum):
    ELITE = "Elite"
    STANDARD = "Standard"
    LEGACY = "Legacy"
    CRITICAL = "Critical"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class HNDLLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class TLSVersion(str, Enum):
    TLS_1_3 = "TLSv1.3"
    TLS_1_2 = "TLSv1.2"
    TLS_1_1 = "TLSv1.1"
    TLS_1_0 = "TLSv1.0"
    SSL_3 = "SSLv3"
    SSL_2 = "SSLv2"


class MigrationComplexity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class QuantumAttack(str, Enum):
    SHOR = "Shor's Algorithm"
    GROVER = "Grover's Algorithm"
    HNDL = "Harvest Now Decrypt Later"
    PROTOCOL_LIMITATION = "Protocol Limitation"
    FUTURE_THREAT = "Future Quantum Threat"


class ClassicalStrength(str, Enum):
    CRITICALLY_WEAK = "CRITICALLY_WEAK"
    WEAK = "WEAK"
    ACCEPTABLE = "ACCEPTABLE"
    STRONG = "STRONG"
    VERY_STRONG = "VERY_STRONG"
    UNKNOWN = "UNKNOWN"


class KeySizeStatus(str, Enum):
    UNSAFE = "UNSAFE"
    MARGINAL = "MARGINAL"
    SAFE_CLASSICAL = "SAFE_CLASSICAL"
    UNKNOWN = "UNKNOWN"


class EndpointSensitivity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class RegressionType(str, Enum):
    CIPHER_DOWNGRADE = "CIPHER_DOWNGRADE"
    TLS_DOWNGRADE = "TLS_DOWNGRADE"
    KEY_SIZE_REDUCTION = "KEY_SIZE_REDUCTION"
    FORWARD_SECRECY_LOST = "FORWARD_SECRECY_LOST"


class AnomalyTrend(str, Enum):
    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    DEGRADING = "DEGRADING"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
