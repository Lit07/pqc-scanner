from sqlalchemy import (
    Column, String, Integer, Float, Boolean,
    DateTime, Text, JSON, ForeignKey
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from db.database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scans = relationship("ScanJob", back_populates="user")


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"))
    hostname = Column(String, nullable=False)
    port = Column(Integer, default=443)
    status = Column(String, default="pending")
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(Text, nullable=True)
    user = relationship("User", back_populates="scans")
    result = relationship("ScanResult", back_populates="scan_job", uselist=False)


class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(String, primary_key=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"))
    hostname = Column(String)
    ip = Column(String, nullable=True)
    tls_version = Column(String, nullable=True)
    cipher_name = Column(String, nullable=True)
    cipher_bits = Column(Integer, nullable=True)
    key_type = Column(String, nullable=True)
    key_size = Column(Integer, nullable=True)
    curve_name = Column(String, nullable=True)
    is_expired = Column(Boolean, default=False)
    days_to_expiry = Column(Integer, nullable=True)
    is_self_signed = Column(Boolean, default=False)
    is_wildcard = Column(Boolean, default=False)
    forward_secrecy = Column(Boolean, default=False)
    final_score = Column(Integer, nullable=True)
    pqc_tier = Column(String, nullable=True)
    pqc_score = Column(Integer, nullable=True)
    pqc_classification = Column(String, nullable=True)
    hndl_threat_level = Column(String, nullable=True)
    hndl_score = Column(Integer, nullable=True)
    endpoint_type = Column(String, nullable=True)
    sensitivity = Column(String, nullable=True)
    grade = Column(String, nullable=True)
    shadow_asset_count = Column(Integer, default=0)
    anomaly_count = Column(Integer, default=0)
    has_regression = Column(Boolean, default=False)
    full_result = Column(JSON, nullable=True)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
    scan_job = relationship("ScanJob", back_populates="result")
    triggered_rules = relationship("TriggeredRule", back_populates="scan_result")
    cbom_entries = relationship("CBOMEntry", back_populates="scan_result")


class TriggeredRule(Base):
    __tablename__ = "triggered_rules"
    id = Column(String, primary_key=True)
    scan_result_id = Column(String, ForeignKey("scan_results.id"))
    rule_id = Column(String)
    rule_name = Column(String)
    severity = Column(String)
    category = Column(String)
    message = Column(Text)
    score_penalty = Column(Float)
    pqc_impact = Column(Boolean, default=False)
    scan_result = relationship("ScanResult", back_populates="triggered_rules")


class CBOMEntry(Base):
    __tablename__ = "cbom_entries"
    id = Column(String, primary_key=True)
    scan_result_id = Column(String, ForeignKey("scan_results.id"))
    hostname = Column(String)
    component_type = Column(String)
    algorithm = Column(String)
    key_size = Column(Integer, nullable=True)
    tls_version = Column(String, nullable=True)
    cipher_suite = Column(String, nullable=True)
    certificate_authority = Column(String, nullable=True)
    is_pqc_vulnerable = Column(Boolean, default=True)
    nist_replacement = Column(String, nullable=True)
    scan_result = relationship("ScanResult", back_populates="cbom_entries")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String, primary_key=True)
    hostname = Column(String, unique=True, nullable=False)
    ip = Column(String, nullable=True)
    asset_type = Column(String, nullable=True)
    owner = Column(String, nullable=True)
    last_scanned = Column(DateTime(timezone=True), nullable=True)
    latest_score = Column(Integer, nullable=True)
    latest_tier = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())