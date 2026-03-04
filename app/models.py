from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from .db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(60), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user")  # user | analyst | admin
    trust_score = Column(Float, default=100.0)
    is_active = Column(Boolean, default=True)

    events = relationship("SecurityEvent", back_populates="user")

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)

    # context
    event_type = Column(String(50), nullable=False)  # login | file_access | api_call | device_connect
    ip = Column(String(60), nullable=True)
    device_id = Column(String(80), nullable=True)
    endpoint = Column(String(120), nullable=True)

    # features
    login_hour = Column(Integer, nullable=True)
    file_access_count = Column(Integer, nullable=True)
    payload_size = Column(Integer, nullable=True)

    # AI outputs
    anomaly_label = Column(String(20), nullable=False, default="UNKNOWN")  # NORMAL | ANOMALY | UNKNOWN
    risk_score = Column(Float, nullable=False, default=0.0)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="events")

class AuditBlock(Base):
    """
    Tamper-evident audit chain (blockchain-style).
    """
    __tablename__ = "audit_blocks"

    id = Column(Integer, primary_key=True, index=True)
    index = Column(Integer, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    data = Column(Text, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    hash = Column(String(64), nullable=False)

Index("ix_audit_blocks_index_unique", AuditBlock.index, unique=True)