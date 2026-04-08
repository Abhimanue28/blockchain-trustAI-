from pydantic import BaseModel, Field
from typing import Optional, Literal


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class EventIn(BaseModel):
    event_type: Literal["login", "file_access", "api_call", "device_connect"]
    ip: Optional[str] = None
    device_id: Optional[str] = None
    endpoint: Optional[str] = None

    login_hour: Optional[int] = Field(default=0, ge=0, le=23)
    file_access_count: Optional[int] = Field(default=0, ge=0, le=10_000)
    payload_size: Optional[int] = Field(default=0, ge=0, le=10_000_000)

    true_label: Optional[Literal["NORMAL", "ANOMALY"]] = None


class DecisionOut(BaseModel):
    decision: Literal["ALLOW", "STEP_UP", "DENY"]
    anomaly_label: str
    risk_score: float
    trust_score: float
    reason: str