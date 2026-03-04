from sqlalchemy.orm import Session
from .models import SecurityEvent, User
from .ai_engine import AIThreatModel

# One in-process model for the prototype (fine for Master's demo).
ai_model = AIThreatModel()

def retrain_ai_from_db(db: Session):
    """
    Train the anomaly model from recent DB events.
    """
    events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(2000).all()
    samples = [(e.login_hour, e.file_access_count, e.payload_size) for e in events]
    ai_model.train(samples)

def update_trust_score(user: User, risk_score: float, anomaly_label: str) -> float:
    """
    Dynamic trust scoring:
      NORMAL  -> slight increase
      UNKNOWN -> small decrease
      ANOMALY -> larger decrease (scaled by risk)
    """
    if anomaly_label == "NORMAL":
        delta = +0.8 * (1.0 - risk_score)
    elif anomaly_label == "UNKNOWN":
        delta = -2.5 * risk_score
    else:  # ANOMALY
        delta = -12.0 * max(0.35, risk_score)

    user.trust_score = float(max(0.0, min(100.0, user.trust_score + delta)))
    return user.trust_score

def zero_trust_decision(trust_score: float, risk_score: float, anomaly_label: str):
    """
    Zero Trust policy:
      DENY: high risk OR low trust
      STEP_UP: suspicious -> require MFA/device attestation
      ALLOW: acceptable
    """
    if trust_score < 35 or risk_score > 0.80:
        return ("DENY", "High risk or low trust (Zero Trust deny).")

    if anomaly_label in ("ANOMALY", "UNKNOWN") and (risk_score > 0.45 or trust_score < 70):
        return ("STEP_UP", "Elevated risk: require step-up verification (MFA/device check).")

    return ("ALLOW", "Risk acceptable under Zero Trust continuous evaluation.")