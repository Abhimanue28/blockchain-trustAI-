from sqlalchemy.orm import Session
from .models import SecurityEvent, User
from .ai_engine import AIThreatModel

# One in-process model for the prototype
ai_model = AIThreatModel()


def retrain_ai_from_db(db: Session):
    events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.created_at.desc())
        .limit(2000)
        .all()
    )

    samples = []
    for e in events:
        if (
            e.login_hour is not None
            and e.file_access_count is not None
            and e.payload_size is not None
        ):
            samples.append(
                (
                    e.login_hour,
                    e.file_access_count,
                    e.payload_size
                )
            )

    # Avoid training on empty data
    if not samples:
        return

    ai_model.train(samples)


def update_trust_score(user: User, risk_score: float, anomaly_label: str) -> float:

    if anomaly_label == "NORMAL":
        delta = +0.8 * (1.0 - risk_score)
    elif anomaly_label == "UNKNOWN":
        delta = -2.5 * risk_score
    else:  # ANOMALY
        delta = -12.0 * max(0.35, risk_score)

    user.trust_score = float(
        max(0.0, min(100.0, user.trust_score + delta))
    )
    return user.trust_score


def zero_trust_decision(trust_score: float, risk_score: float, anomaly_label: str):

    if trust_score < 35 or risk_score > 0.80:
        return ("DENY", "High risk or low trust (Zero Trust deny).")

    if anomaly_label in ("ANOMALY", "UNKNOWN") and (risk_score > 0.45 or trust_score < 70):
        return ("STEP_UP", "Elevated risk: require step-up verification (MFA/device check).")

    return ("ALLOW", "Risk acceptable under Zero Trust continuous evaluation.")