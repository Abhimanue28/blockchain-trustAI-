from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .db import Base, engine, get_db, SessionLocal
from .models import User, SecurityEvent
from .schemas import LoginRequest, Token, EventIn, DecisionOut
from .security import verify_password, create_access_token, decode_access_token
from .seed import seed_users
from .trust_engine import ai_model, retrain_ai_from_db, update_trust_score, zero_trust_decision
from .blockchain_audit import append_block, verify_chain

app = FastAPI(title="NLockChain AI — Blockchain-Driven Zero Trust Security", version="1.0.0")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Create tables
Base.metadata.create_all(bind=engine)

@app.on_event("startup")
def startup():
    db = SessionLocal()
    try:
        seed_users(db)
        retrain_ai_from_db(db)
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def require_role(user: User, roles: set[str]):
    if user.role not in roles:
        raise HTTPException(status_code=403, detail="Not enough permissions")

@app.post("/auth/login", response_model=Token)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username/password")

    token = create_access_token({"sub": user.username, "role": user.role})
    return Token(access_token=token)

@app.post("/events", response_model=DecisionOut)
def submit_event(event: EventIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # 1) AI scoring
    label, risk = ai_model.score(event.login_hour, event.file_access_count, event.payload_size)

    # 2) Save event
    e = SecurityEvent(
        user_id=user.id,
        event_type=event.event_type,
        ip=event.ip,
        device_id=event.device_id,
        endpoint=event.endpoint,
        login_hour=event.login_hour,
        file_access_count=event.file_access_count,
        payload_size=event.payload_size,
        anomaly_label=label,
        risk_score=risk
    )
    db.add(e)

    # 3) Update trust score
    new_trust = update_trust_score(user, risk, label)

    # 4) Zero Trust decision
    decision, reason = zero_trust_decision(new_trust, risk, label)

    db.commit()
    db.refresh(e)

    # 5) Immutable blockchain-style audit log
    summary = (
        f"user={user.username}|role={user.role}|event={event.event_type}|"
        f"label={label}|risk={risk:.3f}|trust={new_trust:.1f}|decision={decision}"
    )
    append_block(db, summary)

    # periodic retrain
    if e.id % 25 == 0:
        retrain_ai_from_db(db)

    return DecisionOut(
        decision=decision,
        anomaly_label=label,
        risk_score=risk,
        trust_score=new_trust,
        reason=reason
    )

@app.get("/audit/verify")
def audit_verify(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_role(user, {"admin", "analyst"})
    return verify_chain(db)

@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role, "trust_score": user.trust_score}