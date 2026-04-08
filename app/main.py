from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import json

from .db import Base, engine, get_db, SessionLocal
from .models import User, SecurityEvent
from .schemas import LoginRequest, Token, EventIn, DecisionOut
from .security import verify_password, create_access_token, decode_access_token
from .seed import seed_users
from .trust_engine import ai_model, retrain_ai_from_db, update_trust_score, zero_trust_decision
from .blockchain_audit import append_block, verify_chain

app = FastAPI(
    title="TrustChainAI — Blockchain-Driven Zero Trust Security",
    docs_url="/docs",
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", include_in_schema=False)
def serve_ui():
    return FileResponse(STATIC_DIR / "index.html")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

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

def evaluate_ai_model(db: Session):
    events = db.query(SecurityEvent).filter(SecurityEvent.true_label.isnot(None)).all()

    if not events:
        raise HTTPException(status_code=404, detail="No labeled events available")

    y_true, y_pred = [], []

    for e in events:
        pred_label, _ = ai_model.score(e.login_hour, e.file_access_count, e.payload_size)
        y_true.append(e.true_label)
        y_pred.append(pred_label)

    labels = sorted(list(set(y_true) | set(y_pred)))

    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist()
    }

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username/password")

    token = create_access_token({"sub": user.username, "role": user.role})
    return Token(access_token=token)

@app.post("/auth/login-json", response_model=Token)
def login_json(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()

    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username/password")

    token = create_access_token({"sub": user.username, "role": user.role})
    return Token(access_token=token)

@app.post("/events", response_model=DecisionOut)
def submit_event(event: EventIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    login_hour = event.login_hour or 0
    file_access_count = event.file_access_count or 0
    payload_size = event.payload_size or 0

    label, risk = ai_model.score(login_hour, file_access_count, payload_size)

    e = SecurityEvent(
        user_id=user.id,
        event_type=event.event_type,
        ip=event.ip,
        device_id=event.device_id,
        endpoint=event.endpoint,
        login_hour=login_hour,
        file_access_count=file_access_count,
        payload_size=payload_size,
        anomaly_label=label,
        true_label=event.true_label,
        risk_score=risk
    )
    db.add(e)

    new_trust = update_trust_score(user, risk, label)
    decision, reason = zero_trust_decision(new_trust, risk, label)

    db.commit()
    db.refresh(e)

    append_block(db, f"user={user.username}|risk={risk:.2f}|decision={decision}")

    return DecisionOut(
        decision=decision,
        anomaly_label=label,
        risk_score=risk,
        trust_score=new_trust,
        reason=reason
    )

@app.post("/events/upload-json")
async def upload_events_json(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    if not file.filename or not file.filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Only .json files are allowed")

    try:
        raw = await file.read()
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        raise HTTPException(status_code=400, detail="JSON must contain an object or a list of objects")

    inserted = 0
    failed = 0
    results = []

    for index, item in enumerate(data, start=1):
        try:
            event = EventIn(**item)

            login_hour = event.login_hour or 0
            file_access_count = event.file_access_count or 0
            payload_size = event.payload_size or 0

            label, risk = ai_model.score(login_hour, file_access_count, payload_size)

            e = SecurityEvent(
                user_id=user.id,
                event_type=event.event_type,
                ip=event.ip,
                device_id=event.device_id,
                endpoint=event.endpoint,
                login_hour=login_hour,
                file_access_count=file_access_count,
                payload_size=payload_size,
                anomaly_label=label,
                true_label=event.true_label,
                risk_score=risk
            )
            db.add(e)

            new_trust = update_trust_score(user, risk, label)
            decision, reason = zero_trust_decision(new_trust, risk, label)

            results.append({
                "row": index,
                "status": "inserted",
                "event_type": event.event_type,
                "decision": decision,
                "anomaly_label": label,
                "risk_score": round(float(risk), 4),
                "trust_score": round(float(new_trust), 4),
                "reason": reason
            })

            inserted += 1

        except Exception as ex:
            failed += 1
            results.append({
                "row": index,
                "status": "failed",
                "error": str(ex),
                "item": item
            })

    db.commit()

    append_block(
        db,
        f"user={user.username}|bulk_upload={file.filename}|inserted={inserted}|failed={failed}"
    )

    return {
        "uploaded_file": file.filename,
        "total_records": len(data),
        "inserted": inserted,
        "failed": failed,
        "results": results
    }

@app.get("/audit/verify")
def audit_verify(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_role(user, {"admin", "analyst"})
    return verify_chain(db)

@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {
        "username": user.username,
        "role": user.role,
        "trust_score": user.trust_score
    }

@app.get("/model/accuracy")
def model_accuracy(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return evaluate_ai_model(db)