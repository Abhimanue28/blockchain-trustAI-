import hashlib
from datetime import datetime
from sqlalchemy.orm import Session
from .models import AuditBlock

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def compute_block_hash(index: int, timestamp: datetime, data: str, previous_hash: str) -> str:
    payload = f"{index}|{timestamp.isoformat()}|{data}|{previous_hash}"
    return sha256_hex(payload)

def get_latest_block(db: Session):
    return db.query(AuditBlock).order_by(AuditBlock.index.desc()).first()

def append_block(db: Session, data: str) -> AuditBlock:
    latest = get_latest_block(db)
    if latest is None:
        index = 0
        prev_hash = "0" * 64
    else:
        index = latest.index + 1
        prev_hash = latest.hash

    ts = datetime.utcnow()
    h = compute_block_hash(index, ts, data, prev_hash)

    block = AuditBlock(index=index, timestamp=ts, data=data, previous_hash=prev_hash, hash=h)
    db.add(block)
    db.commit()
    db.refresh(block)
    return block

def verify_chain(db: Session) -> dict:
    blocks = db.query(AuditBlock).order_by(AuditBlock.index.asc()).all()
    if not blocks:
        return {"ok": True, "message": "No blocks yet."}

    for i, b in enumerate(blocks):
        expected_prev = ("0" * 64) if i == 0 else blocks[i - 1].hash
        if b.previous_hash != expected_prev:
            return {"ok": False, "bad_index": b.index, "reason": "previous_hash mismatch"}

        expected_hash = compute_block_hash(b.index, b.timestamp, b.data, b.previous_hash)
        if b.hash != expected_hash:
            return {"ok": False, "bad_index": b.index, "reason": "hash mismatch (tamper detected)"}

    return {"ok": True, "message": f"Chain verified ({len(blocks)} blocks)."}