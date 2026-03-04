from sqlalchemy.orm import Session
from .models import User
from .security import hash_password

def seed_users(db: Session):
    """
    Creates demo accounts so your professor can run instantly.
    """
    def ensure(username: str, password: str, role: str):
        u = db.query(User).filter(User.username == username).first()
        if not u:
            u = User(
                username=username,
                password_hash=hash_password(password),
                role=role,
                trust_score=100.0,
                is_active=True
            )
            db.add(u)
            db.commit()

    ensure("admin", "admin123", "admin")
    ensure("analyst", "analyst123", "analyst")
    ensure("user1", "user123", "user")