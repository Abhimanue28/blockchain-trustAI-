from sqlalchemy.orm import Session
from .models import User
from .security import hash_password


def seed_users(db: Session):
    users = [
        ("admin", "admin123", "admin"),
        ("analyst", "analyst123", "analyst"),
        ("user1", "user123", "user"),
    ]

    for username, password, role in users:
        existing_user = db.query(User).filter(User.username == username).first()

        if not existing_user:
            new_user = User(
                username=username,
                password_hash=hash_password(password),
                role=role,
                trust_score=100.0,
                is_active=True
            )

            db.add(new_user)

    db.commit()