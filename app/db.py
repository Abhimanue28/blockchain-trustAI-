from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# SQLite for easy demo; later replace with Postgres if needed.
DATABASE_URL = "sqlite:///./nlockchain.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # SQLite only
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """
    FastAPI dependency: yields a DB session per request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()