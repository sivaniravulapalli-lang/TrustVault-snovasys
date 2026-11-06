from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from .config import DATABASE_URL

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False)


def add_missing_columns():
    """create_all() never alters an existing table, so add columns introduced later."""
    insp = inspect(engine)
    if "users" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("users")}
        if "name" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN name VARCHAR(100)"))
        if "telegram_chat_id" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN telegram_chat_id VARCHAR(50)"))
        if "telegram_link_code" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN telegram_link_code VARCHAR(64)"))
        if "email_alerts_enabled" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN email_alerts_enabled BOOLEAN DEFAULT 1"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
