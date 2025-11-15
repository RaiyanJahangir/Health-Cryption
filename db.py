from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DB_URL, PLAIN_DB_URL

# Encrypted/secure store ------------------------------------------------------
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# Plaintext mirror ------------------------------------------------------------
plain_engine = create_engine(PLAIN_DB_URL, connect_args={"check_same_thread": False})
PlainSessionLocal = sessionmaker(bind=plain_engine, autoflush=False, autocommit=False)
PlainBase = declarative_base()
