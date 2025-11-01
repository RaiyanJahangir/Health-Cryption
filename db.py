from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DB_URL

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
