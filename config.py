import os
from pathlib import Path

# SQLite file location
DATA_DIR = Path("./data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "secure_health.db"
DB_URL = f"sqlite:///{DB_PATH.resolve()}"
