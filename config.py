import os
from pathlib import Path

# SQLite file locations (encrypted + plaintext mirrors)
DATA_DIR = Path("./data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
SECURE_DB_PATH = DATA_DIR / "secure_health.db"
PLAIN_DB_PATH = DATA_DIR / "plain_health.db"

# Backwards compatibility: DB_URL still points to the encrypted store
DB_URL = f"sqlite:///{SECURE_DB_PATH.resolve()}"
PLAIN_DB_URL = f"sqlite:///{PLAIN_DB_PATH.resolve()}"
