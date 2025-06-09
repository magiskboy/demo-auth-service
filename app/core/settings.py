from dotenv import load_dotenv
load_dotenv()

import os
import secrets
from pathlib import Path


BASE_DIR = Path(os.getcwd())

DATABASE_URL = os.getenv("POSTGRES_URL", os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/postgres"))


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", 6379)