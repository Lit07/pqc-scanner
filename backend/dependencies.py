from fastapi import Depends
from sqlalchemy.orm import Session
from db.database import get_db as _get_db
from config.settings import Settings

_settings = None


def get_db():
    return _get_db()


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def get_current_user():
    return {"user": "anonymous", "role": "admin"}
