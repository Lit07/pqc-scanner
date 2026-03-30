import os
from dotenv import load_dotenv
from typing import Any, Optional


def load_environment():
    """Load variables from .env file into standard python os.environ."""
    load_dotenv()


def get_env(key: str, default: Optional[Any] = None) -> Any:
    """Safely get an environment variable with a fallback."""
    if key in os.environ:
        return os.environ[key]
    return default
