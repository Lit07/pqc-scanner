import logging.config
import os
import sys
from config.env import get_env


def configure_logging():
    """Configures the root python logger for the PQC Scanner Application."""
    log_level = get_env("LOG_LEVEL", "INFO").upper()

    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "json": {
                "format": '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
                "stream": sys.stdout
            }
        },
        "loggers": {
            "": {  # root logger
                "handlers": ["console"],
                "level": log_level,
                "propagate": True
            },
            "pqc_scanner": {
                "handlers": ["console"],
                "level": log_level,
                "propagate": False
            },
            # Adjust Uvicorn loggers to match app log level
            "uvicorn": {
                "level": log_level,
            },
            "uvicorn.access": {
                "level": log_level,
            }
        }
    }

    try:
        logging.config.dictConfig(log_config)
    except ValueError as e:
        print(f"Failed to configure logging: {e}")
