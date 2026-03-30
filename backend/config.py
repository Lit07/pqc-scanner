from config.settings import Settings

_settings = None


def get_app_config() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def get_database_url() -> str:
    return get_app_config().DATABASE_URL


def get_cors_origins() -> list:
    return get_app_config().CORS_ORIGINS


def is_debug() -> bool:
    return get_app_config().DEBUG
