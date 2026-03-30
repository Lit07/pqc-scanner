import uuid
import hashlib
import time
import datetime


def generate_uuid() -> str:
    return str(uuid.uuid4())


def generate_scan_id(hostname: str) -> str:
    raw = f"{hostname}:{time.time()}:{uuid.uuid4()}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def format_timestamp(dt=None) -> str:
    if dt is None:
        dt = datetime.datetime.now(datetime.timezone.utc)
    if isinstance(dt, str):
        return dt
    return dt.isoformat()


def safe_get(d: dict, *keys, default=None):
    current = d
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return default
        else:
            return default
    return current


def paginate_list(items: list, page: int = 1, page_size: int = 20) -> dict:
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = items[start:end]

    return {
        "items": paginated,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 0,
        "has_next": end < total,
        "has_prev": page > 1
    }


def flatten_dict(d: dict, parent_key: str = "", sep: str = "_") -> dict:
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def truncate_string(s: str, max_length: int = 100) -> str:
    if not s:
        return s
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def merge_dicts(*dicts) -> dict:
    result = {}
    for d in dicts:
        if isinstance(d, dict):
            result.update(d)
    return result


def seconds_to_human(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"
