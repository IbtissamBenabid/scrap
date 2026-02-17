"""Simple disk-backed cache for research results."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

CACHE_TTL_SECONDS = int(os.getenv("RESEARCH_CACHE_TTL_SECONDS", "86400"))  # default: 1 day
CACHE_FILE_PATH = Path(os.getenv("RESEARCH_CACHE_FILE", "./.cache/research-cache.json"))
_CACHE_LOCK = threading.Lock()


def _normalize_company(company: str) -> str:
    return company.strip().lower()


def _ensure_cache_file() -> None:
    CACHE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not CACHE_FILE_PATH.exists():
        CACHE_FILE_PATH.write_text("{}", encoding="utf-8")


def _load_cache() -> Dict[str, Any]:
    if not CACHE_FILE_PATH.exists():
        return {}

    try:
        with CACHE_FILE_PATH.open("r", encoding="utf-8") as fp:
            return json.load(fp)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_cache(cache: Dict[str, Any]) -> None:
    _ensure_cache_file()
    with _CACHE_LOCK:
        with CACHE_FILE_PATH.open("w", encoding="utf-8") as fp:
            json.dump(cache, fp, ensure_ascii=False, indent=2)


def get_cache_entry(company: str) -> Optional[Dict[str, Any]]:
    cache = _load_cache()
    entry = cache.get(_normalize_company(company))
    if not entry:
        return None
    entry.setdefault("company", company)
    return entry


def is_cache_entry_fresh(entry: Dict[str, Any]) -> bool:
    cached_at = entry.get("cached_at")
    if not cached_at:
        return False

    try:
        timestamp = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
    except ValueError:
        return False

    # Use timezone-aware UTC now to match parsed timestamps
    now_utc = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        # treat naive timestamps as UTC
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return now_utc - timestamp < timedelta(seconds=CACHE_TTL_SECONDS)


def store_cache_entry(company: str, profile: Dict[str, Any], completed_at: str) -> None:
    normalized = _normalize_company(company)
    cache = _load_cache()
    cache[normalized] = {
        "company": company,
        "profile": profile,
        "completed_at": completed_at,
        "cached_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_cache(cache)


def entry_age_seconds(entry: Dict[str, Any]) -> Optional[float]:
    cached_at = entry.get("cached_at")
    if not cached_at:
        return None

    try:
        timestamp = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
    except ValueError:
        return None

    now_utc = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return (now_utc - timestamp).total_seconds()
