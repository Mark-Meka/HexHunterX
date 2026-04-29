"""
HexHunterX -- General Helpers.

Deduplication, hashing, timestamps, file I/O utilities.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def timestamp_now() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def generate_hash(data: str) -> str:
    """Generate SHA256 hash of a string."""
    return hashlib.sha256(data.encode()).hexdigest()


def short_hash(data: str, length: int = 8) -> str:
    """Generate a short hash for deduplication keys."""
    return generate_hash(data)[:length]


def deduplicate(items: list, key_func=None) -> list:
    """Deduplicate a list, preserving order."""
    seen = set()
    result = []
    for item in items:
        k = key_func(item) if key_func else item
        if k not in seen:
            seen.add(k)
            result.append(item)
    return result


def chunk_list(items: list, chunk_size: int) -> list[list]:
    """Split a list into chunks of given size."""
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def safe_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)


def ensure_dir(path: str | Path) -> Path:
    """Create directory if it doesn't exist and return the Path."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_json(data: Any, filepath: str | Path, indent: int = 2):
    """Save data to a JSON file."""
    filepath = Path(filepath)
    ensure_dir(filepath.parent)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, default=str)


def load_json(filepath: str | Path) -> Any:
    """Load data from a JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def load_wordlist(filepath: str | Path) -> list[str]:
    """Load a wordlist file, filtering comments and empty lines."""
    path = Path(filepath)
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def bytes_to_human(size: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def seconds_to_human(seconds: float) -> str:
    """Convert seconds to human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"
