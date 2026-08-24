"""Per-provider response cache.

Replaces the Censys-only censys_cache.json that was written into the package
directory. SQLite handles concurrent readers, and the file lives in the user's
cache dir where it belongs.
"""

import json
import os
import sqlite3
import time
from pathlib import Path

from .api.base_call import is_error

DEFAULT_TTL = 86400


def cache_path() -> Path:
    root = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(root) / "hash-searcher" / "responses.db"


class ResponseCache:
    def __init__(self, path=None, enabled: bool = True, refresh: bool = False):
        self.enabled = enabled
        self.refresh = refresh
        self._conn = None
        if not enabled:
            return
        path = Path(path) if path else cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS responses ("
            " provider TEXT NOT NULL,"
            " key TEXT NOT NULL,"
            " stored_at REAL NOT NULL,"
            " payload TEXT NOT NULL,"
            " PRIMARY KEY (provider, key))"
        )
        self._conn.commit()

    def get(self, provider: str, key: str, ttl: int = DEFAULT_TTL):
        if not self._conn or self.refresh:
            return None
        row = self._conn.execute(
            "SELECT stored_at, payload FROM responses WHERE provider = ? AND key = ?",
            (provider, key),
        ).fetchone()
        if not row:
            return None
        stored_at, payload = row
        if time.time() - stored_at >= ttl:
            return None
        return json.loads(payload)

    def put(self, provider: str, key: str, payload) -> None:
        # Only clean results. Caching a transient 403 pinned it for the full TTL.
        if not self._conn or is_error(payload):
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?)",
            (provider, key, time.time(), json.dumps(payload)),
        )
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
