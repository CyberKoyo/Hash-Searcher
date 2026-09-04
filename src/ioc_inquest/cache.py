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


LEGACY_CACHE_DIR = "hash-searcher"


def cache_path() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    path = root / "ioc-inquest" / "responses.db"
    adopt_legacy_db(path, root / LEGACY_CACHE_DIR / "responses.db")
    return path


def adopt_legacy_db(path: Path, legacy: Path) -> None:
    """Carry a pre-rename database over to the current path, once.

    Renaming the project moved the cache directory out from under every
    installation that already had one. The response cache alone could be
    left to rebuild -- that is what a cache is for -- but the same file
    holds the rate budget's daily tally, and a tally that silently resets
    is one that lets a run believe it has 500 VirusTotal calls it has
    already spent.

    An existing database at `path` is the current one and is never
    overwritten, so this is a no-op on every run after the first. Failing
    to move leaves the caller with a fresh database rather than no
    database, which is the same degrade open_db already makes.
    """
    if path.exists() or not legacy.exists():
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        legacy.replace(path)
    except OSError:
        pass


def open_db(path: Path, ddl: tuple[str, ...], what: str):
    """Connect to the shared database and apply `ddl`, or None if we can't.

    Two things keep tables in this one file -- the response cache and the
    rate budget -- and they open it separately rather than sharing a
    connection, because --no-cache closes the cache's and the budget has to
    outlive that. So the open-and-degrade dance lives here rather than in
    either of them.

    Degrading rather than raising, because a file that is not a valid
    SQLite database used to come back out of __init__ uncaught and brick
    every subsequent run until the user found and deleted it by hand.
    sqlite3.connect() does not itself notice -- the first statement is what
    raises -- which is why the DDL runs inside this try and not after it.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        for statement in ddl:
            conn.execute(statement)
        conn.commit()
        return conn
    except (sqlite3.Error, OSError) as e:
        print(f"Warning: could not open the {what} at {path} ({e}); "
              f"continuing without a {what}.")
        return None


RESPONSES_DDL = (
    "CREATE TABLE IF NOT EXISTS responses ("
    " provider TEXT NOT NULL,"
    " key TEXT NOT NULL,"
    " stored_at REAL NOT NULL,"
    " payload TEXT NOT NULL,"
    " PRIMARY KEY (provider, key))",
)


class ResponseCache:
    def __init__(self, path=None, enabled: bool = True, refresh: bool = False):
        self.enabled = enabled
        self.refresh = refresh
        self._conn = None
        if not enabled:
            return
        path = Path(path) if path else cache_path()
        self._conn = open_db(path, RESPONSES_DDL, "response cache")
        self.enabled = self._conn is not None

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
