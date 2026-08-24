import time

from hash_searcher.api.base_call import make_error
from hash_searcher.cache import ResponseCache, cache_path


def test_cache_path_lands_under_xdg_cache_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert cache_path().parent == tmp_path / "hash-searcher"


def test_round_trip(tmp_path):
    cache = ResponseCache(tmp_path / "c.db")
    cache.put("censys", "1.2.3.4", {"ok": True})
    assert cache.get("censys", "1.2.3.4") == {"ok": True}
    cache.close()


def test_miss_returns_none(tmp_path):
    cache = ResponseCache(tmp_path / "c.db")
    assert cache.get("censys", "unseen") is None
    cache.close()


def test_expired_entries_are_not_returned(tmp_path):
    cache = ResponseCache(tmp_path / "c.db")
    cache.put("censys", "1.2.3.4", {"ok": True})
    assert cache.get("censys", "1.2.3.4", ttl=0) is None
    cache.close()


def test_errors_are_never_cached(tmp_path):
    """A transient 403 used to get pinned for the full 24h TTL."""
    cache = ResponseCache(tmp_path / "c.db")
    cache.put("censys", "1.2.3.4", make_error("Censys 403", 403))
    assert cache.get("censys", "1.2.3.4") is None
    cache.close()


def test_providers_do_not_collide_on_the_same_key(tmp_path):
    cache = ResponseCache(tmp_path / "c.db")
    cache.put("censys", "1.2.3.4", {"src": "censys"})
    cache.put("greynoise", "1.2.3.4", {"src": "greynoise"})
    assert cache.get("censys", "1.2.3.4") == {"src": "censys"}
    assert cache.get("greynoise", "1.2.3.4") == {"src": "greynoise"}
    cache.close()


def test_refresh_ignores_hits_but_still_writes(tmp_path):
    cache = ResponseCache(tmp_path / "c.db")
    cache.put("censys", "1.2.3.4", {"v": 1})
    fresh = ResponseCache(tmp_path / "c.db", refresh=True)
    assert fresh.get("censys", "1.2.3.4") is None
    fresh.put("censys", "1.2.3.4", {"v": 2})
    fresh.close()
    assert ResponseCache(tmp_path / "c.db").get("censys", "1.2.3.4") == {"v": 2}


def test_disabled_cache_stores_nothing(tmp_path):
    cache = ResponseCache(tmp_path / "c.db", enabled=False)
    cache.put("censys", "1.2.3.4", {"ok": True})
    assert cache.get("censys", "1.2.3.4") is None
    cache.close()
