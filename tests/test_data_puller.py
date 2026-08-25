"""Coverage for data_puller's provider-gating logic (Task 13).

These monkeypatch `available` and the four fetch coroutines as they are bound
into hash_searcher.api.api_data_puller, never touching real environment state
or the network, so the tests are deterministic regardless of which API keys
(if any) happen to be set on the machine running them.
"""

from hash_searcher.api.api_data_puller import data_puller
from hash_searcher.api.base_call import make_error
from hash_searcher.api.registry import Provider
from hash_searcher.cache import ResponseCache

FAKE_VT_DATA = {
    "data": {"relationships": {"contacted_ips": {"data": [{"id": "198.51.100.10"}]}}}
}


def _provider(name: str) -> Provider:
    return Provider(name=name, key_env=None, indicator_types=(), fetch=None)


class _Recorder:
    """Call-recording async stub -- proves a fetch was never invoked, not
    just that its result was discarded."""

    def __init__(self, return_value):
        self.calls = []
        self._return_value = return_value

    async def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self._return_value


async def test_data_puller_runs_with_only_a_virustotal_key(monkeypatch):
    """The scenario this task exists for: one key present, three absent.

    VT itself reports an IP, which would normally fan out to AbuseIPDB and
    Censys -- but neither key is available, so those fetches must never run
    even though `ips` is non-empty.
    """
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [_provider("virustotal")],
    )

    vt_stub = _Recorder(FAKE_VT_DATA)
    otx_stub = _Recorder(None)
    ipdb_stub = _Recorder(None)
    censys_stub = _Recorder(None)

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", vt_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_otx", otx_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_ipdb", ipdb_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.fetch_censys", censys_stub)

    result = await data_puller("deadbeef", ResponseCache(enabled=False))

    # The disabled providers' fetches were never invoked -- not just absent
    # from the result.
    assert len(vt_stub.calls) == 1
    assert vt_stub.calls[0][0][1] == "deadbeef"  # (client, file_hash)
    assert otx_stub.calls == []
    assert ipdb_stub.calls == []
    assert censys_stub.calls == []

    assert result == {
        "vt": FAKE_VT_DATA,
        "otx": make_error("OTX key not set"),
        "ipdb": [],
        "censys": [],
        "ips": ["198.51.100.10"],
        "hash": "deadbeef",
    }


async def test_data_puller_returns_error_slots_when_no_keys_are_available(monkeypatch):
    """Zero keys: every slot degrades to make_error(...) and nothing fires."""
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [],
    )

    vt_stub = _Recorder(FAKE_VT_DATA)
    otx_stub = _Recorder(None)
    ipdb_stub = _Recorder(None)
    censys_stub = _Recorder(None)

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", vt_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_otx", otx_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_ipdb", ipdb_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.fetch_censys", censys_stub)

    result = await data_puller("deadbeef", ResponseCache(enabled=False))

    assert vt_stub.calls == []
    assert otx_stub.calls == []
    assert ipdb_stub.calls == []
    assert censys_stub.calls == []

    assert result == {
        "vt": make_error("VirusTotal key not set"),
        "otx": make_error("OTX key not set"),
        "ipdb": [],
        "censys": [],
        "ips": [],
        "hash": "deadbeef",
    }


async def test_a_second_run_serves_virustotal_from_the_cache(monkeypatch, tmp_path):
    """R27: the cache reached fetch_censys only. VT's free tier is 4/min and
    500/day, so VT is the provider that most needs it."""
    from hash_searcher.api.api_data_puller import data_puller
    from hash_searcher.api.registry import Provider
    from hash_searcher.cache import ResponseCache

    calls = []

    async def fake_get_vt(client, file_hash):
        calls.append(file_hash)
        return {"data": {"attributes": {}}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_get_vt)
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [Provider(name="virustotal", key_env=None, indicator_types=(), fetch=None)],
    )

    cache = ResponseCache(path=tmp_path / "c.db")
    await data_puller("deadbeef" * 8, cache)
    await data_puller("deadbeef" * 8, cache)
    cache.close()

    assert calls == ["deadbeef" * 8], "the second run should have hit the cache"


async def test_otx_and_abuseipdb_are_cached_too(monkeypatch, tmp_path):
    otx_calls, ipdb_calls = [], []

    async def fake_get_vt(client, file_hash):
        return FAKE_VT_DATA

    async def fake_get_otx(client, file_hash):
        otx_calls.append(file_hash)
        return {"pulse_info": {"count": 1, "pulses": []}}

    async def fake_get_ipdb(client, ip):
        ipdb_calls.append(ip)
        return {"data": {"ipAddress": ip, "abuseConfidenceScore": 10}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_get_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_otx", fake_get_otx)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_ipdb", fake_get_ipdb)
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [_provider("virustotal"), _provider("otx"), _provider("abuseipdb")],
    )

    cache = ResponseCache(path=tmp_path / "c.db")
    await data_puller("deadbeef" * 8, cache)
    await data_puller("deadbeef" * 8, cache)
    cache.close()

    assert otx_calls == ["deadbeef" * 8]
    assert ipdb_calls == ["198.51.100.10"]


async def test_refresh_bypasses_the_cache_for_every_provider(monkeypatch, tmp_path):
    """--refresh must still force fresh calls now that more providers are
    cached, and must re-cache what it fetched."""
    calls = []

    async def fake_get_vt(client, file_hash):
        calls.append(file_hash)
        return {"data": {"attributes": {}}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_get_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal")])

    path = tmp_path / "c.db"
    warm = ResponseCache(path=path)
    await data_puller("deadbeef" * 8, warm)
    warm.close()

    refreshing = ResponseCache(path=path, refresh=True)
    await data_puller("deadbeef" * 8, refreshing)
    refreshing.close()

    assert len(calls) == 2

    reading = ResponseCache(path=path)
    assert reading.get("virustotal", "deadbeef" * 8) is not None
    reading.close()


async def test_no_cache_disables_caching_entirely(monkeypatch, tmp_path):
    calls = []

    async def fake_get_vt(client, file_hash):
        calls.append(file_hash)
        return {"data": {"attributes": {}}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_get_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal")])

    for _ in range(2):
        cache = ResponseCache(enabled=False)
        await data_puller("deadbeef" * 8, cache)
        cache.close()

    assert len(calls) == 2


async def test_a_failed_virustotal_call_is_not_cached(monkeypatch, tmp_path):
    """cache.put refuses error payloads; this pins that the new VT path
    actually relies on that rather than storing a transient failure."""
    calls = []

    async def fake_get_vt(client, file_hash):
        calls.append(file_hash)
        return make_error("VirusTotal API Error 503", 503)

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_get_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal")])

    cache = ResponseCache(path=tmp_path / "c.db")
    await data_puller("deadbeef" * 8, cache)
    await data_puller("deadbeef" * 8, cache)
    cache.close()

    assert len(calls) == 2
