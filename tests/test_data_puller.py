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

FAKE_VT_DATA = {"found": True}


def _provider(name: str) -> Provider:
    return Provider(name=name, key_env=None, key_value=None,
                     indicator_types=(), fetch=None)


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

    vt_stub = _Recorder((FAKE_VT_DATA, ["198.51.100.10"]))
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

    vt_stub = _Recorder((FAKE_VT_DATA, ["198.51.100.10"]))
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
