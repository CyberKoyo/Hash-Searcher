"""Coverage for data_puller's provider-gating logic (Task 13).

These monkeypatch `available` and the four fetch coroutines as they are bound
into hash_searcher.api.api_data_puller, never touching real environment state
or the network, so the tests are deterministic regardless of which API keys
(if any) happen to be set on the machine running them.
"""

import pytest

from hash_searcher.api.api_data_puller import data_puller
from hash_searcher.api.base_call import error_message, is_error, make_error
from hash_searcher.api.registry import Provider, by_name
from hash_searcher.cache import ResponseCache
from hash_searcher.indicators import Indicator

FAKE_VT_DATA = {
    "data": {"relationships": {"contacted_ips": {"data": [{"id": "198.51.100.10"}]}}}
}


# A stand-in provider's timing must be unmistakable for a registry entry's.
# 42 seconds is nowhere near any real cache_ttl (3600 threatfox, 86400 most,
# 604800 rdap), and 0.0 is unlike the 1.0-2.0 the three serial sources
# declare. See _provider below for why that matters.
STUB_CACHE_TTL = 42
STUB_SERIAL_DELAY = 0.0


def _provider(name: str, *, cache_ttl: int = STUB_CACHE_TTL,
              serial_delay: float = STUB_SERIAL_DELAY) -> Provider:
    """Keyless stand-in for a registered provider.

    indicator_types comes from the real registry entry, because data_puller
    selects by indicator type and a stub declaring no types would be
    unreachable through for_indicator -- the exact condition test_registry's
    test_every_registered_provider_declares_at_least_one_indicator_type
    forbids in the registry itself.

    cache_ttl and serial_delay deliberately do not. Copying them off
    `by_name(name)`, which is what this helper did until fix round 2, made
    the patched pool and the global registry identical by construction, so
    no test built on this helper could tell a pool-sourced lookup from a
    global one -- which is the single property Task A5 exists to establish.
    Measured: reverting all eleven pool-aware lookups in data_puller to the
    pre-A5 global form reddened exactly one test, and it was the one test
    that did not use this helper.

    So the defaults here match nothing in PROVIDERS, and a test that needs a
    particular value states it as a literal at the call site rather than
    reading it back out of the very symbol it is supposed to be
    distinguishing itself from.

    serial_delay=0.0 also keeps this suite fast without anyone having to
    remember to stub sleep: a stub carrying censys's real 2.0 turns any test
    that hands fetch_serial a second indicator into a real two-second
    wall-clock sleep, and whether a test has one indicator or two is not the
    kind of thing that should decide how long the suite takes.
    """
    real = by_name(name)
    return Provider(name=name, key_env=None, indicator_types=real.indicator_types,
                    fetch=None, cache_ttl=cache_ttl, serial_delay=serial_delay)


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

    result = await data_puller(Indicator("hash", "deadbeef"), ResponseCache(enabled=False))

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
        # VT reported no contacted_domains, so the domain-typed sources have
        # nothing to run over -- and rdap is keyless, so this proves the
        # fan-out is gated on there being a domain at all, not on a key.
        "domains": [],
        "rdap": [],
        "crtsh": [],
        # Absent from the patched pool here, so they were never asked --
        # None rather than an error dict, which would claim a failed call.
        "bazaar": None,
        "threatfox": None,
        "threatfox_ips": {},
        "shodan": {},
        "greynoise": {},
        "kev": {},
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

    result = await data_puller(Indicator("hash", "deadbeef"), ResponseCache(enabled=False))

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
        "domains": [],
        "rdap": [],
        "crtsh": [],
        "bazaar": None,
        "threatfox": None,
        "threatfox_ips": {},
        "shodan": {},
        "greynoise": {},
        "kev": {},
    }


async def test_a_second_run_serves_virustotal_from_the_cache(monkeypatch, tmp_path):
    """R27: the cache reached fetch_censys only. VT's free tier is 4/min and
    500/day, so VT is the provider that most needs it.

    _provider rather than a hand-built stand-in: the hand-built one left
    cache_ttl at the Provider dataclass's 86400 default, which happens to be
    exactly VirusTotal's registry value, so the pool and PROVIDERS agreed by
    accident here too.
    """
    calls = []

    async def fake_get_vt(client, file_hash):
        calls.append(file_hash)
        return {"data": {"attributes": {}}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_get_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal")])

    cache = ResponseCache(path=tmp_path / "c.db")
    await data_puller(Indicator("hash", "deadbeef" * 8), cache)
    await data_puller(Indicator("hash", "deadbeef" * 8), cache)
    cache.close()

    assert calls == ["deadbeef" * 8], "the second run should have hit the cache"


async def test_otx_and_abuseipdb_are_cached_too(monkeypatch, tmp_path):
    otx_calls, ipdb_calls = [], []

    async def fake_get_vt(client, file_hash):
        return FAKE_VT_DATA

    async def fake_get_otx(client, file_hash, indicator_type="file"):
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
    await data_puller(Indicator("hash", "deadbeef" * 8), cache)
    await data_puller(Indicator("hash", "deadbeef" * 8), cache)
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
    await data_puller(Indicator("hash", "deadbeef" * 8), warm)
    warm.close()

    refreshing = ResponseCache(path=path, refresh=True)
    await data_puller(Indicator("hash", "deadbeef" * 8), refreshing)
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
        await data_puller(Indicator("hash", "deadbeef" * 8), cache)
        cache.close()

    assert len(calls) == 2


async def test_ips_harvested_from_strings_reach_abuseipdb(monkeypatch):
    """Closing the loop: a sample nobody has uploaded still yields IPs to
    enrich, which is the entire argument for the strings analyzer."""
    from hash_searcher.api.api_data_puller import data_puller
    from hash_searcher.cache import ResponseCache

    seen = []

    async def fake_ipdb(client, ip):
        seen.append(ip)
        return {"data": {"ipAddress": ip, "abuseConfidenceScore": 10}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_ipdb", fake_ipdb)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("abuseipdb")])

    await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False),
                      extra_ips=["198.51.100.10"])
    assert seen == ["198.51.100.10"]


async def test_extra_ips_merge_with_vts_own_without_duplicating(monkeypatch):
    """An IP that VT reported AND the strings contain must be looked up once,
    not twice -- AbuseIPDB's free tier is 1000 requests/day."""
    from hash_searcher.api.api_data_puller import data_puller
    from hash_searcher.cache import ResponseCache

    seen = []

    async def fake_ipdb(client, ip):
        seen.append(ip)
        return {"data": {"ipAddress": ip}}

    async def fake_vt(client, file_hash):
        return {"data": {"relationships": {"contacted_ips": {
            "data": [{"id": "198.51.100.10"}]
        }}}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_ipdb", fake_ipdb)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal"), _provider("abuseipdb")])

    await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False),
                      extra_ips=["198.51.100.10", "203.0.113.7"])
    assert seen == ["198.51.100.10", "203.0.113.7"]


async def test_extra_ips_merge_is_capped_at_ioc_limit(monkeypatch):
    """extra_ips can arrive already at Task 6's 50-entry cap. VT can also
    report its own IPs. The merge must not concatenate the two into
    something bigger than the cap -- that is the exact failure this task
    exists to prevent."""
    from hash_searcher.api.api_data_puller import data_puller
    from hash_searcher.api.api_data_puller import IOC_LIMIT
    from hash_searcher.cache import ResponseCache

    seen = []

    async def fake_ipdb(client, ip):
        seen.append(ip)
        return {"data": {"ipAddress": ip}}

    async def fake_vt(client, file_hash):
        return {"data": {"relationships": {"contacted_ips": {
            "data": [{"id": "10.0.0.1"}, {"id": "10.0.0.2"}]
        }}}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_ipdb", fake_ipdb)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal"), _provider("abuseipdb")])

    extra = [f"203.0.113.{i}" for i in range(IOC_LIMIT)]  # already at the cap
    await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False), extra_ips=extra)

    assert len(seen) == IOC_LIMIT
    # VT's own IPs come first and must not be pushed out by the cap.
    assert seen[0] == "10.0.0.1"
    assert seen[1] == "10.0.0.2"


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
    await data_puller(Indicator("hash", "deadbeef" * 8), cache)
    await data_puller(Indicator("hash", "deadbeef" * 8), cache)
    cache.close()

    assert len(calls) == 2


async def test_only_providers_for_the_indicator_type_are_called(monkeypatch):
    """Constraint 5: a domain-only source must never be handed a hash. The
    bug this prevents is silent -- crt.sh would answer 200 with an empty
    list for a hash query, so nothing would look wrong."""
    from hash_searcher.api.api_data_puller import data_puller
    from hash_searcher.api.registry import Provider
    from hash_searcher.cache import ResponseCache

    called = []

    async def spy_crtsh(client, domain, **kwargs):
        called.append(domain)
        return []

    async def fake_vt(client, file_hash, **kwargs):
        # No relationships block: no contacted IPs, no contacted domains.
        return {"data": {"attributes": {}}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_crtsh", spy_crtsh)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available", lambda: [
        Provider("virustotal", None, ("hash",), fake_vt),
        Provider("crtsh", None, ("domain",), spy_crtsh),
    ])

    await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False))
    assert called == []


async def test_the_kev_catalog_is_not_fetched_when_shodan_found_no_cves(monkeypatch):
    """KEV is a 1MB download. Pulling it for a sample with nothing to
    intersect it against is the waste the local-intersection design exists
    to avoid."""
    from hash_searcher.api.api_data_puller import data_puller
    from hash_searcher.api.registry import Provider
    from hash_searcher.cache import ResponseCache

    fetched = []

    async def spy_kev(client, **kwargs):
        fetched.append(True)
        return {"vulnerabilities": []}

    async def fake_vt(client, file_hash, **kwargs):
        return {"data": {"relationships": {
            "contacted_ips": {"data": [{"id": "198.51.100.10"}]}}}}

    async def fake_shodan(client, ip, **kwargs):
        return {"ports": [80], "vulns": []}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_kev", spy_kev)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_shodan", fake_shodan)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available", lambda: [
        Provider("virustotal", None, ("hash",), fake_vt),
        Provider("shodan", None, ("ip",), fake_shodan),
    ])

    result = await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False))
    assert fetched == []
    assert result["kev"] == {}


async def test_the_kev_catalog_is_fetched_once_when_a_cve_turns_up(monkeypatch):
    from hash_searcher.api.api_data_puller import data_puller
    from hash_searcher.api.registry import Provider
    from hash_searcher.cache import ResponseCache

    fetched = []

    async def spy_kev(client, **kwargs):
        fetched.append(True)
        return {"vulnerabilities": [{"cveID": "CVE-2021-41617"}]}

    async def fake_vt(client, file_hash, **kwargs):
        return {"data": {"relationships": {"contacted_ips": {
            "data": [{"id": "198.51.100.10"}, {"id": "203.0.113.7"}]}}}}

    async def fake_shodan(client, ip, **kwargs):
        return {"ports": [22], "vulns": ["CVE-2021-41617"]}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_kev", spy_kev)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_shodan", fake_shodan)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available", lambda: [
        Provider("virustotal", None, ("hash",), fake_vt),
        Provider("shodan", None, ("ip",), fake_shodan),
    ])

    result = await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False))
    # Two IPs, both reporting the same CVE: still one catalog download.
    assert len(fetched) == 1
    assert result["kev"]["vulnerabilities"] == [{"cveID": "CVE-2021-41617"}]


FAKE_VT_TWO_IPS = {
    "data": {"relationships": {"contacted_ips": {"data": [
        {"id": "198.51.100.10"}, {"id": "203.0.113.7"},
    ]}}}
}

THREATFOX_HIT = {"query_status": "ok", "data": [
    {"malware_printable": "Emotet", "confidence_level": 90, "tags": ["botnet", "c2"]},
]}


async def test_threatfox_is_asked_about_every_contacted_ip_not_just_the_sample(monkeypatch):
    """Phase 4 deferred this and said why: report.threatfox was a single
    field. ThreatFox's dataset is overwhelmingly C2 addresses, and neither
    Shodan (exposure) nor GreyNoise (noise-vs-targeted) names a family, so
    querying it on the hash alone throws away the answer it is best at.
    """
    async def fake_vt(client, file_hash, **kwargs):
        return FAKE_VT_TWO_IPS

    asked = []

    async def spy_threatfox(client, indicator, **kwargs):
        asked.append(indicator)
        return THREATFOX_HIT

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_threatfox",
                        spy_threatfox)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal"), _provider("threatfox")])

    result = await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False))

    assert sorted(asked) == sorted(["a" * 64, "198.51.100.10", "203.0.113.7"])
    # Keyed by IP, the way shodan and greynoise are.
    assert list(result["threatfox_ips"]) == ["198.51.100.10", "203.0.113.7"]
    assert result["threatfox_ips"]["203.0.113.7"] == THREATFOX_HIT
    # The sample-level lookup keeps its own slot and its own meaning.
    assert result["threatfox"] == THREATFOX_HIT


def _backdate(path, provider: str, seconds: float) -> None:
    """Push one provider's cached rows `seconds` into the past.

    Reaching into the sqlite file rather than monkeypatching time.time: the
    ttl is read inside _cached/fetch_serial from the Provider the caller
    passed in, and this proves which number it actually read rather than
    restating the constant.
    """
    import sqlite3
    import time

    conn = sqlite3.connect(path)
    conn.execute("UPDATE responses SET stored_at = ? WHERE provider = ?",
                 (time.time() - seconds, provider))
    conn.commit()
    conn.close()


async def test_the_per_ip_threatfox_lookups_expire_after_an_hour(monkeypatch, tmp_path):
    """Constraint 6: ThreatFox's C2 data turns over hourly, so its registry
    entry sets cache_ttl=3600 rather than the day every other source gets.
    The per-IP fan-out must inherit that, not the 86400 default -- a stale
    C2 attribution is worse than none.

    The 3600 is written out twice here on purpose, as two literals: once
    asserted against the registry entry, and once handed to the stub pool
    this run actually reads its ttl from. _provider's defaults deliberately
    match nothing in PROVIDERS (see its docstring), so a stub that wants the
    registry's number has to say the number -- and saying it is what keeps
    this test pinning ThreatFox's hour rather than whatever the registry
    happens to hold at the time.
    """
    assert by_name("threatfox").cache_ttl == 3600, (
        "Constraint 6: ThreatFox's registry entry must stay at an hour"
    )

    async def fake_vt(client, file_hash, **kwargs):
        return {"data": {"relationships": {"contacted_ips": {
            "data": [{"id": "198.51.100.10"}]}}}}

    calls = []

    async def spy_threatfox(client, indicator, **kwargs):
        calls.append(indicator)
        return THREATFOX_HIT

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_threatfox",
                        spy_threatfox)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal"),
                                 _provider("threatfox", cache_ttl=3600)])

    file_hash = "a" * 64
    path = tmp_path / "c.db"

    async def run():
        cache = ResponseCache(path=path)
        await data_puller(Indicator("hash", file_hash), cache)
        cache.close()

    await run()
    assert sorted(calls) == sorted([file_hash, "198.51.100.10"])

    _backdate(path, "threatfox", 1800)   # half an hour old
    await run()
    assert len(calls) == 2, "a 30-minute-old ThreatFox answer is still fresh"

    _backdate(path, "threatfox", 5400)   # ninety minutes old
    await run()
    assert sorted(calls) == sorted(
        [file_hash, "198.51.100.10"] * 2), (
        "past the hourly TTL both ThreatFox lookups must be made again"
    )


async def test_the_per_ip_threatfox_fan_out_is_bounded(monkeypatch):
    """Constraint 8. `ips` reaches IOC_LIMIT entries, and a bare gather over
    them opens fifty simultaneous POSTs at one free abuse.ch endpoint --
    the same failure _bounded_gather was written for on the RDAP fan-out.
    """
    import asyncio

    from hash_searcher.api.api_data_puller import IOC_LIMIT
    from hash_searcher.api.threatfox import THREATFOX_CONCURRENCY

    file_hash = "a" * 64
    ips = [f"198.51.100.{n}" for n in range(IOC_LIMIT)]

    async def fake_vt(client, indicator, **kwargs):
        return {"data": {"relationships": {"contacted_ips": {
            "data": [{"id": ip} for ip in ips]}}}}

    in_flight, peak = [], [0]

    async def spy_threatfox(client, indicator, **kwargs):
        # The hash lookup is a separate single call, not part of the fan-out
        # this test bounds -- counting it would measure the wrong thing.
        counted = indicator != file_hash
        if counted:
            in_flight.append(indicator)
            peak[0] = max(peak[0], len(in_flight))
        await asyncio.sleep(0)
        if counted:
            in_flight.pop()
        return {"query_status": "no_result", "data": []}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_threatfox",
                        spy_threatfox)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal"), _provider("threatfox")])

    result = await data_puller(Indicator("hash", file_hash), ResponseCache(enabled=False))

    assert len(result["threatfox_ips"]) == IOC_LIMIT
    # A hardcoded ceiling, not one derived from THREATFOX_CONCURRENCY: the
    # assertion below compares the observed peak against that same live
    # symbol, so widening the constant would otherwise recompute its own
    # expected value and pass. The bound exists to keep one free abuse.ch
    # endpoint from seeing a burst, and a cap near IOC_LIMIT bounds it only
    # nominally.
    assert THREATFOX_CONCURRENCY <= 10 < IOC_LIMIT
    assert peak[0] == THREATFOX_CONCURRENCY, (
        f"{peak[0]} ThreatFox calls were in flight at once; an unbounded "
        f"gather peaks at {IOC_LIMIT}"
    )


async def test_censys_is_reached_end_to_end_through_data_puller(monkeypatch):
    """fetch_censys picked up a fourth argument (Task A5's `provider`), and
    data_puller's censys_task line -- `fetch_censys(client, ips, cache,
    by_name("censys", pool))` -- is the only place that constructs that
    call. No other test puts "censys" in the patched pool, so that call
    site went unexercised: a wrong arity there would only have surfaced as
    a silently-swallowed extra argument to _Recorder.__call__(*args,
    **kwargs) in the tests that do monkeypatch fetch_censys wholesale, or
    not at all. This puts censys in the pool and lets it run for real (down
    to the stubbed get_censys), so the 4-argument call is actually made.

    Two IPs, not one. Until fix round 2 this test ran the real fetch_serial
    against a stub carrying censys's registry serial_delay of 2.0, and was
    fast only because FAKE_VT_DATA happens to yield exactly one contacted IP
    and fetch_serial sleeps only *between* real requests: a second IP here
    would have bought the offline suite a real two-second sleep. _provider
    now declares serial_delay=0.0 (see its docstring), so the second
    indicator costs nothing, and running two is what demonstrates it rather
    than merely asserting it.
    """
    async def fake_vt(client, file_hash, **kwargs):
        return FAKE_VT_TWO_IPS

    calls = []

    async def fake_censys(client, ip, **kwargs):
        calls.append(ip)
        return {"ip": ip, "services": []}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_censys", fake_censys)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider("virustotal"), _provider("censys")])

    result = await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False))

    assert calls == ["198.51.100.10", "203.0.113.7"]
    assert result["censys"] == [{"ip": ip, "services": []} for ip in calls]


FAKE_VT_TWO_IPS_TWO_DOMAINS = {
    "data": {"relationships": {
        "contacted_ips": {"data": [{"id": "198.51.100.10"},
                                   {"id": "203.0.113.7"}]},
        "contacted_domains": {"data": [{"id": "bad.example"},
                                       {"id": "worse.example"}]},
    }}
}

# Every cache namespace data_puller resolves a Provider for out of its
# caller's pool: (namespace, the coroutine data_puller calls it through, a
# clean payload). threatfox is listed once and resolved twice -- once for
# the sample, once for the per-IP fan-out -- and both resolutions are
# covered, because the assertions below are per (namespace, indicator) pair
# rather than per namespace. The CISA KEV catalog is deliberately absent: it
# is cached like a provider but is not one, has no pool entry to resolve,
# and passes its namespace and ttl as two literals.
EVERY_POOL_SITE = (
    ("virustotal",    "get_vt",        FAKE_VT_TWO_IPS_TWO_DOMAINS),
    ("otx",           "get_otx",       {"pulse_info": {"count": 1, "pulses": []}}),
    ("malwarebazaar", "get_bazaar",    {"query_status": "ok", "data": []}),
    ("threatfox",     "get_threatfox", {"query_status": "no_result", "data": []}),
    ("abuseipdb",     "get_ipdb",      {"data": {}}),
    ("censys",        "get_censys",    {"result": {"resource": {}}}),
    ("shodan",        "get_shodan",    {"ports": [80], "vulns": []}),
    ("greynoise",     "get_greynoise", {"noise": False}),
    ("rdap",          "get_rdap",      {"events": []}),
    ("crtsh",         "get_crtsh",     []),
)


async def test_every_provider_site_reads_its_timing_from_the_pool_not_the_registry(
        monkeypatch, tmp_path):
    """Task A5's whole property, at every site rather than at one of them.

    data_puller resolves eleven Providers out of the pool it was handed.
    Until fix round 2 only one of those eleven was pinned: reverting all
    eleven to the pre-A5 global form (`by_name(X, pool)` -> `by_name(X)`)
    reddened exactly one test, covering virustotal, and reverting the censys
    path all the way back to its three-argument pre-A5 shape reddened none
    at all. The reason was in the fixture, not in the assertions: _provider
    copied cache_ttl and serial_delay off the live registry entry, so the
    patched pool and PROVIDERS held the same numbers and no test built on it
    could tell which one had been read.

    So: every site at once, with a pool whose timing matches nothing in the
    registry. Each stub declares cache_ttl=42; every real entry is 3600 or
    more. Run once to fill the cache, push every row 100 seconds into the
    past -- comfortably past 42, nowhere near 3600 -- and run again. A site
    reading its ttl from the pool must refetch. A site that resolved against
    the global PROVIDERS instead reads a 100-second-old row as fresh and
    skips its call, and the assertion names it.

    The same run pins serial_delay for the three serial sites, from the
    other direction: censys, greynoise and crtsh each get two indicators, so
    fetch_serial's between-requests sleep runs, and the pool says 0.0 where
    the registry says 2.0, 1.0 and 2.0. Recording sleeps rather than
    incurring them keeps that free.
    """
    asked = []

    def spy(namespace, payload):
        async def fetch(client, indicator, **kwargs):
            asked.append((namespace, indicator))
            return payload
        return fetch

    for namespace, attribute, payload in EVERY_POOL_SITE:
        monkeypatch.setattr(f"hash_searcher.api.api_data_puller.{attribute}",
                            spy(namespace, payload))
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [_provider(namespace) for namespace, _, _ in EVERY_POOL_SITE],
    )

    slept = []

    async def record_sleep(seconds):
        slept.append(seconds)

    # Reads module-local, is process-wide -- see
    # test_fetch_serial_reads_serial_delay_from_the_passed_provider. Here it
    # is a measurement rather than a speed fix: the pool already declares
    # 0.0, and what this records is which number fetch_serial actually read.
    monkeypatch.setattr("hash_searcher.api.api_data_puller.asyncio.sleep",
                        record_sleep)

    path = tmp_path / "c.db"
    file_hash = "a" * 64

    async def run():
        cache = ResponseCache(path=path)
        await data_puller(Indicator("hash", file_hash), cache)
        cache.close()

    await run()
    first = list(asked)
    assert {namespace for namespace, _ in first} == {
        namespace for namespace, _, _ in EVERY_POOL_SITE}, (
        "every site has to be reached for this to prove anything about it; "
        f"reached {sorted({n for n, _ in first})}"
    )

    for namespace, _, _ in EVERY_POOL_SITE:
        _backdate(path, namespace, 100)

    asked.clear()
    await run()

    served_stale = sorted(set(first) - set(asked))
    assert not served_stale, (
        f"{served_stale} came back out of a cache row 100 seconds old. "
        "Every provider in the patched pool declares cache_ttl=42, so a "
        "100-second-old row can only read as fresh where the ttl came from "
        "the global PROVIDERS -- whose smallest is threatfox's 3600 -- "
        "instead of from the pool data_puller was actually handed."
    )
    assert sorted(asked) == sorted(first)

    assert slept, (
        "censys, greynoise and crtsh each take two indicators here, so "
        "fetch_serial's between-requests sleep must have run"
    )
    assert set(slept) == {0.0}, (
        f"fetch_serial slept for {sorted(set(slept))}; the patched pool "
        "declares serial_delay=0.0 throughout, and only the global registry "
        "declares 1.0 (greynoise) or 2.0 (censys, crtsh)"
    )


async def test_fetch_serial_reads_ttl_from_the_passed_provider_not_the_registry(tmp_path):
    """Phase 4 review Minor #14: fetch_serial resolved its provider with
    by_name(name) against the global PROVIDERS, so a caller-supplied pool's
    cache_ttl was silently ignored -- every existing test hid this because
    its stubs happened to reuse real provider names, which PROVIDERS also
    has entries for. A provider named 'fictional', which PROVIDERS has no
    entry for at all, proves the coupling is gone: fetch_serial must read
    cache_ttl off the Provider object it is handed, not look one up.
    """
    from hash_searcher.api.api_data_puller import fetch_serial

    provider = Provider(name="fictional", key_env=None, indicator_types=("ip",),
                        fetch=None, cache_ttl=1)

    calls = []

    async def fetch(client, indicator):
        calls.append(indicator)
        return {"ok": True}

    path = tmp_path / "c.db"
    cache = ResponseCache(path=path)
    await fetch_serial(None, provider, fetch, ["203.0.113.1"], cache)
    cache.close()

    # 2s past the stub's 1s ttl -- and nowhere near the 86400s default the
    # registry would hand out for a name it actually recognized.
    _backdate(path, "fictional", 2)

    cache = ResponseCache(path=path)
    await fetch_serial(None, provider, fetch, ["203.0.113.1"], cache)
    cache.close()

    assert calls == ["203.0.113.1", "203.0.113.1"], (
        "the second call must have re-fetched -- the passed provider's 1s "
        "ttl had elapsed"
    )


async def test_cached_reads_ttl_from_the_passed_provider_not_the_registry(tmp_path):
    """Same defect, same fix, for _cached: ttl came from by_name(name)
    against PROVIDERS whenever the caller didn't pass one explicitly (only
    the CISA KEV catalog does, because it isn't a provider). A name absent
    from PROVIDERS entirely proves _cached now reads cache_ttl -- and the
    cache namespace itself -- off the Provider object rather than looking
    either up from a separately-passed name.
    """
    from hash_searcher.api.api_data_puller import _cached

    provider = Provider(name="fictional", key_env=None, indicator_types=("hash",),
                        fetch=None, cache_ttl=1)

    calls = []

    async def fetch():
        calls.append(True)
        return {"ok": True}

    path = tmp_path / "c.db"
    cache = ResponseCache(path=path)
    await _cached(cache, "k", fetch, provider=provider)
    cache.close()

    _backdate(path, "fictional", 2)

    cache = ResponseCache(path=path)
    await _cached(cache, "k", fetch, provider=provider)
    cache.close()

    assert len(calls) == 2, (
        "the second call must have re-fetched -- the passed provider's 1s "
        "ttl had elapsed"
    )


async def test_data_puller_honors_the_patched_pools_cache_ttl_not_the_registrys(monkeypatch, tmp_path):
    """The binding requirement, exercised end to end: a caller's provider
    pool must reach the code that reads cache TTL, not just the code that
    decides whether a source runs at all.

    data_puller's selection is still gated on the literal 'virustotal'
    check (Task A5 doesn't touch that dispatch), so this stub has to reuse
    that name -- but it overrides cache_ttl to 1s, far below the real
    registry entry's 86400s default. If _cached ever fell back to
    by_name('virustotal') against the global PROVIDERS instead of the
    provider data_puller resolved from its own patched pool, a two-second-
    old row would still read as fresh and the second call would never
    happen.
    """
    calls = []

    async def fake_vt(client, file_hash):
        calls.append(file_hash)
        return {"data": {"attributes": {}}}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", fake_vt)
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [Provider(name="virustotal", key_env=None,
                          indicator_types=("hash",), fetch=None,
                          cache_ttl=1)],
    )

    path = tmp_path / "c.db"
    file_hash = "deadbeef" * 8

    cache = ResponseCache(path=path)
    await data_puller(Indicator("hash", file_hash), cache)
    cache.close()

    _backdate(path, "virustotal", 2)

    cache = ResponseCache(path=path)
    await data_puller(Indicator("hash", file_hash), cache)
    cache.close()

    assert calls == [file_hash, file_hash], (
        "the pool's 1s ttl had elapsed; the registry's 86400s default "
        "would have served this from cache instead"
    )


async def test_fetch_serial_reads_serial_delay_from_the_passed_provider(monkeypatch):
    """The brief's requirement names TTL *and* serial delay; every ttl test
    above uses one indicator, so `called` never turns True before the loop
    ends and the sleep branch never runs. Two indicators and a non-zero
    serial_delay close that gap.

    asyncio.sleep is stubbed rather than left real, because a real 5.0s
    serial_delay would really sleep in what is supposed to be a fast suite
    and nothing else in scope prevents that: conftest.py's no_backoff
    fixture is not autouse (only block_network is) and this test does not
    request it.

    Not, as this docstring claimed until fix round 2, because no_backoff is
    scoped to base_call. It is not scoped to anything. Measured:
    `base_call.asyncio is api_data_puller.asyncio is asyncio` is True, so
    monkeypatching "hash_searcher.api.base_call.asyncio.sleep" resolves the
    dotted path to the one shared asyncio module object and replaces
    asyncio.sleep for the whole process, fetch_serial included. The same is
    true of the patch below: it reads as module-local and is not. Both are
    undone by monkeypatch at teardown, so the reach is a hazard for the next
    reader's mental model rather than for this test.
    """
    from hash_searcher.api.api_data_puller import fetch_serial

    provider = Provider(name="fictional", key_env=None, indicator_types=("ip",),
                        fetch=None, cache_ttl=86400, serial_delay=5.0)

    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr("hash_searcher.api.api_data_puller.asyncio.sleep", fake_sleep)

    async def fetch(client, indicator):
        return {"ok": True}

    cache = ResponseCache(enabled=False)
    await fetch_serial(None, provider, fetch, ["203.0.113.1", "203.0.113.2"], cache)

    assert slept == [5.0], (
        "exactly one sleep, before the second call (never before the "
        "first), at the passed provider's serial_delay -- not the "
        "registry's, and not zero"
    )


async def test_cached_accepts_exactly_two_of_its_eight_argument_combinations():
    """A namespace and the ttl governing it must arrive from one place.

    _cached has three optional arguments and therefore eight
    supplied/omitted combinations. Exactly two are meaningful: a `provider`
    alone (namespace and ttl both read off it), or `namespace` and `ttl`
    together (the CISA KEV catalog, cached like a provider but not one).

    The other six are enumerated here rather than sampled, because three of
    them were accepted until fix round 2 and each was a live instance of the
    bug this whole task exists to remove:

    - provider + ttl  -- a namespace governed by a ttl that did not come
      from the provider that owns the namespace. Exactly the Phase 4 Minor
      #14 shape, back in the signature after being driven out of the call
      sites.
    - provider + namespace, with or without a ttl -- two namespaces offered
      and `namespace` silently dropped, so a caller asking for "cisa_kev"
      got a megabyte of catalog written into some provider's own rows under
      the key "catalog", colliding on the cache's (provider, key) primary
      key.

    The remaining three (namespace alone, ttl alone, nothing at all) were
    already rejected and stay rejected: by_name exists so a missing provider
    fails with a message naming what is missing rather than an
    AttributeError three lines later, and _cached's own arguments get the
    same treatment.
    """
    from hash_searcher.api.api_data_puller import _cached

    provider = _provider("otx")

    async def fetch():
        return {"ok": True}

    accepted = [
        {"provider": provider},
        {"namespace": "cisa_kev", "ttl": 604800},
    ]
    rejected = [
        {"provider": provider, "ttl": 7},
        {"provider": provider, "namespace": "threatfox"},
        {"provider": provider, "namespace": "threatfox", "ttl": 7},
        {"namespace": "threatfox"},
        {"ttl": 7},
        {},
    ]
    assert len(accepted) + len(rejected) == 8, "every combination, not a sample"

    for kwargs in accepted:
        assert await _cached(ResponseCache(enabled=False), "k", fetch,
                             **kwargs) == {"ok": True}, kwargs

    for kwargs in rejected:
        with pytest.raises(TypeError, match="never a mixture"):
            await _cached(ResponseCache(enabled=False), "k", fetch, **kwargs)


async def test_a_provider_name_is_rejected_where_a_provider_belongs():
    """The pre-A5 convention passed a provider's *name* to these functions,
    and `fetch_serial(client, "greynoise", get_greynoise, ips, cache)` is
    still arity-compatible with today's signature -- so the stale form
    copied out of git history, or out of any document written before this
    task, reaches the callee and dies there as `'str' object has no
    attribute 'name'`, naming neither the caller nor the argument.

    That is verbatim the failure mode by_name was introduced to remove, and
    the guard _cached grew in fix round 1 covers. All three functions that
    take a resolved Provider get it, each naming itself, so no one has to
    guess which of them was handed the wrong thing.
    """
    from hash_searcher.api.api_data_puller import (
        _cached, fetch_censys, fetch_serial,
    )

    async def fetch():
        return {"ok": True}

    async def fetch_one(client, indicator):
        return {"ok": True}

    cache = ResponseCache(enabled=False)

    for wrong in ("greynoise", 42, object()):
        with pytest.raises(TypeError, match=r"fetch_serial needs the resolved Provider"):
            await fetch_serial(None, wrong, fetch_one, ["203.0.113.1"], cache)
        with pytest.raises(TypeError, match=r"fetch_censys needs the resolved Provider"):
            await fetch_censys(None, ["203.0.113.1"], cache, wrong)
        with pytest.raises(TypeError, match=r"_cached needs the resolved Provider"):
            await _cached(cache, "k", fetch, provider=wrong)


# --- Task B2: the entry is keyed by indicator kind ---------------------------
#
# `for_indicator()` has selected providers by type since Phase 4, but the ip
# and domain providers only ever saw indicators VirusTotal handed them. These
# pin that an ip or a domain typed on the command line reaches exactly the
# same providers, without a VT-by-hash call standing in front of them.


async def test_an_ip_indicator_reaches_every_ip_source_and_never_virustotal(
        monkeypatch):
    """`hash-searcher 198.51.100.10`. VT answers for file hashes only, so
    calling it here would spend a 4-per-minute quota on a guaranteed 404."""
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [_provider(name) for name in
                 ("virustotal", "abuseipdb", "censys", "shodan", "greynoise",
                  "threatfox", "otx")],
    )

    vt_stub = _Recorder(FAKE_VT_DATA)
    ipdb_stub = _Recorder({"data": {}})
    censys_stub = _Recorder([{"ip": "198.51.100.10"}])
    shodan_stub = _Recorder({"ip": "198.51.100.10"})
    greynoise_stub = _Recorder({"noise": True})
    threatfox_stub = _Recorder({"query_status": "ok"})
    otx_stub = _Recorder({})

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", vt_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_ipdb", ipdb_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.fetch_censys", censys_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_shodan", shodan_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_greynoise", greynoise_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_threatfox", threatfox_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_otx", otx_stub)

    result = await data_puller(Indicator("ip", "198.51.100.10"),
                               ResponseCache(enabled=False))

    assert vt_stub.calls == []
    assert result["ips"] == ["198.51.100.10"]
    for stub in (ipdb_stub, shodan_stub, greynoise_stub):
        assert [call[0][1] for call in stub.calls] == ["198.51.100.10"]
    assert censys_stub.calls  # fetch_censys(client, ips, cache, provider)
    assert censys_stub.calls[0][0][1] == ["198.51.100.10"]
    assert otx_stub.calls[0][0][1] == "198.51.100.10"
    # ThreatFox answered for the address through the per-IP fan-out, which is
    # the same question the sample-level slot would have asked -- so it is
    # asked once, not twice, and the answer lands where an IP's answer lives.
    assert result["threatfox_ips"] == {"198.51.100.10": {"query_status": "ok"}}
    assert result["threatfox"] is None
    assert len(threatfox_stub.calls) == 1


async def test_an_ip_indicator_types_its_otx_lookup(monkeypatch):
    """OTX is one endpoint per indicator type. Asking the `file` endpoint
    about an address returns a 404 that reads as "OTX has never seen it"."""
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [_provider("otx")],
    )
    otx_stub = _Recorder({})
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_otx", otx_stub)

    await data_puller(Indicator("ip", "198.51.100.10"), ResponseCache(enabled=False))
    assert otx_stub.calls[0][1]["indicator_type"] == "IPv4"

    otx_stub.calls.clear()
    await data_puller(Indicator("ip", "2001:db8::1"), ResponseCache(enabled=False))
    assert otx_stub.calls[0][1]["indicator_type"] == "IPv6"

    otx_stub.calls.clear()
    await data_puller(Indicator("domain", "evil.example"), ResponseCache(enabled=False))
    assert otx_stub.calls[0][1]["indicator_type"] == "domain"

    otx_stub.calls.clear()
    await data_puller(Indicator("hash", "a" * 64), ResponseCache(enabled=False))
    assert otx_stub.calls[0][1]["indicator_type"] == "file"


async def test_a_domain_indicator_reaches_the_domain_sources(monkeypatch):
    """`hash-searcher evil.example`: RDAP, crt.sh, and ThreatFox."""
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [_provider(name) for name in
                 ("virustotal", "rdap", "crtsh", "threatfox", "abuseipdb")],
    )

    vt_stub = _Recorder(FAKE_VT_DATA)
    rdap_stub = _Recorder({"handle": "x"})
    crtsh_stub = _Recorder([{"name_value": "evil.example"}])
    threatfox_stub = _Recorder({"query_status": "ok"})
    ipdb_stub = _Recorder({"data": {}})

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", vt_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_rdap", rdap_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_crtsh", crtsh_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_threatfox", threatfox_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_ipdb", ipdb_stub)

    result = await data_puller(Indicator("domain", "evil.example"),
                               ResponseCache(enabled=False))

    assert vt_stub.calls == []
    assert ipdb_stub.calls == []          # no IP to fan out over
    assert result["domains"] == ["evil.example"]
    assert [call[0][1] for call in rdap_stub.calls] == ["evil.example"]
    assert [call[0][1] for call in crtsh_stub.calls] == ["evil.example"]
    # The sample-level slot, because for a domain "what is this indicator"
    # IS the domain question.
    assert result["threatfox"] == {"query_status": "ok"}
    assert threatfox_stub.calls[0][0][1] == "evil.example"


async def test_a_url_indicator_runs_the_domain_sources_over_its_host(monkeypatch):
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [_provider(name) for name in ("rdap", "threatfox")],
    )
    rdap_stub = _Recorder({"handle": "x"})
    threatfox_stub = _Recorder({"query_status": "ok"})
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_rdap", rdap_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_threatfox", threatfox_stub)

    result = await data_puller(Indicator("url", "https://evil.example/a"),
                               ResponseCache(enabled=False))

    assert result["domains"] == ["evil.example"]
    assert [call[0][1] for call in rdap_stub.calls] == ["evil.example"]
    # ThreatFox is asked about the URL itself, not its host: it carries URL
    # IOCs, and the host is a strictly weaker question.
    assert threatfox_stub.calls[0][0][1] == "https://evil.example/a"


async def test_a_non_hash_indicator_says_why_virustotal_has_no_answer(monkeypatch):
    """Not "VirusTotal key not set" -- the key may be perfectly fine. VT's
    file endpoint simply does not answer for an address."""
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [_provider("virustotal")],
    )
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt",
                        _Recorder(FAKE_VT_DATA))

    result = await data_puller(Indicator("ip", "198.51.100.10"),
                               ResponseCache(enabled=False))
    assert is_error(result["vt"])
    assert "file hash" in error_message(result["vt"])


async def test_data_puller_rejects_a_bare_string(monkeypatch):
    """The pre-B2 form -- data_puller(Indicator("hash", "deadbeef"), cache) -- is still
    arity-compatible with today's signature, and a bare hash string reaching
    the kind switch would raise `'str' object has no attribute 'kind'` from
    somewhere inside it, naming neither the caller nor the argument. The
    same courtesy _require_provider extends, for the same reason."""
    with pytest.raises(TypeError, match="classified Indicator"):
        await data_puller("deadbeef" * 8, ResponseCache(enabled=False))
