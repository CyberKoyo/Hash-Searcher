"""Coverage for the VirusTotal rate budget (Task D1).

Every test here injects a clock. The windows this module enforces are 60
seconds and 24 hours wide, and a suite that proved a window rolls by
actually waiting for it would take a minute per assertion and a day for the
one that matters most.
"""

import sqlite3

import pytest

from hash_searcher.api.api_data_puller import data_puller
from hash_searcher.api.base_call import error_message, is_error
from hash_searcher.api.registry import Provider, by_name
from hash_searcher.budget import DAY_WINDOW, MINUTE_WINDOW, RateBudget
from hash_searcher.cache import ResponseCache
from hash_searcher.indicators import Indicator

VT = "virustotal"


class _Clock:
    """A hand-wound clock. `advance` is the only thing that moves it."""

    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _budget(tmp_path, clock=None, **kwargs) -> RateBudget:
    return RateBudget(tmp_path / "budget.db", clock=clock or _Clock(), **kwargs)


def _spend(budget: RateBudget, provider: str, times: int) -> None:
    for _ in range(times):
        assert budget.allows(provider), "the fixture itself ran out of budget"
        budget.record(provider)


# --- the per-minute window --------------------------------------------------


def test_a_fifth_call_inside_one_minute_is_refused(tmp_path):
    """VirusTotal's free tier is four requests a minute."""
    budget = _budget(tmp_path)
    _spend(budget, VT, 4)
    assert budget.allows(VT) is False
    budget.close()


def test_the_refusal_expires_when_the_minute_window_rolls(tmp_path):
    clock = _Clock()
    budget = _budget(tmp_path, clock=clock)
    _spend(budget, VT, 4)
    assert budget.allows(VT) is False

    # One second short of the window: the fourth call is still inside it.
    clock.advance(MINUTE_WINDOW - 1)
    assert budget.allows(VT) is False

    clock.advance(2)
    assert budget.allows(VT) is True
    budget.close()


def test_wait_seconds_is_zero_while_the_budget_allows(tmp_path):
    budget = _budget(tmp_path)
    assert budget.wait_seconds(VT) == 0.0
    _spend(budget, VT, 3)
    assert budget.wait_seconds(VT) == 0.0
    budget.close()


def test_wait_seconds_counts_down_to_the_window_edge(tmp_path):
    """The answer is when the OLDEST call in the window leaves it, not a
    flat 60 seconds: four calls made 50 seconds ago free up in 10."""
    clock = _Clock()
    budget = _budget(tmp_path, clock=clock)
    _spend(budget, VT, 4)
    clock.advance(50)
    assert budget.wait_seconds(VT) == pytest.approx(MINUTE_WINDOW - 50)
    budget.close()


# --- the per-day window -----------------------------------------------------


def test_the_daily_ceiling_refuses_even_with_the_minute_window_clear(tmp_path):
    """A day's worth of calls spread far enough apart never trips the
    per-minute rule, and must still stop at the daily ceiling."""
    clock = _Clock()
    budget = _budget(tmp_path, clock=clock, per_day=5)
    for _ in range(5):
        assert budget.allows(VT)
        budget.record(VT)
        clock.advance(MINUTE_WINDOW + 1)  # the minute window is always empty

    assert budget.allows(VT) is False
    assert budget.wait_seconds(VT) > MINUTE_WINDOW
    budget.close()


def test_the_daily_counter_survives_a_process_restart(tmp_path):
    """The whole reason this is a table and not an attribute. Written,
    closed, and reopened at the same path -- which is what a second
    `hash-searcher` invocation is."""
    clock = _Clock()
    first = RateBudget(tmp_path / "budget.db", per_day=4, clock=clock)
    _spend(first, VT, 4)
    first.close()

    # Well past the minute window, so only the daily counter can refuse.
    clock.advance(MINUTE_WINDOW * 10)
    second = RateBudget(tmp_path / "budget.db", per_day=4, clock=clock)
    assert second.allows(VT) is False
    second.close()


def test_a_day_old_call_no_longer_counts(tmp_path):
    clock = _Clock()
    budget = _budget(tmp_path, clock=clock, per_day=4)
    _spend(budget, VT, 4)
    clock.advance(DAY_WINDOW + 1)
    assert budget.allows(VT) is True
    budget.close()


# --- provider isolation and degradation ------------------------------------


def test_providers_do_not_share_a_budget(tmp_path):
    """Wired in at the VT call site today, but the table is keyed by
    provider so a second rate-limited source does not inherit VT's spend."""
    budget = _budget(tmp_path)
    _spend(budget, VT, 4)
    assert budget.allows(VT) is False
    assert budget.allows("otx") is True
    budget.close()


def test_a_broken_database_degrades_instead_of_refusing_every_call(tmp_path, capsys):
    """Fail open, loudly. A budget is a courtesy to a free tier, not a
    security control: an unreadable file must not turn into a tool that
    refuses to look anything up, which is what fail-closed would mean here.
    The 429 that a blown quota actually produces is already retried in
    base_call."""
    bad_path = tmp_path / "corrupt.db"
    bad_path.write_text("not a database at all")

    budget = RateBudget(bad_path)

    assert budget.allows(VT) is True
    budget.record(VT)          # must not raise
    assert budget.wait_seconds(VT) == 0.0
    budget.close()             # must not raise

    out = capsys.readouterr().out
    assert str(bad_path) in out
    assert "budget" in out.lower()


def test_a_zero_limit_refuses_everything(tmp_path):
    """The shape a test needs to force exhaustion without spending four
    calls first, and a real setting for a key with no quota left."""
    budget = _budget(tmp_path, per_minute=0)
    assert budget.allows(VT) is False
    # It never frees up, so there is no honest "retry in" number. The full
    # window is the chosen lie, and it is pinned here rather than left to
    # whatever the arithmetic happens to produce -- an unpinned zero limit
    # is how this would come back as an IndexError on an empty table.
    assert budget.wait_seconds(VT) == MINUTE_WINDOW
    budget.close()


def test_more_calls_than_the_limit_still_report_the_right_wait(tmp_path):
    """Two processes can both pass allows() before either records, so the
    table can legitimately hold more calls in a window than the limit
    allows. wait_seconds must still answer from the call that has to leave
    -- which is no longer the newest one."""
    clock = _Clock()
    budget = _budget(tmp_path, clock=clock, per_minute=4)
    # Six calls, one second apart, recorded past the point allows() would
    # have stopped -- exactly what a race produces.
    for _ in range(6):
        budget.record(VT)
        clock.advance(1)

    # now = t0 + 6. Six present, four allowed: three must expire, the last
    # of those recorded at t0 + 2, which leaves the window at t0 + 62.
    assert budget.allows(VT) is False
    assert budget.wait_seconds(VT) == pytest.approx(56.0)
    budget.close()


# --- degrading at runtime, not just at open ---------------------------------


def test_a_database_that_breaks_after_opening_degrades(tmp_path, capsys):
    """open_db only covers the open. A read-only file passes CREATE TABLE IF
    NOT EXISTS -- it needs no write against a table that already exists --
    and raises on the first INSERT. Uncaught, that was a traceback for a
    single run and, through run_batch's per-indicator handler, EXIT_NO_DATA
    on every line of a batch: a locked database turning into "nothing could
    be looked up", which is the outcome failing open exists to prevent."""
    path = tmp_path / "budget.db"
    RateBudget(path).close()          # create the table while we still can
    path.chmod(0o444)
    try:
        budget = RateBudget(path)
        assert budget._conn is not None   # it really did open
        budget.record(VT)                 # must not raise
        assert budget.allows(VT) is True  # and must fail open afterwards
        assert budget.wait_seconds(VT) == 0.0
        budget.close()
    finally:
        path.chmod(0o644)

    out = capsys.readouterr().out
    assert "rate budget" in out.lower()
    assert "readonly" in out.lower() or "read-only" in out.lower()


def test_the_degradation_warning_is_printed_once(tmp_path, capsys):
    """_degrade drops the connection, so every later call takes the
    already-degraded branch rather than re-raising and re-printing. A
    warning per lookup would bury the report it is warning about."""
    path = tmp_path / "budget.db"
    RateBudget(path).close()
    path.chmod(0o444)
    try:
        budget = RateBudget(path)
        for _ in range(5):
            budget.record(VT)
        budget.close()
    finally:
        path.chmod(0o644)

    assert capsys.readouterr().out.lower().count("rate budget stopped") == 1


def test_using_a_closed_budget_raises_rather_than_reading_as_unlimited(tmp_path):
    """close() and "the database failed" both leave _conn None, and they
    must not answer alike: a caller that kept a reference past the finally
    which closed it would otherwise get an unlimited budget, silently."""
    budget = _budget(tmp_path)
    budget.close()

    with pytest.raises(RuntimeError, match="closed"):
        budget.allows(VT)
    with pytest.raises(RuntimeError, match="closed"):
        budget.record(VT)
    with pytest.raises(RuntimeError, match="closed"):
        budget.wait_seconds(VT)


def test_close_is_idempotent(tmp_path):
    """It runs in finally blocks, including ones that are already unwinding
    an exception. Raising there would replace the real failure."""
    budget = _budget(tmp_path)
    budget.close()
    budget.close()  # must not raise


def test_a_negative_limit_is_rejected_at_construction(tmp_path):
    with pytest.raises(ValueError):
        RateBudget(tmp_path / "b.db", per_minute=-1)
    with pytest.raises(ValueError):
        RateBudget(tmp_path / "b.db", per_day=-1)


def test_the_budget_shares_the_cache_database(tmp_path):
    """One file, two tables. A second file for eight rows is a second thing
    to corrupt, and a second thing to forget to delete."""
    path = tmp_path / "responses.db"
    cache = ResponseCache(path)
    cache.put(VT, "deadbeef", {"ok": True})
    budget = RateBudget(path)
    budget.record(VT)
    budget.close()
    cache.close()

    tables = {
        row[0] for row in
        sqlite3.connect(path).execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {"responses", "rate_events"} <= tables


# --- the call site ----------------------------------------------------------
#
# Same monkeypatch pattern as tests/test_data_puller.py: `available` and the
# fetch coroutines are replaced as they are bound into api_data_puller, so
# nothing here depends on a key or on the network.

FAKE_VT_DATA = {"data": {"attributes": {}}}


class _Recorder:
    def __init__(self, return_value):
        self.calls = []
        self._return_value = return_value

    async def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self._return_value


def _only_virustotal(monkeypatch) -> _Recorder:
    real = by_name(VT)
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [Provider(name=VT, key_env=None,
                          indicator_types=real.indicator_types, fetch=None,
                          cache_ttl=42, serial_delay=0.0)],
    )
    vt_stub = _Recorder(FAKE_VT_DATA)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", vt_stub)
    return vt_stub


async def test_a_real_call_consumes_budget(monkeypatch, tmp_path):
    vt_stub = _only_virustotal(monkeypatch)
    budget = _budget(tmp_path, per_minute=1)

    await data_puller(Indicator("hash", "deadbeef"),
                      ResponseCache(enabled=False), budget=budget)

    assert len(vt_stub.calls) == 1
    assert budget.allows(VT) is False
    budget.close()


async def test_a_cache_hit_does_not_consume_budget(monkeypatch, tmp_path):
    """It made no request. Charging a cache hit against a per-minute quota
    would make `--input-file` over a re-run list refuse calls it never
    made."""
    vt_stub = _only_virustotal(monkeypatch)
    cache = ResponseCache(tmp_path / "responses.db")
    cache.put(VT, "deadbeef", FAKE_VT_DATA)
    budget = _budget(tmp_path, per_minute=1)

    await data_puller(Indicator("hash", "deadbeef"), cache, budget=budget)

    assert vt_stub.calls == []
    assert budget.allows(VT) is True
    budget.close()
    cache.close()


async def test_no_cache_does_not_disable_the_budget(monkeypatch, tmp_path):
    """The budget is persisted beside the cache but does not ride on it:
    --no-cache is what makes every run a fresh request, which is precisely
    when a free tier needs the budget most."""
    vt_stub = _only_virustotal(monkeypatch)
    budget = _budget(tmp_path, per_minute=0)

    raw = await data_puller(Indicator("hash", "deadbeef"),
                            ResponseCache(enabled=False), budget=budget)

    assert vt_stub.calls == []
    assert is_error(raw["vt"])
    assert "rate budget exhausted" in error_message(raw["vt"])
    budget.close()


async def test_an_exhausted_budget_stops_virustotal_and_nothing_else(
        monkeypatch, tmp_path):
    """"Wire in at the VT call site only." Every other source is keyless or
    on a limit this does not model, and a budget that quietly gated them
    would turn one exhausted VirusTotal quota into a run that reports
    nothing at all -- which is the failure mode Task A1 exists to prevent."""
    real_vt, real_otx = by_name(VT), by_name("otx")
    monkeypatch.setattr(
        "hash_searcher.api.api_data_puller.available",
        lambda: [Provider(name=VT, key_env=None,
                          indicator_types=real_vt.indicator_types, fetch=None,
                          cache_ttl=42, serial_delay=0.0),
                 Provider(name="otx", key_env=None,
                          indicator_types=real_otx.indicator_types, fetch=None,
                          cache_ttl=42, serial_delay=0.0)],
    )
    vt_stub = _Recorder(FAKE_VT_DATA)
    otx_stub = _Recorder({"pulse_info": {"count": 3}})
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_vt", vt_stub)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_otx", otx_stub)

    budget = _budget(tmp_path, per_minute=0)
    raw = await data_puller(Indicator("hash", "deadbeef"),
                            ResponseCache(enabled=False), budget=budget)

    assert vt_stub.calls == []                       # VT refused
    assert len(otx_stub.calls) == 1                  # OTX untouched
    assert raw["otx"] == {"pulse_info": {"count": 3}}
    budget.close()


async def test_the_refusal_is_announced_when_it_happens(monkeypatch, tmp_path,
                                                        capsys):
    """The TTY only mentions an unavailable VirusTotal when the verdict came
    out UNKNOWN, so a sample MalwareBazaar calls malicious would render a VT
    section indistinguishable from "VT had nothing". Say it at the point of
    refusal instead, where it is true regardless of the verdict -- and name
    the flag that turns it off."""
    _only_virustotal(monkeypatch)
    budget = _budget(tmp_path, per_minute=0)

    await data_puller(Indicator("hash", "deadbeef"),
                      ResponseCache(enabled=False), budget=budget)

    out = capsys.readouterr().out
    assert "Skipping VirusTotal" in out
    assert "rate budget exhausted" in out
    assert "--ignore-budget" in out
    budget.close()


async def test_a_refresh_forced_miss_still_charges(monkeypatch, tmp_path):
    """--refresh ignores a hit and calls anyway. That call is as real as any
    other, so it must be counted -- a cache hit costs nothing because it
    made no request, not because a cached value exists."""
    vt_stub = _only_virustotal(monkeypatch)
    cache = ResponseCache(tmp_path / "responses.db")
    cache.put(VT, "deadbeef", FAKE_VT_DATA)
    cache.close()

    fresh = ResponseCache(tmp_path / "responses.db", refresh=True)
    budget = _budget(tmp_path, per_minute=1)

    await data_puller(Indicator("hash", "deadbeef"), fresh, budget=budget)

    assert len(vt_stub.calls) == 1        # the hit was ignored
    assert budget.allows(VT) is False     # and the real call was charged
    budget.close()
    fresh.close()


async def test_no_budget_at_all_calls_virustotal(monkeypatch, tmp_path):
    """--ignore-budget, and every pre-D caller: budget=None enforces
    nothing."""
    vt_stub = _only_virustotal(monkeypatch)

    await data_puller(Indicator("hash", "deadbeef"),
                      ResponseCache(enabled=False), budget=None)

    assert len(vt_stub.calls) == 1


async def test_the_exhausted_message_says_when_to_retry(monkeypatch, tmp_path):
    clock = _Clock()
    vt_stub = _only_virustotal(monkeypatch)
    budget = _budget(tmp_path, clock=clock, per_minute=1)
    budget.record(VT)
    clock.advance(20)

    raw = await data_puller(Indicator("hash", "deadbeef"),
                            ResponseCache(enabled=False), budget=budget)

    assert vt_stub.calls == []
    assert "VirusTotal rate budget exhausted" in error_message(raw["vt"])
    assert "40s" in error_message(raw["vt"])
    budget.close()


async def test_an_exhausted_budget_is_never_cached(monkeypatch, tmp_path):
    """cache.put already refuses error payloads, and this is the case that
    proves why it matters: caching "budget exhausted" would pin the refusal
    for a full day, long after the window rolled."""
    _only_virustotal(monkeypatch)
    cache = ResponseCache(tmp_path / "responses.db")
    budget = _budget(tmp_path, per_minute=0)

    await data_puller(Indicator("hash", "deadbeef"), cache, budget=budget)

    assert cache.get(VT, "deadbeef") is None
    budget.close()
    cache.close()


def test_an_exhausted_budget_reads_as_unavailable_not_as_no_record():
    """The distinction Task A3 built, and the reason Part D depends on Part
    A. "We could not ask" must never render as "VirusTotal has no record" --
    the second is a claim about the sample, and this is a claim about us."""
    from hash_searcher.analysis.vt import extract_vt
    from hash_searcher.api.base_call import make_error

    report = extract_vt(make_error("VirusTotal rate budget exhausted; "
                                   "retry in 40s"))

    assert report.found is False
    assert report.unavailable is True


# --- the command line -------------------------------------------------------

EMPTY_RAW = {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": [],
             "domains": [], "rdap": [], "crtsh": [], "shodan": {},
             "greynoise": {}, "kev": {},
             "bazaar": None, "threatfox": None, "threatfox_ips": {}}


class _FakeBudget:
    """Stands in for RateBudget so no test touches the user's real cache
    directory. Identity is what the batch tests assert on, so instances are
    counted rather than reused."""

    def __init__(self, *args, **kwargs):
        self.closed = False

    def close(self):
        self.closed = True


def _stub_cli(monkeypatch) -> dict:
    """Bypass key reading and hash resolution, and record what data_puller
    was handed. Same pattern as tests/test_cli.py's _stub_entry."""
    from hash_searcher.indicators import Indicator

    seen = {"budgets": [], "opened": []}

    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    monkeypatch.setattr(
        "hash_searcher.cli.resolve_indicator",
        lambda indicator, password: [Indicator("hash", "deadbeef")],
    )

    async def fake_puller(indicator, cache, extra_ips=None, pivot_depth=0,
                          budget=None):
        seen["budgets"].append(budget)
        return EMPTY_RAW

    monkeypatch.setattr("hash_searcher.cli.data_puller", fake_puller)

    def fake_budget(*args, **kwargs):
        seen["opened"].append(_FakeBudget())
        return seen["opened"][-1]

    monkeypatch.setattr("hash_searcher.cli.RateBudget", fake_budget)
    monkeypatch.setattr("hash_searcher.batch.RateBudget", fake_budget)
    return seen


def test_the_ignore_budget_flag_defaults_to_off():
    from hash_searcher.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["abc"]).ignore_budget is False
    assert parser.parse_args(["abc", "--ignore-budget"]).ignore_budget is True


async def test_a_plain_run_opens_a_budget_and_closes_it(monkeypatch):
    from hash_searcher.cli import run_cli

    seen = _stub_cli(monkeypatch)
    await run_cli(["deadbeef", "--no-cache"])

    assert len(seen["opened"]) == 1
    assert seen["budgets"] == seen["opened"]
    assert seen["opened"][0].closed is True


async def test_no_cache_still_hands_data_puller_a_budget(monkeypatch):
    """The flag combination Part D's own step 1 calls out: bypassing the
    cache makes every lookup a real request, so it must not also bypass the
    thing counting them."""
    from hash_searcher.cli import run_cli

    seen = _stub_cli(monkeypatch)
    await run_cli(["deadbeef", "--no-cache"])

    assert seen["budgets"][0] is not None


async def test_ignore_budget_enforces_nothing(monkeypatch):
    """For a paid key, which is not bound by the free tier's four a
    minute."""
    from hash_searcher.cli import run_cli

    seen = _stub_cli(monkeypatch)
    await run_cli(["deadbeef", "--no-cache", "--ignore-budget"])

    assert seen["opened"] == []      # none was even constructed
    assert seen["budgets"] == [None]


async def test_a_batch_shares_one_budget_across_every_indicator(monkeypatch):
    """A quota is spent by the run, not by the line. One budget per
    indicator would let a five-line list make five first requests inside
    one minute -- exactly what a four-a-minute ceiling forbids."""
    import io

    from hash_searcher.cli import run_cli

    seen = _stub_cli(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\nc\n"))

    await run_cli(["-", "--no-cache"])

    assert len(seen["opened"]) == 1
    assert len({id(b) for b in seen["budgets"]}) == 1
    assert len(seen["budgets"]) == 3
    assert seen["opened"][0].closed is True


def test_the_readme_states_the_limits_it_enforces():
    """The numbers are VirusTotal's free tier, and --ignore-budget exists
    precisely because a paid key is not bound by them -- a README that
    silently disagreed with the constants would send a paid user looking
    for a quota they do not have. Read from the constants, not spelled
    here, so changing one reddens this."""
    from pathlib import Path

    from hash_searcher.budget import VT_PER_DAY, VT_PER_MINUTE

    readme = (Path(__file__).parents[1] / "README.md").read_text()
    assert "--ignore-budget" in readme
    assert f"{VT_PER_MINUTE} requests/minute" in readme
    assert f"{VT_PER_DAY}/day" in readme


async def test_the_shared_budget_is_closed_even_when_a_run_raises(monkeypatch):
    """The sqlite handle the batch opened must not outlive it, and a run
    that blows up mid-list is exactly when a finally gets forgotten. The
    cache already had this guard; the budget is a second handle on the same
    file and needs its own."""
    import io

    from hash_searcher.cli import run_cli

    seen = _stub_cli(monkeypatch)

    async def boom(user_input, args, cache=None, output=None, budget=None,
                   rows=None):
        raise RuntimeError("provider blew up")

    monkeypatch.setattr("hash_searcher.batch.analyze_one", boom)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\n"))

    await run_cli(["-", "--no-cache"])

    assert len(seen["opened"]) == 1
    assert seen["opened"][0].closed is True


async def test_a_batch_with_ignore_budget_opens_none(monkeypatch):
    import io

    from hash_searcher.cli import run_cli

    seen = _stub_cli(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\n"))

    await run_cli(["-", "--no-cache", "--ignore-budget"])

    assert seen["opened"] == []
    assert seen["budgets"] == [None, None]
