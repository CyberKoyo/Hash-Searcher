import pytest

from hash_searcher.api.registry import Provider, available, by_name, missing_keys


def _providers():
    return [
        Provider(name="vt", key_env="TOTAL_KEY",
                 indicator_types=("hash",), fetch=None),
        Provider(name="censys", key_env="CENSYS_KEY",
                 indicator_types=("ip",), fetch=None, serial_delay=2.0),
        Provider(name="crtsh", key_env=None,
                 indicator_types=("domain",), fetch=None),
    ]


def test_providers_with_a_key_are_available(monkeypatch):
    monkeypatch.setenv("TOTAL_KEY", "set")
    monkeypatch.delenv("CENSYS_KEY", raising=False)
    assert [p.name for p in available(_providers())] == ["vt", "crtsh"]


def test_keyless_providers_are_always_available(monkeypatch):
    monkeypatch.delenv("TOTAL_KEY", raising=False)
    monkeypatch.delenv("CENSYS_KEY", raising=False)
    assert [p.name for p in available(_providers())] == ["crtsh"]


def test_missing_keys_names_the_env_vars(monkeypatch):
    monkeypatch.setenv("TOTAL_KEY", "set")
    monkeypatch.delenv("CENSYS_KEY", raising=False)
    assert missing_keys(_providers()) == ["CENSYS_KEY"]


def test_serial_delay_defaults_to_zero():
    assert Provider(name="x", key_env=None,
                    indicator_types=("hash",), fetch=None).serial_delay == 0.0


def test_real_registry_covers_every_current_source():
    """Pinned by name: a source added to PROVIDERS without a decision about
    its indicator types, TTL, and rate limit is exactly what Constraints 5-7
    forbid, and this list is where that decision becomes visible."""
    from hash_searcher.api.registry import PROVIDERS
    assert {p.name for p in PROVIDERS} == {
        "virustotal", "otx", "abuseipdb", "censys", "malwarebazaar",
        "rdap", "shodan", "greynoise", "crtsh", "threatfox",
    }


def test_by_name_finds_a_provider():
    assert by_name("censys", _providers()).serial_delay == 2.0


def test_by_name_raises_lookup_error_not_stop_iteration():
    with pytest.raises(LookupError, match="no provider named 'nope'"):
        by_name("nope", _providers())


def test_by_name_raises_against_the_global_registry_default(monkeypatch):
    """The reason by_name exists. A bare next() over an import-bound
    PROVIDERS cannot even see a patch to it, and when it does run dry the
    interpreter rewrites the StopIteration into an opaque 'coroutine raised
    StopIteration' (inside a coroutine caller) that names nothing.

    test_by_name_raises_lookup_error_not_stop_iteration pins this against
    an explicit provider list; every real call site in this codebase
    (data_puller resolving a provider from its own pool, or a bare
    by_name(name) call with no override) instead falls through to the
    default pool, PROVIDERS itself, which is import-bound and therefore
    needs its own coverage rather than trusting the explicit-list case to
    stand in for it.

    This used to be async and call fetch_censys, when fetch_censys
    resolved its own provider internally; Task A5 moved that resolution to
    fetch_censys's caller (data_puller), so fetch_censys no longer calls
    by_name at all and had nothing left to test here -- the two assertions
    that mattered, that by_name(name) (no override) raises LookupError and
    names "censys", are both still made below, directly, against the thing
    that's actually responsible for them.
    """
    monkeypatch.setattr("hash_searcher.api.registry.PROVIDERS", [])
    with pytest.raises(LookupError, match="no provider named 'censys'"):
        by_name("censys")


def test_available_sees_a_key_set_after_import(monkeypatch):
    """Obs. C: PROVIDERS is built at import, so key_value used to be frozen
    to whatever the environment held at that moment."""
    monkeypatch.delenv("TOTAL_KEY", raising=False)
    assert "virustotal" not in {p.name for p in available()}

    monkeypatch.setenv("TOTAL_KEY", "set-after-import")
    assert "virustotal" in {p.name for p in available()}
    assert "TOTAL_KEY" not in missing_keys()


INDICATOR_NAMES = {"indicator", "ip", "domain", "file_hash", "hash"}


def test_a_new_provider_needs_only_a_registry_entry():
    """The registry's documented promise, executed rather than asserted in
    prose. The parameter NAME varies meaningfully per source -- pinning one
    word would be pedantry -- but the POSITION is the actual contract."""
    import inspect

    from hash_searcher.api.registry import PROVIDERS

    for provider in PROVIDERS:
        assert provider.fetch is not None, f"{provider.name} has no fetch"
        params = list(inspect.signature(provider.fetch).parameters.values())
        required = [
            p for p in params
            if p.default is inspect.Parameter.empty
            and p.kind not in (inspect.Parameter.VAR_KEYWORD,
                               inspect.Parameter.VAR_POSITIONAL)
        ]
        assert len(required) == 2, \
            f"{provider.name} takes {len(required)} required args, not 2"
        assert required[0].name == "client", f"{provider.name}'s first arg is not client"
        assert required[1].name in INDICATOR_NAMES, \
            f"{provider.name}'s second arg is {required[1].name!r}"
        assert provider.indicator_types, f"{provider.name} declares no indicator types"
        assert provider.cache_ttl > 0, f"{provider.name} has no cache TTL"


def test_every_provider_fetch_takes_client_and_indicator():
    """Obs. B: the registry's promise -- append a Provider, add a source --
    only holds if every fetch agrees on its call shape."""
    import inspect
    from hash_searcher.api.registry import PROVIDERS

    for provider in PROVIDERS:
        # inspect.signature(None) raises TypeError; a placeholder entry
        # should not take the suite down with it.
        if provider.fetch is None:
            continue
        params = list(inspect.signature(provider.fetch).parameters.values())
        # *args/**kwargs are not required parameters -- a provider taking
        # **kwargs to forward max_attempts into api_get/api_post is still
        # callable as fetch(client, indicator), which is the contract.
        required = [
            p for p in params
            if p.default is inspect.Parameter.empty
            and p.kind not in (inspect.Parameter.VAR_KEYWORD,
                               inspect.Parameter.VAR_POSITIONAL)
        ]
        assert len(required) == 2, f"{provider.name} takes {len(required)} required args"
        # Counting arity alone would pass fetch(indicator, client), which
        # breaks the exact promise this test exists to guard.
        assert required[0].name == "client", \
            f"{provider.name} takes {required[0].name!r} first, not 'client'"


def test_for_indicator_selects_only_providers_that_handle_the_type(monkeypatch):
    from hash_searcher.api.registry import for_indicator

    monkeypatch.setenv("TOTAL_KEY", "set")
    monkeypatch.setenv("CENSYS_KEY", "set")
    assert [p.name for p in for_indicator("hash", _providers())] == ["vt"]
    assert [p.name for p in for_indicator("ip", _providers())] == ["censys"]
    assert [p.name for p in for_indicator("domain", _providers())] == ["crtsh"]


def test_for_indicator_still_respects_key_availability(monkeypatch):
    """A provider whose key is unset must not be selected just because it
    declares the right indicator type."""
    from hash_searcher.api.registry import for_indicator

    monkeypatch.delenv("TOTAL_KEY", raising=False)
    assert [p.name for p in for_indicator("hash", _providers())] == []


def test_every_registered_provider_declares_at_least_one_indicator_type():
    """Constraint 5: an empty tuple makes a provider unreachable through
    for_indicator, so it would silently never run."""
    from hash_searcher.api.registry import PROVIDERS

    for provider in PROVIDERS:
        assert provider.indicator_types, f"{provider.name} declares no indicator types"


def test_a_key_shared_by_two_providers_is_named_once(monkeypatch):
    """ABUSECH_KEY covers both MalwareBazaar and ThreatFox; check_env's
    warning line listed it twice before missing_keys de-duplicated."""
    monkeypatch.delenv("ABUSECH_KEY", raising=False)
    assert missing_keys().count("ABUSECH_KEY") == 1


#: Every timing the registry declares, as literals written here rather than
#: read from the thing under test.
#:
#: The rule this pins is "a declared timing that carries a written
#: justification gets a test", and the reason it is a TABLE rather than the
#: three assertions the finding named is that the rule has been applied to a
#: subset twice already: round 2 pinned threatfox's 3600 because that was the
#: constant it happened to be looking at, and left rdap's 604800 and all three
#: serial delays free to be zeroed with the suite green. Every serial source
#: could be silently converted to a parallel one against a registry docstring
#: that says Censys, crt.sh and GreyNoise "all rate limit hard enough to need
#: this".
#:
#: So the whole table is here, defaults included. A zero is a decision too --
#: it is what makes a source's fan-out parallel -- and pinning only the
#: non-zero entries would leave the same hole one row over.
DECLARED_TIMINGS = {
    # name             serial_delay, cache_ttl
    "virustotal":      (0.0, 86400),
    "otx":             (0.0, 86400),
    "abuseipdb":       (0.0, 86400),
    "censys":          (2.0, 86400),
    "malwarebazaar":   (0.0, 86400),
    "rdap":            (0.0, 604800),
    "shodan":          (0.0, 86400),
    "crtsh":           (2.0, 86400),
    "threatfox":       (0.0, 3600),
    "greynoise":       (1.0, 86400),
}


def test_the_registry_declares_the_timings_it_says_it_declares():
    """The values, not just the plumbing that reads them.

    A5 pinned that every call site reads serial_delay and cache_ttl off the
    caller's provider pool, at all eleven sites. Nothing pinned what the real
    registry actually puts there, so `serial_delay=2.0 -> 0.0` on Censys,
    crt.sh and GreyNoise together left 431 tests green -- the three sources
    the module docstring names as rate limiting hard enough to need a gap.

    Exact dict equality, so a provider added without a timing decision
    reddens here too; that is the same promise
    test_real_registry_covers_every_current_source makes about names.
    """
    from hash_searcher.api.registry import PROVIDERS

    assert {p.name: (p.serial_delay, p.cache_ttl) for p in PROVIDERS} \
        == DECLARED_TIMINGS


def test_the_three_rate_limited_sources_are_the_serial_ones():
    """Named separately from the table above because the registry docstring
    makes this claim in prose -- "Censys, crt.sh and GreyNoise all rate limit
    hard enough to need this" -- and a table equality would still pass if the
    set of serial sources changed and the table were updated to match.
    """
    from hash_searcher.api.registry import PROVIDERS

    assert {p.name for p in PROVIDERS if p.serial_delay > 0} \
        == {"censys", "crtsh", "greynoise"}


def test_cache_ttl_defaults_to_a_day():
    """The sibling of test_serial_delay_defaults_to_zero. The registry
    docstring says cache_ttl is "chosen per source, never defaulted by
    accident", and six of the ten entries take this default -- so what the
    default IS is part of six sources' declared behaviour.
    """
    assert Provider(name="x", key_env=None,
                    indicator_types=("hash",), fetch=None).cache_ttl == 86400
