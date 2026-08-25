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


def test_real_registry_covers_the_four_current_sources():
    from hash_searcher.api.registry import PROVIDERS
    assert {p.name for p in PROVIDERS} == {"virustotal", "otx", "abuseipdb", "censys"}


def test_by_name_finds_a_provider():
    assert by_name("censys", _providers()).serial_delay == 2.0


def test_by_name_raises_lookup_error_not_stop_iteration():
    with pytest.raises(LookupError, match="no provider named 'nope'"):
        by_name("nope", _providers())


async def test_fetch_censys_names_a_missing_registry_entry(monkeypatch):
    """The reason by_name exists. A bare next() over an import-bound
    PROVIDERS cannot even see this patch, and when it does run dry inside a
    coroutine the interpreter rewrites the StopIteration into an opaque
    'RuntimeError: coroutine raised StopIteration' that names nothing."""
    from hash_searcher.api.api_data_puller import fetch_censys
    from hash_searcher.cache import ResponseCache

    monkeypatch.setattr("hash_searcher.api.registry.PROVIDERS", [])
    with pytest.raises(LookupError, match="censys"):
        await fetch_censys(None, ["198.51.100.10"], ResponseCache(enabled=False))


def test_available_sees_a_key_set_after_import(monkeypatch):
    """Obs. C: PROVIDERS is built at import, so key_value used to be frozen
    to whatever the environment held at that moment."""
    monkeypatch.delenv("TOTAL_KEY", raising=False)
    assert "virustotal" not in {p.name for p in available()}

    monkeypatch.setenv("TOTAL_KEY", "set-after-import")
    assert "virustotal" in {p.name for p in available()}
    assert "TOTAL_KEY" not in missing_keys()


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
        required = [p for p in params if p.default is inspect.Parameter.empty]
        assert len(required) == 2, f"{provider.name} takes {len(required)} required args"
        # Counting arity alone would pass fetch(indicator, client), which
        # breaks the exact promise this test exists to guard.
        assert required[0].name == "client", \
            f"{provider.name} takes {required[0].name!r} first, not 'client'"
