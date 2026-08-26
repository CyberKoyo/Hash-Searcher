import builtins

import pytest


def test_capabilities_reports_a_library_that_is_not_installed(monkeypatch):
    """The gate must answer from a real import attempt, not a hardcoded
    list, so an environment without the [static] extra is described
    accurately rather than optimistically."""
    from hash_searcher.static import capabilities

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pefile":
            raise ImportError("no pefile here")
        return real_import(name, *args, **kwargs)

    capabilities.have.cache_clear()
    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        assert capabilities.have("pefile") is False
        assert "pefile" in capabilities.missing()
    finally:
        capabilities.have.cache_clear()


def test_capabilities_rejects_an_unknown_name():
    """A typo must fail loudly here rather than silently disabling an
    analyzer that is in fact installed."""
    from hash_searcher.static import capabilities

    with pytest.raises(KeyError):
        capabilities.have("definitely-not-a-static-library")
