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


def test_analyze_runs_every_available_analyzer_and_names_the_skips(tmp_path):
    from hash_searcher.static.runner import analyze

    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + b"\x00" * 4096)

    report = analyze(str(target))
    assert report.size == 4098
    assert report.entropy is not None      # stdlib only, always runs
    assert report.filetype is not None     # stdlib fallback, always runs
    for name in report.skipped:
        assert name in {"pefile", "yara", "magic"}


def test_one_failing_analyzer_does_not_take_down_the_others(tmp_path, monkeypatch):
    """These parse hostile input; one of them failing is the expected case,
    not the exceptional one. A crash must degrade the report, not the run."""
    from hash_searcher.static import runner

    def boom(path):
        raise RuntimeError("analyzer exploded")

    monkeypatch.setattr(runner, "analyze_entropy", boom)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")

    report = runner.analyze(str(target))
    assert report.filetype is not None
    assert "entropy" in report.failed
    assert "entropy" not in report.skipped   # it ran and broke; it wasn't absent


def test_a_missing_library_is_skipped_not_failed(tmp_path):
    """The other half of the skipped/failed distinction: pefile is not
    installed in this environment, so `analyze_pe` is never even called.
    That must show up as `pe` never having run -- named in `skipped` --
    and must never show up in `failed`, which is reserved for an analyzer
    that was called and raised."""
    from hash_searcher.static import capabilities, runner

    assert capabilities.have("pefile") is False  # true in this test env

    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + b"\x00" * 64)

    report = runner.analyze(str(target))
    assert "pefile" in report.skipped
    assert "pefile" not in report.failed
    assert "pe" not in report.failed
    assert report.pe is None


def test_analyze_hashes_the_file_it_analyzed(tmp_path):
    """The static report and the network lookup must be about the same bytes."""
    import hashlib
    from hash_searcher.static.runner import analyze

    target = tmp_path / "sample.bin"
    payload = b"the quick brown fox"
    target.write_bytes(payload)

    assert analyze(str(target)).sha256 == hashlib.sha256(payload).hexdigest()
