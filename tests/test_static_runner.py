import importlib

import pytest


def _pretend_absent(monkeypatch, module_name):
    """Make capabilities.have(...) see `module_name` as not importable,
    regardless of whether it is actually installed in this environment.

    capabilities.have() calls `importlib.import_module`, never the `import`
    statement or `builtins.__import__` -- import_module does not route
    through `__import__` at all (confirmed: patching `builtins.__import__`
    never intercepts it), so faking absence means patching
    `import_module` itself.

    Also clears `have`'s lru_cache before returning. A prior real call to
    `have("pefile")` earlier in the same test session -- likely, once
    pefile is actually installed -- caches the real answer; without
    clearing it here, this fake failure would never even reach the
    function body, and the test would pass by reading a stale True.
    """
    from ioc_inquest.static import capabilities

    real_import_module = importlib.import_module

    def fake_import_module(name, *args, **kwargs):
        if name == module_name:
            raise ImportError(f"pretending {module_name!r} is not installed")
        return real_import_module(name, *args, **kwargs)

    capabilities.have.cache_clear()
    monkeypatch.setattr(importlib, "import_module", fake_import_module)


def test_capabilities_reports_a_library_that_is_not_installed(monkeypatch):
    """The gate must answer from a real import attempt, not a hardcoded
    list, so an environment without the [static] extra is described
    accurately rather than optimistically."""
    from ioc_inquest.static import capabilities

    _pretend_absent(monkeypatch, "pefile")
    try:
        assert capabilities.have("pefile") is False
        assert "pefile" in capabilities.missing()
    finally:
        capabilities.have.cache_clear()


def test_capabilities_rejects_an_unknown_name():
    """A typo must fail loudly here rather than silently disabling an
    analyzer that is in fact installed."""
    from ioc_inquest.static import capabilities

    with pytest.raises(KeyError):
        capabilities.have("definitely-not-a-static-library")


def test_analyze_runs_every_available_analyzer_and_names_the_skips(tmp_path):
    from ioc_inquest.static.runner import analyze

    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + b"\x00" * 4096)

    report = analyze(str(target))
    assert report.size == 4098
    assert report.entropy is not None      # stdlib only, always runs
    assert report.filetype is not None     # stdlib fallback, always runs
    for name in report.skipped:
        # Analyzer field names, not library names -- "pe" not "pefile".
        # See runner.py's module docstring and branch-review.md's minor
        # skipped/failed-namespace finding.
        assert name in {"pe", "yara", "magic"}


def test_one_failing_analyzer_does_not_take_down_the_others(tmp_path, monkeypatch):
    """These parse hostile input; one of them failing is the expected case,
    not the exceptional one. A crash must degrade the report, not the run."""
    from ioc_inquest.static import runner

    def boom(path):
        raise RuntimeError("analyzer exploded")

    monkeypatch.setattr(runner, "analyze_entropy", boom)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")

    report = runner.analyze(str(target))
    assert report.filetype is not None
    assert "entropy" in report.failed
    assert "entropy" not in report.skipped   # it ran and broke; it wasn't absent


def test_a_missing_library_is_skipped_not_failed(tmp_path, monkeypatch):
    """The other half of the skipped/failed distinction: when pefile is
    not importable, `analyze_pe` is never even called. That must show up
    as `pe` never having run -- named in `skipped` -- and must never show
    up in `failed`, which is reserved for an analyzer that was called and
    raised.

    Forced via `_pretend_absent` rather than relying on pefile actually
    being uninstalled: this test must hold in a with-[static] environment
    too, where pefile genuinely imports fine."""
    from ioc_inquest.static import capabilities, runner

    _pretend_absent(monkeypatch, "pefile")
    try:
        assert capabilities.have("pefile") is False

        target = tmp_path / "sample.bin"
        target.write_bytes(b"MZ" + b"\x00" * 64)

        report = runner.analyze(str(target))
        # Named by the analyzer field ("pe"), not the library ("pefile") --
        # the assertion the docstring above already promised, but which the
        # code did not actually deliver until this round (branch-review.md
        # minor finding: skipped/failed used two different namespaces).
        assert "pe" in report.skipped
        assert "pefile" not in report.skipped
        assert "pefile" not in report.failed
        assert "pe" not in report.failed
        assert report.pe is None
    finally:
        capabilities.have.cache_clear()


def test_analyze_hashes_the_file_it_analyzed(tmp_path):
    """The static report and the network lookup must be about the same bytes."""
    import hashlib
    from ioc_inquest.static.runner import analyze

    target = tmp_path / "sample.bin"
    payload = b"the quick brown fox"
    target.write_bytes(payload)

    assert analyze(str(target)).sha256 == hashlib.sha256(payload).hexdigest()


def test_analyze_unpacks_the_yara_hits_and_note_into_the_report(tmp_path, monkeypatch):
    """analyze_yara now returns (hits, note) rather than a bare list
    (branch-review.md I5) -- analyze() must unpack it into StaticReport.yara
    and StaticReport.yara_note rather than stashing the tuple itself where a
    list of YaraHit is expected."""
    from ioc_inquest.models import YaraHit
    from ioc_inquest.static import runner

    def fake_yara(path, rules_path):
        return [YaraHit(rule="Fake_Rule")], "stopped after 1 of 2 rule files"

    monkeypatch.setattr(runner, "analyze_yara", fake_yara)
    # Only "yara" -- not "pefile" too, which would send analyze_pe past its
    # own capability gate and into a real `import pefile` this venv may not
    # have, an unrelated failure this test has no interest in.
    monkeypatch.setattr(runner.capabilities, "have", lambda name: name == "yara")

    target = tmp_path / "sample.bin"
    target.write_bytes(b"anything")

    report = runner.analyze(str(target))
    assert [h.rule for h in report.yara] == ["Fake_Rule"]
    assert report.yara_note == "stopped after 1 of 2 rule files"
