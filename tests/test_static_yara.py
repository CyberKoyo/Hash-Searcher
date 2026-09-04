import time

from tests.conftest import requires

RULE = """
rule IOC_Inquest_Test_Rule
{
    meta:
        description = "matches a synthetic marker, never real malware"
    strings:
        $marker = "IOCINQUESTTESTMARKER"
    condition:
        $marker
}
"""


def test_yara_returns_nothing_without_the_library(tmp_path, monkeypatch):
    from ioc_inquest.static import yara_scan

    monkeypatch.setattr(yara_scan.capabilities, "have", lambda name: False)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"anything")
    assert yara_scan.analyze_yara(str(target), str(tmp_path)) == ([], "")


def test_yara_returns_nothing_when_the_rules_directory_is_absent(tmp_path, monkeypatch):
    """No rules is the default state for a fresh install; it must be a quiet
    empty result, not an error the user has to silence.

    capabilities.have is monkeypatched to True so this test reaches and
    proves the directory-existence guard itself, in every environment --
    including one where yara-python isn't installed -- rather than passing
    vacuously because the capability check short-circuits first.
    """
    from ioc_inquest.static import yara_scan

    monkeypatch.setattr(yara_scan.capabilities, "have", lambda name: True)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"anything")
    assert yara_scan.analyze_yara(str(target), str(tmp_path / "no-such-dir")) == ([], "")


@requires("yara")
def test_a_matching_rule_is_reported_with_its_name(tmp_path):
    from ioc_inquest.static.yara_scan import analyze_yara

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test.yar").write_text(RULE)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"padding IOCINQUESTTESTMARKER padding")

    hits, note = analyze_yara(str(target), str(rules))
    assert [h.rule for h in hits] == ["IOC_Inquest_Test_Rule"]
    assert note == ""


@requires("yara")
def test_a_non_matching_file_yields_no_hits(tmp_path):
    from ioc_inquest.static.yara_scan import analyze_yara

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test.yar").write_text(RULE)

    target = tmp_path / "clean.bin"
    target.write_bytes(b"nothing interesting here")

    assert analyze_yara(str(target), str(rules)) == ([], "")


@requires("yara")
def test_a_broken_rule_file_does_not_abort_the_scan(tmp_path):
    """One malformed .yar in a user's rules directory must not take the whole
    run down -- the other rules still have something to say. This is why each
    file is compiled separately rather than in one batch."""
    from ioc_inquest.static.yara_scan import analyze_yara

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "good.yar").write_text(RULE)
    (rules / "broken.yar").write_text("rule Nope { this is not yara }")

    target = tmp_path / "sample.bin"
    target.write_bytes(b"IOCINQUESTTESTMARKER")

    hits, note = analyze_yara(str(target), str(rules))
    assert [h.rule for h in hits] == ["IOC_Inquest_Test_Rule"]


# --- branch-review.md I5 -----------------------------------------------------


@requires("yara")
def test_the_directory_walk_filters_before_sorting(tmp_path, monkeypatch):
    """`sorted(directory.rglob("*"))` used to materialise every path in the
    tree -- every unrelated file, not just rule files -- before the suffix
    filter ran, which is unbounded memory one `--yara-rules ~` typo away.

    Proven by capturing exactly what reaches `sorted()`, the way
    test_entropy_reads_at_most_the_cap proves its bound by capturing what
    reaches `read()`: shadowing the module-level name the function actually
    looks up (LEGB finds the module global before the builtin, the same
    trick entropy.py's cap test uses on `open`)."""
    from ioc_inquest.static import yara_scan

    monkeypatch.setattr(yara_scan.capabilities, "have", lambda name: True)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text(RULE)
    for i in range(20):
        (rules / f"noise{i}.txt").write_text("not a rule")

    seen_lengths = []
    real_sorted = sorted

    def counting_sorted(iterable, *a, **kw):
        items = list(iterable)
        seen_lengths.append(len(items))
        return real_sorted(items, *a, **kw)

    monkeypatch.setattr(yara_scan, "sorted", counting_sorted, raising=False)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"IOCINQUESTTESTMARKER")
    yara_scan.analyze_yara(str(target), str(rules))

    # Only the one .yar file reached sorted() -- not the 21 total paths
    # under the directory.
    assert seen_lengths == [1]


@requires("yara")
def test_yara_scan_caps_the_number_of_rule_files(tmp_path, monkeypatch):
    """branch-review.md I5: a total ceiling on how many rule files a single
    scan will even consider, independent of how fast each one matches."""
    from ioc_inquest.static import yara_scan

    monkeypatch.setattr(yara_scan, "MAX_RULE_FILES", 2)
    rules = tmp_path / "rules"
    rules.mkdir()
    for i in range(5):
        (rules / f"r{i}.yar").write_text(RULE)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"IOCINQUESTTESTMARKER")

    hits, note = yara_scan.analyze_yara(str(target), str(rules))
    assert len(hits) == 2   # one hit per compiled+matched rule file
    assert "2 of 5" in note


@requires("yara")
def test_yara_scan_stops_after_the_wall_clock_budget(tmp_path, monkeypatch):
    """branch-review.md I5: SCAN_TIMEOUT (30s) bounds a single rule file's
    match() call, but the old code had no ceiling on the sum across a whole
    ruleset -- N * 30s for N files. Proven deterministically rather than by
    an actually-slow rule: time.monotonic is patched to jump past the
    budget between the first and second rule file, so the loop must stop
    without a real 60-second wait."""
    from ioc_inquest.static import yara_scan

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text(RULE)
    (rules / "b.yar").write_text(RULE)
    (rules / "c.yar").write_text(RULE)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"IOCINQUESTTESTMARKER")

    # Patches the module's own reference to time.monotonic, not the
    # `time` module globally -- monkeypatching `time.monotonic` itself
    # would also corrupt this test's own timing calls, since `yara_scan`
    # imports the same module object rather than a copy of the function.
    ticks = iter([0, 0, yara_scan.YARA_WALL_CLOCK_BUDGET, yara_scan.YARA_WALL_CLOCK_BUDGET])
    monkeypatch.setattr(yara_scan, "time", type("FakeTime", (), {
        "monotonic": staticmethod(lambda: next(ticks)),
    }))

    hits, note = yara_scan.analyze_yara(str(target), str(rules))

    assert len(hits) == 1   # only a.yar was scanned before the budget tripped
    assert "budget exceeded" in note


@requires("yara")
def test_yara_scan_of_a_large_rules_directory_stays_fast(tmp_path):
    """End-to-end wall-clock proof, not just the unit-level ones above: a
    rules directory with more files than a triage tool should spend more
    than a few seconds on must still return quickly."""
    from ioc_inquest.static import yara_scan

    rules = tmp_path / "rules"
    rules.mkdir()
    for i in range(50):
        (rules / f"r{i}.yar").write_text(RULE)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"IOCINQUESTTESTMARKER")

    started = time.monotonic()
    hits, note = yara_scan.analyze_yara(str(target), str(rules))
    elapsed = time.monotonic() - started

    assert elapsed < 10.0, f"took {elapsed:.2f}s -- 50 tiny rule files should be fast"
    assert len(hits) == 50
    assert note == ""


def test_rules_dir_is_the_renamed_path(tmp_path, monkeypatch):
    from ioc_inquest.static import yara_scan

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    (tmp_path / "ioc-inquest" / "yara").mkdir(parents=True)

    assert yara_scan.rules_dir() == tmp_path / "ioc-inquest" / "yara"


def test_a_pre_rename_ruleset_is_still_read(tmp_path, monkeypatch):
    """A rename must not quietly turn a populated ruleset into an empty scan."""
    from ioc_inquest.static import yara_scan

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    (tmp_path / "hash-searcher" / "yara").mkdir(parents=True)

    assert yara_scan.rules_dir() == tmp_path / "hash-searcher" / "yara"


def test_the_renamed_path_outranks_the_pre_rename_one(tmp_path, monkeypatch):
    from ioc_inquest.static import yara_scan

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    (tmp_path / "ioc-inquest" / "yara").mkdir(parents=True)
    (tmp_path / "hash-searcher" / "yara").mkdir(parents=True)

    assert yara_scan.rules_dir() == tmp_path / "ioc-inquest" / "yara"


def test_neither_directory_resolves_to_the_renamed_path(tmp_path, monkeypatch):
    from ioc_inquest.static import yara_scan

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    assert yara_scan.rules_dir() == tmp_path / "ioc-inquest" / "yara"
