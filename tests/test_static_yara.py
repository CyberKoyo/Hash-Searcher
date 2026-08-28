from tests.conftest import requires

RULE = """
rule Hash_Searcher_Test_Rule
{
    meta:
        description = "matches a synthetic marker, never real malware"
    strings:
        $marker = "HASHSEARCHERTESTMARKER"
    condition:
        $marker
}
"""


def test_yara_returns_nothing_without_the_library(tmp_path, monkeypatch):
    from hash_searcher.static import yara_scan

    monkeypatch.setattr(yara_scan.capabilities, "have", lambda name: False)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"anything")
    assert yara_scan.analyze_yara(str(target), str(tmp_path)) == []


def test_yara_returns_nothing_when_the_rules_directory_is_absent(tmp_path):
    """No rules is the default state for a fresh install; it must be a quiet
    empty result, not an error the user has to silence."""
    from hash_searcher.static.yara_scan import analyze_yara

    target = tmp_path / "sample.bin"
    target.write_bytes(b"anything")
    assert analyze_yara(str(target), str(tmp_path / "no-such-dir")) == []


@requires("yara")
def test_a_matching_rule_is_reported_with_its_name(tmp_path):
    from hash_searcher.static.yara_scan import analyze_yara

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test.yar").write_text(RULE)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"padding HASHSEARCHERTESTMARKER padding")

    assert [h.rule for h in analyze_yara(str(target), str(rules))] == \
        ["Hash_Searcher_Test_Rule"]


@requires("yara")
def test_a_non_matching_file_yields_no_hits(tmp_path):
    from hash_searcher.static.yara_scan import analyze_yara

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test.yar").write_text(RULE)

    target = tmp_path / "clean.bin"
    target.write_bytes(b"nothing interesting here")

    assert analyze_yara(str(target), str(rules)) == []


@requires("yara")
def test_a_broken_rule_file_does_not_abort_the_scan(tmp_path):
    """One malformed .yar in a user's rules directory must not take the whole
    run down -- the other rules still have something to say. This is why each
    file is compiled separately rather than in one batch."""
    from hash_searcher.static.yara_scan import analyze_yara

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "good.yar").write_text(RULE)
    (rules / "broken.yar").write_text("rule Nope { this is not yara }")

    target = tmp_path / "sample.bin"
    target.write_bytes(b"HASHSEARCHERTESTMARKER")

    assert [h.rule for h in analyze_yara(str(target), str(rules))] == \
        ["Hash_Searcher_Test_Rule"]
