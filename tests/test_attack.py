import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def _bundle() -> dict:
    return json.loads((FIXTURES / "mitre_mini.json").read_text())


def test_resolve_names_a_technique_and_its_tactic():
    from hash_searcher.analysis.attack import resolve

    [technique] = resolve(["T1055"], _bundle())
    assert technique.id == "T1055"
    assert technique.name == "Process Injection"
    assert technique.tactic == "defense-evasion"
    assert technique.url == "https://attack.mitre.org/techniques/T1055"


def test_resolve_handles_a_sub_technique_id():
    from hash_searcher.analysis.attack import resolve

    [technique] = resolve(["T1566.001"], _bundle())
    assert technique.name == "Spearphishing Attachment"


def test_an_unknown_id_survives_as_itself():
    """A vendored bundle older than the pulse must not silently drop
    techniques -- that would turn stale data into missing data."""
    from hash_searcher.analysis.attack import resolve

    [technique] = resolve(["T9999"], _bundle())
    assert technique.id == "T9999"
    assert technique.name == "T9999"
    assert technique.tactic is None


def test_resolve_deduplicates_and_preserves_first_seen_order():
    from hash_searcher.analysis.attack import resolve

    assert [t.id for t in resolve(["T1566.001", "T1055", "T1566.001"], _bundle())] \
        == ["T1566.001", "T1055"]


def test_non_attack_pattern_objects_are_ignored():
    """The bundle carries identities, relationships, and marking definitions;
    only attack-pattern objects have technique IDs."""
    from hash_searcher.analysis.attack import resolve

    assert resolve(["The MITRE Corporation"], _bundle())[0].tactic is None


def test_technique_ids_from_otx_pulses():
    from hash_searcher.analysis.attack import technique_ids_from_otx

    raw = {"pulse_info": {"pulses": [
        {"attack_ids": [{"id": "T1055", "display_name": "T1055 - Process Injection"}]},
        {"attack_ids": [{"id": "T1566.001"}]},
    ]}}
    assert technique_ids_from_otx(raw) == ["T1055", "T1566.001"]


def test_technique_ids_from_vt_behaviour_trees():
    from hash_searcher.analysis.attack import technique_ids_from_vt

    raw = {"data": {"attributes": {"behaviour_mitre_trees": {
        "Zenbox": {"tactics": [{"techniques": [
            {"id": "T1055", "signatures": []},
            {"id": "T1027", "signatures": []},
        ]}]}
    }}}}
    assert technique_ids_from_vt(raw) == ["T1055", "T1027"]


def test_technique_ids_tolerate_an_error_payload():
    from hash_searcher.analysis.attack import technique_ids_from_otx, technique_ids_from_vt
    from hash_searcher.api.base_call import make_error

    assert technique_ids_from_otx(make_error("nope", 404)) == []
    assert technique_ids_from_vt(make_error("nope", 404)) == []


def test_the_vendored_bundle_resolves_a_real_technique():
    """Every other test here runs against tests/fixtures/mitre_mini.json, and
    load_bundle degrades silently on OSError/ValueError -- so replacing the
    shipped 897 KB bundle with `{"objects": []}` left the whole suite green.
    Nothing verified the file we actually ship is a bundle at all, which also
    means nothing guarded the packaging.
    """
    from hash_searcher.analysis.attack import BUNDLE_PATH, resolve

    assert BUNDLE_PATH.exists(), BUNDLE_PATH
    technique = resolve(["T1055"])[0]
    assert technique.name == "Process Injection"
    assert technique.tactic == "defense-evasion"
    assert technique.url == "https://attack.mitre.org/techniques/T1055"


def test_resolving_nothing_does_not_read_the_bundle():
    """The 649-entry index was built before the loop ran, so every extract_vt
    call parsed 897 KB whether or not the payload had any ATT&CK data."""
    from hash_searcher.analysis import attack

    calls = []
    original = attack._default_index
    attack._default_index = lambda: calls.append(1) or {}
    try:
        assert attack.resolve([]) == []
    finally:
        attack._default_index = original
    assert calls == []
