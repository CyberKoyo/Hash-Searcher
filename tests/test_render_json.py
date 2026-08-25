import json

from hash_searcher.models import WhoisRecord
from hash_searcher.render.json_out import to_dict, write_json


def test_schema_keys_are_preserved(sample_report):
    data = to_dict(sample_report)
    assert set(data) == {"file", "time", "report"}
    # Phase 2 adds "vt"; every Phase 1 key above it is unchanged, and
    # "verdict" appears only when one is passed -- see the two tests below.
    assert set(data["report"]) == {"hash", "otx", "censys", "whois", "vt_rules",
                                   "ipdb", "vt"}


def test_censys_entry_has_no_hostnames_key(sample_report):
    # CensysHost carries a `hostnames` field the old censys_formatter output
    # never had. asdict() would leak it; the serializer must not.
    entry = to_dict(sample_report)["report"]["censys"][0]
    assert set(entry) == {"ip", "org", "asn", "country", "ports", "new_hostnames"}


def test_whois_success_entry_has_no_error_key(sample_report):
    # The old whois_formatter never put an `error` key on a successful record.
    entry = to_dict(sample_report)["report"]["whois"][0]
    assert set(entry) == {"domain", "created", "expires", "registrar"}


def test_whois_error_entry_has_only_domain_and_error(sample_report):
    # The old whois_formatter's error branch emitted just `domain`/`error` --
    # no created/expires/registrar filler.
    sample_report.whois = [WhoisRecord(domain="bad.example", error="NXDOMAIN")]
    entry = to_dict(sample_report)["report"]["whois"][0]
    assert set(entry) == {"domain", "error"}
    assert entry == {"domain": "bad.example", "error": "NXDOMAIN"}


def test_sigma_rules_are_grouped_by_level(sample_report):
    rules = to_dict(sample_report)["report"]["vt_rules"]
    assert rules["high"] == [{"title": "Suspicious Process", "description": "spawns cmd"}]
    assert rules["medium"] == [] and rules["low"] == []


def test_ipdb_section_is_present(sample_report):
    # Fetched and printed on main, but silently dropped from the JSON output.
    ipdb = to_dict(sample_report)["report"]["ipdb"]
    assert ipdb == [{"ip": "198.51.100.10", "confidence": 90, "reports": 2,
                     "hostnames": [], "domain": None}]


def test_write_json_round_trips(tmp_path, sample_report):
    path = write_json(sample_report, str(tmp_path / "out.json"))
    assert json.loads(open(path).read())["report"]["hash"] == "abc123"


def test_json_carries_the_verdict_and_its_signals(sample_report, tmp_path):
    import json
    from hash_searcher.models import Signal, Verdict
    from hash_searcher.render.json_out import write_json

    verdict = Verdict(level="MALICIOUS", score=50,
                      signals=[Signal("detection", 50, "48/72 engines flagged this file")])
    path = tmp_path / "out.json"
    write_json(sample_report, str(path), verdict)

    body = json.loads(path.read_text())["report"]["verdict"]
    assert body["level"] == "MALICIOUS"
    assert body["score"] == 50
    assert body["signals"] == [
        {"name": "detection", "points": 50, "detail": "48/72 engines flagged this file"}
    ]


def test_json_without_a_verdict_omits_the_key_entirely(sample_report, tmp_path):
    """Backward compatibility: a consumer of the Phase 1 schema must not
    start seeing a null it never had to handle."""
    import json
    from hash_searcher.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    assert "verdict" not in json.loads(path.read_text())["report"]


def test_json_keeps_every_phase_1_key(sample_report, tmp_path):
    """_censys_dict and _whois_dict exist to reproduce the pre-refactor
    shapes exactly. Adding keys must not perturb the ones already there."""
    import json
    from hash_searcher.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    body = json.loads(path.read_text())["report"]
    for key in ("hash", "otx", "censys", "whois", "ipdb", "vt_rules"):
        assert key in body


def test_json_carries_the_new_vt_blocks(sample_report, tmp_path):
    import json
    from hash_searcher.models import Detection, PEInfo, Signature, ThreatClass
    from hash_searcher.render.json_out import write_json

    sample_report.vt.detection = Detection(malicious=48, suspicious=2, undetected=20, timeout=2)
    sample_report.vt.threat = ThreatClass(label="trojan.emotet", family="emotet",
                                          categories=["trojan"])
    sample_report.vt.signature = Signature(verified=True, signer="Contoso Ltd")
    sample_report.vt.pe = PEInfo(imphash="abc", sections=3, compiled="2019-04-02")
    sample_report.vt.contacted_domains = ["evil.example"]

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    vt = json.loads(path.read_text())["report"]["vt"]

    assert vt["detection"] == {"malicious": 48, "total": 72, "ratio": "48/72"}
    assert vt["threat"]["family"] == "emotet"
    assert vt["signature"]["verified"] is True
    assert vt["pe"]["sections"] == 3
    assert vt["contacted_domains"] == ["evil.example"]


def test_json_vt_blocks_vt_never_returned_are_null(sample_report, tmp_path):
    """A key that is present-but-null says 'VT had nothing here'. Omitting it
    would make a consumer guess whether the tool looked at all."""
    import json
    from hash_searcher.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    vt = json.loads(path.read_text())["report"]["vt"]
    assert vt["detection"] is None
    assert vt["threat"] is None
    assert vt["sandbox"] == [] and vt["yara"] == [] and vt["techniques"] == []
