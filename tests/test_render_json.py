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

    assert vt["detection"] == {
        # All five buckets, not just malicious/total/ratio: the TTY prints
        # suspicious and undetected, and a JSON consumer that cannot
        # reconstruct what the terminal showed is reading a different report.
        "malicious": 48, "suspicious": 2, "harmless": 0, "undetected": 20,
        "timeout": 2, "total": 72, "ratio": "48/72",
    }
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


def test_a_failed_censys_lookup_is_visible_in_the_json(sample_report, tmp_path):
    """The TTY names the error; the JSON used to omit it, so a 403 serialized
    as a host with null org, null asn, and no ports -- indistinguishable from
    a real host Censys knew nothing about."""
    import json
    from hash_searcher.models import CensysHost
    from hash_searcher.render.json_out import write_json

    sample_report.hosts = [CensysHost(ip="198.51.100.10", error="Censys 403: forbidden")]
    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    host = json.loads(path.read_text())["report"]["censys"][0]
    assert host["error"] == "Censys 403: forbidden"
    assert host["ip"] == "198.51.100.10"


# --- Phase 3: the static block ------------------------------------------


def test_static_block_is_omitted_when_report_static_is_none(sample_report, tmp_path):
    """Backward compatibility, the same rule Phase 2's verdict block
    established: a consumer of the pre-Phase-3 schema must not start seeing
    a new key -- null or otherwise -- it never had to handle."""
    from hash_searcher.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    assert "static" not in json.loads(path.read_text())["report"]


def test_static_block_carries_every_analyzer_field(sample_report, tmp_path):
    from hash_searcher.models import EntropyReport, StaticReport, YaraHit
    from hash_searcher.render.json_out import write_json

    sample_report.static = StaticReport(
        path="/tmp/sample.exe", size=2048, sha256="a" * 64,
        entropy=EntropyReport(overall=7.9, packed=True, note="packed"),
        yara=[YaraHit(rule="Emotet_Loader")],
        skipped=["magic"], failed=["pe"],
    )
    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    static = json.loads(path.read_text())["report"]["static"]

    assert static["path"] == "/tmp/sample.exe"
    assert static["size"] == 2048
    assert static["sha256"] == "a" * 64
    assert static["entropy"] == {"overall": 7.9, "packed": True, "note": "packed"}
    assert static["yara"] == [
        {"rule": "Emotet_Loader", "namespace": "default", "tags": []}
    ]
    # Present-but-null for an analyzer that never produced a result, same
    # rule _vt_dict already follows: a consumer can tell "this analyzer had
    # nothing" from "this tool never ran it".
    assert static["filetype"] is None
    assert static["pe"] is None
    assert static["strings"] is None
    assert static["skipped"] == ["magic"]
    assert static["failed"] == ["pe"]


def test_a_successful_censys_host_has_no_error_key(sample_report, tmp_path):
    """Phase 1 schema compatibility: the success shape is unchanged."""
    import json
    from hash_searcher.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    assert "error" not in json.loads(path.read_text())["report"]["censys"][0]
