import json

from ioc_inquest.models import WhoisRecord
from ioc_inquest.render.json_out import to_dict, write_json


def test_schema_keys_are_preserved(sample_report):
    data = to_dict(sample_report)
    assert set(data) == {"file", "time", "report"}
    # Phase 2 adds "vt"; every Phase 1 key above it is unchanged, and
    # "verdict" appears only when one is passed -- see the two tests below.
    assert set(data["report"]) == {"hash", "otx", "censys", "whois", "vt_rules",
                                   "ipdb", "vt",
                                   # Phase 4, always present, null when the
                                   # source never ran.
                                   "bazaar", "threatfox", "certs", "shodan",
                                   "greynoise", "kev", "kev_error",
                                   "kev_unchecked",
                                   # Phase 5 Task A4: ThreatFox per contacted
                                   # IP. Additive and keyed by IP the way
                                   # "shodan"/"greynoise" are; "threatfox"
                                   # keeps its meaning (the sample lookup)
                                   # untouched.
                                   "threatfox_ips",
                                   # Phase 5 Part B: the tool accepts an IP,
                                   # a domain, or a URL now, so "hash" alone
                                   # no longer says what its value is. Added
                                   # beside it rather than replacing it --
                                   # "hash" keeps its name, its position, and
                                   # its meaning (the looked-up indicator).
                                   "indicator_kind"}


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
    from ioc_inquest.models import Signal, Verdict
    from ioc_inquest.render.json_out import write_json

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
    from ioc_inquest.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    assert "verdict" not in json.loads(path.read_text())["report"]


def test_json_keeps_every_phase_1_key(sample_report, tmp_path):
    """_censys_dict and _whois_dict exist to reproduce the pre-refactor
    shapes exactly. Adding keys must not perturb the ones already there."""
    import json
    from ioc_inquest.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    body = json.loads(path.read_text())["report"]
    for key in ("hash", "otx", "censys", "whois", "ipdb", "vt_rules"):
        assert key in body


def test_json_carries_the_new_vt_blocks(sample_report, tmp_path):
    import json
    from ioc_inquest.models import Detection, PEInfo, Signature, ThreatClass
    from ioc_inquest.render.json_out import write_json

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


def test_wrong_typed_vt_text_is_absent_instead_of_python_spelled(sample_report):
    from ioc_inquest.models import SandboxVerdict, ThreatClass

    sample_report.vt.threat = ThreatClass(label=False)
    sample_report.vt.sandbox = [
        SandboxVerdict(sandbox=0, category="malicious"),
    ]

    vt = to_dict(sample_report)["report"]["vt"]
    assert vt["threat"]["label"] == ""
    assert vt["sandbox"][0]["sandbox"] == ""


def test_json_vt_blocks_vt_never_returned_are_null(sample_report, tmp_path):
    """A key that is present-but-null says 'VT had nothing here'. Omitting it
    would make a consumer guess whether the tool looked at all."""
    import json
    from ioc_inquest.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    vt = json.loads(path.read_text())["report"]["vt"]
    assert vt["detection"] is None
    assert vt["threat"] is None
    assert vt["sandbox"] == [] and vt["yara"] == [] and vt["techniques"] == []


def test_a_404_and_a_503_no_longer_serialize_identically(sample_report, tmp_path):
    """Before this, the VT JSON block carried neither `error` nor
    `unavailable` -- a 404 (VT answered: no record) and a 503 (VT never
    answered) both serialized as every field null, indistinguishable to the
    one consumer, a script branching on exit 3, this whole task exists to
    inform. `unavailable` is explicit on both -- `false` on the 404, not a
    missing key a consumer has to read meaning into."""
    from ioc_inquest.analysis.vt import extract_vt
    from ioc_inquest.api.base_call import make_error
    from ioc_inquest.render.json_out import write_json

    sample_report.vt = extract_vt(make_error("Hash not found in GetTotal", 404))
    path_404 = tmp_path / "404.json"
    write_json(sample_report, str(path_404))
    vt_404 = json.loads(path_404.read_text())["report"]["vt"]

    sample_report.vt = extract_vt(make_error("GetTotal API Error 503", 503))
    path_503 = tmp_path / "503.json"
    write_json(sample_report, str(path_503))
    vt_503 = json.loads(path_503.read_text())["report"]["vt"]

    assert vt_404 != vt_503
    assert vt_404["error"] == "Hash not found in GetTotal"
    assert vt_404["unavailable"] is False
    assert vt_503["error"] == "GetTotal API Error 503"
    assert vt_503["unavailable"] is True


def test_a_healthy_vt_block_carries_no_error_or_unavailable_key(sample_report):
    """_vt_dict follows _censys_dict's exact precedent: `error`/`unavailable`
    are omitted entirely on a healthy call, so the success shape stays
    byte-identical to before this task. Mirrors
    test_censys_entry_has_no_hostnames_key and
    test_whois_success_entry_has_no_error_key -- the same guarantee, for
    the one block neither of those two tests covers."""
    vt = to_dict(sample_report)["report"]["vt"]
    assert set(vt) == {"detection", "threat", "submission", "signature",
                        "sandbox", "yara", "pe", "techniques", "contacted_domains"}


def test_a_failed_censys_lookup_is_visible_in_the_json(sample_report, tmp_path):
    """The TTY names the error; the JSON used to omit it, so a 403 serialized
    as a host with null org, null asn, and no ports -- indistinguishable from
    a real host Censys knew nothing about."""
    import json
    from ioc_inquest.models import CensysHost
    from ioc_inquest.render.json_out import write_json

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
    from ioc_inquest.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    assert "static" not in json.loads(path.read_text())["report"]


def test_static_block_carries_every_analyzer_field(sample_report, tmp_path):
    from ioc_inquest.models import EntropyReport, StaticReport, YaraHit
    from ioc_inquest.render.json_out import write_json

    sample_report.static = StaticReport(
        path="/tmp/sample.exe", size=2048, sha256="a" * 64,
        entropy=EntropyReport(overall=7.9, packed=True, note="packed"),
        yara=[YaraHit(rule="Emotet_Loader")],
        yara_note="stopped after 200 of 500 rule files",
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
    assert static["yara_note"] == "stopped after 200 of 500 rule files"
    # Present-but-null for an analyzer that never produced a result, same
    # rule _vt_dict already follows: a consumer can tell "this analyzer had
    # nothing" from "this tool never ran it".
    assert static["filetype"] is None
    assert static["pe"] is None
    assert static["strings"] is None
    assert static["skipped"] == ["magic"]
    assert static["failed"] == ["pe"]


def test_static_pe_block_carries_the_section_entropy_note(sample_report, tmp_path):
    """branch-review.md I1: a silently truncated number is worse than a
    stated one -- the note must actually reach the JSON consumer."""
    from ioc_inquest.models import PEStaticReport, StaticReport
    from ioc_inquest.render.json_out import write_json

    sample_report.static = StaticReport(
        path="/tmp/sample.exe", size=2048, sha256="a" * 64,
        pe=PEStaticReport(
            section_entropy_note="entropy computed over the first 16384 "
                                  "bytes of 2 of 2 sections (Global Constraint 5)",
        ),
    )
    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    static = json.loads(path.read_text())["report"]["static"]
    assert static["pe"]["section_entropy_note"] == (
        "entropy computed over the first 16384 bytes of 2 of 2 sections "
        "(Global Constraint 5)"
    )


def test_a_successful_censys_host_has_no_error_key(sample_report, tmp_path):
    """Phase 1 schema compatibility: the success shape is unchanged."""
    import json
    from ioc_inquest.render.json_out import write_json

    path = tmp_path / "out.json"
    write_json(sample_report, str(path))
    assert "error" not in json.loads(path.read_text())["report"]["censys"][0]


def test_the_phase_4_sources_reach_the_json(tmp_path, sample_report):
    """A field that renders in the terminal and vanishes from -o report.json
    is the drift this test exists to catch."""
    from ioc_inquest.models import (
        BazaarReport, CertReport, GreyNoiseReport, KEVEntry, KEVReport,
        ShodanReport, SourceResult, ThreatFoxReport,
    )
    from ioc_inquest.render.json_out import to_dict

    sample_report.bazaar = SourceResult(
        value=BazaarReport(found=True, family="Emotet", tags=["exe"]), queried=True)
    sample_report.threatfox = SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet", confidence=90),
        queried=True)
    sample_report.certs = SourceResult(
        value=CertReport(siblings=["a.example"], count=42), queried=True)
    sample_report.shodan = {"198.51.100.10": SourceResult(
        value=ShodanReport(ports=[22], vulns=["CVE-2021-41617"]), queried=True)}
    sample_report.greynoise = {"198.51.100.10": SourceResult(
        value=GreyNoiseReport(seen=True, classification="malicious"), queried=True)}
    sample_report.kev = SourceResult(
        value=KEVReport(entries=[KEVEntry(cve="CVE-2021-41617", product="OpenSSH")]),
        queried=True)

    body = to_dict(sample_report)["report"]
    assert body["bazaar"]["family"] == "Emotet"
    assert body["threatfox"]["malware"] == "Emotet"
    # The untruncated total travels with the capped list, same as the TTY.
    assert body["certs"]["count"] == 42
    assert body["shodan"]["198.51.100.10"]["vulns"] == ["CVE-2021-41617"]
    assert body["greynoise"]["198.51.100.10"]["classification"] == "malicious"
    assert [e["cve"] for e in body["kev"]] == ["CVE-2021-41617"]


def test_a_source_that_never_ran_is_null_rather_than_missing(tmp_path, sample_report):
    """Present-but-null is the rule the rest of this module follows: a
    consumer can tell "the source had nothing" from "this tool never asked"."""
    from ioc_inquest.render.json_out import to_dict

    body = to_dict(sample_report)["report"]
    assert body["bazaar"] is None
    assert body["threatfox"] is None
    assert body["certs"] is None
    assert body["shodan"] == {} and body["greynoise"] == {} and body["kev"] == []


def test_per_ip_threatfox_reaches_the_json(sample_report):
    """The machine consumer is the one that most needs a C2 attribution --
    an analyst can read the TTY, a script branching on exit codes cannot.
    Never-asked stays present-but-null, the rule the rest of the module
    follows, so "ThreatFox had nothing" never reads as "nobody asked"."""
    from ioc_inquest.models import SourceResult, ThreatFoxReport

    sample_report.threatfox_ips = {
        "198.51.100.10": SourceResult(
            value=ThreatFoxReport(found=True, malware="Emotet", confidence=90,
                                  tags=["botnet"]), queried=True),
        "203.0.113.7": SourceResult(),
    }
    block = to_dict(sample_report)["report"]["threatfox_ips"]
    assert block["198.51.100.10"] == {
        "found": True, "malware": "Emotet", "confidence": 90,
        "tags": ["botnet"], "error": None,
    }
    assert block["203.0.113.7"] is None


def test_the_sample_level_threatfox_key_still_means_the_sample(sample_report):
    """Constraint 7: an existing key never changes meaning. A per-IP hit
    must not leak into the key a consumer already reads as the sample's
    own answer."""
    from ioc_inquest.models import SourceResult, ThreatFoxReport

    sample_report.threatfox_ips = {"198.51.100.10": SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet"), queried=True)}
    assert to_dict(sample_report)["report"]["threatfox"] is None


#: The six sources _source_dict wraps, each with a distinct error string so a
#: test that reads the wrong block cannot pass by coincidence.
#:
#: Six, not the two or three a finding happens to name. `error` could be
#: deleted from _source_dict outright -- `"error": result.error` ->
#: `"error": None` -- with 431 tests green, which collapses a FAILED source
#: into a successful one for every source below at once. The only `error`
#: assertion that reached a _source_dict block before this pinned `None` on a
#: SUCCESSFUL entry, which is exactly what that mutant produces.
def _errored_phase4(report):
    """Every _source_dict-wrapped source in the queried-and-failed state."""
    from ioc_inquest.models import SourceResult

    report.bazaar = SourceResult(error="MalwareBazaar API Error 502", queried=True)
    report.threatfox = SourceResult(error="ThreatFox API Error 502", queried=True)
    report.certs = SourceResult(error="crt.sh API Error 502", queried=True)
    report.shodan = {"198.51.100.10": SourceResult(
        error="Shodan API Error 403", queried=True)}
    report.greynoise = {"198.51.100.10": SourceResult(
        error="GreyNoise API Error 429", queried=True)}
    report.threatfox_ips = {"198.51.100.10": SourceResult(
        error="ThreatFox API Error 500", queried=True)}
    return report


def test_a_failed_phase_4_source_carries_its_error_into_the_json(sample_report):
    """The JSON is the only machine-readable record that a source failed.

    The whole expected dict, not just the `error` key: _source_dict's
    documented bargain is that a failed source keeps the shape its wrapped
    report had -- every field present at its zero value, `error` set -- so a
    consumer reading `ports` off a failed Shodan block gets `[]` and an
    `error` beside it rather than a missing key. The error branch of that
    promise was pinned by nothing.
    """
    body = to_dict(_errored_phase4(sample_report))["report"]

    assert body["bazaar"] == {
        "found": False, "family": None, "tags": [], "file_type": None,
        "first_seen": None, "yara": [],
        "error": "MalwareBazaar API Error 502",
    }
    assert body["threatfox"] == {
        "found": False, "malware": None, "confidence": 0, "tags": [],
        "error": "ThreatFox API Error 502",
    }
    assert body["certs"] == {
        "siblings": [], "count": 0,
        "error": "crt.sh API Error 502",
    }
    assert body["shodan"]["198.51.100.10"] == {
        "ports": [], "cpes": [], "vulns": [], "hostnames": [],
        "error": "Shodan API Error 403",
    }
    assert body["greynoise"]["198.51.100.10"] == {
        "seen": False, "classification": None, "name": None, "last_seen": None,
        "error": "GreyNoise API Error 429",
    }
    assert body["threatfox_ips"]["198.51.100.10"] == {
        "found": False, "malware": None, "confidence": 0, "tags": [],
        "error": "ThreatFox API Error 500",
    }


def test_the_three_source_states_stay_distinguishable_in_the_json(sample_report):
    """never-asked / asked-and-failed / answered, for all six sources.

    Pinning only the error dict would leave `_source_dict` free to return the
    error shape for a healthy source, or `None` for a failed one -- the
    collapse SourceResult exists to prevent, one surface over. The three
    states must be three different JSON values for every source, not for the
    one a finding happened to name.
    """
    from ioc_inquest.models import (
        BazaarReport, CertReport, GreyNoiseReport, ShodanReport, SourceResult,
        ThreatFoxReport,
    )

    names = ("bazaar", "threatfox", "certs")
    per_ip = ("shodan", "greynoise", "threatfox_ips")

    never = to_dict(sample_report)["report"]
    for name in names:
        assert never[name] is None, f"{name} never-asked is not null"
    for name in per_ip:
        setattr(sample_report, name, {"198.51.100.10": SourceResult()})
    never = to_dict(sample_report)["report"]
    for name in per_ip:
        assert never[name]["198.51.100.10"] is None, \
            f"{name} never-asked is not null"

    failed = to_dict(_errored_phase4(sample_report))["report"]

    sample_report.bazaar = SourceResult(value=BazaarReport(), queried=True)
    sample_report.threatfox = SourceResult(value=ThreatFoxReport(), queried=True)
    sample_report.certs = SourceResult(value=CertReport(), queried=True)
    sample_report.shodan = {"198.51.100.10": SourceResult(
        value=ShodanReport(), queried=True)}
    sample_report.greynoise = {"198.51.100.10": SourceResult(
        value=GreyNoiseReport(), queried=True)}
    sample_report.threatfox_ips = {"198.51.100.10": SourceResult(
        value=ThreatFoxReport(), queried=True)}
    answered = to_dict(sample_report)["report"]

    for name in names:
        assert failed[name] != answered[name], f"{name} error == answered"
        assert failed[name] is not None and answered[name] is not None
        assert answered[name]["error"] is None, f"{name} answered carries an error"
    for name in per_ip:
        got_failed = failed[name]["198.51.100.10"]
        got_ok = answered[name]["198.51.100.10"]
        assert got_failed != got_ok, f"{name} error == answered"
        assert got_failed is not None and got_ok is not None
        assert got_ok["error"] is None, f"{name} answered carries an error"


def test_an_unreachable_kev_catalog_says_so_and_says_how_much_went_unchecked(
        sample_report):
    """The two keys Constraint 5 and Ruling 2 were written about.

    `kev_error` and `kev_unchecked` could both be replaced with constants --
    `kev.error -> None`, `kev.value.unchecked if kev.value else 0 -> 0` --
    with the suite green. test_schema_keys_are_preserved proves the keys
    exist; nothing proved either still meant anything.

    `unchecked` is the one field models.py says survives an error, and an
    empty `kev` list beside a null `kev_error` is exactly the Phase 4 bug:
    "nobody could ask" reading as "nothing is exploited".
    """
    from ioc_inquest.models import KEVReport, SourceResult

    sample_report.kev = SourceResult(value=KEVReport(unchecked=3),
                                     error="CISA KEV API Error 503", queried=True)
    body = to_dict(sample_report)["report"]
    assert body["kev_error"] == "CISA KEV API Error 503"
    assert body["kev_unchecked"] == 3
    assert body["kev"] == []


def test_a_healthy_kev_catalog_reports_nothing_unchecked(sample_report):
    """The other side of the same two keys: a successful catalog fetch leaves
    `kev_error` null and `kev_unchecked` at zero, so the assertion above is
    pinning the failure state rather than a constant."""
    from ioc_inquest.models import KEVEntry, KEVReport, SourceResult

    sample_report.kev = SourceResult(
        value=KEVReport(entries=[KEVEntry(cve="CVE-2021-41617")], unchecked=0),
        queried=True)
    body = to_dict(sample_report)["report"]
    assert body["kev_error"] is None
    assert body["kev_unchecked"] == 0
    assert [e["cve"] for e in body["kev"]] == ["CVE-2021-41617"]


def test_a_failed_otx_lookup_is_distinguishable_from_one_that_never_ran(sample_report):
    """The `error` key OTX did not have, and the shape it matches.

    Every other source in this document already carries its own error --
    censys entries add one when set, `vt` adds one when set, the Phase 4
    blocks carry it always. OTX did not, and `recorded_instances` is "N/A"
    in both states, so a machine consumer had nothing to branch on: a
    failed lookup serialized byte-identically to one nobody made.

    Added under an explicit exception to Global Constraint 7, and in the
    shape _censys_dict set: present only when set, so the success document
    is unchanged. Asserted both ways round -- the key appears on failure
    and is absent on success -- because "unchanged on success" is half the
    exception's terms.
    """
    import dataclasses

    from ioc_inquest.models import OTXReport

    healthy = to_dict(sample_report)
    assert "error" not in healthy["report"]["otx"]
    assert set(healthy["report"]["otx"]) == {"recorded_instances",
                                             "attack_techniques"}

    failed = to_dict(dataclasses.replace(
        sample_report, otx=OTXReport(recorded_instances="N/A",
                                     error="OTX key not set")))
    never_asked = to_dict(dataclasses.replace(
        sample_report, otx=OTXReport(recorded_instances="N/A")))

    assert failed["report"]["otx"]["error"] == "OTX key not set"
    assert "error" not in never_asked["report"]["otx"]
    assert failed["report"]["otx"] != never_asked["report"]["otx"]
    # And it survives the serializer, not just the dict builder.
    assert '"error": "OTX key not set"' in json.dumps(failed, indent=4)


def test_indicator_kind_says_what_the_hash_key_holds(sample_report):
    """The "hash" key holds whatever was looked up, which since Part B can
    be an address. It keeps its name for its consumers; this says what the
    value actually is."""
    sample_report.indicator = "198.51.100.10"
    sample_report.indicator_kind = "ip"
    body = to_dict(sample_report)["report"]
    assert body["hash"] == "198.51.100.10"
    assert body["indicator_kind"] == "ip"


def test_a_report_built_without_a_kind_still_reads_as_a_hash(sample_report):
    # Every Report built before Part B meant "hash", and the default keeps
    # meaning that -- this key is additive in value as well as in name.
    assert to_dict(sample_report)["report"]["indicator_kind"] == "hash"
