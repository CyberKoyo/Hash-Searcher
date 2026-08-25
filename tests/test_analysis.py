from hash_searcher.analysis.censys import extract_hosts
from hash_searcher.analysis.ipdb import extract_ips
from hash_searcher.analysis.otx import extract_otx
from hash_searcher.analysis.vt import extract_vt
from hash_searcher.analysis.whois import extract_whois
from hash_searcher.api.base_call import make_error
from hash_searcher.models import IPReport


def test_extract_vt_partitions_sigma_and_reads_both_relationships(fixture_json):
    vt = extract_vt(fixture_json("vt_malicious"))
    assert vt.found is True
    assert [r.title for r in vt.by_level("high")] == ["Suspicious Process"]
    assert vt.contacted_ips == ["198.51.100.10", "203.0.113.20"]
    # contacted_domains is requested by virustotal.py but was never parsed.
    assert vt.contacted_domains == ["bad.example"]


def test_extract_vt_on_a_404():
    vt = extract_vt(make_error("Hash not found in GetTotal", 404))
    assert vt.found is False
    assert vt.sigma == []
    assert vt.error == "Hash not found in GetTotal"


def test_extract_otx_deduplicates_techniques_in_first_seen_order(fixture_json):
    otx = extract_otx(fixture_json("otx_pulses"))
    assert otx.recorded_instances == 7
    assert otx.attack_techniques == [
        "T1059 Command and Scripting Interpreter",
        "T1105 Ingress Tool Transfer",
    ]


def test_extract_otx_with_no_pulse_info():
    otx = extract_otx({})
    assert otx.recorded_instances == "N/A"
    assert otx.attack_techniques == []
    assert otx.has_pulses is False


def test_extract_otx_pulse_info_without_a_count_key_matches_original_fallback():
    """The pre-branch otx_formatter's default for a missing `count` key was
    the string 'N/A, No recorded instances', not a bare 'N/A' -- the two
    values are printed verbatim and must not be conflated."""
    otx = extract_otx({"pulse_info": {"pulses": []}})
    assert otx.recorded_instances == "N/A, No recorded instances"


def test_extract_otx_has_pulses_true_when_pulses_present(fixture_json):
    otx = extract_otx(fixture_json("otx_pulses"))
    assert otx.has_pulses is True


def test_extract_otx_on_error_has_pulses_false():
    otx = extract_otx(make_error("Hash not found in GetOTX", 404))
    assert otx.has_pulses is False


def test_extract_ips_returns_ipreport_objects(fixture_json):
    ips = extract_ips(fixture_json("ipdb_two_bare_ips"))
    assert isinstance(ips["198.51.100.10"], IPReport)
    assert ips["198.51.100.10"].reports == 2
    assert set(ips) == {"198.51.100.10", "203.0.113.20"}


def test_extract_hosts_flags_only_hostnames_ipdb_lacked(fixture_json):
    ips = {"198.51.100.10": IPReport(ip="198.51.100.10", hostnames=["known.example"])}
    domains, hosts = extract_hosts(fixture_json("censys_host"), ips)
    assert hosts[0].asn == 64496
    assert hosts[0].ports == [80, 443]
    assert hosts[0].new_hostnames == ["new.example"]
    assert "new.example" in domains


def test_extract_hosts_carries_error_entries_rather_than_dropping_them():
    """Phase 1 skipped them, which silently lost main's 'Censys: <error>'
    line (ledger S2). They now come through as hosts carrying an error and
    no enrichment -- see test_a_failed_censys_lookup_becomes_a_host_carrying_its_error."""
    domains, hosts = extract_hosts([make_error("Rate limited", 429)], {})
    assert domains == []
    assert [h.error for h in hosts] == ["Rate limited"]
    assert hosts[0].org is None and hosts[0].ports == []


def test_extract_whois_preserves_failures():
    records = extract_whois([
        {"domain": "a.example", "created": "2020-01-01", "expires": "2027-01-01",
         "registrar": "R"},
        {"domain": "b.example", "error": "No WHOIS data found"},
    ])
    assert records[0].registrar == "R"
    assert records[1].error == "No WHOIS data found"


def test_extract_otx_sets_otx_responded_per_branch(fixture_json):
    """otx_responded mirrors the original's `if not pulse_info:` gate."""
    assert extract_otx(fixture_json("otx_pulses")).otx_responded is True
    assert extract_otx({}).otx_responded is False
    assert extract_otx(make_error("OTX key not set")).otx_responded is False
    # A pulse_info that exists but carries no count is still real data.
    assert extract_otx({"pulse_info": {"pulses": []}}).otx_responded is True


def test_the_two_otx_flags_answer_different_questions():
    """otx_responded is bool(pulse_info); has_pulses is bool(its pulses).
    An empty pulse list is the case that separates them, and conflating the
    two is what caused ruling R28."""
    report = extract_otx({"pulse_info": {"pulses": []}})
    assert report.otx_responded is True
    assert report.has_pulses is False


def test_contacted_ips_reads_the_relationship_block():
    from hash_searcher.api.virustotal import contacted_ips

    payload = {"data": {"relationships": {"contacted_ips": {"data": [
        {"id": "198.51.100.10"}, {"id": "203.0.113.7"},
    ]}}}}
    assert contacted_ips(payload) == ["198.51.100.10", "203.0.113.7"]


def test_contacted_ips_is_empty_on_an_error_payload():
    from hash_searcher.api.base_call import make_error
    from hash_searcher.api.virustotal import contacted_ips

    assert contacted_ips(make_error("Hash not found in GetTotal", 404)) == []


import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def _vt_fixture() -> dict:
    return json.loads((FIXTURES / "vt_full_report.json").read_text())


def test_detection_ratio_counts_only_the_verdict_buckets():
    from hash_searcher.analysis.vt import extract_vt

    report = extract_vt(_vt_fixture())
    assert report.detection.malicious == 48
    assert report.detection.suspicious == 2
    # 48 + 2 + 20 + 0 + 2 == 72; type-unsupported and failure are excluded.
    assert report.detection.total == 72
    assert report.detection.ratio == "48/72"


def test_detection_is_none_when_the_payload_has_no_stats():
    from hash_searcher.analysis.vt import extract_vt

    assert extract_vt({"data": {"attributes": {}}}).detection is None


def test_detection_is_none_on_an_error_payload():
    from hash_searcher.api.base_call import make_error
    from hash_searcher.analysis.vt import extract_vt

    assert extract_vt(make_error("Hash not found in GetTotal", 404)).detection is None


def test_threat_classification_takes_the_most_popular_family():
    """The payload's lists are not pre-sorted, so the first entry is not
    reliably the most popular one. The fixture's first entry is the LOWER
    count on purpose."""
    from hash_searcher.analysis.vt import extract_vt

    threat = extract_vt(_vt_fixture()).threat
    assert threat.label == "trojan.emotet/heurgeneric"
    assert threat.family == "emotet"
    assert threat.categories == ["trojan", "downloader"]


def test_threat_is_none_when_vt_has_no_classification():
    from hash_searcher.analysis.vt import extract_vt

    assert extract_vt({"data": {"attributes": {}}}).threat is None


def test_submission_history_is_rendered_as_a_utc_iso_date():
    from hash_searcher.analysis.vt import extract_vt

    submission = extract_vt(_vt_fixture()).submission
    assert submission.first_seen == "2019-04-02"
    assert submission.times_submitted == 417
    assert submission.names == ["invoice.doc", "rechnung.doc", "sample.bin"]


def test_submission_first_seen_is_none_without_a_timestamp():
    from hash_searcher.analysis.vt import extract_vt

    submission = extract_vt({"data": {"attributes": {"times_submitted": 3}}}).submission
    assert submission.first_seen is None
    assert submission.times_submitted == 3


def test_signature_verified_is_a_bool_derived_from_vts_string():
    """VT's signature_info.verified is prose ('Signed file, verified
    signature'), not a boolean. Any truthiness check on it reports every
    signed-but-INVALID file as verified -- and the verdict layer subtracts
    points for a verified signature, so that error flips real results."""
    from hash_searcher.analysis.vt import extract_vt

    sig = extract_vt(_vt_fixture()).signature
    assert sig.verified is True
    assert sig.signer == "Contoso Ltd"
    assert sig.product == "Contoso Updater"


def test_signature_with_an_invalid_verification_string_is_not_verified():
    from hash_searcher.analysis.vt import extract_vt

    raw = {"data": {"attributes": {"signature_info": {
        "verified": "Signed file, but the signature is invalid",
        "signers": "Nobody",
    }}}}
    assert extract_vt(raw).signature.verified is False


def test_sandbox_verdicts_keep_only_the_flagged_ones():
    """A dozen sandboxes reporting 'undetected' is noise; the one that
    reported 'malicious' is the finding."""
    from hash_searcher.analysis.vt import extract_vt

    verdicts = extract_vt(_vt_fixture()).sandbox
    assert [v.sandbox for v in verdicts] == ["Zenbox"]
    assert verdicts[0].category == "malicious"
    assert verdicts[0].malware_names == ["Emotet"]


def test_yara_matches_are_extracted():
    from hash_searcher.analysis.vt import extract_vt

    yara = extract_vt(_vt_fixture()).yara
    assert [y.rule for y in yara] == ["Emotet_Loader"]
    assert yara[0].author == "Some Researcher"


def test_pe_info_counts_sections_and_dates_the_build():
    from hash_searcher.analysis.vt import extract_vt

    pe = extract_vt(_vt_fixture()).pe
    assert pe.imphash == "5f0b1e9a8c3d4e2f1a0b9c8d7e6f5a4b"
    assert pe.sections == 3
    assert pe.compiled == "2019-04-02"


def test_a_non_pe_sample_has_no_pe_info():
    from hash_searcher.analysis.vt import extract_vt

    assert extract_vt({"data": {"attributes": {}}}).pe is None


def test_otx_report_carries_resolved_techniques():
    from hash_searcher.analysis.otx import extract_otx

    raw = {"pulse_info": {"count": 3, "pulses": [
        {"attack_ids": [{"id": "T1055", "display_name": "T1055 - Process Injection"}]},
    ]}}
    report = extract_otx(raw)
    assert [t.id for t in report.techniques] == ["T1055"]
    # The display-name list is unchanged: json_out and pdf both serialize it,
    # and changing its contents is a schema break for downstream consumers.
    assert report.attack_techniques == ["T1055 - Process Injection"]


def test_a_failed_censys_lookup_becomes_a_host_carrying_its_error():
    """S2: main printed 'Censys: <error>' per entry. Purifying the extractor
    dropped it because CensysHost had nowhere to put it."""
    from hash_searcher.analysis.censys import extract_hosts
    from hash_searcher.api.base_call import make_error

    _, hosts = extract_hosts([make_error("Censys 403: forbidden", 403)], {})
    assert len(hosts) == 1
    assert hosts[0].error == "Censys 403: forbidden"


def test_a_failed_censys_lookup_names_the_ip_when_the_fetcher_tagged_it():
    """The original could only print 'Censys: <error>' -- the error payload
    had no IP in it. fetch_censys knows which IP it was asking about, so it
    tags the failure and the report can name it."""
    from hash_searcher.analysis.censys import extract_hosts
    from hash_searcher.api.base_call import make_error, tag_indicator

    _, hosts = extract_hosts(
        [tag_indicator(make_error("Censys 403: forbidden", 403), "198.51.100.10")], {})
    assert hosts[0].ip == "198.51.100.10"
    assert hosts[0].error == "Censys 403: forbidden"


def test_an_errored_censys_entry_contributes_no_domains():
    """A failure must not widen the WHOIS lookup set."""
    from hash_searcher.analysis.censys import extract_hosts
    from hash_searcher.api.base_call import make_error

    domains, _ = extract_hosts([make_error("Rate limited", 429)], {})
    assert domains == []
