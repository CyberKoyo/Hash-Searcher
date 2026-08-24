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


def test_extract_hosts_skips_error_entries():
    domains, hosts = extract_hosts([make_error("Rate limited", 429)], {})
    assert hosts == [] and domains == []


def test_extract_whois_preserves_failures():
    records = extract_whois([
        {"domain": "a.example", "created": "2020-01-01", "expires": "2027-01-01",
         "registrar": "R"},
        {"domain": "b.example", "error": "No WHOIS data found"},
    ])
    assert records[0].registrar == "R"
    assert records[1].error == "No WHOIS data found"
