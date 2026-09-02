import dataclasses

from hash_searcher.models import (
    CensysHost, IPReport, OTXReport, Report, SigmaRule, VTReport, WhoisRecord,
)


def test_sigma_rule_is_frozen():
    rule = SigmaRule(title="t", description="d", level="high")
    with __import__("pytest").raises(dataclasses.FrozenInstanceError):
        rule.level = "low"


def test_vt_report_defaults_to_empty_collections():
    vt = VTReport(found=False)
    assert vt.sigma == [] and vt.contacted_ips == [] and vt.contacted_domains == []


def test_report_holds_every_section():
    """It constructs all eight fields, so it should assert all eight. IPReport,
    CensysHost, and WhoisRecord had no field-level assertions anywhere."""
    report = Report(
        indicator="abc", generated_at="2026-08-23 00:00:00",
        vt=VTReport(found=True), otx=OTXReport(recorded_instances=0),
        ips={"198.51.100.10": IPReport(ip="198.51.100.10", confidence=90, reports=2,
                                       hostnames=["h.example"], domain="example")},
        hosts=[CensysHost(ip="198.51.100.10", org="Example AS", asn=64496,
                          country="NL", ports=[80], hostnames=["h.example"],
                          new_hostnames=["new.example"])],
        whois=[WhoisRecord(domain="bad.example", created="2020-01-01",
                           expires="2027-01-01", registrar="R")],
        source_file="sample.bin",
    )
    assert report.indicator == "abc"
    assert report.generated_at == "2026-08-23 00:00:00"
    assert report.source_file == "sample.bin"
    assert report.vt.found is True
    assert report.otx.recorded_instances == 0

    ip = report.ips["198.51.100.10"]
    assert (ip.ip, ip.confidence, ip.reports) == ("198.51.100.10", 90, 2)
    assert ip.hostnames == ["h.example"] and ip.domain == "example"

    host = report.hosts[0]
    assert (host.ip, host.org, host.asn, host.country) == \
        ("198.51.100.10", "Example AS", 64496, "NL")
    assert host.ports == [80] and host.new_hostnames == ["new.example"]
    assert host.error is None

    record = report.whois[0]
    assert (record.domain, record.created, record.expires, record.registrar) == \
        ("bad.example", "2020-01-01", "2027-01-01", "R")
    assert record.error is None


def test_sigma_by_level_partitions_rules():
    vt = VTReport(found=True, sigma=[
        SigmaRule("a", "d", "high"),
        SigmaRule("b", "d", "low"),
        SigmaRule("c", "d", "high"),
    ])
    assert [r.title for r in vt.by_level("high")] == ["a", "c"]
    assert [r.title for r in vt.by_level("medium")] == []


def test_as_count_takes_a_number_and_refuses_anything_else():
    """The coercion every payload-populated int field now goes through.

    Hardcoded expectations, one per input shape. A JSON number can arrive as
    a float, so a finite float is a count; bool is an int in Python and is
    not one here, because {"malicious": true} is not a verdict tally; NaN and
    the infinities are floats that are not counts either.
    """
    from hash_searcher.models import as_count

    assert as_count(7) == 7
    assert as_count(0) == 0
    assert as_count(-3) == -3
    assert as_count(7.9) == 7
    assert as_count(True) == 0
    assert as_count(False) == 0
    assert as_count("<script>") == 0
    assert as_count("7") == 0
    assert as_count(None) == 0
    assert as_count([1, 2]) == 0
    assert as_count({"a": 1}) == 0
    assert as_count(float("nan")) == 0
    assert as_count(float("inf")) == 0
    assert as_count(float("-inf")) == 0
    assert as_count("<script>", 5) == 5
