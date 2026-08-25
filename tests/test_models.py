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
    report = Report(
        indicator="abc", generated_at="2026-08-23 00:00:00",
        vt=VTReport(found=True), otx=OTXReport(recorded_instances=0),
        ips={}, hosts=[], whois=[],
    )
    assert report.indicator == "abc"
    assert report.vt.found is True


def test_sigma_by_level_partitions_rules():
    vt = VTReport(found=True, sigma=[
        SigmaRule("a", "d", "high"),
        SigmaRule("b", "d", "low"),
        SigmaRule("c", "d", "high"),
    ])
    assert [r.title for r in vt.by_level("high")] == ["a", "c"]
    assert [r.title for r in vt.by_level("medium")] == []
