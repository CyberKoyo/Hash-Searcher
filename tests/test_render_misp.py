"""The MISP event.

Written before the module exists (Task C3, Step 1). MISP validates on
import: an attribute whose `type` is not a MISP type, or whose `category`
is not one that type is allowed in, is rejected -- and the rejection names
the attribute, not the mapping that produced it. So the type/category pairs
are what these tests pin, alongside the verdict-to-threat-level mapping,
which is the one judgement call in the module.
"""

import json

from ioc_inquest.models import (
    BazaarReport, Detection, OTXReport, Report, SourceResult, ThreatClass,
    ThreatFoxReport, Verdict, VTReport,
)
from ioc_inquest.render.misp import THREAT_LEVELS, to_event, write_misp

SHA256 = "e" * 64

#: type -> the category MISP allows it in, for the three this tool emits.
#: Restated here on purpose rather than imported: a test that reads the
#: mapping it is checking pins nothing.
EXPECTED_CATEGORIES = {
    "sha256": "Payload delivery",
    "ip-dst": "Network activity",
    "domain": "Network activity",
}


def _report(indicator: str = SHA256, kind: str = "hash") -> Report:
    return Report(
        indicator=indicator,
        indicator_kind=kind,
        generated_at="2026-09-03 12:00:00",
        vt=VTReport(found=True),
        otx=OTXReport(recorded_instances="N/A"),
        ips={}, hosts=[], whois=[],
    )


def _attributes(event: dict) -> list[dict]:
    return event["Event"]["Attribute"]


def test_the_document_is_an_event_with_info_analysis_and_a_date():
    event = to_event(_report())["Event"]

    assert SHA256 in event["info"]
    assert event["analysis"] == "2"          # MISP: 2 = completed
    assert event["date"] == "2026-09-03"
    assert event["published"] is False


def test_the_verdict_picks_the_threat_level():
    """MISP's scale runs 1 (high) to 4 (undefined) -- the inverse of this
    tool's score, so the mapping is worth pinning per level."""
    for level, expected in (("MALICIOUS", "1"), ("SUSPICIOUS", "2"),
                            ("CLEAN", "4"), ("UNKNOWN", "4")):
        event = to_event(_report(), Verdict(level=level, score=0))["Event"]
        assert event["threat_level_id"] == expected, level


def test_an_unknown_level_does_not_claim_high_threat():
    """Fail safe: a level this mapping has never heard of must not import
    into MISP as a high-threat event."""
    event = to_event(_report(), Verdict(level="WAT", score=99))["Event"]

    assert event["threat_level_id"] == THREAT_LEVELS["UNKNOWN"]


def test_no_verdict_is_undefined_rather_than_absent():
    event = to_event(_report())["Event"]

    assert event["threat_level_id"] == "4"


def test_the_sample_hash_is_an_attribute_in_a_category_misp_accepts():
    attribute, = [a for a in _attributes(to_event(_report()))
                  if a["type"] == "sha256"]

    assert attribute["value"] == SHA256
    assert attribute["category"] == EXPECTED_CATEGORIES["sha256"]
    assert attribute["to_ids"] is True


def test_every_attribute_uses_a_type_category_pair_misp_allows():
    report = _report()
    report.vt = VTReport(found=True, contacted_ips=["198.51.100.10"],
                         contacted_domains=["bad.example"])

    for attribute in _attributes(to_event(report)):
        assert attribute["category"] == EXPECTED_CATEGORIES[attribute["type"]]


def test_contacted_infrastructure_becomes_network_attributes():
    report = _report()
    report.vt = VTReport(found=True,
                         contacted_ips=["198.51.100.10", "203.0.113.7"],
                         contacted_domains=["bad.example"])

    attributes = _attributes(to_event(report))

    assert [a["value"] for a in attributes if a["type"] == "ip-dst"] == [
        "198.51.100.10", "203.0.113.7"]
    assert [a["value"] for a in attributes if a["type"] == "domain"] == [
        "bad.example"]


def test_an_md5_indicator_is_an_md5_attribute():
    attribute, = _attributes(to_event(_report("d" * 32)))

    assert attribute["type"] == "md5"


def test_an_ip_indicator_is_the_attribute_rather_than_a_hash():
    attribute, = _attributes(to_event(_report("198.51.100.10", "ip")))

    assert (attribute["type"], attribute["value"]) == ("ip-dst", "198.51.100.10")


def test_the_same_value_is_not_attributed_twice():
    """The looked-up IP appearing again in contacted_ips would import as a
    duplicate attribute, which MISP keeps and a reader has to reconcile."""
    report = _report("198.51.100.10", "ip")
    report.vt = VTReport(found=True, contacted_ips=["198.51.100.10"])

    values = [a["value"] for a in _attributes(to_event(report))]

    assert values == ["198.51.100.10"]


def test_what_the_sources_named_reaches_the_event_info():
    report = _report()
    report.vt = VTReport(found=True, detection=Detection(malicious=42, harmless=8),
                         threat=ThreatClass(label="trojan", family="emotet"))
    report.bazaar = SourceResult(queried=True,
                                 value=BazaarReport(found=True, family="emotet"))
    report.threatfox = SourceResult(
        queried=True, value=ThreatFoxReport(found=True, malware="Emotet"))

    info = to_event(report, Verdict(level="MALICIOUS", score=70))["Event"]["info"]

    assert "MALICIOUS" in info
    assert "emotet" in info


def test_the_event_round_trips_through_json_unchanged():
    report = _report()
    report.vt = VTReport(found=True, contacted_ips=["198.51.100.10"])

    event = to_event(report, Verdict(level="MALICIOUS", score=70))

    assert json.loads(json.dumps(event)) == event


def test_write_misp_writes_parseable_json(tmp_path):
    path = tmp_path / "report.misp"

    write_misp(_report(), str(path))

    assert json.loads(path.read_text(encoding="utf-8")) == to_event(_report())
