"""The STIX 2.1 bundle.

Written before the module exists (Task C2, Step 1). The properties pinned
here are the ones a STIX consumer rejects the whole bundle over: an id that
is not `<type>--<uuid>`, a `_ref` pointing at an object that is not in the
bundle, and a pattern that does not parse because a quote in the value was
not escaped.
"""

import json
import re
import uuid

import pytest

from ioc_inquest.models import (
    OTXReport, Report, ThreatClass, Verdict, VTReport,
)
from ioc_inquest.render.stix import to_bundle, write_stix

#: `<type>--<uuid>`, the only id shape STIX 2.1 accepts.
STIX_ID = re.compile(r"^[a-z][a-z0-9-]*--"
                     r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                     r"[0-9a-f]{4}-[0-9a-f]{12}$")

SHA256 = "e" * 64


def _report(indicator: str = SHA256, kind: str = "hash") -> Report:
    return Report(
        indicator=indicator,
        indicator_kind=kind,
        generated_at="2026-09-03 12:00:00",
        vt=VTReport(found=True),
        otx=OTXReport(recorded_instances="N/A"),
        ips={}, hosts=[], whois=[],
    )


def _by_type(bundle: dict, wanted: str) -> list[dict]:
    return [o for o in bundle["objects"] if o["type"] == wanted]


def test_the_bundle_is_a_bundle_with_a_v5_uuid_id():
    bundle = to_bundle(_report())

    assert bundle["type"] == "bundle"
    kind, _, ident = bundle["id"].partition("--")
    assert kind == "bundle"
    assert uuid.UUID(ident).version == 5


def test_every_id_matches_the_stix_id_format():
    report = _report()
    report.vt = VTReport(found=True, contacted_ips=["198.51.100.10"],
                         contacted_domains=["bad.example"])

    bundle = to_bundle(report)

    assert STIX_ID.match(bundle["id"])
    for obj in bundle["objects"]:
        assert STIX_ID.match(obj["id"]), obj


def test_the_indicator_carries_a_stix_pattern_for_the_sample_hash():
    bundle = to_bundle(_report())

    indicator, = _by_type(bundle, "indicator")
    assert indicator["pattern"] == f"[file:hashes.'SHA-256' = '{SHA256}']"
    assert indicator["pattern_type"] == "stix"
    assert indicator["spec_version"] == "2.1"
    assert indicator["valid_from"].endswith("Z")


@pytest.mark.parametrize("indicator,kind,pattern", [
    ("d" * 32, "hash", "[file:hashes.'MD5' = '%s']" % ("d" * 32)),
    ("c" * 40, "hash", "[file:hashes.'SHA-1' = '%s']" % ("c" * 40)),
    ("198.51.100.10", "ip", "[ipv4-addr:value = '198.51.100.10']"),
    ("bad.example", "domain", "[domain-name:value = 'bad.example']"),
    ("http://bad.example/x", "url", "[url:value = 'http://bad.example/x']"),
])
def test_the_pattern_matches_the_kind_of_indicator(indicator, kind, pattern):
    """Part B made every one of these a thing the tool accepts. A bundle
    that describes an IP as a file hash is wrong in a way a consumer cannot
    detect -- it parses."""
    indicator_sdo, = _by_type(to_bundle(_report(indicator, kind)), "indicator")

    assert indicator_sdo["pattern"] == pattern


def test_a_quote_in_a_value_is_escaped_rather_than_ending_the_pattern():
    """A `'` closes the string literal; the rest of the value becomes
    pattern syntax and the whole thing fails to parse."""
    indicator_sdo, = _by_type(
        to_bundle(_report("ev'il.example", "domain")), "indicator")

    assert indicator_sdo["pattern"] == r"[domain-name:value = 'ev\'il.example']"


def test_what_was_observed_becomes_scos():
    report = _report()
    report.vt = VTReport(found=True, contacted_ips=["198.51.100.10"],
                         contacted_domains=["bad.example"])

    bundle = to_bundle(report)

    file_sco, = _by_type(bundle, "file")
    assert file_sco["hashes"] == {"SHA-256": SHA256}
    assert [o["value"] for o in _by_type(bundle, "ipv4-addr")] == ["198.51.100.10"]
    assert [o["value"] for o in _by_type(bundle, "domain-name")] == ["bad.example"]


def test_each_contacted_ip_is_tied_to_the_sample_by_a_relationship():
    report = _report()
    report.vt = VTReport(found=True,
                         contacted_ips=["198.51.100.10", "203.0.113.7"])

    bundle = to_bundle(report)

    file_sco, = _by_type(bundle, "file")
    addresses = {o["id"]: o["value"] for o in _by_type(bundle, "ipv4-addr")}
    communicates = [r for r in _by_type(bundle, "relationship")
                    if r["relationship_type"] == "communicates-with"]
    assert {addresses[r["target_ref"]] for r in communicates} == {
        "198.51.100.10", "203.0.113.7"}
    assert {r["source_ref"] for r in communicates} == {file_sco["id"]}


def test_every_reference_points_at_an_object_in_the_bundle():
    """Fail closed: a dangling `_ref` is the one error a consumer cannot
    work around, and it is what a typo in an id builder produces."""
    report = _report()
    report.vt = VTReport(found=True, contacted_ips=["198.51.100.10"],
                         contacted_domains=["bad.example"])

    bundle = to_bundle(report, Verdict(level="MALICIOUS", score=70))

    present = {o["id"] for o in bundle["objects"]}
    referenced = [value for obj in bundle["objects"] for key, value in obj.items()
                  if key.endswith("_ref")]
    assert referenced  # the test is vacuous if nothing references anything
    for ref in referenced:
        assert ref in present, ref


def test_the_bundle_round_trips_through_json_unchanged():
    report = _report()
    report.vt = VTReport(found=True, contacted_ips=["198.51.100.10"],
                         threat=ThreatClass(label="trojan", family="emotet"))

    bundle = to_bundle(report, Verdict(level="MALICIOUS", score=70))

    assert json.loads(json.dumps(bundle)) == bundle


def test_the_same_report_produces_the_same_ids_twice():
    """v5, not v4, so re-running a report produces a diffable bundle rather
    than one that differs in every id."""
    report = _report()

    assert to_bundle(report) == to_bundle(report)


def test_two_different_indicators_do_not_share_an_id():
    first = to_bundle(_report("a" * 64))
    second = to_bundle(_report("b" * 64))

    assert first["id"] != second["id"]
    assert ({o["id"] for o in first["objects"]}
            & {o["id"] for o in second["objects"]}) == set()


def test_a_malicious_verdict_marks_the_indicator_as_malicious_activity():
    bundle = to_bundle(_report(), Verdict(level="MALICIOUS", score=70))

    indicator, = _by_type(bundle, "indicator")
    assert indicator["indicator_types"] == ["malicious-activity"]


def test_an_unknown_verdict_does_not_claim_malicious_activity():
    bundle = to_bundle(_report(), Verdict(level="UNKNOWN", score=0))

    indicator, = _by_type(bundle, "indicator")
    assert indicator["indicator_types"] == ["unknown"]


def test_write_stix_writes_parseable_json(tmp_path):
    path = tmp_path / "report.stix"

    write_stix(_report(), str(path))

    assert json.loads(path.read_text(encoding="utf-8")) == to_bundle(_report())
