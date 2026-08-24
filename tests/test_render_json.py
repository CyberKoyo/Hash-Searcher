import json

from hash_searcher.models import WhoisRecord
from hash_searcher.render.json_out import to_dict, write_json


def test_schema_keys_are_preserved(sample_report):
    data = to_dict(sample_report)
    assert set(data) == {"file", "time", "report"}
    assert set(data["report"]) == {"hash", "otx", "censys", "whois", "vt_rules", "ipdb"}


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
