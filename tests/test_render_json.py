import json

from hash_searcher.render.json_out import to_dict, write_json


def test_schema_keys_are_preserved(sample_report):
    data = to_dict(sample_report)
    assert set(data) == {"file", "time", "report"}
    assert set(data["report"]) == {"hash", "otx", "censys", "whois", "vt_rules", "ipdb"}


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
