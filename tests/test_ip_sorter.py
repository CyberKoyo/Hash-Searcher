from hash_searcher.formatters import ip_sorter


def test_two_ips_without_hostnames_both_survive(fixture_json):
    result = ip_sorter(fixture_json("ipdb_two_bare_ips"))
    # On main both collapse onto the key ((None,), None) and the second is lost.
    assert set(result) == {"198.51.100.10", "203.0.113.20"}


def test_report_count_is_the_length_of_the_reports_list(fixture_json):
    result = ip_sorter(fixture_json("ipdb_two_bare_ips"))
    assert result["198.51.100.10"]["reports"] == 2
    assert result["203.0.113.20"]["reports"] == 0


def test_confidence_is_carried_through(fixture_json):
    result = ip_sorter(fixture_json("ipdb_two_bare_ips"))
    assert result["198.51.100.10"]["confidence"] == 90


def test_entries_without_data_are_skipped():
    assert ip_sorter([{"data": {}}, {}]) == {}


def test_scalar_hostname_is_wrapped_in_a_list():
    raw = [{"data": {"ipAddress": "192.0.2.1", "hostnames": "a.example",
                     "domain": "example.com", "abuseConfidenceScore": 0, "reports": []}}]
    assert ip_sorter(raw)["192.0.2.1"]["hostnames"] == ["a.example"]
