def test_kev_matching_is_a_local_intersection_not_a_request_per_cve():
    """KEV is a catalog, not a lookup service. Querying it per CVE would be
    seven requests for a file already in hand."""
    from hash_searcher.analysis.kev import known_exploited

    catalog = {"vulnerabilities": [
        {"cveID": "CVE-2021-41617", "vendorProject": "OpenBSD",
         "product": "OpenSSH", "vulnerabilityName": "Privilege Escalation",
         "dateAdded": "2022-03-03", "knownRansomwareCampaignUse": "Unknown"},
    ]}
    hits = known_exploited(["CVE-2018-15473", "CVE-2021-41617"], catalog)
    assert [h.cve for h in hits] == ["CVE-2021-41617"]
    assert hits[0].product == "OpenSSH"


def test_kev_matching_is_case_insensitive():
    from hash_searcher.analysis.kev import known_exploited

    catalog = {"vulnerabilities": [{"cveID": "CVE-2021-41617"}]}
    assert len(known_exploited(["cve-2021-41617"], catalog)) == 1


def test_kev_with_no_cves_returns_nothing():
    """A sample with no Shodan CVEs must not pull a 1MB catalog for nothing;
    the caller checks this list before fetching."""
    from hash_searcher.analysis.kev import known_exploited

    assert known_exploited([], {"vulnerabilities": []}) == []


def test_kev_is_not_in_the_provider_registry():
    """Constraint 4 requires fetch(client, indicator). KEV takes no
    indicator, and forcing a catalog into that shape would be a lie told
    for the sake of uniformity."""
    from hash_searcher.api.registry import PROVIDERS

    assert "cisa_kev" not in {p.name for p in PROVIDERS}
