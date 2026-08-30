def test_kev_matching_is_a_local_intersection_not_a_request_per_cve():
    """KEV is a catalog, not a lookup service. Querying it per CVE would be
    seven requests for a file already in hand."""
    from hash_searcher.analysis.kev import known_exploited

    catalog = {"vulnerabilities": [
        {"cveID": "CVE-2021-41617", "vendorProject": "OpenBSD",
         "product": "OpenSSH", "vulnerabilityName": "Privilege Escalation",
         "dateAdded": "2022-03-03", "knownRansomwareCampaignUse": "Unknown"},
    ]}
    result = known_exploited(["CVE-2018-15473", "CVE-2021-41617"], catalog)
    assert [h.cve for h in result.value.entries] == ["CVE-2021-41617"]
    assert result.value.entries[0].product == "OpenSSH"


def test_kev_matching_is_case_insensitive():
    from hash_searcher.analysis.kev import known_exploited

    catalog = {"vulnerabilities": [{"cveID": "CVE-2021-41617"}]}
    assert len(known_exploited(["cve-2021-41617"], catalog).value.entries) == 1


def test_kev_with_no_cves_returns_nothing():
    """A sample with no Shodan CVEs must not pull a 1MB catalog for nothing;
    the caller checks this list before fetching. No CVEs to check means the
    catalog was never fetched at all -- known_exploited must say so rather
    than answering "found nothing"."""
    from hash_searcher.analysis.kev import known_exploited

    result = known_exploited([], {"vulnerabilities": []})
    assert result.queried is False
    assert result.value is None


def test_kev_reports_how_many_cves_went_unchecked_when_the_catalog_fails():
    """The strongest signal this phase produces must not silently read as
    "nothing is known-exploited" when CISA could not be reached."""
    from hash_searcher.analysis.kev import known_exploited
    from hash_searcher.api.base_call import make_error

    result = known_exploited(["CVE-2021-41617", "CVE-2018-15473"],
                             make_error("CISA KEV API Error 503", 503))
    assert result.error is not None
    assert result.value.entries == []
    assert result.value.unchecked == 2


def test_kev_is_not_in_the_provider_registry():
    """Constraint 4 requires fetch(client, indicator). KEV takes no
    indicator, and forcing a catalog into that shape would be a lie told
    for the sake of uniformity."""
    from hash_searcher.api.registry import PROVIDERS

    assert "cisa_kev" not in {p.name for p in PROVIDERS}
