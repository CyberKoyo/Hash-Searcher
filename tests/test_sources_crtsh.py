import httpx
import respx


@respx.mock
async def test_sibling_domains_are_extracted_and_deduplicated(no_backoff):
    """crt.sh returns one row per log entry, so the same name appears many
    times, and name_value packs multiple SANs into one newline-joined string."""
    from hash_searcher.analysis.crtsh import extract_crtsh
    from hash_searcher.api.crtsh import get_crtsh

    respx.get(url__regex=r"https://crt\.sh/.*").mock(return_value=httpx.Response(200, json=[
        {"name_value": "evil.example\nwww.evil.example"},
        {"name_value": "evil.example"},
        {"name_value": "c2.evil.example"},
    ]))
    async with httpx.AsyncClient() as client:
        result = extract_crtsh(await get_crtsh(client, "evil.example"))

    assert sorted(result.value.siblings) == ["c2.evil.example", "evil.example", "www.evil.example"]


@respx.mock
async def test_wildcard_entries_are_normalized(no_backoff):
    from hash_searcher.analysis.crtsh import extract_crtsh
    from hash_searcher.api.crtsh import get_crtsh

    respx.get(url__regex=r"https://crt\.sh/.*").mock(
        return_value=httpx.Response(200, json=[{"name_value": "*.evil.example"}])
    )
    async with httpx.AsyncClient() as client:
        assert extract_crtsh(await get_crtsh(client, "evil.example")).value.siblings \
            == ["evil.example"]


@respx.mock
async def test_the_sibling_list_is_capped_but_the_count_is_not(no_backoff):
    """A wildcard-heavy domain returns thousands of rows. The report must
    stay readable without lying about how many there were."""
    from hash_searcher.analysis.crtsh import SIBLING_LIMIT, extract_crtsh
    from hash_searcher.api.crtsh import get_crtsh

    rows = [{"name_value": f"h{n}.evil.example"} for n in range(5000)]
    respx.get(url__regex=r"https://crt\.sh/.*").mock(
        return_value=httpx.Response(200, json=rows)
    )
    async with httpx.AsyncClient() as client:
        result = extract_crtsh(await get_crtsh(client, "evil.example"))

    assert len(result.value.siblings) <= SIBLING_LIMIT
    assert result.value.count == 5000


@respx.mock
async def test_an_html_error_page_does_not_crash_the_extractor(no_backoff):
    """crt.sh answers 200 with an HTML error page under load, which is not
    JSON. api_get already normalizes that to an error dict -- assert the
    extractor honors it rather than assuming it received a list."""
    from hash_searcher.analysis.crtsh import extract_crtsh
    from hash_searcher.api.crtsh import get_crtsh

    respx.get(url__regex=r"https://crt\.sh/.*").mock(
        return_value=httpx.Response(200, text="<html>busy</html>")
    )
    async with httpx.AsyncClient() as client:
        result = extract_crtsh(await get_crtsh(client, "evil.example"))

    assert result.value is None
    assert result.error is not None


def test_merge_crtsh_pools_rows_across_domains_before_deduplicating():
    """One CertReport, several queried domains. A name on two contacted
    domains' certificates is the interesting case, and counting it twice
    would overstate the total."""
    from hash_searcher.analysis.crtsh import merge_crtsh

    result = merge_crtsh([
        [{"name_value": "shared.example\na.example"}],
        [{"name_value": "shared.example"}, {"name_value": "b.example"}],
    ])
    assert sorted(result.value.siblings) == ["a.example", "b.example", "shared.example"]
    assert result.value.count == 3
    assert result.error is None


def test_merge_crtsh_keeps_partial_results_when_one_query_fails():
    """One dead lookup among several must not blank out the ones that
    worked -- the whole point of querying more than one domain."""
    from hash_searcher.analysis.crtsh import merge_crtsh
    from hash_searcher.api.base_call import make_error

    result = merge_crtsh([
        make_error("crt.sh API Error 503", 503),
        [{"name_value": "a.example"}],
    ])
    assert result.value.siblings == ["a.example"]
    assert result.error is None


def test_merge_crtsh_reports_an_error_only_when_every_query_failed():
    from hash_searcher.analysis.crtsh import merge_crtsh
    from hash_searcher.api.base_call import make_error

    result = merge_crtsh([make_error("crt.sh API Error 503", 503),
                          make_error("crt.sh API Error 503", 503)])
    assert result.value is None
    # De-duplicated: two identical failures are one message, not two.
    assert result.error == "crt.sh API Error 503"


def test_merge_crtsh_of_nothing_is_an_empty_report_not_an_error():
    """No domains were queried. That must read as "never asked", not as a
    crt.sh failure -- so cli.py can call merge_crtsh unconditionally instead
    of guarding on `if raw["crtsh"]` first."""
    from hash_searcher.analysis.crtsh import merge_crtsh

    result = merge_crtsh([])
    assert result.queried is False
    assert result.value is None and result.error is None


def test_email_addresses_in_a_certificate_are_not_sibling_domains():
    """crt.sh's name_value carries rfc822Name SANs too -- example.com's
    real certificate log has one. An email address is not a domain to
    pivot on."""
    from hash_searcher.analysis.crtsh import extract_crtsh

    result = extract_crtsh([{"name_value": "www.evil.example\nadmin@evil.example"}])
    assert result.value.siblings == ["www.evil.example"]
