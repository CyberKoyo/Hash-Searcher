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
        report = extract_crtsh(await get_crtsh(client, "evil.example"))

    assert sorted(report.siblings) == ["c2.evil.example", "evil.example", "www.evil.example"]


@respx.mock
async def test_wildcard_entries_are_normalized(no_backoff):
    from hash_searcher.analysis.crtsh import extract_crtsh
    from hash_searcher.api.crtsh import get_crtsh

    respx.get(url__regex=r"https://crt\.sh/.*").mock(
        return_value=httpx.Response(200, json=[{"name_value": "*.evil.example"}])
    )
    async with httpx.AsyncClient() as client:
        assert extract_crtsh(await get_crtsh(client, "evil.example")).siblings \
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
        report = extract_crtsh(await get_crtsh(client, "evil.example"))

    assert len(report.siblings) <= SIBLING_LIMIT
    assert report.count == 5000


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
        report = extract_crtsh(await get_crtsh(client, "evil.example"))

    assert report.siblings == []
    assert report.error is not None
