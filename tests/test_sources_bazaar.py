import json
from pathlib import Path

import httpx
import respx

FIXTURES = Path(__file__).parent / "fixtures"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"


@respx.mock
async def test_bazaar_returns_the_family_and_tags(no_backoff):
    from hash_searcher.analysis.bazaar import extract_bazaar
    from hash_searcher.api.malwarebazaar import get_bazaar

    payload = json.loads((FIXTURES / "bazaar_found.json").read_text())
    respx.post(BAZAAR).mock(return_value=httpx.Response(200, json=payload))

    async with httpx.AsyncClient() as client:
        report = extract_bazaar(await get_bazaar(client, "a" * 64))

    assert report.found is True
    assert report.family == "Emotet"
    assert report.tags == ["exe", "Emotet", "banker"]
    assert report.yara == ["Emotet_Loader", "win_emotet_auto"]
    assert report.first_seen == "2019-04-02"


@respx.mock
async def test_a_hash_bazaar_has_never_seen_is_not_an_error(no_backoff):
    """MalwareBazaar answers HTTP 200 with query_status=hash_not_found.
    Treating that as an error would print a failure for the common case --
    most hashes are not in a malware repository, and that is information."""
    from hash_searcher.analysis.bazaar import extract_bazaar
    from hash_searcher.api.malwarebazaar import get_bazaar

    payload = json.loads((FIXTURES / "bazaar_not_found.json").read_text())
    respx.post(BAZAAR).mock(return_value=httpx.Response(200, json=payload))

    async with httpx.AsyncClient() as client:
        report = extract_bazaar(await get_bazaar(client, "a" * 64))

    assert report.found is False
    assert report.error is None
    assert report.family is None


@respx.mock
async def test_a_transport_failure_is_an_error_not_a_not_found(no_backoff):
    """The two must stay distinguishable: 'not in the repository' and 'we
    could not ask' mean different things to an analyst."""
    from hash_searcher.analysis.bazaar import extract_bazaar
    from hash_searcher.api.malwarebazaar import get_bazaar

    respx.post(BAZAAR).mock(return_value=httpx.Response(500))
    async with httpx.AsyncClient() as client:
        report = extract_bazaar(await get_bazaar(client, "a" * 64, max_attempts=1))

    assert report.found is False
    assert report.error is not None
