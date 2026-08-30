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


@respx.mock
async def test_the_abusech_key_travels_as_an_auth_key_header(no_backoff, monkeypatch):
    """abuse.ch put both its APIs behind a free account: an unauthenticated
    request answers 401 {"error": "Unauthorized"}. One key covers both, and
    it is read at call time rather than frozen at import."""
    from hash_searcher.api.malwarebazaar import get_bazaar
    from hash_searcher.api.threatfox import get_threatfox

    bazaar = respx.post(BAZAAR).mock(
        return_value=httpx.Response(200, json={"query_status": "no_result"}))
    fox = respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_result"}))

    monkeypatch.setenv("ABUSECH_KEY", "secret")
    async with httpx.AsyncClient() as client:
        await get_bazaar(client, "a" * 64)
        await get_threatfox(client, "a" * 64)
    assert bazaar.calls[0].request.headers["auth-key"] == "secret"
    assert fox.calls[0].request.headers["auth-key"] == "secret"

    monkeypatch.delenv("ABUSECH_KEY", raising=False)
    async with httpx.AsyncClient() as client:
        await get_bazaar(client, "a" * 64)
    assert "auth-key" not in {k.lower() for k in bazaar.calls[1].request.headers}


@respx.mock
async def test_a_401_names_the_variable_to_set(no_backoff):
    """The failure a user is most likely to hit, and the one where a bare
    'API Error 401' would tell them nothing actionable."""
    from hash_searcher.analysis.bazaar import extract_bazaar
    from hash_searcher.api.malwarebazaar import get_bazaar

    respx.post(BAZAAR).mock(
        return_value=httpx.Response(401, json={"error": "Unauthorized"}))
    async with httpx.AsyncClient() as client:
        report = extract_bazaar(await get_bazaar(client, "a" * 64, max_attempts=1))

    assert "ABUSECH_KEY" in report.error
