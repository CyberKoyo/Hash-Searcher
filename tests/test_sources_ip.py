import json
from pathlib import Path

import httpx
import respx

FIXTURES = Path(__file__).parent / "fixtures"


@respx.mock
async def test_shodan_internetdb_returns_ports_and_cves(no_backoff):
    from ioc_inquest.analysis.shodan import extract_shodan
    from ioc_inquest.api.shodan_internetdb import get_shodan

    payload = json.loads((FIXTURES / "shodan_internetdb.json").read_text())
    respx.get("https://internetdb.shodan.io/198.51.100.10").mock(
        return_value=httpx.Response(200, json=payload)
    )
    async with httpx.AsyncClient() as client:
        result = extract_shodan(await get_shodan(client, "198.51.100.10"))

    assert result.value.ports == [22, 80, 443]
    assert result.value.vulns == ["CVE-2018-15473", "CVE-2021-41617"]


@respx.mock
async def test_shodan_404_means_nothing_known_not_a_failure(no_backoff):
    """InternetDB answers 404 for an IP it has never scanned -- the common
    case for a residential address, and not an error."""
    from ioc_inquest.analysis.shodan import extract_shodan
    from ioc_inquest.api.shodan_internetdb import get_shodan

    respx.get("https://internetdb.shodan.io/198.51.100.10").mock(
        return_value=httpx.Response(404)
    )
    async with httpx.AsyncClient() as client:
        result = extract_shodan(await get_shodan(client, "198.51.100.10"))

    assert result.value.ports == []
    assert result.error is None
    assert result.ok


@respx.mock
async def test_greynoise_distinguishes_internet_noise_from_a_targeted_host(no_backoff):
    from ioc_inquest.analysis.greynoise import extract_greynoise
    from ioc_inquest.api.greynoise import get_greynoise

    payload = json.loads((FIXTURES / "greynoise_seen.json").read_text())
    respx.get(url__regex=r"https://api\.greynoise\.io/v3/community/.*").mock(
        return_value=httpx.Response(200, json=payload)
    )
    async with httpx.AsyncClient() as client:
        result = extract_greynoise(await get_greynoise(client, "198.51.100.10"))

    assert result.value.seen is True
    assert result.value.classification == "malicious"
    assert result.value.name == "Mirai"


@respx.mock
async def test_greynoise_404_means_not_observed(no_backoff):
    from ioc_inquest.analysis.greynoise import extract_greynoise
    from ioc_inquest.api.greynoise import get_greynoise

    respx.get(url__regex=r"https://api\.greynoise\.io/v3/community/.*").mock(
        return_value=httpx.Response(404, json={"message": "IP not observed"})
    )
    async with httpx.AsyncClient() as client:
        result = extract_greynoise(await get_greynoise(client, "198.51.100.10"))

    assert result.value.seen is False
    assert result.error is None
    assert result.ok


@respx.mock
async def test_greynoise_works_without_a_key_and_sends_one_when_present(no_backoff, monkeypatch):
    """GreyNoise Community is keyless at a lower rate limit; a key raises it.
    An unset key must not make the provider unavailable -- which is why it
    carries key_env=None and reads the key at call time instead."""
    from ioc_inquest.api.greynoise import get_greynoise

    route = respx.get(url__regex=r"https://api\.greynoise\.io/v3/community/.*").mock(
        return_value=httpx.Response(200, json={"noise": False, "message": "Success"})
    )

    monkeypatch.delenv("GREYNOISE_KEY", raising=False)
    async with httpx.AsyncClient() as client:
        await get_greynoise(client, "198.51.100.10")
    assert "key" not in {k.lower() for k in route.calls[0].request.headers}

    monkeypatch.setenv("GREYNOISE_KEY", "secret")
    async with httpx.AsyncClient() as client:
        await get_greynoise(client, "198.51.100.10")
    assert route.calls[1].request.headers["key"] == "secret"
