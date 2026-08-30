import json
from pathlib import Path

import httpx
import respx

FIXTURES = Path(__file__).parent / "fixtures"
RDAP_RE = r"https://rdap\.org/domain/.*"


@respx.mock
async def test_rdap_dates_come_out_in_the_format_whois_used(no_backoff):
    """WhoisRecord.created/.expires render into a 12-column field in
    render_whois. Changing their format silently breaks that alignment,
    which no substring assertion would catch."""
    from hash_searcher.analysis.whois import extract_whois
    from hash_searcher.api.rdap import get_rdap

    payload = json.loads((FIXTURES / "rdap_domain.json").read_text())
    respx.get(url__regex=RDAP_RE).mock(return_value=httpx.Response(200, json=payload))

    async with httpx.AsyncClient() as client:
        [record] = extract_whois([await get_rdap(client, "evil.example")])

    assert record.domain == "evil.example"
    assert record.created == "2019-04-02"
    assert record.expires == "2027-04-02"
    assert record.registrar == "Example Registrar, Inc."
    assert record.error is None


@respx.mock
async def test_the_registrar_is_read_from_the_entity_with_that_role(no_backoff):
    """RDAP entities carry roles; the abuse contact is not the registrar,
    and taking entities[0] blindly gets it wrong on many TLDs."""
    from hash_searcher.analysis.whois import extract_whois
    from hash_searcher.api.rdap import get_rdap

    payload = json.loads((FIXTURES / "rdap_domain.json").read_text())
    payload["entities"].reverse()   # abuse contact first now
    respx.get(url__regex=RDAP_RE).mock(return_value=httpx.Response(200, json=payload))

    async with httpx.AsyncClient() as client:
        [record] = extract_whois([await get_rdap(client, "evil.example")])

    assert record.registrar == "Example Registrar, Inc."


@respx.mock
async def test_a_domain_with_no_rdap_record_becomes_an_error_record(no_backoff):
    """The error path must still carry the domain -- an error dict has no
    ldhName, and render_whois prints the domain on the error line."""
    from hash_searcher.analysis.whois import extract_whois
    from hash_searcher.api.rdap import get_rdap

    respx.get(url__regex=RDAP_RE).mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        [record] = extract_whois([await get_rdap(client, "nope.example")])

    assert record.domain == "nope.example"
    assert record.error


@respx.mock
async def test_missing_events_degrade_to_na_rather_than_raising(no_backoff):
    """Many ccTLD RDAP servers omit expiration entirely."""
    from hash_searcher.analysis.whois import extract_whois
    from hash_searcher.api.rdap import get_rdap

    respx.get(url__regex=RDAP_RE).mock(
        return_value=httpx.Response(200, json={"ldhName": "bare.example", "events": []})
    )
    async with httpx.AsyncClient() as client:
        [record] = extract_whois([await get_rdap(client, "bare.example")])

    assert record.created == "N/A" and record.expires == "N/A"


@respx.mock
async def test_a_z_suffixed_timestamp_parses_on_python_310(no_backoff):
    """datetime.fromisoformat cannot parse a trailing 'Z' before 3.11, and
    the CI matrix includes 3.10. Normalize it before parsing."""
    from hash_searcher.analysis.whois import extract_whois
    from hash_searcher.api.rdap import get_rdap

    respx.get(url__regex=RDAP_RE).mock(return_value=httpx.Response(200, json={
        "ldhName": "z.example",
        "events": [{"eventAction": "registration", "eventDate": "2020-06-01T00:00:00Z"}],
    }))
    async with httpx.AsyncClient() as client:
        [record] = extract_whois([await get_rdap(client, "z.example")])

    assert record.created == "2020-06-01"


def test_the_whois_library_is_gone():
    """The dependency the spec named: who_is.py:36 caught bare Exception
    because the library raised almost anything."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    assert not (root / "src/hash_searcher/api/who_is.py").exists()
    assert "whois" not in (root / "requirements.txt").read_text().lower()
