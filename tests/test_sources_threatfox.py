import httpx
import respx


@respx.mock
async def test_threatfox_maps_an_ioc_to_a_family(no_backoff):
    from hash_searcher.analysis.threatfox import extract_threatfox
    from hash_searcher.api.threatfox import get_threatfox

    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "ok", "data": [
            {"malware_printable": "Emotet", "confidence_level": 90,
             "tags": ["botnet", "c2"], "ioc": "198.51.100.10"},
        ]})
    )
    async with httpx.AsyncClient() as client:
        result = extract_threatfox(await get_threatfox(client, "198.51.100.10"))

    assert result.value.found is True
    assert result.value.malware == "Emotet"
    assert result.value.confidence == 90


@respx.mock
async def test_threatfox_no_result_is_not_an_error(no_backoff):
    from hash_searcher.analysis.threatfox import extract_threatfox
    from hash_searcher.api.threatfox import get_threatfox

    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_result", "data": []})
    )
    async with httpx.AsyncClient() as client:
        result = extract_threatfox(await get_threatfox(client, "198.51.100.10"))

    assert result.value.found is False and result.error is None
    assert result.ok
