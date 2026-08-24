import httpx
import pytest
import respx

from hash_searcher.api.base_call import api_get, error_message, error_status, is_error

URL = "https://example.test/thing"


@respx.mock
async def test_success_returns_parsed_json():
    respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    async with httpx.AsyncClient() as client:
        assert await api_get(client, URL, {}, source="Demo") == {"ok": True}


@respx.mock
async def test_404_carries_status_and_message():
    respx.get(URL).mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        result = await api_get(client, URL, {}, source="Demo", not_found="nope")
    assert is_error(result)
    assert error_status(result) == 404
    assert error_message(result) == "nope"


@respx.mock
async def test_network_failure_has_no_status():
    respx.get(URL).mock(side_effect=httpx.ConnectError("down"))
    async with httpx.AsyncClient() as client:
        result = await api_get(client, URL, {}, source="Demo", max_attempts=1)
    assert is_error(result)
    assert error_status(result) is None


@respx.mock
async def test_malformed_json_is_an_error():
    respx.get(URL).mock(return_value=httpx.Response(200, text="not json"))
    async with httpx.AsyncClient() as client:
        result = await api_get(client, URL, {}, source="Demo")
    assert is_error(result)
    assert "malformed" in error_message(result)


def test_non_dict_payloads_are_not_errors():
    assert is_error([]) is False
    assert is_error({"ok": True}) is False
