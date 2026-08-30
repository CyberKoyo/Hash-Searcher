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


@respx.mock
async def test_api_post_returns_parsed_json(no_backoff):
    from hash_searcher.api.base_call import api_post

    respx.post("https://example.invalid/api").mock(
        return_value=httpx.Response(200, json={"query_status": "ok"})
    )
    async with httpx.AsyncClient() as client:
        result = await api_post(client, "https://example.invalid/api", {},
                                source="Test", data={"query": "x"})
    assert result == {"query_status": "ok"}


@respx.mock
async def test_api_post_retries_a_429_like_api_get_does(no_backoff):
    """The whole reason api_post exists rather than a bare client.post:
    retries, backoff, and the error-dict convention live in one place."""
    from hash_searcher.api.base_call import api_post

    route = respx.post("https://example.invalid/api").mock(
        side_effect=[httpx.Response(429), httpx.Response(200, json={"ok": True})]
    )
    async with httpx.AsyncClient() as client:
        assert await api_post(client, "https://example.invalid/api", {},
                              source="Test", data={}) == {"ok": True}
    assert route.call_count == 2


@respx.mock
async def test_api_post_normalizes_a_failure_to_an_error_dict(no_backoff):
    from hash_searcher.api.base_call import api_post, error_status, is_error

    respx.post("https://example.invalid/api").mock(return_value=httpx.Response(500))
    async with httpx.AsyncClient() as client:
        result = await api_post(client, "https://example.invalid/api", {},
                                source="Test", data={}, max_attempts=1)
    assert is_error(result) and error_status(result) == 500


@respx.mock
async def test_every_request_identifies_the_tool(no_backoff):
    """Several of these services ask for a User-Agent, and crt.sh throttles
    anonymous bulk queries harder without one."""
    from hash_searcher.api.base_call import api_get

    route = respx.get("https://example.invalid/x").mock(
        return_value=httpx.Response(200, json={})
    )
    async with httpx.AsyncClient() as client:
        await api_get(client, "https://example.invalid/x", {}, source="Test")

    sent = route.calls[0].request.headers["user-agent"]
    assert "hash-searcher" in sent.lower()
