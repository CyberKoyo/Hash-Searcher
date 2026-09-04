import httpx
import pytest
import respx

from ioc_inquest.api.base_call import api_get, error_status, is_error

URL = "https://example.test/thing"


@respx.mock
async def test_429_then_200_succeeds():
    route = respx.get(URL).mock(side_effect=[
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(200, json={"ok": True}),
    ])
    async with httpx.AsyncClient() as client:
        result = await api_get(client, URL, {}, source="Demo")
    assert result == {"ok": True}
    assert route.call_count == 2


@respx.mock
async def test_retries_are_bounded():
    route = respx.get(URL).mock(
        return_value=httpx.Response(429, headers={"Retry-After": "0"})
    )
    async with httpx.AsyncClient() as client:
        result = await api_get(client, URL, {}, source="Demo", max_attempts=3)
    assert route.call_count == 3
    assert is_error(result)
    assert error_status(result) == 429


@respx.mock
async def test_404_is_not_retried():
    route = respx.get(URL).mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        await api_get(client, URL, {}, source="Demo")
    assert route.call_count == 1


@respx.mock
async def test_transient_network_error_is_retried(no_backoff):
    route = respx.get(URL).mock(side_effect=[
        httpx.ConnectError("down"),
        httpx.Response(200, json={"ok": True}),
    ])
    async with httpx.AsyncClient() as client:
        result = await api_get(client, URL, {}, source="Demo")
    assert result == {"ok": True}
    assert route.call_count == 2


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
@respx.mock
async def test_every_retry_status_is_retried(status, no_backoff):
    """RETRY_STATUSES has five members and only 429 was ever exercised. They
    share a code path, so this is a coverage gap rather than a suspected bug
    -- but a shared path is exactly where a future edit silently drops four
    of the five."""
    route = respx.get(URL).mock(
        side_effect=[httpx.Response(status), httpx.Response(200, json={"ok": True})]
    )
    async with httpx.AsyncClient() as client:
        assert await api_get(client, URL, {}, source="T") == {"ok": True}
    assert route.call_count == 2


async def test_max_attempts_below_one_is_rejected():
    """Unreachable from any caller today -- every call site uses the default
    or a positive value -- but it used to fall straight through the retry
    loop and return the nonsense "Network Error: None"."""
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError):
            await api_get(client, URL, {}, source="Demo", max_attempts=0)
