"""
Shared asynchronous HTTP GET used by every API module.

Every provider follows the same shape: build a URL and headers, GET, switch on
the status code, and hand back parsed JSON or an error dict. This centralizes
that so each provider module is just its URL, its auth header, and its 404 text.

Callers rely on this never raising -- every failure (network or bad status)
comes back as {"hs_error": str, "hs_status": int | None}, so downstream code
uses is_error()/error_message()/error_status() instead of sniffing keys.
"""

import httpx

from typing import Any, Callable

ERROR_KEY = "hs_error"
STATUS_KEY = "hs_status"


def make_error(message: str, status: int | None = None) -> dict:
    return {ERROR_KEY: message, STATUS_KEY: status}


def is_error(payload) -> bool:
    return isinstance(payload, dict) and ERROR_KEY in payload


def error_message(payload) -> str:
    return payload.get(ERROR_KEY, "") if isinstance(payload, dict) else ""


def error_status(payload) -> int | None:
    return payload.get(STATUS_KEY) if isinstance(payload, dict) else None


async def api_get(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    *,
    source: str,
    params: dict[str, Any] | None = None,
    not_found: str | None = None,
    extra_status: dict[int, Callable[[httpx.Response], str]] | None = None,
) -> Any:
    """GET and normalize the result to parsed JSON or an error dict.

    source:       name used in error strings, e.g. "GetTotal"
    not_found:    message for a 404
    extra_status: per-API special cases, {status: response -> message}
    """
    try:
        response = await client.get(url, headers=headers, params=params)
    except httpx.RequestError as e:
        return make_error(f"Network Error: {e}")

    status = response.status_code
    if status == 200:
        try:
            return response.json()
        except ValueError:
            return make_error(f"{source} returned malformed JSON", status)
    if status == 404:
        return make_error(not_found or f"Not found in {source}", status)
    if extra_status and status in extra_status:
        return make_error(extra_status[status](response), status)
    return make_error(f"{source} API Error {status}", status)
