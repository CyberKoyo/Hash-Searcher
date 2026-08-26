"""
Shared asynchronous HTTP GET used by every API module.

Every provider follows the same shape: build a URL and headers, GET, switch on
the status code, and hand back parsed JSON or an error dict. This centralizes
that so each provider module is just its URL, its auth header, and its 404 text.

Callers rely on this never raising -- every failure (network or bad status)
comes back as {"hs_error": str, "hs_status": int | None}, so downstream code
uses is_error()/error_message()/error_status() instead of sniffing keys.
"""

import asyncio

import httpx

from typing import Any, Callable

ERROR_KEY = "hs_error"
STATUS_KEY = "hs_status"
INDICATOR_KEY = "hs_indicator"

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_ATTEMPTS = 3
BACKOFF_BASE = 1.0
MAX_BACKOFF = 60.0


def _backoff_seconds(attempt: int, retry_after: str | None) -> float:
    """Honor Retry-After when the server sends a usable one, else exponential."""
    if retry_after:
        try:
            return min(float(retry_after), MAX_BACKOFF)
        except ValueError:
            pass  # HTTP-date form; fall through to exponential
    return min(BACKOFF_BASE * (2 ** (attempt - 1)), MAX_BACKOFF)


def make_error(message: str, status: int | None = None) -> dict:
    return {ERROR_KEY: message, STATUS_KEY: status}


def tag_indicator(payload: dict, indicator: str) -> dict:
    """Record which indicator a failure was about.

    api_get builds its messages from the status code alone, so an error dict
    cannot say which of several IPs produced it. A caller looping over
    indicators knows, and the report can only name the failing one if that
    knowledge travels with the payload.
    """
    return {**payload, INDICATOR_KEY: indicator}


def error_indicator(payload) -> str | None:
    return payload.get(INDICATOR_KEY) if isinstance(payload, dict) else None


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
    max_attempts: int = MAX_ATTEMPTS,
) -> Any:
    """GET and normalize the result to parsed JSON or an error dict.

    source:       name used in error strings, e.g. "GetTotal"
    not_found:    message for a 404
    extra_status: per-API special cases, {status: response -> message}
    """
    if max_attempts < 1:
        # Falling through the loop returned the nonsense "Network Error: None".
        raise ValueError(f"max_attempts must be at least 1, got {max_attempts}")

    response = None
    last_network_error = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = await client.get(url, headers=headers, params=params)
        except httpx.RequestError as e:
            last_network_error = e
            response = None
            if attempt == max_attempts:
                break
            await asyncio.sleep(_backoff_seconds(attempt, None))
            continue

        if response.status_code in RETRY_STATUSES and attempt < max_attempts:
            await asyncio.sleep(
                _backoff_seconds(attempt, response.headers.get("Retry-After"))
            )
            continue
        break

    if response is None:
        return make_error(f"Network Error: {last_network_error}")

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
