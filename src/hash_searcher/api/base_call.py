"""
Shared asynchronous HTTP verbs used by every API module.

Every provider follows the same shape: build a URL and headers, request, switch on
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


USER_AGENT = "hash-searcher/0.1 (+https://github.com/CyberKoyo/Hash-Searcher)"


async def _request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    *,
    params: dict[str, Any] | None = None,
    data: Any = None,
    json: Any = None,
    max_attempts: int = MAX_ATTEMPTS,
    follow_redirects: bool = False,
):
    """The retry loop, shared by every verb.

    Returns (final response, last network error). The response is None when
    every attempt failed at the transport layer -- the caller turns that into
    an error dict. USER_AGENT is merged in here so no provider has to
    remember it: several of these services ask for one, and crt.sh throttles
    anonymous bulk queries harder without it.
    """
    sent = {"User-Agent": USER_AGENT, **headers}
    response = None
    last_network_error = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = await client.request(
                method, url, headers=sent, params=params, data=data, json=json,
                follow_redirects=follow_redirects,
            )
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

    return response, last_network_error


def _finish(
    response: httpx.Response | None,
    last_network_error: Exception | None,
    *,
    source: str,
    not_found: str | None,
    extra_status: dict[int, Callable[[httpx.Response], str]] | None,
) -> Any:
    """Status handling, shared by every verb: 200 -> JSON, else an error dict."""
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
    follow_redirects: bool = False,
) -> Any:
    """GET and normalize the result to parsed JSON or an error dict.

    source:       name used in error strings, e.g. "GetTotal"
    not_found:    message for a 404
    extra_status: per-API special cases, {status: response -> message}
    """
    if max_attempts < 1:
        # Falling through the loop returned the nonsense "Network Error: None".
        raise ValueError(f"max_attempts must be at least 1, got {max_attempts}")

    response, last_network_error = await _request(
        client, "GET", url, headers, params=params,
        max_attempts=max_attempts, follow_redirects=follow_redirects,
    )
    return _finish(response, last_network_error, source=source,
                   not_found=not_found, extra_status=extra_status)


async def api_post(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    *,
    source: str,
    data: Any = None,
    json: Any = None,
    not_found: str | None = None,
    extra_status: dict[int, Callable[[httpx.Response], str]] | None = None,
    max_attempts: int = MAX_ATTEMPTS,
) -> Any:
    """POST with api_get's exact contract: parsed JSON or an error dict.

    MalwareBazaar and ThreatFox are POST-only. A second copy of the retry
    loop is how the two verbs drift apart, so both go through _request.
    """
    if max_attempts < 1:
        raise ValueError(f"max_attempts must be at least 1, got {max_attempts}")

    response, last_network_error = await _request(
        client, "POST", url, headers, data=data, json=json,
        max_attempts=max_attempts,
    )
    return _finish(response, last_network_error, source=source,
                   not_found=not_found, extra_status=extra_status)
