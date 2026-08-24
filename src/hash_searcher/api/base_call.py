"""
Shared asynchronous HTTP GET used by every API module.

Every provider follows the same shape: build a URL and headers, GET, switch on
the status code, and hand back parsed JSON or an error dict. This centralizes
that so each provider module is just its URL, its auth header, and its 404 text.

Callers rely on this never raising -- network failures come back as
{"error": ...} and bad statuses as {"Error": ...}, so downstream formatters can
keep checking for those keys instead of wrapping calls in try/except.
"""

import httpx

from typing import Any, Callable


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
        return {"error": f"Network Error: {e}"}

    status = response.status_code
    if status == 200:
        try:
            return response.json()
        except ValueError:
            return {"Error": f"{source} returned malformed JSON"}
    if status == 404:
        return {"Error": not_found or f"Not found in {source}"}
    if extra_status and status in extra_status:
        return {"Error": extra_status[status](response)}
    return {"Error": f"{source} API Error {status}"}
