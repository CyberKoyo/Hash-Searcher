"""RDAP domain registration lookup. Keyless, domain indicators.

Replaces the `whois` library, which who_is.py:36 had to wrap in a bare
`except Exception` because it raised almost anything -- parse errors,
socket errors, UnicodeDecodeError on a registrar's non-UTF-8 response.
RDAP is JSON over HTTPS, so it goes through api_get and inherits retries,
backoff, and the error-dict convention, and the blocking dependency (plus
the thread pool who_is needed to work around it) goes away with it.

rdap.org is the bootstrap service: it redirects to whichever server is
authoritative for the TLD, so follow_redirects is required -- without it
every lookup comes back as a 302 body.
"""

import httpx

from .base_call import api_get, make_error

RDAP_BOOTSTRAP = "https://rdap.org/domain"


async def get_rdap(client: httpx.AsyncClient, domain, **kwargs) -> dict:
    """Fetch one domain's RDAP record, with the domain carried on the payload.

    extract_whois needs the domain even on the error path -- an error dict
    has no ldhName, and render_whois prints the domain on its error line.
    who_is.py used the same convention.
    """
    payload = await api_get(
        client,
        f"{RDAP_BOOTSTRAP}/{domain}",
        {"accept": "application/rdap+json"},
        source="RDAP",
        not_found=f"No RDAP record for {domain}",
        follow_redirects=True,
        **kwargs,
    )
    if not isinstance(payload, dict):
        payload = make_error(f"RDAP returned an unexpected shape for {domain}")
    return {**payload, "domain": domain}
