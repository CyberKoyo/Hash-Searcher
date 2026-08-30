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

from urllib.parse import quote

import httpx

from .base_call import api_get, make_error

RDAP_BOOTSTRAP = "https://rdap.org/domain"

#: rdap.org is a free bootstrap service and this fans out over every
#: contacted domain. Five at a time is what the whois library's thread pool
#: allowed, and Constraint 7 applies to keyless sources too.
RDAP_CONCURRENCY = 5


def _not_found_message(response: httpx.Response, domain: str) -> str:
    """Two different 404s, and an analyst needs them apart.

    rdap.org answers 404 with title "No RDAP service is available for this
    resource" when the TLD runs no RDAP server at all (.de, .jp, and .io
    among them). An authoritative server's 404 means the domain is not
    registered. Reporting the first as the second tells an analyst a
    registered domain does not exist.
    """
    try:
        title = str(response.json().get("title") or "")
    except ValueError:
        title = ""
    if "no rdap service" in title.lower():
        return f"No RDAP server for this TLD ({domain}) -- registration data unavailable"
    return f"No RDAP record for {domain}"


async def get_rdap(client: httpx.AsyncClient, domain, **kwargs) -> dict:
    """Fetch one domain's RDAP record, with the domain carried on the payload.

    extract_whois needs the domain even on the error path -- an error dict
    has no ldhName, and render_whois prints the domain on its error line.
    who_is.py used the same convention.
    """
    payload = await api_get(
        client,
        f"{RDAP_BOOTSTRAP}/{quote(str(domain), safe='')}",
        {"accept": "application/rdap+json"},
        source="RDAP",
        # quote() above and this hook both exist because `domain` is
        # third-party data (a VT relationship id, a Censys reverse-DNS
        # name) landing in a URL path followed through redirects.
        extra_status={404: lambda r: _not_found_message(r, domain)},
        follow_redirects=True,
        **kwargs,
    )
    if not isinstance(payload, dict):
        payload = make_error(f"RDAP returned an unexpected shape for {domain}")
    return {**payload, "domain": domain}
