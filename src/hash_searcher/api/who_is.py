import asyncio
import whois
from datetime import datetime

# whois.query is blocking and each lookup takes seconds, so keep a few in
# flight at once without hammering registrars.
WHOIS_CONCURRENCY = 5


def _lookup(domain: str) -> dict:
    """Blocking single-domain WHOIS lookup. Runs in a worker thread."""
    try:
        info = whois.query(domain)
        if not info:
            return {"domain": domain, "error": "No WHOIS data found"}

        data = info.__dict__
        created = data.get("creation_date")
        expires = data.get("expiration_date")

        # creation_date can be a list, take the first entry if so
        if isinstance(created, list):
            created = created[0]
        if isinstance(expires, list):
            expires = expires[0]

        cdate = created.strftime("%Y-%m-%d") if isinstance(created, datetime) else "N/A"
        edate = expires.strftime("%Y-%m-%d") if isinstance(expires, datetime) else "N/A"

        return {
            "domain":     domain,
            "created":    cdate,
            "expires":    edate,
            "registrar":  data.get("registrar") or "N/A",
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}


async def who_is(domains: list) -> list:
    """Look up every domain concurrently, off the event loop.

    The whois library is synchronous, so calling it directly from main() stalled
    every other coroutine for the length of each lookup.
    """
    semaphore = asyncio.Semaphore(WHOIS_CONCURRENCY)

    async def bounded(domain):
        async with semaphore:
            return await asyncio.to_thread(_lookup, domain)

    return list(await asyncio.gather(*(bounded(d) for d in domains)))
