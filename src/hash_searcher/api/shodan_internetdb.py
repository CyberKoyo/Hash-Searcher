"""Shodan InternetDB. Keyless, IP indicators.

Answers what Censys and AbuseIPDB do not: which CVEs Shodan associates
with an address. That list is the input Task 7's CISA KEV intersection
needs -- without it there is nothing local to intersect the catalog with.

A 404 means Shodan has never scanned the address, which is the common case
for a residential IP and is not an error.
"""

from urllib.parse import quote

import httpx

from .base_call import api_get

INTERNETDB_URL = "https://internetdb.shodan.io"


async def get_shodan(client: httpx.AsyncClient, ip, **kwargs) -> dict:
    return await api_get(
        client,
        f"{INTERNETDB_URL}/{quote(str(ip), safe='')}",
        {"accept": "application/json"},
        source="Shodan InternetDB",
        not_found=f"Shodan has no scan data for {ip}",
        **kwargs,
    )
