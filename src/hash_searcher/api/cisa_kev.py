"""CISA Known Exploited Vulnerabilities catalog. Keyless, no indicator.

The odd one out, deliberately: this is a *catalog*, not a per-indicator
lookup -- one ~1MB JSON file listing every CVE CISA has confirmed is
exploited in the wild. It is fetched once, cached for a week, and
intersected locally against the CVEs Shodan reported. Querying it per CVE
would be N requests for a file already in hand.

That is also why it is not a Provider: Constraint 4 requires
fetch(client, indicator), and forcing a catalog into that shape would be a
lie told for the sake of uniformity. See test_kev_is_not_in_the_provider_registry.
"""

import httpx

from .base_call import api_get

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

#: A week. CISA adds to the catalog on the order of a few entries per week,
#: and it is a 1MB download (Constraint 6).
KEV_CACHE_TTL = 604800


async def get_kev(client: httpx.AsyncClient, **kwargs) -> dict:
    return await api_get(
        client,
        KEV_URL,
        {"accept": "application/json"},
        source="CISA KEV",
        not_found="CISA KEV catalog is unavailable",
        **kwargs,
    )
