"""ThreatFox (abuse.ch). Keyless, POST-only, any indicator type.

Maps an IOC -- hash, IP, or domain -- to the malware family it belongs to.
Its data changes hourly, which is why the registry entry's cache_ttl is
3600 rather than the day every other source here gets (Constraint 6).
"""

import httpx

from .base_call import api_post

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def get_threatfox(client: httpx.AsyncClient, indicator, **kwargs) -> dict:
    return await api_post(
        client,
        THREATFOX_URL,
        {"accept": "application/json"},
        json={"query": "search_ioc", "search_term": indicator},
        source="ThreatFox",
        **kwargs,
    )
