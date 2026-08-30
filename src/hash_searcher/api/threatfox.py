"""ThreatFox (abuse.ch). Free key, POST-only, any indicator type.

Maps an IOC -- hash, IP, or domain -- to the malware family it belongs to.
Its data changes hourly, which is why the registry entry's cache_ttl is
3600 rather than the day every other source here gets (Constraint 6).

Shares MalwareBazaar's ABUSECH_KEY: one abuse.ch account covers both, and
an unauthenticated request answers 401 {"error": "Unauthorized"}.
"""

import httpx

from .base_call import api_post
from .malwarebazaar import abusech_headers

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def get_threatfox(client: httpx.AsyncClient, indicator, **kwargs) -> dict:
    return await api_post(
        client,
        THREATFOX_URL,
        abusech_headers(),
        json={"query": "search_ioc", "search_term": indicator},
        source="ThreatFox",
        extra_status={401: lambda r: "ThreatFox rejected the key -- set "
                                     "ABUSECH_KEY (free at https://auth.abuse.ch/)"},
        **kwargs,
    )
