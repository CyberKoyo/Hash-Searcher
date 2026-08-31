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

#: ThreatFox is asked about every contacted IP as well as the sample, and
#: that list reaches IOC_LIMIT entries. Five at a time, the same bound the
#: RDAP fan-out takes: abuse.ch is a free service on one shared account key,
#: and a bare gather would open fifty simultaneous POSTs at it.
THREATFOX_CONCURRENCY = 5


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
