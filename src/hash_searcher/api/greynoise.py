"""GreyNoise Community. Keyless at a lower rate limit, IP indicators.

Answers the question that most reduces analyst workload: is this address
scanning the entire internet, or was it aimed at you?

GREYNOISE_KEY is optional and only raises the rate limit, so the registry
entry carries key_env=None -- an unset key must not mark the source
unavailable. The header is simply omitted, and the key is read at call
time rather than frozen at import (Obs. C).
"""

from urllib.parse import quote

import httpx

from . import config
from .base_call import api_get

COMMUNITY_URL = "https://api.greynoise.io/v3/community"


async def get_greynoise(client: httpx.AsyncClient, ip, **kwargs) -> dict:
    headers = {"accept": "application/json"}
    key = config.key("GREYNOISE_KEY")
    if key:
        headers["key"] = key
    return await api_get(
        client,
        f"{COMMUNITY_URL}/{quote(str(ip), safe='')}",
        headers,
        source="GreyNoise",
        not_found=f"GreyNoise has not observed {ip}",
        **kwargs,
    )
