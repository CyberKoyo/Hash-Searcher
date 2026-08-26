import httpx

from . import config
from .base_call import api_get


async def get_censys(client: httpx.AsyncClient, ip):
    return await api_get(
        client,
        f'https://api.platform.censys.io/v3/global/asset/host/{ip}',
        {
            'accept': 'application/json',
            'authorization': f'Bearer {config.key("CENSYS_KEY") or ""}',
        },
        source='Censys',
        not_found='IP not found in Censys',
        extra_status={
            403: lambda r: f"Censys 403: {r.text}",
            429: lambda r: f"Rate limited, retry after {r.headers.get('Retry-After', 10)}s",
        },
    )
