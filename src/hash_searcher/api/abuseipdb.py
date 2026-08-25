import httpx

from . import config
from .base_call import api_get


async def get_ipdb(client: httpx.AsyncClient, ip):
    return await api_get(
        client,
        'https://api.abuseipdb.com/api/v2/check',
        {'Accept': 'application/json', 'Key': config.key("IPDB_KEY") or ""},
        params={'ipAddress': ip, 'maxAgeInDays': '90'},
        source='IPDB',
        not_found='IP not found',
    )
