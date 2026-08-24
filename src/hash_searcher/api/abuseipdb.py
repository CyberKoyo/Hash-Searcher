import httpx

from .base_call import api_get
from .config import ipdb_api_key


async def get_ipdb(client: httpx.AsyncClient, ip):
    return await api_get(
        client,
        'https://api.abuseipdb.com/api/v2/check',
        {'Accept': 'application/json', 'Key': ipdb_api_key},
        params={'ipAddress': ip, 'maxAgeInDays': '90'},
        source='IPDB',
        not_found='IP not found',
    )
