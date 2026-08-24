import httpx

from .base_call import api_get
from .config import otx_api_key


async def get_otx(client: httpx.AsyncClient, indicator_type, indicator):
    return await api_get(
        client,
        f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general",
        {"accept": "application/json", "X-OTX-API-KEY": otx_api_key},
        source="GetOTX",
        not_found="Hash not found in GetOTX",
    )
