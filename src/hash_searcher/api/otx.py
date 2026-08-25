import httpx

from .base_call import api_get
from . import config


async def get_otx(client: httpx.AsyncClient, indicator, indicator_type="file"):
    return await api_get(
        client,
        f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general",
        {"accept": "application/json", "X-OTX-API-KEY": config.key("OTX_KEY") or ""},
        source="GetOTX",
        not_found="Hash not found in GetOTX",
    )
