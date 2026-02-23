import httpx
from .config import otx_api_key

async def get_otx(client: httpx.AsyncClient, indicator_type, indicator):
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    headers = {"accept": "application/json", "X-OTX-API-KEY": otx_api_key}
    try:
        response = await client.get(url, headers=headers)
        status = int(response.status_code)
        if status == 200:
            return response.json()
        elif status == 404:
            return {"Error": "Hash not found in GetOTX"}
        else:
            return {"Error": f"GetOTX API Error {status}"}

    except httpx.HTTPStatusError as e:
        return {"error": f"VT API Error: {e.response.status_code}"}
    except httpx.RequestError as e:
        return {"error": f"Network Error: {e}"}