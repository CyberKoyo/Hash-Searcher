from api.config import censys_api_key
import httpx


async def get_censys(client: httpx.AsyncClient, ip):
    url = f'https://api.platform.censys.io/v3/global/asset/host/{ip}'
    headers = {
        'accept':'application/json',
        'authorization': f'Bearer {censys_api_key}'
        }
    try:
        response = await client.get(url, headers=headers)
        status = int(response.status_code)
        if status == 200:
            return response.json()
        elif status == 404:
            return {"Error": "IP not found in Censys"}
        elif status == 403:
            return {"Error": f"Censys 403: {response.text}"}
        elif status == 429:
            retry_after = int(response.headers.get("Retry-After", 10))
            return {"Error": f"Rate limited, retry after {retry_after}s"}
        else:
            return {"Error": f"Censys  API Error {status}"}
    except httpx.RequestError as e:
        return {"error": f"Network Error: {e}"}
    

