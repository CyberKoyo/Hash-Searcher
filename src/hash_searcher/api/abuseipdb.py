from .config import ipdb_api_key
import httpx

async def get_ipdb(client: httpx.AsyncClient, ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip,'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json','Key': ipdb_api_key}
    try:
        response = await client.request(method='GET', url=url, headers=headers, params=querystring)
        status = int(response.status_code)
        if status == 200:
            return response.json()
        elif status == 404:
            return {"Error": "IP not found"}
        else:
            return {"Error": f"IPDB API Error {status}"}
    except httpx.HTTPStatusError as e:
        return {"error": f"VT API Error: {e.response.status_code}"}
    except httpx.RequestError as e:
        return {"error": f"Network Error: {e}"}