import httpx
from api.config import total_api_key


async def get_total(client: httpx.AsyncClient, hash):
    url = f'https://www.virustotal.com/api/v3/files/{hash}'
    headers = {"accept": "application/json", "x-apikey": total_api_key}
    try:
        response = await client.get(url, headers=headers)
        status = int(response.status_code) 
        if status == 200:
            return response.json()
        elif status == 404:
            return {"Error": "Hash not found in GetTotal"}
        else:
            return {"Error": f"GetTotal API Error {status}"}
        
    except httpx.HTTPStatusError as e:
        return {"error": f"VT API Error: {e.response.status_code}"}
    except httpx.RequestError as e:
        return {"error": f"Network Error: {e}"}
    
async def get_vt_ips(client: httpx.AsyncClient, hash):
    url = f'https://www.virustotal.com/api/v3/files/{hash}?relationships=contacted_ips,contacted_domains'
    headers = {"accept": "application/json", "x-apikey": total_api_key}
    try:
        response = await client.get(url, headers=headers)
        status = int(response.status_code) 
        if status == 200:
            response = response.json()
            ips = [ip['id'] for ip in response.get('data', {}).get('relationships', {}).get('contacted_ips', {}).get('data',[])]
            return ips
        elif status == 404:
            return {"Error": "Hash not found in GetTotal"}
        else:
            return {"Error": f"GetTotal API Error {status}"}
    except httpx.HTTPStatusError as e:
        return {"error": f"VT API Error: {e.response.status_code}"}
    except httpx.RequestError as e:
        return {"error": f"Network Error: {e}"}