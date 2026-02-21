import sys
from hashing import get_zip_hash
from api.virustotal import get_total, get_vt_ips
from api.otx import get_otx
from api.abuseipdb import get_ipdb
from api.censys import get_censys
import httpx
import asyncio
import os
import json
import time

# Cache system for Censys as it wants to wait longer between calls

CACHE_FILE = 'censys_cache.json'
CACHE_TTL = 86400

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)

async def data_puller():
    if len(sys.argv) < 2:
        print("Error: Please provide a file or hash.")
        return
    user_input = sys.argv[1]
    if len(user_input) == 64:
        file_hash = sys.argv[1]        
    else:
        try:
            if os.path.getsize(user_input) == 0:
                return print("This file has nothing. Try something else.")
            else:
                file_hash = get_zip_hash(sys.argv[1])
        except FileNotFoundError:
            raise FileNotFoundError("This file either doesn't exist or isn't in an accessible directory. Please try again.")
    
    async with httpx.AsyncClient() as client:
        ips = await get_vt_ips(client, file_hash)
        if not ips or isinstance(ips, dict):
            ips = []        
        censys_results = []
        if ips:
            tasks = [
            get_total(client, file_hash),
            get_otx(client, 'file', file_hash),
            *[get_ipdb(client, ip) for ip in ips],
            
            ]
            results = await asyncio.gather(*tasks)
            cache = load_cache()
            for ip in ips:
                if ip in cache and time.time() - cache[ip]['timestamp']  < CACHE_TTL:
                    print(f"Using caches Censys data for {ip}")
                    censys_results.append(cache[ip]['data'])
                    continue
                result = await get_censys(client, ip)
                cache[ip] = {'timestamp': time.time(), 'data': result}
                censys_results.append(result)
                await asyncio.sleep(2)
            save_cache(cache)

        else:
            tasks = [
            get_total(client, file_hash),
            get_otx(client, 'file', file_hash),
            ]
            results = await asyncio.gather(*tasks)
    
    return results, ips, censys_results, file_hash