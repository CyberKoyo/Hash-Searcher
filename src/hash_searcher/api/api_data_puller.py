import sys
import os
import json
import time
import asyncio
import string

import httpx

from ..hashing import get_zip_hash
from .config import BASE_DIR
from .virustotal import get_vt
from .otx import get_otx
from .abuseipdb import get_ipdb
from .censys import get_censys

# Cache system for Censys as it wants to wait longer between calls
CACHE_FILE = os.path.join(BASE_DIR, 'censys_cache.json')
CACHE_TTL = 86400
CENSYS_DELAY = 2


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)


HASH_LENGTHS = frozenset({32, 40, 64})  # md5, sha1, sha256


def looks_like_hash(value: str) -> bool:
    """True if value is a bare hex digest rather than a path."""
    return len(value) in HASH_LENGTHS and all(c in string.hexdigits for c in value)


def resolve_hash(user_input: str) -> list[str] | None:
    """Turn the CLI argument into a list of sha256s, or None if impossible.

    A list because a ZIP can hold several members; a bare hash or a plain
    file yields a one-element list.
    """
    if looks_like_hash(user_input):
        return [user_input.lower()]

    try:
        if os.path.getsize(user_input) == 0:
            print("This file has nothing. Try something else.")
            return None
    except FileNotFoundError:
        raise FileNotFoundError(
            "This file either doesn't exist or isn't in an accessible directory. Please try again."
        )

    hashes = get_zip_hash(user_input)
    if not hashes:
        print("Could not hash that file. Nothing to look up.")
        return None
    # get_zip_hash still returns a single string until Task 3. Wrap it so the
    # declared list[str] contract holds from this task onward.
    return [hashes] if isinstance(hashes, str) else hashes


async def fetch_censys(client, ips):
    """Censys rate limits hard, so these stay serial with a gap between calls.

    Cache hits skip both the request and the gap, and only clean results are
    cached -- a transient 403 or 429 used to get pinned for the full TTL.
    """
    cache = load_cache()
    results = []
    called = False

    for ip in ips:
        entry = cache.get(ip)
        if entry and time.time() - entry['timestamp'] < CACHE_TTL:
            print(f"Using cached Censys data for {ip}")
            results.append(entry['data'])
            continue

        # Space out real requests only; no trailing sleep after the last one.
        if called:
            await asyncio.sleep(CENSYS_DELAY)
        result = await get_censys(client, ip)
        called = True
        results.append(result)

        if not ('Error' in result or 'error' in result):
            cache[ip] = {'timestamp': time.time(), 'data': result}

    save_cache(cache)
    return results


async def data_puller():
    if len(sys.argv) < 2:
        print("Error: Please provide a file or hash.")
        return None

    resolved = resolve_hash(sys.argv[1])
    if not resolved:
        return None
    file_hash = resolved[0]

    async with httpx.AsyncClient() as client:
        # OTX doesn't depend on the VT result, so start it before awaiting VT.
        otx_task = asyncio.create_task(get_otx(client, 'file', file_hash))
        vt_data, ips = await get_vt(client, file_hash)

        if ips:
            otx_data, ipdb_data, censys_results = await asyncio.gather(
                otx_task,
                asyncio.gather(*(get_ipdb(client, ip) for ip in ips)),
                fetch_censys(client, ips),
            )
        else:
            otx_data = await otx_task
            ipdb_data, censys_results = [], []

    return {
        'vt': vt_data,
        'otx': otx_data,
        'ipdb': list(ipdb_data),
        'censys': censys_results,
        'ips': ips,
        'hash': file_hash,
    }
