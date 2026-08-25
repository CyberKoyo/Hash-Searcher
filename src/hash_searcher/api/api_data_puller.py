import os
import asyncio
import string

import httpx

from ..hashing import get_zip_hash
from .virustotal import get_vt
from .otx import get_otx
from .abuseipdb import get_ipdb
from .censys import get_censys
from .base_call import make_error
from .registry import available, by_name

HASH_LENGTHS = frozenset({32, 40, 64})  # md5, sha1, sha256


def looks_like_hash(value: str) -> bool:
    """True if value is a bare hex digest rather than a path."""
    return len(value) in HASH_LENGTHS and all(c in string.hexdigits for c in value)


def resolve_hash(user_input: str, password: str | None = None) -> list[str] | None:
    """Turn the CLI argument into a list of sha256s, or None if impossible.

    A list because a ZIP can hold several members; a bare hash or a plain
    file yields a one-element list. password is forwarded to get_zip_hash
    so an encrypted archive doesn't fall back to an interactive prompt.
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

    hashes = get_zip_hash(user_input, password)
    if not hashes:
        print("Could not hash that file. Nothing to look up.")
        return None
    return hashes


async def fetch_censys(client, ips, cache):
    """Serial with a gap between real requests; cache hits skip both."""
    provider = by_name("censys")
    results = []
    called = False

    for ip in ips:
        hit = cache.get("censys", ip, ttl=provider.cache_ttl)
        if hit is not None:
            print(f"Using cached Censys data for {ip}")
            results.append(hit)
            continue

        if called:
            await asyncio.sleep(provider.serial_delay)
        result = await get_censys(client, ip)
        called = True
        results.append(result)
        cache.put("censys", ip, result)

    return results


async def data_puller(file_hash: str, cache):
    enabled = {p.name for p in available()}

    async with httpx.AsyncClient() as client:
        # OTX doesn't depend on the VT result, so start it before awaiting VT.
        otx_task = (
            asyncio.create_task(get_otx(client, 'file', file_hash))
            if "otx" in enabled else None
        )

        if "virustotal" in enabled:
            vt_data, ips = await get_vt(client, file_hash)
        else:
            vt_data, ips = make_error("VirusTotal key not set"), []

        ipdb_task = (
            asyncio.gather(*(get_ipdb(client, ip) for ip in ips))
            if ips and "abuseipdb" in enabled else None
        )
        # create_task, not a bare coroutine: awaited last, an unscheduled
        # coroutine would not overlap OTX and AbuseIPDB the way gather did.
        censys_task = (
            asyncio.create_task(fetch_censys(client, ips, cache))
            if ips and "censys" in enabled else None
        )

        otx_data = await otx_task if otx_task else make_error("OTX key not set")
        ipdb_data = await ipdb_task if ipdb_task else []
        censys_results = await censys_task if censys_task else []

    return {
        'vt': vt_data, 'otx': otx_data, 'ipdb': list(ipdb_data),
        'censys': censys_results, 'ips': ips, 'hash': file_hash,
    }
