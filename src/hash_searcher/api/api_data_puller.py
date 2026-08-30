import os
import asyncio
import string

import httpx

from ..analysis.censys import extract_hosts
from ..analysis.ipdb import extract_ips
from ..hashing import get_zip_hash
from .rdap import get_rdap
from .virustotal import contacted_domains, contacted_ips, get_vt
from .otx import get_otx
from .abuseipdb import get_ipdb
from .censys import get_censys
from .base_call import is_error, make_error, tag_indicator
from .registry import available, by_name, for_indicator
from ..static.strings import IOC_LIMIT

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


async def _cached(cache, name: str, key: str, fetch):
    """Cache-through for a single-call provider.

    fetch is a zero-arg coroutine function so nothing is awaited on a hit --
    passing an already-created coroutine would fire the request regardless
    and leave an un-awaited coroutine warning behind.
    """
    hit = cache.get(name, key, ttl=by_name(name).cache_ttl)
    if hit is not None:
        print(f"Using cached {name} data for {key}")
        return hit
    result = await fetch()
    cache.put(name, key, result)
    return result


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
        if is_error(result):
            # api_get's messages are built from the status code alone, so
            # the payload cannot say which IP failed. Here it can.
            result = tag_indicator(result, ip)
        called = True
        results.append(result)
        cache.put("censys", ip, result)

    return results


def _merge_indicators(primary: list[str], extra: list[str] | None) -> list[str]:
    """Order-preserving de-duplicated union, VT's own indicators first.

    Capped at IOC_LIMIT -- the same per-category cap Task 6 put on the
    strings harvester -- so this merge cannot turn into an unbounded list
    of per-indicator lookups. `extra` already arrives at or under
    IOC_LIMIT, but `primary` is not itself capped upstream, so the cap is
    enforced here, on the merged result, rather than trusted from either
    input. Used for both the IP and the domain fan-out.
    """
    result = []
    for indicator in (*primary, *(extra or ())):
        if indicator not in result:
            result.append(indicator)
        if len(result) == IOC_LIMIT:
            break
    return result


def _domains(vt_data, ipdb_data: list, censys_results: list) -> list[str]:
    """Every domain worth a domain-typed lookup, VT's own first.

    Two sources, because the tool already had two: VT's contacted_domains
    relationship, fetched since Phase 0, and the hostnames AbuseIPDB and
    Censys surfaced -- which is where the WHOIS section's domains came from
    before RDAP existed. Dropping the second set to keep this simple would
    silently shrink that section. extract_ips/extract_hosts are pure, so
    calling them here and again in cli.py costs nothing but a walk.
    """
    censys_domains, _ = extract_hosts(censys_results, extract_ips(ipdb_data))
    return _merge_indicators(contacted_domains(vt_data), censys_domains)


async def data_puller(file_hash: str, cache, extra_ips: list[str] | None = None):
    # Selection is by indicator type, not by a hand-written branch per name:
    # indicator_types has been declared since Phase 1 and read by nothing,
    # and with seven more sources across three types the branches stop
    # scaling. available() stays the availability half -- a provider whose
    # key is unset is never selected, whatever types it declares.
    pool = available()
    hash_sources = {p.name for p in for_indicator("hash", pool)}
    ip_sources = {p.name for p in for_indicator("ip", pool)}
    domain_sources = {p.name for p in for_indicator("domain", pool)}

    async with httpx.AsyncClient() as client:
        # OTX doesn't depend on the VT result, so start it before awaiting VT.
        otx_task = (
            asyncio.create_task(
                _cached(cache, "otx", file_hash, lambda: get_otx(client, file_hash))
            )
            if "otx" in hash_sources else None
        )

        if "virustotal" in hash_sources:
            vt_data = await _cached(
                cache, "virustotal", file_hash, lambda: get_vt(client, file_hash)
            )
            vt_ips = contacted_ips(vt_data)
        else:
            vt_data, vt_ips = make_error("VirusTotal key not set"), []

        ips = _merge_indicators(vt_ips, extra_ips)

        ipdb_task = (
            asyncio.gather(*(
                _cached(cache, "abuseipdb", ip, lambda ip=ip: get_ipdb(client, ip))
                for ip in ips
            ))
            if ips and "abuseipdb" in ip_sources else None
        )
        # create_task, not a bare coroutine: awaited last, an unscheduled
        # coroutine would not overlap OTX and AbuseIPDB the way gather did.
        censys_task = (
            asyncio.create_task(fetch_censys(client, ips, cache))
            if ips and "censys" in ip_sources else None
        )

        otx_data = await otx_task if otx_task else make_error("OTX key not set")
        ipdb_data = await ipdb_task if ipdb_task else []
        censys_results = await censys_task if censys_task else []

        domains = _domains(vt_data, list(ipdb_data), censys_results)
        rdap_results = (
            await asyncio.gather(*(
                _cached(cache, "rdap", domain,
                        lambda d=domain: get_rdap(client, d))
                for domain in domains
            ))
            if domains and "rdap" in domain_sources else []
        )

    return {
        'vt': vt_data, 'otx': otx_data, 'ipdb': list(ipdb_data),
        'censys': censys_results, 'ips': ips,
        'domains': domains, 'rdap': list(rdap_results),
    }
