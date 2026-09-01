import os
import asyncio
import string

import httpx

from ..analysis.censys import extract_hosts
from ..analysis.ipdb import extract_ips
from ..analysis.shodan import extract_shodan, observed_cves
from ..hashing import get_zip_hash
from .rdap import RDAP_CONCURRENCY, get_rdap
from .virustotal import contacted_domains, contacted_ips, get_vt
from .otx import get_otx
from .abuseipdb import get_ipdb
from .censys import get_censys
from .cisa_kev import KEV_CACHE_TTL, get_kev
from .crtsh import CRTSH_DOMAIN_LIMIT, get_crtsh
from .greynoise import get_greynoise
from .malwarebazaar import get_bazaar
from .shodan_internetdb import get_shodan
from .threatfox import THREATFOX_CONCURRENCY, get_threatfox
from .base_call import is_error, make_error, tag_indicator
from .registry import Provider, available, by_name, for_indicator
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


async def _bounded_gather(limit: int, *coroutines):
    """gather(), but at most `limit` in flight.

    A bare gather over the contacted domains opens one connection per
    domain -- up to IOC_LIMIT of them -- at a free bootstrap service.
    Constraint 7 applies to keyless sources too.
    """
    semaphore = asyncio.Semaphore(limit)

    async def bounded(coroutine):
        async with semaphore:
            return await coroutine

    return list(await asyncio.gather(*(bounded(c) for c in coroutines)))


async def _cached(cache, name: str, key: str, fetch, ttl: int | None = None,
                  provider: Provider | None = None):
    """Cache-through for a single-call provider.

    fetch is a zero-arg coroutine function so nothing is awaited on a hit --
    passing an already-created coroutine would fire the request regardless
    and leave an un-awaited coroutine warning behind.

    ttl defaults to provider.cache_ttl -- the caller's own resolved
    Provider, not a fresh by_name(name) lookup against the global registry,
    so a pool a caller substituted for testing is honored here too, not
    just for whether this call happens at all. name stays a separate
    argument, and doesn't fall back to provider.name, because the one
    caller that passes ttl explicitly -- the CISA KEV catalog -- is cached
    like a provider but is not one, and has no Provider to pass.
    """
    effective_ttl = provider.cache_ttl if ttl is None else ttl
    hit = cache.get(name, key, ttl=effective_ttl)
    if hit is not None:
        print(f"Using cached {name} data for {key}")
        return hit
    result = await fetch()
    cache.put(name, key, result)
    return result


async def fetch_serial(client, provider: Provider, fetch, indicators, cache, label=None):
    """One indicator at a time, with the provider's serial_delay between
    real requests; cache hits skip both the wait and the call.

    Censys, crt.sh, and GreyNoise all rate limit hard enough to need this.
    It was written for Censys alone and is now shared, because three copies
    of a sleep-between-requests loop is three chances to get it wrong.

    Takes the resolved Provider itself, not its name -- every call site
    has a real registry entry (unlike _cached's CISA KEV exception), so
    there is nothing name alone would buy that provider.name doesn't, and
    a second by_name(name) lookup against the global registry is exactly
    the coupling that let a caller-supplied pool's ttl/serial_delay go
    silently ignored.
    """
    name = provider.name
    display = label or name
    results = []
    called = False

    for indicator in indicators:
        hit = cache.get(name, indicator, ttl=provider.cache_ttl)
        if hit is not None:
            print(f"Using cached {display} data for {indicator}")
            results.append(hit)
            continue

        if called:
            await asyncio.sleep(provider.serial_delay)
        result = await fetch(client, indicator)
        if is_error(result):
            # api_get's messages are built from the status code alone, so
            # the payload cannot say which indicator failed. Here it can.
            result = tag_indicator(result, indicator)
        called = True
        results.append(result)
        cache.put(name, indicator, result)

    return results


async def fetch_censys(client, ips, cache, provider: Provider):
    """Serial with a gap between real requests; cache hits skip both."""
    return await fetch_serial(client, provider, get_censys, ips, cache,
                              label="Censys")


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
        # OTX doesn't depend on the VT result, so start it before awaiting VT
        # (ruling R4). The two keyless hash sources are started here for the
        # same reason: all three need only the hash.
        otx_task = (
            asyncio.create_task(
                _cached(cache, "otx", file_hash, lambda: get_otx(client, file_hash),
                       provider=by_name("otx", pool))
            )
            if "otx" in hash_sources else None
        )
        bazaar_task = (
            asyncio.create_task(
                _cached(cache, "malwarebazaar", file_hash,
                        lambda: get_bazaar(client, file_hash),
                        provider=by_name("malwarebazaar", pool))
            )
            if "malwarebazaar" in hash_sources else None
        )
        # ThreatFox answers for the sample AND for every contacted IP; this
        # is the sample half. The per-IP fan-out is below, beside Shodan,
        # and lands in its own Report field -- Shodan gives exposure and
        # GreyNoise gives noise-vs-targeted, and neither names the C2
        # family, which is ThreatFox's whole value and what its dataset is
        # overwhelmingly made of.
        threatfox_task = (
            asyncio.create_task(
                _cached(cache, "threatfox", file_hash,
                        lambda: get_threatfox(client, file_hash),
                        provider=by_name("threatfox", pool))
            )
            if "threatfox" in hash_sources else None
        )

        if "virustotal" in hash_sources:
            vt_data = await _cached(
                cache, "virustotal", file_hash, lambda: get_vt(client, file_hash),
                provider=by_name("virustotal", pool)
            )
            vt_ips = contacted_ips(vt_data)
        else:
            vt_data, vt_ips = make_error("VirusTotal key not set"), []

        ips = _merge_indicators(vt_ips, extra_ips)

        ipdb_task = (
            asyncio.gather(*(
                _cached(cache, "abuseipdb", ip, lambda ip=ip: get_ipdb(client, ip),
                       provider=by_name("abuseipdb", pool))
                for ip in ips
            ))
            if ips and "abuseipdb" in ip_sources else None
        )
        # create_task, not a bare coroutine: awaited last, an unscheduled
        # coroutine would not overlap OTX and AbuseIPDB the way gather did.
        censys_task = (
            asyncio.create_task(
                fetch_censys(client, ips, cache, by_name("censys", pool)))
            if ips and "censys" in ip_sources else None
        )
        # Shodan InternetDB has no published per-minute limit, so it fans
        # out in parallel; GreyNoise Community does, so it goes serial with
        # its declared serial_delay.
        shodan_task = (
            asyncio.gather(*(
                _cached(cache, "shodan", ip, lambda ip=ip: get_shodan(client, ip),
                       provider=by_name("shodan", pool))
                for ip in ips
            ))
            if ips and "shodan" in ip_sources else None
        )
        greynoise_task = (
            asyncio.create_task(
                fetch_serial(client, by_name("greynoise", pool), get_greynoise,
                             ips, cache, label="GreyNoise")
            )
            if ips and "greynoise" in ip_sources else None
        )
        # Bounded, not a bare gather: `ips` reaches IOC_LIMIT entries and
        # abuse.ch is one free endpoint behind one shared account key
        # (Constraint 8). _cached keys on the IP and inherits the registry
        # entry's hourly TTL -- the same 3600 the sample lookup gets, and
        # deliberately not the day the other sources take, because a stale
        # C2 attribution is worse than none (Constraint 6).
        threatfox_ips_task = (
            asyncio.create_task(_bounded_gather(THREATFOX_CONCURRENCY, *(
                _cached(cache, "threatfox", ip,
                        lambda ip=ip: get_threatfox(client, ip),
                        provider=by_name("threatfox", pool))
                for ip in ips
            )))
            if ips and "threatfox" in ip_sources else None
        )

        otx_data = await otx_task if otx_task else make_error("OTX key not set")
        # None, not an error dict: a source that was never asked and one
        # that was asked and failed are different answers, and the renderers
        # print the second while staying silent about the first.
        bazaar_data = await bazaar_task if bazaar_task else None
        threatfox_data = await threatfox_task if threatfox_task else None
        ipdb_data = await ipdb_task if ipdb_task else []
        censys_results = await censys_task if censys_task else []
        shodan_results = await shodan_task if shodan_task else []
        greynoise_results = await greynoise_task if greynoise_task else []
        threatfox_ip_results = (
            await threatfox_ips_task if threatfox_ips_task else [])

        domains = _domains(vt_data, list(ipdb_data), censys_results)
        rdap_results = (
            await _bounded_gather(RDAP_CONCURRENCY, *(
                _cached(cache, "rdap", domain,
                        lambda d=domain: get_rdap(client, d),
                        provider=by_name("rdap", pool))
                for domain in domains
            ))
            if domains and "rdap" in domain_sources else []
        )
        # Capped well below IOC_LIMIT: crt.sh is serial with a 2s gap and
        # answers slowly, and every result is merged into one 100-name
        # CertReport, so domains past the first few add minutes of runtime
        # for names the report will not print.
        crtsh_results = (
            await fetch_serial(client, by_name("crtsh", pool), get_crtsh,
                               domains[:CRTSH_DOMAIN_LIMIT], cache,
                               label="crt.sh")
            if domains and "crtsh" in domain_sources else []
        )

        # KEV is a ~1MB catalog, not a lookup service, and it is not a
        # Provider for exactly that reason: Constraint 4 requires
        # fetch(client, indicator) and this takes no indicator. It is
        # fetched at most once per run, only when Shodan actually reported
        # CVEs to intersect it against, and cached for a week.
        kev_catalog = {}
        # extract_shodan now returns a SourceResult; only a successfully
        # queried IP has vulns worth intersecting against the catalog, and
        # an errored or never-asked entry has nothing to contribute either
        # way -- the same outcome the old ShodanReport.error default (empty
        # vulns) produced, made explicit here instead of implicit there.
        shodan_reports = (extract_shodan(raw) for raw in shodan_results)
        if observed_cves(r.value for r in shodan_reports if r.ok):
            # Left as an error dict when the fetch fails: known_exploited()
            # (analysis/kev.py) turns that into a SourceResult with .error
            # set, so an unreachable CISA is reported rather than read as
            # "nothing is known-exploited".
            kev_catalog = await _cached(cache, "cisa_kev", "catalog",
                                        lambda: get_kev(client),
                                        ttl=KEV_CACHE_TTL)

    return {
        'vt': vt_data, 'otx': otx_data, 'ipdb': list(ipdb_data),
        'censys': censys_results, 'ips': ips,
        'domains': domains, 'rdap': list(rdap_results),
        'bazaar': bazaar_data, 'threatfox': threatfox_data,
        'threatfox_ips': dict(zip(ips, threatfox_ip_results)),
        'shodan': dict(zip(ips, shodan_results)),
        'greynoise': dict(zip(ips, greynoise_results)),
        'crtsh': list(crtsh_results),
        'kev': kev_catalog,
    }
