import os
import asyncio

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
# Re-exported: the definition moved to indicators.py, where classify()
# needs it too, and this module's callers keep importing it from here.
from ..indicators import (  # noqa: F401  (looks_like_hash re-exported)
    HASH_LENGTHS, Indicator, classify, domain_of, looks_like_hash,
    unsupported_reason,
)


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


def resolve_indicator(user_input: str,
                      password: str | None = None) -> list[Indicator] | None:
    """Turn the CLI argument into the indicators to look up, or None.

    A list for the same reason resolve_hash returns one: a ZIP holds
    several members, and each becomes its own hash indicator.

    Unclassifiable input falls through to resolve_hash rather than being
    reported here. That is deliberate -- `hash-searcher notahash` has
    printed "This file either doesn't exist or isn't in an accessible
    directory" since Phase 0, and an argument that is not any recognizable
    indicator is, overwhelmingly, a path that is not where the user thought
    it was. resolve_hash raises FileNotFoundError carrying that message and
    cli.py catches it, exactly as before.
    """
    indicator = classify(user_input)

    if indicator is not None and indicator.kind != "file":
        reason = unsupported_reason(indicator)
        if reason:
            print(reason)
            return None
        return [indicator]

    # A file, or nothing we recognize: both are resolve_hash's job. It
    # hashes the one and raises the long-standing message for the other.
    hashes = resolve_hash(user_input, password)
    if not hashes:
        return None
    return [Indicator("hash", digest) for digest in hashes]


def _require_indicator(indicator) -> None:
    """Reject anything that is not a classified Indicator.

    The same courtesy _require_provider extends, for the same reason: the
    pre-B2 call -- data_puller("deadbeef" * 8, cache) -- is still
    arity-compatible with this signature, and a bare string reaching the
    kind switch below fails as `'str' object has no attribute 'kind'` from
    inside it, naming neither the caller nor the argument.
    """
    if not isinstance(indicator, Indicator):
        raise TypeError(
            "data_puller takes a classified Indicator, not a bare string -- "
            "indicators.classify(value), or resolve_indicator(...) at the "
            f"CLI boundary, is what produces one. Got {indicator!r}"
        )


#: OTX is one endpoint per indicator type, so it is the one provider whose
#: fetch needs to be told which kind it is being handed. Asking the `file`
#: endpoint about an address answers 404, which reads as "OTX has never
#: seen it" rather than as "that was the wrong question".
_OTX_TYPES = {"hash": "file", "domain": "domain", "url": "url"}


def _otx_type(indicator: Indicator) -> str:
    if indicator.kind == "ip":
        return "IPv6" if ":" in indicator.value else "IPv4"
    return _OTX_TYPES[indicator.kind]


#: What data_puller says when VirusTotal is configured and simply cannot
#: answer. Not "key not set", which would send a user to check a key that
#: is perfectly fine: VT's file endpoint takes a digest, and an address or
#: a domain is not one.
VT_HASH_ONLY = "VirusTotal answers for file hashes only"


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


def _require_provider(function: str, provider) -> None:
    """Reject anything that is not a resolved Provider, naming the function
    and the argument.

    by_name exists so a missing provider fails loudly and names the thing
    that is missing, rather than crashing on a None attribute access three
    lines down. Every function that now takes the resolved Provider *itself*
    needs the same courtesy, and for one extra reason: the pre-A5 convention
    passed the provider's name, so `fetch_serial(client, "greynoise",
    get_greynoise, ips, cache)` -- copied out of git history, or out of any
    document written before this task -- is still arity-compatible with
    today's signature. Unguarded it fails as `'str' object has no attribute
    'name'` from inside the callee, naming neither the caller nor the
    argument.

    isinstance rather than a None check, because a None check catches only
    half of that: the stale name-string form is the likelier mistake of the
    two and is the one a None check waves straight through.
    """
    if not isinstance(provider, Provider):
        raise TypeError(
            f"{function} needs the resolved Provider itself as its "
            "`provider` argument, not a provider name -- "
            "by_name(name, pool) at the call site is what resolves one. "
            f"Got {provider!r}"
        )


async def _cached(cache, key: str, fetch, *, provider: Provider | None = None,
                  namespace: str | None = None, ttl: int | None = None):
    """Cache-through for a single-call provider.

    fetch is a zero-arg coroutine function so nothing is awaited on a hit --
    passing an already-created coroutine would fire the request regardless
    and leave an un-awaited coroutine warning behind.

    Exactly one of two argument forms is accepted, and nothing in between:

    - `provider` alone. The cache namespace and its ttl then both come from
      that single Provider -- the one a caller resolved from its own pool --
      so the two cannot disagree. Writing the provider's name out a second
      time at the call site, alongside the call that resolves it, was
      exactly the kind of duplication that let this task's underlying bug
      (registry-vs-pool disagreement) exist in the first place; deriving the
      namespace from provider.name removes that duplication rather than
      re-parameterising around it.
    - `namespace` and `ttl` together, for the one caller with no Provider to
      pass: the CISA KEV catalog, cached like a provider but not one.

    A mixture is rejected rather than silently resolved, and that rejection
    is the point of the shape. `provider=X, ttl=Y` is precisely the hazard
    this task exists to remove -- a namespace governed by a ttl that did not
    come from the provider owning that namespace -- and it would be the more
    dangerous for looking deliberate. `provider=X, namespace=Y` hands the
    function two namespaces and no way to choose; the earlier version
    answered by discarding `namespace` without a word, which would have
    written the CISA KEV catalog into some provider's own rows under the key
    "catalog", colliding on the cache's (provider, key) primary key.
    """
    supplied = (provider is not None, namespace is not None, ttl is not None)
    if supplied == (True, False, False):
        _require_provider("_cached", provider)
        name, effective_ttl = provider.name, provider.cache_ttl
    elif supplied == (False, True, True):
        name, effective_ttl = namespace, ttl
    else:
        shown = provider.name if isinstance(provider, Provider) else provider
        raise TypeError(
            "_cached takes a `provider` alone, or `namespace` and `ttl` "
            "together (the CISA KEV exception) -- never a mixture of the "
            "two forms, and never neither. A `provider` beside a `ttl` is a "
            "cache namespace governed by a ttl its own provider did not "
            "set; a `provider` beside a `namespace` is two namespaces and "
            "no way to pick one. Got "
            f"provider={shown!r}, namespace={namespace!r}, ttl={ttl!r}"
        )
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
    _require_provider("fetch_serial", provider)
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
    """Serial with a gap between real requests; cache hits skip both.

    Guarded here as well as in fetch_serial, one line down, so that the
    message names the function the caller actually called.
    """
    _require_provider("fetch_censys", provider)
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


async def data_puller(indicator: Indicator, cache,
                      extra_ips: list[str] | None = None):
    """Every source that can answer for `indicator`, fanned out once.

    The entry is keyed by the indicator's kind rather than assuming a hash
    and deriving everything else from VirusTotal. A hash still seeds the IP
    fan-out from VT's contacted_ips; an `ip` seeds it directly with its own
    value and never calls VT at all; a `domain` or a `url` seeds the domain
    fan-out. The two fan-outs themselves are unchanged and shared -- which
    is the point: `for_indicator()` has selected providers by type since
    Phase 4, and the ip and domain providers were simply unreachable from
    the command line.
    """
    _require_indicator(indicator)
    # Selection is by indicator type, not by a hand-written branch per name:
    # indicator_types has been declared since Phase 1 and read by nothing,
    # and with seven more sources across three types the branches stop
    # scaling. available() stays the availability half -- a provider whose
    # key is unset is never selected, whatever types it declares.
    pool = available()
    hash_sources = {p.name for p in for_indicator("hash", pool)}
    ip_sources = {p.name for p in for_indicator("ip", pool)}
    domain_sources = {p.name for p in for_indicator("domain", pool)}
    # A url is looked up by the domain-typed sources: they are the ones that
    # answer for a host, and `domain_of` is what hands them one.
    kind_sources = {"hash": hash_sources, "ip": ip_sources,
                    "domain": domain_sources, "url": domain_sources}[indicator.kind]

    async with httpx.AsyncClient() as client:
        # OTX doesn't depend on the VT result, so start it before awaiting VT
        # (ruling R4). The two keyless hash sources are started here for the
        # same reason: all three need only the hash.
        otx_task = (
            asyncio.create_task(
                _cached(cache, indicator.value,
                        lambda: get_otx(client, indicator.value,
                                        indicator_type=_otx_type(indicator)),
                        provider=by_name("otx", pool))
            )
            if "otx" in kind_sources else None
        )
        # MalwareBazaar is a sample database: it is in hash_sources and in
        # no other, so this is gated on the kind as well as on the key.
        bazaar_task = (
            asyncio.create_task(
                _cached(cache, indicator.value,
                        lambda: get_bazaar(client, indicator.value),
                        provider=by_name("malwarebazaar", pool))
            )
            if indicator.kind == "hash" and "malwarebazaar" in hash_sources else None
        )
        # ThreatFox answers for the sample AND for every contacted IP; this
        # is the sample half. The per-IP fan-out is below, beside Shodan,
        # and lands in its own Report field -- Shodan gives exposure and
        # GreyNoise gives noise-vs-targeted, and neither names the C2
        # family, which is ThreatFox's whole value and what its dataset is
        # overwhelmingly made of.
        #
        # Skipped for an `ip` indicator, and only for that one: the per-IP
        # fan-out below asks ThreatFox exactly this question about exactly
        # this address, and a second identical lookup would land the same
        # answer in two Report fields for scoring to count twice.
        threatfox_task = (
            asyncio.create_task(
                _cached(cache, indicator.value,
                        lambda: get_threatfox(client, indicator.value),
                        provider=by_name("threatfox", pool))
            )
            if indicator.kind != "ip" and "threatfox" in kind_sources else None
        )

        if indicator.kind != "hash":
            # VT's file endpoint takes a digest. Calling it with an address
            # spends a 4-per-minute quota on a guaranteed 404, and reports
            # it as "VirusTotal has no record" -- which is true of every
            # address there has ever been.
            vt_data, vt_ips = make_error(VT_HASH_ONLY), []
        elif "virustotal" in hash_sources:
            vt_data = await _cached(
                cache, indicator.value,
                lambda: get_vt(client, indicator.value),
                provider=by_name("virustotal", pool)
            )
            vt_ips = contacted_ips(vt_data)
        else:
            vt_data, vt_ips = make_error("VirusTotal key not set"), []

        # An `ip` indicator seeds the fan-out with itself; a hash seeds it
        # with the addresses VT says the sample contacted. Everything below
        # this line is the same fan-out either way.
        seed_ips = [indicator.value] if indicator.kind == "ip" else vt_ips
        ips = _merge_indicators(seed_ips, extra_ips)

        # Each provider is resolved once per fan-out here, not once per
        # indicator inside the comprehension below it -- by_name is a
        # linear scan, and `ips`/`domains` can reach IOC_LIMIT entries.
        if ips and "abuseipdb" in ip_sources:
            abuseipdb_provider = by_name("abuseipdb", pool)
            ipdb_task = asyncio.gather(*(
                _cached(cache, ip, lambda ip=ip: get_ipdb(client, ip),
                        provider=abuseipdb_provider)
                for ip in ips
            ))
        else:
            ipdb_task = None
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
        if ips and "shodan" in ip_sources:
            shodan_provider = by_name("shodan", pool)
            shodan_task = asyncio.gather(*(
                _cached(cache, ip, lambda ip=ip: get_shodan(client, ip),
                        provider=shodan_provider)
                for ip in ips
            ))
        else:
            shodan_task = None
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
        if ips and "threatfox" in ip_sources:
            threatfox_ip_provider = by_name("threatfox", pool)
            threatfox_ips_task = asyncio.create_task(
                _bounded_gather(THREATFOX_CONCURRENCY, *(
                    _cached(cache, ip, lambda ip=ip: get_threatfox(client, ip),
                            provider=threatfox_ip_provider)
                    for ip in ips
                ))
            )
        else:
            threatfox_ips_task = None

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

        # Same shape on the domain side: a domain or a url seeds the
        # fan-out with its own host, a hash with what VT and the IP sources
        # turned up. _merge_indicators keeps VT's order, de-duplicates, and
        # re-applies IOC_LIMIT to the union.
        primary_domain = domain_of(indicator)
        domains = _merge_indicators(
            [primary_domain] if primary_domain else [],
            _domains(vt_data, list(ipdb_data), censys_results),
        )
        if domains and "rdap" in domain_sources:
            rdap_provider = by_name("rdap", pool)
            rdap_results = await _bounded_gather(RDAP_CONCURRENCY, *(
                _cached(cache, domain, lambda d=domain: get_rdap(client, d),
                        provider=rdap_provider)
                for domain in domains
            ))
        else:
            rdap_results = []
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
            kev_catalog = await _cached(cache, "catalog", lambda: get_kev(client),
                                        namespace="cisa_kev", ttl=KEV_CACHE_TTL)

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
