"""One entry per intelligence source.

Adding a source means appending a Provider here, not editing the
orchestrator. That promise was prose for two phases and false for one of
them, so it is executable now: test_a_new_provider_needs_only_a_registry
_entry enforces every clause below.

The contract each entry signs:

- ``fetch(client, indicator) -> payload or error dict``. Exactly two
  required parameters, in that order. Anything else -- max_attempts, an
  indicator_type -- carries a default or arrives through **kwargs. A
  provider tempted to deviate is a defect in that provider, not in the
  shape.
- ``indicator_types``: which of "hash"/"ip"/"domain" this source can
  answer for. Read by for_indicator(), which is how data_puller decides
  what to call; an empty tuple makes a source unreachable, so it would
  silently never run.
- ``cache_ttl``: chosen per source, never defaulted by accident. CISA KEV
  changes weekly, ThreatFox hourly, RDAP on the order of years.
- ``serial_delay``: seconds between calls for a source that rate limits
  (Censys, crt.sh, GreyNoise). 0 means the fan-out runs in parallel.
- ``key_env=None`` marks a keyless source, which is always available. It
  also covers a source whose key is optional -- GreyNoise Community works
  without one and only raises its rate limit with one, so an unset key
  must not mark it unavailable.

Every fetch goes through api_get/api_post: that is where retries, backoff,
the error-dict convention, and the 404 message live, and a provider
calling client.get directly silently opts out of all four.
"""

from collections.abc import Callable
from dataclasses import dataclass

from . import config
from .abuseipdb import get_ipdb
from .censys import get_censys
from .crtsh import get_crtsh
from .malwarebazaar import get_bazaar
from .otx import get_otx
from .greynoise import get_greynoise
from .rdap import get_rdap
from .shodan_internetdb import get_shodan
from .threatfox import get_threatfox
from .virustotal import get_vt


@dataclass(frozen=True)
class Provider:
    name: str
    key_env: str | None
    indicator_types: tuple[str, ...]
    fetch: Callable | None
    serial_delay: float = 0.0   # seconds between calls; 0 means parallel
    cache_ttl: int = 86400      # seconds

    @property
    def key_value(self) -> str | None:
        """Read live rather than frozen at import -- see config.key."""
        return config.key(self.key_env) if self.key_env else None


PROVIDERS: list[Provider] = [
    Provider("virustotal", "TOTAL_KEY", ("hash",), get_vt),
    Provider("otx", "OTX_KEY", ("hash", "ip", "domain"), get_otx),
    Provider("abuseipdb", "IPDB_KEY", ("ip",), get_ipdb),
    # Censys rate limits hard, so its calls stay serial with a gap between them.
    Provider("censys", "CENSYS_KEY", ("ip",), get_censys, serial_delay=2.0),
    # abuse.ch put its APIs behind a free account after this phase was
    # planned, so these two carry a key_env and are skipped when it is
    # unset -- firing them anyway would print a 401 on every keyless run.
    # One account covers both. A day's TTL: a sample's family and tags do
    # not change once abuse.ch has it.
    Provider("malwarebazaar", "ABUSECH_KEY", ("hash",), get_bazaar, cache_ttl=86400),
    # A week: registration data changes on the order of years, and
    # rdap.org bootstraps through a redirect, so each lookup is two
    # requests rather than one.
    Provider("rdap", None, ("domain",), get_rdap, cache_ttl=604800),
    Provider("shodan", None, ("ip",), get_shodan, cache_ttl=86400),
    # crt.sh throttles anonymous bulk queries, so its lookups stay serial
    # with a gap between them -- the same treatment Censys gets.
    Provider("crtsh", None, ("domain",), get_crtsh,
             serial_delay=2.0, cache_ttl=86400),
    # An hour, not a day: ThreatFox's C2 data turns over hourly, and a
    # stale family attribution is worse than none (Constraint 6).
    Provider("threatfox", "ABUSECH_KEY", ("hash", "ip", "domain"), get_threatfox,
             cache_ttl=3600),
    # Community works keyless at a lower rate limit; GREYNOISE_KEY raises it.
    # key_env stays None so an unset key does not mark the source unavailable
    # -- the header is simply omitted. The key is read at call time, per Obs. C.
    Provider("greynoise", None, ("ip",), get_greynoise,
             serial_delay=1.0, cache_ttl=86400),
]


def available(providers: list[Provider] | None = None) -> list[Provider]:
    pool = PROVIDERS if providers is None else providers
    return [p for p in pool if p.key_env is None or p.key_value]


def missing_keys(providers: list[Provider] | None = None) -> list[str]:
    """The unset key variables, named once each.

    De-duplicated because one variable can serve several providers --
    ABUSECH_KEY covers both MalwareBazaar and ThreatFox -- and check_env
    printed it twice in the warning line before this.
    """
    pool = PROVIDERS if providers is None else providers
    return list(dict.fromkeys(
        p.key_env for p in pool if p.key_env and not p.key_value))


def by_name(name: str, providers: list[Provider] | None = None) -> Provider:
    """Look up one provider by name.

    Raises LookupError, never StopIteration: callers are coroutines, and a
    StopIteration escaping one is rewritten by the interpreter into an
    opaque "coroutine raised StopIteration" that names neither the registry
    nor the entry that went missing.
    """
    pool = PROVIDERS if providers is None else providers
    for provider in pool:
        if provider.name == name:
            return provider
    where = "PROVIDERS" if providers is None else "the supplied provider pool"
    raise LookupError(f"no provider named {name!r} in {where}")


def for_indicator(indicator_type: str,
                  providers: list[Provider] | None = None) -> list[Provider]:
    """Available providers that handle this indicator type.

    indicator_types has been declared since Phase 1 and read by nothing.
    With seven more sources across three types, hand-written branches in
    data_puller stop scaling -- this is what replaces them.
    """
    return [p for p in available(providers) if indicator_type in p.indicator_types]
