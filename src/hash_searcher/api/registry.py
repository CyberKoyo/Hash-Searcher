"""One entry per intelligence source.

Adding a source means appending a Provider here, not editing the
orchestrator. key_env=None marks a keyless source, which is always available.
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
    # Keyless: key_env=None, so it is always available. A day's TTL --
    # a sample's family and tags do not change once abuse.ch has it.
    Provider("malwarebazaar", None, ("hash",), get_bazaar, cache_ttl=86400),
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
    Provider("threatfox", None, ("hash", "ip", "domain"), get_threatfox,
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
    pool = PROVIDERS if providers is None else providers
    return [p.key_env for p in pool if p.key_env and not p.key_value]


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
