"""One entry per intelligence source.

Adding a source means appending a Provider here, not editing the
orchestrator. key_env=None marks a keyless source, which is always available.
"""

from collections.abc import Callable
from dataclasses import dataclass

from . import config
from .abuseipdb import get_ipdb
from .censys import get_censys
from .otx import get_otx
from .virustotal import get_vt


@dataclass(frozen=True)
class Provider:
    name: str
    key_env: str | None
    key_value: str | None
    indicator_types: tuple[str, ...]
    fetch: Callable | None
    serial_delay: float = 0.0   # seconds between calls; 0 means parallel
    cache_ttl: int = 86400      # seconds


PROVIDERS: list[Provider] = [
    Provider("virustotal", "TOTAL_KEY", config.total_api_key, ("hash",), get_vt),
    Provider("otx", "OTX_KEY", config.otx_api_key, ("hash", "ip", "domain"), get_otx),
    Provider("abuseipdb", "IPDB_KEY", config.ipdb_api_key, ("ip",), get_ipdb),
    # Censys rate limits hard, so its calls stay serial with a gap between them.
    Provider("censys", "CENSYS_KEY", config.censys_api_key, ("ip",), get_censys,
             serial_delay=2.0),
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
    raise LookupError(f"no provider named {name!r} in PROVIDERS")
