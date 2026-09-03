"""Printable-string extraction and IOC harvesting.

This closes the loop the spec describes: strings-derived IOCs feed back
into the enrichment path, so a sample nobody has ever seen still produces
IPs and domains to look up. No optional dependency, always runs.

The URL and domain grammar itself lives in ``indicators.py`` -- the CLI
has to recognize exactly the same things when a user pastes one, and a
second copy of a bounded pattern is a second place to get the bound
wrong. The ReDoS analysis that produced these patterns travelled with
them; see the comments there.
"""

import functools
import ipaddress
import re

from ..indicators import (
    DOMAIN_RE, DOMAIN_TOKEN_RE, FILENAME_EXTENSIONS, MAX_DOMAIN, URL_RE,
)
from ..models import IOCSet, StringsReport
from .entropy import MAX_BYTES

IOC_LIMIT = 50   # per category, after de-duplication. Global Constraint 5:
                 # every entry reaches Task 9's rate-limited free-tier lookup.

# These appear in nearly every signed Windows binary. Reporting them is
# noise that buries the one domain that actually matters. Matched against
# a candidate domain or any of its parent domains -- www.microsoft.com and
# crl.digicert.com are as common, and as uninteresting, as the bare names.
IGNORED_DOMAINS = {
    "microsoft.com", "w3.org", "verisign.com", "digicert.com", "symcb.com",
    "globalsign.com", "schemas.xmlsoap.org", "example.com",
}

# RFC 1918 -- the private ranges an analyst never wants looked up. See
# _is_uninteresting() for why these are checked explicitly instead of via
# ipaddress.IPv4Address.is_private.
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

_IP_CANDIDATE_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


@functools.lru_cache(maxsize=None)
def _patterns(min_length: int):
    return (
        re.compile(rb"[\x20-\x7e]{%d,}" % min_length),
        re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length),
    )


def extract_strings(data: bytes, min_length: int = 6) -> list[str]:
    """Printable ASCII runs, then UTF-16LE runs, each >= min_length chars.

    UTF-16LE matters because Windows binaries carry most of their
    interesting strings that way; an ASCII-only scan misses nearly every
    path and URL in a PE.
    """
    ascii_pattern, utf16_pattern = _patterns(min_length)
    found = [match.group(0).decode("ascii") for match in ascii_pattern.finditer(data)]
    for match in utf16_pattern.finditer(data):
        try:
            found.append(match.group(0).decode("utf-16-le"))
        except UnicodeDecodeError:
            continue
    return found


_VERSION_MARKER = "version "


def _preceded_by_version_marker(text: str, start: int) -> bool:
    """True when the dotted quad at `start` reads like a version number.

    `1.2.3.4` is a syntactically valid, publicly routable address --
    `ipaddress` will happily accept it. The only thing separating "product
    version 1.2.3.4" from a real C2 address is the surrounding text.

    Slices only the fixed-width window this actually needs -- at most
    len("version ") characters -- rather than the original `text[:start]`.
    That full-prefix slice-and-lower ran once per dotted-quad candidate
    _find_ips finds, which is O(start) per call; on a long run of
    dotted-quad-shaped text (the same "11.11.11..." adversarial input that
    made DOMAIN_RE quadratic, reached through a different function here)
    that made the whole scan O(n^2): 100KB 0.60s, 200KB 1.96s, 400KB 5.28s,
    800KB 29.43s. Bounding the slice makes each call O(1).
    """
    if start and text[start - 1] == "v":
        return True
    window_start = max(0, start - len(_VERSION_MARKER))
    return text[window_start:start].lower() == _VERSION_MARKER


def _is_uninteresting(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject loopback, link-local, multicast, unspecified, reserved, and
    RFC 1918 private addresses.

    Nothing is gained by looking up 127.0.0.1 in AbuseIPDB, and every
    lookup costs a request against a rate-limited free tier.

    RFC 1918 is checked explicitly rather than via
    `ipaddress.IPv4Address.is_private`: in this interpreter, is_private also
    flags the IANA documentation/test-net ranges (192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24) as private, per the current IANA
    special-purpose registry. Those are exactly the ranges this project's
    fixtures use as stand-ins for real public IOCs so as to never commit a
    real malicious sample -- using is_private as-is would also swallow
    203.0.113.7 and 198.51.100.10, both of which the test suite expects to
    survive. is_reserved, is_loopback, is_link_local, is_multicast, and
    is_unspecified are unaffected by that and are used as-is.
    """
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
        or any(addr in network for network in _RFC1918)
    )


def _find_ips(text: str) -> list[str]:
    found = []
    for match in _IP_CANDIDATE_RE.finditer(text):
        if _preceded_by_version_marker(text, match.start()):
            continue
        try:
            addr = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if _is_uninteresting(addr):
            continue
        found.append(str(addr))
    return found


def _find_urls(text: str) -> list[str]:
    return URL_RE.findall(text)


def _is_ignored_domain(domain: str) -> bool:
    """True for an exact ignored domain or any subdomain of one.

    www.microsoft.com and crl.digicert.com appear in essentially every
    signed Windows binary just as often as the bare names do.
    """
    return any(
        domain == ignored or domain.endswith("." + ignored)
        for ignored in IGNORED_DOMAINS
    )


def _find_domains(text: str) -> list[str]:
    found = []
    for token_match in DOMAIN_TOKEN_RE.finditer(text):
        # Capping at MAX_DOMAIN bounds DOMAIN_RE's backtracking to a
        # constant per token -- see the comment above DOMAIN_TOKEN_RE.
        #
        # The cap truncates rather than skips, so a domain sitting past
        # byte 253 of a single unbroken domain-alphabet run is missed:
        # "a" * 300 + ".c2.evil.example" yields nothing where the
        # uncapped pattern finds c2.evil.example. Reaching that needs
        # 253+ unbroken [A-Za-z0-9._-] characters in front of the domain,
        # so it costs a real IOC only in input already shaped to hide
        # one -- and the alternative is the O(n^2) blowup the cap exists
        # to stop. Stated here because an undisclosed limit is the same
        # failure as the wrong equivalence claim above: it tells the next
        # reader there is nothing to check.
        token = token_match.group(0)[:MAX_DOMAIN]
        for candidate in DOMAIN_RE.findall(token):
            domain = candidate.lower()
            tld = domain.rsplit(".", 1)[-1]
            if tld in FILENAME_EXTENSIONS:
                continue
            if _is_ignored_domain(domain):
                continue
            found.append(domain)
    return found


def _dedup_cap(items: list[str]) -> list[str]:
    """De-dup while preserving first-seen order, then cap at IOC_LIMIT."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
        if len(result) == IOC_LIMIT:
            break
    return result


def harvest_iocs(strings: list[str]) -> IOCSet:
    """Pull IPs, domains, and URLs out of extracted strings.

    URLs are found first and stripped out of each string before IP/domain
    matching runs, so a path segment like payload.bin in a URL is never
    misread as a second domain.
    """
    ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    for text in strings:
        found_urls = _find_urls(text)
        urls.extend(found_urls)
        # A file with many DISTINCT URLs made this an O(len(text) x distinct
        # URLs) string scan: str.replace() re-scans the whole (shrinking but
        # still large) remainder once per URL. IDENTICAL repeated URLs never
        # triggered it, since a single replace() call removes every
        # occurrence in one pass -- only distinct URLs walk the loop body
        # more than once. Measured before this fix: 724KB 2.82s, 1.46MB
        # 12.14s, 2.96MB 51.36s -- clean 4x per 2x, quadratic; a real 2.7MB
        # file took 40.75s end to end through analyze_strings, ~370s at the
        # 8 MiB MAX_BYTES cap. URL_RE.sub() does the same job -- blank out
        # every URL span -- in one linear pass regardless of how many
        # distinct URLs there are. Differential-tested against the old loop
        # over 20,000 mixed strings: 0 differences.
        remainder = URL_RE.sub(" ", text)
        ips.extend(_find_ips(remainder))
        domains.extend(_find_domains(remainder))
    return IOCSet(
        ips=_dedup_cap(ips),
        domains=_dedup_cap(domains),
        urls=_dedup_cap(urls),
    )


def analyze_strings(path: str) -> StringsReport:
    """Extract strings and harvest IOCs from the first MAX_BYTES of `path`.

    MAX_BYTES is entropy.py's cap, reused rather than redefined -- Global
    Constraint 5, applied here too.
    """
    with open(path, "rb") as handle:
        data = handle.read(MAX_BYTES)
    strings = extract_strings(data)
    return StringsReport(count=len(strings), iocs=harvest_iocs(strings))
