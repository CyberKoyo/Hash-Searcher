"""Printable-string extraction and IOC harvesting.

This closes the loop the spec describes: strings-derived IOCs feed back
into the enrichment path, so a sample nobody has ever seen still produces
IPs and domains to look up. No optional dependency, always runs.
"""

import functools
import ipaddress
import re

from ..models import IOCSet, StringsReport
from .entropy import MAX_BYTES

IOC_LIMIT = 50   # per category, after de-duplication. Global Constraint 5:
                 # every entry reaches Task 9's rate-limited free-tier lookup.

# These appear in nearly every signed Windows binary. Reporting them is
# noise that buries the one domain that actually matters.
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
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


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


def _preceded_by_version_marker(text: str, start: int) -> bool:
    """True when the dotted quad at `start` reads like a version number.

    `1.2.3.4` is a syntactically valid, publicly routable address --
    `ipaddress` will happily accept it. The only thing separating "product
    version 1.2.3.4" from a real C2 address is the surrounding text.
    """
    prefix = text[:start]
    return prefix[-1:] == "v" or prefix.lower().endswith("version ")


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
    return _URL_RE.findall(text)


def _find_domains(text: str) -> list[str]:
    found = []
    for match in _DOMAIN_RE.finditer(text):
        domain = match.group(0).lower()
        if domain in IGNORED_DOMAINS:
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
        remainder = text
        for url in found_urls:
            remainder = remainder.replace(url, " ")
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
