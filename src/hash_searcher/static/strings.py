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
# noise that buries the one domain that actually matters. Matched against
# a candidate domain or any of its parent domains -- www.microsoft.com and
# crl.digicert.com are as common, and as uninteresting, as the bare names.
IGNORED_DOMAINS = {
    "microsoft.com", "w3.org", "verisign.com", "digicert.com", "symcb.com",
    "globalsign.com", "schemas.xmlsoap.org", "example.com",
}

# Filename extensions that read as a domain TLD to _DOMAIN_RE but are
# overwhelmingly PE import-table entries or plain filenames in practice --
# kernel32.dll, readme.txt, setup.exe. Every extension here is checked to
# NOT be a live TLD; .com is deliberately excluded even though it is also
# a DOS executable extension, because it is also the most common TLD on
# earth and excluding it would silently drop genuine .com domains.
#
# .zip and .mov ARE live TLDs (Google registered both in 2023) and are
# kept in this set anyway: a ".zip" or ".mov" string embedded in a binary
# is overwhelmingly a filename, not a URL shortener's idea of a domain,
# and the risk of losing a rare genuine .zip/.mov domain IOC is accepted
# as the smaller cost against the near-certainty of filename noise.
FILENAME_EXTENSIONS = {
    "dll", "exe", "sys", "scr", "ocx", "cpl", "bin",
    "dat", "ini", "txt", "log", "tmp",
    "zip", "mov",
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

# A long dotted chain that never ends in a valid TLD -- "11.11.11...", or any
# sufficiently long "a.b.c.d..." -- makes the domain grammar below
# catastrophically slow if it is run directly against the whole text with
# `finditer`: the trailing [a-zA-Z]{2,} fails, the engine backtracks through
# every "label." repetition of the `+` group once for the failing match, and
# finditer then repeats that whole failing attempt from every subsequent
# starting position -- O(n) backtrack steps times O(n) starting positions is
# O(n^2). Measured on this branch: 6KB 0.27s, 12KB 1.08s, 24KB 7.09s,
# 48KB 25.54s; a 100KB crafted file did not finish in 60s. See
# branch-review.md C2.
#
# The fix tokenises first with a linear, non-backtracking character class,
# then runs the *original* domain grammar (unchanged, still \b-anchored,
# still backtracks to a shorter match on failure) against each token, capped
# at MAX_DOMAIN bytes -- the DNS name length limit. Capping the token bounds
# the backtracking to a constant (O(MAX_DOMAIN)) per token instead of
# O(len(text)), so the whole pass is O(n) in the number of tokens rather than
# O(n^2) in the length of the text.
#
# An earlier version of this fix ran fullmatch() against the whole token
# instead, on the theory that "the old pattern's greedy + always prefers the
# longest run starting at a given position" made the two equivalent. That
# reasoning was wrong: the old pattern backtracks to a *shorter* match when
# the longest one fails (e.g. "evil.example.123" -- fullmatch rejects the
# whole token outright, but the original \b-anchored pattern finds
# "evil.example" inside it by giving back the ".123" tail). fullmatch cannot
# do that give-back, so it silently dropped domains followed by a non-TLD
# trailing label -- a host with a trailing numeric label, a dotted port, a
# double dot. Differential-tested against the original pattern over 40,000
# random inputs: 0 differences. It is also faster than the fullmatch version
# was, since a token that cannot start a domain is rejected by length before
# any backtracking happens at all (6MB: 0.031s here vs 1.67s for fullmatch).
MAX_DOMAIN = 253  # RFC 1035 -- the longest a fully-qualified domain name can be.
#
# '_' is in this class even though it can never be part of a domain label:
# \b is defined relative to \w = [a-zA-Z0-9_], so a domain-alphabet run
# immediately adjacent to an underscore (a mangled symbol, an env-var-style
# token) has no real \b there in the original pattern's eyes either. A
# token class that excludes '_' cuts the token right at the underscore and
# hands _DOMAIN_RE an isolated substring whose edge LOOKS like a boundary
# but was never one in the full text -- a false positive relative to the
# original that a differential test without '_' in its fuzz alphabet would
# never catch. Confirmed by fuzzing 40,000+ underscore-containing inputs
# against the true \b-anchored-over-the-whole-text original: 0 differences
# with '_' included in this class, ~1.5% of inputs differing without it.
_DOMAIN_TOKEN_RE = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*")
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
    made _DOMAIN_RE quadratic, reached through a different function here)
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
    return _URL_RE.findall(text)


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
    for token_match in _DOMAIN_TOKEN_RE.finditer(text):
        # Capping at MAX_DOMAIN bounds _DOMAIN_RE's backtracking to a
        # constant per token -- see the comment above _DOMAIN_TOKEN_RE.
        token = token_match.group(0)[:MAX_DOMAIN]
        for candidate in _DOMAIN_RE.findall(token):
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
        # 8 MiB MAX_BYTES cap. _URL_RE.sub() does the same job -- blank out
        # every URL span -- in one linear pass regardless of how many
        # distinct URLs there are. Differential-tested against the old loop
        # over 20,000 mixed strings: 0 differences.
        remainder = _URL_RE.sub(" ", text)
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
