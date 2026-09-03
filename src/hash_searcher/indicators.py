"""What the user actually handed us.

The tool accepted a hash, or a file that becomes a hash, for four phases;
`for_indicator()` has selected providers by type since Phase 4, but the IP
and domain providers only ever saw indicators VirusTotal handed them. This
module is the missing half: it turns one line of user input -- pasted out
of a report, an email, or a ticket, defanged as often as not -- into the
`Indicator` those providers are already selected by.

Pure, and it stays that way: one filesystem `isfile` check (which is the
only way to answer "file or domain?" at all) and no I/O of any other kind.

The URL and domain patterns live here rather than in `static/strings.py`
because both modules need exactly the same grammar, and two copies of a
bounded pattern is two places to get the bound wrong. `strings.py` imports
them; the ReDoS analysis that produced them is carried down with them.
"""

import ipaddress
import os
import re
import string
from dataclasses import dataclass
from urllib.parse import urlsplit

HASH_LENGTHS = frozenset({32, 40, 64})  # md5, sha1, sha256

#: Every kind `classify` can return. `cidr` is recognized and then declined
#: (see `unsupported_reason`) -- recognizing it is what lets the tool say
#: why, instead of reading a /16 as an unclassifiable string.
KINDS = ("hash", "ip", "domain", "url", "cidr", "file")

# Filename extensions that read as a domain TLD to DOMAIN_RE but are
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
#
# classify() applies the same set to a name typed on the command line, and
# for the same reason: `hash-searcher kernel32.dll` is a file that is not
# where the user thought it was, and answering it with a DNS lookup for a
# domain named kernel32.dll is a wrong answer wearing a confident face.
FILENAME_EXTENSIONS = {
    "dll", "exe", "sys", "scr", "ocx", "cpl", "bin",
    "dat", "ini", "txt", "log", "tmp",
    "zip", "mov",
}


URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# A long dotted chain that never ends in a valid TLD -- "11.11.11...", or any
# sufficiently long "a.b.c.d..." -- makes the domain grammar below
# catastrophically slow if it is run directly against the whole text with
# `finditer`: the trailing [a-zA-Z]{2,} fails, the engine backtracks through
# every "label." repetition of the `+` group once for the failing match, and
# finditer then repeats that whole failing attempt from every subsequent
# starting position -- O(n) backtrack steps times O(n) starting positions is
# O(n^2). Measured when found: 6KB 0.27s, 12KB 1.08s, 24KB 7.09s,
# 48KB 25.54s; a 100KB crafted file did not finish in 60s.
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
#
# classify() below carries the same obligation and discharges it the same
# way: it refuses to run DOMAIN_RE against anything longer than MAX_DOMAIN
# at all, since nothing longer can be a domain name.
MAX_DOMAIN = 253  # RFC 1035 -- the longest a fully-qualified domain name can be.
#
# '_' is in this class even though it can never be part of a domain label:
# \b is defined relative to \w = [a-zA-Z0-9_], so a domain-alphabet run
# immediately adjacent to an underscore (a mangled symbol, an env-var-style
# token) has no real \b there in the original pattern's eyes either. A
# token class that excludes '_' cuts the token right at the underscore and
# hands DOMAIN_RE an isolated substring whose edge LOOKS like a boundary
# but was never one in the full text -- a false positive relative to the
# original that a differential test without '_' in its fuzz alphabet would
# never catch. Confirmed by fuzzing 40,000+ underscore-containing inputs
# against the true \b-anchored-over-the-whole-text original: 0 differences
# with '_' included in this class, ~1.5% of inputs differing without it.
DOMAIN_TOKEN_RE = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# Defanging is how an indicator survives a mail gateway, a ticket comment,
# and a PDF, so a pasted one arrives defanged far more often than not.
#
# Every rule is a literal-alternation substitution -- no nested quantifier,
# nothing that can backtrack -- so refang() stays linear in its input. The
# order matters twice: "[://]" is one token and must be rewritten before
# the ":" and "/" rules take it apart, and the scheme rule runs first so
# "hxxps[:]//" reaches the ":" rule already spelled "https[:]//".
_REFANG_RULES = (
    (re.compile(r"h(?:xx|XX)p", re.IGNORECASE), "http"),
    (re.compile(r"\s*[\[({]\s*:\s*//\s*[\])}]\s*"), "://"),
    (re.compile(r"\s*[\[({]\s*(?:\.|dot)\s*[\])}]\s*", re.IGNORECASE), "."),
    (re.compile(r"\s*[\[({]\s*(?::|colon)\s*[\])}]\s*", re.IGNORECASE), ":"),
    (re.compile(r"\s*[\[({]\s*(?:@|at)\s*[\])}]\s*", re.IGNORECASE), "@"),
    (re.compile(r"\s*[\[({]\s*(?:/|slash)\s*[\])}]\s*", re.IGNORECASE), "/"),
)


@dataclass(frozen=True)
class Indicator:
    """One thing to look up. `kind` is one of KINDS."""
    kind: str
    value: str


def looks_like_hash(value: str) -> bool:
    """True if value is a bare hex digest rather than a path."""
    return len(value) in HASH_LENGTHS and all(c in string.hexdigits for c in value)


def refang(raw: str) -> str:
    """Undo the usual defangings: hxxp, [.], (dot), [:], [://], [at].

    Whitespace immediately around a bracketed token is consumed with it,
    because "evil [.] example" is one indicator written with spaces, not
    three tokens. Whitespace elsewhere is left alone -- classify() is what
    decides that an interior space means this was never one indicator.
    """
    result = raw.strip()
    for pattern, replacement in _REFANG_RULES:
        result = pattern.sub(replacement, result)
    return result


def _is_domain(value: str) -> bool:
    """A full-string domain match, bounded before the pattern ever runs.

    The length guard is not an optimization: DOMAIN_RE backtracks, and
    running it against an arbitrarily long argument is the same O(n^2)
    hazard the token cap exists to stop in strings.py. Nothing longer than
    MAX_DOMAIN can be a domain name, so nothing longer is offered to it.
    """
    if not value or len(value) > MAX_DOMAIN:
        return False
    match = DOMAIN_RE.match(value)
    return match is not None and match.end() == len(value)


def _is_file(raw: str) -> bool:
    """isfile, not exists: a directory cannot be hashed, and reporting one
    as a `file` indicator only moves the failure downstream. Long or
    NUL-bearing input raises rather than returning False on some platforms.
    """
    try:
        return os.path.isfile(raw)
    except (OSError, ValueError):
        return False


def classify(raw: str) -> Indicator | None:
    """Turn one line of user input into an Indicator, or None.

    The filesystem is consulted first and against the *raw* argument: a
    path is not a defanged anything, and when a file of that name really is
    on disk, "analyze this file" is what the user meant. `evil.example` is
    a legal filename, and the only way to tell the two readings apart is to
    look.
    """
    if not raw or not raw.strip():
        return None
    if _is_file(raw):
        return Indicator("file", raw)

    value = refang(raw)
    if not value or any(character.isspace() for character in value):
        # Interior whitespace after refanging means this was never one
        # indicator -- a sentence, a column of a table, two IOCs on a line.
        return None

    if looks_like_hash(value):
        return Indicator("hash", value.lower())

    # Before the URL check, because a CIDR is the other thing with a slash
    # in it, and ip_network is a cheap exact parse either way.
    if "/" in value and "://" not in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            pass
        else:
            return Indicator("cidr", value)

    if URL_RE.fullmatch(value):
        # The host is case-insensitive and the path is not, so only the
        # host is normalized -- lowercasing the whole URL would ask a
        # server for a different resource than the user pasted.
        return Indicator("url", _with_lowercased_host(value))

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return Indicator("ip", str(address))

    if _is_domain(value):
        domain = value.lower()
        if domain.rsplit(".", 1)[-1] in FILENAME_EXTENSIONS:
            # A filename whose file is not where the user thought it was.
            # `_is_file` already looked; answering with a DNS lookup for a
            # domain named kernel32.dll would be a wrong answer, not a
            # smaller one.
            return None
        return Indicator("domain", domain)

    return None


def _with_lowercased_host(url: str) -> str:
    parts = urlsplit(url)
    if not parts.netloc or parts.netloc == parts.netloc.lower():
        return url
    return parts._replace(netloc=parts.netloc.lower()).geturl()


def domain_of(indicator: Indicator | None) -> str | None:
    """The domain a domain-typed provider should be handed, or None.

    This is the host, with a leading `www.` dropped -- deliberately not the
    registrable domain (eTLD+1), which cannot be computed without a Public
    Suffix List: trimming to the last two labels would turn
    `evil.example.co.uk` into `co.uk` and point RDAP and crt.sh at a public
    suffix instead of at the name in hand. Handing over the full host asks a
    narrower question than the true eTLD+1 would; handing over `co.uk` would
    ask a wrong one.
    """
    if indicator is None:
        return None
    if indicator.kind == "domain":
        return indicator.value
    if indicator.kind != "url":
        return None
    host = urlsplit(indicator.value).hostname  # drops userinfo and port
    if not host:
        return None
    host = host.lower()
    return host[4:] if host.startswith("www.") and _is_domain(host[4:]) else host


def unsupported_reason(indicator: Indicator | None) -> str | None:
    """Why this indicator cannot be run, or None when it can.

    A CIDR is recognized so that this message exists. Expanding one is the
    alternative, and /16 is 65,536 addresses against providers that all
    rate limit -- a free-tier key spent on a single careless paste, with no
    prompt in between.
    """
    if indicator is not None and indicator.kind == "cidr":
        return (
            f"{indicator.value} is a network range, and expanding it would "
            "queue one rate-limited lookup per address. Pass the individual "
            "addresses you care about instead."
        )
    return None
