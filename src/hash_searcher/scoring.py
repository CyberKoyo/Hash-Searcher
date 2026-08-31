"""Weighted, auditable verdict.

Every signal that fires records its own points and a human-readable reason.
An opaque number would be worse than none: an analyst has to be able to say
why the tool called something malicious, and to disagree with it.

The weights are deliberately coarse and deliberately visible. This is a
triage aid, not a classifier, and the constants below are the whole of the
argument -- change them here or nowhere.
"""

from .models import Report, Signal, Verdict

MALICIOUS_AT = 50
SUSPICIOUS_AT = 15

W_DETECTION_STRONG = 50   # >= 5 engines agree
W_DETECTION_WEAK = 20     # 1-4 engines: real, but the engines disagree
W_SIGMA_HIGH = 15
W_SIGMA_MEDIUM = 5
W_FAMILY = 15
W_SANDBOX = 15
W_YARA = 10
W_OTX_PULSE = 10
W_ABUSEIPDB = 10
W_SIGNED = -20            # a valid signature is evidence AGAINST, not for
W_DETECTION_SUSPICIOUS = 10   # engines hedging, none convicting

# Phase 4: additional sources. certs is deliberately absent -- sibling
# domains from certificate transparency are a pivot, not a verdict, and
# scoring them would make every large hosting provider look malicious.
# Do not "fix" that omission; test_certificate_siblings_are_informational
# _and_score_nothing pins it.
W_BAZAAR = 15
W_THREATFOX = 15
W_KEV = 25                # confirmed exploitation in the wild
W_INTERNET_NOISE = -10    # scanning everyone is not evidence about THIS sample

# Phase 3: local static analysis, no VT record required. These are the only
# three signals that can fire from report.static -- score()'s UNKNOWN guard
# checks for exactly these names among the fired signals, see below.
W_PACKED = 10
W_SUSPICIOUS_IMPORTS = 15
W_YARA_LOCAL = 20

# The sigma term is the only one that scales with the input, and VT's
# crowdsourced Sigma corpus fires readily on benign installers and on anything
# that spawns a shell. Uncapped, four matches outvoted seventy-two engines
# reporting undetected. Capped here, behaviour signals with no engine
# corroboration reach SUSPICIOUS on their own but never MALICIOUS.
SIGMA_CAP = 30

#: Targets named in the threatfox signal's detail before the rest are
#: counted instead. That string lands in a reportlab table cell whose row
#: cannot split across pages, so an unbounded join here is not a long line
#: -- it is a LayoutError that kills `-o report.pdf` after every provider
#: has already succeeded (render/pdf.py's module docstring, rule 2). The
#: measured threshold for that cell is 2445 characters and 42 Emotet hits
#: crossed it, well inside the IOC_LIMIT of 50 addresses the puller can
#: hand this. Same bargain as CVE_DISPLAY_LIMIT and tag_text: cap at an
#: item boundary and state the untruncated total, so a shortened list never
#: reads as the whole answer.
#:
#: This is the honest cap. render/pdf.py also enforces a blunt character
#: bound on EVERY signal detail, because four other signals join provider
#: lists that nothing upstream caps -- see DETAIL_CHAR_LIMIT.
THREATFOX_TARGET_LIMIT = 5

STRONG_DETECTION = 5
SUSPICIOUS_ENGINES = 3    # below this, engine hedging is noise
ABUSE_CONFIDENCE = 75
SUSPICIOUS_IMPORT_FLOOR = 3   # below this, one or two hits could be legitimate


def _detection_signal(report: Report) -> Signal | None:
    detection = report.vt.detection
    if not detection:
        return None
    if detection.malicious == 0:
        # Engines hedging rather than convicting. Weaker than a malicious
        # verdict, but the field was extracted, rendered, and serialized while
        # the scorer ignored it -- showing an analyst a number the tool does
        # not weigh is worse than not showing it.
        if detection.suspicious < SUSPICIOUS_ENGINES:
            return None
        return Signal(
            name="detection",
            points=W_DETECTION_SUSPICIOUS,
            detail=f"{detection.suspicious} engines called this file suspicious "
                   f"({detection.malicious}/{detection.total} malicious)",
        )
    strong = detection.malicious >= STRONG_DETECTION
    return Signal(
        name="detection",
        points=W_DETECTION_STRONG if strong else W_DETECTION_WEAK,
        detail=f"{detection.ratio} engines flagged this file",
    )


def _sigma_signal(report: Report) -> Signal | None:
    high = len(report.vt.by_level("high"))
    medium = len(report.vt.by_level("medium"))
    if not high and not medium:
        return None
    return Signal(
        name="sigma",
        points=min(high * W_SIGMA_HIGH + medium * W_SIGMA_MEDIUM, SIGMA_CAP),
        detail=f"{high} high and {medium} medium sigma rules matched",
    )


def _family_signal(report: Report) -> Signal | None:
    threat = report.vt.threat
    if not threat or not threat.family:
        return None
    return Signal(name="family", points=W_FAMILY,
                  detail=f"VT names the family {threat.family!r}")


def _sandbox_signal(report: Report) -> Signal | None:
    if not report.vt.sandbox:
        return None
    return Signal(name="sandbox", points=W_SANDBOX,
                  detail="flagged by sandbox: "
                         + ", ".join(v.sandbox for v in report.vt.sandbox))


def _yara_signal(report: Report) -> Signal | None:
    if not report.vt.yara:
        return None
    return Signal(name="yara", points=W_YARA,
                  detail="crowdsourced YARA matched: "
                         + ", ".join(y.rule for y in report.vt.yara))


def _otx_signal(report: Report) -> Signal | None:
    if not report.otx.has_pulses:
        return None
    return Signal(name="otx", points=W_OTX_PULSE,
                  detail=f"OTX pulses reference this indicator "
                         f"({report.otx.recorded_instances} recorded instances)")


def _abuseipdb_signal(report: Report) -> Signal | None:
    worst = max((i.confidence for i in report.ips.values()), default=0)
    if worst < ABUSE_CONFIDENCE:
        return None
    return Signal(name="abuseipdb", points=W_ABUSEIPDB,
                  detail=f"a contacted IP has {worst}% AbuseIPDB confidence")


def _signed_signal(report: Report) -> Signal | None:
    signature = report.vt.signature
    if not signature or not signature.verified:
        return None
    detection = report.vt.detection
    if detection and detection.malicious:
        # A valid signature is corroborating evidence FOR a clean file, not
        # exculpatory evidence for a flagged one. W_SIGNED cancels
        # W_DETECTION_WEAK to the point, so without this guard a stolen or
        # abused certificate erased four engines flagging the file -- and the
        # signature is the one input in the scoring set that the attacker
        # attaches to the sample themselves.
        return None
    return Signal(name="signed", points=W_SIGNED,
                  detail=f"valid signature from "
                         f"{signature.signer or 'an unnamed signer'}")


def _packed_signal(report: Report) -> Signal | None:
    static = report.static
    if not static or not static.entropy or not static.entropy.packed:
        return None
    return Signal(name="packed", points=W_PACKED,
                  detail=f"entropy {static.entropy.overall} -- {static.entropy.note}")


def _suspicious_imports_signal(report: Report) -> Signal | None:
    static = report.static
    if not static or not static.pe:
        return None
    imports = static.pe.suspicious_imports
    if len(imports) < SUSPICIOUS_IMPORT_FLOOR:
        return None
    return Signal(name="suspicious_imports", points=W_SUSPICIOUS_IMPORTS,
                  detail=f"imports {len(imports)} APIs associated with process "
                         f"injection or evasion: {', '.join(imports)}")


def _yara_local_signal(report: Report) -> Signal | None:
    static = report.static
    if not static or not static.yara:
        return None
    return Signal(name="yara_local", points=W_YARA_LOCAL,
                  detail="local YARA rules matched: "
                         + ", ".join(h.rule for h in static.yara))


def _bazaar_signal(report: Report) -> Signal | None:
    bazaar = report.bazaar
    # .ok gates BOTH cases a bare `if not bazaar` used to collapse: a source
    # that was never asked and one that was asked and failed. Touching
    # .value before checking .ok would raise on either -- .value is None
    # unless the query actually succeeded.
    if not bazaar.ok or not bazaar.value.found:
        return None
    return Signal(name="bazaar", points=W_BAZAAR,
                  detail=f"MalwareBazaar holds this sample"
                         f"{f' as {bazaar.value.family}' if bazaar.value.family else ''}")


def _threatfox_signal(report: Report) -> Signal | None:
    """Fires on the sample, on any contacted IP, or on both.

    The per-IP half is the half that usually lands: ThreatFox's dataset is
    overwhelmingly C2 addresses, not sample hashes. One signal rather than
    one per target, and a flat W_THREATFOX either way -- four contacted IPs
    in the same botnet's C2 pool is one fact stated four times, and letting
    it multiply would out-vote the engine consensus.

    .ok gates each result before .value is touched: a SourceResult has no
    __bool__, so a never-asked one is truthy and `.value` is None on it.

    The named targets are capped at THREATFOX_TARGET_LIMIT with the
    remainder counted -- see that constant: this detail is rendered into a
    PDF table cell whose row cannot split across pages.
    """
    hits = []
    if report.threatfox.ok and report.threatfox.value.found:
        hits.append(("this indicator", report.threatfox.value))
    hits += [(f"the contacted IP {ip}", result.value)
             for ip, result in report.threatfox_ips.items()
             if result.ok and result.value.found]

    if not hits:
        return None
    named = hits[:THREATFOX_TARGET_LIMIT]
    detail = "ThreatFox names " + "; ".join(
        f"{target} {value.malware or 'a known IOC'} "
        f"({value.confidence}% confidence)"
        for target, value in named)
    if len(hits) > len(named):
        # Always contacted IPs: the sample, when it matched at all, is
        # hits[0] and therefore always inside the cap.
        detail += f" -- and {len(hits) - len(named)} more contacted IPs"
    return Signal(name="threatfox", points=W_THREATFOX, detail=detail)


def _kev_signal(report: Report) -> Signal | None:
    """Confirmed exploitation in the wild -- the strongest single statement
    any Phase 4 source makes, which is why it outweighs the rest of them."""
    kev = report.kev
    if not kev.ok or not kev.value.entries:
        return None
    return Signal(name="kev", points=W_KEV,
                  detail="a contacted host exposes CVEs CISA lists as "
                         "known-exploited: "
                         + ", ".join(entry.cve for entry in kev.value.entries))


def _internet_noise_signal(report: Report) -> Signal | None:
    """Subtracts, never adds.

    An IP that scans the entire internet is not evidence that THIS sample
    was aimed at anyone. Scoring GreyNoise's "seen" as a positive would
    inflate every verdict that touches a contacted IP, which is most of
    them -- so only the benign classification fires, and it fires downward.
    """
    noisy = [ip for ip, r in report.greynoise.items()
             if r.ok and r.value.seen and r.value.classification == "benign"]
    if not noisy:
        return None
    return Signal(name="internet_noise", points=W_INTERNET_NOISE,
                  detail="GreyNoise calls these contacted IPs benign internet "
                         "background noise: " + ", ".join(noisy))


SIGNALS = (
    _detection_signal, _sigma_signal, _family_signal, _sandbox_signal,
    _yara_signal, _otx_signal, _abuseipdb_signal, _signed_signal,
    _packed_signal, _suspicious_imports_signal, _yara_local_signal,
    _bazaar_signal, _threatfox_signal, _kev_signal, _internet_noise_signal,
)

# The signal names allowed to escape the UNKNOWN guard below -- the ones
# that mean a source examined the FILE itself. This is
# deliberately NOT every signal report.static can produce -- "packed" is a
# real signal (see W_PACKED above, and _packed_signal), and still adds its
# points to the score whenever something else has already escaped UNKNOWN,
# but it is excluded here on purpose (branch-review.md I2). The UNKNOWN
# guard's contract is "independent evidence this file is malicious", not
# merely "this tool looked" -- suspicious_imports and yara_local both clear
# SUSPICIOUS_AT on their own and are evidence of that kind; a packed file is
# merely opaque, and the README's own caveat is that packed is not
# automatically malicious. Before this exclusion, a packed-only sample with
# no VT record scored 10 (W_PACKED, under SUSPICIOUS_AT), fell through the
# guard, and landed in CLEAN with exit 0 -- the exact failure mode this
# guard exists to prevent, just reached through a different signal than OTX
# (see the comment in score() below). Raising W_PACKED to SUSPICIOUS_AT was
# considered and rejected: that would call every packed installer
# SUSPICIOUS on its own, a much stronger claim.
#
# Adding a fourth static signal means adding its maker to SIGNALS, and --
# only if it is independent evidence of malice on its own -- its name here.
# "bazaar" joins them for the same reason and no other: MalwareBazaar
# holding this exact sample is a source having examined the FILE, not an
# opinion about an indicator the file happened to touch. Without it, a run
# with no VT key -- the keyless case this phase exists to serve -- would
# report UNKNOWN even when abuse.ch names the family, discarding the only
# real finding of the run. threatfox and kev are deliberately NOT here:
# ThreatFox describes an indicator and KEV describes a CVE on a contacted
# host, which is evidence ABOUT something the file touched, exactly the
# category OTX pulses were folded back into this guard for.
SAMPLE_EVIDENCE_NAMES = frozenset({"suspicious_imports", "yara_local", "bazaar"})


def score(report: Report) -> Verdict:
    """Total the signals that fired and band the result.

    UNKNOWN is not the bottom of the scale -- it is the answer when nothing
    has ever seen this file. Collapsing it into CLEAN would tell a shell
    script that an unanalyzed sample is safe.
    """
    signals = [s for s in (make(report) for make in SIGNALS) if s]
    signals.sort(key=lambda s: -s.points)
    total = sum(s.points for s in signals)

    has_sample_evidence = any(s.name in SAMPLE_EVIDENCE_NAMES for s in signals)

    if not report.vt.found and not has_sample_evidence:
        # VT having no record of the file is what "nobody analyzed this"
        # means -- but Phase 3 gives the tool its own eyes on a file VT has
        # never seen. A packed sample, a PE importing CreateRemoteThread, or
        # a local YARA hit is evidence the tool itself has now examined the
        # file and found something, even with zero network corroboration --
        # that is no longer "nobody has ever seen this", it is "nothing
        # ONLINE has ever seen this, and this tool looked and found X". OTX
        # pulses used to escape this guard the same way, but the only signal
        # escaping it could produce is otx at +10 -- under SUSPICIOUS_AT --
        # so an indicator sitting in OTX threat pulses fell through to CLEAN
        # and exit 0; pulses are evidence ABOUT an indicator, not evidence
        # the file was analyzed, and were folded back into this guard for
        # exactly that reason. Static findings are evidence the file WAS
        # analyzed -- by this tool, locally -- which is the one thing OTX
        # pulses could never claim, so they are allowed to escape where OTX
        # is not.
        return Verdict(level="UNKNOWN", score=total, signals=signals)
    if total >= MALICIOUS_AT:
        level = "MALICIOUS"
    elif total >= SUSPICIOUS_AT:
        level = "SUSPICIOUS"
    else:
        level = "CLEAN"
    return Verdict(level=level, score=total, signals=signals)
