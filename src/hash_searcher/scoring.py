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

STRONG_DETECTION = 5
ABUSE_CONFIDENCE = 75


def _detection_signal(report: Report) -> Signal | None:
    detection = report.vt.detection
    if not detection or detection.malicious == 0:
        return None
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
        points=high * W_SIGMA_HIGH + medium * W_SIGMA_MEDIUM,
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
    return Signal(name="signed", points=W_SIGNED,
                  detail=f"valid signature from "
                         f"{signature.signer or 'an unnamed signer'}")


SIGNALS = (
    _detection_signal, _sigma_signal, _family_signal, _sandbox_signal,
    _yara_signal, _otx_signal, _abuseipdb_signal, _signed_signal,
)


def score(report: Report) -> Verdict:
    """Total the signals that fired and band the result.

    UNKNOWN is not the bottom of the scale -- it is the answer when nothing
    has ever seen this file. Collapsing it into CLEAN would tell a shell
    script that an unanalyzed sample is safe.
    """
    signals = [s for s in (make(report) for make in SIGNALS) if s]
    signals.sort(key=lambda s: -s.points)
    total = sum(s.points for s in signals)

    if not report.vt.found and not report.otx.has_pulses:
        return Verdict(level="UNKNOWN", score=total, signals=signals)
    if total >= MALICIOUS_AT:
        level = "MALICIOUS"
    elif total >= SUSPICIOUS_AT:
        level = "SUSPICIOUS"
    else:
        level = "CLEAN"
    return Verdict(level=level, score=total, signals=signals)
