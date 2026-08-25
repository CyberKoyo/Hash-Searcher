"""The verdict must be explainable. Every test here asserts on the SIGNALS,
not just the level -- a level that lands on the right band for the wrong
reason is the failure mode this layer exists to prevent."""

from hash_searcher.models import (
    Detection, IPReport, OTXReport, Report, SigmaRule, Signature, ThreatClass, VTReport,
)
from hash_searcher.scoring import score


def _report(vt=None, otx=None, ips=None) -> Report:
    return Report(
        indicator="a" * 64,
        generated_at="2026-08-25 00:00:00",
        vt=vt if vt is not None else VTReport(found=False, error="Hash not found"),
        otx=otx if otx is not None else OTXReport(recorded_instances="N/A"),
        ips=ips or {},
        hosts=[],
        whois=[],
    )


def test_a_hash_nobody_has_seen_is_unknown_not_clean():
    """The distinction the whole layer turns on: 'no evidence of evil' and
    'evidence of no evil' are different answers, and a shell script must be
    able to tell them apart."""
    verdict = score(_report())
    assert verdict.level == "UNKNOWN"
    assert verdict.score == 0
    assert verdict.signals == []


def test_a_high_detection_ratio_is_malicious():
    verdict = score(_report(vt=VTReport(found=True, detection=Detection(malicious=48, undetected=24))))
    assert verdict.level == "MALICIOUS"
    signal = next(s for s in verdict.signals if s.name == "detection")
    assert signal.points == 50
    assert "48/72" in signal.detail


def test_a_single_detection_is_suspicious_not_malicious():
    """One engine out of seventy is a real signal and a weak one. Banding it
    MALICIOUS would make the verdict useless on commodity false positives."""
    verdict = score(_report(vt=VTReport(found=True, detection=Detection(malicious=1, undetected=71))))
    assert verdict.level == "SUSPICIOUS"


def test_a_file_seen_by_vt_with_zero_detections_is_clean():
    verdict = score(_report(vt=VTReport(found=True, detection=Detection(malicious=0, undetected=72))))
    assert verdict.level == "CLEAN"


def test_signals_accumulate_and_each_carries_its_own_rationale():
    verdict = score(_report(
        vt=VTReport(
            found=True,
            detection=Detection(malicious=5, undetected=67),
            sigma=[SigmaRule("t", "d", "high"), SigmaRule("t2", "d2", "low")],
            threat=ThreatClass(label="trojan.emotet", family="emotet"),
        ),
        otx=OTXReport(recorded_instances=4, has_pulse_info=True, has_pulses=True),
        ips={"198.51.100.10": IPReport(ip="198.51.100.10", confidence=95, reports=40)},
    ))
    assert {s.name for s in verdict.signals} == {
        "detection", "sigma", "family", "otx", "abuseipdb"
    }
    assert verdict.score == sum(s.points for s in verdict.signals)
    for signal in verdict.signals:
        assert signal.detail, f"{signal.name} fired with no rationale"


def test_signals_are_ordered_heaviest_first():
    """The renderer prints them in order; the strongest reason should be the
    first thing an analyst reads."""
    verdict = score(_report(
        vt=VTReport(found=True, detection=Detection(malicious=48, undetected=24),
                    sigma=[SigmaRule("t", "d", "low")]),
    ))
    assert [s.points for s in verdict.signals] == sorted(
        (s.points for s in verdict.signals), reverse=True
    )


def test_a_verified_signature_subtracts():
    verdict = score(_report(vt=VTReport(
        found=True, detection=Detection(malicious=1, undetected=71),
        signature=Signature(verified=True, signer="Contoso Ltd"),
    )))
    assert any(s.name == "signed" and s.points < 0 for s in verdict.signals)
