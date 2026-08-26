"""The verdict must be explainable. Every test here asserts on the SIGNALS,
not just the level -- a level that lands on the right band for the wrong
reason is the failure mode this layer exists to prevent."""

import pytest

from hash_searcher.models import (
    Detection, IPReport, OTXReport, Report, SandboxVerdict, SigmaRule, Signature,
    ThreatClass, VTReport, YaraMatch,
)
from hash_searcher.scoring import (
    SIGMA_CAP, W_DETECTION_SUSPICIOUS, W_SANDBOX, W_YARA, score,
)


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
        otx=OTXReport(recorded_instances=4, otx_responded=True, has_pulses=True),
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
    """Used to pass a detection of 1 alongside the signature. That case now
    suppresses the credit entirely -- see
    test_a_signature_cannot_erase_engine_detections -- so this pins the case
    the credit is actually for: a file nothing flagged.
    """
    verdict = score(_report(vt=VTReport(
        found=True, detection=Detection(malicious=0, undetected=72),
        signature=Signature(verified=True, signer="Contoso Ltd"),
    )))
    assert any(s.name == "signed" and s.points < 0 for s in verdict.signals)


def test_otx_pulses_without_a_vt_record_are_unknown_not_clean():
    """Critical, review of 86996f9: `has_pulses` used to be enough to escape
    the UNKNOWN guard, but the only signal escaping it can produce is otx at
    +10 -- below SUSPICIOUS_AT. So an indicator sitting in OTX threat pulses
    that VT has never seen fell through to CLEAN and exit 0, which is exactly
    what score()'s docstring says this layer exists to prevent.

    VT having no record of the file is what "nobody analyzed this" means. OTX
    pulses are evidence ABOUT an indicator, not evidence the file was analyzed.
    """
    verdict = score(_report(
        vt=VTReport(found=False, error="Hash not found"),
        otx=OTXReport(recorded_instances=12, otx_responded=True, has_pulses=True),
    ))
    assert verdict.level == "UNKNOWN"
    assert any(s.name == "otx" for s in verdict.signals), (
        "the signal must still be reported -- UNKNOWN means unanalyzed, "
        "not that the pulses go unmentioned"
    )


def test_a_signature_cannot_erase_engine_detections():
    """W_SIGNED == -W_DETECTION_WEAK to the point, so a signature used to zero
    out four engines flagging the file. Code-signing abuse is a first-class
    technique and the signature is the one input in the scoring set an
    attacker fully controls; letting it cancel independent third-party
    detections inverts the trust model. A valid signature is corroborating
    evidence FOR a clean file, not exculpatory evidence for a flagged one.
    """
    verdict = score(_report(vt=VTReport(
        found=True, detection=Detection(malicious=4, undetected=68),
        signature=Signature(verified=True, signer="Contoso Ltd"),
    )))
    assert not any(s.name == "signed" for s in verdict.signals)
    assert verdict.level == "SUSPICIOUS"
    assert verdict.score == 20


def test_the_sigma_term_is_capped():
    """`high * 15 + medium * 5` was the only unbounded term in the model, so
    four crowdsourced Sigma matches outvoted seventy-two engines reporting
    undetected. VT's Sigma corpus fires readily on benign installers and
    anything that spawns a shell -- behaviour signals with no engine
    corroboration should reach SUSPICIOUS on their own, never MALICIOUS.
    """
    twenty_high = [SigmaRule(f"t{i}", "d", "high") for i in range(20)]
    verdict = score(_report(vt=VTReport(
        found=True, detection=Detection(malicious=0, undetected=72), sigma=twenty_high,
    )))
    sigma = next(s for s in verdict.signals if s.name == "sigma")
    assert sigma.points == SIGMA_CAP
    assert verdict.level == "SUSPICIOUS"


def test_engines_calling_a_file_suspicious_are_scored_not_just_printed():
    """`Detection.suspicious` was extracted, rendered, and serialized, and then
    ignored by the scorer -- the tool showed an analyst a number it did not
    weigh. Weaker than a malicious verdict, but not nothing."""
    verdict = score(_report(vt=VTReport(
        found=True, detection=Detection(malicious=0, suspicious=12, undetected=60),
    )))
    signal = next(s for s in verdict.signals if s.name == "detection")
    assert signal.points == W_DETECTION_SUSPICIOUS
    assert "12" in signal.detail


def test_one_engine_calling_a_file_suspicious_is_below_the_floor():
    verdict = score(_report(vt=VTReport(
        found=True, detection=Detection(malicious=0, suspicious=1, undetected=71),
    )))
    assert not any(s.name == "detection" for s in verdict.signals)
    assert verdict.level == "CLEAN"


def test_a_sandbox_verdict_fires_its_own_signal():
    verdict = score(_report(vt=VTReport(
        found=True, sandbox=[SandboxVerdict(sandbox="Zenbox", category="malicious")],
    )))
    signal = next(s for s in verdict.signals if s.name == "sandbox")
    assert signal.points == W_SANDBOX
    assert "Zenbox" in signal.detail


def test_a_yara_match_fires_its_own_signal():
    verdict = score(_report(vt=VTReport(
        found=True, yara=[YaraMatch(rule="malw_eicar", author="Marc Rivero")],
    )))
    signal = next(s for s in verdict.signals if s.name == "yara")
    assert signal.points == W_YARA
    assert "malw_eicar" in signal.detail


def _sigma(high: int = 0, medium: int = 0) -> list[SigmaRule]:
    return ([SigmaRule(f"h{i}", "d", "high") for i in range(high)]
            + [SigmaRule(f"m{i}", "d", "medium") for i in range(medium)])


@pytest.mark.parametrize("vt, expected_score, expected_level", [
    # Straddle SUSPICIOUS_AT (15) and MALICIOUS_AT (50) from both sides, with
    # reports that could actually come back from VT rather than fabricated
    # scores. Before this test the bands were pinned only by a README-sync
    # test -- no behavioural test asserted either boundary.
    (VTReport(found=True, sigma=_sigma(medium=2)), 10, "CLEAN"),
    (VTReport(found=True, sigma=_sigma(medium=3)), 15, "SUSPICIOUS"),
    (VTReport(found=True, sigma=_sigma(high=2),
              threat=ThreatClass(label="trojan.x", family="x")), 45, "SUSPICIOUS"),
    (VTReport(found=True, sigma=_sigma(high=2),
              detection=Detection(malicious=1, undetected=71)), 50, "MALICIOUS"),
])
def test_the_band_boundaries(vt, expected_score, expected_level):
    verdict = score(_report(vt=vt))
    assert verdict.score == expected_score
    assert verdict.level == expected_level
