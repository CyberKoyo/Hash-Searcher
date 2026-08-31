"""The verdict must be explainable. Every test here asserts on the SIGNALS,
not just the level -- a level that lands on the right band for the wrong
reason is the failure mode this layer exists to prevent."""

import pytest

from hash_searcher.models import (
    Detection, IPReport, OTXReport, Report, SandboxVerdict, SigmaRule, Signature,
    ThreatClass, VTReport, YaraMatch,
)
from hash_searcher.scoring import (
    SIGMA_CAP, W_DETECTION_SUSPICIOUS, W_PACKED, W_SANDBOX, W_SUSPICIOUS_IMPORTS,
    W_YARA, W_YARA_LOCAL, score,
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


# --- Phase 3: static signals -------------------------------------------------


def test_packed_and_suspicious_imports_raise_the_score():
    from hash_searcher.models import EntropyReport, PEStaticReport, StaticReport

    report = _report()  # the Phase 2 helper in tests/test_scoring.py
    report.static = StaticReport(
        path="x", size=1, sha256="a" * 64,
        entropy=EntropyReport(overall=7.9, packed=True, note="packed"),
        pe=PEStaticReport(suspicious_imports=[
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        ]),
    )
    names = {s.name for s in score(report).signals}
    assert "packed" in names and "suspicious_imports" in names


def test_a_yara_hit_from_local_rules_is_a_signal():
    from hash_searcher.models import StaticReport, YaraHit

    report = _report()
    report.static = StaticReport(path="x", size=1, sha256="a" * 64,
                                 yara=[YaraHit(rule="Emotet_Loader")])
    assert any(s.name == "yara_local" for s in score(report).signals)


def test_the_static_signals_carry_their_pinned_weights():
    """The scoring layer's weights are the whole argument (module docstring)
    -- pin them here the same way the Phase 2 signals are pinned elsewhere
    in this file."""
    from hash_searcher.models import EntropyReport, PEStaticReport, StaticReport, YaraHit

    report = _report()
    report.static = StaticReport(
        path="x", size=1, sha256="a" * 64,
        entropy=EntropyReport(overall=7.9, packed=True, note="packed"),
        pe=PEStaticReport(suspicious_imports=["A", "B", "C"]),
        yara=[YaraHit(rule="R")],
    )
    points = {s.name: s.points for s in score(report).signals}
    assert points["packed"] == W_PACKED
    assert points["suspicious_imports"] == W_SUSPICIOUS_IMPORTS
    assert points["yara_local"] == W_YARA_LOCAL


def test_fewer_than_three_suspicious_imports_does_not_fire():
    """'Firing at three or more' -- one or two hits could be a legitimate
    program that merely resolves LoadLibrary/GetProcAddress."""
    from hash_searcher.models import PEStaticReport, StaticReport

    report = _report()
    report.static = StaticReport(path="x", size=1, sha256="a" * 64,
                                 pe=PEStaticReport(suspicious_imports=["A", "B"]))
    assert not any(s.name == "suspicious_imports" for s in score(report).signals)


def test_static_findings_alone_lift_a_sample_out_of_unknown():
    """The decision this phase forces: a file with local findings and no VT
    record is no longer 'nobody has ever seen this'. Whichever way this is
    decided, it must be decided explicitly and pinned here."""
    from hash_searcher.models import StaticReport, YaraHit

    report = _report()  # vt.found is False, no OTX pulses
    report.static = StaticReport(path="x", size=1, sha256="a" * 64,
                                 yara=[YaraHit(rule="Emotet_Loader")])
    assert score(report).level != "UNKNOWN"


def test_a_static_report_with_no_findings_stays_unknown():
    """The guard must key off signals that actually fired, not off whether a
    StaticReport merely exists -- a clean local scan is not evidence the file
    was ever seen anywhere else."""
    from hash_searcher.models import StaticReport

    report = _report()
    report.static = StaticReport(path="x", size=1, sha256="a" * 64)
    assert score(report).level == "UNKNOWN"


def test_a_packed_only_sample_with_no_vt_record_stays_unknown():
    """branch-review.md I2 ruling: before this, a packed-only static report
    escaped the UNKNOWN guard (packed's 10 points is a fired signal) and
    the score itself totalled 10, under SUSPICIOUS_AT (15) -- so the level
    fell all the way through to CLEAN, exit 0. That is the failure mode the
    UNKNOWN guard exists to prevent, reached through a different signal
    than the OTX case score()'s docstring already explains: 'packed' means
    the tool could not see inside the file, not that it found evidence of
    anything, and the README's own caveat is that a packed binary is not
    automatically malicious. suspicious_imports and yara_local are each
    independent evidence on their own (see the other tests in this class)
    and correctly do still escape the guard -- only 'packed' alone must
    not. This pins the resulting LEVEL, not just which signal fired --
    the gap the reviewer found in
    test_static_findings_alone_lift_a_sample_out_of_unknown, which only
    ever exercised yara_local and asserted nothing about packed."""
    from hash_searcher.models import EntropyReport, StaticReport

    report = _report()  # vt.found is False, no OTX pulses
    report.static = StaticReport(
        path="x", size=1, sha256="a" * 64,
        entropy=EntropyReport(overall=7.9, packed=True, note="packed"),
    )
    verdict = score(report)
    assert verdict.level == "UNKNOWN"
    # The signal still fires and still carries its points -- W_PACKED keeps
    # contributing once something else has escaped the guard. Only the
    # ESCAPE is denied to it, not its weight.
    assert any(s.name == "packed" and s.points == 10 for s in verdict.signals)
    assert verdict.score == 10


def test_a_malwarebazaar_family_match_is_a_signal():
    from hash_searcher.models import BazaarReport, SourceResult
    from hash_searcher.scoring import score

    report = _report()
    report.bazaar = SourceResult(value=BazaarReport(found=True, family="Emotet"),
                                 queried=True)
    assert any(s.name == "bazaar" for s in score(report).signals)


def test_a_source_nobody_asked_never_fires_its_signal():
    """The crash this wrapper exists to prevent: a signal function touching
    .value on a SourceResult nobody queried must not raise AttributeError on
    a bare `Report()`'s default -- it must simply not fire."""
    from hash_searcher.scoring import score

    report = _report()
    assert not any(s.name == "bazaar" for s in score(report).signals)


def test_a_known_exploited_cve_is_a_strong_signal():
    """KEV means confirmed exploitation in the wild -- the strongest single
    statement any source in this phase makes."""
    from hash_searcher.models import KEVEntry, KEVReport, SourceResult
    from hash_searcher.scoring import score

    report = _report()
    report.kev = SourceResult(
        value=KEVReport(entries=[KEVEntry(cve="CVE-2021-41617", product="OpenSSH")]),
        queried=True)
    assert next(s for s in score(report).signals if s.name == "kev").points >= 20


def test_greynoise_internet_noise_subtracts_rather_than_adds():
    """An IP scanning the entire internet is not evidence that THIS sample
    was aimed at you. Scoring it as a positive inflates every verdict that
    touches a contacted IP, which is most of them."""
    from hash_searcher.models import GreyNoiseReport, SourceResult
    from hash_searcher.scoring import score

    report = _report()
    report.greynoise = {
        "198.51.100.10": SourceResult(
            value=GreyNoiseReport(seen=True, classification="benign"), queried=True)
    }
    assert any(s.name == "internet_noise" and s.points < 0 for s in score(report).signals)


def test_certificate_siblings_are_informational_and_score_nothing():
    """Sibling domains are a pivot, not a verdict. Scoring them would make
    every large hosting provider look malicious."""
    from hash_searcher.models import CertReport, SourceResult
    from hash_searcher.scoring import score

    report = _report()
    report.certs = SourceResult(
        value=CertReport(siblings=["a.example", "b.example"], count=2), queried=True)
    assert not any(s.name == "certs" for s in score(report).signals)


def test_a_threatfox_family_match_is_a_signal():
    from hash_searcher.models import SourceResult, ThreatFoxReport
    from hash_searcher.scoring import score

    report = _report()
    report.threatfox = SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet", confidence=90),
        queried=True)
    assert any(s.name == "threatfox" for s in score(report).signals)


def test_a_bazaar_family_match_escapes_unknown_without_a_vt_record():
    """The phase's headline case: no VT key at all, and abuse.ch holds this
    exact sample and names its family. That is a source having examined the
    FILE, not merely having an opinion about an indicator it touched --
    reporting UNKNOWN there would discard the only real finding of the run.
    """
    from hash_searcher.models import BazaarReport, SourceResult
    from hash_searcher.scoring import score

    report = _report()
    report.bazaar = SourceResult(value=BazaarReport(found=True, family="Emotet"),
                                 queried=True)
    assert score(report).level != "UNKNOWN"


def test_threatfox_fires_on_a_contacted_ip_even_when_the_sample_is_unknown():
    """The reason Task A4 exists. ThreatFox's dataset is overwhelmingly C2
    addresses, so the per-IP answer is the one it most often has -- and
    before this the signal could only fire on the sample's own hash, which
    ThreatFox rarely holds. Shodan reports exposure and GreyNoise reports
    noise-vs-targeted; neither names the family.
    """
    from hash_searcher.models import SourceResult, ThreatFoxReport
    from hash_searcher.scoring import score

    report = _report()
    report.threatfox_ips = {"198.51.100.10": SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet", confidence=90),
        queried=True)}

    assert report.threatfox.queried is False, "the sample itself was never asked"
    signals = [s for s in score(report).signals if s.name == "threatfox"]
    assert len(signals) == 1
    assert "198.51.100.10" in signals[0].detail
    assert "Emotet" in signals[0].detail


def test_a_threatfox_ip_lookup_with_nothing_to_report_is_not_a_signal():
    """Both non-answers, and neither is evidence: an address ThreatFox has
    no record of, and one nobody asked it about."""
    from hash_searcher.models import SourceResult, ThreatFoxReport
    from hash_searcher.scoring import score

    report = _report()
    report.threatfox_ips = {
        "198.51.100.10": SourceResult(value=ThreatFoxReport(found=False),
                                      queried=True),
        "203.0.113.7": SourceResult(),
    }
    assert not any(s.name == "threatfox" for s in score(report).signals)


def test_the_sample_level_threatfox_detail_is_unchanged_by_the_per_ip_pass():
    """The per-IP fan-out adds targets to this signal; it must not reword
    the answer the sample-level lookup already gave."""
    from hash_searcher.models import SourceResult, ThreatFoxReport
    from hash_searcher.scoring import score

    report = _report()
    report.threatfox = SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet", confidence=90),
        queried=True)
    signal = next(s for s in score(report).signals if s.name == "threatfox")
    assert signal.detail == (
        "ThreatFox names this indicator Emotet (90% confidence)"
    )
