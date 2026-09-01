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


def _threatfox_hits(*ips):
    from hash_searcher.models import SourceResult, ThreatFoxReport
    return {ip: SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet", confidence=90),
        queried=True) for ip in ips}


def test_many_threatfox_hits_stay_one_signal_at_a_flat_weight():
    """The claim _threatfox_signal's docstring makes, and nothing pinned:
    fifty contacted IPs in one botnet's C2 pool is ONE fact stated fifty
    times. Letting the weight multiply would score +750 and out-vote the
    engine consensus by itself; splitting it into fifty signals would bury
    every other line of the verdict rationale.

    Compared against W_THREATFOX rather than a literal on purpose -- the
    mutation this kills changes the EXPRESSION (`* len(hits)`), not the
    constant, so reading the constant here pins the arithmetic without
    freezing a weight the module says to tune in one place.
    """
    from hash_searcher.scoring import W_THREATFOX, score

    report = _report()
    report.threatfox_ips = _threatfox_hits(*(f"198.51.100.{n}" for n in range(50)))

    verdict = score(report)
    fired = [s for s in verdict.signals if s.name == "threatfox"]
    assert len(fired) == 1, "fifty hits, one signal"
    assert fired[0].points == W_THREATFOX
    assert verdict.score == W_THREATFOX, "it is the only signal firing here"


def test_the_threatfox_detail_names_several_targets_not_just_the_first():
    """The sample AND the contacted IPs -- the "or on both" case the
    docstring claims and no test built. Every hit up to the cap is named:
    an analyst who cannot see WHICH address was attributed cannot pivot."""
    from hash_searcher.models import SourceResult, ThreatFoxReport
    from hash_searcher.scoring import score

    report = _report()
    report.threatfox = SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet", confidence=90),
        queried=True)
    report.threatfox_ips = _threatfox_hits("198.51.100.10", "203.0.113.7")

    detail = next(s for s in score(report).signals if s.name == "threatfox").detail
    assert "this indicator" in detail
    assert "198.51.100.10" in detail
    assert "203.0.113.7" in detail
    assert detail.count("; ") == 2, "three targets, joined"


def test_a_long_threatfox_target_list_is_capped_with_the_total_kept():
    """This detail lands in a reportlab table cell whose row cannot split
    across pages, so an unbounded join here is a crash in the filed PDF --
    rule 2 of render/pdf.py's module docstring. Capped at an item boundary
    with the TOTAL stated, the way tag_text and _cve_cell already do.
    """
    from hash_searcher.scoring import THREATFOX_TARGET_LIMIT, score

    ips = [f"198.51.100.{n}" for n in range(50)]
    report = _report()
    report.threatfox_ips = _threatfox_hits(*ips)

    detail = next(s for s in score(report).signals if s.name == "threatfox").detail
    assert ips[THREATFOX_TARGET_LIMIT - 1] in detail
    assert ips[THREATFOX_TARGET_LIMIT] not in detail
    assert f"50 targets (showing {THREATFOX_TARGET_LIMIT})" in detail
    # A hardcoded ceiling, not one derived from the constant under test.
    # What it keeps this string clear of is not one number: the cell
    # overflows by rendered HEIGHT, and the 624pt that crosses the frame is
    # 740 characters of ("W" * 13 + " "), 1678 of ", ".join CVE ids and 2669
    # of lowercase prose. render/pdf.py's _fitted measures that height; this
    # cap is what keeps its mid-string truncation from being the ordinary
    # rendering path for a threatfox detail.
    assert len(detail) < 1000


# ---------------------------------------------------------------------------
# Every signal detail that joins a provider list is capped HERE, at the
# source, not at the table cell that renders it.
#
# render/pdf.py's DETAIL_CHAR_LIMIT is a backstop: it truncates mid-string
# and says so, which is the right thing to do for an input nobody
# anticipated and the wrong thing to do for the ordinary case. A KEV detail
# for one busy host crosses it today -- the documented realistic figure is
# 120-137 CVEs, and 80 is enough -- so the analyst reads a mid-identifier
# fragment ("...CVE-2021-00070, CVE ... (truncated at 1200 of 2251
# characters)") on input the tool sees every day. A last-resort fallback
# that fires on ordinary input is no longer a signal that anything is wrong.
#
# The ceilings below are hardcoded rather than derived from the constant
# under test. A ceiling computed from the symbol it is bounding is not a
# bound: widening the constant would recompute the expectation and stay
# green.
# ---------------------------------------------------------------------------

def _kev_at_the_provider_maximum():
    """KEV at the largest result the puller can actually produce.

    known_exploited() caps nothing; it intersects the CVEs Shodan reported
    across every contacted IP against the catalog. That is IOC_LIMIT hosts
    at the documented realistic 137 CVEs each.
    """
    from hash_searcher.api.api_data_puller import IOC_LIMIT
    from hash_searcher.models import KEVEntry, KEVReport, SourceResult

    return SourceResult(value=KEVReport(entries=[
        KEVEntry(cve=f"CVE-2021-{n:05d}", vendor="Apache", product="HTTP Server",
                 name="Some Vulnerability", date_added="2022-03-03")
        for n in range(IOC_LIMIT * 137)]), queried=True)


def test_the_kev_detail_is_capped_at_the_source():
    """137 CVEs for one host is the figure _cve_cell's own docstring calls
    realistic, and 80 of them already overflow the PDF's detail budget.
    Uncapped, the reachable maximum is over a hundred thousand characters."""
    from hash_searcher.scoring import score

    report = _report()
    report.kev = _kev_at_the_provider_maximum()

    detail = next(s for s in score(report).signals if s.name == "kev").detail
    assert len(detail) < 400, f"kev detail is {len(detail)} characters"
    assert "CVE-2021-00000" in detail, "the named CVEs must still be named"
    assert "6850 CVEs" in detail, "the untruncated total, recoverable without arithmetic"
    assert "CVE-2021-06849" not in detail


def test_the_crowdsourced_yara_detail_is_capped_at_the_source():
    """analysis/vt.py's NAME_LIMIT reaches `names` and nothing else. VT
    returns hundreds of crowdsourced YARA results and _yara caps none."""
    from hash_searcher.scoring import score

    rules = [f"APT_Cobalt_Strike_Beacon_x64_variant_{n}" for n in range(500)]
    report = _report(vt=VTReport(found=True,
                                 yara=[YaraMatch(rule=r) for r in rules]))

    detail = next(s for s in score(report).signals if s.name == "yara").detail
    assert len(detail) < 400, f"yara detail is {len(detail)} characters"
    assert rules[0] in detail
    assert "500 rules" in detail
    assert rules[-1] not in detail


def test_the_sandbox_detail_is_capped_at_the_source():
    """Same gap as the YARA one: _sandbox caps nothing either."""
    from hash_searcher.scoring import score

    names = [f"Zenbox Sandbox Cluster Node {n}" for n in range(200)]
    report = _report(vt=VTReport(found=True, sandbox=[
        SandboxVerdict(sandbox=n, category="malicious") for n in names]))

    detail = next(s for s in score(report).signals if s.name == "sandbox").detail
    assert len(detail) < 400, f"sandbox detail is {len(detail)} characters"
    assert names[0] in detail
    assert "200 sandboxes" in detail
    assert names[-1] not in detail


def test_the_local_yara_detail_is_capped_at_the_source():
    """Bounded only by how many rules the operator dropped in the rules
    directory -- which is to say, not bounded by this tool at all."""
    from hash_searcher.models import StaticReport, YaraHit
    from hash_searcher.scoring import score

    rules = [f"Local_Detection_Rule_For_Family_{n}" for n in range(300)]
    report = _report()
    report.static = StaticReport(path="x", size=1, sha256="a" * 64,
                                 yara=[YaraHit(rule=r) for r in rules])

    detail = next(s for s in score(report).signals if s.name == "yara_local").detail
    assert len(detail) < 400, f"yara_local detail is {len(detail)} characters"
    assert rules[0] in detail
    assert "300 rules" in detail
    assert rules[-1] not in detail


def test_a_capped_detail_states_the_total_never_the_remainder():
    """One convention across all five capped joins.

    _cve_cell says "137 CVEs (showing 12): ..." and tag_text says "150 tags
    (showing 8): ...". The threatfox detail used to say "-- and 46 more
    contacted IPs", the REMAINDER, which forces the reader to add two
    numbers to learn how many there were -- and which contradicted the
    comment above THREATFOX_TARGET_LIMIT claiming it stated the total.
    """
    from hash_searcher.models import SourceResult, ThreatFoxReport, YaraHit
    from hash_searcher.models import StaticReport
    from hash_searcher.scoring import score

    report = _report(vt=VTReport(
        found=True,
        yara=[YaraMatch(rule=f"Rule_{n}") for n in range(500)],
        sandbox=[SandboxVerdict(sandbox=f"Box{n}", category="malicious")
                 for n in range(200)]))
    report.kev = _kev_at_the_provider_maximum()
    report.static = StaticReport(path="x", size=1, sha256="a" * 64,
                                 yara=[YaraHit(rule=f"Local_{n}") for n in range(300)])
    report.threatfox_ips = _threatfox_hits(*(f"198.51.100.{n}" for n in range(50)))

    capped = {s.name: s.detail for s in score(report).signals}
    assert {"kev", "yara", "sandbox", "yara_local", "threatfox"} <= set(capped)
    for name, detail in capped.items():
        if name not in {"kev", "yara", "sandbox", "yara_local", "threatfox"}:
            continue
        assert "(showing " in detail, f"{name} does not state what it showed"
        assert " more " not in detail, (
            f"{name} states a remainder; the convention is the total")


def test_a_capped_list_of_six_does_not_read_as_one_more():
    """The remainder convention produced "-- and 1 more contacted IPs" at
    exactly six hits. Stating the total instead makes the plural bug
    unreachable: the count is only printed when it exceeds the cap, so it
    is never one."""
    from hash_searcher.scoring import THREATFOX_TARGET_LIMIT, score

    report = _report()
    report.threatfox_ips = _threatfox_hits(
        *(f"198.51.100.{n}" for n in range(THREATFOX_TARGET_LIMIT + 1)))

    detail = next(s for s in score(report).signals if s.name == "threatfox").detail
    assert "1 more contacted IPs" not in detail
    assert "6 targets" in detail


def test_the_pdf_backstop_never_fires_on_input_the_puller_can_produce():
    """The point of capping at the source.

    DETAIL_CHAR_LIMIT truncates mid-identifier and labels itself the blunt
    last resort. With every join capped upstream it stays a last resort:
    drive every joined signal to its reachable provider maximum at once and
    no detail comes near it. The ceiling is hardcoded -- deriving it from
    DETAIL_CHAR_LIMIT would let a widened backstop excuse an uncapped
    source.
    """
    from hash_searcher.models import SourceResult, GreyNoiseReport
    from hash_searcher.models import StaticReport, YaraHit
    from hash_searcher.api.api_data_puller import IOC_LIMIT
    from hash_searcher.scoring import score

    report = _report(vt=VTReport(
        found=True,
        yara=[YaraMatch(rule=f"APT_Cobalt_Strike_Beacon_x64_variant_{n}")
              for n in range(500)],
        sandbox=[SandboxVerdict(sandbox=f"Zenbox Cluster Node {n}",
                                category="malicious") for n in range(200)]))
    report.kev = _kev_at_the_provider_maximum()
    report.static = StaticReport(path="x", size=1, sha256="a" * 64,
                                 yara=[YaraHit(rule=f"Local_Detection_Rule_{n}")
                                       for n in range(300)])
    ips = [f"198.51.100.{n}" for n in range(IOC_LIMIT)]
    report.threatfox_ips = _threatfox_hits(*ips)
    report.greynoise = {ip: SourceResult(value=GreyNoiseReport(
        seen=True, classification="benign", name="Shodan Scanner"), queried=True)
        for ip in ips}

    # 1000, hardcoded and below DETAIL_CHAR_LIMIT, so this test proves the
    # backstop stays unreached. The largest detail here is internet_noise at
    # 808 characters, and it is the one join deliberately left uncapped: it
    # is bounded by IOC_LIMIT rather than by a display cap. That bound is a
    # puller tuning constant, not a display decision, so if IOC_LIMIT is ever
    # raised this assertion is what says so.
    for signal in score(report).signals:
        assert len(signal.detail) < 1000, (
            f"{signal.name} reaches {len(signal.detail)} characters, so the "
            f"blunt backstop is this signal's ordinary rendering path")


def test_one_over_long_item_is_truncated_at_the_source_too():
    """_capped_join bounded how MANY items a detail names and never how long
    one item may be, so eight items -- exactly DETAIL_ITEM_LIMIT, the count
    cap doing its job -- still produced a 3409-character detail from a
    provider that returned 400-character rule names, and that detail raised
    LayoutError out of a real write_pdf.

    render/pdf.py fits the cell by measured height and so cannot crash on
    it, but that fit truncates mid-string: it is the last resort, and a
    provider string nobody sanitised must not be what routinely triggers
    it. Capping the ITEM here keeps every one of the eight names on the
    page, each stating its own true length, instead of one name and a
    fragment.
    """
    from hash_searcher.scoring import ITEM_CHAR_LIMIT, score

    rules = [f"{'W' * 13 + ' ' * 1}" * 30 + f"_{n}" for n in range(8)]
    assert len(rules[0]) > 400 and len(rules) == 8
    report = _report(vt=VTReport(found=True,
                                 yara=[YaraMatch(rule=r) for r in rules]))

    detail = next(s for s in score(report).signals if s.name == "yara").detail
    # Hardcoded, not derived from ITEM_CHAR_LIMIT: a ceiling computed from
    # the constant it bounds moves when the constant moves and pins nothing.
    assert len(detail) < 900, f"yara detail is {len(detail)} characters"
    for rule in rules:
        assert rule[:ITEM_CHAR_LIMIT] in detail, "every named rule is still named"
        assert rule not in detail, "and none of them is named in full"
    assert f"of {len(rules[0])} chars" in detail, (
        "a shortened item must state its own untruncated length")


def test_a_provider_string_of_ordinary_length_is_not_touched():
    """The item cap must be invisible for every name real input produces.
    The longest rule name in this suite's own fixtures is 39 characters
    ("APT_Cobalt_Strike_Beacon_x64_variant_NN"); provider YARA and sandbox
    names run to about forty. A cap that shortens those would be a bug, not
    a bound."""
    from hash_searcher.scoring import score

    rules = [f"APT_Cobalt_Strike_Beacon_x64_variant_{n}" for n in range(3)]
    report = _report(vt=VTReport(found=True,
                                 yara=[YaraMatch(rule=r) for r in rules]))

    detail = next(s for s in score(report).signals if s.name == "yara").detail
    assert detail == "crowdsourced YARA matched: " + ", ".join(rules)


def test_the_threatfox_item_cap_is_measured_against_the_provider_string():
    """ITEM_CHAR_LIMIT bounds how long ONE PROVIDER string may be. At four of
    its five call sites the item IS the provider string; at this one it is a
    whole clause this module composed, and most of the budget went on our
    own scaffolding.

    "the contacted IP " plus a max-length IPv4 plus " (100% confidence)" is
    51 characters of text nobody outside this repo wrote, leaving a malware
    family 29 of the 80. `"the contacted IP 198.51.100.10 "
    "Trojan.Win32.Emotet.Downloader (95% confidence)"` is 78 characters --
    two short of firing on an entirely ordinary answer, at which point the
    analyst reads a family name cut mid-word and a lost confidence figure.

    Each provider substring is measured on its own now, so the composed
    clause may exceed 80 while neither thing ThreatFox actually said does.
    """
    from hash_searcher.models import SourceResult, ThreatFoxReport
    from hash_searcher.scoring import ITEM_CHAR_LIMIT

    family = "Trojan.Win32.Emotet.Downloader.Gen.Variant.B"   # 44 chars, real shape
    assert len(family) <= ITEM_CHAR_LIMIT, "the provider string is not the long thing"

    report = _report(vt=VTReport(found=True))
    report.threatfox_ips = {"198.51.100.10": SourceResult(
        value=ThreatFoxReport(found=True, malware=family, confidence=95),
        queried=True)}

    detail = next(s for s in score(report).signals if s.name == "threatfox").detail
    assert family in detail, (
        "the family name ThreatFox returned is 44 characters and must "
        "survive whole")
    assert "(95% confidence)" in detail, (
        "the confidence figure is the tail the composed-item cap ate")
    assert "chars)" not in detail, "nothing here was long enough to truncate"


def test_an_unbounded_threatfox_target_is_still_capped():
    """Dropping the cap on the composed clause must not drop it on the parts.

    The keys of `threatfox_ips` are provider-supplied too, and nothing on
    their path checks that they look like IPs: api/api_data_puller.py keys
    the dict with `dict(zip(ips, threatfox_ip_results))`, where `ips` is
    `_merge_indicators(contacted_ips(vt_data), extra_ips)` -- VT's
    contacted_ips relationship plus the IP-shaped strings the static pass
    harvested out of the sample -- and cli.py rebuilds report.threatfox_ips
    from `raw["threatfox_ips"]`, those same keys. So the address half of the
    clause gets its own budget rather than none.
    """
    from hash_searcher.models import SourceResult, ThreatFoxReport
    from hash_searcher.scoring import ITEM_CHAR_LIMIT

    report = _report(vt=VTReport(found=True))
    report.threatfox_ips = {"9" * 4000: SourceResult(
        value=ThreatFoxReport(found=True, malware="E" * 4000, confidence=90),
        queried=True)}

    detail = next(s for s in score(report).signals if s.name == "threatfox").detail
    assert "9" * (ITEM_CHAR_LIMIT + 1) not in detail
    assert "E" * (ITEM_CHAR_LIMIT + 1) not in detail
    # A hardcoded ceiling, not one computed from the limits it checks: two
    # capped substrings, their two "(N of M chars)" suffixes, and this
    # module's own wording cannot reach a quarter of DETAIL_CHAR_LIMIT.
    assert len(detail) < 300


def test_a_provider_supplied_number_in_a_detail_is_bounded_too():
    """A confidence figure was bounded by accident, and then it was not.

    Before each provider substring got its own budget, _capped_join measured
    the whole composed clause -- "the contacted IP X Y (N% confidence)" --
    against ITEM_CHAR_LIMIT, which bounded the confidence figure inside it
    incidentally. Capping the substrings and telling the join to stop
    measuring the clause (cap_items=False) was the right fix, and it dropped
    that incidental bound without anyone noticing: analysis/threatfox.py
    only isinstance-checks `confidence_level`, and json.loads yields
    arbitrary-precision ints, so `{value.confidence}%` was a provider value
    interpolated into a detail with no bound anywhere.

    The PDF cannot crash on it -- DETAIL_CHAR_LIMIT and render/pdf.py's
    height fit are a layer below and bound the cell either way. But "a
    substring that used to be bounded incidentally and now is not" is this
    failure class's exact signature, and the TTY and the JSON report have no
    such backstop.

    All three provider numbers a detail names are checked, not just the one
    that regressed: AbuseIPDB's `abuseConfidenceScore` and OTX's pulse
    `count` are taken off their payloads with no more validation than
    ThreatFox's figure. Fixing the reported site and leaving its siblings is
    the exact move five rounds of this failure have already made.
    """
    from hash_searcher.models import (
        OTXReport, IPReport, SourceResult, ThreatFoxReport,
    )
    from hash_searcher.scoring import ITEM_CHAR_LIMIT, score

    huge = int("9" * 4000)
    assert len(str(huge)) == 4000, "json.loads has no integer width limit"

    report = _report(
        otx=OTXReport(recorded_instances=huge, has_pulses=True,
                      otx_responded=True),
        ips={"198.51.100.10": IPReport(ip="198.51.100.10", confidence=huge,
                                       reports=1)})
    report.threatfox_ips = {"198.51.100.10": SourceResult(
        value=ThreatFoxReport(found=True, malware="RedLine Stealer",
                              confidence=huge),
        queried=True)}

    details = {s.name: s.detail for s in score(report).signals}
    assert {"threatfox", "abuseipdb", "otx"} <= set(details), (
        f"the fixture must reach every signal that names a number; got "
        f"{sorted(details)}")

    for name in ("threatfox", "abuseipdb", "otx"):
        detail = details[name]
        assert "9" * (ITEM_CHAR_LIMIT + 1) not in detail, (
            f"the {name} detail carries an unbounded provider number")
        assert f"of {len(str(huge))} chars" in detail, (
            f"the {name} detail shortened a number without saying so")
        # A hardcoded ceiling, not one computed from the limits it checks:
        # one capped number, its "(N of M chars)" suffix, and this module's
        # own wording cannot reach a quarter of DETAIL_CHAR_LIMIT.
        assert len(detail) < 300, (
            f"the {name} detail is {len(detail)} characters")


def test_a_number_of_ordinary_size_is_printed_exactly():
    """The bound above must be invisible for every figure real input
    produces. A confidence score is 0-100 and a pulse count is a handful of
    digits; a cap that touched those would be a bug, not a bound."""
    from hash_searcher.models import (
        OTXReport, IPReport, SourceResult, ThreatFoxReport,
    )
    from hash_searcher.scoring import score

    report = _report(
        otx=OTXReport(recorded_instances=7, has_pulses=True, otx_responded=True),
        ips={"198.51.100.10": IPReport(ip="198.51.100.10", confidence=90,
                                       reports=1)})
    report.threatfox_ips = {"198.51.100.10": SourceResult(
        value=ThreatFoxReport(found=True, malware="RedLine Stealer",
                              confidence=95),
        queried=True)}

    details = {s.name: s.detail for s in score(report).signals}
    assert details["otx"] == ("OTX pulses reference this indicator "
                              "(7 recorded instances)")
    assert details["abuseipdb"] == "a contacted IP has 90% AbuseIPDB confidence"
    assert details["threatfox"] == ("ThreatFox names the contacted IP "
                                    "198.51.100.10 RedLine Stealer "
                                    "(95% confidence)")
