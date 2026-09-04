from ioc_inquest.render.tty import (
    RULE, VT_UNAVAILABLE_NOTE, render, render_hosts, render_ip_intel, render_ips, render_otx,
    render_vt, render_whois,
)
from ioc_inquest.models import (
    AttackTechnique, CensysHost, IPReport, OTXReport, PEInfo, Report, SandboxVerdict,
    SigmaRule, Signature, SourceResult, Submission, ThreatClass, VTReport, WhoisRecord, YaraMatch,
)


def test_render_emits_every_section(capsys, sample_report):
    render(sample_report)
    out = capsys.readouterr().out
    for heading in ("VIRUSTOTAL SIGMA RULES", "HIGH PRIORITY RULES",
                    "CENSYS ENRICHMENT", "WHOIS DATA", "OTX DATA"):
        assert heading in out


def test_render_shows_values_not_object_reprs(capsys, sample_report):
    render(sample_report)
    out = capsys.readouterr().out
    assert "198.51.100.10" in out
    assert "90%" in out
    assert "80, 443" in out
    assert "IPReport(" not in out


def test_empty_rule_levels_say_so(capsys, sample_report):
    render(sample_report)
    out = capsys.readouterr().out
    assert "No Medium Priority Rules Found." in out
    assert "No Low Priority Rules Found." in out


def test_new_indicators_are_flagged(capsys, sample_report):
    render(sample_report)
    assert "[!] New indicators not found in AbuseIPDB:" in capsys.readouterr().out


def test_ip_intel_renders_silence_for_a_source_nobody_asked(capsys, sample_report):
    """A never-asked SourceResult (queried=False) must render as silence,
    not a crash. SourceResult has no __bool__, so every instance -- even a
    bare, never-asked one -- is truthy; a bug routed that truthiness into
    the success branch and dereferenced `.value` (None) instead of treating
    `queried=False` as nothing to report."""
    sample_report.shodan = {"198.51.100.10": SourceResult()}
    sample_report.greynoise = {"198.51.100.10": SourceResult()}

    render_ip_intel(sample_report)

    out = capsys.readouterr().out
    assert "Ports:" not in out
    assert "CVEs:" not in out
    assert "Names:" not in out
    assert "GreyNoise:" not in out


def test_render_ips_exact_formatting(capsys):
    """Assert exact column alignment and separator in IP report table."""
    report = Report(
        indicator="test",
        generated_at="2026-08-23",
        vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"),
        ips={"198.51.100.10": IPReport(ip="198.51.100.10", confidence=90, reports=2)},
        hosts=[],
        whois=[],
    )
    render_ips(report)
    out = capsys.readouterr().out
    expected = (
        "\n==================================================\n"
        "IP               CONFIDENCE   REPORTS   \n"
        "----------------------------------------\n"
        "198.51.100.10    90%          2         \n"
        "----------------------------------------\n"
    )
    assert out == expected


def test_render_whois_exact_formatting(capsys):
    """Assert exact column alignment and separator in WHOIS table.

    The separator is 92 as of R13: the header pads to
    35 + 1 + 12 + 1 + 12 + 1 + 30 == 92, and the 89 pinned here through
    Phase 1 was a faithful port of formatters.py:183-184's defect.
    """
    report = Report(
        indicator="test",
        generated_at="2026-08-23",
        vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"),
        ips={},
        hosts=[],
        whois=[
            WhoisRecord(
                domain="bad.example",
                created="2020-01-01",
                expires="2027-01-01",
                registrar="R",
            )
        ],
    )
    render_whois(report)
    out = capsys.readouterr().out
    expected = (
        "\n==================================================\n"
        "WHOIS DATA\n"
        "==================================================\n"
        "DOMAIN                              CREATED      EXPIRES      REGISTRAR                     \n"
        "--------------------------------------------------------------------------------------------\n"
        "bad.example                         2020-01-01   2027-01-01   R                             \n"
    )
    assert out == expected


def test_render_vt_exact_formatting_matches_pre_branch_bytes(capsys):
    """The pre-branch vt_rules() treated each priority level differently:
    HIGH descriptions carried a trailing space, MEDIUM did not, LOW printed
    bare title/description with no colon or period, and only HIGH and
    MEDIUM were followed by a blank line. Verified against a scratch run of
    the original formatters.py (git show 129ff8d) with the same input.
    """
    report = Report(
        indicator="test",
        generated_at="2026-08-23",
        vt=VTReport(found=True, sigma=[
            SigmaRule("Suspicious Process", "spawns cmd", "high"),
            SigmaRule("Odd Registry Write", "writes to Run key", "medium"),
            SigmaRule("Benign Marker", "harmless indicator", "low"),
        ]),
        otx=OTXReport(recorded_instances="N/A"),
        ips={},
        hosts=[],
        whois=[],
    )
    render_vt(report)
    out = capsys.readouterr().out
    expected = (
        "\nVIRUSTOTAL SIGMA RULES\n"
        "\n==================================================\n"
        "HIGH PRIORITY RULES\n"
        "==================================================\n"
        "Suspicious Process:\n"
        "spawns cmd. \n"
        "\n\n"
        "MEDIUM PRIORITY RULES\n"
        "==================================================\n"
        "Odd Registry Write:\n"
        "writes to Run key.\n"
        "\n\n"
        "LOW PRIORITY RULES\n"
        "==================================================\n"
        "Benign Marker\n"
        "harmless indicator\n"
    )
    assert out == expected


def test_render_vt_empty_levels_say_so_with_no_extra_blank_lines(capsys):
    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=True, sigma=[]),
        otx=OTXReport(recorded_instances="N/A"), ips={}, hosts=[], whois=[],
    )
    render_vt(report)
    out = capsys.readouterr().out
    expected = (
        "\nVIRUSTOTAL SIGMA RULES\n"
        "\n==================================================\n"
        "HIGH PRIORITY RULES\n"
        "==================================================\n"
        "No High Priority Rules Found.\n"
        "\n\n"
        "MEDIUM PRIORITY RULES\n"
        "==================================================\n"
        "No Medium Priority Rules Found.\n"
        "\n\n"
        "LOW PRIORITY RULES\n"
        "==================================================\n"
        "No Low Priority Rules Found.\n"
    )
    assert out == expected


def test_render_hosts_exact_formatting(capsys):
    """Assert exact formatting for both the new-hostnames and no-new-hostnames
    branches of the Censys enrichment section."""
    report = Report(
        indicator="test",
        generated_at="2026-08-23",
        vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"),
        ips={},
        hosts=[
            CensysHost(ip="198.51.100.10", org="Example AS", asn=64496,
                       country="NL", ports=[80, 443], new_hostnames=["new.example"]),
            CensysHost(ip="203.0.113.20", org=None, asn=None,
                       country="N/A", ports=[], new_hostnames=[]),
        ],
        whois=[],
    )
    render_hosts(report)
    out = capsys.readouterr().out
    expected = (
        "\n==================================================\n"
        "CENSYS ENRICHMENT\n"
        "==================================================\n"
        "\nIP:      198.51.100.10\n"
        "Org:     Example AS  |  ASN: 64496\n"
        "Country: NL\n"
        "Ports:   80, 443\n"
        "[!] New indicators not found in AbuseIPDB:\n"
        "    Hostnames: new.example\n"
        "\nIP:      203.0.113.20\n"
        "Org:     None  |  ASN: None\n"
        "Country: N/A\n"
        "Ports:   N/A\n"
        "    No new indicators beyond AbuseIPDB data.\n"
    )
    assert out == expected


def test_render_otx_exact_formatting_with_data(capsys):
    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances=7, attack_techniques=["T1059 Command"],
                      otx_responded=True),
        ips={}, hosts=[], whois=[],
    )
    render_otx(report)
    out = capsys.readouterr().out
    expected = (
        "\n==================================================\n"
        "OTX DATA\n"
        "==================================================\n"
        "Recorded instances: 7\n"
        "T1059 Command\n"
    )
    assert out == expected


def test_render_otx_matches_original_message_when_no_pulse_info(capsys):
    """A 200 response with no `pulse_info` at all (recorded_instances stays
    the bare 'N/A' extract_otx sets in that branch) printed 'No OTX data
    available.' in the original -- not a bare 'Recorded instances: N/A'."""
    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"),
        ips={}, hosts=[], whois=[],
    )
    render_otx(report)
    out = capsys.readouterr().out
    expected = (
        "\n==================================================\n"
        "OTX DATA\n"
        "==================================================\n"
        "No OTX data available.\n"
    )
    assert out == expected


def test_render_otx_pulse_info_present_but_no_count(capsys):
    """pulse_info present but lacking a `count` key: the original printed
    the recorded-instances line AND folded 'No recorded instances' into it
    via the fallback string, not a bare 'N/A'."""
    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A, No recorded instances",
                      otx_responded=True),
        ips={}, hosts=[], whois=[],
    )
    render_otx(report)
    out = capsys.readouterr().out
    expected = (
        "\n==================================================\n"
        "OTX DATA\n"
        "==================================================\n"
        "Recorded instances: N/A, No recorded instances\n"
    )
    assert out == expected


def test_a_failed_otx_lookup_says_so_instead_of_reading_as_no_data(capsys):
    """The assertion this suite could not make until now.

    A failed OTX lookup printed "No OTX data available." -- byte-identical
    to a lookup that was never made, and a claim about OTX rather than
    about this tool. Every other source in this renderer already said
    which: `Censys: <error>`, `MalwareBazaar: <error>`, `crt.sh: <error>`.
    OTX was the last asymmetry, and the two states are asserted here
    against each other rather than each against a literal, because being
    DIFFERENT is the property that was missing.
    """
    def rendered(otx):
        report = Report(
            indicator="test", generated_at="x", vt=VTReport(found=False),
            otx=otx, ips={}, hosts=[], whois=[],
        )
        render_otx(report)
        return capsys.readouterr().out

    header = ("\n==================================================\n"
              "OTX DATA\n"
              "==================================================\n")

    failed = rendered(OTXReport(recorded_instances="N/A",
                                error="OTX key not set"))
    never_asked = rendered(OTXReport(recorded_instances="N/A"))
    answered = rendered(OTXReport(recorded_instances=4, otx_responded=True,
                                  attack_techniques=["Process Injection"]))

    assert failed == header + "OTX: OTX key not set\n"
    assert never_asked == header + "No OTX data available.\n"
    assert answered == header + "Recorded instances: 4\nProcess Injection\n"
    assert failed != never_asked


def test_render_gates_ip_censys_whois_sections_on_vt_contacted_ips(capsys):
    """B1: the gate belongs on VT's contacted-IP list. AbuseIPDB yielding
    nothing (report.ips == {}) must not hide Censys/WHOIS data that VT's
    contacted IPs triggered."""
    report = Report(
        indicator="test",
        generated_at="x",
        vt=VTReport(found=True, contacted_ips=["198.51.100.10"]),
        otx=OTXReport(recorded_instances="N/A"),
        ips={},
        hosts=[CensysHost(ip="198.51.100.10")],
        whois=[WhoisRecord(domain="bad.example")],
    )
    render(report)
    out = capsys.readouterr().out
    assert "CENSYS ENRICHMENT" in out
    assert "WHOIS DATA" in out


def test_render_skips_ip_sections_when_vt_reported_no_contacted_ips(capsys):
    """The original never printed a bare CENSYS ENRICHMENT header when VT
    returned no IPs at all -- the gate must stay a single all-or-nothing
    check, not three independent per-section gates."""
    report = Report(
        indicator="test",
        generated_at="x",
        vt=VTReport(found=True, contacted_ips=[]),
        otx=OTXReport(recorded_instances="N/A"),
        ips={},
        hosts=[],
        whois=[],
    )
    render(report)
    out = capsys.readouterr().out
    assert "CENSYS ENRICHMENT" not in out
    assert "WHOIS DATA" not in out


def test_render_otx_count_literally_na_is_not_mistaken_for_no_data(capsys):
    """A real pulse_info whose count is the string "N/A" must still print the
    recorded-instances line.

    render_otx used to branch on `recorded_instances == "N/A"`, overloading a
    value as a control signal. The original gated on `if not pulse_info:`
    (formatters.py:otx_formatter at 129ff8d), so this input printed
    "Recorded instances: N/A" there. Gating on otx_responded restores that.
    """
    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A", otx_responded=True),
        ips={}, hosts=[], whois=[],
    )
    render_otx(report)
    out = capsys.readouterr().out
    expected = (
        "\n==================================================\n"
        "OTX DATA\n"
        "==================================================\n"
        "Recorded instances: N/A\n"
    )
    assert out == expected


def test_verdict_section_leads_with_the_level_and_lists_every_signal(capsys, sample_report):
    from ioc_inquest.models import Signal, Verdict
    from ioc_inquest.render.tty import RULE, render_verdict

    verdict = Verdict(level="MALICIOUS", score=60, signals=[
        Signal("detection", 50, "48/72 engines flagged this file"),
        Signal("otx", 10, "OTX pulses reference this indicator (3 recorded instances)"),
    ])
    render_verdict(verdict)

    assert capsys.readouterr().out == (
        "\n" + RULE + "\n"
        "VERDICT: MALICIOUS (score 60)\n"
        + RULE + "\n"
        "  +50  detection   48/72 engines flagged this file\n"
        "  +10  otx         OTX pulses reference this indicator (3 recorded instances)\n"
    )


def test_a_verdict_with_no_signals_says_so(capsys, sample_report):
    from ioc_inquest.models import Verdict
    from ioc_inquest.render.tty import render_verdict

    render_verdict(Verdict(level="UNKNOWN", score=0, signals=[]))
    out = capsys.readouterr().out
    assert "VERDICT: UNKNOWN (score 0)" in out
    assert "No signals fired." in out


def test_a_negative_signal_prints_its_sign(capsys, sample_report):
    from ioc_inquest.models import Signal, Verdict
    from ioc_inquest.render.tty import render_verdict

    render_verdict(Verdict(level="CLEAN", score=-20, signals=[
        Signal("signed", -20, "valid signature from Contoso Ltd"),
    ]))
    assert "  -20  signed" in capsys.readouterr().out


def test_an_unreachable_virustotal_says_so_rather_than_implying_nobody_has_seen_it(capsys):
    """UNKNOWN means 'nothing has ever seen this'. A 503 supports no such
    claim, and a script branching on exit 3 deserves to know which it got."""
    from ioc_inquest.scoring import score

    report = _phase4_report(vt=VTReport(found=False, unavailable=True,
                                         error="GetTotal API Error 503"))
    render(report, score(report))
    out = capsys.readouterr().out
    # Pinned against the literal wording, not just re-derived from the same
    # live import -- VT_UNAVAILABLE_NOTE.format(...) alone would recompute
    # its expected value from the very constant under test, so deleting the
    # caveat's second clause would vanish from both sides at once and this
    # assertion would never notice.
    assert VT_UNAVAILABLE_NOTE == (
        "VirusTotal did not answer ({error}) -- this UNKNOWN is not "
        "confirmation that nobody has seen this sample."
    )
    assert f"Note: {VT_UNAVAILABLE_NOTE.format(error='GetTotal API Error 503')}" in out.splitlines()


def test_the_caveat_is_silent_once_the_verdict_no_longer_depends_on_vt(capsys):
    """unavailable alone must not print the caveat -- only unavailable AND
    UNKNOWN. Sample evidence (here, a MalwareBazaar hit) escapes the
    UNKNOWN guard on its own; once the verdict does not lean on VT's
    non-answer, the caveat has nothing left to qualify."""
    from ioc_inquest.models import BazaarReport, SourceResult
    from ioc_inquest.scoring import score

    report = _phase4_report(
        vt=VTReport(found=False, unavailable=True, error="GetTotal API Error 503"),
        bazaar=SourceResult(value=BazaarReport(found=True, family="Emotet"), queried=True),
    )
    verdict = score(report)
    assert verdict.level != "UNKNOWN"
    render(report, verdict)
    assert "VirusTotal did not answer" not in capsys.readouterr().out


def test_the_caveat_is_silent_for_a_genuine_404_at_unknown(capsys):
    """A 404 is VirusTotal's actual answer: no record of this sample. That
    is exactly the UNKNOWN case the caveat must stay silent for -- printing
    it here would cast doubt on the one answer VT actually gave."""
    from ioc_inquest.analysis.vt import extract_vt
    from ioc_inquest.api.base_call import make_error
    from ioc_inquest.scoring import score

    report = _phase4_report(vt=extract_vt(make_error("Hash not found in GetTotal", 404)))
    verdict = score(report)
    assert verdict.level == "UNKNOWN"
    render(report, verdict)
    assert "VirusTotal did not answer" not in capsys.readouterr().out


def test_detection_section_prints_the_ratio(capsys, sample_report):
    from ioc_inquest.models import Detection
    from ioc_inquest.render.tty import render_detection

    sample_report.vt.detection = Detection(malicious=48, suspicious=0, undetected=24)
    render_detection(sample_report)
    assert capsys.readouterr().out == (
        "\nDetections: 48/72  (suspicious 0, undetected 24)\n"
    )


def test_detection_section_is_silent_without_stats(capsys, sample_report):
    from ioc_inquest.render.tty import render_detection

    sample_report.vt.detection = None
    render_detection(sample_report)
    assert capsys.readouterr().out == ""


def test_contacted_domains_exact_formatting(capsys, sample_report):
    """R14. This asserted `"CONTACTED DOMAINS" in out and "evil.example" in out`,
    which left the body format of a whole new section unpinned -- changing it
    to `- {domain}` kept the suite green."""
    from ioc_inquest.render.tty import render_domains

    sample_report.vt.contacted_domains = ["evil.example", "worse.example"]
    render_domains(sample_report)
    assert capsys.readouterr().out == (
        "\n" + RULE + "\n"
        "CONTACTED DOMAINS\n"
        + RULE + "\n"
        "evil.example\n"
        "worse.example\n"
    )


def test_render_domains_is_silent_when_vt_reported_none(capsys, sample_report):
    from ioc_inquest.render.tty import render_domains

    sample_report.vt.contacted_domains = []
    render_domains(sample_report)
    assert capsys.readouterr().out == ""


def test_render_attribution_exact_formatting(capsys, sample_report):
    """R14, and the largest gap the review found: seven output shapes and no
    test called this function at all. Its only exercise anywhere was
    `out.index("ATTRIBUTION")` in the ordering test, so rewriting the
    signature line to `SIG={state}` kept 189 tests green.
    """
    from ioc_inquest.render.tty import render_attribution

    vt = sample_report.vt
    vt.threat = ThreatClass(label="trojan.emotet", family="emotet",
                            categories=["trojan", "downloader"])
    vt.signature = Signature(verified=False, signer="Contoso Ltd")
    vt.sandbox = [SandboxVerdict(sandbox="Zenbox", category="malicious",
                                 malware_names=["Emotet"]),
                  SandboxVerdict(sandbox="Lastline", category="malicious")]
    vt.yara = [YaraMatch(rule="malw_emotet", author="Marc Rivero"),
               YaraMatch(rule="anonymous_rule")]
    vt.pe = PEInfo(sections=5, imphash="d41d8c", compiled="2024-01-02 03:04:05")
    vt.submission = Submission(times_submitted=12, first_seen="2024-01-01",
                               names=["invoice.exe", "setup.exe"])
    vt.techniques = [AttackTechnique(id="T1055", name="Process Injection",
                                     tactic="defense-evasion"),
                     AttackTechnique(id="T9999", name="Unmapped")]

    render_attribution(sample_report)
    assert capsys.readouterr().out == (
        "\n" + RULE + "\n"
        "ATTRIBUTION\n"
        + RULE + "\n"
        "Label:      trojan.emotet\n"
        "Family:     emotet\n"
        "Categories: trojan, downloader\n"
        "Signature:  present but NOT verified (Contoso Ltd)\n"
        "Sandbox:    Zenbox says malicious -- Emotet\n"
        "Sandbox:    Lastline says malicious\n"
        "YARA:       malw_emotet (Marc Rivero)\n"
        "YARA:       anonymous_rule (unknown author)\n"
        "PE:         5 sections, imphash d41d8c, compiled 2024-01-02 03:04:05\n"
        "Submitted:  12 times, first seen 2024-01-01\n"
        "Names:      invoice.exe, setup.exe\n"
        "ATT&CK:     T1055 Process Injection (defense-evasion)\n"
        "ATT&CK:     T9999 Unmapped\n"
    )


def test_render_attribution_is_silent_when_vt_returned_none_of_it(capsys, sample_report):
    """The gate at the top of the section. sample_report carries sigma rules
    and contacted IPs but no attribution fields, which is the common case for
    a file VT has seen and nothing has classified."""
    from ioc_inquest.render.tty import render_attribution

    render_attribution(sample_report)
    assert capsys.readouterr().out == ""


def test_a_verified_signature_reads_differently_from_an_unverified_one(capsys, sample_report):
    """VT's signature_info.verified is prose and every value of it is truthy;
    the extractor compares against the one string that means verified. Pin
    both renderings so the distinction cannot collapse."""
    from ioc_inquest.render.tty import render_attribution

    sample_report.vt.signature = Signature(verified=True, signer=None)
    render_attribution(sample_report)
    assert "Signature:  verified (unnamed signer)\n" in capsys.readouterr().out


def test_render_emits_the_new_sections_in_a_pinned_order(capsys, sample_report):
    """The per-section exact-output tests pin each section's bytes, but
    nothing pinned the ORDER render() prints them in -- so Task 7's
    reordering could have drifted silently. Verdict leads, static analysis
    (Task 8) sits directly under it and ahead of everything network-derived,
    the detection ratio sits above the sigma rules it summarizes, attribution
    follows the rules, and contacted domains land with the other network
    indicators rather than after OTX.
    """
    from ioc_inquest.models import Detection, Signal, StaticReport, ThreatClass, Verdict
    from ioc_inquest.render.tty import render

    sample_report.vt.detection = Detection(malicious=48, undetected=24)
    sample_report.vt.threat = ThreatClass(label="trojan.emotet", family="emotet")
    sample_report.vt.contacted_domains = ["evil.example"]
    sample_report.static = StaticReport(path="x", size=1, sha256="a" * 64)
    render(sample_report, Verdict(level="MALICIOUS", score=50,
                                  signals=[Signal("detection", 50, "48/72 engines flagged this file")]))

    out = capsys.readouterr().out
    markers = [
        "VERDICT: MALICIOUS (score 50)",
        "STATIC ANALYSIS",
        "Detections: 48/72",
        "VIRUSTOTAL SIGMA RULES",
        "ATTRIBUTION",
        "CENSYS ENRICHMENT",
        "WHOIS DATA",
        "CONTACTED DOMAINS",
        "OTX DATA",
    ]
    positions = [out.index(marker) for marker in markers]
    assert positions == sorted(positions), (
        f"sections drifted out of order: "
        f"{[m for _, m in sorted(zip(positions, markers))]}"
    )


def test_render_without_a_verdict_prints_no_verdict_section(capsys, sample_report):
    """render(report) keeps working for every pre-Phase-2 call site."""
    from ioc_inquest.render.tty import render

    render(sample_report)
    assert "VERDICT:" not in capsys.readouterr().out


# --- Phase 3: render_static --------------------------------------------------


def test_render_static_is_silent_when_no_static_report(capsys, sample_report):
    """sample_report.static defaults to None -- render() keeps working for
    every pre-Phase-3 call site, the same guarantee Phase 2 gave render()
    without a verdict."""
    from ioc_inquest.render.tty import render_static

    render_static(sample_report)
    assert capsys.readouterr().out == ""


def test_render_static_exact_formatting(capsys):
    from ioc_inquest.models import (
        EntropyReport, FileTypeReport, IOCSet, PEStaticReport, PESection,
        StaticReport, StringsReport, YaraHit,
    )
    from ioc_inquest.render.tty import render_static

    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"), ips={}, hosts=[], whois=[],
        static=StaticReport(
            path="/tmp/sample.exe", size=2048, sha256="a" * 64,
            entropy=EntropyReport(
                overall=7.91, packed=True,
                note="high entropy: compressed or encrypted, commonly a packer"),
            filetype=FileTypeReport(
                detected="PE", extension=".txt", mismatch=True,
                note="content looks like PE but the name says '.txt'"),
            pe=PEStaticReport(
                imports={"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory"]},
                sections=[PESection(name=".text", size=512, entropy=6.5, executable=True)],
                compiled="2024-01-02",
                suspicious_imports=["VirtualAllocEx", "WriteProcessMemory",
                                    "CreateRemoteThread"],
            ),
            yara=[YaraHit(rule="Emotet_Loader", namespace="default", tags=["trojan"])],
            strings=StringsReport(
                count=42,
                iocs=IOCSet(ips=["203.0.113.7"], domains=["evil.example"], urls=[])),
            skipped=["magic"],
            failed=["yara"],
        ),
    )
    render_static(report)
    out = capsys.readouterr().out
    assert out == (
        "\n" + RULE + "\n"
        "STATIC ANALYSIS\n"
        + RULE + "\n"
        "File:   /tmp/sample.exe (2048 bytes)\n"
        "SHA256: " + "a" * 64 + "\n"
        "Entropy: 7.91 (packed) -- high entropy: compressed or encrypted, "
        "commonly a packer\n"
        "File type: PE -- content looks like PE but the name says '.txt'\n"
        "PE: 1 sections, 2 imports, compiled 2024-01-02\n"
        "Suspicious imports: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread\n"
        "YARA:   Emotet_Loader (default)\n"
        "Strings: 42 extracted, 1 IPs, 1 domains, 0 URLs\n"
        "Skipped: magic\n"
        "Failed:  yara\n"
    )


def test_render_static_prints_none_for_empty_skipped_and_failed(capsys):
    """Skipped and failed must be printed by name -- a silently missing
    section is indistinguishable from a clean result. When both are empty
    that must still be said explicitly, not left implicit by omission."""
    from ioc_inquest.models import StaticReport
    from ioc_inquest.render.tty import render_static

    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"), ips={}, hosts=[], whois=[],
        static=StaticReport(path="x", size=1, sha256="a" * 64),
    )
    render_static(report)
    out = capsys.readouterr().out
    assert "Skipped: none" in out
    assert "Failed:  none" in out


def test_render_static_names_what_was_skipped_and_failed(capsys):
    from ioc_inquest.models import StaticReport
    from ioc_inquest.render.tty import render_static

    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"), ips={}, hosts=[], whois=[],
        static=StaticReport(path="x", size=1, sha256="a" * 64,
                            skipped=["pefile", "yara"], failed=["strings"]),
    )
    render_static(report)
    out = capsys.readouterr().out
    assert "Skipped: pefile, yara" in out
    assert "Failed:  strings" in out


def test_render_static_prints_the_yara_truncation_note(capsys):
    """branch-review.md I5: a partial YARA scan must never look identical to
    a complete one that simply found nothing."""
    from ioc_inquest.models import StaticReport, YaraHit
    from ioc_inquest.render.tty import render_static

    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"), ips={}, hosts=[], whois=[],
        static=StaticReport(
            path="x", size=1, sha256="a" * 64,
            yara=[YaraHit(rule="Emotet_Loader")],
            yara_note="stopped after 200 of 500 rule files",
        ),
    )
    render_static(report)
    out = capsys.readouterr().out
    assert "YARA:   Emotet_Loader (default)\n" in out
    assert "YARA:   stopped after 200 of 500 rule files\n" in out


def test_render_hosts_prints_the_per_ip_error(capsys, sample_report):
    from ioc_inquest.models import CensysHost
    from ioc_inquest.render.tty import render_hosts

    sample_report.hosts = [CensysHost(ip="198.51.100.10", error="Censys 403: forbidden")]
    render_hosts(sample_report)
    assert "Censys 403: forbidden" in capsys.readouterr().out


def test_render_hosts_error_branch_exact_formatting(capsys, sample_report):
    from ioc_inquest.models import CensysHost
    from ioc_inquest.render.tty import RULE, render_hosts

    sample_report.hosts = [
        CensysHost(ip="198.51.100.10", error="Censys 403: forbidden"),
        CensysHost(ip="N/A", error="Rate limited"),
    ]
    render_hosts(sample_report)
    assert capsys.readouterr().out == (
        "\n" + RULE + "\n"
        "CENSYS ENRICHMENT\n"
        + RULE + "\n"
        "\nIP:      198.51.100.10\n"
        "Censys: Censys 403: forbidden\n"
        "\nIP:      N/A\n"
        "Censys: Rate limited\n"
    )


def test_render_ips_says_so_when_abuseipdb_returned_nothing(capsys, sample_report):
    """S3: 'No data from IPDB available.' -- an empty table looks like a bug."""
    from ioc_inquest.render.tty import render_ips

    sample_report.ips = {}
    render_ips(sample_report)
    assert "No data from IPDB available." in capsys.readouterr().out


def test_the_whois_separator_matches_the_header_width(capsys, sample_report):
    """R13: 35+1+12+1+12+1+30 == 92. The separator was 89 -- three short, a
    faithful port of a defect in formatters.py:183-184."""
    from ioc_inquest.render.tty import render_whois

    render_whois(sample_report)
    lines = capsys.readouterr().out.splitlines()
    header = next(line for line in lines if line.startswith("DOMAIN"))
    separator = lines[lines.index(header) + 1]
    assert len(separator) == 92
    assert separator == "-" * 92


def test_an_entry_dropped_for_a_missing_ip_leaves_no_blank_row(capsys):
    """Ledger, Task 4: the extractor drops an AbuseIPDB entry with no
    `ipAddress` where the pre-branch code printed a row of empty columns.
    That deviation was authorized but never pinned at the rendering layer --
    a blank row is worse than no row, because it reads as a real IP the tool
    failed to describe. Assert the exact bytes, not just the row count.
    """
    from ioc_inquest.analysis.ipdb import extract_ips

    report = Report(
        indicator="test",
        generated_at="2026-08-23",
        vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"),
        ips=extract_ips([
            {"data": {"ipAddress": "198.51.100.10", "abuseConfidenceScore": 90,
                      "reports": 2}},
            {"data": {"abuseConfidenceScore": 90, "reports": 2}},
        ]),
        hosts=[],
        whois=[],
    )
    render_ips(report)
    assert capsys.readouterr().out == (
        "\n==================================================\n"
        "IP               CONFIDENCE   REPORTS   \n"
        "----------------------------------------\n"
        "198.51.100.10    90%          2         \n"
        "----------------------------------------\n"
    )


def _phase4_report(**kwargs) -> Report:
    base = dict(
        indicator="a" * 64,
        generated_at="2026-08-25 00:00:00",
        vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"),
        ips={}, hosts=[], whois=[],
    )
    base.update(kwargs)
    return Report(**base)


def test_render_bazaar_exact_formatting(capsys):
    from ioc_inquest.models import BazaarReport, SourceResult
    from ioc_inquest.render.tty import render_bazaar

    render_bazaar(_phase4_report(bazaar=SourceResult(value=BazaarReport(
        found=True, family="Emotet", tags=["exe", "banker"], file_type="exe",
        first_seen="2019-04-02", yara=["Emotet_Loader"]), queried=True)))
    assert capsys.readouterr().out == (
        "\n==================================================\n"
        "MALWAREBAZAAR\n"
        "==================================================\n"
        "Family:     Emotet\n"
        "File type:  exe\n"
        "First seen: 2019-04-02\n"
        "Tags:       exe, banker\n"
        "YARA:       Emotet_Loader\n"
    )


def test_a_sample_bazaar_has_never_seen_says_so_rather_than_going_silent(capsys):
    """A missing section reads as a bug. 'abuse.ch has never seen this' is
    an answer, and a different one from 'we could not ask abuse.ch'."""
    from ioc_inquest.models import BazaarReport, SourceResult
    from ioc_inquest.render.tty import render_bazaar

    render_bazaar(_phase4_report(
        bazaar=SourceResult(value=BazaarReport(found=False), queried=True)))
    out = capsys.readouterr().out
    assert "MalwareBazaar has no record of this sample." in out

    render_bazaar(_phase4_report(bazaar=SourceResult(error="500", queried=True)))
    assert "MalwareBazaar: 500" in capsys.readouterr().out


def test_render_ip_intel_shows_ports_cves_and_noise(capsys):
    from ioc_inquest.models import GreyNoiseReport, ShodanReport, SourceResult
    from ioc_inquest.render.tty import render_ip_intel

    render_ip_intel(_phase4_report(
        shodan={"198.51.100.10": SourceResult(value=ShodanReport(
            ports=[22, 443], vulns=["CVE-2021-41617"]), queried=True)},
        greynoise={"198.51.100.10": SourceResult(value=GreyNoiseReport(
            seen=True, classification="malicious", name="Mirai"), queried=True)},
    ))
    out = capsys.readouterr().out
    assert "198.51.100.10" in out
    assert "22, 443" in out
    assert "CVE-2021-41617" in out
    assert "malicious" in out and "Mirai" in out


def test_kev_entries_are_rendered_with_the_product(capsys):
    from ioc_inquest.models import KEVEntry, KEVReport, SourceResult
    from ioc_inquest.render.tty import render_kev

    render_kev(_phase4_report(kev=SourceResult(value=KEVReport(entries=[KEVEntry(
        cve="CVE-2021-41617", vendor="OpenBSD", product="OpenSSH",
        name="Privilege Escalation", date_added="2022-03-03")]), queried=True)))
    out = capsys.readouterr().out
    assert "KNOWN EXPLOITED VULNERABILITIES" in out
    assert "CVE-2021-41617" in out and "OpenSSH" in out


def test_a_capped_sibling_list_says_how_many_there_were(capsys):
    """The count is the whole point of capping honestly: a truncated list
    that reads as complete is worse than no list."""
    from ioc_inquest.models import CertReport, SourceResult
    from ioc_inquest.render.tty import render_certs

    render_certs(_phase4_report(certs=SourceResult(value=CertReport(
        siblings=[f"h{n}.evil.example" for n in range(100)], count=5000),
        queried=True)))
    out = capsys.readouterr().out
    assert "5000" in out
    assert "showing 100" in out


def test_sections_for_sources_that_never_ran_are_absent(capsys):
    """None means the source never ran, and a section printed for it would
    be indistinguishable from one that ran and found nothing."""
    from ioc_inquest.render.tty import render_bazaar, render_certs, render_kev

    empty = _phase4_report()
    render_bazaar(empty)
    render_certs(empty)
    render_kev(empty)
    assert capsys.readouterr().out == ""


def test_a_long_cve_list_is_capped_with_the_total_kept(capsys):
    """A real Shodan answer for a busy web server carries over a hundred
    CVEs. Printed whole they are one unreadable line that buries the KEV
    section underneath -- capped, the count still says how many there were."""
    from ioc_inquest.models import ShodanReport, SourceResult
    from ioc_inquest.render.tty import CVE_DISPLAY_LIMIT, render_ip_intel

    cves = [f"CVE-2021-{n:05d}" for n in range(128)]
    render_ip_intel(_phase4_report(
        shodan={"198.51.100.10": SourceResult(
            value=ShodanReport(ports=[80], vulns=cves), queried=True)}))
    out = capsys.readouterr().out
    assert cves[CVE_DISPLAY_LIMIT] not in out
    assert f"128 CVEs" in out
    assert f"showing {CVE_DISPLAY_LIMIT}" in out


def test_ip_intel_names_the_c2_family_for_a_contacted_ip(capsys):
    """The section already had exposure (Shodan) and noise-vs-targeted
    (GreyNoise). Neither names a C2 family, which is ThreatFox's whole
    value and the reason it now runs per IP as well as per sample."""
    from ioc_inquest.models import ShodanReport, SourceResult, ThreatFoxReport
    from ioc_inquest.render.tty import render_ip_intel

    render_ip_intel(_phase4_report(
        shodan={"198.51.100.10": SourceResult(
            value=ShodanReport(ports=[443]), queried=True)},
        threatfox_ips={"198.51.100.10": SourceResult(
            value=ThreatFoxReport(found=True, malware="Emotet", confidence=90,
                                  tags=["botnet", "c2"]), queried=True)},
    ))
    out = capsys.readouterr().out
    assert "ThreatFox: Emotet (90% confidence)" in out
    assert "botnet, c2" in out


def test_an_ip_only_threatfox_answered_for_still_gets_a_row(capsys):
    """threatfox_ips is a third per-IP dict beside shodan and greynoise, so
    it has to join the key union too -- otherwise an attribution for an
    address Shodan never answered about is fetched and then dropped."""
    from ioc_inquest.models import SourceResult, ThreatFoxReport
    from ioc_inquest.render.tty import render_ip_intel

    render_ip_intel(_phase4_report(threatfox_ips={"203.0.113.7": SourceResult(
        value=ThreatFoxReport(found=True, malware="Qakbot", confidence=75),
        queried=True)}))
    out = capsys.readouterr().out
    assert "IP INTELLIGENCE" in out
    assert "IP:      203.0.113.7" in out
    assert "ThreatFox: Qakbot (75% confidence)" in out


def test_an_address_threatfox_has_no_record_of_says_so(capsys):
    """A real answer, and a different one from an error or a source nobody
    asked -- the same three-way split every other renderer here makes."""
    from ioc_inquest.models import SourceResult, ThreatFoxReport
    from ioc_inquest.render.tty import render_ip_intel

    render_ip_intel(_phase4_report(threatfox_ips={"203.0.113.7": SourceResult(
        value=ThreatFoxReport(found=False), queried=True)}))
    assert "ThreatFox: no C2 record for this address" in capsys.readouterr().out

    render_ip_intel(_phase4_report(threatfox_ips={"203.0.113.7": SourceResult(
        error="ThreatFox rejected the key", queried=True)}))
    assert "ThreatFox: ThreatFox rejected the key" in capsys.readouterr().out


def test_ip_intel_is_silent_when_no_per_ip_source_was_ever_asked(capsys):
    """Carried from Task A2's review. The old guard tested the DICTS --
    `if not report.shodan and not report.greynoise` -- and a dict holding
    only never-asked SourceResults is non-empty and therefore truthy. The
    header printed and each IP rendered as a bare `IP: x.x.x.x` line with
    nothing under it. The gate has to ask whether anything was queried."""
    from ioc_inquest.models import SourceResult
    from ioc_inquest.render.tty import render_ip_intel

    render_ip_intel(_phase4_report(
        shodan={"198.51.100.10": SourceResult()},
        greynoise={"198.51.100.10": SourceResult()},
        threatfox_ips={"198.51.100.10": SourceResult()},
    ))
    assert capsys.readouterr().out == ""


def test_an_ip_nobody_asked_about_is_dropped_while_the_answered_ones_stay(capsys):
    """The third per-IP dict is exactly the change that can leave one dict
    populated and another not, so the gate is per IP, not per section."""
    from ioc_inquest.models import ShodanReport, SourceResult
    from ioc_inquest.render.tty import render_ip_intel

    render_ip_intel(_phase4_report(
        shodan={"198.51.100.10": SourceResult(
            value=ShodanReport(ports=[443]), queried=True),
            "203.0.113.7": SourceResult()},
        threatfox_ips={"203.0.113.7": SourceResult()},
    ))
    out = capsys.readouterr().out
    assert "198.51.100.10" in out
    assert "203.0.113.7" not in out


def test_a_long_threatfox_tag_list_is_capped_with_the_total_kept(capsys):
    """Same bargain as the CVE cap: a truncated list that reads as complete
    is worse than no list. In the PDF the cap is load-bearing rather than
    cosmetic -- an unbounded provider list in a table cell raises
    LayoutError -- so both surfaces share TAG_DISPLAY_LIMIT."""
    from ioc_inquest.models import SourceResult, ThreatFoxReport
    from ioc_inquest.render.tty import TAG_DISPLAY_LIMIT, render_ip_intel

    tags = [f"tag-{n:03d}" for n in range(40)]
    render_ip_intel(_phase4_report(threatfox_ips={"203.0.113.7": SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet", confidence=90,
                              tags=tags), queried=True)}))
    out = capsys.readouterr().out
    assert tags[TAG_DISPLAY_LIMIT] not in out
    assert tags[TAG_DISPLAY_LIMIT - 1] in out
    assert f"40 tags (showing {TAG_DISPLAY_LIMIT})" in out


def test_an_unreachable_kev_says_how_many_cves_went_unchecked(capsys):
    """The count models.py singles out as the one field that survives an error.

    `KEVReport.unchecked` is set correctly and pinned there; no CONSUMER's use
    of it was pinned on either surface, so
    `f"{kev.value.unchecked} CVEs ..."` -> `f"0 CVEs ..."` left 431 tests
    green -- an unreachable catalog reporting that nothing went unchecked,
    which is the Phase 4 KEV bug wearing the words of the fix for it.

    Two different counts, and the whole line as a literal: one count would
    also pass against a hardcoded number in the renderer.
    """
    from ioc_inquest.models import KEVReport, SourceResult
    from ioc_inquest.render.tty import render_kev

    for unchecked in (3, 17):
        render_kev(_phase4_report(kev=SourceResult(
            value=KEVReport(unchecked=unchecked),
            error="CISA KEV API Error 503", queried=True)))
        out = capsys.readouterr().out
        assert "KNOWN EXPLOITED VULNERABILITIES" in out
        assert (f"CISA KEV was unreachable (CISA KEV API Error 503) -- "
                f"{unchecked} CVEs on contacted hosts went unchecked."
                in out.splitlines())


def test_render_kev_is_silent_when_the_catalog_answered_with_no_hits(capsys):
    """The property render_kev's docstring now claims.

    It used to say "silent only when there was nothing to check", which was
    false: a catalog that ran and matched nothing is silent too. The shape is
    right -- an empty KEV section is not news -- so the docstring was the
    thing that was wrong, and this pins what it says now.
    """
    from ioc_inquest.models import KEVReport, SourceResult
    from ioc_inquest.render.tty import render_kev

    render_kev(_phase4_report(kev=SourceResult(
        value=KEVReport(entries=[], unchecked=0), queried=True)))
    assert capsys.readouterr().out == ""
