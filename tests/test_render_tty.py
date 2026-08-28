from hash_searcher.render.tty import RULE, render, render_hosts, render_ips, render_otx, render_vt, render_whois
from hash_searcher.models import (
    AttackTechnique, CensysHost, IPReport, OTXReport, PEInfo, Report, SandboxVerdict,
    SigmaRule, Signature, Submission, ThreatClass, VTReport, WhoisRecord, YaraMatch,
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


def test_render_otx_error_path_unaffected(capsys):
    report = Report(
        indicator="test", generated_at="x", vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A", error="OTX key not set"),
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
    from hash_searcher.models import Signal, Verdict
    from hash_searcher.render.tty import RULE, render_verdict

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
    from hash_searcher.models import Verdict
    from hash_searcher.render.tty import render_verdict

    render_verdict(Verdict(level="UNKNOWN", score=0, signals=[]))
    out = capsys.readouterr().out
    assert "VERDICT: UNKNOWN (score 0)" in out
    assert "No signals fired." in out


def test_a_negative_signal_prints_its_sign(capsys, sample_report):
    from hash_searcher.models import Signal, Verdict
    from hash_searcher.render.tty import render_verdict

    render_verdict(Verdict(level="CLEAN", score=-20, signals=[
        Signal("signed", -20, "valid signature from Contoso Ltd"),
    ]))
    assert "  -20  signed" in capsys.readouterr().out


def test_detection_section_prints_the_ratio(capsys, sample_report):
    from hash_searcher.models import Detection
    from hash_searcher.render.tty import render_detection

    sample_report.vt.detection = Detection(malicious=48, suspicious=0, undetected=24)
    render_detection(sample_report)
    assert capsys.readouterr().out == (
        "\nDetections: 48/72  (suspicious 0, undetected 24)\n"
    )


def test_detection_section_is_silent_without_stats(capsys, sample_report):
    from hash_searcher.render.tty import render_detection

    sample_report.vt.detection = None
    render_detection(sample_report)
    assert capsys.readouterr().out == ""


def test_contacted_domains_exact_formatting(capsys, sample_report):
    """R14. This asserted `"CONTACTED DOMAINS" in out and "evil.example" in out`,
    which left the body format of a whole new section unpinned -- changing it
    to `- {domain}` kept the suite green."""
    from hash_searcher.render.tty import render_domains

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
    from hash_searcher.render.tty import render_domains

    sample_report.vt.contacted_domains = []
    render_domains(sample_report)
    assert capsys.readouterr().out == ""


def test_render_attribution_exact_formatting(capsys, sample_report):
    """R14, and the largest gap the review found: seven output shapes and no
    test called this function at all. Its only exercise anywhere was
    `out.index("ATTRIBUTION")` in the ordering test, so rewriting the
    signature line to `SIG={state}` kept 189 tests green.
    """
    from hash_searcher.render.tty import render_attribution

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
    from hash_searcher.render.tty import render_attribution

    render_attribution(sample_report)
    assert capsys.readouterr().out == ""


def test_a_verified_signature_reads_differently_from_an_unverified_one(capsys, sample_report):
    """VT's signature_info.verified is prose and every value of it is truthy;
    the extractor compares against the one string that means verified. Pin
    both renderings so the distinction cannot collapse."""
    from hash_searcher.render.tty import render_attribution

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
    from hash_searcher.models import Detection, Signal, StaticReport, ThreatClass, Verdict
    from hash_searcher.render.tty import render

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
    from hash_searcher.render.tty import render

    render(sample_report)
    assert "VERDICT:" not in capsys.readouterr().out


# --- Phase 3: render_static --------------------------------------------------


def test_render_static_is_silent_when_no_static_report(capsys, sample_report):
    """sample_report.static defaults to None -- render() keeps working for
    every pre-Phase-3 call site, the same guarantee Phase 2 gave render()
    without a verdict."""
    from hash_searcher.render.tty import render_static

    render_static(sample_report)
    assert capsys.readouterr().out == ""


def test_render_static_exact_formatting(capsys):
    from hash_searcher.models import (
        EntropyReport, FileTypeReport, IOCSet, PEStaticReport, PESection,
        StaticReport, StringsReport, YaraHit,
    )
    from hash_searcher.render.tty import render_static

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
    from hash_searcher.models import StaticReport
    from hash_searcher.render.tty import render_static

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
    from hash_searcher.models import StaticReport
    from hash_searcher.render.tty import render_static

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


def test_render_hosts_prints_the_per_ip_error(capsys, sample_report):
    from hash_searcher.models import CensysHost
    from hash_searcher.render.tty import render_hosts

    sample_report.hosts = [CensysHost(ip="198.51.100.10", error="Censys 403: forbidden")]
    render_hosts(sample_report)
    assert "Censys 403: forbidden" in capsys.readouterr().out


def test_render_hosts_error_branch_exact_formatting(capsys, sample_report):
    from hash_searcher.models import CensysHost
    from hash_searcher.render.tty import RULE, render_hosts

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
    from hash_searcher.render.tty import render_ips

    sample_report.ips = {}
    render_ips(sample_report)
    assert "No data from IPDB available." in capsys.readouterr().out


def test_the_whois_separator_matches_the_header_width(capsys, sample_report):
    """R13: 35+1+12+1+12+1+30 == 92. The separator was 89 -- three short, a
    faithful port of a defect in formatters.py:183-184."""
    from hash_searcher.render.tty import render_whois

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
    from hash_searcher.analysis.ipdb import extract_ips

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
