from hash_searcher.render.tty import render, render_hosts, render_ips, render_otx, render_vt, render_whois
from hash_searcher.models import CensysHost, IPReport, OTXReport, Report, SigmaRule, VTReport, WhoisRecord


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
        vt=None,
        otx=None,
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
    """Assert exact column alignment and separator in WHOIS table."""
    report = Report(
        indicator="test",
        generated_at="2026-08-23",
        vt=None,
        otx=None,
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
        "-----------------------------------------------------------------------------------------\n"
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
        otx=None,
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
        otx=None, ips={}, hosts=[], whois=[],
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
        vt=None,
        otx=None,
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
        indicator="test", generated_at="x", vt=None,
        otx=OTXReport(recorded_instances=7, attack_techniques=["T1059 Command"],
                      has_pulse_info=True),
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
        indicator="test", generated_at="x", vt=None,
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
        indicator="test", generated_at="x", vt=None,
        otx=OTXReport(recorded_instances="N/A, No recorded instances",
                      has_pulse_info=True),
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
        indicator="test", generated_at="x", vt=None,
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
    "Recorded instances: N/A" there. Gating on has_pulse_info restores that.
    """
    report = Report(
        indicator="test", generated_at="x", vt=None,
        otx=OTXReport(recorded_instances="N/A", has_pulse_info=True),
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
