from hash_searcher.render.tty import render, render_ips, render_whois
from hash_searcher.models import IPReport, WhoisRecord, Report


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
