from hash_searcher.render.tty import render


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
