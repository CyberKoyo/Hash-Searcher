"""The Markdown writer: the report as a pasteable ticket comment.

Written before the module exists (Task C1, Step 1). The escaping tests are
the ones that matter: a `|` in a provider-supplied value splits a table row
into extra cells and every column after it renders under the wrong header,
which is the same bug class as the PDF's unescaped `<` that cost Phase 2 a
Critical. A newline does worse -- it ends the row entirely.
"""

from hash_searcher.models import (
    BazaarReport, CertReport, Detection, IPReport, KEVEntry, KEVReport,
    OTXReport, Report, Signal, SourceResult, ThreatClass, ThreatFoxReport,
    Verdict, VTReport,
)
from hash_searcher.render.markdown import to_markdown, write_markdown


def _bare_report(indicator: str = "abc123") -> Report:
    return Report(
        indicator=indicator,
        generated_at="2026-09-03 12:00:00",
        vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"),
        ips={}, hosts=[], whois=[],
    )


def test_the_verdict_table_carries_the_level_the_score_and_each_signal():
    verdict = Verdict(level="MALICIOUS", score=70, signals=[
        Signal(name="detection", points=40, detail="42/50 engines"),
        Signal(name="bazaar", points=30, detail="abuse.ch names emotet"),
    ])

    text = to_markdown(_bare_report(), verdict)

    assert "| MALICIOUS | 70 |" in text
    assert "| detection | +40 | 42/50 engines |" in text
    assert "| bazaar | +30 | abuse.ch names emotet |" in text


def test_a_pipe_in_a_provider_value_is_escaped():
    """abuse.ch returns the family verbatim; a `|` in it must not become a
    cell boundary."""
    report = _bare_report()
    report.bazaar = SourceResult(
        queried=True, value=BazaarReport(found=True, family="evil|family"))

    text = to_markdown(report)

    assert "evil|family" not in text
    assert r"evil\|family" in text


def test_a_newline_in_a_provider_value_does_not_end_the_row():
    """A bare `\\n` in a cell terminates the table row -- everything after
    it renders as a paragraph, and the remaining columns are gone."""
    report = _bare_report()
    report.threatfox = SourceResult(
        queried=True,
        value=ThreatFoxReport(found=True, malware="Emotet\nsecond line"))

    text = to_markdown(report)

    assert "Emotet\nsecond line" not in text
    assert "Emotet second line" in text


def test_each_populated_section_appears():
    report = _bare_report()
    report.vt = VTReport(found=True, detection=Detection(malicious=42, harmless=8),
                         threat=ThreatClass(label="trojan", family="emotet"),
                         contacted_ips=["198.51.100.10"],
                         contacted_domains=["bad.example"])
    report.ips = {"198.51.100.10": IPReport(ip="198.51.100.10", confidence=90,
                                            reports=2)}
    report.bazaar = SourceResult(queried=True,
                                 value=BazaarReport(found=True, family="emotet"))
    report.threatfox = SourceResult(
        queried=True, value=ThreatFoxReport(found=True, malware="Emotet",
                                            confidence=100))
    report.certs = SourceResult(queried=True,
                                value=CertReport(siblings=["sib.example"], count=1))
    report.kev = SourceResult(queried=True, value=KEVReport(
        entries=[KEVEntry(cve="CVE-2021-44228", name="Log4Shell")]))
    report.otx = OTXReport(recorded_instances=7, otx_responded=True,
                           attack_techniques=["T1059 Command"])

    text = to_markdown(report)

    for heading in ("## Detections", "## Attribution", "## MalwareBazaar",
                    "## ThreatFox", "## Contacted IPs", "## Contacted domains",
                    "## Certificate transparency",
                    "## Known exploited vulnerabilities", "## OTX"):
        assert heading in text


def test_a_section_whose_source_was_never_asked_is_absent():
    """Silence, not an empty section -- the same rule the TTY follows, so a
    reader cannot mistake "nobody asked abuse.ch" for "abuse.ch had nothing".
    """
    text = to_markdown(_bare_report())

    assert "## MalwareBazaar" not in text
    assert "## ThreatFox" not in text
    assert "## Known exploited vulnerabilities" not in text


def test_a_source_that_failed_says_what_failed():
    report = _bare_report()
    report.bazaar = SourceResult(queried=True, error="timeout")

    text = to_markdown(report)

    assert "## MalwareBazaar" in text
    assert "timeout" in text


def test_the_document_opens_with_the_indicator_and_the_time():
    text = to_markdown(_bare_report("198.51.100.10"))

    assert text.startswith("# ")
    assert "198.51.100.10" in text
    assert "2026-09-03 12:00:00" in text


def test_write_markdown_writes_what_to_markdown_returns(tmp_path):
    report = _bare_report()
    path = tmp_path / "report.md"

    write_markdown(report, str(path))

    assert path.read_text(encoding="utf-8") == to_markdown(report)


def test_the_file_ends_with_exactly_one_newline(tmp_path):
    path = tmp_path / "report.md"

    write_markdown(_bare_report(), str(path))

    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n") and not text.endswith("\n\n")


def test_a_queried_source_with_no_value_renders_as_no_record():
    """`SourceResult.value` is Optional even on a success, and a renderer
    must never be the thing that crashes on it. No value and no error is
    the same answer as found=False -- not an AttributeError three frames
    down naming neither the source nor the report.
    """
    report = _bare_report()
    report.bazaar = SourceResult(queried=True)
    report.threatfox = SourceResult(queried=True)
    report.certs = SourceResult(queried=True)
    report.kev = SourceResult(queried=True)

    text = to_markdown(report)

    assert "abuse.ch has no record of this sample." in text
    assert "ThreatFox has no record of this indicator." in text
    assert "No certificates found for the contacted domains." in text
    # KEV stays silent: nothing known-exploited is not worth a section.
    assert "## Known exploited vulnerabilities" not in text
