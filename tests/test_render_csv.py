"""The CSV writer: one row per indicator, flat enough for a spreadsheet.

Written before the module exists (Task C1, Step 1). The three properties
worth pinning are the ones a spreadsheet consumer breaks on: a header that
does not move, a field carrying a comma that stays one field, and an
optional column that is empty rather than the string "None".
"""

import csv

from hash_searcher.models import (
    BazaarReport, Detection, IPReport, OTXReport, Report, SourceResult,
    ThreatClass, ThreatFoxReport, Verdict, VTReport,
)
from hash_searcher.render.csv_out import CSV_HEADER, row, write_csv, write_rows


def _bare_report(indicator: str = "abc123") -> Report:
    """A Report with nothing populated -- every optional column empty.

    Not the sample_report fixture: the point of this one is that every
    field a column reads from is absent, which is the state a run against
    a sample nobody has ever seen produces.
    """
    return Report(
        indicator=indicator,
        generated_at="2026-09-03 12:00:00",
        vt=VTReport(found=False),
        otx=OTXReport(recorded_instances="N/A"),
        ips={}, hosts=[], whois=[],
    )


def _read(path) -> list[list[str]]:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.reader(handle))


def test_the_header_is_the_first_line_and_names_every_column(tmp_path):
    path = tmp_path / "report.csv"
    write_csv(_bare_report(), str(path))

    rows = _read(path)
    assert rows[0] == list(CSV_HEADER)


def test_one_row_per_indicator(tmp_path):
    """A batch's whole answer in one file: N indicators, N rows, one header."""
    path = tmp_path / "report.csv"
    entries = [(_bare_report("abc123"), None),
               (_bare_report("198.51.100.10"), None),
               (_bare_report("evil.example"), None)]

    write_rows(entries, str(path))

    rows = _read(path)
    assert len(rows) == 4  # header + three indicators
    assert [r[0] for r in rows[1:]] == ["abc123", "198.51.100.10", "evil.example"]


def test_a_field_containing_a_comma_stays_one_field(tmp_path):
    """Two contacted IPs join with ", " -- unquoted, that is two columns,
    and every column after it in the spreadsheet is shifted by one."""
    report = _bare_report()
    report.vt = VTReport(found=True,
                         contacted_ips=["198.51.100.10", "203.0.113.7"])
    path = tmp_path / "report.csv"

    write_csv(report, str(path))

    assert '"198.51.100.10, 203.0.113.7"' in path.read_text(encoding="utf-8")
    header, body = _read(path)
    assert len(body) == len(header)
    assert body[header.index("contacted_ips")] == "198.51.100.10, 203.0.113.7"


def test_every_optional_column_is_empty_rather_than_none(tmp_path):
    """`None` reaching csv.writer prints the four characters N-o-n-e, which
    a spreadsheet reads as a value. Absent means empty."""
    path = tmp_path / "report.csv"

    write_csv(_bare_report(), str(path))

    header, body = _read(path)
    assert len(body) == len(header)
    assert "None" not in body
    # The indicator and the timestamp are the only columns a bare run fills.
    assert body[header.index("indicator")] == "abc123"
    assert body[header.index("generated_at")] == "2026-09-03 12:00:00"


def test_the_row_carries_the_verdict_when_one_was_scored(tmp_path):
    report = _bare_report()
    verdict = Verdict(level="MALICIOUS", score=70)
    path = tmp_path / "report.csv"

    write_csv(report, str(path), verdict)

    header, body = _read(path)
    assert body[header.index("verdict")] == "MALICIOUS"
    assert body[header.index("score")] == "70"


def test_the_row_reads_through_every_populated_source():
    """One assertion per source the header promises, so a column that
    silently stops being populated reddens here rather than shipping empty.
    """
    report = _bare_report()
    report.vt = VTReport(
        found=True,
        detection=Detection(malicious=42, harmless=8),
        threat=ThreatClass(label="trojan", family="emotet"),
        contacted_domains=["bad.example"],
    )
    report.ips = {"198.51.100.10": IPReport(ip="198.51.100.10", confidence=90)}
    report.bazaar = SourceResult(queried=True,
                                 value=BazaarReport(found=True, family="emotet"))
    report.threatfox = SourceResult(
        queried=True, value=ThreatFoxReport(found=True, malware="Emotet"))

    values = dict(zip(CSV_HEADER, row(report, Verdict(level="MALICIOUS", score=70))))

    assert values["vt_malicious"] == "42"
    assert values["vt_total"] == "50"
    assert values["vt_family"] == "emotet"
    assert values["bazaar_family"] == "emotet"
    assert values["threatfox_malware"] == "Emotet"
    assert values["contacted_domains"] == "bad.example"
    assert values["abuseipdb_ips"] == "198.51.100.10"


def test_a_source_that_failed_says_so_rather_than_reading_as_no_record():
    """The distinction Part A built: "asked and failed" is not "no record".
    A CSV that flattens the two hands a spreadsheet a false negative.
    """
    report = _bare_report()
    report.vt = VTReport(found=False, error="503 Service Unavailable",
                         unavailable=True)
    report.bazaar = SourceResult(queried=True, error="timeout")

    values = dict(zip(CSV_HEADER, row(report)))

    assert values["vt_error"] == "503 Service Unavailable"
    assert values["errors"] == "bazaar: timeout"


def test_a_source_nobody_asked_contributes_no_error():
    """queried=False is silence, not a failure -- the SourceResult
    truthiness trap, which every surface on this branch has had to learn.

    The result carries an error string it was never asked for, which is the
    only shape that tells the `queried` gate apart from a bare `if
    result.error`: without the gate this row reports a failure for a source
    the run deliberately skipped.
    """
    report = _bare_report()
    report.bazaar = SourceResult(queried=False, error="never asked")

    values = dict(zip(CSV_HEADER, row(report)))

    assert values["errors"] == ""
    assert values["bazaar_family"] == ""
