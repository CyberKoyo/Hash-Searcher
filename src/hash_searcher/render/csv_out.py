"""The report as one spreadsheet row.

The flattest surface this tool has: a triage queue of a hundred indicators
sorted by score is a thing an analyst does in a spreadsheet, and neither
the JSON report (nested, one file per indicator) nor the PDF answers that.

Two rules the columns follow, both learned elsewhere in this package:

- **Absent is empty, never the string "None".** `csv.writer` stringifies
  whatever it is handed, so a bare `None` reaches the spreadsheet as four
  characters that sort, filter, and read as a value.
- **"asked and failed" is not "no record".** Part A built that distinction
  through `SourceResult`; flattening it here would hand a spreadsheet a
  false negative for every source that timed out. `vt_error` carries VT's
  own failure (VT is the column set a reader looks at first), and `errors`
  carries every other source's, each one naming the source it came from.

Only the model is consumed -- never the TTY's printed output -- so what a
column says cannot drift from what the run actually found.
"""

import csv

from ..models import Report, Verdict

#: The column order. Stable: a consumer's `awk -F, '{print $5}'` and every
#: saved spreadsheet filter is keyed on position, so a new column is
#: appended rather than inserted, and none of these is ever renamed.
CSV_HEADER = (
    "indicator",
    "indicator_kind",
    "generated_at",
    "verdict",
    "score",
    "signals",
    "vt_malicious",
    "vt_total",
    "vt_label",
    "vt_family",
    "vt_error",
    "bazaar_family",
    "threatfox_malware",
    "kev_cves",
    "abuseipdb_ips",
    "contacted_ips",
    "contacted_domains",
    "errors",
    "source_file",
)

#: What separates the values inside one cell. A comma, deliberately -- it
#: is what a reader expects to see in a list, and `csv.writer` quotes the
#: field for it. The quoting is the point: unquoted, a two-IP cell is two
#: columns and every column after it shifts by one.
JOIN = ", "


def _text(value) -> str:
    """A cell's text, with absent rendered as empty rather than "None"."""
    return "" if value is None else str(value)


def _list(values) -> str:
    return JOIN.join(_text(v) for v in values or ())


def _errors(report: Report) -> str:
    """Every source that was asked and failed, each naming itself.

    VT is excluded: it has `vt_error` to itself. A source nobody asked
    contributes nothing -- `queried` is the gate, never truthiness of the
    `SourceResult`, which has no `__bool__` and is therefore always true.
    """
    found = []
    if report.otx.error:
        found.append(f"otx: {report.otx.error}")
    for name, result in (("bazaar", report.bazaar),
                         ("threatfox", report.threatfox),
                         ("certs", report.certs),
                         ("kev", report.kev)):
        if result.queried and result.error:
            found.append(f"{name}: {result.error}")
    for name, source in (("shodan", report.shodan),
                         ("greynoise", report.greynoise),
                         ("threatfox_ips", report.threatfox_ips)):
        for ip, result in source.items():
            if result.queried and result.error:
                found.append(f"{name}[{ip}]: {result.error}")
    for host in report.hosts:
        if host.error:
            found.append(f"censys[{host.ip}]: {host.error}")
    for record in report.whois:
        if record.error:
            found.append(f"rdap[{record.domain}]: {record.error}")
    return "; ".join(found)


def row(report: Report, verdict: Verdict | None = None) -> list[str]:
    """One indicator's row, in CSV_HEADER order.

    Every value is already a string: a caller that writes the row itself
    (a batch accumulating rows across runs) gets the same "" for absent
    that `write_rows` does, rather than each caller re-deciding.
    """
    vt = report.vt
    detection = vt.detection
    threat = vt.threat
    bazaar = report.bazaar
    threatfox = report.threatfox
    kev = report.kev
    return [
        _text(report.indicator),
        _text(report.indicator_kind),
        _text(report.generated_at),
        _text(verdict.level) if verdict else "",
        _text(verdict.score) if verdict else "",
        "; ".join(f"{s.name} {s.points:+d}" for s in verdict.signals)
        if verdict else "",
        _text(detection.malicious) if detection else "",
        _text(detection.total) if detection else "",
        _text(threat.label) if threat else "",
        _text(threat.family) if threat else "",
        _text(vt.error),
        _text(bazaar.value.family) if bazaar.ok and bazaar.value else "",
        _text(threatfox.value.malware) if threatfox.ok and threatfox.value else "",
        _list(e.cve for e in kev.value.entries) if kev.ok and kev.value else "",
        _list(report.ips),
        _list(vt.contacted_ips),
        _list(vt.contacted_domains),
        _errors(report),
        _text(report.source_file),
    ]


def failure_row(indicator: str, reason: str,
                source_file: str = "") -> list[str]:
    """A row for an indicator that never produced a Report at all.

    A batch line can die before there is anything to render: an unreadable
    archive, an indicator that resolves to nothing, a provider raising. The
    alternative to this row is omitting the line, and a triage table that
    silently drops the three indicators that failed reads as an all-clear
    for three things nobody checked. The row count matching the input
    list's line count is what makes the table trustworthy.

    Built by walking CSV_HEADER rather than by writing out N empty strings,
    so a column appended to the header cannot leave this row one field
    short -- which would shift every column after it, on this line only.

    `source_file` carries the input line, so both kinds of row identify it
    the same way. A successful file lookup reports the resolved digest in
    `indicator` and the line in `source_file` -- cli.py sets that for every
    indicator kind, not only for paths -- while a failed one has no digest
    to report and puts the line in `indicator` instead. Without this the
    two rows name the same input by different columns, and a consumer
    joining the table back to the list it fed in matches neither.

    Every other column stays empty, `verdict` above all: a row that could
    not be analyzed must not read as one that was analyzed and found
    nothing. That is the same rule `_errors` exists for, one level up.
    """
    known = {"indicator": indicator, "errors": reason,
             "source_file": source_file}
    return [_text(known.get(name, "")) for name in CSV_HEADER]


def write_rendered_rows(rows, path: str) -> str:
    """A header and the rows given, already rendered.

    The seam a batch writes through: it accumulates rows across runs, and
    some of them never had a Report behind them (see failure_row), so it
    cannot hand over (report, verdict) pairs for all of them.

    `newline=""` is not optional: without it csv.writer's \\r\\n meets the
    platform's own line ending and every row is separated by a blank one.
    """
    with open(path, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(CSV_HEADER)
        writer.writerows(rows)
    return path


def write_rows(entries, path: str) -> str:
    """A header and one row per (report, verdict) pair.

    Renders and delegates rather than opening the file itself: a second
    copy of the header-and-loop is how the two writers would drift, and
    the header is the one thing in this module that consumers pin.
    """
    return write_rendered_rows(
        [row(report, verdict) for report, verdict in entries], path)


def write_csv(report: Report, path: str, verdict: Verdict | None = None) -> str:
    """One report's file -- a single run, or one indicator of a batch whose
    -o named some other format. A batch writing CSV aggregates into one
    table instead (see batch.run_batch), so this is the single-row case of
    write_rows rather than a second implementation of it."""
    return write_rows([(report, verdict)], path)
