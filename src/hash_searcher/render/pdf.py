"""The written report an analyst files.

Two rules govern this module, and both were learned from a crash: every
interpolated provider value goes through _x(), and every provider-supplied
STRING that lands in a table cell goes through _fitted(). A table row
cannot split across pages, so an unbounded cell raises LayoutError after
every provider has already succeeded.

Rule 2 used to say "every provider-supplied LIST ... is capped", and that
was the narrower half of it. Capping the list bounds how many items a cell
names; it does not bound how long one of them is, and one 400-character
"rule name" overflowed the row on its own. Nor is a character count the
bound: what overflows is HEIGHT, and 624pt of it is 740 characters of one
shape and 2669 of another (CELL_HEIGHT_LIMIT). _fitted measures instead.

Neither rule can be checked by asserting on build_story's flowables. Only a
real doc.build() raises either failure, and only a payload reportlab
actually rejects exercises the first -- an unknown tag is discarded
silently. See test_write_pdf_survives_a_realistic_worst_case.
"""

from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..models import Report, Verdict
from .tty import CVE_DISPLAY_LIMIT, VT_UNAVAILABLE_NOTE, queried_ips, tag_text

TABLE_STYLE = TableStyle([
    ('BACKGROUND',      (0, 0), (-1, 0), colors.grey),
    ('TEXTCOLOR',       (0, 0), (-1, 0), colors.whitesmoke),
    ('GRID',            (0, 0), (-1, -1), 0.5, colors.black),
    ('ROWBACKGROUNDS',  (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ('WORDWRAP',        (0, 0), (-1, -1), True),
    ('VALIGN',          (0, 0), (-1, -1), 'TOP'),
])


def _x(value) -> str:
    """Escape a provider-supplied value for reportlab's mini-HTML parser.

    Paragraph does not render a stray '<' oddly -- it raises. A crafted
    Authenticode signer name or YARA rule name containing one killed
    `-o report.pdf` with a traceback on an otherwise successful run. Every
    interpolated value in this module comes from a provider payload, which is
    to say from someone else; this module's own markup (the ATT&CK ampersand,
    the <b> around a Sigma title) is written literally around the escaped
    value, never through it.
    """
    return escape(str(value))


#: The three tables' column widths, named because _fitted has to measure
#: against exactly the number the Table lays out with. They drifted apart
#: once already: the IP table's five columns sum to 460pt inside a 456pt
#: frame.
SIGNAL_WIDTHS = [50, 90, 250]
IP_WIDTHS = [80, 55, 120, 95, 100]
KEV_WIDTHS = [130, 200, 90]

#: reportlab's default cell padding, 6pt per side. Subtracted from a column
#: width to get the width its Paragraph actually wraps in, and from the
#: frame height to get the height a cell may occupy.
CELL_PADDING = 6

#: The real bound on a table cell, in points of rendered height.
#:
#: A character count is not one. Bisected against a real write_pdf with the
#: character backstop disabled, every content shape crossed the frame at the
#: SAME wrapped height -- 624.0pt, to the point -- while the character count
#: that reaches it varies by 3.6x:
#:
#:     ("W" * 13 + " ")            740      ", ".join CVE ids     1678
#:     ("W" * 10 + " ")           1149      ", ".join YARA names  2128
#:     "W" * n                    1301      ", ".join IPs         2389
#:     ALL CAPS PROSE             1914      lowercase prose       2669
#:
#: That is why DETAIL_CHAR_LIMIT = 1200 was not a bound: against the first
#: shape it truncated to ~1276 characters and the TRUNCATED string still
#: raised LayoutError. Any single number of characters is either too small
#: for prose or too large for wide capitals, because it is a proxy for a
#: width the font decides.
#:
#: 624 is where the measurement puts the frame: letter is 792pt, the
#: SimpleDocTemplate margins write_pdf accepts take 144, the frame's padding
#: 12, and a cell's own padding 6 top and 6 bottom. 600 keeps two lines of
#: 12pt leading in hand against a style or margin change, and costs nothing
#: real -- the largest detail today, internet_noise at ~808 characters of
#: IP list, wraps to about 210pt.
CELL_HEIGHT_LIMIT = 600

#: Hard ceiling on any one signal's detail before it becomes a table cell.
#:
#: Not the crash bound -- CELL_HEIGHT_LIMIT is, and it applies after this
#: one. This is a READING bound: how much of a rationale a filed report asks
#: an analyst to read before the rest becomes a JSON lookup. It also keeps
#: the height fit's binary search off strings that are large for a reason
#: nobody anticipated.
#:
#: The per-signal caps in scoring.py are the honest fix -- they truncate at
#: an item boundary and state the total, so a shortened list still reads as
#: a shortened list. All five joined details are capped there now
#: (_capped_join), in both dimensions: how many items, and how long one item
#: may be. This is the blunt last resort behind them, and it exists because
#: the crash is a property of the CELL, not of any one signal -- a detail
#: nobody anticipated, from a source added later, still cannot be allowed to
#: take down `-o report.pdf` after every provider has succeeded.
#:
#: It truncates mid-string, which is why it must stay a last resort. Before
#: the source caps landed it was the ordinary rendering path for a KEV
#: detail, which crosses this budget at 80 CVEs against the 120-137 for a
#: single host that _cve_cell below calls realistic -- so an analyst read
#: "...CVE-2021-00070, CVE ... (truncated)" on Tuesday input, and a fallback
#: that fires routinely no longer signals that anything is wrong. The
#: largest detail real input produces today is internet_noise at ~808
#: characters, which passes through untouched, and a truncated one says what
#: it dropped rather than losing the tail silently. The full text is always
#: in the JSON report.
DETAIL_CHAR_LIMIT = 1200

#: How many KEV entries the table below prints, out of a reachable 6850 --
#: IOC_LIMIT contacted hosts at the 120-137 CVEs _cve_cell calls realistic.
#:
#: This one is not a crash bound either, and for the opposite reason to
#: DETAIL_CHAR_LIMIT: a many-row table splits across pages perfectly well,
#: so it never raised. It is a time and size bound. Layout cost grows
#: superlinearly in the row count -- 200 entries 0.13s, 1000 0.65s, 3000
#: 2.36s, 6850 6.82s for a 319 KiB PDF, and 11.4s on a slower machine --
#: which is 130 pages of table nobody reads to the end of.
#:
#: 50 rather than the 12 of CVE_DISPLAY_LIMIT or the 8 of TAG_DISPLAY_LIMIT:
#: those two are CELLS inside a row an eye has to take in at once, and this
#: is a section of its own, where a page of rows is still usable. It is also
#: IOC_LIMIT, one confirmed-exploited CVE per contacted host, which is
#: already more than a triage report needs. The untruncated total is printed
#: above the table and the full list is in the JSON report.
KEV_ROW_LIMIT = 50


def _shortened(text: str, keep: int) -> str:
    """`text` cut to `keep` characters, saying so and stating the total.

    The same bargain scoring.py's _capped_join makes, one layer down and
    without its item boundary: what was dropped is stated rather than
    silently lost, and the reader recovers the rest without arithmetic.
    """
    if keep >= len(text):
        return text
    return (text[:keep].rstrip()
            + f" ... (truncated at {keep} "
              f"of {len(text)} characters; the full text is in the JSON report)")


def _fitted(text: str, width: float, char_limit: int | None = None) -> Paragraph:
    """A provider string as a table cell that cannot overflow the page.

    This module's rule 2. A reportlab table row does not split across
    pages, so a cell taller than the frame is a LayoutError raised after
    every provider has already answered -- and neither the count caps in
    scoring.py nor DETAIL_CHAR_LIMIT can prevent it, because the row
    overflows by HEIGHT and both of those bound characters. See
    CELL_HEIGHT_LIMIT for the measurements.

    So the cell measures itself: wrap the text reportlab will actually
    render, at the width the Table will actually give it, and if it is too
    tall, binary-search the longest prefix that fits. Measuring the escaped
    text is deliberate -- `&amp;` is five characters of markup and one
    character of ink -- and truncating the RAW text before escaping is
    equally deliberate, since cutting an escaped string can leave a
    half-written entity for the parser.
    """
    keep = len(text) if char_limit is None else min(len(text), char_limit)
    if _cell_height(_shortened(text, keep), width) <= CELL_HEIGHT_LIMIT:
        return Paragraph(_x(_shortened(text, keep)))
    low, high = 0, keep
    while low < high:
        mid = (low + high + 1) // 2
        if _cell_height(_shortened(text, mid), width) <= CELL_HEIGHT_LIMIT:
            low = mid
        else:
            high = mid - 1
    return Paragraph(_x(_shortened(text, low)))


def _cell_height(text: str, width: float) -> float:
    """How tall this cell's Paragraph renders at this column width."""
    return Paragraph(_x(text)).wrap(width - 2 * CELL_PADDING,
                                    CELL_HEIGHT_LIMIT)[1]


def _table(rows, widths=None) -> Table:
    """One style, three tables. It was copy-pasted per table before."""
    table = Table(rows, colWidths=widths)
    table.setStyle(TABLE_STYLE)
    return table


def _ip_rows(report: Report):
    """Every IP some per-IP source was actually asked about.

    queried_ips is shared with tty.py's render_ip_intel: `if report.shodan
    or report.greynoise` tested the DICTS, and a dict of never-asked
    SourceResults is non-empty and therefore truthy, so this table printed
    a heading and a row of empty cells per IP. See queried_ips.
    """
    return [(ip, report.shodan.get(ip)) for ip in queried_ips(report)]


def _cve_cell(shodan) -> str:
    """Bounded CVE text for a table cell.

    A reportlab table row cannot split across pages, so an unbounded list
    here is not a formatting wart -- it raises LayoutError and takes the
    whole `-o report.pdf` run down after every provider succeeded. Real
    Shodan answers reach 120-137 CVEs for one host, well past the ~50 that
    overflows the frame. Same cap and same honesty as render_ip_intel: the
    total is stated, so a truncated cell never reads as the whole answer.
    """
    if shodan is None or not shodan.ok:
        return ""
    vulns = shodan.value.vulns
    if not vulns:
        return ""
    shown = vulns[:CVE_DISPLAY_LIMIT]
    if len(vulns) <= CVE_DISPLAY_LIMIT:
        return ", ".join(shown)
    return (f"{len(vulns)} CVEs (showing {CVE_DISPLAY_LIMIT}): "
            + ", ".join(shown))


def _greynoise_cell(noise) -> str:
    """Blank when nobody asked -- never "not observed".

    "Not observed" is a claim GreyNoise made. A result nobody asked for
    supports no claim at all, and this cell used to state the opposite of
    the truth for exactly the case `queried` exists to express. Same rule
    as _threatfox_cell below, and as every renderer in this tree: a source
    that never ran renders as silence, not as a negative finding.
    """
    if noise is None or not noise.queried:
        return ""
    if noise.error:
        return noise.error
    if not noise.value.seen:
        return "not observed"
    return " -- ".join(
        x for x in (noise.value.classification or "seen", noise.value.name) if x)


def _threatfox_cell(result) -> str:
    """ThreatFox's C2 attribution for one address.

    `tags` is a provider-supplied list in a table cell, so it is capped --
    this module's second rule, and the reason is a crash, not tidiness.
    tag_text states the untruncated total beside the capped list, the same
    bargain _cve_cell makes.
    """
    if result is None or not result.queried:
        return ""
    if result.error:
        return result.error
    if not result.value.found:
        return "no record"
    tags = tag_text(result.value.tags)
    return (f"{result.value.malware or 'unnamed'} "
            f"({result.value.confidence}% confidence)"
            f"{f' -- {tags}' if tags else ''}")


def build_story(report: Report, verdict: Verdict | None = None) -> list:
    """Every flowable, in order. Separate from write_pdf so the content can be
    asserted on directly -- there is no PDF text extractor in the dev
    dependencies, and asserting on bytes reportlab just compressed would test
    zlib rather than this module."""
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Threat Intelligence Report", styles['Title']))
    story.append(Paragraph(f"Hash: {_x(report.indicator)}", styles['Normal']))
    story.append(Paragraph(f"Generated: {_x(report.generated_at)}", styles['Normal']))
    story.append(Spacer(1, 12))

    if verdict is not None:
        story.append(Paragraph(
            f"Verdict: {_x(verdict.level)} (score {verdict.score})", styles['Heading1']))
        if verdict.signals:
            story.append(_table(
                [["Points", "Signal", "Why"]]
                + [[f"{s.points:+d}", _fitted(s.name, SIGNAL_WIDTHS[1]),
                    _fitted(s.detail, SIGNAL_WIDTHS[2], DETAIL_CHAR_LIMIT)]
                   for s in verdict.signals],
                widths=SIGNAL_WIDTHS,
            ))
        else:
            story.append(Paragraph("No signals fired.", styles['Normal']))
        if verdict.level == "UNKNOWN" and report.vt.unavailable:
            # Same caveat tty.py's render_verdict prints, sharing its exact
            # wording via VT_UNAVAILABLE_NOTE, and for the same reason: a
            # written report an analyst files should not show a bare
            # UNKNOWN when VT never actually answered -- the Phase 4 KEV
            # bug was exactly this asymmetry, a failed fetch reading as a
            # clean answer on one surface and not the other. Only the
            # interpolated error value is escaped, per this module's own
            # rule -- the template text is this module's own markup.
            story.append(Paragraph(
                f"Note: {VT_UNAVAILABLE_NOTE.format(error=_x(report.vt.error))}",
                styles['Normal']))
        story.append(Spacer(1, 12))

    if report.vt.detection:
        story.append(Paragraph("Detections", styles['Heading1']))
        story.append(Paragraph(
            f"{_x(report.vt.detection.ratio)} engines flagged this file "
            f"(suspicious {report.vt.detection.suspicious}, "
            f"undetected {report.vt.detection.undetected})", styles['Normal']))
        story.append(Spacer(1, 12))

    story.append(Paragraph("OTX Intelligence", styles['Heading1']))
    story.append(Paragraph(
        f"Recorded Instances: {_x(report.otx.recorded_instances)}", styles['Normal']))
    for technique in report.otx.attack_techniques:
        story.append(Paragraph(f"• {_x(technique)}", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("AbuseIPDB", styles['Heading1']))
    story.append(_table(
        [["IP", "Confidence", "Reports"]]
        + [[_x(i.ip), f"{_x(i.confidence)}%", _x(i.reports)] for i in report.ips.values()]
    ))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Censys Enrichment", styles['Heading1']))
    story.append(_table(
        [["IP", "Org", "ASN", "Country", "Ports"]]
        # An errored host used to render as a row of "None": the lookup failed
        # and the PDF showed it as a host Censys had nothing on. Say which.
        + [[Paragraph(_x(h.ip)), Paragraph(_x(h.error)), "", "", ""] if h.error
           else [Paragraph(_x(h.ip)), Paragraph(_x(h.org or "N/A")), Paragraph(_x(h.asn)),
                 Paragraph(_x(h.country)),
                 Paragraph(_x(", ".join(str(p) for p in h.ports)))]
           for h in report.hosts],
        widths=[80, 120, 70, 60, 120],
    ))
    story.append(Spacer(1, 12))

    story.append(Paragraph("WHOIS Data", styles['Heading1']))
    story.append(_table(
        [["Domain", "Created", "Expires", "Registrar"]]
        + [[Paragraph(_x(w.domain)), Paragraph(_x(w.created)),
            Paragraph(_x(w.expires)), Paragraph(_x(w.registrar))]
           for w in report.whois if not w.error],
        widths=[150, 70, 70, 150],
    ))
    story.append(Spacer(1, 12))

    vt = report.vt
    if any((vt.threat, vt.signature, vt.sandbox, vt.yara, vt.pe, vt.techniques)):
        story.append(Paragraph("Attribution", styles['Heading1']))
        if vt.threat:
            story.append(Paragraph(f"Label: {_x(vt.threat.label)}", styles['Normal']))
            if vt.threat.family:
                story.append(Paragraph(f"Family: {_x(vt.threat.family)}", styles['Normal']))
        if vt.signature:
            state = "verified" if vt.signature.verified else "present but NOT verified"
            story.append(Paragraph(
                f"Signature: {state} "
                f"({_x(vt.signature.signer or 'unnamed signer')})",
                styles['Normal']))
        for sandbox in vt.sandbox:
            story.append(Paragraph(
                f"Sandbox: {_x(sandbox.sandbox)} says {_x(sandbox.category)}", styles['Normal']))
        for match in vt.yara:
            story.append(Paragraph(f"YARA: {_x(match.rule)}", styles['Normal']))
        if vt.pe:
            story.append(Paragraph(
                f"PE: {vt.pe.sections} sections, "
                f"imphash {_x(vt.pe.imphash or 'N/A')}, "
                f"compiled {_x(vt.pe.compiled or 'N/A')}", styles['Normal']))
        for technique in vt.techniques:
            tactic = f" ({_x(technique.tactic)})" if technique.tactic else ""
            story.append(Paragraph(
                f"ATT&amp;CK: {_x(technique.id)} {_x(technique.name)}{tactic}", styles['Normal']))
        story.append(Spacer(1, 12))

    if report.bazaar.ok and report.bazaar.value.found:
        story.append(Paragraph("MalwareBazaar", styles['Heading1']))
        story.append(Paragraph(
            f"Family: {_x(report.bazaar.value.family or 'unnamed')}", styles['Normal']))
        if report.bazaar.value.tags:
            story.append(Paragraph(
                f"Tags: {_x(', '.join(report.bazaar.value.tags))}", styles['Normal']))
        story.append(Spacer(1, 12))

    if report.threatfox.ok and report.threatfox.value.found:
        story.append(Paragraph("ThreatFox", styles['Heading1']))
        story.append(Paragraph(
            f"Malware: {_x(report.threatfox.value.malware or 'unnamed')} "
            f"({report.threatfox.value.confidence}% confidence)", styles['Normal']))
        story.append(Spacer(1, 12))

    ip_rows = _ip_rows(report)
    if ip_rows:
        story.append(Paragraph("IP Intelligence", styles['Heading1']))
        story.append(_table(
            [["IP", "Ports", "CVEs", "GreyNoise", "ThreatFox"]]
            + [[_fitted(ip, IP_WIDTHS[0]),
                _fitted(", ".join(str(p) for p in s.value.ports)
                        if s and s.ok else "", IP_WIDTHS[1]),
                _fitted(_cve_cell(s), IP_WIDTHS[2]),
                _fitted(_greynoise_cell(report.greynoise.get(ip)), IP_WIDTHS[3]),
                _fitted(_threatfox_cell(report.threatfox_ips.get(ip)),
                        IP_WIDTHS[4])]
               for ip, s in ip_rows],
            widths=IP_WIDTHS,
        ))
        story.append(Spacer(1, 12))

    if report.kev.ok and report.kev.value.entries:
        entries = report.kev.value.entries
        story.append(Paragraph("Known Exploited Vulnerabilities", styles['Heading1']))
        if len(entries) > KEV_ROW_LIMIT:
            # One row per entry was unbounded, and the reachable maximum is
            # 6850 of them. See KEV_ROW_LIMIT: the total goes here so a
            # shortened table never reads as the whole answer, the same
            # bargain _cve_cell and _capped_join make.
            story.append(Paragraph(
                f"{len(entries)} known exploited vulnerabilities "
                f"(showing {KEV_ROW_LIMIT}); the full list is in the JSON "
                f"report.", styles['Normal']))
        story.append(_table(
            [["CVE", "Product", "Added"]]
            + [[_fitted(e.cve, KEV_WIDTHS[0]),
                _fitted(" ".join(x for x in (e.vendor, e.product) if x),
                        KEV_WIDTHS[1]),
                _fitted(e.date_added or "N/A", KEV_WIDTHS[2])]
               for e in entries[:KEV_ROW_LIMIT]],
            widths=KEV_WIDTHS,
        ))
        story.append(Spacer(1, 12))

    if report.certs.ok and report.certs.value.siblings:
        story.append(Paragraph("Certificate Transparency", styles['Heading1']))
        story.append(Paragraph(
            f"{report.certs.value.count} sibling domains on shared certificates "
            f"(showing {len(report.certs.value.siblings)}): "
            f"{_x(', '.join(report.certs.value.siblings))}", styles['Normal']))
        story.append(Spacer(1, 12))

    story.append(Paragraph("VirusTotal Sigma Rules", styles['Heading1']))
    for level in ('high', 'medium', 'low'):
        story.append(Paragraph(level.upper(), styles['Heading2']))
        rules = report.vt.by_level(level)
        if not rules:
            story.append(Paragraph("None found.", styles['Normal']))
        for rule in rules:
            story.append(Paragraph(
                f"<b>{_x(rule.title)}</b>: {_x(rule.description)}", styles['Normal']))

    return story


def write_pdf(report: Report, path: str, verdict: Verdict | None = None) -> str:
    doc = SimpleDocTemplate(path, pagesize=letter)
    doc.build(build_story(report, verdict))
    print(f"\nReport saved as: {path}")
    return path
