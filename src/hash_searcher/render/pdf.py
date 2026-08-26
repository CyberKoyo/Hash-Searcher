from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..models import Report, Verdict

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


def _table(rows, widths=None) -> Table:
    """One style, three tables. It was copy-pasted per table before."""
    table = Table(rows, colWidths=widths)
    table.setStyle(TABLE_STYLE)
    return table


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
                + [[f"{s.points:+d}", Paragraph(_x(s.name)), Paragraph(_x(s.detail))]
                   for s in verdict.signals],
                widths=[50, 90, 250],
            ))
        else:
            story.append(Paragraph("No signals fired.", styles['Normal']))
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
        + [[Paragraph(_x(h.ip)), Paragraph(_x(h.org or "N/A")), Paragraph(_x(h.asn)),
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
