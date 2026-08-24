from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..models import Report

TABLE_STYLE = TableStyle([
    ('BACKGROUND',      (0, 0), (-1, 0), colors.grey),
    ('TEXTCOLOR',       (0, 0), (-1, 0), colors.whitesmoke),
    ('GRID',            (0, 0), (-1, -1), 0.5, colors.black),
    ('ROWBACKGROUNDS',  (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ('WORDWRAP',        (0, 0), (-1, -1), True),
    ('VALIGN',          (0, 0), (-1, -1), 'TOP'),
])


def _table(rows, widths=None) -> Table:
    """One style, three tables. It was copy-pasted per table before."""
    table = Table(rows, colWidths=widths)
    table.setStyle(TABLE_STYLE)
    return table


def write_pdf(report: Report, path: str) -> str:
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Threat Intelligence Report", styles['Title']))
    story.append(Paragraph(f"Hash: {report.indicator}", styles['Normal']))
    story.append(Paragraph(f"Generated: {report.generated_at}", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("OTX Intelligence", styles['Heading1']))
    story.append(Paragraph(
        f"Recorded Instances: {report.otx.recorded_instances}", styles['Normal']))
    for technique in report.otx.attack_techniques:
        story.append(Paragraph(f"• {technique}", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("AbuseIPDB", styles['Heading1']))
    story.append(_table(
        [["IP", "Confidence", "Reports"]]
        + [[i.ip, f"{i.confidence}%", str(i.reports)] for i in report.ips.values()]
    ))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Censys Enrichment", styles['Heading1']))
    story.append(_table(
        [["IP", "Org", "ASN", "Country", "Ports"]]
        + [[Paragraph(h.ip), Paragraph(h.org or "N/A"), Paragraph(str(h.asn)),
            Paragraph(h.country), Paragraph(", ".join(str(p) for p in h.ports))]
           for h in report.hosts],
        widths=[80, 120, 70, 60, 120],
    ))
    story.append(Spacer(1, 12))

    story.append(Paragraph("WHOIS Data", styles['Heading1']))
    story.append(_table(
        [["Domain", "Created", "Expires", "Registrar"]]
        + [[Paragraph(w.domain), Paragraph(w.created),
            Paragraph(w.expires), Paragraph(w.registrar)]
           for w in report.whois if not w.error],
        widths=[150, 70, 70, 150],
    ))
    story.append(Spacer(1, 12))

    story.append(Paragraph("VirusTotal Sigma Rules", styles['Heading1']))
    for level in ('high', 'medium', 'low'):
        story.append(Paragraph(level.upper(), styles['Heading2']))
        rules = report.vt.by_level(level)
        if not rules:
            story.append(Paragraph("None found.", styles['Normal']))
        for rule in rules:
            story.append(Paragraph(
                f"<b>{rule.title}</b>: {rule.description}", styles['Normal']))

    doc.build(story)
    print(f"\nReport saved as: {path}")
    return path
