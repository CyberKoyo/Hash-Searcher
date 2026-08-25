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


def write_pdf(report: Report, path: str, verdict=None) -> str:
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Threat Intelligence Report", styles['Title']))
    story.append(Paragraph(f"Hash: {report.indicator}", styles['Normal']))
    story.append(Paragraph(f"Generated: {report.generated_at}", styles['Normal']))
    story.append(Spacer(1, 12))

    if verdict is not None:
        story.append(Paragraph(
            f"Verdict: {verdict.level} (score {verdict.score})", styles['Heading1']))
        if verdict.signals:
            story.append(_table(
                [["Points", "Signal", "Why"]]
                + [[f"{s.points:+d}", Paragraph(s.name), Paragraph(s.detail)]
                   for s in verdict.signals],
                widths=[50, 90, 250],
            ))
        else:
            story.append(Paragraph("No signals fired.", styles['Normal']))
        story.append(Spacer(1, 12))

    if report.vt.detection:
        story.append(Paragraph("Detections", styles['Heading1']))
        story.append(Paragraph(
            f"{report.vt.detection.ratio} engines flagged this file "
            f"(suspicious {report.vt.detection.suspicious}, "
            f"undetected {report.vt.detection.undetected})", styles['Normal']))
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

    vt = report.vt
    if any((vt.threat, vt.signature, vt.sandbox, vt.yara, vt.pe, vt.techniques)):
        story.append(Paragraph("Attribution", styles['Heading1']))
        if vt.threat:
            story.append(Paragraph(f"Label: {vt.threat.label}", styles['Normal']))
            if vt.threat.family:
                story.append(Paragraph(f"Family: {vt.threat.family}", styles['Normal']))
        if vt.signature:
            state = "verified" if vt.signature.verified else "present but NOT verified"
            story.append(Paragraph(
                f"Signature: {state} ({vt.signature.signer or 'unnamed signer'})",
                styles['Normal']))
        for sandbox in vt.sandbox:
            story.append(Paragraph(
                f"Sandbox: {sandbox.sandbox} says {sandbox.category}", styles['Normal']))
        for match in vt.yara:
            story.append(Paragraph(f"YARA: {match.rule}", styles['Normal']))
        if vt.pe:
            story.append(Paragraph(
                f"PE: {vt.pe.sections} sections, imphash {vt.pe.imphash or 'N/A'}, "
                f"compiled {vt.pe.compiled or 'N/A'}", styles['Normal']))
        for technique in vt.techniques:
            tactic = f" ({technique.tactic})" if technique.tactic else ""
            story.append(Paragraph(
                f"ATT&amp;CK: {technique.id} {technique.name}{tactic}", styles['Normal']))
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
