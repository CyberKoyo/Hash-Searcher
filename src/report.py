from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
from .api.config import BASE_DIR
import os

def generate_pdf(file, hash, vt_summary, otx_summary, ipdb_data, enriched_ips, whois_results):
    output_path = os.path.join(BASE_DIR, file)
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("Threat Intelligence Report", styles['Title']))
    story.append(Paragraph(f"Hash: {hash}", styles['Normal']))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 12))

    # OTX
    story.append(Paragraph("OTX Intelligence", styles['Heading1']))
    story.append(Paragraph(f"Recorded Instances: {otx_summary.get('recorded_instances', 'N/A')}", styles['Normal']))
    for technique in otx_summary.get('attack_techniques', []):
        story.append(Paragraph(f"• {technique}", styles['Normal']))
    story.append(Spacer(1, 12))

    # IPDB Table
    story.append(Paragraph("AbuseIPDB", styles['Heading1']))
    ipdb_table_data = [["IP", "Confidence", "Reports"]]
    for (hostname_tuple, domain_str), ip_info in ipdb_data.items():
        if isinstance(ip_info, dict):
            ipdb_table_data.append([
                ip_info.get("ip", "N/A"),
                f"{ip_info.get('confidence', 'N/A')}%",
                str(ip_info.get("reports", "N/A"))
            ])
    t = Table(ipdb_table_data)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.whitesmoke),
        ('GRID',       (0,0), (-1,-1), 0.5, colors.black),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.lightgrey]),
        ('WORDWRAP',   (0,0), (-1, -1), True),
        ('VALIGN',      (0,0), (-1, -1), 'TOP'),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # Censys Table
    story.append(Paragraph("Censys Enrichment", styles['Heading1']))
    censys_table_data = [["IP", "Org", "ASN", "Country", "Ports"]]
    for entry in enriched_ips:
        censys_table_data.append([
            Paragraph(entry.get("ip", "N/A")),
            Paragraph(entry.get("org", "N/A")),
            Paragraph(str(entry.get("asn", "N/A"))),
            Paragraph(entry.get("country", "N/A")),
            Paragraph(", ".join(str(p) for p in entry.get("ports", [])))
        ])
    t2 = Table(censys_table_data, colWidths=[80, 120, 70, 60, 120])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.whitesmoke),
        ('GRID',       (0,0), (-1,-1), 0.5, colors.black),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.lightgrey]),
        ('WORDWRAP',   (0,0), (-1, -1), True),
        ('VALIGN',      (0,0), (-1, -1), 'TOP'),
    ]))
    story.append(t2)
    story.append(Spacer(1, 12))

    # WHOIS Table
    story.append(Paragraph("WHOIS Data", styles['Heading1']))
    whois_table_data = [["Domain", "Created", "Expires", "Registrar"]]
    for entry in whois_results:
        if "error" not in entry:
            whois_table_data.append([
                Paragraph(entry.get("domain", "N/A")),
                Paragraph(entry.get("created", "N/A")),
                Paragraph(entry.get("expires", "N/A")),
                Paragraph(entry.get("registrar", "N/A"))
            ])
    t3 = Table(whois_table_data, colWidths=[150, 70, 70, 150])
    t3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.whitesmoke),
        ('GRID',       (0,0), (-1,-1), 0.5, colors.black),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.lightgrey]),
        ('WORDWRAP',   (0,0), (-1, -1), True),
        ('VALIGN',      (0,0), (-1, -1), 'TOP'),
    ]))
    story.append(t3)

    # VT Sigma Rules
    story.append(Spacer(1, 12))
    story.append(Paragraph("VirusTotal Sigma Rules", styles['Heading1']))
    for level in ['high', 'medium', 'low']:
        story.append(Paragraph(f"{level.upper()}", styles['Heading2']))
        rules = vt_summary.get(level, [])
        if not rules:
            story.append(Paragraph("None found.", styles['Normal']))
        for rule in rules:
            story.append(Paragraph(f"<b>{rule.get('title')}</b>: {rule.get('description')}", styles['Normal']))

    doc.build(story)
    print(f"\nReport saved as: {output_path}")
    return output_path