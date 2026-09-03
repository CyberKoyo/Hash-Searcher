"""The report as a pasteable ticket comment.

What an analyst actually does with a finding is paste it into a ticket, a
chat channel, or a wiki page -- all three of which render Markdown and none
of which render a PDF inline. This is that surface.

**Every provider-supplied value goes through `cell()`, without exception.**
A `|` inside a family name or a sandbox verdict is a cell boundary: the row
gains a column, and every value after it renders under the wrong header. A
newline is worse -- it ends the row, and the rest of the record renders as a
loose paragraph. This is the same bug class as the unescaped `<` that cost
Phase 2 a Critical in the PDF, and the reason `cell()` is applied uniformly
rather than only at the sites that are tables today: a value that moves from
a bullet into a table later must not become a defect by being moved.

Consumes the model, never the TTY's printed output.
"""

from ..models import Report, Verdict

#: Verdict-table and signal-table headers, so a reader of a pasted comment
#: sees the same three columns the terminal prints.
_SIGNAL_COLUMNS = ("Signal", "Points", "Detail")


def cell(value) -> str:
    """One value, safe to place between two pipes.

    Whitespace is collapsed rather than escaped: a cell is a single line by
    construction in every Markdown dialect, so a newline has no rendering
    to preserve. `\\` is escaped before `|`, otherwise escaping the pipe
    would produce a backslash that a following escape could pair with.
    """
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _table(headers, rows) -> list[str]:
    """A pipe table, or nothing at all when there are no rows.

    An empty table with a header and no body renders as a header floating
    over a rule, which reads as "we looked and the answer is nothing" --
    the caller decides whether that is true, so this returns nothing and
    lets the caller's own guard speak.
    """
    rows = list(rows)
    if not rows:
        return []
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(cell(v) for v in row) + " |" for row in rows)
    return lines


def _verdict_lines(verdict: Verdict) -> list[str]:
    lines = ["## Verdict", ""]
    lines.extend(_table(("Level", "Score"), [(verdict.level, verdict.score)]))
    lines.append("")
    if not verdict.signals:
        lines.append("No signals fired.")
        return lines
    lines.extend(_table(_SIGNAL_COLUMNS,
                        [(s.name, f"{s.points:+d}", s.detail)
                         for s in verdict.signals]))
    return lines


def _detection_lines(report: Report) -> list[str]:
    detection = report.vt.detection
    if detection is None:
        return []
    return [
        "## Detections", "",
        f"**{cell(detection.ratio)}** engines flagged this sample "
        f"({cell(detection.suspicious)} suspicious, "
        f"{cell(detection.undetected)} undetected).",
    ]


def _attribution_lines(report: Report) -> list[str]:
    """VirusTotal's own attribution, which is several optional blocks.

    Silent when every one of them is absent, rather than a heading over
    nothing.
    """
    vt = report.vt
    body = []
    if vt.threat:
        body.append(f"- Label: {cell(vt.threat.label)}")
        if vt.threat.family:
            body.append(f"- Family: {cell(vt.threat.family)}")
        if vt.threat.categories:
            body.append(f"- Categories: {', '.join(cell(c) for c in vt.threat.categories)}")
    if vt.signature:
        state = "signed" if vt.signature.verified else "unverified signature"
        body.append(f"- Signature: {cell(state)} "
                    f"({cell(vt.signature.signer or 'unnamed signer')})")
    for verdict in vt.sandbox:
        names = (f" -- {', '.join(cell(n) for n in verdict.malware_names)}"
                 if verdict.malware_names else "")
        body.append(f"- Sandbox: {cell(verdict.sandbox)} says "
                    f"{cell(verdict.category)}{names}")
    for match in vt.yara:
        body.append(f"- YARA: {cell(match.rule)} "
                    f"({cell(match.author or 'unknown author')})")
    if vt.pe:
        body.append(f"- PE: {cell(vt.pe.sections)} sections, imphash "
                    f"{cell(vt.pe.imphash or 'N/A')}, compiled "
                    f"{cell(vt.pe.compiled or 'N/A')}")
    if vt.submission and vt.submission.times_submitted:
        body.append(f"- Submitted: {cell(vt.submission.times_submitted)} times, "
                    f"first seen {cell(vt.submission.first_seen or 'N/A')}")
    for technique in vt.techniques:
        tactic = f" ({cell(technique.tactic)})" if technique.tactic else ""
        body.append(f"- ATT&CK: {cell(technique.id)} {cell(technique.name)}{tactic}")
    if not body:
        return []
    return ["## Attribution", ""] + body


def _vt_note_lines(report: Report) -> list[str]:
    """VirusTotal's failure, said out loud.

    Task A3's whole point: an unreachable VT is not a sample VT has no
    record of, and a pasted ticket comment that omits the difference tells
    the next reader the sample is unknown when nobody actually asked.
    """
    vt = report.vt
    if not vt.error:
        return []
    state = ("VirusTotal could not be reached" if vt.unavailable
             else "VirusTotal has no record of this indicator")
    return ["## VirusTotal", "", f"{state}: {cell(vt.error)}"]


def _bazaar_lines(report: Report) -> list[str]:
    bazaar = report.bazaar
    if not bazaar.queried:
        return []
    lines = ["## MalwareBazaar", ""]
    if bazaar.error:
        return lines + [f"Lookup failed: {cell(bazaar.error)}"]
    if not bazaar.value.found:
        return lines + ["abuse.ch has no record of this sample."]
    lines.append(f"- Family: {cell(bazaar.value.family or 'unnamed')}")
    if bazaar.value.file_type:
        lines.append(f"- File type: {cell(bazaar.value.file_type)}")
    if bazaar.value.first_seen:
        lines.append(f"- First seen: {cell(bazaar.value.first_seen)}")
    if bazaar.value.tags:
        lines.append(f"- Tags: {', '.join(cell(t) for t in bazaar.value.tags)}")
    if bazaar.value.yara:
        lines.append(f"- YARA: {', '.join(cell(y) for y in bazaar.value.yara)}")
    return lines


def _threatfox_lines(report: Report) -> list[str]:
    threatfox = report.threatfox
    if not threatfox.queried:
        return []
    lines = ["## ThreatFox", ""]
    if threatfox.error:
        return lines + [f"Lookup failed: {cell(threatfox.error)}"]
    if not threatfox.value.found:
        return lines + ["ThreatFox has no record of this indicator."]
    lines.append(f"- Malware: {cell(threatfox.value.malware or 'unnamed')} "
                 f"({cell(threatfox.value.confidence)}% confidence)")
    if threatfox.value.tags:
        lines.append(f"- Tags: {', '.join(cell(t) for t in threatfox.value.tags)}")
    return lines


def _ip_lines(report: Report) -> list[str]:
    """AbuseIPDB's table for the contacted addresses."""
    if not report.ips:
        return []
    rows = [(info.ip, f"{info.confidence}%", info.reports,
             ", ".join(info.hostnames) or "none")
            for info in report.ips.values()]
    return (["## Contacted IPs", ""]
            + _table(("IP", "Abuse confidence", "Reports", "Hostnames"), rows))


def _ip_intel_lines(report: Report) -> list[str]:
    """Shodan / GreyNoise / ThreatFox, per contacted address.

    `queried_ips` is shared with the TTY and the PDF rather than
    re-derived, so the three surfaces cannot disagree about which
    addresses are worth a row -- and so that a dict full of never-asked
    SourceResults (all truthy, none answered) cannot produce a table of
    empty rows.
    """
    from .tty import queried_ips  # circular at module scope: tty imports models only

    ips = queried_ips(report)
    if not ips:
        return []
    rows = []
    for ip in ips:
        shodan = report.shodan.get(ip)
        noise = report.greynoise.get(ip)
        fox = report.threatfox_ips.get(ip)
        if shodan is None or not shodan.queried:
            ports = "not asked"
        elif shodan.error:
            ports = f"error: {shodan.error}"
        else:
            ports = ", ".join(str(p) for p in shodan.value.ports) or "none known"
        if noise is None or not noise.queried:
            classification = "not asked"
        elif noise.error:
            classification = f"error: {noise.error}"
        elif noise.value.seen:
            classification = noise.value.classification or "seen"
        else:
            classification = "not observed scanning"
        if fox is None or not fox.queried:
            malware = "not asked"
        elif fox.error:
            malware = f"error: {fox.error}"
        elif fox.value.found:
            malware = f"{fox.value.malware or 'unnamed'} ({fox.value.confidence}%)"
        else:
            malware = "no C2 record"
        rows.append((ip, ports, classification, malware))
    return (["## IP intelligence", ""]
            + _table(("IP", "Shodan ports", "GreyNoise", "ThreatFox"), rows))


def _kev_lines(report: Report) -> list[str]:
    """Silent when nobody asked and when the catalog found nothing.

    An unreachable CISA gets a line of its own: it suppresses the strongest
    signal the tool has, and an absent section would read as "none of these
    CVEs are known-exploited".
    """
    kev = report.kev
    if not kev.queried:
        return []
    heading = ["## Known exploited vulnerabilities", ""]
    if kev.error:
        unchecked = kev.value.unchecked if kev.value else 0
        return heading + [f"CISA KEV was unreachable ({cell(kev.error)}) -- "
                          f"{cell(unchecked)} CVEs went unchecked."]
    if not kev.value.entries:
        return []
    rows = [(e.cve, " ".join(x for x in (e.vendor, e.product) if x) or "unknown",
             e.name or "no title", e.date_added or "N/A",
             "yes" if e.ransomware else "no")
            for e in kev.value.entries]
    return heading + _table(("CVE", "Product", "Name", "Added", "Ransomware"), rows)


def _domain_lines(report: Report) -> list[str]:
    if not report.vt.contacted_domains:
        return []
    return (["## Contacted domains", ""]
            + [f"- {cell(d)}" for d in report.vt.contacted_domains])


def _cert_lines(report: Report) -> list[str]:
    certs = report.certs
    if not certs.queried:
        return []
    lines = ["## Certificate transparency", ""]
    if certs.error:
        return lines + [f"Lookup failed: {cell(certs.error)}"]
    if not certs.value.siblings:
        return lines + ["No certificates found for the contacted domains."]
    shown = len(certs.value.siblings)
    tail = f" (showing {shown})" if shown < certs.value.count else ""
    lines.append(f"{cell(certs.value.count)} sibling domains on shared "
                 f"certificates{tail}:")
    lines.append("")
    lines.extend(f"- {cell(d)}" for d in certs.value.siblings)
    return lines


def _otx_lines(report: Report) -> list[str]:
    otx = report.otx
    if otx.error:
        return ["## OTX", "", f"Lookup failed: {cell(otx.error)}"]
    if not otx.otx_responded:
        return []
    lines = ["## OTX", "", f"Recorded instances: {cell(otx.recorded_instances)}"]
    if otx.attack_techniques:
        lines.append("")
        lines.extend(f"- {cell(t)}" for t in otx.attack_techniques)
    return lines


def _static_lines(report: Report) -> list[str]:
    static = report.static
    if static is None:
        return []
    lines = ["## Static analysis", "",
             f"- File: {cell(static.path)} ({cell(static.size)} bytes)",
             f"- SHA256: {cell(static.sha256)}"]
    if static.entropy:
        state = "packed" if static.entropy.packed else "not packed"
        lines.append(f"- Entropy: {cell(static.entropy.overall)} ({state})")
    if static.filetype and static.filetype.detected:
        mismatch = " -- extension mismatch" if static.filetype.mismatch else ""
        lines.append(f"- File type: {cell(static.filetype.detected)}{mismatch}")
    if static.pe and static.pe.suspicious_imports:
        lines.append("- Suspicious imports: "
                     + ", ".join(cell(i) for i in static.pe.suspicious_imports))
    for hit in static.yara:
        lines.append(f"- YARA: {cell(hit.rule)} ({cell(hit.namespace)})")
    if static.strings:
        lines.append(f"- Strings: {cell(static.strings.count)} extracted")
    return lines


def to_markdown(report: Report, verdict: Verdict | None = None) -> str:
    """The whole report, one Markdown document, ending in a single newline."""
    lines = [f"# {cell(report.indicator)}", "",
             f"- Kind: {cell(report.indicator_kind)}",
             f"- Generated: {cell(report.generated_at)}"]
    if report.source_file and report.source_file != report.indicator:
        lines.append(f"- Source file: {cell(report.source_file)}")

    sections = []
    if verdict is not None:
        sections.append(_verdict_lines(verdict))
    sections.extend([
        _static_lines(report),
        _detection_lines(report),
        _vt_note_lines(report),
        _attribution_lines(report),
        _bazaar_lines(report),
        _threatfox_lines(report),
        _ip_lines(report),
        _ip_intel_lines(report),
        _kev_lines(report),
        _domain_lines(report),
        _cert_lines(report),
        _otx_lines(report),
    ])
    for section in sections:
        if section:
            lines.append("")
            lines.extend(section)
    return "\n".join(lines) + "\n"


def write_markdown(report: Report, path: str,
                   verdict: Verdict | None = None) -> str:
    with open(path, "w", encoding="utf-8") as out:
        out.write(to_markdown(report, verdict))
    return path
