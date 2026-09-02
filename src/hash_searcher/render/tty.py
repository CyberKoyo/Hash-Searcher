"""Terminal rendering. The only module in the display path that prints.

Section functions are public so a verdict section can be slotted in without
rewriting render().
"""

from ..models import Report, Verdict

RULE = "=" * 50


def _header(title: str) -> None:
    print("\n" + RULE)
    print(title)
    print(RULE)


def render_vt(report: Report) -> None:
    """Byte-identical to the pre-branch vt_rules(): high/medium/low each have
    their own, genuinely different, formatting -- see formatters.py history.
    """
    print("\nVIRUSTOTAL SIGMA RULES")
    print("\n" + RULE)

    print("HIGH PRIORITY RULES")
    print(RULE)
    high = report.vt.by_level("high")
    if not high:
        print("No High Priority Rules Found.")
    for rule in high:
        print(f"{rule.title}:")
        print(f"{rule.description}. ")
    print('\n')

    print("MEDIUM PRIORITY RULES")
    print(RULE)
    medium = report.vt.by_level("medium")
    if not medium:
        print("No Medium Priority Rules Found.")
    for rule in medium:
        print(f"{rule.title}:")
        print(f"{rule.description}.")
    print('\n')

    print("LOW PRIORITY RULES")
    print(RULE)
    low = report.vt.by_level("low")
    if not low:
        print("No Low Priority Rules Found.")
    for rule in low:
        print(rule.title)
        print(rule.description)


def render_ips(report: Report) -> None:
    w1, w2, w3 = 16, 12, 10
    total = w1 + w2 + w3 + 2
    print("\n" + RULE)
    print(f"{'IP':<{w1}} {'CONFIDENCE':<{w2}} {'REPORTS':<{w3}}")
    print("-" * total)
    if not report.ips:
        # S3: an empty table reads as a bug. main said this explicitly.
        print("No data from IPDB available.")
    for info in report.ips.values():
        print(f"{info.ip:<{w1}} {f'{info.confidence}%':<{w2}} {str(info.reports):<{w3}}")
    print("-" * total)


def render_hosts(report: Report) -> None:
    _header("CENSYS ENRICHMENT")
    for host in report.hosts:
        print(f"\nIP:      {host.ip}")
        if host.error:
            # Matches the string main printed before the extractors were
            # purified; the IP line above is new, and is only useful because
            # fetch_censys now tags the failure with it.
            print(f"Censys: {host.error}")
            continue
        print(f"Org:     {host.org}  |  ASN: {host.asn}")
        print(f"Country: {host.country}")
        print(f"Ports:   {', '.join(str(p) for p in host.ports) if host.ports else 'N/A'}")
        if host.new_hostnames:
            print("[!] New indicators not found in AbuseIPDB:")
            print(f"    Hostnames: {', '.join(host.new_hostnames)}")
        else:
            print("    No new indicators beyond AbuseIPDB data.")


def render_whois(report: Report) -> None:
    _header("WHOIS DATA")
    print(f"{'DOMAIN':<35} {'CREATED':<12} {'EXPIRES':<12} {'REGISTRAR':<30}")
    print("-" * 92)
    for record in report.whois:
        if record.error:
            print(f"{record.domain:<35} Error")
            continue
        print(f"{record.domain:<35} {record.created:<12} "
              f"{record.expires:<12} {record.registrar:<30}")


def render_otx(report: Report) -> None:
    _header("OTX DATA")
    # Mirrors the original's `if not pulse_info:` gate. Keying off the
    # recorded_instances string instead would collide with a real count
    # whose value happens to be "N/A".
    if not report.otx.otx_responded:
        print("No OTX data available.")
        return
    print(f'Recorded instances: {report.otx.recorded_instances}')
    for technique in report.otx.attack_techniques:
        print(technique)


SIGNAL_NAME_WIDTH = 11

#: The caveat both render_verdict (here) and pdf.py's build_story print for
#: an UNKNOWN verdict that rests on a VT call which never actually
#: answered. One template so the load-bearing second clause -- "not
#: confirmation that nobody has seen this sample" -- cannot drift between
#: the two surfaces the way two independently written copies of the same
#: sentence eventually do.
VT_UNAVAILABLE_NOTE = (
    "VirusTotal did not answer ({error}) -- this UNKNOWN is not "
    "confirmation that nobody has seen this sample."
)


def render_verdict(verdict: Verdict, report: Report | None = None) -> None:
    """Score first, then every signal that produced it.

    The rationale lines are the point. A verdict an analyst cannot decompose
    is one they cannot disagree with, which makes it useless to them.

    `report` is optional so every pre-existing call site that passes only a
    verdict keeps working. When it is given and VT's call failed outright
    (not merely a 404), an UNKNOWN here is not "nobody has ever seen this
    sample" -- it is "we do not actually know", and the caveat says so.
    """
    _header(f"VERDICT: {verdict.level} (score {verdict.score})")
    if not verdict.signals:
        print("No signals fired.")
    else:
        for signal in verdict.signals:
            print(f"  {signal.points:+d}  {signal.name:<{SIGNAL_NAME_WIDTH}} {signal.detail}")
    if report is not None and verdict.level == "UNKNOWN" and report.vt.unavailable:
        # Mechanism-neutral on purpose: a missing API key never dialled
        # VirusTotal at all, so "unreachable" would assert something untrue
        # for that case even though the underlying claim -- this UNKNOWN is
        # not confirmation of absence -- holds regardless of why VT never
        # answered. The error text carries the mechanism; this line only
        # carries the fact that VT did not answer.
        print(f"\nNote: {VT_UNAVAILABLE_NOTE.format(error=report.vt.error)}")


def render_static(report: Report) -> None:
    """Local findings from the analyzers in static/. Absent entirely when
    static analysis never ran (--no-static, a bare hash argument, or an
    analyzer-fan-out failure) -- but once report.static exists, `skipped`
    and `failed` are always printed by name, even when both are empty. A
    silently missing section is indistinguishable from a clean result.
    """
    static = report.static
    if static is None:
        return
    _header("STATIC ANALYSIS")
    print(f"File:   {static.path} ({static.size} bytes)")
    print(f"SHA256: {static.sha256}")

    if static.entropy:
        state = "packed" if static.entropy.packed else "normal"
        print(f"Entropy: {static.entropy.overall} ({state}) -- {static.entropy.note}")

    if static.filetype:
        ft = static.filetype
        if ft.mismatch:
            print(f"File type: {ft.detected} -- {ft.note}")
        elif ft.detected:
            print(f"File type: {ft.detected}")

    if static.pe:
        pe = static.pe
        if pe.note:
            print(f"PE: {pe.note}")
        else:
            print(f"PE: {len(pe.sections)} sections, "
                  f"{sum(len(names) for names in pe.imports.values())} imports, "
                  f"compiled {pe.compiled or 'N/A'}")
            if pe.suspicious_imports:
                print(f"Suspicious imports: {', '.join(pe.suspicious_imports)}")
        if pe.section_entropy_note:
            print(f"PE: {pe.section_entropy_note}")

    for hit in static.yara:
        print(f"YARA:   {hit.rule} ({hit.namespace})")
    if static.yara_note:
        print(f"YARA:   {static.yara_note}")

    if static.strings:
        iocs = static.strings.iocs
        print(f"Strings: {static.strings.count} extracted, "
              f"{len(iocs.ips)} IPs, {len(iocs.domains)} domains, {len(iocs.urls)} URLs")

    print(f"Skipped: {', '.join(static.skipped) if static.skipped else 'none'}")
    print(f"Failed:  {', '.join(static.failed) if static.failed else 'none'}")


def render_detection(report: Report) -> None:
    detection = report.vt.detection
    if not detection:
        return
    print(f"\nDetections: {detection.ratio}"
          f"  (suspicious {detection.suspicious}, undetected {detection.undetected})")


def render_attribution(report: Report) -> None:
    """Family, signature, sandbox, YARA, PE, submissions, ATT&CK -- whichever
    of them VT actually returned. Silent when it returned none."""
    vt = report.vt
    if not any((vt.threat, vt.signature, vt.sandbox, vt.yara, vt.pe,
                vt.techniques, vt.submission and vt.submission.times_submitted)):
        return
    _header("ATTRIBUTION")
    if vt.threat:
        print(f"Label:      {vt.threat.label}")
        if vt.threat.family:
            print(f"Family:     {vt.threat.family}")
        if vt.threat.categories:
            print(f"Categories: {', '.join(vt.threat.categories)}")
    if vt.signature:
        state = "verified" if vt.signature.verified else "present but NOT verified"
        print(f"Signature:  {state} ({vt.signature.signer or 'unnamed signer'})")
    for verdict in vt.sandbox:
        names = f" -- {', '.join(verdict.malware_names)}" if verdict.malware_names else ""
        print(f"Sandbox:    {verdict.sandbox} says {verdict.category}{names}")
    for match in vt.yara:
        print(f"YARA:       {match.rule} ({match.author or 'unknown author'})")
    if vt.pe:
        print(f"PE:         {vt.pe.sections} sections, "
              f"imphash {vt.pe.imphash or 'N/A'}, compiled {vt.pe.compiled or 'N/A'}")
    if vt.submission and vt.submission.times_submitted:
        print(f"Submitted:  {vt.submission.times_submitted} times, "
              f"first seen {vt.submission.first_seen or 'N/A'}")
        if vt.submission.names:
            print(f"Names:      {', '.join(vt.submission.names)}")
    for technique in vt.techniques:
        tactic = f" ({technique.tactic})" if technique.tactic else ""
        print(f"ATT&CK:     {technique.id} {technique.name}{tactic}")


def render_domains(report: Report) -> None:
    """contacted_domains has been fetched since Phase 0 and never printed."""
    if not report.vt.contacted_domains:
        return
    _header("CONTACTED DOMAINS")
    for domain in report.vt.contacted_domains:
        print(domain)


def render_bazaar(report: Report) -> None:
    """MalwareBazaar's answer. Absent only when the source never ran.

    found=False with no error prints a line rather than nothing: "abuse.ch
    has never seen this sample" is an answer, and a different one from "we
    could not ask abuse.ch".
    """
    bazaar = report.bazaar
    if not bazaar.queried:
        return
    _header("MALWAREBAZAAR")
    if bazaar.error:
        print(f"MalwareBazaar: {bazaar.error}")
        return
    if not bazaar.value.found:
        print("MalwareBazaar has no record of this sample.")
        return
    print(f"Family:     {bazaar.value.family or 'unnamed'}")
    if bazaar.value.file_type:
        print(f"File type:  {bazaar.value.file_type}")
    if bazaar.value.first_seen:
        print(f"First seen: {bazaar.value.first_seen}")
    if bazaar.value.tags:
        print(f"Tags:       {', '.join(bazaar.value.tags)}")
    if bazaar.value.yara:
        print(f"YARA:       {', '.join(bazaar.value.yara)}")


def render_threatfox(report: Report) -> None:
    threatfox = report.threatfox
    if not threatfox.queried:
        return
    _header("THREATFOX")
    if threatfox.error:
        print(f"ThreatFox: {threatfox.error}")
        return
    if not threatfox.value.found:
        print("ThreatFox has no record of this indicator.")
        return
    print(f"Malware:    {threatfox.value.malware or 'unnamed'} "
          f"({threatfox.value.confidence}% confidence)")
    if threatfox.value.tags:
        print(f"Tags:       {', '.join(threatfox.value.tags)}")


#: A real Shodan answer for a busy web server carries well over a hundred
#: CVEs. Printed whole they are one unreadable line that buries every
#: section under it -- so the list is capped and the total printed beside
#: it, the same bargain render_certs makes with sibling domains. The full
#: list is still in the JSON report.
CVE_DISPLAY_LIMIT = 12

#: ThreatFox tags for a busy C2 address run to dozens. Same bargain as
#: CVE_DISPLAY_LIMIT: the list is capped and the total printed beside it, so
#: a truncated list never reads as the whole answer. Shared with pdf.py,
#: where the cap is load-bearing rather than cosmetic -- an unbounded
#: provider list in a table cell raises LayoutError.
TAG_DISPLAY_LIMIT = 8


def tag_text(tags: list[str]) -> str:
    """A capped, honestly-labelled tag list, or "" when there are none."""
    if not tags:
        return ""
    shown = ", ".join(tags[:TAG_DISPLAY_LIMIT])
    if len(tags) <= TAG_DISPLAY_LIMIT:
        return f"tags: {shown}"
    return f"{len(tags)} tags (showing {TAG_DISPLAY_LIMIT}): {shown}"


def queried_ips(report: Report) -> list[str]:
    """Every contacted IP at least one per-IP source actually answered for.

    The dicts cannot be the gate. They hold SourceResults, which have no
    __bool__, so a dict of nothing but never-asked results is non-empty and
    therefore truthy -- `if not report.shodan and not report.greynoise`
    passed, the section header printed, and each IP rendered as a bare
    `IP: x.x.x.x` line with nothing under it. Asking whether anything was
    queried is the question the guard meant to ask all along, and it stops
    mattering only in theory once a THIRD per-IP dict exists: one source
    populated and another not is exactly the state threatfox_ips creates.

    pdf.py's IP table shares this, so the two surfaces cannot drift into
    disagreeing about which addresses are worth a row.
    """
    per_ip = (report.shodan, report.greynoise, report.threatfox_ips)
    return [ip for ip in dict.fromkeys(k for source in per_ip for k in source)
            if any(ip in source and source[ip].queried for source in per_ip)]


def render_ip_intel(report: Report) -> None:
    """Shodan exposure, GreyNoise noise-vs-targeted, and ThreatFox's C2
    attribution, per contacted IP."""
    ips = queried_ips(report)
    if not ips:
        return
    _header("IP INTELLIGENCE")
    for ip in ips:
        print(f"\nIP:      {ip}")
        shodan = report.shodan.get(ip)
        if shodan and shodan.error:
            print(f"Shodan:  {shodan.error}")
        elif shodan and shodan.ok:
            ports, vulns, hostnames = (shodan.value.ports, shodan.value.vulns,
                                        shodan.value.hostnames)
            print(f"Ports:   {', '.join(str(p) for p in ports) or 'none known'}")
            if vulns:
                shown = vulns[:CVE_DISPLAY_LIMIT]
                more = (f" (showing {CVE_DISPLAY_LIMIT})"
                        if len(vulns) > CVE_DISPLAY_LIMIT else "")
                print(f"CVEs:    {len(vulns)} CVEs{more}: "
                      f"{', '.join(shown)}")
            if hostnames:
                print(f"Names:   {', '.join(hostnames)}")
        noise = report.greynoise.get(ip)
        if noise and noise.error:
            print(f"GreyNoise: {noise.error}")
        elif noise and noise.ok and noise.value.seen:
            actor = f" -- {noise.value.name}" if noise.value.name else ""
            print(f"GreyNoise: {noise.value.classification or 'seen'}{actor}, "
                  f"last seen {noise.value.last_seen or 'N/A'}")
        elif noise and noise.ok:
            # The more interesting answer of the two: an address GreyNoise
            # has never seen scanning is not internet background noise.
            print("GreyNoise: not observed scanning the internet")
        # The one thing neither source above says: which malware family the
        # address belongs to. Same three-way split as GreyNoise -- a failed
        # lookup, a hit, and a clean "no record", with a source nobody asked
        # rendering as silence.
        threatfox = report.threatfox_ips.get(ip)
        if threatfox and threatfox.error:
            print(f"ThreatFox: {threatfox.error}")
        elif threatfox and threatfox.ok and threatfox.value.found:
            tags = tag_text(threatfox.value.tags)
            print(f"ThreatFox: {threatfox.value.malware or 'unnamed'} "
                  f"({threatfox.value.confidence}% confidence)"
                  f"{f', {tags}' if tags else ''}")
        elif threatfox and threatfox.ok:
            print("ThreatFox: no C2 record for this address")


def render_kev(report: Report) -> None:
    """Silent when nothing was checked, AND when the check found nothing.

    An unreachable CISA is not the same answer as "none of these CVEs are
    known-exploited", and it suppresses the strongest signal the tool has,
    so it gets a line of its own rather than an absent section.

    The two silent cases are the ones with nothing to say: nobody asked
    (`queried is False`), and the catalog answered with no hits. This
    docstring used to claim the first was the ONLY silent case, which was
    false of the second and had been since the section was written -- a
    false claim in a docstring is the same defect as a false claim in a
    comment, and the shape here is right, so the docstring is what changes.
    """
    kev = report.kev
    if not kev.queried:
        return
    if kev.error:
        _header("KNOWN EXPLOITED VULNERABILITIES")
        print(f"CISA KEV was unreachable ({kev.error}) -- "
              f"{kev.value.unchecked} CVEs on contacted hosts went unchecked.")
        return
    if not kev.value.entries:
        return
    _header("KNOWN EXPLOITED VULNERABILITIES")
    for entry in kev.value.entries:
        product = " ".join(x for x in (entry.vendor, entry.product) if x)
        ransomware = "  [ransomware campaign]" if entry.ransomware else ""
        print(f"{entry.cve}  {product or 'unknown product'} -- "
              f"{entry.name or 'no title'} (added {entry.date_added or 'N/A'})"
              f"{ransomware}")


def render_certs(report: Report) -> None:
    """Certificate-transparency siblings. Informational, and scored at zero
    on purpose -- see scoring.py. The count is printed alongside a capped
    list because a truncated list that reads as complete is worse than none.
    """
    certs = report.certs
    if not certs.queried:
        return
    _header("CERTIFICATE TRANSPARENCY")
    if certs.error:
        print(f"crt.sh: {certs.error}")
        return
    if not certs.value.siblings:
        print("No certificates found for the contacted domains.")
        return
    shown = len(certs.value.siblings)
    tail = f" (showing {shown})" if shown < certs.value.count else ""
    print(f"{certs.value.count} sibling domains on shared certificates{tail}:")
    for domain in certs.value.siblings:
        print(f"  {domain}")


def render(report: Report, verdict: Verdict | None = None) -> None:
    if verdict is not None:
        render_verdict(verdict, report)
    render_static(report)
    render_detection(report)
    render_vt(report)
    render_attribution(report)
    # Gate on whether VT actually returned contacted IPs, not on whether
    # AbuseIPDB happened to yield usable data -- see main.py history. This
    # keeps the TTY and JSON/PDF outputs in agreement regardless of which
    # of AbuseIPDB/Censys/WHOIS succeeded.
    render_bazaar(report)
    render_threatfox(report)
    if report.vt.contacted_ips:
        render_ips(report)
        render_hosts(report)
        render_whois(report)
    render_ip_intel(report)
    render_kev(report)
    render_domains(report)
    render_certs(report)
    render_otx(report)
