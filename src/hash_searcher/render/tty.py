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


def render_verdict(verdict: Verdict) -> None:
    """Score first, then every signal that produced it.

    The rationale lines are the point. A verdict an analyst cannot decompose
    is one they cannot disagree with, which makes it useless to them.
    """
    _header(f"VERDICT: {verdict.level} (score {verdict.score})")
    if not verdict.signals:
        print("No signals fired.")
        return
    for signal in verdict.signals:
        print(f"  {signal.points:+d}  {signal.name:<{SIGNAL_NAME_WIDTH}} {signal.detail}")


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
    if bazaar is None:
        return
    _header("MALWAREBAZAAR")
    if bazaar.error:
        print(f"MalwareBazaar: {bazaar.error}")
        return
    if not bazaar.found:
        print("MalwareBazaar has no record of this sample.")
        return
    print(f"Family:     {bazaar.family or 'unnamed'}")
    if bazaar.file_type:
        print(f"File type:  {bazaar.file_type}")
    if bazaar.first_seen:
        print(f"First seen: {bazaar.first_seen}")
    if bazaar.tags:
        print(f"Tags:       {', '.join(bazaar.tags)}")
    if bazaar.yara:
        print(f"YARA:       {', '.join(bazaar.yara)}")


def render_threatfox(report: Report) -> None:
    threatfox = report.threatfox
    if threatfox is None:
        return
    _header("THREATFOX")
    if threatfox.error:
        print(f"ThreatFox: {threatfox.error}")
        return
    if not threatfox.found:
        print("ThreatFox has no record of this indicator.")
        return
    print(f"Malware:    {threatfox.malware or 'unnamed'} "
          f"({threatfox.confidence}% confidence)")
    if threatfox.tags:
        print(f"Tags:       {', '.join(threatfox.tags)}")


#: A real Shodan answer for a busy web server carries well over a hundred
#: CVEs. Printed whole they are one unreadable line that buries every
#: section under it -- so the list is capped and the total printed beside
#: it, the same bargain render_certs makes with sibling domains. The full
#: list is still in the JSON report.
CVE_DISPLAY_LIMIT = 12


def render_ip_intel(report: Report) -> None:
    """Shodan exposure and GreyNoise noise-vs-targeted, per contacted IP."""
    if not report.shodan and not report.greynoise:
        return
    _header("IP INTELLIGENCE")
    for ip in dict.fromkeys((*report.shodan, *report.greynoise)):
        print(f"\nIP:      {ip}")
        shodan = report.shodan.get(ip)
        if shodan and shodan.error:
            print(f"Shodan:  {shodan.error}")
        elif shodan:
            print(f"Ports:   {', '.join(str(p) for p in shodan.ports) or 'none known'}")
            if shodan.vulns:
                shown = shodan.vulns[:CVE_DISPLAY_LIMIT]
                more = (f" (showing {CVE_DISPLAY_LIMIT})"
                        if len(shodan.vulns) > CVE_DISPLAY_LIMIT else "")
                print(f"CVEs:    {len(shodan.vulns)} CVEs{more}: "
                      f"{', '.join(shown)}")
            if shodan.hostnames:
                print(f"Names:   {', '.join(shodan.hostnames)}")
        noise = report.greynoise.get(ip)
        if noise and noise.error:
            print(f"GreyNoise: {noise.error}")
        elif noise and noise.seen:
            actor = f" -- {noise.name}" if noise.name else ""
            print(f"GreyNoise: {noise.classification or 'seen'}{actor}, "
                  f"last seen {noise.last_seen or 'N/A'}")
        elif noise:
            # The more interesting answer of the two: an address GreyNoise
            # has never seen scanning is not internet background noise.
            print("GreyNoise: not observed scanning the internet")


def render_kev(report: Report) -> None:
    """Silent only when there was nothing to check.

    An unreachable CISA is not the same answer as "none of these CVEs are
    known-exploited", and it suppresses the strongest signal the tool has,
    so it gets a line of its own rather than an absent section.
    """
    if report.kev_error:
        _header("KNOWN EXPLOITED VULNERABILITIES")
        print(f"CISA KEV was unreachable ({report.kev_error}) -- "
              f"{report.kev_unchecked} CVEs on contacted hosts went unchecked.")
        return
    if not report.kev:
        return
    _header("KNOWN EXPLOITED VULNERABILITIES")
    for entry in report.kev:
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
    if certs is None:
        return
    _header("CERTIFICATE TRANSPARENCY")
    if certs.error:
        print(f"crt.sh: {certs.error}")
        return
    if not certs.siblings:
        print("No certificates found for the contacted domains.")
        return
    shown = len(certs.siblings)
    tail = f" (showing {shown})" if shown < certs.count else ""
    print(f"{certs.count} sibling domains on shared certificates{tail}:")
    for domain in certs.siblings:
        print(f"  {domain}")


def render(report: Report, verdict: Verdict | None = None) -> None:
    if verdict is not None:
        render_verdict(verdict)
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
