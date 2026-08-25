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
    print("-" * 89)
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
    if not report.otx.has_pulse_info:
        print("No OTX data available.")
        return
    print(f'Recorded instances: {report.otx.recorded_instances}')
    for technique in report.otx.attack_techniques:
        print(technique)


SIGNAL_NAME_WIDTH = 11


def render_verdict(report: Report, verdict: Verdict) -> None:
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


def render(report: Report, verdict: Verdict | None = None) -> None:
    if verdict is not None:
        render_verdict(report, verdict)
    render_detection(report)
    render_vt(report)
    render_attribution(report)
    # Gate on whether VT actually returned contacted IPs, not on whether
    # AbuseIPDB happened to yield usable data -- see main.py history. This
    # keeps the TTY and JSON/PDF outputs in agreement regardless of which
    # of AbuseIPDB/Censys/WHOIS succeeded.
    if report.vt.contacted_ips:
        render_ips(report)
        render_hosts(report)
        render_whois(report)
    render_domains(report)
    render_otx(report)
