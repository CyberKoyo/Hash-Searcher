"""Terminal rendering. The only module in the display path that prints.

Section functions are public so a verdict section can be slotted in without
rewriting render().
"""

from ..models import Report

RULE = "=" * 50


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
    for info in report.ips.values():
        print(f"{info.ip:<{w1}} {f'{info.confidence}%':<{w2}} {str(info.reports):<{w3}}")
    print("-" * total)


def render_hosts(report: Report) -> None:
    print("\n" + RULE)
    print("CENSYS ENRICHMENT")
    print(RULE)
    for host in report.hosts:
        print(f"\nIP:      {host.ip}")
        print(f"Org:     {host.org}  |  ASN: {host.asn}")
        print(f"Country: {host.country}")
        print(f"Ports:   {', '.join(str(p) for p in host.ports) if host.ports else 'N/A'}")
        if host.new_hostnames:
            print("[!] New indicators not found in AbuseIPDB:")
            print(f"    Hostnames: {', '.join(host.new_hostnames)}")
        else:
            print("    No new indicators beyond AbuseIPDB data.")


def render_whois(report: Report) -> None:
    print("\n" + RULE)
    print("WHOIS DATA")
    print(RULE)
    print(f"{'DOMAIN':<35} {'CREATED':<12} {'EXPIRES':<12} {'REGISTRAR':<30}")
    print("-" * 89)
    for record in report.whois:
        if record.error:
            print(f"{record.domain:<35} Error")
            continue
        print(f"{record.domain:<35} {record.created:<12} "
              f"{record.expires:<12} {record.registrar:<30}")


def render_otx(report: Report) -> None:
    print("\n" + RULE)
    print("OTX DATA")
    print(RULE)
    # Mirrors the original's `if not pulse_info:` gate. Keying off the
    # recorded_instances string instead would collide with a real count
    # whose value happens to be "N/A".
    if not report.otx.has_pulse_info:
        print("No OTX data available.")
        return
    print(f'Recorded instances: {report.otx.recorded_instances}')
    for technique in report.otx.attack_techniques:
        print(technique)


def render(report: Report) -> None:
    render_vt(report)
    # Gate on whether VT actually returned contacted IPs, not on whether
    # AbuseIPDB happened to yield usable data -- see main.py history. This
    # keeps the TTY and JSON/PDF outputs in agreement regardless of which
    # of AbuseIPDB/Censys/WHOIS succeeded.
    if report.vt.contacted_ips:
        render_ips(report)
        render_hosts(report)
        render_whois(report)
    render_otx(report)
