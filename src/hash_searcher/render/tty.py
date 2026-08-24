"""Terminal rendering. The only module in the display path that prints.

Section functions are public so a verdict section can be slotted in without
rewriting render().
"""

from ..models import Report

RULE = "=" * 50


def render_vt(report: Report) -> None:
    print("\nVIRUSTOTAL SIGMA RULES")
    print("\n" + RULE)
    for level, heading in (("high", "HIGH PRIORITY RULES"),
                           ("medium", "MEDIUM PRIORITY RULES"),
                           ("low", "LOW PRIORITY RULES")):
        print(heading)
        print(RULE)
        rules = report.vt.by_level(level)
        if not rules:
            print(f"No {heading.split()[0].title()} Priority Rules Found.")
        for rule in rules:
            print(f"{rule.title}:")
            print(f"{rule.description}.")
        print('\n')


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
    if report.otx.error:
        print("No OTX data available.")
        return
    print(f'Recorded instances: {report.otx.recorded_instances}')
    for technique in report.otx.attack_techniques:
        print(technique)


def render(report: Report) -> None:
    render_vt(report)
    if report.ips:
        render_ips(report)
        render_hosts(report)
        render_whois(report)
    render_otx(report)
