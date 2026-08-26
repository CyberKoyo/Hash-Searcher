from ..api.base_call import error_indicator, error_message, is_error
from ..models import CensysHost, IPReport


def extract_hosts(raw_list, ips: dict[str, IPReport]) -> tuple[list[str], list[CensysHost]]:
    """Returns (sorted domains for WHOIS, per-IP enrichment).

    new_hostnames is what Censys knows that AbuseIPDB did not surface.
    """
    known_hostnames = set()
    domains = set()
    for info in ips.values():
        known_hostnames.update(info.hostnames)
        if info.domain:
            domains.add(info.domain)

    hosts: list[CensysHost] = []
    for raw in raw_list:
        if is_error(raw):
            # Carried, not skipped: dropping it lost main's "Censys: <error>"
            # line entirely (ledger S2). A failed lookup contributes no
            # hostnames, so it must not widen the WHOIS domain set either.
            hosts.append(CensysHost(
                ip=error_indicator(raw) or "N/A",
                error=error_message(raw),
            ))
            continue

        result = raw.get("result", {}).get("resource", {})
        autonomous = result.get("autonomous_system", {})
        censys_hostnames = set(
            result.get("dns", {}).get("reverse_dns", {}).get("names", []) or []
        )
        domains.update(censys_hostnames)

        hosts.append(CensysHost(
            ip=result.get("ip", "N/A"),
            org=autonomous.get("name"),
            asn=autonomous.get("asn"),
            country=autonomous.get("country_code") or "N/A",
            ports=[s["port"] for s in result.get("services", []) if "port" in s],
            hostnames=sorted(censys_hostnames),
            new_hostnames=sorted(censys_hostnames - known_hostnames),
        ))

    return sorted(domains), hosts
