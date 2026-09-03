from ..api.base_call import error_indicator, error_message, is_error
from ..models import CensysHost, IPReport
from .payload import as_mapping, as_mappings, as_sequence, dig


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
    for raw in as_sequence(raw_list):
        if is_error(raw):
            # Carried, not skipped: dropping it lost main's "Censys: <error>"
            # line entirely (ledger S2). A failed lookup contributes no
            # hostnames, so it must not widen the WHOIS domain set either.
            hosts.append(CensysHost(
                ip=error_indicator(raw) or "N/A",
                error=error_message(raw),
            ))
            continue

        result = dig(raw, "result", "resource")
        autonomous = as_mapping(result.get("autonomous_system"))
        # Filtered to strings because these are sorted() below and put into
        # a set: a mixed list raises TypeError on the comparison, and an
        # unhashable member raises on the set.
        censys_hostnames = {
            name for name in as_sequence(dig(result, "dns", "reverse_dns").get("names"))
            if isinstance(name, str)
        }
        domains.update(censys_hostnames)

        hosts.append(CensysHost(
            ip=result.get("ip", "N/A"),
            org=autonomous.get("name"),
            asn=autonomous.get("asn"),
            country=autonomous.get("country_code") or "N/A",
            # as_mappings, not `result.get("services", [])`: a services of
            # ["port-scan-result"] made `"port" in s` a SUBSTRING test that
            # passed, and s["port"] then raised TypeError out of cli.py:183
            # with no try around it. Which ports survive is CensysHost.ports'
            # own business now -- it is declared list[int] and models.py's
            # @coerced makes that true, the same way ShodanReport.ports gets
            # it. Neither extractor filters by hand any more, so the two
            # cannot drift apart again.
            ports=[service.get("port") for service in as_mappings(result.get("services"))],
            hostnames=sorted(censys_hostnames),
            new_hostnames=sorted(censys_hostnames - known_hostnames),
        ))

    return sorted(domains), hosts
