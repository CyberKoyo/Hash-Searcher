from ..models import IPReport


def extract_ips(raw_list) -> dict[str, IPReport]:
    """Keyed by IP -- see Task 4 for why not by (hostnames, domain)."""
    ips: dict[str, IPReport] = {}
    for entry in raw_list:
        inner = entry.get("data", {}) if isinstance(entry, dict) else {}
        ip = inner.get("ipAddress")
        if not ip:
            continue

        hostnames = inner.get("hostnames") or []
        if not isinstance(hostnames, list):
            hostnames = [hostnames]

        reports = inner.get("reports", 0)
        ips[ip] = IPReport(
            ip=ip,
            confidence=inner.get("abuseConfidenceScore", 0),
            reports=len(reports) if isinstance(reports, list) else reports,
            hostnames=[h for h in hostnames if h],
            domain=inner.get("domain"),
        )
    return ips
