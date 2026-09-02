from ..models import IPReport, as_count


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
            # scoring.py's _abuseipdb_signal does `max(i.confidence ...)`
            # and then `worst < ABUSE_CONFIDENCE`, so a non-numeric
            # confidence raised TypeError out of score() -- and therefore
            # out of the TTY, the PDF and the JSON, which all take a
            # verdict. This is deferred minor #9, and it is the same defect
            # as the VT one above, so it is fixed in the same round.
            confidence=as_count(inner.get("abuseConfidenceScore")),
            reports=len(reports) if isinstance(reports, list) else as_count(reports),
            hostnames=[h for h in hostnames if h],
            domain=inner.get("domain"),
        )
    return ips
