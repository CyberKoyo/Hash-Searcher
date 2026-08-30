"""Shodan InternetDB payloads, reduced to a ShodanReport.

A 404 -- Shodan has never scanned this address -- is an empty report, not a
failure: most residential addresses have never been scanned, and saying "we
asked and Shodan knows nothing" is information. Any other failure keeps its
error, on the wrapping SourceResult, so an analyst can tell the two apart.
"""

from ..api.base_call import error_message, error_status, is_error
from ..models import ShodanReport, SourceResult


def extract_shodan(raw) -> SourceResult[ShodanReport]:
    if raw is None:
        return SourceResult()                       # nobody asked
    if is_error(raw):
        if error_status(raw) == 404:
            return SourceResult(value=ShodanReport(), queried=True)
        return SourceResult(error=error_message(raw), queried=True)
    if not isinstance(raw, dict):
        return SourceResult(error="Shodan returned an unexpected shape",
                            queried=True)

    return SourceResult(
        value=ShodanReport(
            ports=[p for p in (raw.get("ports") or []) if isinstance(p, int)],
            cpes=list(raw.get("cpes") or []),
            vulns=list(raw.get("vulns") or []),
            hostnames=list(raw.get("hostnames") or []),
        ),
        queried=True,
    )


def observed_cves(reports) -> list[str]:
    """Every CVE Shodan reported across the contacted IPs, de-duplicated.

    One implementation, two callers: data_puller checks it to decide
    whether the KEV catalog is worth downloading at all, and cli passes it
    to known_exploited(). They were the same list computed twice, in two
    layers, from two shapes. `reports` is an iterable of ShodanReport --
    already unwrapped from SourceResult -- because a source that failed or
    was never asked has nothing to contribute here either way.
    """
    cves = []
    for report in reports:
        for cve in report.vulns:
            if cve not in cves:
                cves.append(cve)
    return cves
