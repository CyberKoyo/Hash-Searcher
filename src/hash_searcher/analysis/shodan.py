"""Shodan InternetDB payloads, reduced to a ShodanReport.

A 404 -- Shodan has never scanned this address -- is an empty report with
error=None, not a failure: most residential addresses have never been
scanned, and saying "we asked and Shodan knows nothing" is information.
Any other failure keeps its error so an analyst can tell the two apart.
"""

from ..api.base_call import error_message, error_status, is_error
from ..models import ShodanReport


def extract_shodan(raw) -> ShodanReport:
    if is_error(raw):
        if error_status(raw) == 404:
            return ShodanReport()
        return ShodanReport(error=error_message(raw))
    if not isinstance(raw, dict):
        return ShodanReport(error="Shodan returned an unexpected shape")

    return ShodanReport(
        ports=[p for p in (raw.get("ports") or []) if isinstance(p, int)],
        cpes=list(raw.get("cpes") or []),
        vulns=list(raw.get("vulns") or []),
        hostnames=list(raw.get("hostnames") or []),
    )
