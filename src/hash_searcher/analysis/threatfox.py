"""ThreatFox's query_status envelope, reduced to a ThreatFoxReport.

Same three-way split as MalwareBazaar: a failed request, a match, and
"no_result" -- which is a clean absence, not an error. Most indicators are
not in ThreatFox, and reporting that as a failure would print an error on
nearly every run.
"""

from ..api.base_call import error_message, is_error
from ..models import ThreatFoxReport


def extract_threatfox(raw) -> ThreatFoxReport:
    if is_error(raw):
        return ThreatFoxReport(found=False, error=error_message(raw))
    if not isinstance(raw, dict):
        return ThreatFoxReport(found=False,
                               error="ThreatFox returned an unexpected shape")

    status = raw.get("query_status")
    if status in ("no_result", "illegal_search_term"):
        return ThreatFoxReport(found=False)
    if status != "ok":
        return ThreatFoxReport(found=False,
                               error=f"ThreatFox query_status: {status}")

    entries = raw.get("data") or []
    if not entries:
        return ThreatFoxReport(found=False)
    entry = entries[0]

    confidence = entry.get("confidence_level")
    return ThreatFoxReport(
        found=True,
        malware=entry.get("malware_printable") or entry.get("malware"),
        confidence=confidence if isinstance(confidence, int) else 0,
        tags=list(entry.get("tags") or []),
    )
