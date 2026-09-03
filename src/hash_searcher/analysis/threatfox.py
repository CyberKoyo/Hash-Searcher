"""ThreatFox's query_status envelope, reduced to a ThreatFoxReport.

Same three-way split as MalwareBazaar: a failed request, a match, and
"no_result" -- which is a clean absence, not an error. Most indicators are
not in ThreatFox, and reporting that as a failure would print an error on
nearly every run. raw is None when nobody asked ThreatFox at all -- the
fourth state SourceResult wraps this in for.
"""

from ..api.base_call import error_message, is_error
from ..models import SourceResult, ThreatFoxReport
from .payload import as_mappings, as_sequence


def extract_threatfox(raw) -> SourceResult[ThreatFoxReport]:
    if raw is None:
        return SourceResult()                       # nobody asked
    if is_error(raw):
        return SourceResult(error=error_message(raw), queried=True)
    if not isinstance(raw, dict):
        return SourceResult(error="ThreatFox returned an unexpected shape",
                            queried=True)

    status = raw.get("query_status")
    if status in ("no_result", "illegal_search_term"):
        return SourceResult(value=ThreatFoxReport(found=False), queried=True)
    if status != "ok":
        return SourceResult(error=f"ThreatFox query_status: {status}",
                            queried=True)

    entries = as_mappings(raw.get("data"))
    if not entries:
        return SourceResult(value=ThreatFoxReport(found=False), queried=True)
    entry = entries[0]

    return SourceResult(
        value=ThreatFoxReport(
            found=True,
            malware=entry.get("malware_printable") or entry.get("malware"),
            # No isinstance here any more: `confidence: int` is the
            # declaration and models.py's @coerced is what makes it true, the
            # same as every other payload number in the tree.
            confidence=entry.get("confidence_level"),
            tags=as_sequence(entry.get("tags")),
        ),
        queried=True,
    )
