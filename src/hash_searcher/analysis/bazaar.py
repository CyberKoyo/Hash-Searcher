"""MalwareBazaar's query_status envelope, reduced to a BazaarReport.

Three outcomes, not two. is_error(raw) means the request itself failed;
"ok" means the sample is in the repository; "hash_not_found" is a clean
absence -- most hashes are not in a malware repository, and saying so is
information, not a failure. Collapsing the last two would print an error
for the common case. A fourth outcome -- raw is None, nobody asked
MalwareBazaar at all -- is the one BazaarReport itself could never express;
that is what the SourceResult wrapper is for.
"""

from ..api.base_call import error_message, is_error
from ..models import BazaarReport, SourceResult


def _first_seen(value) -> str | None:
    """abuse.ch stamps "YYYY-MM-DD HH:MM:SS"; the report shows the date."""
    if not isinstance(value, str) or not value:
        return None
    return value.split(" ")[0]


def extract_bazaar(raw) -> SourceResult[BazaarReport]:
    if raw is None:
        return SourceResult()                       # nobody asked
    if is_error(raw):
        return SourceResult(error=error_message(raw), queried=True)
    if not isinstance(raw, dict):
        return SourceResult(error="MalwareBazaar returned an unexpected shape",
                            queried=True)

    status = raw.get("query_status")
    if status == "hash_not_found":
        return SourceResult(value=BazaarReport(found=False), queried=True)
    if status != "ok":
        return SourceResult(error=f"MalwareBazaar query_status: {status}",
                            queried=True)

    entries = [e for e in (raw.get("data") or []) if isinstance(e, dict)]
    if not entries:
        return SourceResult(value=BazaarReport(found=False), queried=True)
    entry = entries[0]

    return SourceResult(
        value=BazaarReport(
            found=True,
            family=entry.get("signature"),
            tags=list(entry.get("tags") or []),
            file_type=entry.get("file_type"),
            first_seen=_first_seen(entry.get("first_seen")),
            yara=[r.get("rule_name") for r in (entry.get("yara_rules") or [])
                  if isinstance(r, dict) and r.get("rule_name")],
        ),
        queried=True,
    )
