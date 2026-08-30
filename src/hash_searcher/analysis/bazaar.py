"""MalwareBazaar's query_status envelope, reduced to a BazaarReport.

Three outcomes, not two. is_error(raw) means the request itself failed;
"ok" means the sample is in the repository; "hash_not_found" is a clean
absence -- most hashes are not in a malware repository, and saying so is
information, not a failure. Collapsing the last two would print an error
for the common case.
"""

from ..api.base_call import error_message, is_error
from ..models import BazaarReport


def _first_seen(value) -> str | None:
    """abuse.ch stamps "YYYY-MM-DD HH:MM:SS"; the report shows the date."""
    if not isinstance(value, str) or not value:
        return None
    return value.split(" ")[0]


def extract_bazaar(raw) -> BazaarReport:
    if is_error(raw):
        return BazaarReport(found=False, error=error_message(raw))
    if not isinstance(raw, dict):
        return BazaarReport(found=False, error="MalwareBazaar returned an unexpected shape")

    status = raw.get("query_status")
    if status == "hash_not_found":
        return BazaarReport(found=False)
    if status != "ok":
        return BazaarReport(found=False,
                            error=f"MalwareBazaar query_status: {status}")

    entries = [e for e in (raw.get("data") or []) if isinstance(e, dict)]
    if not entries:
        return BazaarReport(found=False)
    entry = entries[0]

    return BazaarReport(
        found=True,
        family=entry.get("signature"),
        tags=list(entry.get("tags") or []),
        file_type=entry.get("file_type"),
        first_seen=_first_seen(entry.get("first_seen")),
        yara=[r.get("rule_name") for r in (entry.get("yara_rules") or [])
              if isinstance(r, dict) and r.get("rule_name")],
    )
