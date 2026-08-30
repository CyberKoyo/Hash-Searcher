"""crt.sh rows, reduced to a de-duplicated sibling-domain list.

Two shapes to survive: crt.sh returns one row per certificate log entry,
so the same name recurs many times, and each row's name_value packs every
SAN on that certificate into one newline-joined string.
"""

from ..api.base_call import error_message, is_error
from ..models import CertReport

#: A wildcard-heavy domain returns thousands of rows. The rendered list is
#: capped here; CertReport.count keeps the untruncated total, so the report
#: stays readable without lying about how many names there were.
SIBLING_LIMIT = 100


def extract_crtsh(raw) -> CertReport:
    if is_error(raw):
        return CertReport(error=error_message(raw))
    if not isinstance(raw, list):
        return CertReport(error="crt.sh returned an unexpected shape")

    siblings: list[str] = []
    seen: set[str] = set()
    for row in raw:
        if not isinstance(row, dict):
            continue
        for name in str(row.get("name_value") or "").split("\n"):
            name = name.strip().lower().removeprefix("*.")
            if not name or name in seen:
                continue
            seen.add(name)
            siblings.append(name)

    return CertReport(siblings=siblings[:SIBLING_LIMIT], count=len(siblings))
