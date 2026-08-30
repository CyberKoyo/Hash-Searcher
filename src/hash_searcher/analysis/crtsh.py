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
            # name_value carries rfc822Name SANs as well as DNS names --
            # example.com's own certificate log has one. An email address
            # is not a domain to pivot on.
            if not name or "@" in name or name in seen:
                continue
            seen.add(name)
            siblings.append(name)

    return CertReport(siblings=siblings[:SIBLING_LIMIT], count=len(siblings))


def merge_crtsh(raw_list) -> CertReport:
    """One CertReport across every domain that was queried.

    The report carries a single certificate section, but crt.sh is asked
    once per contacted domain. Rows are pooled and de-duplicated together
    -- siblings shared between two contacted domains are the interesting
    case, and reporting them twice would overstate the count. An error is
    surfaced only when every query failed: one dead lookup among five must
    not blank out the four that worked.
    """
    rows = []
    errors = []
    for raw in raw_list:
        if is_error(raw):
            errors.append(error_message(raw))
        elif isinstance(raw, list):
            rows.extend(raw)
        else:
            errors.append("crt.sh returned an unexpected shape")

    if rows or not errors:
        return extract_crtsh(rows)
    return CertReport(error="; ".join(dict.fromkeys(errors)))
