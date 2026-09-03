"""crt.sh rows, reduced to a de-duplicated sibling-domain list.

Two shapes to survive: crt.sh returns one row per certificate log entry,
so the same name recurs many times, and each row's name_value packs every
SAN on that certificate into one newline-joined string.
"""

from ..api.base_call import error_message, is_error
from ..models import CertReport, SourceResult
from .payload import as_mappings, as_sequence, as_text

#: A wildcard-heavy domain returns thousands of rows. The rendered list is
#: capped here; CertReport.count keeps the untruncated total, so the report
#: stays readable without lying about how many names there were.
SIBLING_LIMIT = 100


def extract_crtsh(raw) -> SourceResult[CertReport]:
    if raw is None:
        return SourceResult()                       # nobody asked
    if is_error(raw):
        return SourceResult(error=error_message(raw), queried=True)
    if not isinstance(raw, list):
        return SourceResult(error="crt.sh returned an unexpected shape",
                            queried=True)

    siblings: list[str] = []
    seen: set[str] = set()
    for row in as_mappings(raw):
        for name in as_text(row.get("name_value")).split("\n"):
            name = name.strip().lower().removeprefix("*.")
            # name_value carries rfc822Name SANs as well as DNS names --
            # example.com's own certificate log has one. An email address
            # is not a domain to pivot on.
            if not name or "@" in name or name in seen:
                continue
            seen.add(name)
            siblings.append(name)

    return SourceResult(
        value=CertReport(siblings=siblings[:SIBLING_LIMIT], count=len(siblings)),
        queried=True,
    )


def merge_crtsh(raw_list) -> SourceResult[CertReport]:
    """One CertReport across every domain that was queried.

    The report carries a single certificate section, but crt.sh is asked
    once per contacted domain. Rows are pooled and de-duplicated together
    -- siblings shared between two contacted domains are the interesting
    case, and reporting them twice would overstate the count. An error is
    surfaced only when every query failed: one dead lookup among five must
    not blank out the four that worked. An empty raw_list means no domains
    were queried at all -- crt.sh was never asked -- so cli.py can call this
    unconditionally instead of guarding on `if raw["crtsh"]` first.
    """
    if not raw_list:
        return SourceResult()                       # no domains to query

    rows = []
    errors = []
    for raw in as_sequence(raw_list):
        if is_error(raw):
            errors.append(error_message(raw))
        elif isinstance(raw, list):
            rows.extend(raw)
        else:
            errors.append("crt.sh returned an unexpected shape")

    if rows or not errors:
        return extract_crtsh(rows)
    return SourceResult(error="; ".join(dict.fromkeys(errors)), queried=True)
