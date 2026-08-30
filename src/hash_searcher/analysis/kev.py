"""Local intersection of observed CVEs against the CISA KEV catalog.

Pure: no request happens here. The caller fetches the catalog once (see
api/cisa_kev.py) and hands it in, because KEV is a file rather than a
lookup service.

KEV is the one source that could not carry Phase 4's found/error/never-asked
distinction on its own report dataclass -- it has no per-CVE payload to hang
`error` off, only a catalog that either arrived or didn't. That is what used
to bolt `kev_error`/`kev_unchecked` onto `Report` directly. Wrapping the
result in a SourceResult[KEVReport] instead means `known_exploited` decides
"never asked" vs "asked and failed" vs "answered" in one place, and cli.py
no longer has to unwrap `raw["kev"]` and compute `kev_unchecked` by hand.
"""

from ..api.base_call import error_message, is_error
from ..models import KEVEntry, KEVReport, SourceResult


def known_exploited(cves: list[str], raw_catalog) -> SourceResult[KEVReport]:
    """The subset of `cves` CISA has confirmed is exploited in the wild.

    `raw_catalog` is the RAW payload data_puller fetched for `raw["kev"]`:
    an error dict when the fetch failed, `{}` when there was nothing to
    check (the catalog is only fetched when Shodan reported CVEs, so an
    empty `cves` list means the catalog was never fetched at all), or the
    parsed catalog on success. Matching is case-insensitive: Shodan and CISA
    do not agree on the case of the "CVE" prefix, and a case-sensitive match
    silently found nothing.
    """
    if not cves:
        return SourceResult()                       # nothing to check

    if is_error(raw_catalog):
        # There WERE CVEs to check and CISA could not be reached. `unchecked`
        # survives on the value even though this is an error result -- it is
        # the fact both the CLI and the renderers need, and dropping it here
        # would make an unreachable catalog indistinguishable from "nothing
        # is known-exploited", the strongest signal this phase produces.
        return SourceResult(value=KEVReport(unchecked=len(cves)),
                            error=error_message(raw_catalog), queried=True)
    if not isinstance(raw_catalog, dict):
        return SourceResult(value=KEVReport(unchecked=len(cves)),
                            error="CISA KEV returned an unexpected shape",
                            queried=True)

    wanted = {cve.upper() for cve in cves if isinstance(cve, str)}
    hits = []
    for entry in raw_catalog.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        cve = str(entry.get("cveID") or "")
        if cve.upper() not in wanted:
            continue
        hits.append(KEVEntry(
            cve=cve,
            vendor=entry.get("vendorProject"),
            product=entry.get("product"),
            name=entry.get("vulnerabilityName"),
            date_added=entry.get("dateAdded"),
            ransomware=entry.get("knownRansomwareCampaignUse") == "Known",
        ))
    return SourceResult(value=KEVReport(entries=hits, unchecked=0), queried=True)
