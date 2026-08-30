"""Local intersection of observed CVEs against the CISA KEV catalog.

Pure: no request happens here. The caller fetches the catalog once (see
api/cisa_kev.py) and hands it in, because KEV is a file rather than a
lookup service.
"""

from ..models import KEVEntry


def known_exploited(cves: list[str], catalog: dict) -> list[KEVEntry]:
    """The subset of `cves` CISA has confirmed is exploited in the wild.

    Matching is case-insensitive: Shodan and CISA do not agree on the case
    of the "CVE" prefix, and a case-sensitive match silently found nothing.
    """
    if not cves:
        return []
    if not isinstance(catalog, dict):
        return []

    wanted = {cve.upper() for cve in cves if isinstance(cve, str)}
    hits = []
    for entry in catalog.get("vulnerabilities") or []:
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
    return hits
