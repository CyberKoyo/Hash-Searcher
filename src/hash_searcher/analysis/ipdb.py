from ..models import IPReport
from .payload import as_mapping, as_sequence


def extract_ips(raw_list) -> dict[str, IPReport]:
    """Keyed by IP -- see Task 4 for why not by (hostnames, domain)."""
    ips: dict[str, IPReport] = {}
    for entry in as_sequence(raw_list):
        inner = as_mapping(as_mapping(entry).get("data"))
        ip = inner.get("ipAddress")
        # A str, not merely truthy: this keys the dict `ips`, so an
        # unhashable ipAddress raised TypeError on the assignment itself.
        if not isinstance(ip, str) or not ip:
            continue

        reports = inner.get("reports", 0)
        ips[ip] = IPReport(
            ip=ip,
            # scoring.py's _abuseipdb_signal does `max(i.confidence ...)`
            # and then `worst < ABUSE_CONFIDENCE`, so a non-numeric
            # confidence raised TypeError out of score() -- and therefore
            # out of the TTY, the PDF and the JSON, which all take a
            # verdict. The coercion is IPReport's own now (models.py's
            # @coerced); this hands over the raw value and the declaration
            # `confidence: int` is what makes it a number.
            confidence=inner.get("abuseConfidenceScore"),
            reports=len(reports) if isinstance(reports, list) else reports,
            # as_sequence, not the `or []` plus a hand-rolled wrap this
            # used to carry. That was the one module in the package that
            # re-implemented a payload.py helper, and predictably the one
            # that behaved differently: it WRAPPED a non-list, so
            # {"hostnames": "h.example"} became ["h.example"] and
            # {"hostnames": {"a": 1}} became a hostname spelled "{'a': 1}",
            # where as_sequence discards both. AbuseIPDB documents
            # hostnames as an array; a bare string is a shape it did not
            # promise, and guessing at one is what payload.py's docstring
            # argues against. CensysHost.hostnames and
            # ShodanReport.hostnames already discard. `if h` drops the
            # empty string; anything that is not a string at all is
            # IPReport.hostnames' own business, declared list[str].
            hostnames=[h for h in as_sequence(inner.get("hostnames")) if h],
            domain=inner.get("domain"),
        )
    return ips
