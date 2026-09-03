"""GreyNoise Community payloads, reduced to a GreyNoiseReport.

A 404 means GreyNoise has never observed the address -- seen=False, not a
failure. That is the answer that matters most: an address GreyNoise has NOT
seen scanning the internet is more interesting than one it has.
"""

from ..api.base_call import error_message, error_status, is_error
from ..models import GreyNoiseReport, SourceResult


def extract_greynoise(raw) -> SourceResult[GreyNoiseReport]:
    if raw is None:
        return SourceResult()                       # nobody asked
    if is_error(raw):
        if error_status(raw) == 404:
            return SourceResult(value=GreyNoiseReport(seen=False), queried=True)
        return SourceResult(error=error_message(raw), queried=True)
    if not isinstance(raw, dict):
        return SourceResult(error="GreyNoise returned an unexpected shape",
                            queried=True)

    return SourceResult(
        value=GreyNoiseReport(
            # `noise` is GreyNoise's own flag for "this address scans the
            # internet"; `riot` marks common business services. Either means
            # GreyNoise has a record of the address.
            seen=bool(raw.get("noise") or raw.get("riot")),
            classification=raw.get("classification"),
            name=raw.get("name"),
            last_seen=raw.get("last_seen"),
        ),
        queried=True,
    )
