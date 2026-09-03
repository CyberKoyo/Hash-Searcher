"""The report as a MISP event.

The other half of "hand this to a platform": a STIX bundle goes to a TIP,
a MISP event goes to MISP, and neither speaks the other's document. Both
are the standard library only, for the reason `stix.py` states at length.

MISP validates on import, and the thing it rejects is an attribute whose
`category` is not one its `type` is allowed in. That mapping is data here
(`ATTRIBUTE_TYPES`), one row per type, so a new attribute type is a row
rather than a branch -- and the row carries the category with it, which is
what makes the pair impossible to get half-right.

The verdict-to-threat-level mapping is the one judgement call in this
module, so it is a module-level dict rather than a conditional buried in
the builder: someone will disagree with it, and they should be able to see
and change it in one place.
"""

import datetime
import json

from ..models import Report, Verdict

#: This tool's verdict to MISP's `threat_level_id`. MISP's scale is the
#: inverse of the score: 1 is High, 4 is Undefined.
#:
#: CLEAN maps to 4 (Undefined) rather than 3 (Low): "we found nothing" is
#: not the same claim as "this is a low threat", and MISP has no term for
#: benign. An unmapped level takes UNKNOWN's value below -- an event this
#: tool cannot classify must never import as High.
THREAT_LEVELS = {
    "MALICIOUS": "1",   # High
    "SUSPICIOUS": "2",  # Medium
    "CLEAN": "4",       # Undefined
    "UNKNOWN": "4",     # Undefined
}

#: MISP's `analysis` field: 0 initial, 1 ongoing, 2 completed. Every run
#: this writer serializes has finished by definition.
ANALYSIS_COMPLETED = "2"

#: Indicator kind (and, for a hash, digest length) to the MISP attribute
#: type and the category that type belongs in.
ATTRIBUTE_TYPES = {
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
}

#: Digest length to the key above. Same detection `stix.py` uses -- a
#: 40-character hash is a SHA-1 and there is nothing else it could be.
HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256"}


def _attribute(key: str, value: str, comment: str = "") -> dict | None:
    """One attribute, or None for a kind MISP has no type for.

    None rather than a guessed type: an attribute MISP rejects fails the
    import of the whole event, so omitting one value is strictly better
    than mislabelling it.
    """
    pair = ATTRIBUTE_TYPES.get(key)
    if pair is None:
        return None
    attribute_type, category = pair
    return {
        "type": attribute_type,
        "category": category,
        "value": value,
        # These are observations from threat-intelligence sources, which is
        # what to_ids means: safe to turn into a detection rule.
        "to_ids": True,
        "comment": comment,
    }


def _indicator_key(report: Report) -> str | None:
    """Which ATTRIBUTE_TYPES row the looked-up indicator belongs to."""
    if report.indicator_kind in ("hash", "file"):
        return HASH_KINDS.get(len(report.indicator))
    return report.indicator_kind


def _info(report: Report, verdict: Verdict | None) -> str:
    """The event title -- what a MISP user sees in the event list.

    Carries the names the sources actually produced, because an event
    titled with a bare digest is indistinguishable from every other event
    titled with a bare digest.
    """
    parts = [f"hash-searcher: {report.indicator}"]
    if verdict is not None:
        parts.append(f"{verdict.level} (score {verdict.score})")
    families = []
    if report.vt.threat and report.vt.threat.family:
        families.append(report.vt.threat.family)
    if report.bazaar.ok and report.bazaar.value and report.bazaar.value.family:
        families.append(report.bazaar.value.family)
    if (report.threatfox.ok and report.threatfox.value
            and report.threatfox.value.malware):
        families.append(report.threatfox.value.malware)
    # dict.fromkeys rather than a set: two sources naming the same family
    # must not reorder the title from one run to the next.
    if families:
        parts.append(", ".join(dict.fromkeys(families)))
    return " -- ".join(parts)


def _date(generated_at: str) -> str:
    """MISP's `date`, which is a day, not a timestamp.

    Same fallback rule as stix._timestamp: a `generated_at` in an
    unexpected shape is not worth crashing a renderer over.
    """
    try:
        moment = datetime.datetime.strptime(generated_at, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        moment = datetime.datetime.now()
    return moment.strftime("%Y-%m-%d")


def to_event(report: Report, verdict: Verdict | None = None) -> dict:
    """The report as one MISP event, ready for `POST /events`."""
    attributes = []
    seen = set()

    def add(key: str, value: str, comment: str) -> None:
        # A value MISP already holds for this event is a duplicate a human
        # then has to reconcile: the looked-up IP reappearing in
        # contacted_ips is the case that actually happens.
        if not value or value in seen:
            return
        attribute = _attribute(key, value, comment)
        if attribute is None:
            return
        seen.add(value)
        attributes.append(attribute)

    key = _indicator_key(report)
    if key is not None:
        add(key, report.indicator, "the indicator this report is about")
    for ip in report.vt.contacted_ips:
        add("ip", ip, "contacted by the sample (VirusTotal)")
    for domain in report.vt.contacted_domains:
        add("domain", domain, "contacted by the sample (VirusTotal)")

    return {
        "Event": {
            "info": _info(report, verdict),
            "date": _date(report.generated_at),
            "threat_level_id": (THREAT_LEVELS.get(verdict.level,
                                                  THREAT_LEVELS["UNKNOWN"])
                                if verdict else THREAT_LEVELS["UNKNOWN"]),
            "analysis": ANALYSIS_COMPLETED,
            # Publishing is the operator's decision, not this tool's: a
            # published event fans out to every connected instance.
            "published": False,
            "Attribute": attributes,
        }
    }


def write_misp(report: Report, path: str, verdict: Verdict | None = None) -> str:
    with open(path, "w", encoding="utf-8") as out:
        json.dump(to_event(report, verdict), out, indent=4, ensure_ascii=False)
    return path
