"""The report as a STIX 2.1 bundle.

What a TIP ingests. The JSON report is this tool's own schema and nothing
else speaks it; a STIX bundle is the one output another platform can take
without a translation layer written by whoever receives it.

**The standard library only -- `uuid` and `json`.** A STIX dependency
(`stix2`) exists and is not worth it for one serializer: it pulls a
validation stack and a pinned `pytz` into a tool whose entire runtime is
httpx plus reportlab, and this module emits five object types with fixed
shapes. Said here explicitly so nobody "fixes" the omission later.

Two decisions worth stating:

**Ids are UUIDv5, not v4.** The spec says SDO ids SHOULD be v4 (random).
Random ids mean re-running the same indicator produces a bundle that differs
in every id, which cannot be diffed and imports as a second, unrelated set
of objects. v5 over a fixed namespace makes the bundle a function of what
was observed. SCOs use the namespace the spec itself assigns to
deterministic SCO ids; everything else uses this tool's own namespace, which
is what keeps two tools from colliding on the same generated id.

**Every pattern value is escaped.** A `'` inside a domain closes the string
literal and the rest of the value becomes pattern syntax -- the bundle then
fails to parse at the consumer, not here, which is the worst place for it.
"""

import datetime
import json
import uuid

from ..models import Report, Verdict

#: The namespace STIX 2.1 assigns for deterministic SCO ids (section 2.9).
#: Using it means another tool that observed the same IP derives the same
#: `ipv4-addr` id, which is what makes two bundles merge instead of
#: duplicating every observable.
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

#: This tool's own namespace, for the objects the spec does NOT define a
#: deterministic id for (the bundle, the indicator, the relationships). A
#: UUIDv5 of the project URL under the DNS namespace: stable forever,
#: derived rather than invented, and distinct from any other producer's.
TOOL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS,
                            "ioc-inquest.github.io/CyberKoyo")

#: Hash digest length to the STIX hash algorithm name. The dict is the
#: whole of the type detection: a 64-character indicator classified as a
#: hash is a SHA-256, and there is nothing else it could be.
HASH_ALGORITHMS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}

#: Verdict level to STIX `indicator_types` (an open vocabulary; these are
#: the vocabulary's own terms). UNKNOWN must not claim malicious-activity,
#: and an unmapped level lands on "unknown" rather than on something
#: stronger -- the same fail-safe rule cli.exit_code follows.
INDICATOR_TYPES = {
    "MALICIOUS": "malicious-activity",
    "SUSPICIOUS": "anomalous-activity",
    "CLEAN": "benign",
    "UNKNOWN": "unknown",
}

#: What `-o report.stix` writes when no verdict was scored.
DEFAULT_INDICATOR_TYPE = "unknown"

SPEC_VERSION = "2.1"


def _timestamp(generated_at: str) -> str:
    """`Report.generated_at` as an RFC 3339 UTC timestamp.

    The report's own format is `%Y-%m-%d %H:%M:%S`, which STIX does not
    accept -- it wants the `T`, the sub-second precision, and the zone. A
    value in any other shape is not this tool's (a hand-built Report, a
    future format change); rather than crash a renderer over a display
    string, that case falls back to now, which is honest about being the
    time the bundle was produced.
    """
    try:
        moment = datetime.datetime.strptime(generated_at, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        moment = datetime.datetime.now()
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _escape(value: str) -> str:
    """A value safe inside a STIX pattern's single-quoted string literal.

    Backslash first: escaping the quote introduces backslashes of its own,
    and doing it the other way round would double-escape them.
    """
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _identifier(kind: str, *parts: str, namespace: uuid.UUID = TOOL_NAMESPACE) -> str:
    """A STIX id: `<type>--<uuid5 of what this object represents>`.

    `parts` is what makes the object what it is -- the observable's value
    for an SCO, the pair of endpoints for a relationship. Two different
    things must never derive the same id, so the parts are joined by a
    separator no value can contain.
    """
    return f"{kind}--{uuid.uuid5(namespace, '|'.join(parts))}"


def _sco_id(kind: str, payload: dict) -> str:
    """The spec's own deterministic SCO id: v5 over the canonical JSON of
    the object's ID contributing properties."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _identifier(kind, canonical, namespace=SCO_NAMESPACE)


def _observable(report: Report) -> tuple[dict, str] | tuple[None, None]:
    """The SCO for the looked-up indicator itself, and its STIX pattern.

    None for an indicator STIX has no observable for -- a CIDR range, or a
    digest of a length `HASH_ALGORITHMS` does not name. A bundle without
    the sample is still worth emitting for what else was observed, and
    inventing an object type is worse than omitting one.
    """
    value = report.indicator
    kind = report.indicator_kind
    if kind == "hash" or kind == "file":
        algorithm = HASH_ALGORITHMS.get(len(value))
        if algorithm is None:
            return None, None
        payload = {"type": "file", "hashes": {algorithm: value}}
        payload["id"] = _sco_id("file", {"hashes": {algorithm: value}})
        return payload, f"[file:hashes.'{algorithm}' = '{_escape(value)}']"
    stix_type = {"ip": "ipv4-addr", "domain": "domain-name", "url": "url"}.get(kind)
    if stix_type is None:
        return None, None
    payload = {"type": stix_type, "id": _sco_id(stix_type, {"value": value}),
               "value": value}
    return payload, f"[{stix_type}:value = '{_escape(value)}']"


def _value_sco(stix_type: str, value: str) -> dict:
    return {"type": stix_type, "id": _sco_id(stix_type, {"value": value}),
            "value": value}


def _relationship(kind: str, source: str, target: str, moment: str) -> dict:
    return {
        "type": "relationship",
        "spec_version": SPEC_VERSION,
        "id": _identifier("relationship", kind, source, target),
        "created": moment,
        "modified": moment,
        "relationship_type": kind,
        "source_ref": source,
        "target_ref": target,
    }


def to_bundle(report: Report, verdict: Verdict | None = None) -> dict:
    """The whole report as one STIX 2.1 bundle.

    Object order is deliberate and stable -- observable, indicator,
    contacted observables, relationships -- so two runs of the same report
    produce byte-identical JSON and a diff shows what actually changed.
    """
    moment = _timestamp(report.generated_at)
    objects: list[dict] = []
    sample, pattern = _observable(report)
    if sample is not None:
        objects.append(sample)

    indicator_type = (INDICATOR_TYPES.get(verdict.level, DEFAULT_INDICATOR_TYPE)
                      if verdict else DEFAULT_INDICATOR_TYPE)
    if pattern is not None:
        indicator = {
            "type": "indicator",
            "spec_version": SPEC_VERSION,
            "id": _identifier("indicator", report.indicator_kind, report.indicator),
            "created": moment,
            "modified": moment,
            "name": report.indicator,
            "indicator_types": [indicator_type],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": moment,
        }
        if verdict is not None:
            indicator["description"] = (f"{verdict.level} (score {verdict.score}) "
                                        f"-- ioc-inquest")
        objects.append(indicator)
        if sample is not None:
            objects.append(_relationship("based-on", indicator["id"],
                                         sample["id"], moment))

    # Contacted infrastructure, and what ties it to the sample. Without the
    # relationships these are a loose pile of addresses: a TIP that ingests
    # them cannot tell which sample contacted what, which is the single
    # most useful thing this report knows.
    for ip in report.vt.contacted_ips:
        sco = _value_sco("ipv4-addr", ip)
        objects.append(sco)
        if sample is not None:
            objects.append(_relationship("communicates-with", sample["id"],
                                         sco["id"], moment))
    for domain in report.vt.contacted_domains:
        sco = _value_sco("domain-name", domain)
        objects.append(sco)
        if sample is not None:
            objects.append(_relationship("communicates-with", sample["id"],
                                         sco["id"], moment))

    return {
        "type": "bundle",
        # The bundle's identity is the set of objects in it, so an
        # unchanged report re-imports as the same bundle rather than as a
        # new one holding the same objects.
        "id": _identifier("bundle", report.indicator,
                          *(o["id"] for o in objects)),
        "objects": objects,
    }


def write_stix(report: Report, path: str, verdict: Verdict | None = None) -> str:
    with open(path, "w", encoding="utf-8") as out:
        json.dump(to_bundle(report, verdict), out, indent=4, ensure_ascii=False)
    return path
