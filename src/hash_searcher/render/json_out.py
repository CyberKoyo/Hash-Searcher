import json
from dataclasses import asdict

from ..models import (
    BazaarReport, CensysHost, CertReport, GreyNoiseReport, Report, ShodanReport,
    SourceResult, StaticReport, ThreatFoxReport, Verdict, VTReport, WhoisRecord,
)


def _censys_dict(host: CensysHost) -> dict:
    """Reproduce the old censys_formatter shape: no `hostnames` key.

    A failed lookup adds an `error` key -- without it a 403 serialized as a
    host with null org, null asn, and no ports, indistinguishable from a real
    host Censys knew nothing about. Added only when set, the same way
    _whois_dict has always handled it, so the success shape is unchanged.
    """
    body = {
        "ip": host.ip,
        "org": host.org,
        "asn": host.asn,
        "country": host.country,
        "ports": host.ports,
        "new_hostnames": host.new_hostnames,
    }
    if host.error:
        body["error"] = host.error
    return body


def _whois_dict(record: WhoisRecord) -> dict:
    """Reproduce the old whois_formatter shape: error entries carried only
    `domain`/`error`, success entries never had an `error` key at all."""
    if record.error:
        return {"domain": record.domain, "error": record.error}
    return {
        "domain": record.domain,
        "created": record.created,
        "expires": record.expires,
        "registrar": record.registrar,
    }


def _source_dict(result: SourceResult, default) -> dict | None:
    """Flatten a SourceResult to the shape its wrapped report used to have.

    Present-but-null when the source never ran, same rule the rest of this
    module follows. When it ran and failed, `.value` is None (the extractor
    template never sets it on an error) -- `default` (a bare, zero-valued
    instance of the wrapped report type) stands in so the JSON shape stays
    exactly what it was before this report grew an `error` field of its own:
    every field present, `error` set, everything else at its zero value.
    """
    if not result.queried:
        return None
    return {**asdict(result.value if result.value is not None else default),
            "error": result.error}


def _verdict_dict(verdict: Verdict) -> dict:
    return {
        "level": verdict.level,
        "score": verdict.score,
        "signals": [
            {"name": s.name, "points": s.points, "detail": s.detail}
            for s in verdict.signals
        ],
    }


def _vt_dict(vt: VTReport) -> dict:
    """The Phase 2 VT blocks, under their own key.

    Present-but-null rather than omitted when VT returned nothing for a
    block: a consumer can then tell "VT had no classification" from "this
    tool never looked". The Phase 1 keys stay exactly where they were --
    `vt_rules` is not folded in here, because moving it would be a schema
    break for anything already reading it.
    """
    detection = vt.detection
    return {
        # All five buckets: the TTY prints suspicious and undetected, and a
        # consumer that could not reconstruct what the terminal showed would
        # be reading a different report from the one the analyst saw.
        "detection": (
            {"malicious": detection.malicious,
             "suspicious": detection.suspicious,
             "harmless": detection.harmless,
             "undetected": detection.undetected,
             "timeout": detection.timeout,
             "total": detection.total,
             "ratio": detection.ratio}
            if detection else None
        ),
        "threat": asdict(vt.threat) if vt.threat else None,
        "submission": asdict(vt.submission) if vt.submission else None,
        "signature": asdict(vt.signature) if vt.signature else None,
        "sandbox": [asdict(v) for v in vt.sandbox],
        "yara": [asdict(y) for y in vt.yara],
        "pe": asdict(vt.pe) if vt.pe else None,
        "techniques": [asdict(t) for t in vt.techniques],
        "contacted_domains": vt.contacted_domains,
    }


def _static_dict(static: StaticReport) -> dict:
    """report.static's full field set, under its own key.

    Component fields are present-but-null when that analyzer never produced
    a result -- same rule _vt_dict already follows -- so a consumer can tell
    "this analyzer had nothing" from "this tool never ran it". `skipped` and
    `failed` always carry the analyzer names, empty list or not.
    """
    return {
        "path": static.path,
        "size": static.size,
        "sha256": static.sha256,
        "entropy": asdict(static.entropy) if static.entropy else None,
        "filetype": asdict(static.filetype) if static.filetype else None,
        "pe": asdict(static.pe) if static.pe else None,
        "yara": [asdict(hit) for hit in static.yara],
        "yara_note": static.yara_note,
        "strings": asdict(static.strings) if static.strings else None,
        "skipped": static.skipped,
        "failed": static.failed,
    }


def _phase4_dict(report: Report) -> dict:
    """The Phase 4 sources, each present-but-null when it never ran.

    Same rule as _vt_dict and _static_dict above: a consumer can then tell
    "the source had nothing" from "this tool never asked it". certs carries
    the untruncated `count` alongside the capped `siblings` list, so a JSON
    consumer is not misled by the cap either. kev_error/kev_unchecked stay
    their own top-level keys -- both already shipped on main, and Global
    Constraint 7 says an existing JSON key never moves -- populated from the
    SourceResult[KEVReport] that replaced the two bolted-on Report fields.
    """
    kev = report.kev
    return {
        "bazaar": _source_dict(report.bazaar, BazaarReport()),
        "threatfox": _source_dict(report.threatfox, ThreatFoxReport()),
        "certs": _source_dict(report.certs, CertReport()),
        "shodan": {ip: _source_dict(r, ShodanReport())
                   for ip, r in report.shodan.items()},
        "greynoise": {ip: _source_dict(r, GreyNoiseReport())
                      for ip, r in report.greynoise.items()},
        "kev": [asdict(entry) for entry in kev.value.entries] if kev.value else [],
        # Present-but-null unless the catalog could not be fetched, so a
        # consumer never reads an empty "kev" as "nothing is exploited"
        # when the truth is that nobody could ask.
        "kev_error": kev.error,
        "kev_unchecked": kev.value.unchecked if kev.value else 0,
    }


def to_dict(report: Report, verdict: Verdict | None = None) -> dict:
    body = {
        "hash": report.indicator,
        "otx": {
            "recorded_instances": report.otx.recorded_instances,
            "attack_techniques": report.otx.attack_techniques,
        },
        "censys": [_censys_dict(h) for h in report.hosts],
        "whois": [_whois_dict(w) for w in report.whois],
        "ipdb": [asdict(i) for i in report.ips.values()],
        "vt_rules": {
            level: [{"title": r.title, "description": r.description}
                    for r in report.vt.by_level(level)]
            for level in ("high", "medium", "low")
        },
        "vt": _vt_dict(report.vt),
        **_phase4_dict(report),
    }
    if verdict is not None:
        body["verdict"] = _verdict_dict(verdict)
    if report.static is not None:
        body["static"] = _static_dict(report.static)
    return {
        "file": report.source_file or report.indicator,
        "time": report.generated_at,
        "report": body,
    }


def write_json(report: Report, path: str, verdict: Verdict | None = None) -> str:
    with open(path, "w") as out:
        json.dump(to_dict(report, verdict), out, sort_keys=True, indent=4,
                  ensure_ascii=False)
    return path
