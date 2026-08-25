import json
from dataclasses import asdict

from ..models import CensysHost, Report, VTReport, WhoisRecord


def _censys_dict(host: CensysHost) -> dict:
    """Reproduce the old censys_formatter shape: no `hostnames` key."""
    return {
        "ip": host.ip,
        "org": host.org,
        "asn": host.asn,
        "country": host.country,
        "ports": host.ports,
        "new_hostnames": host.new_hostnames,
    }


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


def _verdict_dict(verdict) -> dict:
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
        "detection": (
            {"malicious": detection.malicious, "total": detection.total,
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


def to_dict(report: Report, verdict=None) -> dict:
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
    }
    if verdict is not None:
        body["verdict"] = _verdict_dict(verdict)
    return {
        "file": report.source_file or report.indicator,
        "time": report.generated_at,
        "report": body,
    }


def write_json(report: Report, path: str, verdict=None) -> str:
    with open(path, "w") as out:
        json.dump(to_dict(report, verdict), out, sort_keys=True, indent=4,
                  ensure_ascii=False)
    return path
