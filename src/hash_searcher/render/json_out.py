import json
from dataclasses import asdict

from ..models import CensysHost, Report, WhoisRecord


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


def to_dict(report: Report) -> dict:
    return {
        "file": report.source_file or report.indicator,
        "time": report.generated_at,
        "report": {
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
        },
    }


def write_json(report: Report, path: str) -> str:
    with open(path, "w") as out:
        json.dump(to_dict(report), out, sort_keys=True, indent=4, ensure_ascii=False)
    return path
