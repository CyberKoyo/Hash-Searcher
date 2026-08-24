import json
from dataclasses import asdict

from ..models import Report


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
            "censys": [asdict(h) for h in report.hosts],
            "whois": [asdict(w) for w in report.whois],
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
