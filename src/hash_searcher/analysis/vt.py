from ..api.base_call import error_message, is_error
from ..models import SigmaRule, VTReport


def _relationship_ids(data: dict, name: str) -> list[str]:
    return [
        entry["id"]
        for entry in data.get("data", {})
                         .get("relationships", {})
                         .get(name, {})
                         .get("data", [])
        if "id" in entry
    ]


def extract_vt(raw) -> VTReport:
    if is_error(raw):
        return VTReport(found=False, error=error_message(raw))

    rules = raw.get("data", {}).get("attributes", {}).get("sigma_analysis_results", []) or []
    sigma = [
        SigmaRule(
            title=r.get("rule_title", ""),
            description=r.get("rule_description", ""),
            level=r.get("rule_level", ""),
        )
        for r in rules
    ]
    return VTReport(
        found=True,
        sigma=sigma,
        contacted_ips=_relationship_ids(raw, "contacted_ips"),
        contacted_domains=_relationship_ids(raw, "contacted_domains"),
    )
