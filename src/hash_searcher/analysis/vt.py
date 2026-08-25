from ..api.base_call import error_message, is_error
from ..models import Detection, SigmaRule, VTReport


def _relationship_ids(data: dict, name: str) -> list[str]:
    return [
        entry["id"]
        for entry in data.get("data", {})
                         .get("relationships", {})
                         .get(name, {})
                         .get("data", [])
        if "id" in entry
    ]


def _detection(attributes: dict) -> Detection | None:
    """None, not a zeroed Detection: 'VT reported nothing' and 'VT reported
    0/72' are different facts and the verdict layer weighs them differently.
    """
    stats = attributes.get("last_analysis_stats")
    if not stats:
        return None
    return Detection(
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        timeout=stats.get("timeout", 0),
    )


def extract_vt(raw) -> VTReport:
    if is_error(raw):
        return VTReport(found=False, error=error_message(raw))

    attributes = raw.get("data", {}).get("attributes", {})
    rules = attributes.get("sigma_analysis_results", []) or []
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
        detection=_detection(attributes),
    )
