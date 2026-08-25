import datetime

from ..api.base_call import error_message, is_error
from ..models import Detection, SigmaRule, Submission, ThreatClass, VTReport

NAME_LIMIT = 5  # VT returns hundreds; the report shows the first few.


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


def _by_count(entries: list[dict]) -> list[str]:
    """VT's popular_threat_* lists carry a count per value and are not
    pre-sorted. Highest count first, ties in payload order."""
    return [
        entry["value"]
        for entry in sorted(entries or [], key=lambda e: -e.get("count", 0))
        if entry.get("value")
    ]


def _threat(attributes: dict) -> ThreatClass | None:
    block = attributes.get("popular_threat_classification")
    if not block:
        return None
    families = _by_count(block.get("popular_threat_name", []))
    return ThreatClass(
        label=block.get("suggested_threat_label", ""),
        family=families[0] if families else None,
        categories=_by_count(block.get("popular_threat_category", [])),
    )


def _submission(attributes: dict) -> Submission:
    ts = attributes.get("first_submission_date")
    first_seen = (
        datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
        if ts else None
    )
    return Submission(
        first_seen=first_seen,
        times_submitted=attributes.get("times_submitted", 0),
        names=list(attributes.get("names", []) or [])[:NAME_LIMIT],
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
        threat=_threat(attributes),
        submission=_submission(attributes),
    )
