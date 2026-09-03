import datetime
import math

from ..api.base_call import error_message, error_status, is_error
from ..models import (
    Detection, PEInfo, SandboxVerdict, Signature, SigmaRule, Submission,
    ThreatClass, VTReport, YaraMatch, as_count,
)
from .attack import resolve, technique_ids_from_vt
from .payload import as_mapping, as_mappings, as_sequence, as_text, dig

NAME_LIMIT = 5  # VT returns hundreds; the report shows the first few.
FLAGGED = frozenset({"malicious", "suspicious"})
VERIFIED_SIGNATURE = "signed file, verified signature"


def relationship_ids(data: dict, name: str) -> list[str]:
    """Walk data.relationships.<name>.data, collecting `id`.

    Public because api/virustotal.py's contacted_ips delegates here --
    the two had drifted into disagreeing implementations.
    """
    return [
        entry["id"]
        for entry in as_mappings(dig(data, "data", "relationships", name).get("data"))
        # isinstance, not `"id" in entry`: over a list of STRINGS that was a
        # substring test that passed, and entry["id"] then raised
        # `TypeError: string indices must be integers`. The same two lines as
        # analysis/censys.py's services bug, in a second module.
        if isinstance(entry.get("id"), str)
    ]


def _epoch_date(value) -> str | None:
    """A VT epoch-seconds field, as a date, or None when it is not one.

    `datetime.fromtimestamp` raises TypeError on a string and OverflowError
    or OSError on a number outside the platform's range, and both
    first_submission_date and pe_info.timestamp are taken straight off the
    payload. A falsy value stays None, which is what `if ts else None`
    already meant.
    """
    if not value or isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    try:
        return datetime.datetime.fromtimestamp(
            value, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return None


def _detection(attributes: dict) -> Detection | None:
    """None, not a zeroed Detection: 'VT reported nothing' and 'VT reported
    0/72' are different facts and the verdict layer weighs them differently.
    """
    stats = as_mapping(attributes.get("last_analysis_stats"))
    if not stats:
        return None
    # as_count, not a bare .get(name, 0): the 0 default covers an absent
    # key and says nothing about a present one. Detection.total sums these
    # five, so one non-numeric bucket raised TypeError out of `score`, the
    # TTY, the PDF and the JSON alike -- from provider input, on a run in
    # which every provider answered.
    return Detection(
        malicious=stats.get("malicious"),
        suspicious=stats.get("suspicious"),
        harmless=stats.get("harmless"),
        undetected=stats.get("undetected"),
        timeout=stats.get("timeout"),
    )


def _by_count(entries: list[dict]) -> list[str]:
    """VT's popular_threat_* lists carry a count per value and are not
    pre-sorted. Highest count first, ties in payload order."""
    # The sort key is the same defect one expression over: `-"<script>"`
    # raises TypeError before any of the five Detection buckets are even
    # built, so a hostile `count` here took the run down first.
    return [
        entry["value"]
        for entry in sorted(as_mappings(entries), key=lambda e: -as_count(e.get("count")))
        if entry.get("value")
    ]


def _threat(attributes: dict) -> ThreatClass | None:
    block = as_mapping(attributes.get("popular_threat_classification"))
    if not block:
        return None
    families = _by_count(block.get("popular_threat_name", []))
    return ThreatClass(
        label=block.get("suggested_threat_label", ""),
        family=families[0] if families else None,
        categories=_by_count(block.get("popular_threat_category", [])),
    )


def _submission(attributes: dict) -> Submission:
    return Submission(
        first_seen=_epoch_date(attributes.get("first_submission_date")),
        times_submitted=attributes.get("times_submitted"),
        names=as_sequence(attributes.get("names"))[:NAME_LIMIT],
    )


def _signature(attributes: dict) -> Signature | None:
    block = as_mapping(attributes.get("signature_info"))
    if not block:
        return None
    # as_text: .strip() and .split() are why these two need to be strings,
    # and a payload of {"verified": null} raised AttributeError on the first.
    verified = as_text(block.get("verified"))
    signers = as_text(block.get("signers"))
    return Signature(
        # VT writes prose here. The constant below is the only form that
        # means valid; every other string -- including the ones about
        # invalid and revoked signatures -- is truthy and must not count.
        verified=verified.strip().lower() == VERIFIED_SIGNATURE,
        signer=(signers.split(";")[0].strip() or None) if signers else None,
        product=block.get("product") or None,
    )


def _sandbox(attributes: dict) -> list[SandboxVerdict]:
    verdicts = []
    for name, raw_body in as_mapping(attributes.get("sandbox_verdicts")).items():
        body = as_mapping(raw_body)
        # as_text before the membership test: an unhashable category raised
        # TypeError on `in FLAGGED` rather than simply not matching.
        category = as_text(body.get("category"))
        if category not in FLAGGED:
            continue
        verdicts.append(SandboxVerdict(
            sandbox=body.get("sandbox_name", name),
            category=category,
            malware_names=as_sequence(body.get("malware_names")),
        ))
    return verdicts


def _yara(attributes: dict) -> list[YaraMatch]:
    return [
        YaraMatch(
            rule=match.get("rule_name", ""),
            author=match.get("author") or None,
            description=match.get("description") or None,
        )
        for match in as_mappings(attributes.get("crowdsourced_yara_results"))
        if match.get("rule_name")
    ]


def _pe(attributes: dict) -> PEInfo | None:
    block = as_mapping(attributes.get("pe_info"))
    if not block:
        return None
    return PEInfo(
        imphash=block.get("imphash") or None,
        entry_point=block.get("entry_point"),
        sections=len(as_sequence(block.get("sections"))),
        compiled=_epoch_date(block.get("timestamp")),
    )


def extract_vt(raw) -> VTReport:
    if is_error(raw):
        # raw is already known to be an error dict here, so a status of
        # None does not mean "no error" -- it means an error with no HTTP
        # status, which is exactly what a retry-exhausted network failure
        # (offline, DNS, timeout; see base_call.py's _finish) produces. A
        # 404 is VirusTotal's answer: "no record", real information. Every
        # other error -- with a status or without one -- means the call
        # failed and VT never actually answered; unavailable is how the
        # render layer tells the two apart.
        return VTReport(
            found=False,
            error=error_message(raw),
            unavailable=error_status(raw) != 404,
        )

    attributes = dig(raw, "data", "attributes")
    rules = as_mappings(attributes.get("sigma_analysis_results"))
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
        contacted_ips=relationship_ids(raw, "contacted_ips"),
        contacted_domains=relationship_ids(raw, "contacted_domains"),
        detection=_detection(attributes),
        threat=_threat(attributes),
        submission=_submission(attributes),
        signature=_signature(attributes),
        sandbox=_sandbox(attributes),
        yara=_yara(attributes),
        pe=_pe(attributes),
        techniques=resolve(technique_ids_from_vt(raw)),
    )
