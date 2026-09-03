from ..api.base_call import error_message, is_error
from ..models import OTXReport
from .attack import resolve, technique_ids_from_otx
from .payload import as_mapping, as_mappings

RECENT_PULSES = 5


def extract_otx(raw) -> OTXReport:
    if is_error(raw):
        return OTXReport(recorded_instances="N/A", error=error_message(raw))

    # as_mapping twice: `raw` itself is not guaranteed to be a dict (a bare
    # list came back as AttributeError from cli.py:172), and neither is
    # pulse_info -- `if not pulse_info` caught the null and let every other
    # non-mapping through to a .get that raised.
    pulse_info = as_mapping(as_mapping(raw).get("pulse_info"))
    if not pulse_info:
        return OTXReport(recorded_instances="N/A")

    techniques: list[str] = []
    # Non-mapping pulses are dropped before the slice rather than after, so
    # RECENT_PULSES means five pulses this can read rather than five entries
    # of which some are unusable.
    for pulse in as_mappings(pulse_info.get("pulses"))[:RECENT_PULSES]:
        for attack in as_mappings(pulse.get("attack_ids")):
            name = attack.get("display_name")
            if isinstance(name, str) and name and name not in techniques:
                techniques.append(name)

    return OTXReport(
        recorded_instances=pulse_info.get("count", "N/A, No recorded instances"),
        attack_techniques=techniques,
        has_pulses=bool(pulse_info.get("pulses")),
        otx_responded=True,
        techniques=resolve(technique_ids_from_otx(raw)),
    )
