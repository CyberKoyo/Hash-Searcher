from ..api.base_call import error_message, is_error
from ..models import OTXReport

RECENT_PULSES = 5


def extract_otx(raw) -> OTXReport:
    if is_error(raw):
        return OTXReport(recorded_instances="N/A", error=error_message(raw))

    pulse_info = raw.get("pulse_info")
    if not pulse_info:
        return OTXReport(recorded_instances="N/A")

    techniques: list[str] = []
    for pulse in pulse_info.get("pulses", [])[:RECENT_PULSES]:
        for attack in pulse.get("attack_ids", []) or []:
            name = attack.get("display_name")
            if name and name not in techniques:
                techniques.append(name)

    return OTXReport(
        recorded_instances=pulse_info.get("count", "N/A, No recorded instances"),
        attack_techniques=techniques,
        has_pulses=bool(pulse_info.get("pulses")),
        has_pulse_info=True,
    )
