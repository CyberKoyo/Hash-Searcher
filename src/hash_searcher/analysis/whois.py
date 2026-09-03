"""RDAP payloads, reduced to the WhoisRecord shape the renderers already use.

The signature and return type are unchanged from the whois-library era on
purpose: render/tty.py, json_out.py, and pdf.py consume WhoisRecord and
needed no edit when the source underneath changed.
"""

import datetime

from ..api.base_call import error_message, is_error
from ..models import WhoisRecord
from .payload import as_mapping, as_mappings, as_sequence

MISSING = "N/A"


def _iso_date(value) -> str:
    """RDAP event dates are ISO-8601 with a timezone; the report shows a date.

    datetime.fromisoformat cannot parse a trailing 'Z' before Python 3.11
    and the CI matrix includes 3.10, so normalize it first. Anything
    unparseable degrades to "N/A" -- exactly what the old library produced.
    """
    if not isinstance(value, str) or not value:
        return MISSING
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.datetime.fromisoformat(value).strftime("%Y-%m-%d")
    except ValueError:
        return MISSING


def _event_date(events, action: str) -> str:
    """Dates live in the events array, keyed by eventAction.

    Many ccTLD RDAP servers omit expiration entirely, so a missing event is
    a normal answer rather than a failure.
    """
    for event in as_mappings(events):
        if event.get("eventAction") == action:
            return _iso_date(event.get("eventDate"))
    return MISSING


def _vcard_name(vcard) -> str | None:
    """Pull `fn` out of ["vcard", [["fn", {}, "text", "Name"], ...]]."""
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for entry in as_sequence(vcard[1]):
        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
            return entry[3]
    return None


def _registrar(entities) -> str:
    """The entity whose roles contain "registrar", never entities[0].

    RDAP entities carry roles, and the abuse contact is not the registrar --
    taking the first entry gets it wrong on many TLDs.
    """
    for entity in as_mappings(entities):
        if "registrar" in as_sequence(entity.get("roles")):
            name = _vcard_name(entity.get("vcardArray"))
            if name:
                return name
    return MISSING


def extract_whois(raw_list) -> list[WhoisRecord]:
    records = []
    for entry in as_sequence(raw_list):
        if not isinstance(entry, dict):
            records.append(WhoisRecord(domain="", error="unrecognized RDAP payload"))
            continue
        # get_rdap carries `domain` on both paths, but .get() anyway: that is
        # a coupling between two modules, not a guarantee this one can rely on.
        domain = entry.get("domain") or entry.get("ldhName") or ""
        if is_error(entry):
            records.append(WhoisRecord(domain=domain, error=error_message(entry)))
            continue
        records.append(WhoisRecord(
            domain=domain or MISSING,
            created=_event_date(entry.get("events"), "registration"),
            expires=_event_date(entry.get("events"), "expiration"),
            registrar=_registrar(entry.get("entities")),
        ))
    return records
