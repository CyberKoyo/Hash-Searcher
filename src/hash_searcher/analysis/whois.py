from ..models import WhoisRecord


def extract_whois(raw_list) -> list[WhoisRecord]:
    records = []
    for entry in raw_list:
        if "error" in entry:
            # .get(), like the success path below: api/who_is.py happens to
            # set `domain` alongside `error` today, but that is a coupling
            # between two modules, not a guarantee this one can rely on.
            records.append(WhoisRecord(
                domain=entry.get("domain", ""), error=entry["error"]))
            continue
        records.append(WhoisRecord(
            domain=entry.get("domain", "N/A"),
            created=entry.get("created", "N/A"),
            expires=entry.get("expires", "N/A"),
            registrar=entry.get("registrar", "N/A"),
        ))
    return records
