from ..models import WhoisRecord


def extract_whois(raw_list) -> list[WhoisRecord]:
    records = []
    for entry in raw_list:
        if "error" in entry:
            records.append(WhoisRecord(domain=entry["domain"], error=entry["error"]))
            continue
        records.append(WhoisRecord(
            domain=entry.get("domain", "N/A"),
            created=entry.get("created", "N/A"),
            expires=entry.get("expires", "N/A"),
            registrar=entry.get("registrar", "N/A"),
        ))
    return records
