import whois
from datetime import datetime

def who_is(domains: list) -> list:
    results = []
    for domain in domains:
        try:
            info = whois.query(domain)
            if not info:
                results.append({"domain": domain, "error": "No WHOIS data found"})
                continue
            
            data = info.__dict__
            created = data.get("creation_date")
            expires = data.get("expiration_date")
            
            # creation_date can be a list, take the first entry if so
            if isinstance(created, list):
                created = created[0]
            if isinstance(expires, list):
                expires = expires[0]

            cdate = created.strftime("%Y-%m-%d") if isinstance(created, datetime) else "N/A"
            edate = expires.strftime("%Y-%m-%d") if isinstance(expires, datetime) else "N/A"

            results.append({
                "domain":     domain,
                "created":    cdate,
                "expires":    edate,
                "registrar":  data.get("registrar") or "N/A",
            })
        except Exception as e:
            results.append({"domain": domain, "error": str(e)})
    
    return results