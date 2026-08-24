
def ip_sorter(data):
    """Build {ip: info} from AbuseIPDB responses.

    Keyed by IP. Keying by (hostnames, domain) meant every IP that came back
    without either one shared a key, and all but the first were dropped.
    """
    ips = {}
    for entry in data:
        inner = entry.get('data', {})
        if not inner:
            print("No data from IPDB available.")
            continue

        ip = inner.get('ipAddress')
        if not ip:
            continue

        hostnames = inner.get('hostnames') or []
        if not isinstance(hostnames, list):
            hostnames = [hostnames]

        reports = inner.get('reports', 0)

        ips[ip] = {
            'ip': ip,
            'confidence': inner.get('abuseConfidenceScore', 0),
            'reports': len(reports) if isinstance(reports, list) else reports,
            'hostnames': [h for h in hostnames if h],
            'domain': inner.get('domain'),
        }
    return ips

def vt_rules(vt_data):
    rules = vt_data.get('data', {}).get('attributes', {}).get('sigma_analysis_results', [])
    high_priority = []
    mid_priority = []
    low_priority = []
    for i in rules:
        if i.get('rule_level') == 'high':
            high_priority.append(i)
        elif i.get('rule_level') == 'medium':
            mid_priority.append(i)
        elif i.get('rule_level') == 'low':
            low_priority.append(i)
    print("HIGH PRIORITY RULES")
    print("="*50)
    if len(high_priority) == 0:
        print('No High Priority Rules Found.') 
    else:
        for rule in high_priority:
            print(f"{rule.get('rule_title')}:")
            print(f"{rule.get('rule_description')}. ")
    print('\n')
    print("MEDIUM PRIORITY RULES")
    print("="*50)
    if len(mid_priority) == 0:
        print('No Medium Priority Rules Found.') 
    else:
        for rule in mid_priority:
            print(f"{rule.get('rule_title')}:")
            print(f"{rule.get('rule_description')}.")
    print('\n')
    print("LOW PRIORITY RULES")
    print("="*50)
    if len(low_priority) == 0:
        print('No Low Priority Rules Found.') 
    else:
        for rule in low_priority:
            print(rule.get('rule_title'))
            print(rule.get('rule_description'))
    return {
            "high": [{"title": r.get("rule_title"), "description": r.get('rule_description')} for r in high_priority], 
            "medium": [{"title": r.get("rule_title"), "description": r.get('rule_description')} for r in mid_priority], 
            "low": [{"title": r.get("rule_title"), "description": r.get('rule_description')} for r in low_priority]
    }

def otx_formatter(data):
    pulse_info = data.get('pulse_info')
    if not pulse_info:
        print("No OTX data available.")
        return {"recorded_instances": "N/A", "attack_techniques": []}
    counts = pulse_info.get('count', 'N/A, No recorded instances')
    pulse_data = pulse_info.get('pulses', [])

    print(f'Recorded instances: {counts}')

    recent_pulses = pulse_data[:5]
    flags = []
    for i in recent_pulses:
        activity = i.get('attack_ids', [])
        if len(activity) != 0:
            for j in activity:
                malware_flag = j.get('display_name')
                if malware_flag not in flags:
                    flags.append(malware_flag)
    
    for a in flags:
        print(a)
    return {
        "recorded_instances": counts,
        "attack_techniques": flags
    }

def ip_formatter(data):
    w1, w2, w3 = 16, 12, 10
    total = w1 + w2 + w3 + 2
    print(f"{'IP':<{w1}} {'CONFIDENCE':<{w2}} {'REPORTS':<{w3}}")
    print("-" * total)
    for info in data.values():
        display_ip = str(info.get("ip", "N/A"))
        display_conf = f"{info.get('confidence', 'N/A')}%"
        display_reports = str(info.get("reports", "N/A"))
        print(f"{display_ip:<{w1}} {display_conf:<{w2}} {display_reports:<{w3}}")
    print("-" * total)


def censys_formatter(censys_results, ips_and_hostnames):
    """
    Takes a list of raw Censys API responses (one per IP) and the map returned
    by ip_sorter. Prints enrichment data and flags anything new that IPDB
    didn't have.
    """
    # Flatten all known hostnames and domains from IPDB into sets for quick lookup
    known_hostnames = set()
    known_domains = set()
    for info in ips_and_hostnames.values():
        known_hostnames.update(info['hostnames'])
        if info['domain']:
            known_domains.add(info['domain'])
    all_domains = known_domains.copy()
    print("\n" + "="*50)
    print("CENSYS ENRICHMENT")
    print("="*50)

    enriched_ips = []
    for censys_data in censys_results:
        # Skip error responses
        if "Error" in censys_data or "error" in censys_data:
            print(f"Censys: {censys_data.get('Error') or censys_data.get('error')}")
            continue
        result = censys_data.get('result', {}).get('resource', {})
        ip_str  = result.get("ip", "N/A")
        org     = result.get("autonomous_system", {}).get("name")
        asn     = result.get("autonomous_system", {}).get("asn")
        ports   = [s['port'] for s in result.get('services', [])]
        country = result.get('autonomous_system', {}).get("country_code") or "N/A"

        censys_hostnames = set(result.get('dns', {}).get('reverse_dns', {}).get("names", []))

        # Find what Censys knows that IPDB didn't surface
        new_hostnames = censys_hostnames - known_hostnames
        all_domains.update(censys_hostnames)
        print(f"\nIP:      {ip_str}")
        print(f"Org:     {org}  |  ASN: {asn}")
        print(f"Country: {country}")
        print(f"Ports:   {', '.join(str(p) for p in ports) if ports else 'N/A'}")

        if new_hostnames:
            print("[!] New indicators not found in AbuseIPDB:")
            print(f"    Hostnames: {', '.join(sorted(new_hostnames))}")
            if ip_str in ips_and_hostnames:
                ips_and_hostnames[ip_str]['hostnames'].extend(sorted(new_hostnames))
        else:
            print("    No new indicators beyond AbuseIPDB data.")
        enriched_ips.append({
            'ip': ip_str,
            'org': org,
            'asn': asn,
            'country': country,
            'ports': ports,
            'new_hostnames': sorted(new_hostnames)
        })
    return sorted(all_domains), enriched_ips


def whois_formatter(whois_results: list):
    print("\n" + "="*50)
    print("WHOIS DATA")
    print("="*50)
    print(f"{'DOMAIN':<35} {'CREATED':<12} {'EXPIRES':<12} {'REGISTRAR':<30}")
    print("-"*89)
    for entry in whois_results:
        if "error" in entry:
            print(f"{entry['domain']:<35} Error")
            continue
        print(f"{entry['domain']:<35} {entry['created']:<12} {entry['expires']:<12} {entry['registrar']:<30}")
    return whois_results

