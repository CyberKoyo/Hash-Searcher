
ips_and_hostnames = {}
def ip_sorter(data):
    for i in data:
        inner_data = i.get('data', {})
        if not inner_data:
            print("No data from IPDB available.")
            pass
        ip_data = inner_data.get('ipAddress', {})
        hostname_data = inner_data.get('hostnames')
        domain_data = inner_data.get('domain')
        confidence = inner_data.get('abuseConfidenceScore', 0)
        reports = inner_data.get('reports', 0)
        if reports != 0:
            report_count = len(reports)
        else:
            report_count = reports

        hostname_tuple = tuple(hostname_data) if isinstance(hostname_data, list) else (hostname_data,)
        combined_key = (hostname_tuple, domain_data)
        
        if combined_key not in ips_and_hostnames:
            ips_and_hostnames[combined_key] = {
                'ip': ip_data,
                'confidence': confidence,
                'reports': report_count
            }
    return ips_and_hostnames

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
    counts = pulse_info.get('count', 'N/A, No recorded instances')
    pulse_data = pulse_info.get('pulses', [])

    print(f'Recorded instances: {counts}')

    recent_pulses = []
    if len(pulse_data) >= 5:
        for i in range(5):
            recent_pulses.append(pulse_data[i])
    else:
        for i in pulse_data:
            recent_pulses.append(i)
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
    for (domain, hostname), ip_info in data.items():
        if isinstance(ip_info, dict):
            display_ip      = str(ip_info.get("ip", "N/A"))
            display_conf    = f"{ip_info.get('confidence', 'N/A')}%"
            display_reports = str(ip_info.get("reports", "N/A"))
        else:
            display_ip      = str(ip_info)
            display_conf    = "N/A"
            display_reports = "N/A"

        print(f"{display_ip:<{w1}} {display_conf:<{w2}} {display_reports:<{w3}}")
    print("-" * total)


def censys_formatter(censys_results):
    """
    Takes a list of raw Censys API responses (one per IP).
    Cross-references against ips_and_hostnames already populated by ip_sorter.
    Prints enrichment data and flags anything new that IPDB didn't have.
    """
    # Flatten all known hostnames and domains from IPDB into sets for quick lookup
    known_hostnames = set()
    known_domains = set()
    for (hostname_tuple, domain_str) in ips_and_hostnames.keys():
        for h in hostname_tuple:
            if h:
                known_hostnames.add(h)
        if domain_str:
            known_domains.add(domain_str)
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
            if new_hostnames:
                print(f"    Hostnames: {', '.join(sorted(new_hostnames))}")
                key = (tuple(sorted(new_hostnames)), None)
                if key not in ips_and_hostnames:
                    ips_and_hostnames[key] = ip_str
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

# TODO:
# 4. Auto-generate JSON at end.