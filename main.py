from hashing import check_env
import sys
import asyncio
from formatters import ip_sorter, ip_formatter, otx_formatter, vt_rules, censys_formatter, whois_formatter
from api.api_data_puller import data_puller
from who_is import who_is
import datetime
import json
from report import generate_pdf
async def main():

    if ((len(sys.argv) > 4) or (len(sys.argv) < 2)):
        print("Usage: python hash-searcher.py <file_or_hash> [-o]")
        return
    check_env()
    print("Pulling data from VirusTotal, IPDB, OTX, Censys, and WHOIS...")
    results, ips, censys_results, file_hash = await data_puller()
    if not results or len(results) < 2:
        return "No data was able to be pulled."

    vt_data = results[0]
    otx_data = results[1]
    
    # 1, Displays what the virus does in priority order with a title and description
    print("\nVIRUSTOTAL SIGMA RULES")
    print("\n" + "="*50)
    vt_summary = vt_rules(vt_data) 
    reports_and_confidence = {}
    enriched_ips = []
    whois_results = []
    if len(results) > 3:
        ipdb_data = results[2:2+len(ips)]
        if (vt_data.get('Error') == 'Hash not found in GetTotal') and not (otx_data.get('pulse_info').get('pulses')):
            return print("Invalid hash. Please check filename or hash.")
        
        # 2. Display IPs, AbuseIPDB confidence, and number of reports
        print("\n" + "="*50)
        reports_and_confidence = ip_sorter(ipdb_data)
        ip_formatter(reports_and_confidence)

        # 3. Displays IPs, organization who owns it, asn, countries, and ports running
        all_domains, enriched_ips = censys_formatter(censys_results)
        whois_results = whois_formatter(who_is(all_domains))
        


        # 4. Display OTX Data: recorded instances, what it's flagged to do
    print("\n" + "="*50)
    print("OTX DATA")
    print("="*50)
    otx_summary = otx_formatter(otx_data)
    
    # 5. Outputs in either a JSON or PDF
    time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if len(sys.argv) == 4 and sys.argv[2] == '-o':
        file = sys.argv[3]
        name = sys.argv[1]
        if ".json" in file:
            report = {
                'file': name,
                'time': time,
                'report': {
                    'hash': file_hash,
                    'otx': otx_summary,
                    'censys': enriched_ips,
                    'whois': whois_results, 
                    'vt_rules': vt_summary
                }
            }
            with open(file, 'w') as out_file:
                json.dump(report, out_file, sort_keys=True, indent=4, ensure_ascii=False)
        elif ".pdf" in file:
            generate_pdf(file, file_hash, vt_summary, otx_summary, reports_and_confidence, enriched_ips, whois_results)



if __name__ == "__main__":
    asyncio.run(main())
