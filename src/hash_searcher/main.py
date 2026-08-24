from .hashing import check_env
import sys
import asyncio
from .formatters import ip_sorter, ip_formatter, otx_formatter, vt_rules, censys_formatter, whois_formatter
from .api.api_data_puller import data_puller
from .api.who_is import who_is
from .api.base_call import error_status
import datetime
import json
from .report import generate_pdf
from .api.config import BASE_DIR
import os

async def main():

    if ((len(sys.argv) > 4) or (len(sys.argv) < 2)):
        print("Usage: python hash-searcher.py <file_or_hash> [-o]")
        return
    check_env()
    print("Pulling data from VirusTotal, IPDB, OTX, Censys, and WHOIS...")
    data = await data_puller()
    if not data:
        return print("No data was able to be pulled.")

    vt_data = data['vt']
    otx_data = data['otx']
    ipdb_data = data['ipdb']
    censys_results = data['censys']
    ips = data['ips']
    file_hash = data['hash']

    # Bail before printing empty sections if neither source recognized the hash.
    if error_status(vt_data) == 404 and not otx_data.get('pulse_info', {}).get('pulses'):
        return print("Invalid hash. Please check filename or hash.")

    # 1, Displays what the virus does in priority order with a title and description
    print("\nVIRUSTOTAL SIGMA RULES")
    print("\n" + "="*50)
    vt_summary = vt_rules(vt_data)
    reports_and_confidence = {}
    enriched_ips = []
    whois_results = []

    # Gate on whether VT actually returned contacted IPs, not on how many
    # entries a positional results list happened to have.
    if ips:
        # 2. Display IPs, AbuseIPDB confidence, and number of reports
        print("\n" + "="*50)
        reports_and_confidence = ip_sorter(ipdb_data)
        ip_formatter(reports_and_confidence)

        # 3. Displays IPs, organization who owns it, asn, countries, and ports running
        all_domains, enriched_ips = censys_formatter(censys_results, reports_and_confidence)
        whois_results = whois_formatter(await who_is(all_domains))

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
            output_path = os.path.join(BASE_DIR, file)
            with open(output_path, 'w') as out_file:
                json.dump(report, out_file, sort_keys=True, indent=4, ensure_ascii=False)
        elif ".pdf" in file:
            generate_pdf(file, file_hash, vt_summary, otx_summary, reports_and_confidence, enriched_ips, whois_results)



def run():
    """Console-script entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
