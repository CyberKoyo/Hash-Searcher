import argparse
import asyncio
import datetime
import os
import sys

from .analysis.censys import extract_hosts
from .analysis.ipdb import extract_ips
from .analysis.otx import extract_otx
from .analysis.vt import extract_vt
from .analysis.whois import extract_whois
from .api.api_data_puller import data_puller, resolve_hash
from .api.config import BASE_DIR
from .api.who_is import who_is
from .hashing import check_env
from .models import Report
from .render.json_out import write_json
from .render.pdf import write_pdf
from .render.tty import render

EXIT_OK = 0
EXIT_NO_DATA = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash-searcher",
        description="Check a file or hash against VirusTotal, AbuseIPDB, "
                    "Censys, OTX, and WHOIS.",
    )
    parser.add_argument("indicator", help="a file path, or an MD5/SHA-1/SHA-256 digest")
    parser.add_argument("-o", "--output", help="write a report to this path (.json or .pdf)")
    parser.add_argument("--zip-password", help="password for an encrypted ZIP")
    return parser


def output_format(path: str) -> str | None:
    ext = os.path.splitext(path)[1].lower()
    return {".json": "json", ".pdf": "pdf"}.get(ext)


async def run_cli(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    check_env()

    resolved = resolve_hash(args.indicator)
    if not resolved:
        return EXIT_NO_DATA

    file_hash = resolved[0]
    if len(resolved) > 1:
        print(f"\n[!] Archive holds {len(resolved)} files. Analyzing the first: {file_hash}")
        for skipped in resolved[1:]:
            print(f"    not analyzed: {skipped}")

    print("Pulling data from VirusTotal, IPDB, OTX, Censys, and WHOIS...")
    raw = await data_puller(file_hash)
    if not raw:
        print("No data was able to be pulled.")
        return EXIT_NO_DATA

    vt = extract_vt(raw["vt"])
    otx = extract_otx(raw["otx"])
    if not vt.found and not otx.attack_techniques and otx.recorded_instances == "N/A":
        print("Invalid hash. Please check filename or hash.")
        return EXIT_NO_DATA

    ips = extract_ips(raw["ipdb"])
    domains, hosts = extract_hosts(raw["censys"], ips)
    whois = extract_whois(await who_is(domains)) if domains else []

    report = Report(
        indicator=file_hash,
        generated_at=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        vt=vt, otx=otx, ips=ips, hosts=hosts, whois=whois,
        source_file=args.indicator,
    )

    render(report)

    if args.output:
        path = os.path.join(BASE_DIR, args.output)
        fmt = output_format(args.output)
        if fmt == "json":
            write_json(report, path)
        elif fmt == "pdf":
            write_pdf(report, path)
        else:
            print(f"Unrecognized output extension: {args.output} (use .json or .pdf)")

    return EXIT_OK


def run() -> None:
    """Console-script entry point."""
    sys.exit(asyncio.run(run_cli()))
