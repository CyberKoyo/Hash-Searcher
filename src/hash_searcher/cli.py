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
from .api.base_call import error_status
from .api.who_is import who_is
from .cache import ResponseCache
from .hashing import check_env
from .models import Report
from .render.json_out import write_json
from .render.pdf import write_pdf
from .render.tty import render
from .scoring import score

EXIT_CLEAN = 0
EXIT_SUSPICIOUS = 1
EXIT_MALICIOUS = 2
EXIT_UNKNOWN = 3
EXIT_NO_DATA = 3  # an unusable run and an unknown sample answer a script alike

_EXIT_BY_LEVEL = {
    "CLEAN": EXIT_CLEAN,
    "SUSPICIOUS": EXIT_SUSPICIOUS,
    "MALICIOUS": EXIT_MALICIOUS,
    "UNKNOWN": EXIT_UNKNOWN,
}


def exit_code(verdict) -> int:
    """Unknown levels fail safe to EXIT_UNKNOWN, never to EXIT_CLEAN."""
    return _EXIT_BY_LEVEL.get(verdict.level, EXIT_UNKNOWN)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash-searcher",
        description="Check a file or hash against VirusTotal, AbuseIPDB, "
                    "Censys, OTX, and WHOIS.",
    )
    parser.add_argument("indicator", help="a file path, or an MD5/SHA-1/SHA-256 digest")
    parser.add_argument("-o", "--output", help="write a report to this path (.json or .pdf)")
    parser.add_argument("--zip-password", help="password for an encrypted ZIP")
    parser.add_argument("--no-cache", action="store_true", help="ignore and bypass the cache")
    parser.add_argument("--refresh", action="store_true", help="force fresh calls, then re-cache")
    return parser


def output_format(path: str) -> str | None:
    ext = os.path.splitext(path)[1].lower()
    return {".json": "json", ".pdf": "pdf"}.get(ext)


def write_report(report: Report, output: str, verdict=None) -> None:
    """Resolve output relative to the CWD and dispatch on the extension.

    This used to join onto BASE_DIR -- the installed package directory --
    so `-o report.json` wrote inside site-packages rather than where the
    user ran the command.
    """
    path = os.path.abspath(output)
    fmt = output_format(output)
    if fmt == "json":
        write_json(report, path, verdict)
    elif fmt == "pdf":
        write_pdf(report, path, verdict)
    else:
        print(f"Unrecognized output extension: {output} (use .json or .pdf)")


async def run_cli(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not check_env():
        return EXIT_NO_DATA

    try:
        resolved = resolve_hash(args.indicator, args.zip_password)
    except FileNotFoundError as e:
        # The exception is constructed with a perfectly good user-facing
        # string and was simply never caught, so `hash-searcher notahash`
        # printed a traceback. Pre-existing on 43e9f92 and on 129ff8d.
        print(e)
        return EXIT_NO_DATA
    if not resolved:
        return EXIT_NO_DATA

    file_hash = resolved[0]
    if len(resolved) > 1:
        print(f"\n[!] Archive holds {len(resolved)} files. Analyzing the first: {file_hash}")
        for skipped in resolved[1:]:
            print(f"    not analyzed: {skipped}")

    print("Pulling data from VirusTotal, IPDB, OTX, Censys, and WHOIS...")
    cache = ResponseCache(enabled=not args.no_cache, refresh=args.refresh)
    try:
        raw = await data_puller(file_hash, cache)
    finally:
        cache.close()
    if not raw:
        print("No data was able to be pulled.")
        return EXIT_NO_DATA

    vt = extract_vt(raw["vt"])
    otx = extract_otx(raw["otx"])
    if error_status(raw["vt"]) == 404 and not otx.has_pulses:
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

    verdict = score(report)
    render(report, verdict)

    if args.output:
        write_report(report, args.output, verdict)

    return exit_code(verdict)


def run() -> None:
    """Console-script entry point."""
    sys.exit(asyncio.run(run_cli()))
