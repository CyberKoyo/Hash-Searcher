import argparse
import asyncio
import datetime
import os
import sys

from .analysis.bazaar import extract_bazaar
from .analysis.censys import extract_hosts
from .analysis.crtsh import merge_crtsh
from .analysis.greynoise import extract_greynoise
from .analysis.ipdb import extract_ips
from .analysis.kev import known_exploited
from .analysis.shodan import extract_shodan, observed_cves
from .analysis.threatfox import extract_threatfox
from .analysis.otx import extract_otx
from .analysis.vt import extract_vt
from .analysis.whois import extract_whois
from .api.api_data_puller import data_puller, resolve_hash
from .api.base_call import error_status, make_error
from .cache import ResponseCache
from .hashing import check_env
from .models import Report, Verdict
from .render.json_out import write_json
from .render.pdf import write_pdf
from .render.tty import render
from .scoring import score
from .static.runner import analyze

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


def exit_code(verdict: Verdict) -> int:
    """Unknown levels fail safe to EXIT_UNKNOWN, never to EXIT_CLEAN."""
    return _EXIT_BY_LEVEL.get(verdict.level, EXIT_UNKNOWN)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash-searcher",
        description="Check a file or hash against VirusTotal, AbuseIPDB, "
                    "Censys, OTX, RDAP, and several keyless sources.",
    )
    parser.add_argument("indicator", help="a file path, or an MD5/SHA-1/SHA-256 digest")
    parser.add_argument("-o", "--output", help="write a report to this path (.json or .pdf)")
    parser.add_argument("--zip-password", help="password for an encrypted ZIP")
    parser.add_argument("--no-cache", action="store_true", help="ignore and bypass the cache")
    parser.add_argument("--refresh", action="store_true", help="force fresh calls, then re-cache")
    parser.add_argument("--no-static", action="store_true",
                        help="skip local static analysis (entropy, PE, YARA, strings)")
    parser.add_argument("--yara-rules", dest="yara_rules",
                        help="directory of .yar/.yara rules to scan the sample against")
    return parser


def output_format(path: str) -> str | None:
    ext = os.path.splitext(path)[1].lower()
    return {".json": "json", ".pdf": "pdf"}.get(ext)


def write_report(report: Report, output: str,
                 verdict: Verdict | None = None) -> None:
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

    # Static analysis runs before any network call and before check_env() --
    # both above the point that used to bail early. A sample nobody has ever
    # uploaded, or a run with no API key configured at all, is exactly the
    # case this phase exists to serve: local findings must never be computed
    # and then thrown away because the online half has nothing to add.
    # os.path.isfile guards a bare hash argument -- there is no file to
    # analyze, and attempting one is a crash, not a smaller report.
    static_report = None
    if not args.no_static and os.path.isfile(args.indicator):
        try:
            static_report = analyze(args.indicator, yara_rules=args.yara_rules)
        except Exception:
            # A local analyzer failure must never block the network pass --
            # this phase exists to ADD information, not to become a new way
            # the tool can fail to run at all.
            static_report = None

    # strings-derived IOCs feed back into the enrichment path: a sample
    # nobody has ever uploaded to VT still yields IPs to look up. static_report
    # is None on --no-static/a bare hash, and .strings is None when that one
    # analyzer landed in `failed` -- neither may crash this pass.
    extra_ips = None
    if static_report is not None and static_report.strings is not None:
        extra_ips = static_report.strings.iocs.ips

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

    if not check_env():
        if static_report is None:
            return EXIT_NO_DATA
        # No provider is configured at all, but the static pass above still
        # produced a report -- render it instead of discarding it. This is
        # the phase's headline case: with no key and no network, a sample
        # still yields local findings rather than a bare "no usable
        # sources" and nothing else. vt/otx/ips/hosts/whois all read as "no
        # online data available" rather than as an error; score() already
        # treats vt.found is False correctly, escaping UNKNOWN only when the
        # static pass itself found something.
        print("Continuing with local static analysis results only.")
        offline = make_error("no API key configured")
        report = Report(
            indicator=file_hash,
            generated_at=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            vt=extract_vt(offline), otx=extract_otx(offline),
            ips={}, hosts=[], whois=[],
            source_file=args.indicator,
            static=static_report,
        )
        verdict = score(report)
        render(report, verdict)
        if args.output:
            write_report(report, args.output, verdict)
        return exit_code(verdict)

    print("Pulling data from VirusTotal, IPDB, OTX, Censys, and RDAP...")
    cache = ResponseCache(enabled=not args.no_cache, refresh=args.refresh)
    try:
        raw = await data_puller(file_hash, cache, extra_ips=extra_ips)
    finally:
        cache.close()
    if not raw:
        print("No data was able to be pulled.")
        return EXIT_NO_DATA

    vt = extract_vt(raw["vt"])
    otx = extract_otx(raw["otx"])
    if error_status(raw["vt"]) == 404:
        # Not an error, and never a reason to stop: resolve_hash already
        # proved this is a well-formed digest or a real file, and the
        # keyless sources answer for hashes VT has never recorded. The old
        # "Invalid hash" bail discarded a MalwareBazaar family match and a
        # ThreatFox attribution that had already been fetched.
        print("VirusTotal has no record of this indicator -- "
              "continuing with the other sources.")

    ips = extract_ips(raw["ipdb"])
    _domains, hosts = extract_hosts(raw["censys"], ips)
    # RDAP is a registered provider now, so its fan-out happens inside
    # data_puller alongside every other source -- cli only extracts.
    whois = extract_whois(raw["rdap"])

    shodan = {ip: extract_shodan(payload) for ip, payload in raw["shodan"].items()}
    greynoise = {ip: extract_greynoise(payload)
                 for ip, payload in raw["greynoise"].items()}
    # Purely local: data_puller downloaded the catalog at most once, and
    # only if there was a CVE to intersect it against. Every entry in
    # `shodan` was queried by construction (raw["shodan"] only holds IPs
    # data_puller actually fetched), but .ok is checked anyway rather than
    # assumed.
    cves = observed_cves(r.value for r in shodan.values() if r.ok)

    report = Report(
        indicator=file_hash,
        generated_at=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        vt=vt, otx=otx, ips=ips, hosts=hosts, whois=whois,
        source_file=args.indicator,
        static=static_report,
        # Each extractor now decides "never asked" for itself -- raw["bazaar"]
        # is None or raw["crtsh"] is [] means exactly that, and the extractor
        # returns a SourceResult saying so instead of cli.py checking first.
        bazaar=extract_bazaar(raw["bazaar"]),
        threatfox=extract_threatfox(raw["threatfox"]),
        certs=merge_crtsh(raw["crtsh"]),
        shodan=shodan,
        greynoise=greynoise,
        kev=known_exploited(cves, raw["kev"]),
    )

    verdict = score(report)
    render(report, verdict)

    if args.output:
        write_report(report, args.output, verdict)

    return exit_code(verdict)


def run() -> None:
    """Console-script entry point."""
    sys.exit(asyncio.run(run_cli()))
