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
from .api.api_data_puller import (
    PIVOT_FETCH_BUDGET, data_puller, resolve_indicator,
)
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


def _depth(value: str) -> int:
    """A non-negative pivot depth, rejected by argparse rather than deep
    inside the fan-out where the message would name neither the flag nor
    the value."""
    depth = int(value)
    if depth < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or more, got {depth}")
    return depth


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash-searcher",
        description="Check a file, hash, IP, domain, or URL against "
                    "VirusTotal, AbuseIPDB, Censys, OTX, RDAP, and "
                    "several keyless sources.",
    )
    # nargs="?" because --input-file supplies the indicators instead, and
    # `hash-searcher --input-file iocs.txt` -- the form the README shows --
    # is not a command anyone should have to pad with a dummy argument.
    # parse_args() below rejects the case where neither is given, so the
    # requirement survives; it just cannot be spelled by argparse alone.
    parser.add_argument(
        "indicator", nargs="?", default=None,
        help="a file path, an MD5/SHA-1/SHA-256 digest, an IP, a domain, "
             "or a URL -- defanged forms (hxxp://, 1[.]2[.]3[.]4) accepted; "
             "omit it when using --input-file, or pass - to read stdin")
    parser.add_argument("--input-file", dest="input_file",
                        help="read indicators from this file, one per line "
                             "(blank lines and # comments are skipped)")
    parser.add_argument("-o", "--output", help="write a report to this path (.json or .pdf)")
    parser.add_argument("--zip-password", help="password for an encrypted ZIP")
    parser.add_argument("--no-cache", action="store_true", help="ignore and bypass the cache")
    parser.add_argument("--refresh", action="store_true", help="force fresh calls, then re-cache")
    parser.add_argument("--pivot-depth", dest="pivot_depth", type=_depth,
                        default=0, metavar="N",
                        help=f"look up domains discovered through crt.sh, N "
                             f"levels deep (default 0). At most "
                             f"{PIVOT_FETCH_BUDGET} extra domain lookups per "
                             f"run whatever N is")
    parser.add_argument("--no-static", action="store_true",
                        help="skip local static analysis (entropy, PE, YARA, strings)")
    parser.add_argument("--yara-rules", dest="yara_rules",
                        help="directory of .yar/.yara rules to scan the sample against")
    return parser


#: The positional argument that means "read the indicators from stdin".
#: The conventional spelling, and it cannot collide with a real indicator:
#: classify() does not recognize "-", and a file named "-" would have to be
#: passed as "./-" for any other tool either.
STDIN_ARGUMENT = "-"


COMMENT_PREFIX = "#"


def read_indicators(handle) -> list[str]:
    """One indicator per line, with blank lines and # comments dropped.

    A list an analyst pastes out of a report carries both. Feeding either
    one to classify() would produce a "not a recognizable indicator" line
    per blank line, which buries the answers.
    """
    found = []
    for line in handle:
        stripped = line.strip()
        if stripped and not stripped.startswith(COMMENT_PREFIX):
            found.append(stripped)
    return found


def batch_lines(args) -> list[str] | None:
    """The indicators for a batch run, or None when this is a single run.

    None rather than a one-element list, so the single-indicator path stays
    exactly what it was -- including a ZIP argument, where resolve_indicator
    returns several hashes and analyze_one deliberately analyzes only the
    first. Treating that as a batch would silently change what a ZIP does.
    """
    if args.input_file:
        with open(args.input_file, encoding="utf-8") as handle:
            return read_indicators(handle)
    if args.indicator == STDIN_ARGUMENT:
        return read_indicators(sys.stdin)
    return None


def parse_args(argv: list[str] | None = None):
    """Parse argv and enforce what argparse cannot say on its own.

    The indicator is optional only because --input-file can stand in for
    it. Neither one is still an error, and it is raised through
    parser.error so it exits 2 with a usage line like every other argument
    mistake rather than as a message this module invents.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.indicator is None and not args.input_file:
        parser.error("an indicator is required -- pass one, or --input-file "
                     "PATH, or - to read a list from stdin")
    return args


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


async def analyze_one(user_input: str, args, cache: ResponseCache | None = None,
                      output: str | None = None) -> int:
    """One indicator, start to finish: resolve, fetch, score, render, exit.

    This is the whole of what `run_cli` used to be, with three arguments
    lifted out of `args` so a batch can vary them per indicator:

    - `user_input` rather than args.indicator, because a batch's indicators
      come from stdin or a file, not from the positional argument.
    - `cache`, so a batch opens ONE ResponseCache for the whole run. Two
      indicators that share a contacted IP should cost one lookup, and a
      cache per indicator would throw that away. None means "single run" --
      open one here and close it before returning.
    - `output`, so `-o report.json` over a batch writes one file per
      indicator instead of overwriting the same file N times.
    """
    output = output or args.output

    # Static analysis runs before any network call and before check_env() --
    # both above the point that used to bail early. A sample nobody has ever
    # uploaded, or a run with no API key configured at all, is exactly the
    # case this phase exists to serve: local findings must never be computed
    # and then thrown away because the online half has nothing to add.
    # os.path.isfile guards a bare hash argument -- there is no file to
    # analyze, and attempting one is a crash, not a smaller report.
    static_report = None
    if not args.no_static and os.path.isfile(user_input):
        try:
            static_report = analyze(user_input, yara_rules=args.yara_rules)
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
        resolved = resolve_indicator(user_input, args.zip_password)
    except FileNotFoundError as e:
        # The exception is constructed with a perfectly good user-facing
        # string and was simply never caught, so `hash-searcher notahash`
        # printed a traceback. Pre-existing on 43e9f92 and on 129ff8d.
        print(e)
        return EXIT_NO_DATA
    if not resolved:
        return EXIT_NO_DATA

    indicator = resolved[0]
    if len(resolved) > 1:
        print(f"\n[!] Archive holds {len(resolved)} files. "
              f"Analyzing the first: {indicator.value}")
        for skipped in resolved[1:]:
            print(f"    not analyzed: {skipped.value}")

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
            indicator=indicator.value,
            indicator_kind=indicator.kind,
            generated_at=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            vt=extract_vt(offline), otx=extract_otx(offline),
            ips={}, hosts=[], whois=[],
            source_file=user_input,
            static=static_report,
        )
        verdict = score(report)
        render(report, verdict)
        if output:
            write_report(report, output, verdict)
        return exit_code(verdict)

    print("Pulling data from every source that answers for "
          f"{indicator.kind} indicators...")
    own_cache = cache is None
    if own_cache:
        cache = ResponseCache(enabled=not args.no_cache, refresh=args.refresh)
    try:
        raw = await data_puller(indicator, cache, extra_ips=extra_ips,
                                pivot_depth=args.pivot_depth)
    finally:
        # Only whoever opened it may close it: a batch's cache outlives
        # every individual run in it.
        if own_cache:
            cache.close()
    if not raw:
        print("No data was able to be pulled.")
        return EXIT_NO_DATA

    vt = extract_vt(raw["vt"])
    otx = extract_otx(raw["otx"])
    if error_status(raw["vt"]) == 404:
        # Not an error, and never a reason to stop: resolve_indicator
        # already proved this is a well-formed digest or a real file, and the
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
        indicator=indicator.value,
        indicator_kind=indicator.kind,
        generated_at=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        vt=vt, otx=otx, ips=ips, hosts=hosts, whois=whois,
        source_file=user_input,
        static=static_report,
        # Each extractor now decides "never asked" for itself -- raw["bazaar"]
        # is None or raw["crtsh"] is [] means exactly that, and the extractor
        # returns a SourceResult saying so instead of cli.py checking first.
        bazaar=extract_bazaar(raw["bazaar"]),
        threatfox=extract_threatfox(raw["threatfox"]),
        # The same extractor over the per-IP payloads: ThreatFox's answer
        # has the same shape whatever the indicator type was.
        threatfox_ips={ip: extract_threatfox(payload)
                       for ip, payload in raw["threatfox_ips"].items()},
        certs=merge_crtsh(raw["crtsh"]),
        shodan=shodan,
        greynoise=greynoise,
        kev=known_exploited(cves, raw["kev"]),
    )

    verdict = score(report)
    render(report, verdict)

    if output:
        write_report(report, output, verdict)

    return exit_code(verdict)


async def run_cli(argv: list[str] | None = None) -> int:
    """Parse the command line and dispatch to one run or to a batch."""
    args = parse_args(argv)

    # --- I2: a list that cannot be read is a message, not a traceback.
    # cli.py already carries this exact fix for the positional argument
    # (see the FileNotFoundError catch in analyze_one); --input-file opened
    # a second door to the same behavior.
    try:
        lines = batch_lines(args)
    except (OSError, UnicodeDecodeError) as e:
        print(f"Could not read {args.input_file}: {e}")
        return EXIT_NO_DATA

    if lines is None:
        return await analyze_one(args.indicator, args)
    # Imported here, not at module scope: batch.py runs this module's
    # analyze_one over each indicator and reads its exit codes, so it
    # imports cli. One of the two directions has to be deferred, and this
    # is the one -- dispatching to a batch is the later, higher-level half
    # of the pair, and cli is fully initialized by the time it runs.
    from .batch import run_batch
    return await run_batch(lines, args)


def run() -> None:
    """Console-script entry point."""
    sys.exit(asyncio.run(run_cli()))
