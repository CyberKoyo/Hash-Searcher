"""Running one list of indicators, and answering for the list as a whole.

Two things belong here that a single run has no opinion about: the cache and
the VirusTotal rate budget are opened once for the batch rather than once
per indicator, and the process exit code is the most severe of the runs
rather than the last of them.

Imports cli rather than the other way round. cli.run_cli defers its import
of this module for exactly that reason -- see the comment there.
"""

import os
import re

from .budget import RateBudget
from .cache import ResponseCache
from .cli import (
    EXIT_CLEAN, EXIT_MALICIOUS, EXIT_NO_DATA, EXIT_SUSPICIOUS, EXIT_UNKNOWN,
    analyze_one, output_format, unrecognized_output_message,
)
from .render.csv_out import failure_row, row, write_rendered_rows

#: How bad each exit code is, which is NOT the order of the codes
#: themselves: UNKNOWN is 3 and MALICIOUS is 2, so max() over the codes
#: would report a batch holding one malicious sample as merely unknown.
#: EXIT_NO_DATA is EXIT_UNKNOWN by construction (an unusable run and an
#: unknown sample answer a script alike), so it needs no entry of its own.
SEVERITY = {
    EXIT_CLEAN: 0,
    EXIT_UNKNOWN: 1,
    EXIT_SUSPICIOUS: 2,
    EXIT_MALICIOUS: 3,
}

#: Anything outside this class is replaced in a batch output filename. The
#: indicator is user input on its way into a path, so this is an allowlist:
#: a denylist of separators would still let through whatever the next
#: platform treats as one.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")

#: Long enough to keep a sha256 (64 chars) whole, short enough to stay well
#: inside the 255-byte filename limit once the stem and index are added.
SLUG_LIMIT = 64


def worst_exit_code(codes) -> int:
    """The most severe of the runs' exit codes.

    A batch that found one malicious sample must not exit 0 because the two
    after it were clean, and it must not exit 3 because the last one was
    unknown. An empty batch is EXIT_NO_DATA: nothing was checked, so
    nothing may report itself clean.
    """
    codes = list(codes)
    if not codes:
        return EXIT_NO_DATA
    # Unknown codes fail safe to the top of the UNKNOWN band rather than to
    # CLEAN, the same rule cli.exit_code follows for an unknown level.
    return max(codes, key=lambda code: SEVERITY.get(code, SEVERITY[EXIT_UNKNOWN]))


def _slug(indicator: str) -> str:
    return _UNSAFE.sub("_", indicator)[:SLUG_LIMIT] or "indicator"


def batch_output_path(output: str, index: int, indicator: str) -> str:
    """Where this indicator's report goes, given the batch's -o path.

    `-o report.json` over three indicators wrote one file three times, so
    two of the three reports were gone by the time the command returned.

    The name carries both an index and the indicator: the indicator so a
    reader can tell the files apart, and the index because the slug is
    lossy -- "a/b" and "a:b" both sanitize to "a_b" -- and only the index
    makes the name unique. Sanitizing is not cosmetic either: the indicator
    is user input reaching a filename, and "../../etc/passwd" must name a
    file in the output directory rather than one three levels above it.
    """
    directory, name = os.path.split(output)
    stem, extension = os.path.splitext(name)
    return os.path.join(directory, f"{stem}-{index + 1}-{_slug(indicator)}{extension}")


async def run_batch(indicators: list[str], args) -> int:
    """Every indicator in turn, over one cache and one budget, answering as
    a whole.

    Serial rather than concurrent, deliberately: every provider here rate
    limits, several are serial within a single run already, and running
    N indicators at once would multiply the request rate by N against
    exactly the free tiers Constraint 8 exists to protect.

    Serial is not on its own enough for VirusTotal, though, which is why
    the budget is opened here beside the cache and shared: four requests a
    minute is a ceiling a batch of five reaches without ever running two
    lookups at once.
    """
    if not indicators:
        print("No indicators to check.")
        return EXIT_NO_DATA

    # Checked once, before the first lookup. A single run prints
    # "Unrecognized output extension" after the work is done and still
    # shows its verdict; a batch would print it once per indicator, having
    # spent every rate-limited lookup on reports it then cannot write.
    if args.output and output_format(args.output) is None:
        print(unrecognized_output_message(args.output))
        return EXIT_NO_DATA

    # Same rule, same reason, one step further: an aggregating batch writes
    # nothing until the last indicator is done, so an unwritable path would
    # not surface until every rate-limited lookup had been spent. Under
    # per-indicator output the first indicator failed and the user found
    # out immediately. Checked by opening it, not with os.access -- access
    # answers for the real uid and lies under ACLs and read-only mounts,
    # and the only question that matters is whether the write will work.
    if args.output and output_format(args.output) == "csv":
        try:
            with open(os.path.abspath(args.output), "a", encoding="utf-8"):
                pass
        except OSError as e:
            print(f"Could not write {args.output}: {e}")
            return EXIT_NO_DATA

    cache = ResponseCache(enabled=not args.no_cache, refresh=args.refresh)
    # None is how --ignore-budget is spelled all the way down: analyze_one
    # sees a budget it did not open and does not open one of its own, and
    # data_puller enforces nothing.
    budget = None if args.ignore_budget else RateBudget()

    # CSV is the one format whose whole purpose is a table of N indicators
    # -- a triage queue sorted by score is what an analyst opens it for --
    # so a batch writing CSV accumulates and writes once. `-o` therefore
    # means "the file" for CSV and "the filename stem" for every other
    # format, which is an inconsistency on purpose: it is what each format
    # can actually express. A STIX bundle or a MISP event could hold N
    # indicators too, and deliberately does not yet.
    aggregating = bool(args.output) and output_format(args.output) == "csv"
    # Rendered as each run ends, not held as (report, verdict) pairs until
    # the last one: a 10,000-line batch would otherwise keep 10,000 whole
    # Reports alive -- static analysis, harvested strings, per-IP source
    # results -- for the sake of a row apiece. It also keeps this list one
    # type, so the write below is not sorting out what each entry is.
    collected: list[list[str]] = []

    codes = []
    write_failed = False
    try:
        for index, indicator in enumerate(indicators):
            print(f"\n[{index + 1}/{len(indicators)}] {indicator}")
            # One or the other, never both: with `pairs` supplied,
            # analyze_one appends to it and writes nothing, and this
            # function owns the single write. Two writers aimed at one path
            # would race for it.
            output = (batch_output_path(args.output, index, indicator)
                      if args.output and not aggregating else None)
            pairs: list | None = [] if aggregating else None
            try:
                codes.append(await analyze_one(indicator, args, cache=cache,
                                               output=output, budget=budget,
                                               rows=pairs))
                reason = "" if not aggregating or pairs else (
                    "no report produced -- see this indicator's output above")
            except Exception as e:
                # A batch is the mode where partial results matter most: a
                # 100-line run that dies on line 3 has already paid for
                # three lookups and produced nothing. The same rule
                # cli.py applies to a failing static analyzer -- one
                # component's failure must not become a new way the whole
                # run fails -- and the indicator is named, because a
                # traceback naming only the provider does not say which
                # line of the list produced it.
                reason = f"run failed ({type(e).__name__}: {e})"
                print(f"    {indicator}: {reason}")
                codes.append(EXIT_NO_DATA)
            if aggregating:
                # A failure row is synthesized here rather than inside
                # analyze_one, which reaches EXIT_NO_DATA from five
                # different places -- an unreadable archive, an indicator
                # resolving to nothing, no key and no static report, an
                # empty pull -- none of which has a Report to append. This
                # loop knows the indicator and the outcome for all five at
                # once, so the table's row count matches the input list's
                # line count without threading a placeholder through every
                # early return.
                collected.extend(row(*pair) for pair in pairs)
                if not pairs:
                    # The raw input line, unconditionally, because that is
                    # what a successful row carries: cli.py builds every
                    # Report with source_file=user_input whatever the
                    # indicator kind turned out to be. Guarding it on
                    # os.path.isfile reads as the more careful choice and is
                    # the wrong one -- it would make the failure rows the
                    # only ones where that column is sometimes empty, and a
                    # consumer joining the table back to the list it fed in
                    # needs the one column that always holds the line.
                    collected.append(
                        failure_row(indicator, reason, source_file=indicator))
    finally:
        cache.close()
        if budget is not None:
            budget.close()
        # In the finally, and this is the point of it: a KeyboardInterrupt
        # or a cancellation is a BaseException and walks straight past the
        # `except Exception` above, so a write placed after this block
        # simply would not run. Ctrl-C on line 3 of a long list would then
        # throw away lines 1 and 2 -- lookups already made and already paid
        # for -- which is the exact failure the loop's own handler exists
        # to prevent. Under per-indicator output those files were on disk
        # the moment each run ended; one table has to earn that back here.
        if aggregating and collected:
            try:
                write_rendered_rows(collected, os.path.abspath(args.output))
            except OSError as e:
                # Never mask whatever we are already unwinding, and never
                # turn a hundred good lookups into a traceback.
                print(f"Could not write {args.output}: {e}")
                write_failed = True

    if write_failed:
        # Not CLEAN. Every lookup may have succeeded, but the user asked for
        # a file and does not have one, and `hash-searcher ... -o out.csv &&
        # process out.csv` would otherwise run the second half against a
        # file that is not there. EXIT_NO_DATA is what this tool already
        # says for a run a script cannot act on.
        codes.append(EXIT_NO_DATA)
    return worst_exit_code(codes)
