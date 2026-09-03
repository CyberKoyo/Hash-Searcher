"""Running one list of indicators, and answering for the list as a whole.

Two things belong here that a single run has no opinion about: the cache is
opened once for the batch rather than once per indicator, and the process
exit code is the most severe of the runs rather than the last of them.

Imports cli rather than the other way round. cli.run_cli defers its import
of this module for exactly that reason -- see the comment there.
"""

import os
import re

from .cache import ResponseCache
from .cli import (
    EXIT_CLEAN, EXIT_MALICIOUS, EXIT_NO_DATA, EXIT_SUSPICIOUS, EXIT_UNKNOWN,
    analyze_one,
)

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
    """Every indicator in turn, over one cache, answering as a whole.

    Serial rather than concurrent, deliberately: every provider here rate
    limits, several are serial within a single run already, and running
    N indicators at once would multiply the request rate by N against
    exactly the free tiers Constraint 8 exists to protect.
    """
    if not indicators:
        print("No indicators to check.")
        return EXIT_NO_DATA

    cache = ResponseCache(enabled=not args.no_cache, refresh=args.refresh)
    codes = []
    try:
        for index, indicator in enumerate(indicators):
            print(f"\n[{index + 1}/{len(indicators)}] {indicator}")
            output = (batch_output_path(args.output, index, indicator)
                      if args.output else None)
            codes.append(await analyze_one(indicator, args, cache=cache,
                                           output=output))
    finally:
        cache.close()
    return worst_exit_code(codes)
