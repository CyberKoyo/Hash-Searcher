"""Scan the sample against a user-supplied YARA rules directory.

No rules ship with the tool: open rulesets are large, fast-moving, and
variously licensed. The default location follows the same XDG convention
cache.py uses, and an absent directory is a quiet empty result rather than
an error -- no rules is the normal state of a fresh install.
"""

import os
import time
from pathlib import Path

from ..models import YaraHit
from . import capabilities

SCAN_TIMEOUT = 30  # seconds; the per-rule-file ceiling on a single match() call
RULE_SUFFIXES = (".yar", ".yara")

# branch-review.md I5: SCAN_TIMEOUT alone bounds one rule file, but a real
# community ruleset is routinely hundreds of files, and the old code had no
# ceiling on the total -- worst case N * SCAN_TIMEOUT, which for a few
# hundred files is hours. This is the budget for the WHOLE scan, across
# every rule file. 60s is generous for a local, offline pass (no network
# latency anywhere in this loop) while still returning a triage tool's
# result in about the time a user will wait without wondering if it hung.
YARA_WALL_CLOCK_BUDGET = 60

# And a ceiling on how many rule files are even considered, independent of
# how fast each one scans -- compiling and matching against 500 files (a
# large real-world ruleset, per the review) is already a lot of work before
# the wall-clock budget above would even trip on fast rules; beyond that,
# `--yara-rules ~` or a similar typo is more likely than a deliberately
# large ruleset.
MAX_RULE_FILES = 500


LEGACY_DATA_DIR = "hash-searcher"


def rules_dir() -> Path:
    """The default ruleset directory, or the pre-rename one still holding it.

    Renaming the project moved this path, and the rules under it are the
    user's own files, not ours to relocate. Reading the old directory when
    the new one does not exist keeps a rename from silently turning a
    populated default ruleset into an empty scan; writing rules to the new
    path takes precedence from then on.
    """
    root = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    current = root / "ioc-inquest" / "yara"
    if not current.exists():
        legacy = root / LEGACY_DATA_DIR / "yara"
        if legacy.exists():
            return legacy
    return current


def analyze_yara(path: str, rules_path: str | None = None) -> tuple[list[YaraHit], str]:
    """Returns (hits, note). `note` is non-empty only when the scan stopped
    before considering every rule file -- either the file-count cap or the
    aggregate wall-clock budget below was hit. A silently truncated scan
    would look identical to a complete one that simply found nothing."""
    if not capabilities.have("yara"):
        return [], ""

    directory = Path(rules_path) if rules_path else rules_dir()
    if not directory.is_dir():
        return [], ""

    import yara

    # Filtered BEFORE sorted() runs, not after: `sorted(directory.rglob("*"))`
    # used to materialise every path in the tree -- every unrelated file, not
    # just rule files -- before the suffix check ran. A generator expression
    # here means sorted() never sees, and never has to hold in memory, a path
    # that was never going to be a rule file in the first place.
    rule_files = sorted(
        p for p in directory.rglob("*") if p.suffix.lower() in RULE_SUFFIXES
    )

    note_parts: list[str] = []
    total_found = len(rule_files)
    if total_found > MAX_RULE_FILES:
        rule_files = rule_files[:MAX_RULE_FILES]
        note_parts.append(f"stopped after {MAX_RULE_FILES} of {total_found} rule files")

    hits: list[YaraHit] = []
    started = time.monotonic()
    for index, rule_file in enumerate(rule_files):
        elapsed = time.monotonic() - started
        if elapsed >= YARA_WALL_CLOCK_BUDGET:
            note_parts.append(
                f"stopped after {index} of {len(rule_files)} rule files "
                f"({YARA_WALL_CLOCK_BUDGET}s budget exceeded)"
            )
            break
        try:
            # Compiled one file at a time: a single malformed .yar in the
            # user's directory must not abort every other rule.
            compiled = yara.compile(filepath=str(rule_file))
            # Never wait longer for one file than the aggregate budget has
            # left -- a single slow rule must not itself exhaust the budget
            # that the loop above is trying to enforce.
            remaining = max(1, int(YARA_WALL_CLOCK_BUDGET - elapsed))
            for match in compiled.match(path, timeout=min(SCAN_TIMEOUT, remaining)):
                hits.append(YaraHit(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                ))
        except Exception:
            continue
    return hits, "; ".join(note_parts)
