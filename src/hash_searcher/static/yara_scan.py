"""Scan the sample against a user-supplied YARA rules directory.

No rules ship with the tool: open rulesets are large, fast-moving, and
variously licensed. The default location follows the same XDG convention
cache.py uses, and an absent directory is a quiet empty result rather than
an error -- no rules is the normal state of a fresh install.
"""

import os
from pathlib import Path

from ..models import YaraHit
from . import capabilities

SCAN_TIMEOUT = 30  # seconds; a pathological rule set must not hang the tool
RULE_SUFFIXES = (".yar", ".yara")


def rules_dir() -> Path:
    root = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(root) / "hash-searcher" / "yara"


def analyze_yara(path: str, rules_path: str | None = None) -> list[YaraHit]:
    if not capabilities.have("yara"):
        return []

    directory = Path(rules_path) if rules_path else rules_dir()
    if not directory.is_dir():
        return []

    import yara

    hits: list[YaraHit] = []
    for rule_file in sorted(directory.rglob("*")):
        if rule_file.suffix.lower() not in RULE_SUFFIXES:
            continue
        try:
            # Compiled one file at a time: a single malformed .yar in the
            # user's directory must not abort every other rule.
            compiled = yara.compile(filepath=str(rule_file))
            for match in compiled.match(path, timeout=SCAN_TIMEOUT):
                hits.append(YaraHit(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                ))
        except Exception:
            continue
    return hits
