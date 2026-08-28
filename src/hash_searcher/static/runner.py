"""Fan out the static analyzers and assemble one StaticReport.

One assembly point, so `cli.py` calls a single `analyze()` and every
"this analyzer could not run" reason lands in a field the renderer can
print.

`skipped` and `failed` name analyzers, not libraries, and they answer
different questions. `skipped` means the analyzer's capability gate says
the library it needs is not importable -- read straight off
`capabilities.have(...)` before the analyzer is ever called. `failed`
means the analyzer *was* called and raised. An analyzer can never land in
both: a skipped analyzer is never invoked, so it can never also fail, and
`entropy`/`filetype`/`strings` carry no capability gate at all -- stdlib
only -- so for them only `failed` is reachable.
"""

import os

from ..hashing import get_reg_hash
from ..models import StaticReport
from . import capabilities
from .entropy import analyze_entropy
from .filetype import analyze_filetype
from .pe import analyze_pe
from .strings import analyze_strings
from .yara_scan import analyze_yara

# (report field name, capability gate or None, analyzer function name).
#
# The function is looked up from this module's globals *inside* analyze(),
# by name, rather than captured into this tuple directly. A tuple entry
# like `("entropy", None, analyze_entropy)` would bind the function object
# at import time; a test monkeypatching `runner.analyze_entropy` would then
# rebind the module attribute without touching the object this table
# already captured, and the patch would silently do nothing. Looking the
# name up at call time makes `globals()["analyze_entropy"]` and
# `runner.analyze_entropy` the same read, so the patch takes.
_ANALYZERS = (
    ("entropy", None, "analyze_entropy"),
    ("filetype", None, "analyze_filetype"),
    ("pe", "pefile", "analyze_pe"),
    ("yara", "yara", "analyze_yara"),
    ("strings", None, "analyze_strings"),
)


def analyze(path: str, yara_rules: str | None = None) -> StaticReport:
    """Run every static analyzer over `path` and assemble one report.

    Never runs the sample -- only reads its bytes and parses structures,
    same as every analyzer it calls. The sha256 comes from
    `hashing.get_reg_hash` so the static report and the network lookup are
    provably about the same bytes.
    """
    size = os.path.getsize(path)
    sha256 = get_reg_hash(path)

    results: dict[str, object] = {}
    skipped: list[str] = []
    failed: list[str] = []

    for field, capability, func_name in _ANALYZERS:
        if capability is not None and not capabilities.have(capability):
            skipped.append(capability)
            continue

        analyzer = globals()[func_name]
        try:
            if func_name == "analyze_yara":
                results[field] = analyzer(path, yara_rules)
            else:
                results[field] = analyzer(path)
        except Exception:
            # A parser exploding on hostile input is the expected case for
            # these analyzers, not the exceptional one -- record it and
            # keep going so one bad analyzer never takes the rest down.
            failed.append(field)

    return StaticReport(
        path=path,
        size=size,
        sha256=sha256,
        entropy=results.get("entropy"),
        filetype=results.get("filetype"),
        pe=results.get("pe"),
        yara=results.get("yara", []),
        strings=results.get("strings"),
        skipped=skipped,
        failed=failed,
    )
