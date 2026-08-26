"""The one place that knows which optional analysis libraries are importable.

Scattering `try: import pefile` across four modules produces four subtly
different fallbacks. This module answers the question once, and the runner
turns the answer into a skipped analyzer plus a named line in the report.
"""

import functools
import importlib

MODULES = {
    "pefile": "pefile",
    "yara": "yara",
    "magic": "magic",
}


@functools.lru_cache(maxsize=None)
def have(name: str) -> bool:
    """True if the optional library behind `name` can actually be imported.

    Answered by attempting the import rather than by consulting a version
    table: a package can be installed and still fail to load. python-magic
    without the system libmagic is the common case, and it raises OSError,
    not ImportError -- hence the broad except.
    """
    module = MODULES[name]  # KeyError on a typo, deliberately
    try:
        importlib.import_module(module)
    except Exception:
        return False
    return True


def missing() -> list[str]:
    return [name for name in MODULES if not have(name)]
