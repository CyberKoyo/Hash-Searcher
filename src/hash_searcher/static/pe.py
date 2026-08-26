"""PE structure: imports, sections, build timestamp.

Imports are the highest-signal thing in a PE. A binary importing
VirtualAllocEx, WriteProcessMemory and CreateRemoteThread is describing
process injection regardless of what any engine says about it -- and unlike
a detection ratio, it is true of a sample nobody has ever uploaded.
"""

import datetime

from ..models import PESection, PEStaticReport
from . import capabilities
from .entropy import shannon

# Grouped by what they let a program do. Matched case-insensitively.
SUSPICIOUS_IMPORTS = {
    # process injection
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetThreadContext", "QueueUserAPC",
    # dynamic resolution -- the classic packer tell
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    # anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    # persistence and privilege
    "RegSetValueExA", "RegSetValueExW", "AdjustTokenPrivileges", "CreateServiceA",
    # credential and input capture
    "SetWindowsHookExA", "GetAsyncKeyState", "CryptUnprotectData",
    # network
    "InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA", "WinHttpOpen",
}

_LOOKUP = {name.lower(): name for name in SUSPICIOUS_IMPORTS}
EXECUTABLE_FLAG = 0x20000000  # IMAGE_SCN_MEM_EXECUTE


def suspicious(imports: dict[str, list[str]]) -> list[str]:
    """Canonical names of the suspicious APIs present, sorted for stability."""
    found = {
        _LOOKUP[name.lower()]
        for names in imports.values()
        for name in names
        if name and name.lower() in _LOOKUP
    }
    return sorted(found)


def analyze_pe(path: str) -> PEStaticReport | None:
    """None when this is not a PE, or when pefile is not installed.

    A malformed PE returns a report carrying a note instead of raising --
    a truncated or deliberately corrupt header is itself information, and a
    traceback would lose both it and the rest of the run.
    """
    if not capabilities.have("pefile"):
        return None

    with open(path, "rb") as handle:
        if not handle.read(2).startswith(b"MZ"):
            return None

    import pefile

    try:
        binary = pefile.PE(path, fast_load=True)
        binary.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception:
        return PEStaticReport(note="looks like a PE but could not be parsed")

    imports: dict[str, list[str]] = {}
    for entry in getattr(binary, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = (entry.dll or b"").decode("utf-8", "replace").lower()
        imports[dll] = [
            (imp.name or b"").decode("utf-8", "replace")
            for imp in entry.imports if imp.name
        ]

    sections = [
        PESection(
            name=(section.Name or b"").rstrip(b"\x00").decode("utf-8", "replace"),
            size=section.SizeOfRawData,
            entropy=round(shannon(section.get_data()), 2),
            executable=bool(section.Characteristics & EXECUTABLE_FLAG),
        )
        for section in binary.sections
    ]

    ts = getattr(binary.FILE_HEADER, "TimeDateStamp", 0)
    compiled = None
    if ts:
        try:
            compiled = datetime.datetime.fromtimestamp(
                ts, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            # A zeroed or absurd timestamp is itself a packer tell; leaving
            # it None and saying nothing beats printing 1970 or crashing.
            compiled = None

    binary.close()
    return PEStaticReport(
        imports=imports,
        sections=sections,
        compiled=compiled,
        suspicious_imports=suspicious(imports),
    )
