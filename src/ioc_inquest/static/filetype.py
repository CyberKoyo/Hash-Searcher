"""What the bytes say the file is, versus what the name claims.

python-magic when it is available; a four-signature fallback table when it
is not. The fallback is deliberately tiny -- these are the types where a
mismatch actually means something.
"""

import os

from ..models import FileTypeReport
from . import capabilities

SIGNATURES = (
    (b"MZ", "PE"),
    (b"\x7fELF", "ELF"),
    (b"%PDF-", "PDF"),
    (b"PK\x03\x04", "ZIP"),
)

# Extensions each detected type may legitimately carry.
EXPECTED = {
    "PE": {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".bin", ""},
    "ELF": {".so", ".elf", ".bin", ".o", ""},
    "PDF": {".pdf"},
    "ZIP": {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".epub"},
}


def _by_signature(head: bytes) -> str | None:
    for magic, name in SIGNATURES:
        if head.startswith(magic):
            return name
    return None


def _by_magic(path: str) -> str | None:
    try:
        import magic
        return magic.from_file(path)
    except Exception:
        return None


def analyze_filetype(path: str) -> FileTypeReport:
    """A type we could not identify is never a mismatch.

    Absence of evidence is not evidence of a lie: reporting "unknown type"
    as "the extension is wrong" would fire on every proprietary format, and
    a finding that fires on everything tells an analyst nothing.
    """
    extension = os.path.splitext(path)[1].lower()
    with open(path, "rb") as handle:
        head = handle.read(16)

    signature = _by_signature(head)
    detected = (_by_magic(path) if capabilities.have("magic") else None) or signature

    mismatch = bool(
        signature and extension not in EXPECTED.get(signature, {extension})
    )
    return FileTypeReport(
        detected=detected,
        extension=extension,
        mismatch=mismatch,
        note=(f"content looks like {signature} but the name says {extension!r}"
              if mismatch else ""),
    )
