"""Repo hygiene guards. Cheap, and they catch drift no other test sees."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TEXT_SUFFIXES = {".py", ".toml", ".txt", ".md", ".yml", ".yaml", ".json", ".cfg", ".ini"}


def _tracked_text_files() -> list[Path]:
    """git ls-files, not a walk: never trips over venv/, build/, or __pycache__."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return [
        ROOT / name
        for name in out.split("\0")
        if name and Path(name).suffix in TEXT_SUFFIXES
    ]


def test_every_tracked_text_file_ends_with_a_newline():
    offenders = [
        str(p.relative_to(ROOT))
        for p in _tracked_text_files()
        if p.is_file() and p.stat().st_size and not p.read_bytes().endswith(b"\n")
    ]
    assert offenders == []
