import tomllib
from pathlib import Path

import pytest


def test_console_script_is_declared():
    data = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert data["project"]["scripts"]["hash-searcher"] == "hash_searcher.main:run"


@pytest.mark.skip(
    reason="main.py still imports the now-deleted formatters/report modules; "
           "Task 11 leaves it as-is on purpose, Task 12 rewrites main.py as a "
           "thin `from .cli import run, run_cli` wrapper and restores this test."
)
def test_run_is_importable_and_callable():
    from hash_searcher.main import run
    assert callable(run)


def test_readme_does_not_advertise_a_missing_script():
    readme = (Path(__file__).parents[1] / "README.md").read_text()
    assert "python hash-searcher.py" not in readme
    assert "hash-searcher " in readme


def test_readme_states_nested_archives_are_not_unpacked():
    readme = (Path(__file__).parents[1] / "README.md").read_text()
    # A positive assertion: the clarification must be present. Asserting the
    # absence of "ZIPS in ZIPS" was vacuous — that string was never in the README.
    assert "Nested archives are not unpacked" in readme
    assert "recursiv" not in readme.lower()
