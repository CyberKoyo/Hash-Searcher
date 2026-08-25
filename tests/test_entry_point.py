try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 — tomllib landed in 3.11 (PEP 680)
    import tomli as tomllib
from pathlib import Path


def test_console_script_is_declared():
    data = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert data["project"]["scripts"]["hash-searcher"] == "hash_searcher.cli:run"


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
