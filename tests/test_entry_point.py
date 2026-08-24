import tomllib
from pathlib import Path


def test_console_script_is_declared():
    data = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert data["project"]["scripts"]["hash-searcher"] == "hash_searcher.main:run"


def test_run_is_importable_and_callable():
    from hash_searcher.main import run
    assert callable(run)


def test_readme_does_not_advertise_a_missing_script():
    readme = (Path(__file__).parents[1] / "README.md").read_text()
    assert "python hash-searcher.py" not in readme
    assert "hash-searcher " in readme


def test_readme_does_not_claim_recursive_zip_support():
    readme = (Path(__file__).parents[1] / "README.md").read_text().lower()
    assert "zips in zips" not in readme
