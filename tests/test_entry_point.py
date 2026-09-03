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
    """The second assertion used to be `"hash-searcher " in readme`, which the
    string "hash-searcher.py is gone" would satisfy. Pin the usage line itself,
    and take the command name from pyproject so a rename cannot leave the
    README documenting a script that no longer exists.
    """
    root = Path(__file__).parents[1]
    readme = (root / "README.md").read_text()
    scripts = tomllib.loads((root / "pyproject.toml").read_text())["project"]["scripts"]
    name = next(iter(scripts))
    assert "python hash-searcher.py" not in readme
    # Part B widened the argument from a hash-or-file to any indicator, and
    # added "-" for a stdin batch. Still the whole line rather than a prefix:
    # a rename must redden this, which is the reason it reads the name out of
    # pyproject instead of spelling it here.
    assert f"    {name} <indicator | - > [-o report.json | report.pdf]" in readme


def test_readme_does_not_claim_every_archive_member_is_analyzed():
    """R20: the README describes what the tool does. get_zip_hash hashes every
    member, but cli.run_cli sends only resolved[0] to the providers and prints
    the rest as "not analyzed" -- so "hashes every file inside", full stop,
    overpromises.
    """
    readme = (Path(__file__).parents[1] / "README.md").read_text()
    assert "hashes every file inside" not in readme
    assert "only the first is analyzed" in readme


def test_readme_states_nested_archives_are_not_unpacked():
    readme = (Path(__file__).parents[1] / "README.md").read_text()
    # A positive assertion: the clarification must be present. Asserting the
    # absence of "ZIPS in ZIPS" was vacuous — that string was never in the README.
    assert "Nested archives are not unpacked" in readme
    assert "recursiv" not in readme.lower()


def test_readme_documents_the_real_exit_codes():
    """R20 again, this time for the codes a shell script branches on. Read
    them from cli rather than restating them, so renumbering an exit code
    without touching the README fails here.
    """
    from hash_searcher.cli import _EXIT_BY_LEVEL

    readme = (Path(__file__).parents[1] / "README.md").read_text()
    for level, code in _EXIT_BY_LEVEL.items():
        assert f"| `{code}` | {level} " in readme


def test_readme_documents_the_real_verdict_thresholds():
    from hash_searcher.scoring import MALICIOUS_AT, SUSPICIOUS_AT

    readme = (Path(__file__).parents[1] / "README.md").read_text()
    assert f"score >= {MALICIOUS_AT}" in readme
    assert f"score >= {SUSPICIOUS_AT}" in readme
