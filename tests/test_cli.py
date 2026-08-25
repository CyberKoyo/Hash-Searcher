import os

import pytest

from hash_searcher.api.base_call import make_error
from hash_searcher.cli import (
    EXIT_NO_DATA, EXIT_SUSPICIOUS, EXIT_UNKNOWN, build_parser, output_format, run_cli,
)


def test_positional_indicator_is_required():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_output_flag_is_optional():
    args = build_parser().parse_args(["abc123"])
    assert args.indicator == "abc123"
    assert args.output is None


def test_short_and_long_output_flags_agree():
    parser = build_parser()
    assert parser.parse_args(["abc", "-o", "r.json"]).output == "r.json"
    assert parser.parse_args(["abc", "--output", "r.json"]).output == "r.json"


@pytest.mark.parametrize("name,expected", [
    ("report.json", "json"),
    ("report.pdf", "pdf"),
    ("REPORT.JSON", "json"),
    ("report.txt", None),
])
def test_output_format_is_chosen_by_extension(name, expected):
    assert output_format(name) == expected


def test_zip_password_flag_is_accepted():
    assert build_parser().parse_args(["a.zip", "--zip-password", "s3cret"]).zip_password == "s3cret"


# --- run_cli coverage -------------------------------------------------------
#
# data_puller, who_is, check_env, and resolve_hash are monkeypatched as they
# are bound into hash_searcher.cli, not at their source modules -- the same
# pattern tests/test_data_puller.py uses for the fetch coroutines.


def _stub_entry(monkeypatch):
    """Bypass check_env's real key-reading and resolve_hash's real file/hash
    parsing so these tests are independent of both the filesystem and
    whatever API keys happen to be set on the machine running them."""
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    monkeypatch.setattr(
        "hash_searcher.cli.resolve_hash",
        lambda indicator, password: ["deadbeef"],
    )


def _stub_data_puller(monkeypatch, raw):
    async def _fake(file_hash, cache):
        return raw
    monkeypatch.setattr("hash_searcher.cli.data_puller", _fake)


def _stub_who_is(monkeypatch):
    async def _fake(domains):
        return [
            {"domain": d, "created": "2020-01-01", "expires": "2027-01-01", "registrar": "R"}
            for d in domains
        ]
    monkeypatch.setattr("hash_searcher.cli.who_is", _fake)


async def test_censys_and_whois_survive_an_empty_abuseipdb_result(monkeypatch, fixture_json, capsys):
    """B1: VT reports contacted IPs, AbuseIPDB yields nothing usable (empty
    list), Censys returns a real host. The Censys and WHOIS sections must
    still appear -- the gate belongs on VT's contacted-IP list, not on
    whatever AbuseIPDB happened to produce.
    """
    _stub_entry(monkeypatch)
    raw = {
        "vt": fixture_json("vt_malicious"),
        "otx": fixture_json("otx_pulses"),
        "ipdb": [],
        "censys": fixture_json("censys_host"),
        "ips": ["198.51.100.10", "203.0.113.20"],
        "hash": "deadbeef",
    }
    _stub_data_puller(monkeypatch, raw)
    _stub_who_is(monkeypatch)

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    # vt_malicious carries one high sigma rule (15) and otx_pulses carries
    # pulses (10): 25 points, which bands SUSPICIOUS.
    assert exit_code == EXIT_SUSPICIOUS
    assert "VERDICT: SUSPICIOUS" in out
    assert "CENSYS ENRICHMENT" in out
    assert "WHOIS DATA" in out


async def test_vt_404_with_no_otx_pulses_reports_invalid_hash(monkeypatch, capsys):
    """B2(i): the real not-found case still bails."""
    _stub_entry(monkeypatch)
    raw = {
        "vt": make_error("Hash not found in GetTotal", 404),
        "otx": {},
        "ipdb": [],
        "censys": [],
        "ips": [],
        "hash": "deadbeef",
    }
    _stub_data_puller(monkeypatch, raw)
    _stub_who_is(monkeypatch)

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_NO_DATA
    assert "Invalid hash. Please check filename or hash." in out


async def test_vt_network_error_with_no_otx_pulses_does_not_bail(monkeypatch, capsys):
    """B2(ii): a transient VT failure is not a 404 and must not be treated
    as an invalid hash."""
    _stub_entry(monkeypatch)
    raw = {
        "vt": make_error("Network Error: timed out"),
        "otx": {},
        "ipdb": [],
        "censys": [],
        "ips": [],
        "hash": "deadbeef",
    }
    _stub_data_puller(monkeypatch, raw)
    _stub_who_is(monkeypatch)

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    assert "Invalid hash. Please check filename or hash." not in out
    # Nothing saw this file, so the verdict is UNKNOWN. That the code equals
    # EXIT_NO_DATA is a deliberate collision, not a bail -- the absent
    # "Invalid hash" line above is what proves the run completed.
    assert exit_code == EXIT_UNKNOWN
    assert "VERDICT: UNKNOWN" in out


async def test_no_vt_key_and_no_otx_key_does_not_bail(monkeypatch, capsys):
    """B2(iii): a key configuration with neither VT nor OTX must still be
    able to run with whatever keys are present -- the whole point of the
    provider registry."""
    _stub_entry(monkeypatch)
    raw = {
        "vt": make_error("VirusTotal key not set"),
        "otx": make_error("OTX key not set"),
        "ipdb": [],
        "censys": [],
        "ips": [],
        "hash": "deadbeef",
    }
    _stub_data_puller(monkeypatch, raw)
    _stub_who_is(monkeypatch)

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    assert "Invalid hash. Please check filename or hash." not in out
    # No provider returned anything, so no signal can fire: UNKNOWN.
    assert exit_code == EXIT_UNKNOWN
    assert "VERDICT: UNKNOWN" in out


def test_output_path_is_relative_to_the_cwd_not_the_package(tmp_path, monkeypatch):
    """S7: BASE_DIR is the installed package dir, so a relative --output
    landed inside site-packages -- unfindable, and unwritable under a
    non-editable install."""
    import hash_searcher.cli as cli

    monkeypatch.chdir(tmp_path)
    written = {}
    monkeypatch.setattr(cli, "write_json",
                        lambda report, path: written.setdefault("path", path))

    cli.write_report(object(), "report.json")

    assert written["path"] == os.path.join(str(tmp_path), "report.json")


@pytest.mark.parametrize("level,expected", [
    ("CLEAN", 0), ("SUSPICIOUS", 1), ("MALICIOUS", 2), ("UNKNOWN", 3),
])
def test_exit_code_maps_each_verdict_level(level, expected):
    from hash_searcher.cli import exit_code
    from hash_searcher.models import Verdict

    assert exit_code(Verdict(level=level, score=0)) == expected


def test_an_unrecognized_level_exits_unknown_rather_than_claiming_clean():
    """Fail safe: a level this function has never heard of must not be
    reported to a shell script as a clean file."""
    from hash_searcher.cli import exit_code
    from hash_searcher.models import Verdict

    assert exit_code(Verdict(level="WAT", score=0)) == 3
