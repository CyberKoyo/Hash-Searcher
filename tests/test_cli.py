import os

import pytest

from hash_searcher.api.base_call import make_error
from hash_searcher.cli import (
    EXIT_CLEAN, EXIT_MALICIOUS, EXIT_NO_DATA, EXIT_SUSPICIOUS, EXIT_UNKNOWN,
    build_parser, output_format, run_cli,
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


def test_no_static_flag_is_accepted():
    assert build_parser().parse_args(["abc", "--no-static"]).no_static is True
    assert build_parser().parse_args(["abc"]).no_static is False


def test_yara_rules_flag_is_accepted():
    assert build_parser().parse_args(["abc", "--yara-rules", "/rules"]).yara_rules == "/rules"
    assert build_parser().parse_args(["abc"]).yara_rules is None


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
    async def _fake(file_hash, cache, extra_ips=None):
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
                        lambda report, path, verdict=None: written.setdefault("path", path))

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


def test_write_report_dispatches_a_pdf_extension(tmp_path, monkeypatch):
    """Only the json branch was ever covered."""
    import hash_searcher.cli as cli

    monkeypatch.chdir(tmp_path)
    written = {}
    monkeypatch.setattr(cli, "write_pdf",
                        lambda report, path, verdict=None: written.setdefault("path", path))

    cli.write_report(object(), "report.pdf")

    assert written["path"] == os.path.join(str(tmp_path), "report.pdf")


def test_write_report_rejects_an_unrecognized_extension(tmp_path, monkeypatch, capsys):
    """The deferred-minors plan asserted 'the existing unrecognized-extension
    test must still pass'; `grep -rn Unrecognized tests/` returned nothing --
    no such test ever existed, so that verification step was vacuous. This is
    the test it assumed."""
    import hash_searcher.cli as cli

    monkeypatch.chdir(tmp_path)
    calls = []
    monkeypatch.setattr(cli, "write_json", lambda *a, **k: calls.append("json"))
    monkeypatch.setattr(cli, "write_pdf", lambda *a, **k: calls.append("pdf"))

    cli.write_report(object(), "report.txt")

    assert calls == []
    assert "Unrecognized output extension: report.txt (use .json or .pdf)" \
        in capsys.readouterr().out


async def test_a_nonexistent_file_argument_prints_a_message_not_a_traceback(
        monkeypatch, capsys):
    """`hash-searcher notahash` raised FileNotFoundError out of resolve_hash
    and printed a full traceback. Pre-existing on 43e9f92 and on 129ff8d.

    check_env only is stubbed here -- _stub_entry also replaces resolve_hash,
    which is the function under test.
    """
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)

    exit_code = await run_cli(["notahash", "--no-cache"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_NO_DATA
    assert "isn't in an accessible directory" in out
    assert "Traceback" not in out


async def test_a_full_run_on_a_malicious_file_exits_two(monkeypatch, fixture_json, capsys):
    """The exit-code map is unit-tested over all four levels, but the whole
    path -- data_puller to extract to score to exit -- was only ever exercised
    for SUSPICIOUS and UNKNOWN. These are the two verdicts a pipeline actually
    branches on.
    """
    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {
        "vt": fixture_json("vt_full_report"),
        "otx": fixture_json("otx_pulses"),
        "ipdb": [],
        "censys": [],
        "ips": [],
    })
    _stub_who_is(monkeypatch)

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_MALICIOUS
    assert "VERDICT: MALICIOUS" in out
    assert "48/72 engines flagged this file" in out


# --- Phase 3: static analysis wiring ----------------------------------------
#
# Every test below stubs check_env via _stub_entry -- the suite must pass
# offline with no .env and no provider keys set (Global Constraint 7). A
# previous version of test_static_analysis_runs_before_the_network_pass left
# check_env unstubbed and passed only because this repo's own .env holds
# real keys; on a runner with no keys check_env() returned False and the
# whole run bailed before `order` was ever touched. See branch-review.md C1.

async def test_static_analysis_runs_before_the_network_pass(tmp_path, monkeypatch):
    """The whole point of the phase. If the static pass ran after
    data_puller, an early bail on 'Invalid hash' would skip it entirely --
    which is exactly the case this phase exists to serve."""
    order = []
    _stub_entry(monkeypatch)
    monkeypatch.setattr("hash_searcher.cli.analyze",
                        lambda path, yara_rules=None: order.append("static"))

    async def fake_puller(file_hash, cache, extra_ips=None):
        order.append("network")
        return {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": []}

    monkeypatch.setattr("hash_searcher.cli.data_puller", fake_puller)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + b"\x00" * 512)
    await run_cli([str(target)])

    assert order == ["static", "network"]


async def test_no_static_skips_the_pass(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr("hash_searcher.cli.analyze",
                        lambda path, yara_rules=None: called.append(1))
    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": []})

    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")
    await run_cli([str(target), "--no-static", "--no-cache"])
    assert called == []


async def test_a_bare_hash_argument_skips_static_analysis(monkeypatch):
    """There is no file to analyze. Attempting one would be a crash, not a
    smaller report."""
    called = []
    monkeypatch.setattr("hash_searcher.cli.analyze",
                        lambda path, yara_rules=None: called.append(1))
    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": []})

    await run_cli(["a" * 64, "--no-cache"])
    assert called == []


async def test_a_static_report_is_attached_to_the_report_and_rendered(
        tmp_path, monkeypatch, capsys):
    """Not just called -- its result must actually reach the Report the
    renderer (and --output) sees."""
    from hash_searcher.models import EntropyReport, StaticReport

    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": []})

    fake = StaticReport(path="x", size=4, sha256="a" * 64,
                        entropy=EntropyReport(overall=7.9, packed=True, note="packed"))
    monkeypatch.setattr("hash_searcher.cli.analyze", lambda path, yara_rules=None: fake)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")
    await run_cli([str(target), "--no-cache"])

    out = capsys.readouterr().out
    assert "STATIC ANALYSIS" in out
    assert "packed" in out


async def test_yara_rules_flag_is_forwarded_to_analyze(tmp_path, monkeypatch):
    from hash_searcher.models import StaticReport

    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": []})

    seen = {}

    def fake_analyze(path, yara_rules=None):
        seen["yara_rules"] = yara_rules
        return StaticReport(path=path, size=1, sha256="a" * 64)

    monkeypatch.setattr("hash_searcher.cli.analyze", fake_analyze)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")
    await run_cli([str(target), "--yara-rules", "/opt/rules", "--no-cache"])

    assert seen["yara_rules"] == "/opt/rules"


async def test_a_static_analysis_failure_does_not_block_the_network_pass(
        tmp_path, monkeypatch, capsys):
    """A local analyzer raising must never take the network pass down with
    it -- static analysis exists to ADD information, not to become a new way
    the whole run can fail."""
    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": []})

    def boom(path, yara_rules=None):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("hash_searcher.cli.analyze", boom)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")
    exit_code = await run_cli([str(target), "--no-cache"])

    out = capsys.readouterr().out
    assert "STATIC ANALYSIS" not in out
    assert exit_code == EXIT_CLEAN


# --- C3 (branch-review.md): neither bail may discard a computed static
# report. Both tests below pin the exit code to exit_code(score(report)) --
# the same mechanism the full online path already uses -- rather than to a
# fixed EXIT_NO_DATA, so a shell script can rely on the code actually
# reflecting what the static pass found.

async def test_check_env_false_with_a_static_report_renders_it_instead_of_bailing(
        tmp_path, monkeypatch, capsys):
    """With no provider configured, check_env() returns False. That used to
    return EXIT_NO_DATA above the static-analysis block entirely, so with no
    keys static analysis never ran at all. It must now render whatever the
    static pass found and never touch the network."""
    from hash_searcher.models import PEStaticReport, StaticReport

    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: False)
    monkeypatch.setattr(
        "hash_searcher.cli.resolve_hash",
        lambda indicator, password: ["deadbeef"],
    )

    fake = StaticReport(
        path="x", size=4, sha256="a" * 64,
        pe=PEStaticReport(suspicious_imports=[
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        ]),
    )
    monkeypatch.setattr("hash_searcher.cli.analyze", lambda path, yara_rules=None: fake)

    called = []

    async def fake_puller(*a, **k):
        called.append(1)
        return {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": []}

    monkeypatch.setattr("hash_searcher.cli.data_puller", fake_puller)

    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")
    exit_code = await run_cli([str(target), "--no-cache"])

    out = capsys.readouterr().out
    assert called == []  # no provider configured -- data_puller must never run
    assert "STATIC ANALYSIS" in out
    assert exit_code == EXIT_SUSPICIOUS


async def test_check_env_false_with_no_static_report_still_bails(monkeypatch):
    """No file, no keys: nothing was computed and there is nothing to
    render, so the original bail is still correct here."""
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: False)

    exit_code = await run_cli(["a" * 64, "--no-cache"])

    assert exit_code == EXIT_NO_DATA


async def test_vt_404_with_a_static_report_renders_it_instead_of_bailing(
        tmp_path, monkeypatch, capsys):
    """VT 404 with no OTX pulses is the definition of 'a sample nobody has
    ever uploaded' -- the exact case this phase exists to serve. The
    analyzer ran and produced findings; the tool must not throw them away
    and print 'Invalid hash'."""
    from hash_searcher.models import PEStaticReport, StaticReport

    _stub_entry(monkeypatch)
    fake = StaticReport(
        path="x", size=4, sha256="a" * 64,
        pe=PEStaticReport(suspicious_imports=[
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        ]),
    )
    monkeypatch.setattr("hash_searcher.cli.analyze", lambda path, yara_rules=None: fake)

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

    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")
    exit_code = await run_cli([str(target), "--no-cache"])

    out = capsys.readouterr().out
    assert "Invalid hash. Please check filename or hash." not in out
    assert "STATIC ANALYSIS" in out
    assert exit_code == EXIT_SUSPICIOUS


async def test_a_full_run_on_a_file_nothing_flagged_exits_zero(monkeypatch, capsys):
    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {
        "vt": {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0,
                                    "undetected": 72, "timeout": 0},
        }}},
        "otx": {"pulse_info": {"pulses": []}},
        "ipdb": [],
        "censys": [],
        "ips": [],
    })
    _stub_who_is(monkeypatch)

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_CLEAN
    assert "VERDICT: CLEAN" in out
    assert "No signals fired." in out
