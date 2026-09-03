import os

import pytest

from hash_searcher.api.base_call import make_error
from hash_searcher.cli import (
    EXIT_CLEAN, EXIT_MALICIOUS, EXIT_NO_DATA, EXIT_SUSPICIOUS, EXIT_UNKNOWN,
    build_parser, output_format, run_cli,
)
from hash_searcher.indicators import Indicator


def test_an_indicator_or_an_input_file_is_required():
    """The positional is nargs="?" so --input-file can stand in for it, so
    argparse alone no longer enforces this -- parse_args does."""
    from hash_searcher.cli import parse_args

    with pytest.raises(SystemExit):
        parse_args([])


def test_an_input_file_alone_needs_no_positional():
    """The form the README documents: `hash-searcher --input-file iocs.txt`.
    It exited 2 with "the following arguments are required: indicator"."""
    from hash_searcher.cli import parse_args

    args = parse_args(["--input-file", "iocs.txt"])
    assert args.indicator is None
    assert args.input_file == "iocs.txt"


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
# data_puller, check_env, and resolve_indicator are monkeypatched as they
# are bound into hash_searcher.cli, not at their source modules -- the same
# pattern tests/test_data_puller.py uses for the fetch coroutines.


def _stub_entry(monkeypatch):
    """Bypass check_env's real key-reading and resolve_indicator's real
    file/hash parsing so these tests are independent of both the filesystem
    and whatever API keys happen to be set on the machine running them."""
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    monkeypatch.setattr(
        "hash_searcher.cli.resolve_indicator",
        lambda indicator, password: [Indicator("hash", "deadbeef")],
    )


EMPTY_RAW = {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": [],
             "domains": [], "rdap": [], "crtsh": [], "shodan": {},
             "greynoise": {}, "kev": {},
             "bazaar": None, "threatfox": None, "threatfox_ips": {}}


def _stub_data_puller(monkeypatch, raw):
    """Every slot the caller did not name defaults to empty.

    data_puller's return dict grows with every source this phase adds; a
    test about VT's 404 path should not have to enumerate the other slots
    to stay green.
    """
    payload = {**EMPTY_RAW, **raw}

    async def _fake(indicator, cache, extra_ips=None, pivot_depth=0):
        return payload
    monkeypatch.setattr("hash_searcher.cli.data_puller", _fake)


def _rdap(*domains) -> list[dict]:
    """RDAP payloads for the WHOIS section, as data_puller now returns them."""
    return [
        {"domain": d,
         "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}],
         "entities": [{"roles": ["registrar"],
                       "vcardArray": ["vcard", [["fn", {}, "text", "R"]]]}]}
        for d in domains
    ]


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
        "rdap": _rdap("bad.example"),
    }
    _stub_data_puller(monkeypatch, raw)

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    # vt_malicious carries one high sigma rule (15) and otx_pulses carries
    # pulses (10): 25 points, which bands SUSPICIOUS.
    assert exit_code == EXIT_SUSPICIOUS
    assert "VERDICT: SUSPICIOUS" in out
    assert "CENSYS ENRICHMENT" in out
    assert "WHOIS DATA" in out


async def test_vt_404_no_longer_bails_before_the_verdict(monkeypatch, capsys):
    """B2(i): a VT 404 with no OTX pulses used to be treated as an invalid
    hash and bail before score()/render(). resolve_indicator already proved
    this is a well-formed digest, so the run must reach a rendered verdict."""
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

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    assert "Invalid hash" not in out
    assert "VirusTotal has no record of this indicator -- continuing with the other sources." in out
    assert "VERDICT: UNKNOWN" in out
    # No source saw anything, so EXIT_NO_DATA and EXIT_UNKNOWN collide here
    # by design -- see their definitions in cli.py.
    assert exit_code == EXIT_NO_DATA


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

    Still the message for an unclassifiable argument after B2: an argument
    that is not any recognizable indicator is overwhelmingly a path that is
    not where the user thought it was, so resolve_indicator hands it to
    resolve_hash rather than answering with a vaguer message of its own.

    check_env only is stubbed here -- _stub_entry also replaces
    resolve_indicator, which is the function under test.
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

    async def fake_puller(indicator, cache, extra_ips=None, pivot_depth=0):
        order.append("network")
        return dict(EMPTY_RAW)

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
    _stub_data_puller(monkeypatch, {})

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
    _stub_data_puller(monkeypatch, {})

    await run_cli(["a" * 64, "--no-cache"])
    assert called == []


async def test_a_static_report_is_attached_to_the_report_and_rendered(
        tmp_path, monkeypatch, capsys):
    """Not just called -- its result must actually reach the Report the
    renderer (and --output) sees."""
    from hash_searcher.models import EntropyReport, StaticReport

    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {})

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
    _stub_data_puller(monkeypatch, {})

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
    _stub_data_puller(monkeypatch, {})

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
        "hash_searcher.cli.resolve_indicator",
        lambda indicator, password: [Indicator("hash", "deadbeef")],
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
        return dict(EMPTY_RAW)

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

    exit_code = await run_cli(["deadbeef", "--no-cache"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_CLEAN
    assert "VERDICT: CLEAN" in out
    assert "No signals fired." in out


async def test_a_bare_hash_vt_has_never_seen_still_reports_what_abusech_found(
        monkeypatch, capsys):
    """The case Phase 4 exists for. VT 404s on a sample MalwareBazaar holds;
    bailing here throws away the family name we already paid a request for."""
    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {
        "vt": make_error("Hash not found in GetTotal", 404),
        "bazaar": {"query_status": "ok", "data": [
            {"signature": "Emotet", "file_type": "exe", "tags": ["banker"]}]},
    })

    exit_code = await run_cli(["a" * 64, "--no-cache"])
    out = capsys.readouterr().out

    assert "Invalid hash" not in out
    assert "MALWAREBAZAAR" in out and "Emotet" in out
    # bazaar is in SAMPLE_EVIDENCE_NAMES, so this escapes UNKNOWN.
    assert exit_code != EXIT_UNKNOWN


async def test_a_hash_no_source_has_ever_seen_is_unknown_not_invalid(
        monkeypatch, capsys):
    """The spec's acceptance row: random hex -> UNKNOWN, exit 3, no traceback.
    Exit 3 was already right; the message and the missing verdict were not."""
    _stub_entry(monkeypatch)
    _stub_data_puller(monkeypatch, {
        "vt": make_error("Hash not found in GetTotal", 404),
    })

    exit_code = await run_cli(["a" * 64, "--no-cache"])
    out = capsys.readouterr().out

    assert exit_code == EXIT_UNKNOWN
    assert "VERDICT: UNKNOWN" in out
    assert "Invalid hash" not in out


# --- Task B2: the file argument, pinned -------------------------------------
#
# B2 reworked data_puller's entry from "a hash, and everything else derived
# from VirusTotal" to "whatever kind of indicator this is". The file path is
# the one that already worked, so it is the one that can regress.


def _capture_data_puller(monkeypatch):
    """Record what data_puller was handed, and return an empty raw dict."""
    seen = []

    async def fake_puller(indicator, cache, extra_ips=None, pivot_depth=0):
        seen.append((indicator, extra_ips))
        return dict(EMPTY_RAW)

    monkeypatch.setattr("hash_searcher.cli.data_puller", fake_puller)
    return seen


async def test_a_file_argument_is_hashed_and_analyzed_exactly_as_before(
        tmp_path, monkeypatch, capsys):
    """A real file on disk: hashed, statically analyzed, and looked up by
    that digest -- not classified as a domain, not passed through as a
    string. The whole of B2's regression risk in one test."""
    import hashlib

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x90\x00 not a real PE")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()

    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    seen = _capture_data_puller(monkeypatch)

    analyzed = []

    def fake_analyze(path, yara_rules=None):
        analyzed.append(path)
        return None

    monkeypatch.setattr("hash_searcher.cli.analyze", fake_analyze)

    await run_cli([str(sample), "--no-cache"])

    assert analyzed == [str(sample)]          # static analysis still runs
    assert seen == [(Indicator("hash", digest), None)]
    assert "Traceback" not in capsys.readouterr().out


async def test_a_file_whose_name_reads_as_a_domain_is_still_hashed(
        tmp_path, monkeypatch):
    """`hash-searcher evil.example` with a file of that name in the working
    directory. classify() consults the filesystem first for exactly this."""
    import hashlib

    sample = tmp_path / "evil.example"
    sample.write_bytes(b"payload")
    digest = hashlib.sha256(b"payload").hexdigest()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    monkeypatch.setattr("hash_searcher.cli.analyze", lambda path, yara_rules=None: None)
    seen = _capture_data_puller(monkeypatch)

    await run_cli(["evil.example", "--no-cache"])

    assert seen == [(Indicator("hash", digest), None)]


async def test_a_bare_hash_argument_still_skips_static_analysis(monkeypatch):
    """There is no file to analyze, and attempting one is a crash rather
    than a smaller report."""
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    seen = _capture_data_puller(monkeypatch)

    def fail(path, yara_rules=None):
        raise AssertionError("static analysis ran on a bare hash")

    monkeypatch.setattr("hash_searcher.cli.analyze", fail)

    await run_cli(["a" * 64, "--no-cache"])
    assert seen == [(Indicator("hash", "a" * 64), None)]


async def test_an_ip_argument_reaches_data_puller_as_an_ip(monkeypatch):
    """The capability this part exists for: `hash-searcher 198.51.100.10`
    could not work before B2, because the entry assumed a hash."""
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    seen = _capture_data_puller(monkeypatch)

    await run_cli(["198.51.100.10", "--no-cache"])
    assert seen == [(Indicator("ip", "198.51.100.10"), None)]


async def test_a_defanged_url_argument_is_refanged_before_lookup(monkeypatch):
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    seen = _capture_data_puller(monkeypatch)

    await run_cli(["hxxps://evil[.]example/path", "--no-cache"])
    assert seen == [(Indicator("url", "https://evil.example/path"), None)]


async def test_a_cidr_argument_is_declined_rather_than_expanded(monkeypatch, capsys):
    """65,536 rate-limited lookups is not a smaller answer, it is a spent key."""
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    seen = _capture_data_puller(monkeypatch)

    exit_code = await run_cli(["198.51.100.0/16", "--no-cache"])

    assert exit_code == EXIT_NO_DATA
    assert seen == []
    assert "network range" in capsys.readouterr().out


async def test_the_report_carries_the_indicator_that_was_looked_up(monkeypatch):
    """Report.indicator held the sha256 because a sha256 was the only thing
    the tool could be handed. It now holds whatever was looked up, which is
    what -o and the batch loop key their output on."""
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    _capture_data_puller(monkeypatch)

    rendered = []
    monkeypatch.setattr("hash_searcher.cli.render",
                        lambda report, verdict: rendered.append(report))

    await run_cli(["evil.example", "--no-cache"])
    assert [r.indicator for r in rendered] == ["evil.example"]
    assert rendered[0].source_file == "evil.example"


async def test_a_missing_input_file_prints_a_message_not_a_traceback(
        monkeypatch, capsys):
    """The same defect analyze_one's FileNotFoundError catch exists for.
    --input-file opened a second door to it."""
    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)

    exit_code = await run_cli(["--input-file", "/nonexistent/iocs.txt"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_NO_DATA
    assert "/nonexistent/iocs.txt" in out
    assert "Traceback" not in out


async def test_an_input_file_is_read_as_utf8_whatever_the_locale_is(
        monkeypatch, tmp_path):
    """An IOC list is not local text. Reading it in the locale's encoding
    makes a punycode-free domain list fail on a non-UTF-8 machine only."""
    listing = tmp_path / "iocs.txt"
    listing.write_bytes("# ünicode comment\n198.51.100.10\n".encode("utf-8"))

    from hash_searcher.cli import batch_lines, parse_args

    args = parse_args(["--input-file", str(listing)])
    assert batch_lines(args) == ["198.51.100.10"]
