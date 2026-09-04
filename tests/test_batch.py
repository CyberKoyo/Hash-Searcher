"""Coverage for multi-indicator runs (Task B3).

Every test here stubs analyze_one: what a batch is responsible for is the
loop, the shared cache, the per-indicator output paths, and the aggregate
exit code -- not what one run does, which tests/test_cli.py already owns.
"""

import io

import pytest

from hash_searcher.batch import batch_output_path, run_batch, worst_exit_code
from hash_searcher.cli import (
    EXIT_CLEAN, EXIT_MALICIOUS, EXIT_NO_DATA, EXIT_SUSPICIOUS, EXIT_UNKNOWN,
    build_parser, read_indicators, run_cli,
)


def _args(argv):
    return build_parser().parse_args(argv)


def _stub_analyze(monkeypatch, codes=None):
    """Record every (indicator, cache, output) analyze_one was called with."""
    seen = []
    answers = list(codes or [])

    async def fake_analyze_one(user_input, args, cache=None, output=None,
                                budget=None, rows=None):
        seen.append((user_input, cache, output))
        return answers.pop(0) if answers else EXIT_CLEAN

    monkeypatch.setattr("hash_searcher.batch.analyze_one", fake_analyze_one)
    return seen


# --- reading a list ---------------------------------------------------------

def test_blank_lines_and_comments_are_skipped():
    handle = io.StringIO(
        "# a header an analyst pasted along with the list\n"
        "198.51.100.10\n"
        "\n"
        "   \n"
        "  evil.example  \n"
        "  # an indented comment\n"
        "203.0.113.7\n"
    )
    assert read_indicators(handle) == ["198.51.100.10", "evil.example", "203.0.113.7"]


async def test_a_stdin_list_produces_one_run_per_indicator(monkeypatch):
    seen = _stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO(
        "198.51.100.10\nevil.example\n203.0.113.7\n"))

    await run_cli(["-", "--no-cache"])

    assert [value for value, _, _ in seen] == [
        "198.51.100.10", "evil.example", "203.0.113.7"]


async def test_an_input_file_produces_one_run_per_indicator(monkeypatch, tmp_path):
    listing = tmp_path / "iocs.txt"
    listing.write_text("# from the report\n198.51.100.10\n\nevil.example\n")
    seen = _stub_analyze(monkeypatch)

    await run_cli(["ignored", "--input-file", str(listing), "--no-cache"])

    assert [value for value, _, _ in seen] == ["198.51.100.10", "evil.example"]


async def test_an_empty_list_says_so_rather_than_exiting_clean(monkeypatch, capsys):
    seen = _stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("# nothing but a comment\n"))

    code = await run_cli(["-", "--no-cache"])

    assert seen == []
    assert code == EXIT_NO_DATA
    assert "No indicators" in capsys.readouterr().out


# --- the aggregate exit code ------------------------------------------------

@pytest.mark.parametrize("codes,expected", [
    ([EXIT_CLEAN, EXIT_CLEAN], EXIT_CLEAN),
    ([EXIT_CLEAN, EXIT_MALICIOUS, EXIT_CLEAN], EXIT_MALICIOUS),
    ([EXIT_SUSPICIOUS, EXIT_UNKNOWN], EXIT_SUSPICIOUS),
    ([EXIT_UNKNOWN, EXIT_CLEAN], EXIT_UNKNOWN),
    ([EXIT_MALICIOUS, EXIT_SUSPICIOUS], EXIT_MALICIOUS),
    ([], EXIT_NO_DATA),
])
def test_the_aggregate_is_the_most_severe_run(codes, expected):
    """Not the last, and not the numerically largest: UNKNOWN is 3 and
    MALICIOUS is 2, so max() would report a batch holding one malicious
    sample as merely unknown."""
    assert worst_exit_code(codes) == expected


async def test_one_malicious_indicator_makes_the_whole_batch_exit_two(monkeypatch):
    """The reason this aggregation exists: a batch that found one malicious
    sample must not exit 0 because the other two were clean."""
    _stub_analyze(monkeypatch, [EXIT_CLEAN, EXIT_MALICIOUS, EXIT_CLEAN])
    monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\nc\n"))

    assert await run_cli(["-", "--no-cache"]) == EXIT_MALICIOUS


# --- one cache, not one per indicator ---------------------------------------

async def test_the_whole_batch_shares_one_cache(monkeypatch):
    """Two indicators that share a contacted IP should cost one lookup. A
    cache per indicator throws that away, and re-opening the sqlite file
    once per line is the more expensive way to get the worse answer."""
    opened = []

    class FakeCache:
        def __init__(self, **kwargs):
            opened.append(kwargs)
            self.closed = False

        def close(self):
            self.closed = True

    monkeypatch.setattr("hash_searcher.batch.ResponseCache", FakeCache)
    seen = _stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\nc\n"))

    await run_cli(["-"])

    assert len(opened) == 1
    caches = {id(cache) for _, cache, _ in seen}
    assert len(caches) == 1
    assert seen[0][1].closed is True   # and closed once the batch is done


async def test_one_failing_indicator_does_not_discard_the_rest(monkeypatch, capsys):
    """A 100-line batch that dies on line 3 has paid for three lookups and
    produced nothing. The failure is reported, scored EXIT_NO_DATA, and the
    remaining indicators still run."""
    seen = []

    async def sometimes_boom(user_input, args, cache=None, output=None,
                             budget=None, rows=None):
        seen.append(user_input)
        if user_input == "b":
            raise RuntimeError("provider blew up")
        return EXIT_CLEAN

    monkeypatch.setattr("hash_searcher.batch.analyze_one", sometimes_boom)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\nc\n"))

    code = await run_cli(["-", "--no-cache"])

    assert seen == ["a", "b", "c"]
    assert code == EXIT_NO_DATA          # the failed run is not CLEAN
    out = capsys.readouterr().out
    assert "b: run failed" in out
    assert "provider blew up" in out


async def test_the_shared_cache_is_closed_even_when_a_run_raises(monkeypatch):
    class FakeCache:
        def __init__(self, **kwargs):
            self.closed = False

        def close(self):
            self.closed = True

    made = []
    monkeypatch.setattr("hash_searcher.batch.ResponseCache",
                        lambda **kw: made.append(FakeCache()) or made[-1])

    async def boom(user_input, args, cache=None, output=None, budget=None,
                   rows=None):
        raise RuntimeError("provider blew up")

    monkeypatch.setattr("hash_searcher.batch.analyze_one", boom)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\n"))

    # Every run failing is still a completed batch -- one that found
    # nothing. What must hold regardless is that the sqlite handle the
    # batch opened is closed.
    assert await run_cli(["-"]) == EXIT_NO_DATA
    assert made[0].closed is True


# --- one output file per indicator ------------------------------------------

def test_batch_output_paths_are_unique_and_name_their_indicator():
    first = batch_output_path("report.json", 0, "198.51.100.10")
    second = batch_output_path("report.json", 1, "evil.example")
    assert first != second
    assert first.endswith(".json") and second.endswith(".json")
    assert "198.51.100.10" in first
    assert "evil.example" in second


def test_two_indicators_that_slug_alike_still_get_separate_files():
    """A slug is lossy -- "a/b" and "a:b" both sanitize to "a_b". The index
    is what guarantees the batch never overwrites its own output."""
    assert batch_output_path("r.json", 0, "a/b") != batch_output_path("r.json", 1, "a:b")


def test_a_path_separator_in_an_indicator_cannot_escape_the_output_directory():
    """The indicator is user input, and it reaches a filename. "../../x" must
    name a file in the output directory, not one two levels above it."""
    path = batch_output_path("out/report.json", 0, "../../etc/passwd")
    assert path.startswith("out/")
    assert "/.." not in path


async def test_a_batch_with_output_writes_one_file_per_indicator(monkeypatch):
    seen = _stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("198.51.100.10\nevil.example\n"))

    await run_cli(["-", "-o", "report.json", "--no-cache"])

    outputs = [output for _, _, output in seen]
    assert len(set(outputs)) == 2
    assert all(path.endswith(".json") for path in outputs)


async def test_a_batch_without_output_asks_for_no_file(monkeypatch):
    seen = _stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("198.51.100.10\n"))

    await run_cli(["-", "--no-cache"])
    assert [output for _, _, output in seen] == [None]


async def test_a_single_indicator_run_is_not_a_batch(monkeypatch):
    """A ZIP argument resolves to several hashes and analyze_one analyzes
    only the first, on purpose. Routing a single argument through the batch
    path would silently change that."""
    async def fail(*a, **k):
        raise AssertionError("run_batch ran for a single indicator")

    monkeypatch.setattr("hash_searcher.batch.run_batch", fail)
    seen = []

    async def fake_analyze_one(user_input, args, cache=None, output=None,
                                budget=None):
        seen.append(user_input)
        return EXIT_CLEAN

    monkeypatch.setattr("hash_searcher.cli.analyze_one", fake_analyze_one)

    assert await run_cli(["198.51.100.10", "--no-cache"]) == EXIT_CLEAN
    assert seen == ["198.51.100.10"]


async def test_a_batch_rejects_an_unusable_output_extension_before_any_lookup(
        monkeypatch, capsys):
    """A single run prints "Unrecognized output extension" after the work is
    done and still shows its verdict. A batch would print it once per
    indicator, having spent every rate-limited lookup on reports it cannot
    write -- so it is checked once, first."""
    seen = _stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("198.51.100.10\nevil.example\n"))

    code = await run_cli(["-", "-o", "report.txt", "--no-cache"])

    assert seen == []
    assert code == EXIT_NO_DATA
    assert capsys.readouterr().out.count("Unrecognized output extension") == 1


# --- a batch's CSV is one table, not N single-row files ----------------------


def _csv_stub_analyze(monkeypatch, codes=None, failures=()):
    """analyze_one, but appending a real (report, verdict) pair to `rows`.

    Closer to the real thing than the recording stub above, because the
    aggregate table is precisely what the pairs turn into -- a stub that
    only recorded its arguments could not tell a one-table batch from N
    single-row ones.
    """
    from hash_searcher.models import OTXReport, Report, Verdict, VTReport

    seen = []
    answers = list(codes or [])

    async def fake_analyze_one(user_input, args, cache=None, output=None,
                               budget=None, rows=None):
        seen.append((user_input, output, rows))
        if user_input in failures:
            # A line that dies before a Report exists: it appends nothing,
            # exactly as analyze_one's early returns do.
            raise RuntimeError("provider blew up")
        if rows is not None:
            rows.append((
                Report(indicator=user_input, generated_at="2026-09-03 12:00:00",
                       vt=VTReport(found=False),
                       otx=OTXReport(recorded_instances="N/A"),
                       ips={}, hosts=[], whois=[]),
                Verdict(level="CLEAN", score=0),
            ))
        return answers.pop(0) if answers else EXIT_CLEAN

    monkeypatch.setattr("hash_searcher.batch.analyze_one", fake_analyze_one)
    return seen


def _read_csv(path):
    import csv
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.reader(handle))


async def test_a_batch_csv_is_one_file_with_one_row_per_indicator(
        monkeypatch, tmp_path):
    """The gap Part C left open on purpose: write_rows took N reports from
    the day it was written, and batch.py handed it one at a time, so
    `-o report.csv` over three indicators produced three single-row files
    instead of the triage table the format exists for."""
    _csv_stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin",
                        io.StringIO("abc123\n198.51.100.10\nevil.example\n"))
    out = tmp_path / "report.csv"

    await run_cli(["-", "-o", str(out), "--no-cache"])

    assert out.exists()
    assert list(tmp_path.glob("report-*.csv")) == []   # no per-indicator files
    rows = _read_csv(out)
    assert len(rows) == 4                              # header + three
    assert [r[0] for r in rows[1:]] == ["abc123", "198.51.100.10", "evil.example"]


async def test_a_failed_line_still_gets_a_row(monkeypatch, tmp_path):
    """Row count matches the input list's line count. A table that silently
    dropped the indicator that failed would read as an all-clear for
    something nobody checked."""
    _csv_stub_analyze(monkeypatch, failures={"evil.example"})
    monkeypatch.setattr("sys.stdin", io.StringIO("abc123\nevil.example\ngood.example\n"))
    out = tmp_path / "report.csv"

    await run_cli(["-", "-o", str(out), "--no-cache"])

    rows = _read_csv(out)
    assert len(rows) == 4
    header, body = rows[0], rows[1:]
    assert [r[0] for r in body] == ["abc123", "evil.example", "good.example"]

    failed = dict(zip(header, body[1]))
    assert failed["verdict"] == ""             # never CLEAN
    assert "provider blew up" in failed["errors"]


async def test_the_batch_csv_keeps_the_run_going_after_a_failure(
        monkeypatch, tmp_path):
    """The failure row must not cost the lines after it -- a 100-line run
    that dies on line 3 has already paid for three lookups."""
    _csv_stub_analyze(monkeypatch, failures={"a"})
    monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\nc\n"))
    out = tmp_path / "report.csv"

    code = await run_cli(["-", "-o", str(out), "--no-cache"])

    assert code == EXIT_NO_DATA                       # the failure still counts
    assert [r[0] for r in _read_csv(out)[1:]] == ["a", "b", "c"]


async def test_every_other_format_still_writes_one_file_per_indicator(
        monkeypatch, tmp_path):
    """-o means "the file" for CSV and "the filename stem" for everything
    else, because that is what each format can express. Only CSV changed."""
    seen = _csv_stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("abc123\nevil.example\n"))

    await run_cli(["-", "-o", str(tmp_path / "report.json"), "--no-cache"])

    outputs = [output for _, output, _ in seen]
    assert len(set(outputs)) == 2
    assert all(path.endswith(".json") for path in outputs)
    # and it did NOT ask analyze_one to accumulate rows
    assert all(rows is None for _, _, rows in seen)


async def test_a_csv_batch_asks_analyze_one_for_rows_not_a_file(
        monkeypatch, tmp_path):
    """The mechanism: analyze_one appends its pair and writes nothing, and
    the batch owns the single write. Two writers would race for the path."""
    seen = _csv_stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("abc123\n"))

    await run_cli(["-", "-o", str(tmp_path / "report.csv"), "--no-cache"])

    (_, output, rows) = seen[0]
    assert output is None          # analyze_one writes no file of its own
    assert rows is not None        # it accumulates instead


async def test_an_interrupted_batch_keeps_the_rows_it_finished(monkeypatch, tmp_path):
    """Ctrl-C on line 3 of a long list must not discard lines 1 and 2.

    This is the module's own rule -- "a 100-line run that dies on line 3 has
    already paid for three lookups" -- and aggregation is what put it at
    risk: the per-indicator files were on disk the moment each run ended,
    whereas one table is written once, at the end. A KeyboardInterrupt is a
    BaseException, so it walks straight past `except Exception`; the write
    has to be in the `finally` or it does not happen at all.
    """
    from hash_searcher.models import OTXReport, Report, Verdict, VTReport

    seen = []

    async def interrupt_on_third(user_input, args, cache=None, output=None,
                                 budget=None, rows=None):
        seen.append(user_input)
        if len(seen) == 3:
            raise KeyboardInterrupt("user hit ctrl-c")
        rows.append((
            Report(indicator=user_input, generated_at="2026-09-03 12:00:00",
                   vt=VTReport(found=False),
                   otx=OTXReport(recorded_instances="N/A"),
                   ips={}, hosts=[], whois=[]),
            Verdict(level="CLEAN", score=0),
        ))
        return EXIT_CLEAN

    monkeypatch.setattr("hash_searcher.batch.analyze_one", interrupt_on_third)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\nc\nd\n"))
    out = tmp_path / "report.csv"

    with pytest.raises(KeyboardInterrupt):
        await run_cli(["-", "-o", str(out), "--no-cache"])

    # The interrupt still reaches the caller -- it is not swallowed -- but
    # the two lookups already paid for are on disk.
    assert out.exists()
    assert [r[0] for r in _read_csv(out)[1:]] == ["a", "b"]


async def test_an_output_path_that_cannot_be_written_is_refused_up_front(
        monkeypatch, tmp_path, capsys):
    """The same rule the extension pre-flight follows one branch above: a
    batch must not spend every rate-limited lookup and only then discover it
    cannot write the file. Under per-indicator output the first indicator
    failed and the user learned immediately; one table would not fail until
    after the hundredth."""
    seen = _csv_stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\n"))

    code = await run_cli(["-", "-o", str(tmp_path / "nope" / "report.csv"),
                          "--no-cache"])

    assert code == EXIT_NO_DATA
    assert seen == []                       # nothing was looked up
    assert "report.csv" in capsys.readouterr().out


async def test_a_failing_final_write_does_not_become_a_traceback(
        monkeypatch, tmp_path, capsys):
    """A hundred good lookups must not exit as an unhandled OSError because
    the directory went away mid-run. The loop already applies this rule to a
    failing indicator; the write deserves it too."""
    _csv_stub_analyze(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\n"))

    def explode(rows, path):
        raise OSError("disk full")

    monkeypatch.setattr("hash_searcher.batch.write_rendered_rows", explode)

    code = await run_cli(["-", "-o", str(tmp_path / "report.csv"), "--no-cache"])

    assert code == EXIT_NO_DATA
    assert "disk full" in capsys.readouterr().out


async def test_a_failure_row_names_the_line_in_the_same_column_a_success_does(
        monkeypatch, tmp_path):
    """Joining the table back to the input list has to work across both
    kinds of row, and `source_file` is the column that always holds the
    line -- `indicator` holds a resolved digest on the success side."""
    _csv_stub_analyze(monkeypatch, failures={"evil.example"})
    monkeypatch.setattr("sys.stdin", io.StringIO("evil.example\n"))
    out = tmp_path / "report.csv"

    await run_cli(["-", "-o", str(out), "--no-cache"])

    header, body = _read_csv(out)[0], _read_csv(out)[1]
    values = dict(zip(header, body))
    assert values["source_file"] == "evil.example"
