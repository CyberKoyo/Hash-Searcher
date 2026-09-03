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

    async def fake_analyze_one(user_input, args, cache=None, output=None):
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


async def test_the_shared_cache_is_closed_even_when_a_run_raises(monkeypatch):
    class FakeCache:
        def __init__(self, **kwargs):
            self.closed = False

        def close(self):
            self.closed = True

    made = []
    monkeypatch.setattr("hash_searcher.batch.ResponseCache",
                        lambda **kw: made.append(FakeCache()) or made[-1])

    async def boom(user_input, args, cache=None, output=None):
        raise RuntimeError("provider blew up")

    monkeypatch.setattr("hash_searcher.batch.analyze_one", boom)
    monkeypatch.setattr("sys.stdin", io.StringIO("a\n"))

    with pytest.raises(RuntimeError):
        await run_cli(["-"])
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

    async def fake_analyze_one(user_input, args, cache=None, output=None):
        seen.append(user_input)
        return EXIT_CLEAN

    monkeypatch.setattr("hash_searcher.cli.analyze_one", fake_analyze_one)

    assert await run_cli(["198.51.100.10", "--no-cache"]) == EXIT_CLEAN
    assert seen == ["198.51.100.10"]
