import os


def test_shannon_of_uniform_bytes_is_maximal():
    """256 distinct byte values, each exactly once: 8.0 bits per byte."""
    from hash_searcher.static.entropy import shannon

    assert shannon(bytes(range(256))) == 8.0


def test_shannon_of_a_single_repeated_byte_is_zero():
    from hash_searcher.static.entropy import shannon

    assert shannon(b"\x00" * 4096) == 0.0


def test_shannon_of_empty_input_is_zero_not_a_zero_division():
    from hash_searcher.static.entropy import shannon

    assert shannon(b"") == 0.0


def test_english_text_lands_in_the_expected_middle_band():
    from hash_searcher.static.entropy import shannon

    assert 3.5 < shannon(b"the quick brown fox jumps over the lazy dog. " * 100) < 4.8


def test_a_high_entropy_file_is_flagged_as_packed(tmp_path):
    from hash_searcher.static.entropy import PACKED_AT, analyze_entropy

    target = tmp_path / "packed.bin"
    target.write_bytes(os.urandom(64 * 1024))

    report = analyze_entropy(str(target))
    assert report.overall > PACKED_AT
    assert report.packed is True
    assert "compressed or encrypted" in report.note


def test_a_plain_text_file_is_not_flagged(tmp_path):
    from hash_searcher.static.entropy import analyze_entropy

    target = tmp_path / "plain.txt"
    target.write_text("hello world\n" * 5000)

    assert analyze_entropy(str(target)).packed is False


def test_entropy_reads_at_most_the_cap(tmp_path):
    """Global Constraint 5: a 2GB sample must not be read into memory.

    Asserted by counting bytes read, not by comparing entropy values -- a
    truncated read of a uniform file gives the same number either way, which
    would make this test pass against an uncapped implementation.
    """
    from hash_searcher.static import entropy

    target = tmp_path / "big.bin"
    target.write_bytes(os.urandom(1024 * 1024))

    read = []
    real_open = open

    def counting_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        real_read = handle.read

        def tracked(n=-1):
            chunk = real_read(n)
            read.append(len(chunk))
            return chunk

        handle.read = tracked
        return handle

    entropy.open = counting_open          # module-level shadow, undone below
    try:
        entropy.file_entropy(str(target), cap=4096)
    finally:
        del entropy.open
    assert sum(read) <= 4096
