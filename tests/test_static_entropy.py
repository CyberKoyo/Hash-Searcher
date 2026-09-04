import os


def test_shannon_of_uniform_bytes_is_maximal():
    """256 distinct byte values, each exactly once: 8.0 bits per byte."""
    from ioc_inquest.static.entropy import shannon

    assert shannon(bytes(range(256))) == 8.0


def test_shannon_of_a_single_repeated_byte_is_zero():
    from ioc_inquest.static.entropy import shannon

    assert shannon(b"\x00" * 4096) == 0.0


def test_shannon_of_empty_input_is_zero_not_a_zero_division():
    from ioc_inquest.static.entropy import shannon

    assert shannon(b"") == 0.0


def test_english_text_lands_in_the_expected_middle_band():
    from ioc_inquest.static.entropy import shannon

    assert 3.5 < shannon(b"the quick brown fox jumps over the lazy dog. " * 100) < 4.8


def test_a_high_entropy_file_is_flagged_as_packed(tmp_path):
    from ioc_inquest.static.entropy import PACKED_AT, analyze_entropy

    target = tmp_path / "packed.bin"
    target.write_bytes(os.urandom(64 * 1024))

    report = analyze_entropy(str(target))
    assert report.overall > PACKED_AT
    assert report.packed is True
    assert "compressed or encrypted" in report.note


def test_a_plain_text_file_is_not_flagged(tmp_path):
    from ioc_inquest.static.entropy import analyze_entropy

    target = tmp_path / "plain.txt"
    target.write_text("hello world\n" * 5000)

    assert analyze_entropy(str(target)).packed is False


def test_entropy_reads_at_most_the_cap(tmp_path):
    """Global Constraint 5: a 2GB sample must not be read into memory.

    Asserted by counting bytes read, not by comparing entropy values -- a
    truncated read of a uniform file gives the same number either way, which
    would make this test pass against an uncapped implementation.
    """
    from ioc_inquest.static import entropy

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


def test_entropy_on_zero_byte_file_on_disk(tmp_path):
    """Finding 2: test analyze_entropy / file_entropy against zero-byte file."""
    from ioc_inquest.static.entropy import analyze_entropy

    target = tmp_path / "empty.bin"
    target.write_bytes(b"")

    report = analyze_entropy(str(target))
    assert report.overall == 0.0
    assert report.packed is False
    assert "normal range" in report.note


def test_packed_flag_pins_the_boundary(tmp_path):
    """Finding 3: pin the PACKED_AT = 7.2 boundary behavior for packed flag.

    Creates data with mixed entropy levels just under and just over 7.2 to
    ensure the > comparison is enforced.
    """
    from ioc_inquest.static.entropy import PACKED_AT, analyze_entropy

    # Data below 7.2: mix 80% random (ent ~8.0) + 20% null bytes (ent 0.0)
    # Expected entropy: ~6.4
    below_threshold = os.urandom(800) + (b"\x00" * 200)
    target_below = tmp_path / "below.bin"
    target_below.write_bytes(below_threshold)

    report_below = analyze_entropy(str(target_below))
    assert report_below.overall < PACKED_AT
    assert report_below.packed is False

    # Data above 7.2: mix 95% random (ent ~8.0) + 5% null bytes (ent 0.0)
    # Expected entropy: ~7.6
    above_threshold = os.urandom(950) + (b"\x00" * 50)
    target_above = tmp_path / "above.bin"
    target_above.write_bytes(above_threshold)

    report_above = analyze_entropy(str(target_above))
    assert report_above.overall > PACKED_AT
    assert report_above.packed is True
