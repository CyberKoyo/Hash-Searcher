import struct

from tests.conftest import requires


def _build_pe(num_sections: int, section_body: bytes) -> bytes:
    """A real, well-formed PE32 with `num_sections` sections, each backed by
    a genuine (small) chunk of `section_body` at its own file offset --
    unlike `_build_malformed_pe` below, pefile's own SizeOfRawData/
    PointerToRawData bookkeeping is honest here, used to prove the
    truncation note stays silent on an ordinary file."""
    file_align = 0x200
    section_header_size = 40

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    pe_sig = b"PE\x00\x00"
    size_of_optional_header = 224

    coff_header = struct.pack(
        "<HHIIIHH", 0x14C, num_sections, 0, 0, 0, size_of_optional_header, 0x0102,
    )

    headers_len = (len(dos_header) + len(pe_sig) + len(coff_header)
                   + size_of_optional_header + num_sections * section_header_size)
    size_of_headers = ((headers_len + file_align - 1) // file_align) * file_align

    num_rva_and_sizes = 16
    opt_standard = struct.pack("<HBBIIIII", 0x10B, 0, 0, 0, 0, 0, 0x1000, 0x1000)
    opt_standard += struct.pack("<I", 0x2000)
    section_align = 0x1000
    opt_windows = struct.pack(
        "<IIIHHHHHHIIIIHHIIIIII",
        0x400000, section_align, file_align, 0, 0, 0, 0, 4, 0, 0,
        section_align * (num_sections + 1), size_of_headers, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, num_rva_and_sizes,
    )
    optional_header = opt_standard + opt_windows + b"\x00" * (8 * num_rva_and_sizes)

    section_data_len = ((len(section_body) + file_align - 1) // file_align) * file_align
    padded_body = section_body.ljust(section_data_len, b"\x00")

    section_headers = b""
    bodies = b""
    for i in range(num_sections):
        name = f".s{i}".encode("ascii")[:8].ljust(8, b"\x00")
        raw_ptr = size_of_headers + i * section_data_len
        section_headers += struct.pack(
            "<8sIIIIIIHHI",
            name,
            len(section_body),      # VirtualSize
            section_align * (i + 1),
            section_data_len,       # SizeOfRawData -- honest
            raw_ptr,                # PointerToRawData -- honest
            0, 0, 0, 0,
            0x60000020,
        )
        bodies += padded_body

    header_blob = (dos_header + pe_sig + coff_header + optional_header
                   + section_headers).ljust(size_of_headers, b"\x00")
    return header_blob + bodies


def _build_malformed_pe(num_sections: int, body_size: int) -> bytes:
    """A real, pefile-parseable PE whose section table lies about size --
    the same shape as the branch-review.md I1 repro: every section's
    SizeOfRawData/PointerToRawData claim it maps the whole file (or beyond
    it), so `section.get_data()` with no cap would return up to the full
    file for every single section. Built with struct.pack rather than a
    committed binary fixture -- Global Constraint 8 (never commit a real
    sample) applies to malformed-but-legitimate PE shapes too, and a
    synthetic byte-built file is unambiguously not one.
    """
    file_align = 0x200
    section_header_size = 40

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    pe_sig = b"PE\x00\x00"
    size_of_optional_header = 224

    coff_header = struct.pack(
        "<HHIIIHH", 0x14C, num_sections, 0, 0, 0, size_of_optional_header, 0x0102,
    )

    headers_len = (len(dos_header) + len(pe_sig) + len(coff_header)
                   + size_of_optional_header + num_sections * section_header_size)
    size_of_headers = ((headers_len + file_align - 1) // file_align) * file_align

    num_rva_and_sizes = 16
    opt_standard = struct.pack("<HBBIIIII", 0x10B, 0, 0, 0, 0, 0, 0x1000, 0x1000)
    opt_standard += struct.pack("<I", 0x2000)
    section_align = 0x1000
    opt_windows = struct.pack(
        "<IIIHHHHHHIIIIHHIIIIII",
        0x400000, section_align, file_align, 0, 0, 0, 0, 4, 0, 0,
        section_align * (num_sections + 1), size_of_headers, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, num_rva_and_sizes,
    )
    optional_header = opt_standard + opt_windows + b"\x00" * (8 * num_rva_and_sizes)

    section_headers = b""
    for i in range(num_sections):
        name = f".s{i}".encode("ascii")[:8].ljust(8, b"\x00")
        section_headers += struct.pack(
            "<8sIIIIIIHHI",
            name,
            0x0FFFFFFF,              # VirtualSize -- lies
            section_align * (i + 1),
            0x0FFFFFFF,              # SizeOfRawData -- lies: claims way past EOF
            0,                       # PointerToRawData -- every section starts at 0
            0, 0, 0, 0,
            0x60000020,
        )

    header_blob = (dos_header + pe_sig + coff_header + optional_header
                   + section_headers).ljust(size_of_headers, b"\x00")
    return header_blob + b"\x41" * body_size


def test_analyze_pe_returns_none_for_a_non_pe(tmp_path):
    from ioc_inquest.static.pe import analyze_pe

    target = tmp_path / "notpe.txt"
    target.write_text("hello")
    assert analyze_pe(str(target)) is None


def test_analyze_pe_returns_none_without_pefile(tmp_path, monkeypatch):
    """Global Constraint 3: absent library, smaller report, no crash."""
    from ioc_inquest.static import pe

    monkeypatch.setattr(pe.capabilities, "have", lambda name: False)
    target = tmp_path / "x.exe"
    target.write_bytes(b"MZ" + b"\x00" * 1024)
    assert pe.analyze_pe(str(target)) is None


def test_suspicious_imports_are_named_not_just_counted():
    """A count tells an analyst nothing. The API names are the finding."""
    from ioc_inquest.static.pe import suspicious

    found = suspicious({
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "lstrlenA"],
        "user32.dll": ["MessageBoxA"],
    })
    assert found == ["VirtualAllocEx", "WriteProcessMemory"]


def test_suspicious_import_matching_is_case_insensitive_and_canonicalizes():
    """Import tables are not consistently cased; the report must be."""
    from ioc_inquest.static.pe import suspicious

    assert suspicious({"kernel32.dll": ["virtualallocex"]}) == ["VirtualAllocEx"]


def test_a_benign_import_table_yields_nothing():
    from ioc_inquest.static.pe import suspicious

    assert suspicious({"msvcrt.dll": ["printf", "malloc", "free"]}) == []


@requires("pefile")
def test_a_malformed_pe_is_reported_not_raised(tmp_path):
    """Global Constraint 5: hostile input is the expected case here, not the
    exceptional one. pefile raises PEFormatError on a truncated header, and
    that must never reach the user as a traceback."""
    from ioc_inquest.static.pe import analyze_pe

    target = tmp_path / "broken.exe"
    target.write_bytes(b"MZ" + b"\xff" * 200)

    report = analyze_pe(str(target))
    assert report is not None
    assert "could not be parsed" in report.note


# --- branch-review.md I1 ------------------------------------------------------


@requires("pefile")
def test_section_entropy_never_hashes_more_than_the_cap(tmp_path, monkeypatch):
    """The bound that actually matters, proven the way
    test_entropy_reads_at_most_the_cap proves entropy.py's cap: by counting
    bytes actually handed to shannon(), not by timing -- a wall-clock
    assertion alone can pass for a degenerate reason (a fast machine) or
    fail for one (a loaded CI runner) without the bound itself moving.
    """
    from ioc_inquest.static import pe as pe_module

    target = tmp_path / "malformed.exe"
    target.write_bytes(_build_malformed_pe(num_sections=50, body_size=4 * 1024 * 1024))

    seen = []
    real_shannon = pe_module.shannon

    def counting_shannon(data):
        seen.append(len(data))
        return real_shannon(data)

    monkeypatch.setattr(pe_module, "shannon", counting_shannon)
    report = pe_module.analyze_pe(str(target))

    assert report is not None
    assert len(seen) == 50   # every section was still scored, just bounded
    assert all(n <= pe_module.SECTION_ENTROPY_CAP for n in seen)


@requires("pefile")
def test_a_pe_with_a_malformed_section_table_does_not_hang(tmp_path):
    """branch-review.md I1: a synthetic 4MB PE with 600 sections, each
    claiming to map the whole file, took 167.26s before this cap existed --
    exactly the case Global Constraint 5 names ('a PE with a malformed
    section table'). 300 sections here (half that PoC) keeps this test
    itself fast while still exercising the same shape; the unit-level test
    above pins the actual mechanism."""
    import time

    from ioc_inquest.static.pe import analyze_pe

    target = tmp_path / "malformed.exe"
    target.write_bytes(_build_malformed_pe(num_sections=300, body_size=4 * 1024 * 1024))

    started = time.monotonic()
    report = analyze_pe(str(target))
    elapsed = time.monotonic() - started

    assert elapsed < 10.0, f"took {elapsed:.2f}s -- section entropy cap regressed"
    assert report is not None
    assert len(report.sections) == 300
    assert "Global Constraint 5" in report.section_entropy_note


@requires("pefile")
def test_section_entropy_note_is_empty_when_nothing_was_truncated(tmp_path):
    """A silently truncated number is worse than a stated one -- and a note
    printed on every well-formed PE, truncated or not, would be just as
    silently useless. The note must say something only when it is true."""
    from ioc_inquest.static.pe import analyze_pe

    target = tmp_path / "wellformed.exe"
    target.write_bytes(_build_pe(num_sections=2, section_body=b"A" * 100))

    report = analyze_pe(str(target))
    assert report is not None
    assert len(report.sections) == 2
    assert report.section_entropy_note == ""
