from tests.conftest import requires


def test_analyze_pe_returns_none_for_a_non_pe(tmp_path):
    from hash_searcher.static.pe import analyze_pe

    target = tmp_path / "notpe.txt"
    target.write_text("hello")
    assert analyze_pe(str(target)) is None


def test_analyze_pe_returns_none_without_pefile(tmp_path, monkeypatch):
    """Global Constraint 3: absent library, smaller report, no crash."""
    from hash_searcher.static import pe

    monkeypatch.setattr(pe.capabilities, "have", lambda name: False)
    target = tmp_path / "x.exe"
    target.write_bytes(b"MZ" + b"\x00" * 1024)
    assert pe.analyze_pe(str(target)) is None


def test_suspicious_imports_are_named_not_just_counted():
    """A count tells an analyst nothing. The API names are the finding."""
    from hash_searcher.static.pe import suspicious

    found = suspicious({
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "lstrlenA"],
        "user32.dll": ["MessageBoxA"],
    })
    assert found == ["VirtualAllocEx", "WriteProcessMemory"]


def test_suspicious_import_matching_is_case_insensitive_and_canonicalizes():
    """Import tables are not consistently cased; the report must be."""
    from hash_searcher.static.pe import suspicious

    assert suspicious({"kernel32.dll": ["virtualallocex"]}) == ["VirtualAllocEx"]


def test_a_benign_import_table_yields_nothing():
    from hash_searcher.static.pe import suspicious

    assert suspicious({"msvcrt.dll": ["printf", "malloc", "free"]}) == []


@requires("pefile")
def test_a_malformed_pe_is_reported_not_raised(tmp_path):
    """Global Constraint 5: hostile input is the expected case here, not the
    exceptional one. pefile raises PEFormatError on a truncated header, and
    that must never reach the user as a traceback."""
    from hash_searcher.static.pe import analyze_pe

    target = tmp_path / "broken.exe"
    target.write_bytes(b"MZ" + b"\xff" * 200)

    report = analyze_pe(str(target))
    assert report is not None
    assert "could not be parsed" in report.note
