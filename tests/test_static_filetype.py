from tests.conftest import requires


def test_a_pe_named_pdf_is_a_mismatch(tmp_path):
    from hash_searcher.static.filetype import analyze_filetype

    target = tmp_path / "invoice.pdf"
    target.write_bytes(b"MZ\x90\x00" + b"\x00" * 1024)

    report = analyze_filetype(str(target))
    assert report.mismatch is True
    assert report.extension == ".pdf"


def test_a_pe_named_exe_is_not_a_mismatch(tmp_path):
    from hash_searcher.static.filetype import analyze_filetype

    target = tmp_path / "setup.exe"
    target.write_bytes(b"MZ\x90\x00" + b"\x00" * 1024)

    assert analyze_filetype(str(target)).mismatch is False


def test_an_unknown_type_is_not_reported_as_a_mismatch(tmp_path):
    """Absence of evidence: 'we could not identify this' must not render as
    'the extension is lying'. Otherwise every proprietary format fires."""
    from hash_searcher.static.filetype import analyze_filetype

    target = tmp_path / "thing.dat"
    target.write_bytes(b"\x17\x42" * 64)

    assert analyze_filetype(str(target)).mismatch is False


def test_the_builtin_signature_table_works_without_magic(tmp_path, monkeypatch):
    """Global Constraint 3: no optional library, smaller report, still useful."""
    from hash_searcher.static import filetype

    monkeypatch.setattr(filetype.capabilities, "have", lambda name: False)

    target = tmp_path / "doc.pdf"
    target.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 64)

    report = filetype.analyze_filetype(str(target))
    assert report.detected == "ELF"
    assert report.mismatch is True


def test_an_empty_file_does_not_raise(tmp_path):
    from hash_searcher.static.filetype import analyze_filetype

    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    assert analyze_filetype(str(target)).mismatch is False


@requires("magic")
def test_magic_is_preferred_when_available(tmp_path):
    from hash_searcher.static.filetype import analyze_filetype

    target = tmp_path / "script.txt"
    target.write_text("#!/bin/sh\necho hi\n")

    detected = (analyze_filetype(str(target)).detected or "").lower()
    assert "shell" in detected or "text" in detected
