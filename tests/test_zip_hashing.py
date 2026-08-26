import hashlib
import zipfile

import pyzipper

from hash_searcher.hashing import get_zip_hash

# password="" everywhere below, never omitted: get_zip_hash prompts on
# stdin when password is None, and reading stdin while pytest captures
# output raises OSError. Do not "clean this up" -- it reintroduces a hang.

A = b"first member contents"
B = b"second member contents"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_every_member_is_hashed(tmp_path):
    archive = tmp_path / "two.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a.bin", A)
        z.writestr("b.bin", B)

    assert get_zip_hash(str(archive), password="") == [_sha(A), _sha(B)]


def test_members_do_not_share_hash_state(tmp_path):
    """A shared hashlib object would make the second digest sha256(A + B)."""
    archive = tmp_path / "two.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a.bin", A)
        z.writestr("b.bin", B)

    second = get_zip_hash(str(archive), password="")[1]
    assert second == _sha(B)
    assert second != _sha(A + B)


def test_directory_entries_are_skipped(tmp_path):
    archive = tmp_path / "dir.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("sub/", b"")
        z.writestr("sub/a.bin", A)

    assert get_zip_hash(str(archive), password="") == [_sha(A)]


def test_empty_archive_returns_empty_list(tmp_path):
    archive = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive, "w"):
        pass

    assert get_zip_hash(str(archive), password="") == []


def test_plain_file_returns_single_element_list(tmp_path):
    target = tmp_path / "plain.bin"
    target.write_bytes(A)

    assert get_zip_hash(str(target)) == [_sha(A)]


def _aes_archive(path, password: bytes) -> None:
    """Write an AES-256 encrypted archive.

    The stdlib zipfile can only READ encrypted archives, and only the legacy
    ZipCrypto kind -- it cannot create either. pyzipper is what the reader
    uses, so it is what builds the fixture.
    """
    with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password)
        z.writestr("a.bin", A)


def test_the_correct_password_reads_an_encrypted_member(tmp_path):
    """The encrypted path was verified by hand in Phase 0 and never pinned."""
    archive = tmp_path / "sealed.zip"
    _aes_archive(archive, b"s3cret")

    assert get_zip_hash(str(archive), password="s3cret") == [_sha(A)]


def test_a_wrong_password_skips_the_member_rather_than_aborting(tmp_path, capsys):
    archive = tmp_path / "sealed.zip"
    _aes_archive(archive, b"s3cret")

    assert get_zip_hash(str(archive), password="wrong") == []
    out = capsys.readouterr().out
    assert "a.bin" in out
