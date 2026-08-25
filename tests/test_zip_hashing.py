import hashlib
import zipfile

from hash_searcher.hashing import get_zip_hash

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
