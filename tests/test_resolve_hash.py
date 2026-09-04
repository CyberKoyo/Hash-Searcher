import hashlib

import pyzipper
import pytest

from ioc_inquest.api.api_data_puller import looks_like_hash, resolve_hash

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize("value", [MD5, SHA1, SHA256])
def test_all_three_digest_lengths_are_hashes(value):
    assert looks_like_hash(value) is True


def test_uppercase_hash_is_normalized(tmp_path):
    assert resolve_hash(SHA256.upper()) == [SHA256]


@pytest.mark.parametrize("value", [
    "README.md",
    "d41d8cd98f00b204e9800998ecf8427",    # 31 chars
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",   # right length, not hex
])
def test_non_hashes_are_rejected(value):
    assert looks_like_hash(value) is False


def test_md5_is_returned_without_touching_the_filesystem():
    # Would raise FileNotFoundError on main.
    assert resolve_hash(MD5) == [MD5]


def _build_encrypted_zip(tmp_path, data: bytes, password: bytes) -> str:
    path = str(tmp_path / "encrypted.zip")
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES
    ) as z:
        z.setpassword(password)
        z.writestr("secret.bin", data)
    return path


def test_resolve_hash_uses_the_supplied_zip_password(tmp_path):
    """Proves --zip-password actually reaches the archive: without the
    correct password this AES-encrypted member cannot be read at all."""
    data = b"top secret payload"
    archive = _build_encrypted_zip(tmp_path, data, b"correct-horse")

    assert resolve_hash(archive, password="correct-horse") == [hashlib.sha256(data).hexdigest()]


def test_resolve_hash_without_a_password_falls_back_to_a_prompt(tmp_path, monkeypatch):
    """Omitting the password does not silently succeed against an encrypted
    archive -- it must still reach hashing.get_zip_hash's interactive
    input() prompt rather than, say, defaulting to an empty password."""
    data = b"top secret payload"
    archive = _build_encrypted_zip(tmp_path, data, b"correct-horse")

    calls = []

    def fake_input(prompt=""):
        calls.append(prompt)
        return "wrong-password"

    monkeypatch.setattr("builtins.input", fake_input)

    assert resolve_hash(archive) is None
    assert len(calls) == 1


def test_resolve_hash_reports_and_skips_a_wrong_password(tmp_path):
    data = b"top secret payload"
    archive = _build_encrypted_zip(tmp_path, data, b"correct-horse")

    assert resolve_hash(archive, password="wrong-password") is None
