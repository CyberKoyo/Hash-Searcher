import pytest

from hash_searcher.api.api_data_puller import looks_like_hash, resolve_hash

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
