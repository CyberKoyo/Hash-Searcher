from hash_searcher.hashing import get_reg_hash

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_get_reg_hash_of_empty_file(tmp_path):
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    assert get_reg_hash(str(target)) == EMPTY_SHA256


def test_get_reg_hash_spans_multiple_read_buffers(tmp_path):
    # 65536 is the read buffer in get_reg_hash; go past it to prove the
    # loop accumulates rather than hashing only the first chunk.
    import hashlib
    payload = b"A" * (65536 * 2 + 17)
    target = tmp_path / "big.bin"
    target.write_bytes(payload)
    assert get_reg_hash(str(target)) == hashlib.sha256(payload).hexdigest()
