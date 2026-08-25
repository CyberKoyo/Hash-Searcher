from hash_searcher.hashing import check_env, get_reg_hash

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


def test_check_env_warns_but_runs_with_a_partial_key_set(monkeypatch, capsys):
    """A VT-only setup used to sys.exit(1). It must now warn and continue."""
    from hash_searcher.api.registry import Provider

    monkeypatch.setattr(
        "hash_searcher.hashing.missing_keys",
        lambda: ["OTX_KEY", "IPDB_KEY", "CENSYS_KEY"],
    )
    monkeypatch.setattr(
        "hash_searcher.hashing.available",
        lambda: [Provider(name="virustotal", key_env=None,
                           indicator_types=(), fetch=None)],
    )

    assert check_env() is True

    out = capsys.readouterr().out
    assert "OTX_KEY" in out and "IPDB_KEY" in out and "CENSYS_KEY" in out
    assert "Sources enabled: virustotal" in out


def test_check_env_reports_failure_with_zero_usable_keys(monkeypatch, capsys):
    monkeypatch.setattr(
        "hash_searcher.hashing.missing_keys",
        lambda: ["TOTAL_KEY", "OTX_KEY", "IPDB_KEY", "CENSYS_KEY"],
    )
    monkeypatch.setattr("hash_searcher.hashing.available", lambda: [])

    assert check_env() is False

    out = capsys.readouterr().out
    assert "no usable sources" in out.lower()
