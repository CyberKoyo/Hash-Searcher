def test_printable_runs_are_extracted_and_short_noise_is_not():
    from ioc_inquest.static.strings import extract_strings

    data = b"\x00\x01hello world\x00ab\x00another string here\xff"
    assert extract_strings(data, min_length=6) == ["hello world", "another string here"]


def test_utf16le_strings_are_found_too():
    """Windows binaries carry most of their interesting strings as UTF-16LE;
    an ASCII-only scan misses nearly every path and URL in a PE."""
    from ioc_inquest.static.strings import extract_strings

    data = "http://evil.example/x".encode("utf-16-le")
    assert "http://evil.example/x" in extract_strings(data, min_length=6)


def test_iocs_are_harvested_from_strings():
    from ioc_inquest.static.strings import harvest_iocs

    iocs = harvest_iocs([
        "GET http://evil.example/payload.bin HTTP/1.1",
        "connect to 198.51.100.10 now",
        "c2.evil.example",
        "not an ioc at all",
    ])
    assert iocs.ips == ["198.51.100.10"]
    assert "c2.evil.example" in iocs.domains
    assert iocs.urls == ["http://evil.example/payload.bin"]


def test_version_numbers_are_not_mistaken_for_ip_addresses():
    """The single most common false positive in strings-based IOC work."""
    from ioc_inquest.static.strings import harvest_iocs

    assert harvest_iocs(["product version 1.2.3.4", "999.999.999.999"]).ips == []


def test_private_and_loopback_addresses_are_dropped():
    """Nothing is gained by looking up 127.0.0.1 in AbuseIPDB, and every
    lookup costs a request against a rate-limited free tier."""
    from ioc_inquest.static.strings import harvest_iocs

    assert harvest_iocs([
        "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "203.0.113.7",
    ]).ips == ["203.0.113.7"]


def test_common_library_domains_are_filtered():
    """These appear in nearly every signed Windows binary. Reporting them is
    noise that buries the one domain that matters."""
    from ioc_inquest.static.strings import harvest_iocs

    domains = harvest_iocs(["microsoft.com", "w3.org", "evil.example"]).domains
    assert domains == ["evil.example"]


def test_iocs_are_deduplicated_and_capped():
    from ioc_inquest.static.strings import IOC_LIMIT, harvest_iocs

    strings = [f"203.0.113.{n % 250}" for n in range(400)]
    ips = harvest_iocs(strings).ips
    assert len(ips) <= IOC_LIMIT
    assert len(ips) == len(set(ips))


def test_pe_import_filenames_are_not_reported_as_domains():
    """kernel32.dll and friends cluster early in a PE's string table and,
    uncapped, would crowd the one genuine domain IOC out of IOC_LIMIT."""
    from ioc_inquest.static.strings import harvest_iocs

    domains = harvest_iocs([
        "KERNEL32.dll", "USER32.dll", "ADVAPI32.dll", "readme.txt", "setup.exe",
    ]).domains
    assert domains == []


def test_a_genuine_dot_com_domain_is_still_reported():
    """Guards against an over-broad filename blocklist: .com is both the
    most common TLD and a DOS executable extension, and must stay a
    reportable domain."""
    from ioc_inquest.static.strings import harvest_iocs

    assert harvest_iocs(["evil-domain.com"]).domains == ["evil-domain.com"]


def test_subdomains_of_ignored_domains_are_filtered():
    from ioc_inquest.static.strings import harvest_iocs

    domains = harvest_iocs(["www.microsoft.com", "crl.digicert.com"]).domains
    assert domains == []


def test_subdomain_of_a_non_ignored_domain_is_still_reported():
    from ioc_inquest.static.strings import harvest_iocs

    assert harvest_iocs(["c2.evil.example"]).domains == ["c2.evil.example"]


def test_a_dotted_chain_with_no_valid_tld_does_not_hang():
    """branch-review.md C2: the old _DOMAIN_RE backtracked catastrophically
    on a long dotted chain that never ends in a letters-only TLD -- "11.11.
    11...". This is real Global Constraint 5 bait: it needs no PE, no YARA,
    and no optional library, and analyze_strings has no capability gate, so
    it runs on every file the CLI is pointed at. Measured on the old regex:
    6KB 0.27s, 12KB 1.08s, 24KB 7.09s, 48KB 25.54s -- clean 4x per 2x,
    quadratic; a 100KB file did not finish in 60s."""
    import time

    from ioc_inquest.static.strings import harvest_iocs

    started = time.monotonic()
    result = harvest_iocs(["11." * 20000])
    elapsed = time.monotonic() - started

    assert elapsed < 1.0, f"took {elapsed:.2f}s -- catastrophic backtracking regressed"
    # "11.11.11...11" never ends in a letters-only TLD, so it is not a domain.
    assert result.domains == []


def test_many_dotted_quads_do_not_make_ip_matching_quadratic():
    """Fixing _DOMAIN_RE surfaced a second O(n^2) on the exact same
    adversarial "11.11.11..." shape, reached through _find_ips instead:
    _preceded_by_version_marker used to slice the *entire* prefix up to
    each candidate's start position and lower() it, once per dotted-quad
    match. Measured before this fix at this exact input (~500KB): 9.31s --
    the same quadratic signature as C2, just via a different function, and
    still reachable within analyze_strings' 8 MiB MAX_BYTES cap. The fixed
    code measures 0.4-0.5s here; the 3s budget leaves generous headroom for
    a loaded CI runner while still catching a quadratic regression, which
    gets dramatically worse (not just 6x slower) at this size."""
    import time

    from ioc_inquest.static.strings import harvest_iocs

    started = time.monotonic()
    harvest_iocs(["11." * 166_667])  # ~500KB
    elapsed = time.monotonic() - started

    assert elapsed < 3.0, f"took {elapsed:.2f}s -- quadratic IP scanning regressed"


def test_many_distinct_urls_do_not_make_stripping_quadratic():
    """branch-review.md C4: harvest_iocs's URL-stripping loop did
    `remainder = remainder.replace(url, " ")` once per URL _find_urls
    found. Each call rescans the whole (shrinking but still large)
    remainder, so N DISTINCT URLs cost O(len(text) x N). IDENTICAL
    repeated URLs do NOT reproduce this -- a single replace() call removes
    every occurrence of one URL in one pass, so the loop body only runs
    more than once when the URLs differ from each other. This was masked
    until C2's two blowups were fixed, since both of those hung first.
    Measured before this fix on this exact shape (20,000 distinct URLs,
    ~838KB): 3.28s; the fixed code measures ~0.03s here."""
    import time

    from ioc_inquest.static.strings import harvest_iocs

    text = " ".join(f"http://example{i}.test/path/to/thing{i}" for i in range(20_000))
    started = time.monotonic()
    harvest_iocs([text])
    elapsed = time.monotonic() - started

    assert elapsed < 2.0, f"took {elapsed:.2f}s -- quadratic URL stripping regressed"


def test_domains_followed_by_a_non_tld_trailing_label_are_still_found():
    """branch-review.md I6: the C2 fix first shipped as fullmatch() against
    a whole tokenised run, which cannot backtrack to a shorter match the
    way the original word-boundary-anchored pattern does on failure. That silently
    dropped a valid domain immediately followed by a trailing label that
    is not a letters-only TLD -- a numeric suffix, a dotted port, a
    double dot -- which is exactly the shape an IOC extractor exists to
    catch. 640 of 40,000 random fuzz inputs differed from the original
    pattern's behaviour under that version. The fix runs the original
    pattern's own backtracking inside each token instead, so these must
    still be found."""
    from ioc_inquest.static.strings import harvest_iocs

    assert harvest_iocs(["evil.example.123"]).domains == ["evil.example"]
    assert harvest_iocs(["host.evil.example.99"]).domains == ["host.evil.example"]
    assert harvest_iocs(["a.b.evil.example.7"]).domains == ["a.b.evil.example"]
    assert harvest_iocs(["foo..bar.example"]).domains == ["bar.example"]


def test_a_domain_run_that_bleeds_into_an_underscore_is_not_a_false_positive():
    """Found while differential-testing the I6 fix beyond the review's own
    fuzz coverage (their reported 40,000-input run used an alphabet
    without '_'). Regex word-boundary anchors are defined relative to the
    word-character class, which includes '_' along with letters and
    digits, so "1.kyzas__su" has no real word boundary after "kyzas" --
    the underscore is itself a word character. The original
    word-boundary-anchored pattern therefore finds nothing here. A
    domain-token character class that excludes '_' cuts the token right
    before the underscore and isolates "1.kyzas" as if it stood alone,
    manufacturing a boundary the full text never had -- a false positive
    relative to the original that a fuzz run without '_' in its alphabet
    would never surface. Including '_' in the token's character class
    (even though '_' can never be part of a domain label itself)
    preserves the adjacency the word-boundary anchor needs to see, at no
    cost to the ReDoS fix -- MAX_DOMAIN still bounds the backtracking to a
    constant regardless of how the token is delimited."""
    from ioc_inquest.static.strings import harvest_iocs

    assert harvest_iocs(["1.kyzas__su"]).domains == []
    assert harvest_iocs(["_bgg 93hlqp17.kv_r"]).domains == []


# --- branch-review.md I3: analyze_strings itself had zero direct coverage ----


def test_analyze_strings_returns_a_report_with_the_expected_count_and_iocs(tmp_path):
    """The public entry point named in the plan's Interfaces, exercised
    directly for the first time -- everything above this line tests
    extract_strings/harvest_iocs, never the function that wires them
    together and reads the file."""
    from ioc_inquest.static.strings import analyze_strings

    target = tmp_path / "sample.bin"
    target.write_bytes(
        b"\x00" * 4
        + b"connect to 198.51.100.10 for c2.evil.example now please\x00"
        + b"\x00" * 4
    )

    report = analyze_strings(str(target))
    assert report.count == 1
    assert report.iocs.ips == ["198.51.100.10"]
    assert report.iocs.domains == ["c2.evil.example"]


def test_analyze_strings_reads_at_most_max_bytes(tmp_path, monkeypatch):
    """Global Constraint 5: analyze_strings has no capability gate -- it
    runs on every file the CLI is pointed at -- so its cap is load-bearing
    for every run, not just a with-[static] one.

    Modeled directly on test_entropy_reads_at_most_the_cap: counting bytes
    actually read, not comparing output, because a truncated read of
    uniform filler data can look identical to an untruncated one either
    way. `grep -rn "MAX_BYTES\\|analyze_strings" tests/` returned nothing
    before this test existed, and mutating `handle.read(MAX_BYTES)` to
    `handle.read()` left the whole suite green.

    `strings.MAX_BYTES` (imported from entropy.py, real default 8 MiB) is
    patched down to a small value rather than writing an 8 MiB+ fixture --
    `analyze_strings` has no `cap` parameter of its own the way
    `file_entropy` does, but it re-reads the module-global name on every
    call, so patching the module attribute has the same effect entropy's
    test gets by passing `cap=4096` directly.
    """
    from ioc_inquest.static import strings

    monkeypatch.setattr(strings, "MAX_BYTES", 4096)
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * (1024 * 1024))

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

    strings.open = counting_open          # module-level shadow, undone below
    try:
        strings.analyze_strings(str(target))
    finally:
        del strings.open
    assert sum(read) <= 4096
