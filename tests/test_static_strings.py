def test_printable_runs_are_extracted_and_short_noise_is_not():
    from hash_searcher.static.strings import extract_strings

    data = b"\x00\x01hello world\x00ab\x00another string here\xff"
    assert extract_strings(data, min_length=6) == ["hello world", "another string here"]


def test_utf16le_strings_are_found_too():
    """Windows binaries carry most of their interesting strings as UTF-16LE;
    an ASCII-only scan misses nearly every path and URL in a PE."""
    from hash_searcher.static.strings import extract_strings

    data = "http://evil.example/x".encode("utf-16-le")
    assert "http://evil.example/x" in extract_strings(data, min_length=6)


def test_iocs_are_harvested_from_strings():
    from hash_searcher.static.strings import harvest_iocs

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
    from hash_searcher.static.strings import harvest_iocs

    assert harvest_iocs(["product version 1.2.3.4", "999.999.999.999"]).ips == []


def test_private_and_loopback_addresses_are_dropped():
    """Nothing is gained by looking up 127.0.0.1 in AbuseIPDB, and every
    lookup costs a request against a rate-limited free tier."""
    from hash_searcher.static.strings import harvest_iocs

    assert harvest_iocs([
        "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "203.0.113.7",
    ]).ips == ["203.0.113.7"]


def test_common_library_domains_are_filtered():
    """These appear in nearly every signed Windows binary. Reporting them is
    noise that buries the one domain that matters."""
    from hash_searcher.static.strings import harvest_iocs

    domains = harvest_iocs(["microsoft.com", "w3.org", "evil.example"]).domains
    assert domains == ["evil.example"]


def test_iocs_are_deduplicated_and_capped():
    from hash_searcher.static.strings import IOC_LIMIT, harvest_iocs

    strings = [f"203.0.113.{n % 250}" for n in range(400)]
    ips = harvest_iocs(strings).ips
    assert len(ips) <= IOC_LIMIT
    assert len(ips) == len(set(ips))
