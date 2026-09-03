"""Coverage for the indicator classifier (Task B1).

Pure and offline by construction: nothing here touches a provider, and the
only filesystem access is against tmp_path, because "is this a file?" is a
real part of what classify() answers.
"""

import time

import pytest

from hash_searcher.indicators import (
    Indicator, classify, domain_of, looks_like_hash, refang, unsupported_reason,
)

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# --- the six kinds -------------------------------------------------------

def test_a_bare_digest_is_a_hash():
    assert classify(SHA256) == Indicator("hash", SHA256)


def test_an_uppercase_digest_is_normalized():
    assert classify(SHA256.upper()) == Indicator("hash", SHA256)


def test_a_dotted_quad_is_an_ip():
    assert classify("198.51.100.10") == Indicator("ip", "198.51.100.10")


def test_an_ipv6_address_is_an_ip():
    assert classify("2001:db8::1") == Indicator("ip", "2001:db8::1")


def test_a_bare_name_is_a_domain():
    assert classify("evil.example") == Indicator("domain", "evil.example")


def test_a_domain_is_lowercased():
    # DNS is case-insensitive, and the cache keys on the indicator value --
    # EVIL.example and evil.example must not cost two lookups.
    assert classify("EVIL.Example") == Indicator("domain", "evil.example")


def test_an_http_string_is_a_url():
    assert classify("https://evil.example/path") == Indicator(
        "url", "https://evil.example/path")


def test_a_url_path_keeps_its_case():
    # The host is case-insensitive; the path is not. Lowercasing the whole
    # URL would silently ask for a different resource.
    assert classify("https://evil.example/PaTh").value.endswith("/PaTh")


def test_a_prefix_is_a_cidr():
    assert classify("198.51.100.0/24") == Indicator("cidr", "198.51.100.0/24")


def test_an_existing_path_is_a_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    assert classify(str(sample)) == Indicator("file", str(sample))


# --- file wins over domain, but only when the file is really there -------

def test_a_path_that_also_reads_as_a_domain_resolves_to_file(monkeypatch, tmp_path):
    """`hash-searcher evil.example` in a directory holding a file of that
    name must analyze the file. The filesystem is the tiebreaker, because
    it is the only one of the two readings that can be checked."""
    (tmp_path / "evil.example").write_bytes(b"MZ")
    monkeypatch.chdir(tmp_path)
    assert classify("evil.example") == Indicator("file", "evil.example")


def test_the_same_name_is_a_domain_when_no_such_file_exists(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert classify("evil.example") == Indicator("domain", "evil.example")


def test_a_directory_is_not_a_file(monkeypatch, tmp_path):
    (tmp_path / "evil.example").mkdir()
    monkeypatch.chdir(tmp_path)
    # os.path.exists() would say yes here; a directory cannot be hashed.
    assert classify("evil.example") == Indicator("domain", "evil.example")


# --- defanged input ------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("hxxp://evil.example/a", "http://evil.example/a"),
    ("hXXps://evil.example/a", "https://evil.example/a"),
    ("1[.]2[.]3[.]4", "1.2.3.4"),
    ("1(.)2(.)3(.)4", "1.2.3.4"),
    ("evil[dot]com", "evil.com"),
    ("evil [.] example", "evil.example"),
    ("hxxps[:]//evil[.]example", "https://evil.example"),
    ("hxxps[://]evil[.]example", "https://evil.example"),
    ("user[at]evil.example", "user@evil.example"),
])
def test_refang_undoes_the_common_defangings(raw, expected):
    assert refang(raw) == expected


def test_a_defanged_url_classifies_and_yields_its_domain():
    indicator = classify("hxxps://evil[.]example/path")
    assert indicator == Indicator("url", "https://evil.example/path")
    assert domain_of(indicator) == "evil.example"


def test_a_defanged_ip_classifies():
    assert classify("198[.]51[.]100[.]10") == Indicator("ip", "198.51.100.10")


def test_domain_of_a_domain_is_itself():
    assert domain_of(Indicator("domain", "evil.example")) == "evil.example"


def test_domain_of_a_url_drops_port_and_userinfo():
    assert domain_of(classify("http://user:pw@evil.example:8080/x")) == "evil.example"


def test_domain_of_a_www_host_drops_the_www():
    assert domain_of(classify("https://www.evil.example/")) == "evil.example"


@pytest.mark.parametrize("indicator", [
    Indicator("ip", "198.51.100.10"),
    Indicator("hash", SHA256),
    Indicator("file", "/bin/ls"),
])
def test_domain_of_has_no_answer_for_a_non_domain(indicator):
    assert domain_of(indicator) is None


# --- a CIDR is recognized and then declined ------------------------------

def test_a_cidr_is_declined_with_a_reason():
    """Recognized, not silently expanded: /16 is 65,536 rate-limited
    lookups, and a tool that starts them without saying so is a tool that
    burns a free-tier key on one careless paste."""
    reason = unsupported_reason(classify("198.51.100.0/24"))
    assert reason is not None
    assert "198.51.100.0/24" in reason


@pytest.mark.parametrize("indicator", [
    Indicator("hash", SHA256),
    Indicator("ip", "198.51.100.10"),
    Indicator("domain", "evil.example"),
    Indicator("url", "https://evil.example/"),
    Indicator("file", "/bin/ls"),
])
def test_every_other_kind_is_supported(indicator):
    assert unsupported_reason(indicator) is None


# --- nothing at all ------------------------------------------------------

@pytest.mark.parametrize("raw", ["", "   ", "\n", "not an indicator", "..",
                                 "ftp://evil.example/x", "kernel32.dll"])
def test_unclassifiable_input_is_none(raw):
    assert classify(raw) is None


def test_looks_like_hash_is_still_exported_here():
    # api_data_puller imported this from itself for four phases; the
    # definition moved, the behavior did not.
    assert looks_like_hash(SHA256) is True
    assert looks_like_hash("README.md") is False


# --- the ReDoS regression Phase 3 closed twice ---------------------------

# Explicit ids: pytest builds a case id out of the parameter value, so a
# 10,000-space input becomes a 10,000-character test name -- and a failure
# summary that is mostly whitespace.
@pytest.mark.parametrize("raw", [
    pytest.param("1" + ".1" * 5000, id="dotted-chain"),   # made DOMAIN_RE quadratic
    pytest.param("a" * 10000, id="one-long-token"),
    pytest.param("a." * 5000, id="many-short-labels"),
    pytest.param("hxxp://" + "a[.]" * 2500, id="many-defanged-dots"),
    # Whitespace runs, which is what refang()'s own rules backtrack over:
    # five of the six begin with a whitespace quantifier, so a long run of
    # spaces is consumed and given back one character at a time from every
    # starting position. Measured before this was bounded: 10,000 spaces
    # took 3.19s, 20,000 took 12.77s -- clean 4x per 2x. None of the four
    # inputs above contains a single space, so the guard was green while
    # asserting nothing about the rules most able to blow up.
    pytest.param("a" + " " * 10000 + "b", id="spaces-between-tokens"),
    pytest.param("a" + "\t" * 10000 + "b", id="tabs-between-tokens"),
    pytest.param(" " * 10000, id="nothing-but-spaces"),
    pytest.param(("[" + " " * 200 + "." + " " * 200 + "]") * 30,
                 id="padded-defanged-dots"),
])
def test_a_ten_thousand_character_input_classifies_promptly(raw):
    """efd7c49 and 97c22d1 closed two ReDoS findings in static/strings.py.
    This module reuses those patterns, so it inherits the obligation not to
    reintroduce either one."""
    assert len(raw) >= 10000
    start = time.perf_counter()
    classify(raw)
    assert time.perf_counter() - start < 0.1


# --- a mistyped path is not a domain ----------------------------------------

@pytest.mark.parametrize("raw", [
    "missing.pdf", "sample.docx", "report.xlsx", "payload.elf", "a.rar",
    "dropper.lnk", "capture.pcap", "installer.msi", "kernel32.dll",
    "readme.txt", "core.dmp", "phish.eml",
])
def test_a_mistyped_file_path_is_not_answered_with_a_domain_lookup(raw):
    """`hash-searcher missing.pdf` from the wrong directory ran RDAP and
    crt.sh against a domain named "missing.pdf". A wrong answer wearing a
    confident face is worse than the "this file doesn't exist" message the
    tool has printed since Phase 0 -- which is what classify returning None
    lets resolve_indicator fall through to."""
    assert classify(raw) is None


@pytest.mark.parametrize("raw", [
    "evil.md", "c2.py", "panel.sh", "beacon.js", "host.io", "evil.com",
])
def test_an_extension_that_is_also_a_live_tld_stays_a_domain(raw):
    """The other side of the same trade. .md is Moldova, .py Paraguay, .sh
    St. Helena, .js Jersey -- dropping a real domain to catch a typo is the
    worse error, so these keep the domain reading."""
    assert classify(raw) == Indicator("domain", raw)


def test_no_filename_extension_is_secretly_a_live_tld():
    """Membership in FILENAME_EXTENSIONS is decided by "not a live TLD",
    and .zip/.mov are the two documented exceptions to that rule. A future
    addition that breaks it silently drops a whole TLD's domains."""
    from hash_searcher.indicators import FILENAME_EXTENSIONS

    live_tlds = {"md", "py", "sh", "js", "io", "com", "zip", "mov", "app",
                 "dev", "so", "ai", "co", "me", "tv", "cc", "ly", "gg"}
    documented_exceptions = {"zip", "mov"}
    assert (FILENAME_EXTENSIONS & live_tlds) == documented_exceptions
