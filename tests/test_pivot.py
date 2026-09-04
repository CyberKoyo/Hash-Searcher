"""Coverage for --pivot-depth (Task B4).

Pivoting is the one feature in this part that can multiply the request
count, so most of what is pinned here is what it refuses to do: nothing at
all at depth 0, one level at depth 1, and never more than a stated number of
lookups however many names a certificate log hands back.
"""

import pytest

from hash_searcher.api.api_data_puller import PIVOT_FETCH_BUDGET, data_puller
from hash_searcher.api.crtsh import CRTSH_DOMAIN_LIMIT
from hash_searcher.cache import ResponseCache
from hash_searcher.indicators import Indicator
from hash_searcher.api.registry import Provider, by_name


def _provider(name: str) -> Provider:
    real = by_name(name)
    return Provider(name=name, key_env=None, indicator_types=real.indicator_types,
                    fetch=None, cache_ttl=42, serial_delay=0.0)


def _pool(monkeypatch, *names):
    monkeypatch.setattr("hash_searcher.api.api_data_puller.available",
                        lambda: [_provider(name) for name in names])


class _Siblings:
    """A crt.sh stub whose answer for `domain` is a certificate naming its
    children -- one level of pivot per generation."""

    def __init__(self, children):
        self.children = children
        self.asked = []

    async def __call__(self, client, domain, **kwargs):
        self.asked.append(domain)
        names = self.children.get(domain, [])
        return [{"name_value": "\n".join(names)}] if names else []


async def _run(monkeypatch, crtsh, pivot_depth, rdap=None):
    _pool(monkeypatch, "rdap", "crtsh")
    rdap_asked = []

    async def fake_rdap(client, domain, **kwargs):
        rdap_asked.append(domain)
        return rdap if rdap is not None else {"handle": domain}

    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_crtsh", crtsh)
    monkeypatch.setattr("hash_searcher.api.api_data_puller.get_rdap", fake_rdap)

    result = await data_puller(Indicator("domain", "evil.example"),
                               ResponseCache(enabled=False),
                               pivot_depth=pivot_depth)
    return result, rdap_asked


async def test_depth_zero_fetches_nothing_extra(monkeypatch):
    """The default, and exactly today's behavior: a sibling domain is
    reported, not looked up."""
    crtsh = _Siblings({"evil.example": ["sibling.example"]})
    result, rdap_asked = await _run(monkeypatch, crtsh, pivot_depth=0)

    assert crtsh.asked == ["evil.example"]
    assert rdap_asked == ["evil.example"]
    assert result["domains"] == ["evil.example"]


async def test_depth_one_looks_up_a_domain_discovered_through_crtsh(monkeypatch):
    crtsh = _Siblings({"evil.example": ["sibling.example"]})
    result, rdap_asked = await _run(monkeypatch, crtsh, pivot_depth=1)

    assert crtsh.asked == ["evil.example", "sibling.example"]
    assert rdap_asked == ["evil.example", "sibling.example"]
    assert result["domains"] == ["evil.example", "sibling.example"]


async def test_depth_one_stops_at_one_level(monkeypatch):
    """A sibling's own siblings are depth 2, and depth 2 was not asked for."""
    crtsh = _Siblings({
        "evil.example": ["sibling.example"],
        "sibling.example": ["grandchild.example"],
    })
    result, _ = await _run(monkeypatch, crtsh, pivot_depth=1)

    assert "grandchild.example" not in crtsh.asked
    assert "grandchild.example" not in result["domains"]


async def test_depth_two_reaches_the_second_generation(monkeypatch):
    crtsh = _Siblings({
        "evil.example": ["sibling.example"],
        "sibling.example": ["grandchild.example"],
    })
    _, rdap_asked = await _run(monkeypatch, crtsh, pivot_depth=2)
    assert rdap_asked == ["evil.example", "sibling.example", "grandchild.example"]


async def test_a_domain_is_never_looked_up_twice(monkeypatch):
    """Certificate logs are full of cycles: two names on one certificate
    each name the other. Without a visited set that is an infinite walk
    that only the budget stops."""
    crtsh = _Siblings({
        "evil.example": ["sibling.example"],
        "sibling.example": ["evil.example", "sibling.example"],
    })
    _, rdap_asked = await _run(monkeypatch, crtsh, pivot_depth=3)
    assert rdap_asked == ["evil.example", "sibling.example"]


async def test_total_lookups_are_capped_however_many_names_come_back(monkeypatch):
    """The reason this is breadth-first with a budget rather than recursion:
    depth 2 over 50 domains is thousands of requests against providers that
    all rate limit. Every generation here hands back 200 fresh names."""
    generation = {"n": 0}

    class _Explosive:
        def __init__(self):
            self.asked = []

        async def __call__(self, client, domain, **kwargs):
            self.asked.append(domain)
            generation["n"] += 1
            return [{"name_value": "\n".join(
                f"g{generation['n']}-{i}.example" for i in range(200))}]

    crtsh = _Explosive()
    _, rdap_asked = await _run(monkeypatch, crtsh, pivot_depth=5)

    # The base pass is one domain; everything after it comes out of the
    # budget. crt.sh additionally caps each level at CRTSH_DOMAIN_LIMIT.
    assert len(rdap_asked) <= 1 + PIVOT_FETCH_BUDGET
    assert len(crtsh.asked) <= 1 + PIVOT_FETCH_BUDGET
    # Stated absolutely as well, so raising a constant has to be a decision
    # rather than a side effect: 200 names per generation over five levels
    # is 10^11 lookups without a ceiling.
    assert len(rdap_asked) <= 25
    assert CRTSH_DOMAIN_LIMIT <= PIVOT_FETCH_BUDGET


async def test_a_negative_depth_is_rejected(monkeypatch):
    crtsh = _Siblings({})
    with pytest.raises(ValueError, match="pivot_depth"):
        await _run(monkeypatch, crtsh, pivot_depth=-1)


# --- the flag ---------------------------------------------------------------

def test_pivot_depth_defaults_to_zero():
    from hash_searcher.cli import build_parser

    assert build_parser().parse_args(["abc"]).pivot_depth == 0


def test_the_parser_rejects_a_negative_depth():
    from hash_searcher.cli import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["abc", "--pivot-depth", "-1"])


async def test_the_flag_reaches_data_puller(monkeypatch):
    from hash_searcher.cli import run_cli

    seen = []

    async def fake_puller(indicator, cache, extra_ips=None, pivot_depth=0, budget=None):
        seen.append(pivot_depth)
        return {"vt": {}, "otx": {}, "ipdb": [], "censys": [], "ips": [],
                "domains": [], "rdap": [], "crtsh": [], "shodan": {},
                "greynoise": {}, "kev": {}, "bazaar": None, "threatfox": None,
                "threatfox_ips": {}}

    monkeypatch.setattr("hash_searcher.cli.check_env", lambda: True)
    monkeypatch.setattr("hash_searcher.cli.data_puller", fake_puller)

    await run_cli(["evil.example", "--pivot-depth", "2", "--no-cache"])
    assert seen == [2]
