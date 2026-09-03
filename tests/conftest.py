import json
import socket
from pathlib import Path

import pytest

from hash_searcher.models import (
    CensysHost, IPReport, OTXReport, Report, SigmaRule, VTReport, WhoisRecord,
)
from hash_searcher.static import capabilities

FIXTURES = Path(__file__).parent / "fixtures"

# Hosts a test is allowed to resolve without tripping the network guard
# below -- local library/interpreter plumbing occasionally calls
# getaddrinfo for these with nothing real reached over the network.
_LOCAL_HOSTS = {None, "", "localhost", "127.0.0.1", "::1"}


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """No test in this suite may make a real network call.

    Global Constraint 7 says the suite is offline and needs no key, but
    until now that rested entirely on every test author remembering to
    stub every fetch function -- C1 (branch-review.md) is proof of how
    easily a test reaches real environment state instead: it forgot to
    stub `check_env()` and only ever passed because this repo's `.env`
    holds real provider keys, which silently masked a test that would fail
    the moment it ran on a CI runner with no `.env` at all.

    Blocking at the socket layer, rather than trying to remember every
    fetch function's call site, turns a future test like that into an
    immediate, loud failure here instead of a slow hang or a pass that
    depends on this machine's environment happening to have keys or
    connectivity. Verified before adding this: the suite passes unchanged
    with `socket.connect`, `socket.connect_ex`, `socket.create_connection`,
    and non-local `getaddrinfo` all raising -- in both the extras-free and
    with-[static] environments. No test in this suite makes, or needs to
    make, a real network call.

    getaddrinfo is blocked only for non-local hosts; resolving
    "localhost"/loopback is left alone, since it happens as ordinary
    interpreter/library setup with no network actually reached.
    """
    def _blocked_connect(*args, **kwargs):
        raise RuntimeError(
            "a test tried to open a real network connection -- stub the "
            "fetch function instead of letting it reach a real socket "
            "(see tests/conftest.py: block_network)"
        )

    real_getaddrinfo = socket.getaddrinfo

    def _guarded_getaddrinfo(host, *args, **kwargs):
        if host in _LOCAL_HOSTS:
            return real_getaddrinfo(host, *args, **kwargs)
        raise RuntimeError(
            f"a test tried to resolve a real hostname ({host!r}) -- stub "
            "the fetch function instead of letting it reach the network "
            "(see tests/conftest.py: block_network)"
        )

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked_connect)
    monkeypatch.setattr(socket, "create_connection", _blocked_connect)
    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)


@pytest.fixture
def fixture_json():
    """Load a recorded provider response from tests/fixtures/<name>.json."""
    def _load(name: str):
        return json.loads((FIXTURES / f"{name}.json").read_text())
    return _load


@pytest.fixture
def no_backoff(monkeypatch):
    """Make retry backoff instant.

    Retry-After: 0 only zeroes the status-code retry path. The network-error
    path has no header to read and always takes the hardcoded exponential, so
    it can only be neutralized by replacing sleep itself.

    The dotted path below reads as if it scoped the patch to base_call. It
    does not, and nothing in this suite should be written as though it did:
    `hash_searcher.api.base_call.asyncio` resolves to the one shared asyncio
    module object, so this replaces asyncio.sleep for the whole process
    until monkeypatch undoes it. What actually keeps this fixture out of
    other tests' way is that it is not autouse -- only block_network is --
    so a test gets it only by asking for it by name.
    """
    async def _instant(_seconds):
        return None

    monkeypatch.setattr("hash_searcher.api.base_call.asyncio.sleep", _instant)


@pytest.fixture
def sample_report():
    """A fully populated Report. Shared by the TTY, JSON, and PDF renderer tests.

    In conftest rather than a test module: `from tests.X import Y` resolves only
    under `python -m pytest`, and dies under bare `pytest`.
    """
    return Report(
        indicator="abc123",
        generated_at="2026-08-23 12:00:00",
        vt=VTReport(found=True, sigma=[SigmaRule("Suspicious Process", "spawns cmd", "high")],
                    contacted_ips=["198.51.100.10"]),
        otx=OTXReport(recorded_instances=7, attack_techniques=["T1059 Command"],
                      otx_responded=True),
        ips={"198.51.100.10": IPReport(ip="198.51.100.10", confidence=90, reports=2)},
        hosts=[CensysHost(ip="198.51.100.10", org="Example AS", asn=64496,
                          country="NL", ports=[80, 443], new_hostnames=["new.example"])],
        whois=[WhoisRecord(domain="bad.example", created="2020-01-01",
                           expires="2027-01-01", registrar="R")],
    )


def requires(name: str):
    """Skip, never fail, when an optional analysis library is absent.

    Global Constraint 3: the suite must pass with none of the [static]
    extras installed, and CI runs a leg that proves it.
    """
    return pytest.mark.skipif(
        not capabilities.have(name),
        reason=f"optional dependency {name!r} is not installed",
    )
