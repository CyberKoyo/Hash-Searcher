import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


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
    from hash_searcher.models import (
        CensysHost, IPReport, OTXReport, Report, SigmaRule, VTReport, WhoisRecord,
    )

    return Report(
        indicator="abc123",
        generated_at="2026-08-23 12:00:00",
        vt=VTReport(found=True, sigma=[SigmaRule("Suspicious Process", "spawns cmd", "high")]),
        otx=OTXReport(recorded_instances=7, attack_techniques=["T1059 Command"]),
        ips={"198.51.100.10": IPReport(ip="198.51.100.10", confidence=90, reports=2)},
        hosts=[CensysHost(ip="198.51.100.10", org="Example AS", asn=64496,
                          country="NL", ports=[80, 443], new_hostnames=["new.example"])],
        whois=[WhoisRecord(domain="bad.example", created="2020-01-01",
                           expires="2027-01-01", registrar="R")],
    )
