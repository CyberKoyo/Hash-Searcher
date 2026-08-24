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
