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
