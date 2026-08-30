"""Shannon entropy over file bytes.

The cheapest signal in the tool: no dependency, no network, and the one
thing that can be said about a sample nobody has ever uploaded. High entropy
means compressed or encrypted, which for an executable usually means packed.
"""

import math
from collections import Counter

from ..models import EntropyReport

MAX_BYTES = 8 * 1024 * 1024   # entropy converges long before this
CHUNK = 64 * 1024
PACKED_AT = 7.2               # empirical: UPX-packed PEs sit near 7.9


def _entropy_from_counts(counts: Counter, total: int) -> float:
    if not total:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def shannon(data: bytes) -> float:
    """Bits of entropy per byte, 0.0 to 8.0. Empty input is 0.0."""
    return _entropy_from_counts(Counter(data), len(data))


def file_entropy(path: str, cap: int = MAX_BYTES) -> float:
    """Entropy of the first `cap` bytes.

    Capped because entropy converges quickly and because a hostile sample
    may be arbitrarily large -- Global Constraint 5.
    """
    counts: Counter = Counter()
    read = 0
    with open(path, "rb") as handle:
        while read < cap:
            chunk = handle.read(min(CHUNK, cap - read))
            if not chunk:
                break
            counts.update(chunk)
            read += len(chunk)
    return _entropy_from_counts(counts, read)


def analyze_entropy(path: str) -> EntropyReport:
    overall = file_entropy(path)
    packed = overall > PACKED_AT
    return EntropyReport(
        overall=round(overall, 2),
        packed=packed,
        note=("high entropy: compressed or encrypted, commonly a packer"
              if packed else "entropy is in the normal range"),
    )
