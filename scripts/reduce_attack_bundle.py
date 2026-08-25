"""Reduce the MITRE ATT&CK STIX bundle to what analysis/attack.py reads.

The full enterprise bundle is ~35MB, nearly all of it prose fields this tool
never touches. Keeping only attack-pattern objects and four fields each gets
it under 1MB, small enough to vendor and to review in a diff.
"""

import json
import sys

KEEP = ("id", "name", "external_references", "kill_chain_phases", "type")

source, destination = sys.argv[1], sys.argv[2]
bundle = json.loads(open(source).read())
objects = [
    {k: v for k, v in obj.items() if k in KEEP}
    for obj in bundle.get("objects", [])
    if obj.get("type") == "attack-pattern" and not obj.get("revoked")
]
# Trailing newline: tests/test_hygiene.py requires one on every tracked
# text file, and json.dump does not write one.
with open(destination, "w") as out:
    json.dump({"type": "bundle", "objects": objects}, out)
    out.write("\n")
print(f"{len(objects)} techniques kept")
