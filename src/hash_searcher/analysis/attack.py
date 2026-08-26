"""Resolve MITRE ATT&CK technique IDs against a vendored STIX bundle.

Vendored, not fetched: the spec puts a "no key, no internet" guarantee on
the offline path, and a network call here would break it. See
data/README.md for the bundle's release tag, hashes, and refresh command.
"""

import functools
import json
from pathlib import Path

from ..models import AttackTechnique

BUNDLE_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre-attack-enterprise.json"
ATTACK_SOURCE = "mitre-attack"


@functools.lru_cache(maxsize=1)
def load_bundle() -> dict:
    """Read the vendored bundle once per process.

    A missing or corrupt file is not fatal: resolve() degrades to echoing
    the raw IDs, which is worse output but still true output.
    """
    try:
        return json.loads(BUNDLE_PATH.read_text())
    except (OSError, ValueError):
        return {"objects": []}


def _index(bundle: dict) -> dict[str, AttackTechnique]:
    index: dict[str, AttackTechnique] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        reference = next(
            (r for r in obj.get("external_references", [])
             if r.get("source_name") == ATTACK_SOURCE and r.get("external_id")),
            None,
        )
        if not reference:
            continue
        tactic = next(
            (p.get("phase_name") for p in obj.get("kill_chain_phases", [])
             if p.get("kill_chain_name") == ATTACK_SOURCE),
            None,
        )
        index[reference["external_id"]] = AttackTechnique(
            id=reference["external_id"],
            name=obj.get("name", reference["external_id"]),
            tactic=tactic,
            url=reference.get("url"),
        )
    return index


@functools.lru_cache(maxsize=1)
def _default_index() -> dict[str, AttackTechnique]:
    return _index(load_bundle())


def resolve(technique_ids: list[str], bundle: dict | None = None) -> list[AttackTechnique]:
    """Deduplicated, first-seen order.

    An ID absent from the bundle survives as itself rather than being
    dropped: a stale bundle should degrade the output, not censor it.
    """
    if not technique_ids:
        # The index costs ~28 ms to build on first use. Most payloads carry no
        # ATT&CK data at all, and building 649 entries to resolve nothing is
        # pure cost.
        return []
    index = _index(bundle) if bundle is not None else _default_index()
    out: list[AttackTechnique] = []
    seen: set[str] = set()
    for tid in technique_ids:
        if not tid or tid in seen:
            continue
        seen.add(tid)
        out.append(index.get(tid) or AttackTechnique(id=tid, name=tid))
    return out


def technique_ids_from_otx(raw) -> list[str]:
    """OTX attack_ids carry both an id and a display_name; take the id."""
    if not isinstance(raw, dict):
        return []
    ids: list[str] = []
    for pulse in (raw.get("pulse_info") or {}).get("pulses", []) or []:
        for attack in pulse.get("attack_ids", []) or []:
            tid = attack.get("id") if isinstance(attack, dict) else attack
            if tid:
                ids.append(tid)
    return ids


def technique_ids_from_vt(raw) -> list[str]:
    """behaviour_mitre_trees is {sandbox: {tactics: [{techniques: [...]}]}}."""
    if not isinstance(raw, dict):
        return []
    trees = raw.get("data", {}).get("attributes", {}).get("behaviour_mitre_trees") or {}
    ids: list[str] = []
    for tree in trees.values():
        for tactic in tree.get("tactics", []) or []:
            for technique in tactic.get("techniques", []) or []:
                if technique.get("id"):
                    ids.append(technique["id"])
    return ids
