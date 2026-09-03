"""Resolve MITRE ATT&CK technique IDs against a vendored STIX bundle.

Vendored, not fetched: the spec puts a "no key, no internet" guarantee on
the offline path, and a network call here would break it. See
data/README.md for the bundle's release tag, hashes, and refresh command.
"""

import functools
import json
from pathlib import Path

from ..models import AttackTechnique
from .payload import as_mapping, as_mappings, as_sequence, dig

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
    """The bundle is vendored, but load_bundle already promises a corrupt one
    is not fatal -- and `{"objects": null}` is valid JSON that json.loads
    accepts, so the promise needs the same shape checks a live payload gets.
    `bundle` is also a public argument of resolve().
    """
    index: dict[str, AttackTechnique] = {}
    for obj in as_mappings(as_mapping(bundle).get("objects")):
        if obj.get("type") != "attack-pattern":
            continue
        reference = next(
            (r for r in as_mappings(obj.get("external_references"))
             if r.get("source_name") == ATTACK_SOURCE
             and isinstance(r.get("external_id"), str) and r["external_id"]),
            None,
        )
        if not reference:
            continue
        tactic = next(
            (p.get("phase_name") for p in as_mappings(obj.get("kill_chain_phases"))
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
    for tid in as_sequence(technique_ids):
        # isinstance before `tid in seen`: an unhashable id raises TypeError
        # on the set membership test, and VT's behaviour_mitre_trees supplies
        # the id straight off the payload.
        if not isinstance(tid, str) or not tid or tid in seen:
            continue
        seen.add(tid)
        out.append(index.get(tid) or AttackTechnique(id=tid, name=tid))
    return out


def technique_ids_from_otx(raw) -> list[str]:
    """OTX attack_ids carry both an id and a display_name; take the id."""
    ids: list[str] = []
    for pulse in as_mappings(as_mapping(as_mapping(raw).get("pulse_info")).get("pulses")):
        for attack in as_sequence(pulse.get("attack_ids")):
            tid = attack.get("id") if isinstance(attack, dict) else attack
            if isinstance(tid, str) and tid:
                ids.append(tid)
    return ids


def technique_ids_from_vt(raw) -> list[str]:
    """behaviour_mitre_trees is {sandbox: {tactics: [{techniques: [...]}]}}."""
    trees = as_mapping(dig(raw, "data", "attributes").get("behaviour_mitre_trees"))
    ids: list[str] = []
    for tree in trees.values():
        for tactic in as_mappings(as_mapping(tree).get("tactics")):
            for technique in as_mappings(tactic.get("techniques")):
                tid = technique.get("id")
                if isinstance(tid, str) and tid:
                    ids.append(tid)
    return ids
