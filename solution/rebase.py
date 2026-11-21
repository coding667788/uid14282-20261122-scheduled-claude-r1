"""Projection of an inventory proof through a chain of two-root change proofs.

The inventory holder has an ordinary single-root proof for a fixed key set ``S``
at root ``A``.  The auditor supplies a chain of two-root proofs ``A -> B -> C``;
every hop may modify a different key set ``T``.  Re-proving ``S`` at the final
root never expands the whole tree and never invents undisclosed branch content:

* a hop leaf for an ``S`` key gives its new hash; its *old* hash is compared
  independently with the hash already bound by earlier evidence,
* a hop citation strictly above an ``S`` key means the region is shared between
  that hop's two roots, so the key is unchanged there and nothing is inferred
  below the citation,
* a hop citation at an ``S`` boundary prefix must agree with the digest already
  carried; when two pieces of evidence bind the same digest both are checked,
* every other node is determined by the hop's proof (leaves, citations, and
  emptiness elsewhere), so the boundary digest is recomputed from it.

After every hop the carried scene -- ``S`` leaves plus ``S`` boundary digests --
must reproduce the hop's new root, which proves that only the affected branches
were replaced.  At the end the boundaries are rebuilt into a minimal ordinary
proof for ``S`` at the final root and round-tripped against that root.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .core import (
    EMPTY_HEX,
    boundary,
    err,
    parse_proof,
    require,
    value_hash,
)
from .merkle import Scene, render_value_proof, scene_of_value_proof


@dataclass
class Hop:
    """One chain hop, already verified against its own trusted root pair."""

    index: int
    version: int
    old_root: str
    new_root: str
    proof: Any
    policy: Any = None
    path: str = "chain"
    report: Any = None


@dataclass
class RebaseResult:
    final_root: str
    depth: int
    values: dict[str, str | None]
    rows: list[dict[str, Any]]
    proof: dict[str, Any]
    claims: dict[str, str]
    touched: set[str]
    hops: list[dict[str, Any]] = field(default_factory=list)


def check_chain(hops: Sequence[Hop], inventory_root: str, field: str = "chain") -> None:
    """Continuity and version order -- validated before anything is projected."""
    require(hops, "EMPTY_CHAIN", field, "the change chain must have at least one hop")
    for i, hop in enumerate(hops):
        if i == 0:
            require(hop.old_root == inventory_root, "CHAIN_BROKEN", f"{field}[{i}].old_root",
                    "the chain does not start at the inventory root")
        else:
            require(hop.old_root == hops[i - 1].new_root, "CHAIN_BROKEN",
                    f"{field}[{i}].old_root",
                    "the hop does not continue from the previous hop's new root")
            require(hop.version > hops[i - 1].version, "VERSION_ORDER",
                    f"{field}[{i}].version",
                    f"hop version {hop.version} does not follow {hops[i - 1].version}")


def _cited_region(proof, point: str) -> str | None:
    """Longest proof citation that is a prefix of (or equal to) ``point``."""
    best = None
    for prefix in proof.cites:
        if point.startswith(prefix) and (best is None or len(prefix) > len(best)):
            best = prefix
    return best


def _inside_cite(proof, point: str) -> bool:
    """True when a citation strictly above ``point`` keeps it undisclosed."""
    return any(len(p) < len(point) and point.startswith(p) for p in proof.cites)


def run_rebase(inventory_root: str, inv_proof, s_keys: Iterable[str] | None,
               hops: Sequence[Hop], field: str = "chain") -> RebaseResult:
    keys = sorted(set(inv_proof.keys))
    if s_keys is not None:
        require(set(keys) == set(s_keys), "KEY_SET_MISMATCH", "inventory.proof.leaves",
                "the inventory proof must cover exactly the S key set")
    check_chain(hops, inventory_root, field)

    depth = inv_proof.depth
    for hop in hops:
        require(hop.proof.depth == depth, "KEY_DEPTH_MISMATCH", hop.path + ".proof.leaves",
                f"hop keys must have depth {depth}, matching the inventory proof")

    # Carried evidence: leaf hashes and values for S, one digest per boundary.
    leaf_hash = {k: value_hash(inv_proof.values[k][0]) for k in keys}
    values = {k: inv_proof.values[k][0] for k in keys}
    bounds = boundary(keys)
    claims: dict[str, str] = {}
    for prefix in bounds:
        digest = inv_proof.cites.get(prefix)
        if digest is None:
            raise err("MISSING_BOUNDARY", "inventory.proof.citations",
                      f"the inventory proof does not bind boundary branch {prefix}")
        claims[prefix] = digest

    history: dict[str, list[int]] = {k: [] for k in keys}
    applied: dict[str, list[dict[str, Any]]] = {k: [] for k in keys}
    touched: set[str] = set()
    hop_rows: list[dict[str, Any]] = []

    for hop in hops:
        proof = hop.proof
        scene = Scene(depth, 2)
        for key in proof.keys:
            scene.add_leaf(key, [value_hash(proof.values[key][0]),
                                 value_hash(proof.values[key][1])],
                           hop.path + ".proof.leaves")
        for prefix, digest in proof.cites.items():
            scene.add_cite(prefix, digest, hop.path + ".proof.citations")
        scene.check_root(0, hop.old_root, hop.path, "hop old")
        scene.check_root(1, hop.new_root, hop.path, "hop new")

        changed = [k for k in proof.keys if proof.values[k][0] != proof.values[k][1]]
        touched.update(changed)
        s_changed = []

        # --- 1. every S leaf: check the old side, then adopt the new side.
        for key in keys:
            if key in proof.values:
                old_value, new_value = proof.values[key]
                if value_hash(old_value) != leaf_hash[key]:
                    raise err("OLD_VALUE_CONFLICT", hop.path + ".proof.leaves",
                              f"hop {hop.index} and the carried evidence disagree about the "
                              f"old value of key {key}")
                new_hash = value_hash(new_value)
                if new_hash != leaf_hash[key]:
                    history[key].append(hop.index)
                    applied[key].append({"hop": hop.index, "from": values[key],
                                         "to": new_value})
                    leaf_hash[key] = new_hash
                    values[key] = new_value
                    s_changed.append(key)
                continue
            cite = _cited_region(proof, key)
            if cite is None:
                # Empty on both sides of this hop: the S leaf became absent.
                if leaf_hash[key] != EMPTY_HEX:
                    history[key].append(hop.index)
                    applied[key].append({"hop": hop.index, "from": values[key], "to": None})
                    leaf_hash[key] = EMPTY_HEX
                    values[key] = None
                    s_changed.append(key)
                continue
            if len(cite) == len(key):
                # A leaf-level citation is the leaf hash itself: check it twice.
                if proof.cites[cite] != leaf_hash[key]:
                    raise err("OLD_BRANCH_CONFLICT", hop.path + ".proof.citations",
                              f"hop {hop.index} binds leaf {key} to a digest that contradicts "
                              f"the carried value")
            # Strictly above: shared between both roots, so the leaf is unchanged.

        # --- 2. every S boundary branch: keep it unless this hop touched it.
        for prefix in bounds:
            cite = _cited_region(proof, prefix)
            if cite is not None:
                if len(cite) == len(prefix):
                    if proof.cites[cite] != claims[prefix]:
                        raise err("OLD_BRANCH_CONFLICT", hop.path + ".proof.citations",
                                  f"hop {hop.index} and the carried evidence disagree about "
                                  f"branch {prefix}")
                continue
            if _inside_cite(proof, prefix):
                # Unreachable: _cited_region would have found the covering citation.
                raise err("INTERNAL", hop.path, "inconsistent citation lookup")
            old_digest = scene.node(prefix, 0)
            if old_digest != claims[prefix]:
                raise err("OLD_BRANCH_CONFLICT", hop.path + ".proof.citations",
                          f"hop {hop.index} recomputes branch {prefix} as {old_digest} but the "
                          f"carried evidence binds {claims[prefix]}")
            claims[prefix] = scene.node(prefix, 1)

        # --- 3. the carried scene must reproduce this hop's new root.
        carried = _carried_scene(depth, keys, leaf_hash, bounds, claims)
        carried.check_root(0, hop.new_root, hop.path,
                           f"carried root after hop {hop.index}")

        hop_rows.append({
            "hop": hop.index,
            "version": hop.version,
            "old_root": "sha256:" + hop.old_root,
            "new_root": "sha256:" + hop.new_root,
            "audited": len(proof.keys),
            "modified": len(changed),
            "s_changed": s_changed,
        })

    final_root = hops[-1].new_root
    final_scene = _carried_scene(depth, keys, leaf_hash, bounds, claims)
    final_scene.check_root(0, final_root, field, "final")

    proof = render_value_proof(final_scene, keys, values)
    round_trip = scene_of_value_proof(parse_proof(proof, "proof", ("value",)))
    round_trip.check_root(0, final_root, "proof", "final")

    rows = []
    for key in keys:
        hops_changed = history[key]
        rows.append({
            "key": key,
            "value": values[key],
            "initial": inv_proof.values[key][0],
            "changes": applied[key],
            "first_change_hop": hops_changed[0] if hops_changed else None,
            "last_change_hop": hops_changed[-1] if hops_changed else None,
            "changed": bool(hops_changed),
        })

    return RebaseResult(
        final_root=final_root,
        depth=depth,
        values=values,
        rows=rows,
        proof=proof,
        claims=claims,
        touched=touched,
        hops=hop_rows,
    )


def _carried_scene(depth: int, keys: Sequence[str], leaf_hash: dict[str, str],
                   bounds: Sequence[str], claims: dict[str, str]) -> Scene:
    scene = Scene(depth, 1)
    for key in keys:
        scene.add_leaf(key, [leaf_hash[key]])
    for prefix in bounds:
        scene.add_cite(prefix, claims[prefix])
    return scene
