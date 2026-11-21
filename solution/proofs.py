"""Case handlers for the offline proof commands.

``verify``, ``merge``, ``proof-rebase`` and ``split-verify`` live here.  A handler
takes the decoded CASE object and returns the JSON-able result that
``python -m solution`` writes to stdout.  Structural problems raise
:class:`solution.core.ArchiveError` with a code and the JSON path of the field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .core import (
    ArchiveError,
    change_kind,
    check_key,
    check_root,
    expect_int,
    expect_list,
    expect_object,
    expect_str,
    parse_policy,
    parse_proof,
    require,
    value_hash,
)
from .merkle import (
    Scene,
    cite_text,
    parse_cite_text,
    render_dual_proof,
    scene_of_dual_proof,
    scene_of_value_proof,
)

KINDS = ("insert", "delete", "update", "unchanged")
DUAL_SIDES = ("old_value", "new_value")
SINGLE_SIDES = ("value",)


# --------------------------------------------------------------------------- helpers

def kind_counts(kinds: Iterable[str]) -> dict[str, int]:
    out = {k: 0 for k in KINDS}
    for kind in kinds:
        out[kind] += 1
    return out


def key_row(key: str, old: str | None, new: str | None) -> dict[str, Any]:
    return {"key": key, "old": old, "new": new, "kind": change_kind(old, new)}


def parse_declared(raw: Any, field: str, keys: Iterable[str]) -> dict[str, str]:
    """Declared audited set: ``[{"key": ..., "kind"?: ...}]``.

    The declaration must cover exactly the audited keys, so a proof cannot smuggle
    in or omit keys relative to what the caller asked for.
    """
    declared: dict[str, str] = {}
    for i, item in enumerate(expect_list(raw, field)):
        path = f"{field}[{i}]"
        obj = expect_object(item, path, "declaration")
        key = check_key(obj.get("key"), path + ".key")
        kind = obj.get("kind")
        if kind is not None:
            require(kind in KINDS, "BAD_KIND", path + ".kind",
                    f"kind must be one of {', '.join(KINDS)}")
        else:
            kind = "unchanged"
        require(key not in declared, "DUP_LEAF", path, f"key {key} is declared twice")
        declared[key] = kind
    known = set(keys)
    for key in sorted(known):
        require(key in declared, "DECLARED_KEY_MISSING", field,
                f"audited key {key} is missing from the declared key set")
    for key in sorted(declared):
        require(key in known, "DECLARED_KEY_UNPROVEN", field,
                f"declared key {key} is not covered by the proof")
    return declared


def parse_key_list(raw: Any, field: str) -> list[str]:
    return [check_key(k, f"{field}[{i}]") for i, k in enumerate(expect_list(raw, field))]


@dataclass
class DualCheck:
    proof: Any
    scene: Scene
    rows: list[dict[str, Any]] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return kind_counts(r["kind"] for r in self.rows)


def check_dual(raw: Any, field: str, old_root: str, new_root: str, policy,
               declared_raw: Any = None, depth: int | None = None) -> DualCheck:
    """Verify a two-root proof against trusted roots, policy and declaration."""
    proof = parse_proof(raw, field, DUAL_SIDES)
    if depth is not None:
        require(proof.depth == depth, "KEY_DEPTH_MISMATCH", field + ".leaves",
                f"audited keys must all have depth {depth}")
    scene = scene_of_dual_proof(proof)
    scene.check_root(0, old_root, field, "old")
    scene.check_root(1, new_root, field, "new")
    declared = parse_declared(declared_raw, "declared", proof.keys) \
        if declared_raw is not None else None
    rows = []
    for key in proof.keys:
        old, new = proof.values[key]
        kind = change_kind(old, new)
        policy.check(key, kind, field + ".leaves")
        if declared is not None and kind != "unchanged":
            require(declared[key] == kind, "DECLARED_KIND_MISMATCH", "declared",
                    f"key {key} is declared as {declared[key]} but changes as {kind}")
            require(declared[key] != "unchanged", "DECLARED_KIND_MISMATCH", "declared",
                    f"key {key} changes as {kind} but is declared unchanged")
        rows.append(key_row(key, old, new))
    return DualCheck(proof, scene, rows)


def check_value(raw: Any, field: str, root: str, keys: Iterable[str] | None = None):
    proof = parse_proof(raw, field, SINGLE_SIDES)
    scene = scene_of_value_proof(proof)
    scene.check_root(0, root, field, "inventory")
    if keys is not None:
        want = set(keys)
        require(want == set(proof.keys), "KEY_SET_MISMATCH", field + ".leaves",
                "the inventory proof must cover exactly the requested key set")
    return proof, scene


def render_cites(cites: dict[str, str], depth: int) -> list[dict[str, str]]:
    return [{"prefix": p, "hash": cite_text(cites[p], p, depth)} for p in sorted(cites)]


# --------------------------------------------------------------------------- verify

def handle_verify(case: dict[str, Any]) -> dict[str, Any]:
    old_root = check_root(case.get("old_root"), "old_root", allow_empty=False)
    new_root = check_root(case.get("new_root"), "new_root", allow_empty=False)
    policy = parse_policy(case.get("policy"), "policy")
    check = check_dual(case.get("proof"), "proof", old_root, new_root, policy,
                       case.get("declared"))
    return {
        "ok": True,
        "command": "verify",
        "verified": True,
        "old_root": "sha256:" + old_root,
        "new_root": "sha256:" + new_root,
        "depth": check.proof.depth,
        "audited": len(check.rows),
        "changed": sum(1 for r in check.rows if r["kind"] != "unchanged"),
        "counts": check.counts,
        "keys": check.rows,
        "citations": render_cites(check.proof.cites, check.proof.depth),
        "policy": policy.as_dict(),
        "checks": {
            "citation_shape": "boundary citations exactly match the induced tree",
            "old_root": "recovered from audited leaves and shared branches",
            "new_root": "recovered from the same shared branches",
            "policy": "change direction and allowed prefix range",
            "declared": "audited key set and declared directions",
        },
    }


# --------------------------------------------------------------------------- merge

def merge_scenes(a: Scene, b: Scene, field: str) -> Scene:
    require(a.depth == b.depth, "KEY_DEPTH_MISMATCH", field,
            "proofs use different key depths")
    out = a.clone()
    for bits in sorted(b.leaves):
        out.merge_leaf(bits, b.leaves[bits], field)
    for prefix in sorted(b.cites):
        out.merge_cite(prefix, b.cites[prefix], field)
    return out


def merge_all(scenes: list[Scene], field: str) -> Scene:
    out = scenes[0].clone()
    for other in scenes[1:]:
        out = merge_scenes(out, other, field)
    return out


def canonical_merge(proofs: list[Any], old_root: str, new_root: str, field: str) -> Scene:
    """Union of proofs: shared leaves/branches must agree, then expand and re-check."""
    scene = merge_all([scene_of_dual_proof(p) for p in proofs], field)
    scene.expand_all(field)
    scene.check_root(0, old_root, field, "old")
    scene.check_root(1, new_root, field, "new")
    return scene


def handle_merge(case: dict[str, Any]) -> dict[str, Any]:
    old_root = check_root(case.get("old_root"), "old_root", allow_empty=False)
    new_root = check_root(case.get("new_root"), "new_root", allow_empty=False)
    policy = parse_policy(case.get("policy"), "policy")
    raw_proofs = expect_list(case.get("proofs"), "proofs")
    require(len(raw_proofs) >= 2, "MERGE_ARITY", "proofs",
            "merge needs at least two proofs over the same root pair")

    checks = [check_dual(raw, f"proofs[{i}]", old_root, new_root, policy)
              for i, raw in enumerate(raw_proofs)]
    proofs = [c.proof for c in checks]
    before = [len(p.cites) for p in proofs]

    scene = canonical_merge(proofs, old_root, new_root, "proofs")
    keys = sorted(scene.leaves)
    values: dict[str, tuple[str | None, str | None]] = {}
    for key in keys:
        for p in proofs:
            if key in p.values:
                values[key] = p.values[key]
                break

    merged = render_dual_proof(scene, keys, values)
    merged_proof = parse_proof(merged, "merged", DUAL_SIDES)
    check = scene_of_dual_proof(merged_proof)
    check.check_root(0, old_root, "merged", "old")
    check.check_root(1, new_root, "merged", "new")
    require(len(merged_proof.cites) == len(scene.boundary_cites(keys)),
            "NOT_MINIMAL", "merged.citations",
            "the merged proof carries more citations than the union boundary needs")

    # Order independence: the merge is commutative, including tie-free output.
    reverse = merge_all([scene_of_dual_proof(p) for p in reversed(proofs)], "proofs")
    reverse.expand_all("proofs")
    require(reverse.roots() == scene.roots(), "MERGE_ORDER_DEPENDENT", "proofs",
            "merging in the opposite order produced a different root pair")

    rows = [key_row(k, values[k][0], values[k][1]) for k in keys]
    return {
        "ok": True,
        "command": "merge",
        "verified": True,
        "old_root": "sha256:" + old_root,
        "new_root": "sha256:" + new_root,
        "depth": scene.depth,
        "inputs": [
            {"audited": len(c.rows), "citations": len(c.proof.cites), "counts": c.counts}
            for c in checks
        ],
        "merged": {
            "audited": len(keys),
            "citations": len(merged_proof.cites),
            "citations_before": sum(before),
            "counts": kind_counts(r["kind"] for r in rows),
        },
        "keys": rows,
        "proof": merged,
        "checks": {
            "inputs": "each proof verified independently against the trusted roots",
            "overlap": "overlapping leaves agree",
            "expansion": "expandable branch digests match the expanded subtree",
            "minimal": "citation set equals the union induced-tree boundary",
            "order": "merge is independent of proof order",
        },
    }


# --------------------------------------------------------------------------- proof-rebase

def handle_proof_rebase(case: dict[str, Any]) -> dict[str, Any]:
    from .rebase import Hop, run_rebase

    inventory = expect_object(case.get("inventory"), "inventory", "inventory")
    inv_root = check_root(inventory.get("root"), "inventory.root", allow_empty=False)
    s_keys = parse_key_list(case["s_keys"], "s_keys") if "s_keys" in case else None
    chain_raw = expect_list(case.get("chain"), "chain")
    require(chain_raw, "EMPTY_CHAIN", "chain", "the change chain must have at least one hop")

    # Pass 1 -- shallow: roots, versions and continuity are validated before any
    # proof is expanded, so a broken chain is reported as such.
    shallow = []
    for i, item in enumerate(chain_raw):
        path = f"chain[{i}]"
        hop_raw = expect_object(item, path, "hop")
        shallow.append({
            "path": path,
            "old": check_root(hop_raw.get("old_root"), path + ".old_root", allow_empty=False),
            "new": check_root(hop_raw.get("new_root"), path + ".new_root", allow_empty=False),
            "version": expect_int(hop_raw["version"], path + ".version", minimum=1)
            if "version" in hop_raw else i + 1,
            "depth": expect_int(hop_raw["depth"], path + ".depth", minimum=1)
            if "depth" in hop_raw else None,
            "raw": hop_raw,
        })
    for i, hop in enumerate(shallow):
        if i == 0:
            require(hop["old"] == inv_root, "CHAIN_BROKEN", hop["path"] + ".old_root",
                    "the chain does not start at the inventory root")
        else:
            require(hop["old"] == shallow[i - 1]["new"], "CHAIN_BROKEN",
                    hop["path"] + ".old_root",
                    "the hop does not continue from the previous hop's new root")
            require(hop["version"] > shallow[i - 1]["version"], "VERSION_ORDER",
                    hop["path"] + ".version",
                    f"hop version {hop['version']} does not follow "
                    f"{shallow[i - 1]['version']}")

    # Pass 2 -- each hop's proof is verified independently against its own roots.
    hops: list[Hop] = []
    depth: int | None = None
    for i, hop in enumerate(shallow):
        if hop["depth"] is not None:
            depth = hop["depth"]
        policy = parse_policy(hop["raw"].get("policy"), hop["path"] + ".policy")
        check = check_dual(hop["raw"].get("proof"), hop["path"] + ".proof",
                           hop["old"], hop["new"], policy, hop["raw"].get("declared"),
                           depth=depth)
        if depth is None:
            depth = check.proof.depth
        hops.append(Hop(index=i + 1, version=hop["version"], old_root=hop["old"],
                        new_root=hop["new"], proof=check.proof, policy=policy,
                        path=hop["path"], report=check))

    inv_proof, _ = check_value(inventory.get("proof"), "inventory.proof", inv_root, s_keys)
    if depth is not None:
        require(inv_proof.depth == depth, "KEY_DEPTH_MISMATCH", "inventory.proof.leaves",
                f"the inventory proof has depth {inv_proof.depth}, the chain uses {depth}")

    result = run_rebase(inv_root, inv_proof, s_keys, hops)

    return {
        "ok": True,
        "command": "proof-rebase",
        "verified": True,
        "inventory_root": "sha256:" + inv_root,
        "final_root": "sha256:" + result.final_root,
        "depth": result.depth,
        "hops": result.hops,
        "audited": len(result.rows),
        "audited_changed": sum(1 for r in result.rows if r["changed"]),
        "disclosed_keys": len(result.touched | set(inv_proof.keys)),
        "untouched": sorted(set(inv_proof.keys) - result.touched),
        "keys": result.rows,
        "proof": result.proof,
        "checks": {
            "chain": "roots are continuous and hop versions strictly ascend",
            "hops": "each hop verified independently against its own root pair and policy",
            "shared_evidence": "a value or branch digest bound twice is checked twice",
            "replacement": "only the branches named by T are replaced per hop",
            "carried_root": "after every hop the carried S scene reproduces that hop's new root",
            "final": "the projected minimal proof recovers the final root",
        },
    }


# --------------------------------------------------------------------------- split-verify

def handle_split_verify(case: dict[str, Any]) -> dict[str, Any]:
    old_root = check_root(case.get("old_root"), "old_root", allow_empty=False)
    new_root = check_root(case.get("new_root"), "new_root", allow_empty=False)
    full = check_dual(case.get("proof"), "proof", old_root, new_root,
                      parse_policy(None, "policy"))
    proof = full.proof
    shards_raw = expect_list(case.get("shards"), "shards")
    require(shards_raw, "NO_SHARDS", "shards", "at least one evidence shard is required")

    shards = []
    for i, item in enumerate(shards_raw):
        path = f"shards[{i}]"
        shard = expect_object(item, path, "shard")
        shard_id = expect_str(shard.get("shard_id"), path + ".shard_id")
        # A shard may bind the roots itself; if it omits them it inherits the
        # request's pair, and the shape check below is what rejects a bad shard.
        bound_old = check_root(shard.get("old_root"), path + ".old_root", allow_empty=False) \
            if "old_root" in shard else old_root
        bound_new = check_root(shard.get("new_root"), path + ".new_root", allow_empty=False) \
            if "new_root" in shard else new_root
        require(bound_old == old_root and bound_new == new_root, "SHARD_ROOT_MISMATCH", path,
                "the shard is bound to a different root pair than the requested one")
        cites = []
        seen: set[str] = set()
        for j, raw_cite in enumerate(expect_list(shard.get("citations"), path + ".citations")):
            cpath = f"{path}.citations[{j}]"
            cite = expect_object(raw_cite, cpath, "citation")
            prefix = expect_str(cite.get("prefix"), cpath + ".prefix", allow_empty=True)
            require(prefix not in seen, "DUP_CITE", cpath + ".prefix",
                    f"prefix {prefix} appears twice inside one shard")
            seen.add(prefix)
            digest = parse_cite_text(expect_str(cite.get("hash"), cpath + ".hash"),
                                     prefix, proof.depth)
            cites.append((prefix, digest, cpath))
        stems = sorted(cites)
        for a, (pa, _, _) in enumerate(stems):
            for pb, _, _ in stems[a + 1:]:
                if pb.startswith(pa):
                    raise ArchiveError("PARENT_CHILD_OVERLAP", path + ".citations",
                                       f"one shard nests citations {pa} and {pb}")
        shards.append({"id": shard_id, "cites": cites, "path": path, "index": i})

    shards.sort(key=lambda s: (s["id"], s["index"]))
    expected = dict(proof.cites)
    merged: dict[str, str] = {}
    providers: dict[str, list[str]] = {}
    extras: list[tuple[str, str]] = []
    conflicts: list[tuple[str, str]] = []
    for shard in shards:
        for prefix, digest, cpath in shard["cites"]:
            providers.setdefault(prefix, []).append(shard["id"])
            if prefix not in expected:
                extras.append((prefix, cpath))
                continue
            if prefix in merged:
                if merged[prefix] != digest:
                    conflicts.append((prefix, cpath))
                continue
            merged[prefix] = digest

    if extras:
        prefix, cpath = min(extras)
        raise ArchiveError("EXTRA_SHARD_PREFIX", cpath,
                           f"shard evidence for prefix {prefix} is not part of the proof")
    if conflicts:
        prefix, cpath = min(conflicts)
        raise ArchiveError("SHARD_CONFLICT", cpath,
                           f"shards disagree about prefix {prefix}")
    missing = [p for p in expected if p not in merged]
    if missing:
        raise ArchiveError("MISSING_SHARD", "shards",
                           f"no evidence shard provides prefix {min(missing)}")

    # Roots are recovered only after the complete evidence set is assembled.
    scene = Scene(proof.depth, 2)
    for key in proof.keys:
        scene.add_leaf(key, [value_hash(proof.values[key][0]), value_hash(proof.values[key][1])])
    for prefix, digest in sorted(merged.items()):
        scene.add_cite(prefix, digest)
    scene.check_root(0, old_root, "shards", "old")
    scene.check_root(1, new_root, "shards", "new")

    return {
        "ok": True,
        "command": "split-verify",
        "verified": True,
        "old_root": "sha256:" + old_root,
        "new_root": "sha256:" + new_root,
        "depth": proof.depth,
        "audited": len(proof.keys),
        "shards": [{"shard_id": s["id"], "citations": len(s["cites"])} for s in shards],
        "evidence": {
            "citations": len(merged),
            "shared": sum(1 for ids in providers.values() if len(ids) > 1),
            "assembled": True,
        },
        "checks": {
            "shape": "each shard's citations are well formed and non-nested",
            "binding": "each shard is bound to the requested root pair",
            "coverage": "every proof citation arrives exactly once; repeats must agree",
            "ordering": "shard arrival order does not matter",
            "roots": "roots are recovered only after the evidence set is complete",
        },
    }
