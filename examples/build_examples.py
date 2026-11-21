"""Regenerate every fixture under ``examples/`` from complete small trees.

The manifests here are tiny (depth 4–6) so this script can hash the *entire* tree
with :mod:`solution.refimpl` and thereby cross-check the sparse production code
against an independent full computation.  All data is fictional.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from solution import refimpl  # noqa: E402
from solution.core import boundary  # noqa: E402


def write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def fmt(mapping, depth):
    return refimpl.fmt_root(mapping, depth)


def checkpoint(cid, mapping, generation, policy_version=1, depth=4, label=""):
    return {"checkpoint_id": cid, "root": fmt(mapping, depth), "generation": generation,
            "policy_version": policy_version, "label": label}


def edge(eid, old, new, old_cp, new_cp, generation, depth=4, keys=None,
         categories=("privacy",), archive_use="cold-archive", policy=None):
    keys = keys or sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
    proof = refimpl.dual_proof(old, new, keys, depth)
    return {"edge_id": eid, "from": old_cp, "to": new_cp, "generation": generation,
            "policy_version": 1, "archive_use": archive_use, "proof": proof,
            "kept_branches": [c["prefix"] for c in proof["citations"]],
            "categories": list(categories),
            "policy": policy or {"allowed_prefixes": ["0", "1"]}}


def vote(vid, eid, old, new, reviewer, institution, depth=4, category="privacy",
         issued_at=0, expires_at=10_000):
    return {"vote_id": vid, "edge_id": eid, "category": category,
            "reviewer_id": reviewer, "institution_id": institution,
            "policy_version": 1, "old_root": fmt(old, depth),
            "new_root": fmt(new, depth), "issued_at": issued_at,
            "expires_at": expires_at}


# --------------------------------------------------------------------------- verify

def build_verify() -> None:
    depth = 4
    old = {"0001": "alpha", "0010": "", "0110": "gamma", "1001": "kept"}
    new = {"0001": "alpha", "0010": None, "0110": "gamma2", "1100": "fresh",
           "1001": "kept"}
    audited = ["0001", "0010", "0110", "1100", "1001"]
    case = {
        "note": "absent vs empty-string vs insert: 0010 is deleted, 1100 inserted",
        "old_root": fmt(old, depth),
        "new_root": fmt(new, depth),
        "policy": {"allowed_prefixes": ["0001", "001", "011", "11", "100"]},
        "declared": [
            {"key": "0001", "kind": "unchanged"},
            {"key": "0010", "kind": "delete"},
            {"key": "0110", "kind": "update"},
            {"key": "1100", "kind": "insert"},
            {"key": "1001", "kind": "unchanged"},
        ],
        "proof": refimpl.dual_proof(old, new, audited, depth),
    }
    write(HERE / "verify" / "case.json", case)


# --------------------------------------------------------------------------- merge

def build_merge() -> None:
    depth = 5
    old = {"00010": "a", "01000": "x", "01010": "y", "10000": "q"}
    new = {"00010": "A", "01000": "x", "01010": "y", "10000": "q"}
    left = refimpl.dual_proof(old, new, ["00010", "01000"], depth)
    right = refimpl.dual_proof(old, new, ["00010", "01010"], depth)
    union = ["00010", "01000", "01010"]
    case = {
        "note": "left cites the whole 0100/0101 region; right expands it",
        "old_root": fmt(old, depth),
        "new_root": fmt(new, depth),
        "policy": {"allowed_prefixes": ["0001"]},
        "proofs": [left, right],
        "expected_union_boundary": boundary(union),
    }
    write(HERE / "merge" / "case.json", case)


# --------------------------------------------------------------------------- proof-rebase

def build_rebase() -> None:
    depth = 6
    a = {"000100": "a", "010000": "x", "010100": "y", "100000": "p"}
    b = refimpl.apply_patch(a, {"000100": "A", "010000": "x2"})
    c = refimpl.apply_patch(b, {"010000": "x3", "010100": "Y"})
    d = refimpl.apply_patch(c, {"000100": "a"})  # back to the original digest
    s = ["000100", "010000", "100000"]
    chain = []
    for i, (old, new) in enumerate([(a, b), (b, c), (c, d)], start=1):
        keys = sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
        chain.append({"version": i, "old_root": fmt(old, depth),
                      "new_root": fmt(new, depth),
                      "policy": {"allowed_prefixes": ["0", "1"]},
                      "proof": refimpl.dual_proof(old, new, keys, depth)})
    case = {
        "note": "000100 is overwritten twice and returns to its old value; "
                "100000 is untouched; 010000 is overwritten in two hops",
        "inventory": {"root": fmt(a, depth), "proof": refimpl.value_proof(a, s, depth)},
        "s_keys": s,
        "chain": chain,
    }
    write(HERE / "proof-rebase" / "case.json", case)


# --------------------------------------------------------------------------- split-verify

def build_split_verify() -> None:
    depth = 6
    old = {"000100": "a", "010000": "x", "100000": "z"}
    new = {"000100": "A", "010000": "X", "100000": "z"}
    proof = refimpl.dual_proof(old, new, ["000100", "010000"], depth)
    cites = proof["citations"]
    shards = [
        {"shard_id": "third", "old_root": fmt(old, depth), "new_root": fmt(new, depth),
         "citations": cites[2::3]},
        {"shard_id": "first", "old_root": fmt(old, depth), "new_root": fmt(new, depth),
         "citations": cites[0::3]},
        {"shard_id": "second", "old_root": fmt(old, depth), "new_root": fmt(new, depth),
         "citations": cites[1::3]},
    ]
    case = {
        "note": "shards arrive shuffled; each is bound to the same root pair",
        "old_root": fmt(old, depth),
        "new_root": fmt(new, depth),
        "proof": proof,
        "shards": shards,
    }
    write(HERE / "split-verify" / "case.json", case)


# --------------------------------------------------------------------------- ledger

def build_ledger() -> None:
    depth = 4
    a = {"0001": "alpha", "0010": "beta", "0100": "gamma"}
    b = refimpl.apply_patch(a, {"0001": "ALPHA"})
    c = refimpl.apply_patch(b, {"0100": "GAMMA"})
    s = ["0001", "0100"]

    ingest = {
        "checkpoints": [checkpoint("cp-A", a, 10), checkpoint("cp-B", b, 11),
                        checkpoint("cp-C", c, 12)],
        "edges": [edge("e1", a, b, "cp-A", "cp-B", 11),
                  edge("e2", b, c, "cp-B", "cp-C", 12)],
        "votes": [vote("v1", "e1", a, b, "alice", "inst-1"),
                  vote("v2", "e1", a, b, "bob", "inst-2"),
                  vote("v3", "e2", b, c, "carol", "inst-3"),
                  vote("v4", "e2", b, c, "dave", "inst-4")],
        "institutions": [{"subject": "alice", "institution_id": "inst-1"},
                         {"subject": "bob", "institution_id": "inst-2"},
                         {"subject": "carol", "institution_id": "inst-3"},
                         {"subject": "dave", "institution_id": "inst-4"}],
    }
    request = {
        "start_checkpoint": "cp-A", "end_checkpoint": "cp-C", "policy_version": 1,
        "logical_clock": 5, "archive_use": "cold-archive", "s_keys": s,
        "inventory": {"root": fmt(a, depth), "proof": refimpl.value_proof(a, s, depth)},
    }
    publish = dict(request)
    publish["request_id"] = "pub-0001"
    publish["plan"] = {
        "edge_ids": ["e1", "e2"],
        "votes": [{"hop": 1, "category": "privacy", "vote_id": "v1"},
                  {"hop": 1, "category": "privacy", "vote_id": "v2"},
                  {"hop": 2, "category": "privacy", "vote_id": "v3"},
                  {"hop": 2, "category": "privacy", "vote_id": "v4"}],
    }
    write(HERE / "ledger" / "ingest.json", ingest)
    write(HERE / "ledger" / "plan.json", request)
    write(HERE / "ledger" / "publish.json", publish)
    write(HERE / "ledger" / "view.json", {"commit_seq": 1})
    write(HERE / "ledger" / "revoke.json", {"vote_id": "v4",
                                           "reason": "reviewer recused after the fact"})
    write(HERE / "ledger" / "status.json", {})
    db = HERE / "ledger" / "ledger.sqlite"
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(db) + suffix)
        if candidate.exists():
            candidate.unlink()


def main() -> int:
    if (HERE / "ledger").exists():
        shutil.rmtree(HERE / "ledger")
    build_verify()
    build_merge()
    build_rebase()
    build_split_verify()
    build_ledger()
    print("examples regenerated under", HERE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
