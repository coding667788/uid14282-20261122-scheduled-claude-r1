"""Publication, revocation, historical views and ledger status.

``publish`` is a single ``BEGIN IMMEDIATE`` transaction that re-validates the
whole plan against committed state before writing anything:

* the start checkpoint is the end of the latest receipt (and carries the
  inventory root),
* every selected edge is verified, contiguous, and registered under the pinned
  policy version,
* the fragment-set hash of the selected edges matches what was committed,
* every vote is verified, unrevoked, unconsumed, inside its validity window and
  bound to this edge / root pair / policy version / category,
* the submitted votes form a legal global assignment (no vote or review subject
  twice, two institutions per category slot),
* the inventory proof still rebases to the end checkpoint root.

Only then are the votes consumed and the receipt, plan, proof and projection
written.  Retrying the same ``request_id`` with identical content returns the
original receipt; different content is refused.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Sequence

from . import store
from .core import (
    canonical,
    checksum,
    err,
    expect_int,
    expect_list,
    expect_object,
    expect_str,
    parse_proof,
    require,
)
from .ledger_model import World
from .ledger import _request, plan_publication, rebase_path

DUAL_SIDES = ("old_value", "new_value")


# --------------------------------------------------------------------------- helpers

def _now() -> float:
    return time.time()


def _latest_receipt(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute("SELECT receipt FROM publications ORDER BY commit_seq DESC LIMIT 1") \
        .fetchone()
    return json.loads(row[0]) if row else None


def _parse_plan(raw: Any) -> dict[str, Any]:
    obj = expect_object(raw, "plan", "plan")
    edge_ids = [expect_str(e, f"plan.edge_ids[{i}]")
                for i, e in enumerate(expect_list(obj.get("edge_ids"), "plan.edge_ids"))]
    require(edge_ids, "EMPTY_PLAN", "plan.edge_ids", "the plan must select at least one edge")
    votes = []
    for i, item in enumerate(expect_list(obj.get("votes", []), "plan.votes")):
        path = f"plan.votes[{i}]"
        entry = expect_object(item, path, "vote reference")
        votes.append({
            "hop": expect_int(entry.get("hop"), path + ".hop", minimum=1),
            "category": expect_str(entry.get("category"), path + ".category"),
            "vote_id": expect_str(entry.get("vote_id"), path + ".vote_id"),
        })
    votes.sort(key=lambda v: (v["hop"], v["category"], v["vote_id"]))
    declared = obj.get("fragments_hash")
    return {"edge_ids": edge_ids, "votes": votes,
            "fragments_hash": expect_str(declared, "plan.fragments_hash")
            if declared is not None else None}


def _fragments_hash(conn: sqlite3.Connection, edge_ids: Sequence[str]) -> str:
    hashes = []
    for edge_id in edge_ids:
        row = conn.execute("SELECT fragments_hash FROM edges WHERE edge_id = ?",
                           (edge_id,)).fetchone()
        hashes.append({"edge_id": edge_id, "fragments_hash": row[0] if row else ""})
    return checksum(hashes)


def _assignment(world: World, votes: Sequence[dict[str, Any]]) -> list[tuple[int, str, str, str]]:
    return [(v["hop"], v["category"], v["vote_id"],
             world.subject(world.votes[v["vote_id"]].reviewer_id))
            for v in votes]


def check_global_assignment(world: World, hops: Sequence[Any],
                            votes: Sequence[dict[str, Any]]) -> None:
    """One vote and one review subject per request; two institutions per slot."""
    used_votes: set[str] = set()
    used_subjects: set[str] = set()
    per_slot: dict[tuple[int, str], list[str]] = {}
    for vote_ref in votes:
        vote_id = vote_ref["vote_id"]
        hop, category = vote_ref["hop"], vote_ref["category"]
        require(1 <= hop <= len(hops), "VOTE_HOP_OUT_OF_RANGE", "plan.votes",
                f"vote {vote_id} names hop {hop} outside the plan")
        vote = world.votes.get(vote_id)
        if vote is None:
            raise err("VOTE_NOT_VERIFIED", "plan.votes",
                      f"vote {vote_id} is not a verified vote")
        subject = world.subject(vote.reviewer_id)
        require(vote_id not in used_votes, "VOTE_REUSED", "plan.votes",
                f"vote {vote_id} appears twice in one request")
        require(subject not in used_subjects, "REVIEWER_REUSED", "plan.votes",
                f"review subject {subject} signs twice in one request (alias-resolved)")
        used_votes.add(vote_id)
        used_subjects.add(subject)
        per_slot.setdefault((hop, category), []).append(vote_id)
    for (hop, category), ids in sorted(per_slot.items()):
        require(len(ids) == 2, "VOTE_COVERAGE", "plan.votes",
                f"hop {hop} category {category} needs exactly two votes, got {len(ids)}")
        institutions = {world.institution_of(world.votes[v]) for v in ids}
        require(len(institutions) == 2, "INSTITUTION_CONFLICT", "plan.votes",
                f"hop {hop} category {category} needs two distinct institutions")
    for hop, edge in enumerate(hops, start=1):
        for category in edge.categories:
            require((hop, category) in per_slot, "VOTE_COVERAGE", "plan.votes",
                    f"hop {hop} category {category} has no review votes")


def _check_vote_binding(world: World, hop_index: int, hop, vote_ref: dict[str, Any],
                        req: dict[str, Any]) -> None:
    vote_id = vote_ref["vote_id"]
    vote = world.votes[vote_id]
    if vote_id in world.revoked:
        raise err("VOTE_REVOKED", "plan.votes",
                  f"vote {vote_id} was revoked before this publication could commit")
    if vote_id in world.consumed:
        raise err("VOTE_CONSUMED", "plan.votes",
                  f"vote {vote_id} was already consumed by publication "
                  f"{world.consumed[vote_id]}")
    require(vote.valid_at(req["clock"]), "VOTE_EXPIRED", "plan.votes",
            f"vote {vote_id} is outside its logical validity window")
    require(vote.edge_id == hop.edge_id, "VOTE_EDGE_MISMATCH", "plan.votes",
            f"vote {vote_id} is bound to edge {vote.edge_id}, not {hop.edge_id}")
    require(vote.category == vote_ref["category"], "VOTE_CATEGORY_MISMATCH", "plan.votes",
            f"vote {vote_id} covers {vote.category}, not {vote_ref['category']}")
    require(vote.policy_version == req["policy_version"], "POLICY_GENERATION", "plan.votes",
            f"vote {vote_id} was issued under policy version {vote.policy_version}, "
            f"the request pins {req['policy_version']}")
    from_root = world.checkpoints[hop.from_id].root
    to_root = world.checkpoints[hop.to_id].root
    require(vote.old_root == from_root and vote.new_root == to_root,
            "VOTE_ROOT_MISMATCH", "plan.votes",
            f"vote {vote_id} is bound to a different root pair")


# --------------------------------------------------------------------------- publish

def handle_publish(case: dict[str, Any], db: str | None) -> dict[str, Any]:
    conn = store.connect(db)  # type: ignore[arg-type]
    try:
        request_id = expect_str(case.get("request_id"), "request_id")
        request_hash = checksum(case)
        # Rendezvous before the write lock: lets a test align two contenders so they
        # really do race for the same lock rather than starting at arbitrary times.
        store.sync_point("publish:before-begin")

        with store.write_tx(conn):
            prior = conn.execute("SELECT request_hash, receipt FROM publications "
                                 "WHERE request_id = ?", (request_id,)).fetchone()
            if prior is not None:
                if prior[0] != request_hash:
                    raise err("IDEMPOTENCY_CONFLICT", "request_id",
                              f"request {request_id} is already committed with different "
                              f"content")
                return {"ok": True, "command": "ledger-publish", "verified": True,
                        "idempotent": True, "receipt": json.loads(prior[1])}

            req = _request(case)
            world = store.load_world(conn)
            world.fragments = {eid: h for eid, h in conn.execute(
                "SELECT edge_id, fragments_hash FROM edges WHERE status = 'verified'")}

            start_cp = world.checkpoints.get(req["start"])
            if start_cp is None:
                raise err("START_NOT_REGISTERED", "start_checkpoint",
                          f"checkpoint {req['start']} is not registered")
            require(start_cp.root == req["inv_root"], "START_ROOT_MISMATCH", "inventory.root",
                    f"the inventory proof is rooted at sha256:{req['inv_root']} but checkpoint "
                    f"{req['start']} carries sha256:{start_cp.root}")
            latest = _latest_receipt(conn)
            if latest is not None:
                require(latest["end_checkpoint"] == req["start"], "START_NOT_CURRENT",
                        "start_checkpoint",
                        f"the last committed receipt ends at {latest['end_checkpoint']}; a "
                        f"request must start at the previous receipt, not at "
                        f"{req['start']} (equal roots do not let a request skip a checkpoint)")

            # --- the plan itself, exactly as the planner would have produced it.
            if case.get("plan") is not None:
                plan = _parse_plan(case.get("plan"))
            else:
                result = plan_publication(world, req)
                plan = {"edge_ids": result["plan"]["edge_ids"],
                        "votes": result["plan"]["votes"],
                        "fragments_hash": result["plan"]["fragments_hash"]}
                plan["votes"] = [{"hop": v["hop"], "category": v["category"],
                                  "vote_id": v["vote_id"]} for v in plan["votes"]]

            hops = []
            node = req["start"]
            for i, edge_id in enumerate(plan["edge_ids"]):
                edge = world.edges.get(edge_id)
                if edge is None:
                    raise err("EDGE_NOT_VERIFIED", f"plan.edge_ids[{i}]",
                              f"edge {edge_id} is not a verified edge")
                if edge.from_id != node:
                    raise err("STRUCTURE_BROKEN", f"plan.edge_ids[{i}]",
                              f"edge {edge_id} starts at {edge.from_id}, not at {node}")
                if edge.policy_version != req["policy_version"]:
                    raise err("POLICY_GENERATION", f"plan.edge_ids[{i}]",
                              f"edge {edge_id} belongs to policy version "
                              f"{edge.policy_version}, the request pins "
                              f"{req['policy_version']}")
                hops.append(edge)
                node = edge.to_id
            if node != req["end"]:
                raise err("STRUCTURE_BROKEN", "plan.edge_ids",
                          f"the plan ends at {node}, not at the requested checkpoint "
                          f"{req['end']}")

            computed_fragments = _fragments_hash(conn, plan["edge_ids"])
            if plan["fragments_hash"] is not None:
                require(plan["fragments_hash"] == computed_fragments,
                        "FRAGMENT_SET_MISMATCH", "plan.fragments_hash",
                        "the committed fragment set of the selected edges does not hash "
                        "to the value the plan pinned")
            for i, edge in enumerate(hops):
                require(world.fragments.get(edge.edge_id), "FRAGMENT_SET_MISSING",
                        f"plan.edge_ids[{i}]",
                        f"edge {edge.edge_id} has no committed fragment-set hash")

            for vote_ref in plan["votes"]:
                hop = hops[vote_ref["hop"] - 1]
                _check_vote_binding(world, vote_ref["hop"], hop, vote_ref, req)
            check_global_assignment(world, hops, plan["votes"])

            inv_proof = parse_proof(req["inventory"].get("proof"), "inventory.proof",
                                    ("value",))
            rebase = rebase_path(world, hops, inv_proof, req)
            end_root = world.checkpoints[req["end"]].root
            require(rebase.final_root == end_root, "FINAL_ROOT_MISMATCH", "end_checkpoint",
                    "the rebased projection does not reach the end checkpoint root")

            store.sync_point("publish:before-commit")

            commit_seq = store.next_commit_seq(conn)
            consumed = sorted({v["vote_id"] for v in plan["votes"]})
            for vote_id in consumed:
                conn.execute("INSERT INTO consumption(vote_id, commit_seq, request_id) "
                             "VALUES(?, ?, ?)", (vote_id, commit_seq, request_id))

            receipt = {
                "receipt_id": f"rcpt-{commit_seq:06d}",
                "commit_seq": commit_seq,
                "request_id": request_id,
                "start_checkpoint": req["start"],
                "end_checkpoint": req["end"],
                "root": "sha256:" + rebase.final_root,
                "policy_version": req["policy_version"],
                "logical_clock": req["clock"],
                "edge_ids": plan["edge_ids"],
                "hops": len(plan["edge_ids"]),
                "votes": plan["votes"],
                "consumed_votes": consumed,
                "fragments_hash": computed_fragments,
                "disclosed_keys": len(set().union(
                    *(set(h.disclosed_keys()) for h in hops))),
            }
            snapshot = {
                "proof": rebase.proof,
                "rows": rebase.rows,
                "root": rebase.final_root,
            }
            conn.execute(
                "INSERT INTO publications(request_id, request_hash, start_checkpoint, "
                "end_checkpoint, root, policy_version, plan, proof, receipt) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (request_id, request_hash, req["start"], req["end"], rebase.final_root,
                 req["policy_version"], canonical(plan), canonical(snapshot),
                 canonical(receipt)))
            store.audit(conn, "publish", receipt)

        store.sync_point("publish:after-commit")
        return {"ok": True, "command": "ledger-publish", "verified": True,
                "idempotent": False, "receipt": receipt,
                "projection": rebase.proof, "keys": rebase.rows}
    finally:
        conn.close()


# --------------------------------------------------------------------------- revoke

def handle_revoke(case: dict[str, Any], db: str | None) -> dict[str, Any]:
    conn = store.connect(db)  # type: ignore[arg-type]
    try:
        vote_id = expect_str(case.get("vote_id"), "vote_id")
        reason = expect_str(case.get("reason", ""), "reason", allow_empty=True)
        store.sync_point("revoke:before-begin")
        with store.write_tx(conn):
            row = conn.execute("SELECT status FROM votes WHERE vote_id = ?",
                               (vote_id,)).fetchone()
            if row is None:
                raise err("UNKNOWN_VOTE", "vote_id", f"cannot revoke unknown vote {vote_id}")
            existing = conn.execute("SELECT commit_seq, reason FROM revocations "
                                    "WHERE vote_id = ?", (vote_id,)).fetchone()
            if existing is not None:
                return {"ok": True, "command": "ledger-revoke", "verified": True,
                        "idempotent": True,
                        "revocation": {"vote_id": vote_id, "commit_seq": existing[0],
                                       "reason": existing[1]}}
            store.sync_point("revoke:before-commit")
            commit_seq = store.next_commit_seq(conn)
            conn.execute("INSERT INTO revocations(vote_id, revoked_at, reason, commit_seq) "
                         "VALUES(?, ?, ?, ?)", (vote_id, _now(), reason, commit_seq))
            consumed = conn.execute("SELECT request_id, commit_seq FROM consumption "
                                    "WHERE vote_id = ?", (vote_id,)).fetchone()
            store.audit(conn, "revoke", {"vote_id": vote_id, "commit_seq": commit_seq})
        return {
            "ok": True, "command": "ledger-revoke", "verified": True, "idempotent": False,
            "revocation": {"vote_id": vote_id, "commit_seq": commit_seq, "reason": reason},
            "note": "historical publication snapshots are unchanged; the revocation only "
                    "blocks future use of the vote",
            "consumed_by": consumed[0] if consumed else None,
        }
    finally:
        conn.close()


# --------------------------------------------------------------------------- view

def handle_view(case: dict[str, Any], db: str | None) -> dict[str, Any]:
    conn = store.connect(db)  # type: ignore[arg-type]
    try:
        with store.read_tx(conn):
            commit_seq = case.get("commit_seq")
            if commit_seq is None:
                row = conn.execute(
                    "SELECT commit_seq, receipt, proof, plan, root, policy_version, "
                    "start_checkpoint, end_checkpoint, request_id FROM publications "
                    "ORDER BY commit_seq DESC LIMIT 1").fetchone()
            else:
                row = conn.execute(
                    "SELECT commit_seq, receipt, proof, plan, root, policy_version, "
                    "start_checkpoint, end_checkpoint, request_id FROM publications "
                    "WHERE commit_seq = ?",
                    (expect_int(commit_seq, "commit_seq", minimum=1),)).fetchone()
            if row is None:
                raise err("NO_SUCH_COMMIT", "commit_seq", "no publication with that commit number")
            snapshot = json.loads(row[2])
            return {
                "ok": True,
                "command": "ledger-view",
                "verified": True,
                "commit_seq": row[0],
                "receipt": json.loads(row[1]),
                "root": "sha256:" + row[4],
                "policy_version": row[5],
                "start_checkpoint": row[6],
                "end_checkpoint": row[7],
                "request_id": row[8],
                "plan": json.loads(row[3]),
                "proof": snapshot["proof"],
                "keys": snapshot["rows"],
                "immutable": "committed snapshots are replayed by commit number and are not "
                             "changed by later revocations",
            }
    finally:
        conn.close()


# --------------------------------------------------------------------------- status

def handle_status(case: dict[str, Any], db: str | None) -> dict[str, Any]:
    conn = store.connect(db)  # type: ignore[arg-type]
    try:
        with store.read_tx(conn):
            world = store.load_world(conn)
            staged_world = store.load_world(conn, include_staged=True)
            rows = conn.execute("SELECT status, reason, COUNT(*) FROM edges "
                                "GROUP BY status, reason ORDER BY status, reason").fetchall()
            return {
                "ok": True,
                "command": "ledger-status",
                "verified": True,
                "commit_seq": int(store.meta_get(conn, "commit_seq", "0")),
                "checkpoints": len(world.checkpoints),
                "edges": len(world.edges),
                "votes": len(world.votes),
                "revoked": sorted(world.revoked),
                "consumed": sorted(world.consumed),
                "edge_states": [{"status": s, "reason": r, "count": c} for s, r, c in rows],
                "publications": conn.execute("SELECT COUNT(*) FROM publications").fetchone()[0],
                "staged_edges": sorted(set(staged_world.edges) - set(world.edges)),
            }
    finally:
        conn.close()
