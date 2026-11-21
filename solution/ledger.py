"""Ledger commands: ingest, plan, publish, view, revoke, status.

Ingestion accepts out-of-order evidence on two channels -- checkpoints plus
fragment sets of two-root edge proofs, and review votes plus revocations.  A
batch is applied in one write transaction, so a crash leaves the previous state
untouched; an edge is only ``verified`` once *all* its fragments arrived and the
assembled proof reproduces the bound root pair.  Nothing half-arrived can ever be
queried as a verified edge or contribute a root to a plan.

Planning is global, not greedy: candidate paths are ordered by the exact objective
(``disclosed keys``, then ``hops``, then edge-id sequence, then the sorted
``(hop, category, vote_id)`` list) and the first path with a conflict-free global
vote assignment and a successful rebase wins.  Two partial plans that reach the
same checkpoint with different consumed vote sets are never merged -- the search
enumerates whole paths, so such states simply stay distinct.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Sequence

from . import store
from .core import (
    ArchiveError,
    canonical,
    change_kind,
    check_key,
    check_root,
    checksum,
    err,
    expect_int,
    expect_list,
    expect_object,
    expect_str,
    parse_policy,
    parse_proof,
    require,
)
from .ledger_model import Checkpoint, Edge, Plan, Vote, World
from .merkle import Scene, scene_of_dual_proof
from .rebase import Hop, run_rebase

DUAL_SIDES = ("old_value", "new_value")


# --------------------------------------------------------------------------- parsing

def _checkpoint(raw: Any, field: str) -> Checkpoint:
    obj = expect_object(raw, field, "checkpoint")
    cid = expect_str(obj.get("checkpoint_id"), field + ".checkpoint_id")
    root = check_root(obj.get("root"), field + ".root", allow_empty=False)
    generation = expect_int(obj.get("generation", 0), field + ".generation", minimum=0)
    policy_version = expect_int(obj.get("policy_version", 1), field + ".policy_version", minimum=1)
    label = obj.get("label", "")
    require(isinstance(label, str), "BAD_FIELD", field + ".label", "label must be a string")
    return Checkpoint(cid, root, generation, label, policy_version)


def _edge(raw: Any, field: str) -> Edge:
    obj = expect_object(raw, field, "edge")
    return Edge(
        edge_id=expect_str(obj.get("edge_id"), field + ".edge_id"),
        from_id=expect_str(obj.get("from"), field + ".from"),
        to_id=expect_str(obj.get("to"), field + ".to"),
        generation=expect_int(obj.get("generation"), field + ".generation", minimum=0),
        policy_version=expect_int(obj.get("policy_version"), field + ".policy_version", minimum=1),
        proof=obj.get("proof") or {"leaves": [], "citations": []},
        kept_branches=tuple(_kept(obj.get("kept_branches", []), field + ".kept_branches")),
        categories=tuple(_categories(obj.get("categories", []), field + ".categories")),
        archive_use=expect_str(obj.get("archive_use", ""), field + ".archive_use",
                               allow_empty=True),
        label=obj.get("label", "") if isinstance(obj.get("label", ""), str) else "",
    )


def _kept(raw: Any, field: str) -> list[str]:
    out = []
    for i, item in enumerate(expect_list(raw, field)):
        path = f"{field}[{i}]"
        if isinstance(item, str):
            out.append(item)
            continue
        obj = expect_object(item, path, "kept branch")
        out.append(expect_str(obj.get("prefix"), path + ".prefix", allow_empty=True))
    return out


def _categories(raw: Any, field: str) -> list[str]:
    out = [expect_str(c, f"{field}[{i}]") for i, c in enumerate(expect_list(raw, field))]
    require(len(set(out)) == len(out), "DUP_CATEGORY", field, "a category is listed twice")
    return sorted(out)


def _vote(raw: Any, field: str) -> Vote:
    obj = expect_object(raw, field, "vote")
    issued = expect_int(obj.get("issued_at", 0), field + ".issued_at")
    expires = expect_int(obj.get("expires_at", 1 << 62), field + ".expires_at")
    require(issued < expires, "BAD_WINDOW", field + ".expires_at",
            "expires_at must be greater than issued_at")
    return Vote(
        vote_id=expect_str(obj.get("vote_id"), field + ".vote_id"),
        edge_id=expect_str(obj.get("edge_id"), field + ".edge_id"),
        category=expect_str(obj.get("category"), field + ".category"),
        reviewer_id=expect_str(obj.get("reviewer_id"), field + ".reviewer_id"),
        institution_id=expect_str(obj.get("institution_id"), field + ".institution_id"),
        policy_version=expect_int(obj.get("policy_version"), field + ".policy_version", minimum=1),
        old_root=check_root(obj.get("old_root"), field + ".old_root", allow_empty=False),
        new_root=check_root(obj.get("new_root"), field + ".new_root", allow_empty=False),
        issued_at=issued,
        expires_at=expires,
        signature=expect_str(obj.get("signature", ""), field + ".signature", allow_empty=True),
    )


# --------------------------------------------------------------------------- edge proof check

def assemble_fragments(fragments: list[dict[str, Any]], field: str) -> dict[str, Any]:
    """Merge proof fragments into one dual proof; duplicates must agree exactly."""
    leaves: list[dict[str, Any]] = []
    citations: dict[str, str] = {}
    seen: dict[str, dict[str, Any]] = {}
    for i, fragment in enumerate(fragments):
        path = f"{field}[{i}].payload"
        payload = expect_object(fragment.get("payload"), path, "fragment payload")
        for j, leaf in enumerate(expect_list(payload.get("leaves", []), path + ".leaves")):
            item = expect_object(leaf, f"{path}.leaves[{j}]", "leaf")
            key = check_key(item.get("key"), f"{path}.leaves[{j}].key")
            if key in seen:
                require(canonical(seen[key]) == canonical(item), "FRAGMENT_CONFLICT",
                        f"{path}.leaves[{j}]",
                        f"two fragments disagree about leaf {key}")
                continue
            seen[key] = item
            leaves.append(item)
        for j, cite in enumerate(expect_list(payload.get("citations", []),
                                             path + ".citations")):
            item = expect_object(cite, f"{path}.citations[{j}]", "citation")
            prefix = expect_str(item.get("prefix"), f"{path}.citations[{j}].prefix",
                                allow_empty=True)
            h = expect_str(item.get("hash"), f"{path}.citations[{j}].hash")
            if prefix in citations:
                require(citations[prefix] == h, "FRAGMENT_CONFLICT", f"{path}.citations[{j}]",
                        f"two fragments disagree about citation {prefix}")
                continue
            citations[prefix] = h
    return {"leaves": leaves,
            "citations": [{"prefix": p, "hash": citations[p]} for p in sorted(citations)]}


def verify_edge(edge: Edge, from_cp: Checkpoint, to_cp: Checkpoint,
                proof_raw: Any, policy_raw: Any, field: str) -> tuple[Any, Scene]:
    """Structural + root + policy verification of one assembled edge proof."""
    policy = parse_policy(policy_raw, field + ".policy")
    proof = parse_proof(proof_raw, field + ".proof", DUAL_SIDES)
    scene = scene_of_dual_proof(proof)
    scene.check_root(0, from_cp.root, field + ".proof", "edge old")
    scene.check_root(1, to_cp.root, field + ".proof", "edge new")

    cited = set(proof.cites)
    for i, prefix in enumerate(edge.kept_branches):
        require(prefix in cited, "KEPT_NOT_CITED", f"{field}.kept_branches[{i}]",
                f"kept branch {prefix} is not disclosed as a shared citation")
    for key in proof.keys:
        old, new = proof.values[key]
        kind = change_kind(old, new)
        if kind == "unchanged":
            continue
        policy.check(key, kind, field + ".proof.leaves")
        for i, prefix in enumerate(edge.kept_branches):
            require(not key.startswith(prefix), "KEPT_BRANCH_CHANGED",
                    f"{field}.kept_branches[{i}]",
                    f"branch {prefix} is declared kept but key {key} changed inside it")
    return proof, scene


# --------------------------------------------------------------------------- ingest

def handle_ingest(case: dict[str, Any], db: str | None) -> dict[str, Any]:
    conn = store.connect(db)  # type: ignore[arg-type]
    try:
        return _ingest(conn, case)
    finally:
        conn.close()


def _ingest(conn: sqlite3.Connection, case: dict[str, Any]) -> dict[str, Any]:
    with store.write_tx(conn):
        world = store.load_world(conn)
        report: dict[str, Any] = {
            "ok": True, "command": "ledger-ingest", "verified": True,
            "channels": [], "checkpoints": {"accepted": [], "rejected": []},
            "edges": {"verified": [], "staged": [], "rejected": []},
            "votes": {"accepted": [], "rejected": []},
            "revocations": {"accepted": [], "rejected": []},
            "aliases": {"accepted": [], "rejected": []},
            "institutions": {"accepted": [], "rejected": []},
        }

        # --- channel 1a: checkpoints (identity is the id, not the root content).
        for i, raw in enumerate(case.get("checkpoints") or []):
            try:
                cp = _checkpoint(raw, f"checkpoints[{i}]")
            except ArchiveError as exc:
                report["checkpoints"]["rejected"].append(exc.as_dict())
                continue
            known = world.checkpoints.get(cp.checkpoint_id)
            if known is not None and known.root != cp.root:
                report["checkpoints"]["rejected"].append({
                    "code": "CHECKPOINT_CONTENT_CONFLICT",
                    "field": f"checkpoints[{i}].root",
                    "detail": f"checkpoint {cp.checkpoint_id} is already registered with "
                              f"root sha256:{known.root}"})
                continue
            store.store_checkpoint(conn, {
                "checkpoint_id": cp.checkpoint_id, "root": cp.root,
                "generation": cp.generation, "label": cp.label,
                "policy_version": cp.policy_version,
            })
            world.checkpoints[cp.checkpoint_id] = cp
            report["checkpoints"]["accepted"].append(cp.checkpoint_id)

        for i, raw in enumerate(case.get("edges") or []):
            path = f"edges[{i}]"
            try:
                _ingest_edge(conn, world, raw, path, report)
            except ArchiveError as exc:
                report["edges"]["rejected"].append(exc.as_dict())
        for i, raw in enumerate(case.get("proofs") or []):
            path = f"proofs[{i}]"
            try:
                _ingest_edge(conn, world, raw, path, report)
            except ArchiveError as exc:
                report["edges"]["rejected"].append(exc.as_dict())

        # --- channel 2: votes and revocations.
        for i, raw in enumerate(case.get("votes") or []):
            _ingest_vote(conn, world, raw, f"votes[{i}]", report)
        for i, raw in enumerate(case.get("revocations") or []):
            _ingest_revocation(conn, world, raw, f"revocations[{i}]", report)
        for i, raw in enumerate(case.get("aliases") or []):
            _ingest_alias(conn, world, raw, f"aliases[{i}]", report)
        for i, raw in enumerate(case.get("institutions") or []):
            _ingest_institution(conn, world, raw, f"institutions[{i}]", report)

        report["channels"] = [
            "checkpoints", "edge_proof_fragments", "votes", "revocations",
            "aliases", "institutions",
        ]
        store.audit(conn, "ingest", {k: len(v) if isinstance(v, list) else v
                                     for k, v in report.items() if k not in ("ok", "command",
                                                                              "verified", "channels")})
        store.sync_point("ingest:before-commit")
    return report


def _ingest_edge(conn: sqlite3.Connection, world: World, raw: Any, field: str,
                 report: dict[str, Any]) -> None:
    try:
        edge = _edge(raw, field)
        expected = expect_int(raw.get("expected_fragments", 1),
                              field + ".expected_fragments", minimum=1)
        fragment_id = raw.get("fragment_id")
        payload = raw.get("fragment") or raw.get("payload")
        require(payload is not None or edge.proof, "NO_FRAGMENT", field,
                "an edge must arrive with a proof or a proof fragment")
    except ArchiveError as exc:
        report["edges"]["rejected"].append(exc.as_dict())
        return

    known = conn.execute(
        "SELECT status, from_id, to_id, generation, policy_version, archive_use, "
        "fragments_hash FROM edges WHERE edge_id = ?", (edge.edge_id,)).fetchone()
    if known is not None and known[0] == "verified":
        if edge.edge_id in report["edges"]["verified"]:
            return
        # A verified edge id is immutable: re-submitting it must be a byte-identical
        # registration, otherwise two different proofs would share one identity.
        same = (known[1] == edge.from_id and known[2] == edge.to_id
                and known[4] == edge.policy_version
                and known[5] == edge.archive_use)
        if not same:
            detail = (f"edge {edge.edge_id} is already verified as "
                      f"{known[1]}->{known[2]} under policy version {known[4]}; a verified "
                      f"edge id cannot be re-registered with different content")
            report["edges"]["rejected"].append({
                "code": "EDGE_REGISTRATION_CONFLICT", "field": field,
                "detail": detail})
            return
        report["edges"]["verified"].append(edge.edge_id)
        return
    if payload is None:
        payload = edge.proof
        fragment_id = "full"
    if fragment_id is not None:
        store.store_fragment(conn, edge.edge_id, expect_str(fragment_id, field + ".fragment_id"),
                             payload)
    rows = conn.execute("SELECT fragment_id, payload FROM edge_fragments WHERE edge_id = ? "
                        "ORDER BY fragment_id", (edge.edge_id,)).fetchall()
    fragments = [{"fragment_id": fid, "payload": json.loads(body)} for fid, body in rows]
    frag_hash = store.fragment_digest(fragments)

    from_cp = world.checkpoints.get(edge.from_id)
    to_cp = world.checkpoints.get(edge.to_id)
    problems = []
    if from_cp is None:
        problems.append(("UNKNOWN_CHECKPOINT", field + ".from",
                         f"checkpoint {edge.from_id} is not registered"))
    if to_cp is None:
        problems.append(("UNKNOWN_CHECKPOINT", field + ".to",
                         f"checkpoint {edge.to_id} is not registered"))
    if from_cp is not None and to_cp is not None:
        if to_cp.generation <= from_cp.generation:
            problems.append(("GENERATION_ORDER", field + ".generation",
                             "the edge must lead to a checkpoint of higher generation"))
        if edge.generation <= from_cp.generation:
            problems.append(("GENERATION_ORDER", field + ".generation",
                             f"the edge generation must exceed the start checkpoint's "
                             f"generation ({from_cp.generation})"))
    if problems:
        code, path, detail = problems[0]
        store.store_edge(conn, _edge_row(edge), "rejected", detail, frag_hash, expected)
        report["edges"]["rejected"].append({"code": code, "field": path, "detail": detail})
        return

    if len(fragments) < expected:
        store.store_edge(conn, _edge_row(edge), "staged",
                         f"awaiting {expected - len(fragments)} more fragment(s)",
                         frag_hash, expected)
        report["edges"]["staged"].append({
            "edge_id": edge.edge_id, "have": len(fragments), "expected": expected})
        return

    try:
        assembled = assemble_fragments(
            [{"payload": f["payload"]} for f in fragments], field + ".fragments")
        proof, _scene = verify_edge(edge, from_cp, to_cp, assembled,
                                    raw.get("policy"), field)
    except ArchiveError as exc:
        store.store_edge(conn, _edge_row(edge), "rejected", exc.detail, frag_hash, expected)
        report["edges"]["rejected"].append(exc.as_dict())
        return

    row = _edge_row(edge, proof.as_dict())
    store.store_edge(conn, row, "verified", "", frag_hash, expected)
    world.edges[edge.edge_id] = Edge(
        edge.edge_id, edge.from_id, edge.to_id, edge.generation, edge.policy_version,
        proof.as_dict(), edge.kept_branches, edge.categories, edge.label)
    report["edges"]["verified"].append(edge.edge_id)


def _edge_row(edge: Edge, proof: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "edge_id": edge.edge_id, "from": edge.from_id, "to": edge.to_id,
        "generation": edge.generation, "policy_version": edge.policy_version,
        "proof": proof if proof is not None else edge.proof,
        "kept_branches": list(edge.kept_branches), "categories": list(edge.categories),
        "archive_use": edge.archive_use, "label": edge.label,
    }


def _ingest_vote(conn: sqlite3.Connection, world: World, raw: Any, field: str,
                 report: dict[str, Any]) -> None:
    try:
        vote = _vote(raw, field)
    except ArchiveError as exc:
        report["votes"]["rejected"].append(exc.as_dict())
        return
    if vote.vote_id in world.votes:
        report["votes"]["accepted"].append(vote.vote_id)
        return
    subject = world.subject(vote.reviewer_id)
    registered = world.institutions.get(subject)
    if registered is not None and registered != vote.institution_id:
        detail = (f"vote {vote.vote_id} declares institution {vote.institution_id} but "
                  f"subject {subject} is registered with {registered}")
        store.store_vote(conn, _vote_row(vote), "rejected", detail)
        report["votes"]["rejected"].append({"code": "INSTITUTION_MISMATCH",
                                            "field": field + ".institution_id",
                                            "detail": detail})
        return
    store.store_vote(conn, _vote_row(vote), "verified")
    world.votes[vote.vote_id] = vote
    report["votes"]["accepted"].append(vote.vote_id)


def _vote_row(vote: Vote) -> dict[str, Any]:
    return {
        "vote_id": vote.vote_id, "edge_id": vote.edge_id, "category": vote.category,
        "reviewer_id": vote.reviewer_id, "institution_id": vote.institution_id,
        "policy_version": vote.policy_version, "old_root": vote.old_root,
        "new_root": vote.new_root, "issued_at": vote.issued_at,
        "expires_at": vote.expires_at, "signature": vote.signature,
    }


def _ingest_revocation(conn: sqlite3.Connection, world: World, raw: Any, field: str,
                       report: dict[str, Any]) -> None:
    try:
        obj = expect_object(raw, field, "revocation")
        vote_id = expect_str(obj.get("vote_id"), field + ".vote_id")
        reason = expect_str(obj.get("reason", ""), field + ".reason", allow_empty=True)
    except ArchiveError as exc:
        report["revocations"]["rejected"].append(exc.as_dict())
        return
    if vote_id in world.revoked:
        report["revocations"]["accepted"].append(vote_id)
        return
    require(vote_id in world.votes, "UNKNOWN_VOTE", field + ".vote_id",
            f"cannot revoke unknown vote {vote_id}")
    commit_seq = store.next_commit_seq(conn)
    conn.execute("INSERT INTO revocations(vote_id, revoked_at, reason, commit_seq) "
                 "VALUES(?, ?, ?, ?)", (vote_id, _now(), reason, commit_seq))
    world.revoked[vote_id] = commit_seq
    report["revocations"]["accepted"].append(vote_id)


def _ingest_alias(conn: sqlite3.Connection, world: World, raw: Any, field: str,
                  report: dict[str, Any]) -> None:
    try:
        obj = expect_object(raw, field, "alias")
        alias = expect_str(obj.get("alias"), field + ".alias")
        subject = expect_str(obj.get("subject"), field + ".subject")
    except ArchiveError as exc:
        report["aliases"]["rejected"].append(exc.as_dict())
        return
    require(alias != subject, "ALIAS_CYCLE", field + ".subject",
            "an alias must resolve to a different subject")
    known = world.aliases.get(alias)
    if known is not None and known != subject:
        report["aliases"]["rejected"].append({
            "code": "ALIAS_CONFLICT", "field": field + ".subject",
            "detail": f"alias {alias} already resolves to {known}"})
        return
    # Reject cycles introduced by the new mapping.
    seen = {alias}
    cur = subject
    while cur in world.aliases:
        require(cur not in seen, "ALIAS_CYCLE", field + ".subject",
                f"alias chain through {cur} would form a cycle")
        seen.add(cur)
        cur = world.aliases[cur]
    conn.execute("INSERT INTO aliases(alias, subject) VALUES(?, ?) "
                 "ON CONFLICT(alias) DO UPDATE SET subject = excluded.subject",
                 (alias, subject))
    world.aliases[alias] = subject
    report["aliases"]["accepted"].append(alias)


def _ingest_institution(conn: sqlite3.Connection, world: World, raw: Any, field: str,
                        report: dict[str, Any]) -> None:
    try:
        obj = expect_object(raw, field, "institution")
        subject = expect_str(obj.get("subject"), field + ".subject")
        institution = expect_str(obj.get("institution_id"), field + ".institution_id")
    except ArchiveError as exc:
        report["institutions"]["rejected"].append(exc.as_dict())
        return
    known = world.institutions.get(subject)
    if known is not None and known != institution:
        report["institutions"]["rejected"].append({
            "code": "INSTITUTION_CONFLICT", "field": field + ".institution_id",
            "detail": f"subject {subject} is already registered with {known}"})
        return
    conn.execute("INSERT INTO institutions(subject, institution_id) VALUES(?, ?) "
                 "ON CONFLICT(subject) DO UPDATE SET institution_id = excluded.institution_id",
                 (subject, institution))
    world.institutions[subject] = institution
    report["institutions"]["accepted"].append(subject)


def _now() -> float:
    import time

    return time.time()


# --------------------------------------------------------------------------- planning

def _request(case: dict[str, Any]) -> dict[str, Any]:
    start = expect_str(case.get("start_checkpoint"), "start_checkpoint")
    end = expect_str(case.get("end_checkpoint"), "end_checkpoint")
    policy_version = expect_int(case.get("policy_version"), "policy_version", minimum=1)
    clock = expect_int(case.get("logical_clock", 0), "logical_clock")
    archive_use = case.get("archive_use")
    if archive_use is not None:
        archive_use = expect_str(archive_use, "archive_use")
    inventory = expect_object(case.get("inventory"), "inventory", "inventory")
    inv_root = check_root(inventory.get("root"), "inventory.root", allow_empty=False)
    s_keys = [check_key(k, f"s_keys[{i}]") for i, k in enumerate(expect_list(
        case.get("s_keys"), "s_keys"))]
    return {
        "start": start, "end": end, "policy_version": policy_version, "clock": clock,
        "archive_use": archive_use, "inventory": inventory, "inv_root": inv_root,
        "s_keys": s_keys,
        "max_paths": expect_int(case.get("max_paths", 20000), "max_paths", minimum=1),
    }


def _eligible_edges(world: World, req: dict[str, Any]) -> dict[str, Edge]:
    out: dict[str, Edge] = {}
    for edge in world.edges.values():
        if edge.policy_version != req["policy_version"]:
            continue
        if req["archive_use"] is not None and edge.archive_use != req["archive_use"]:
            continue
        if edge.from_id not in world.checkpoints or edge.to_id not in world.checkpoints:
            continue
        out[edge.edge_id] = edge
    return out


def _sub_world(world: World, edges: dict[str, Edge]) -> World:
    return World(checkpoints=world.checkpoints, edges=edges, votes=world.votes,
                 revoked=world.revoked, consumed=world.consumed, aliases=world.aliases,
                 institutions=world.institutions)


def _path_cost(edges: Sequence[Edge]) -> int:
    disclosed: set[str] = set()
    for edge in edges:
        disclosed |= edge.disclosed_keys()
    return len(disclosed)


def plan_case(world: World, case: dict[str, Any]) -> dict[str, Any]:
    """Public planning entry point: parse a raw request, then plan."""
    return plan_publication(world, _request(case))


def plan_publication(world: World, req: dict[str, Any]) -> dict[str, Any]:
    """Choose the minimum-cost executable path with a global vote assignment.

    ``req`` is the parsed request produced by :func:`_request`; callers holding a
    raw CASE object should use :func:`plan_case`.  The search is joint over
    ``(path, vote assignment)`` -- see :mod:`solution.plan_search` -- so a cheap
    prefix that burns a later hop's only reviewer cannot win.
    """
    from .core import parse_proof as _parse
    from .merkle import scene_of_value_proof
    from .plan_search import search

    if req["end"] not in world.checkpoints:
        raise err("TARGET_NOT_REGISTERED", "end_checkpoint",
                  f"checkpoint {req['end']} is not registered")
    if req["start"] not in world.checkpoints:
        raise err("START_NOT_REGISTERED", "start_checkpoint",
                  f"checkpoint {req['start']} is not registered")
    start_cp = world.checkpoints[req["start"]]
    require(start_cp.root == req["inv_root"], "START_ROOT_MISMATCH", "inventory.root",
            f"the inventory proof is rooted at sha256:{req['inv_root']} but checkpoint "
            f"{req['start']} carries sha256:{start_cp.root}")

    inv_proof = _parse(req["inventory"].get("proof"), "inventory.proof", ("value",))
    require(set(inv_proof.keys) == set(req["s_keys"]), "KEY_SET_MISMATCH",
            "inventory.proof.leaves",
            "the inventory proof must cover exactly the S key set")
    scene_of_value_proof(inv_proof).check_root(0, start_cp.root, "inventory.proof",
                                               "start checkpoint")

    eligible = _eligible_edges(world, req)
    if not eligible:
        raise err("STRUCTURE_BROKEN", "graph",
                  f"no verified edge with archive use {req['archive_use']!r} is "
                  f"registered under policy version {req['policy_version']}")
    sub = _sub_world(world, eligible)
    label = search(sub, req["start"], req["end"], clock=req["clock"],
                   policy_version=req["policy_version"])
    if label is None:
        policy_edges = [e for e in world.edges.values()
                        if e.policy_version == req["policy_version"]]
        if not policy_edges:
            raise err("STRUCTURE_BROKEN", "policy_version",
                      f"no edge is registered under policy version "
                      f"{req['policy_version']}")
        if not reachable(sub, req["start"], req["end"]):
            raise err("STRUCTURE_BROKEN", "end_checkpoint",
                      f"no chain of verified edges reaches checkpoint {req['end']} from "
                      f"{req['start']} under archive use {req['archive_use']!r} and policy "
                      f"version {req['policy_version']}")
        raise err("INSUFFICIENT_VOTES", "votes",
                  "every structurally reachable path is blocked by the global "
                  "review-vote constraints (one vote and one review subject per "
                  "request, two institutions per category slot)")

    hops = [world.edges[eid] for eid in label.hops]
    try:
        result = rebase_path(world, hops, inv_proof, req)
    except ArchiveError as exc:
        raise err("REBASE_FAILED", "plan",
                  f"the selected path {list(label.hops)} cannot rebase S: "
                  f"{exc.code}: {exc.detail}")

    plan = Plan(
        edge_ids=label.hops,
        votes=tuple((h, c, v, world.subject(world.votes[v].reviewer_id))
                    for h, c, v in label.votes),
        disclosed_keys=len(label.disclosed),
        roots=tuple(world.checkpoints[e.from_id].root for e in hops)
        + (world.checkpoints[hops[-1].to_id].root,),
        rebase=result,
    )
    return _plan_payload(world, req, plan, len(eligible), [], [])


def reachable(world: World, start: str, end: str) -> bool:
    """Structural reachability in the DAG, ignoring votes entirely."""
    if start == end:
        return True
    outgoing: dict[str, list[str]] = {}
    for edge in world.edges.values():
        outgoing.setdefault(edge.from_id, []).append(edge.to_id)
    seen = {start}
    stack = [start]
    while stack:
        node = stack.pop()
        for nxt in outgoing.get(node, ()):
            if nxt == end:
                return True
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return False


def rebase_path(world: World, hops: Sequence[Edge], inv_proof, req: dict[str, Any]):
    """Rebase the inventory proof along ``hops``; each edge is independently verified."""
    rebase_hops = []
    for i, edge in enumerate(hops):
        from_cp = world.checkpoints[edge.from_id]
        to_cp = world.checkpoints[edge.to_id]
        proof = parse_proof(edge.proof, f"edges[{edge.edge_id}].proof", DUAL_SIDES)
        scene = scene_of_dual_proof(proof)
        scene.check_root(0, from_cp.root, f"edges[{edge.edge_id}].proof", "edge old")
        scene.check_root(1, to_cp.root, f"edges[{edge.edge_id}].proof", "edge new")
        rebase_hops.append(Hop(index=i + 1, version=i + 1, old_root=from_cp.root,
                              new_root=to_cp.root, proof=proof,
                              path=f"edges[{edge.edge_id}].proof"))
    return run_rebase(world.checkpoints[hops[0].from_id].root, inv_proof, req["s_keys"],
                      rebase_hops, field="plan")


def _plan_payload(world: World, req: dict[str, Any], plan: Plan, considered: int,
                  vote_failures: list[str], rebase_failures: list[str]) -> dict[str, Any]:
    hops_payload = []
    for hop, edge_id in enumerate(plan.edge_ids, start=1):
        edge = world.edges[edge_id]
        frag_hash = _edge_fragment_hash(world, edge_id)
        hops_payload.append({
            "hop": hop,
            "edge_id": edge_id,
            "from": edge.from_id,
            "to": edge.to_id,
            "from_root": "sha256:" + world.checkpoints[edge.from_id].root,
            "to_root": "sha256:" + world.checkpoints[edge.to_id].root,
            "generation": edge.generation,
            "policy_version": edge.policy_version,
            "categories": list(edge.categories),
            "kept_branches": list(edge.kept_branches),
            "archive_use": edge.archive_use,
            "disclosed": sorted(edge.disclosed_keys()),
            "fragments_hash": frag_hash,
            "votes": [
                {"category": c, "vote_id": v}
                for h, c, v, _ in plan.votes if h == hop
            ],
        })
    return {
        "ok": True,
        "command": "ledger-plan",
        "verified": True,
        "start_checkpoint": req["start"],
        "end_checkpoint": req["end"],
        "policy_version": req["policy_version"],
        "logical_clock": req["clock"],
        "plan": {
            "edge_ids": list(plan.edge_ids),
            "hops": hops_payload,
            "hops_count": len(plan.edge_ids),
            "disclosed_keys": plan.disclosed_keys,
            "disclosed_key_list": sorted(
                set().union(*(set(world.edges[e].disclosed_keys()) for e in plan.edge_ids))),
            "votes": [{"hop": h, "category": c, "vote_id": v, "subject": s}
                      for h, c, v, s in plan.votes],
            "fragments_hash": checksum([
                {"edge_id": h["edge_id"], "fragments_hash": h["fragments_hash"]}
                for h in hops_payload]),
        },
        "final_root": "sha256:" + plan.rebase.final_root,
        "projection": plan.rebase.proof,
        "keys": plan.rebase.rows,
        "search": {
            "candidate_edges": considered,
            "algorithm": "joint label search over (path, consumed votes, consumed subjects)",
            "objective": "disclosed keys, then hops, then edge-id sequence, then vote list",
            "note": "a label is pruned only when another label at the same checkpoint is "
                    "at least as good on every objective and leaves at least as many "
                    "votes and subjects unused",
        },
    }


def _edge_fragment_hash(world: World, edge_id: str) -> str:
    return world.fragments.get(edge_id, "")


def handle_plan(case: dict[str, Any], db: str | None) -> dict[str, Any]:
    conn = store.connect(db)  # type: ignore[arg-type]
    try:
        with store.read_tx(conn):
            world = store.load_world(conn)
            world.fragments = _fragment_hashes(conn)
            req = _request(case)
            return plan_publication(world, req)
    finally:
        conn.close()


def _fragment_hashes(conn: sqlite3.Connection) -> dict[str, str]:
    return {eid: h for eid, h in conn.execute(
        "SELECT edge_id, fragments_hash FROM edges WHERE status = 'verified'")}
