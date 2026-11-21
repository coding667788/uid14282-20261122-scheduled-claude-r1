"""SQLite persistence for the archive publication ledger.

Two invariants shape this module.

*In-flight evidence is never half-visible.*  Ingestion stages everything it was
given in a single transaction; an edge only becomes ``verified`` when every
expected proof fragment is present and the fragment set reproduces the bound root
pair.  A process killed at any point leaves either the previous committed state
or nothing -- a staged half-edge is never queryable as a verified edge, and no
query can combine a root from one stage with a proof from another.

*Publication is one transaction.*  ``publish`` re-checks the start checkpoint, the
fragment-set hash, the policy generation, vote revocation and consumption, and
the idempotency key inside ``BEGIN IMMEDIATE`` before it writes.  Two concurrent
publishers competing for the same vote or the same start point therefore
serialise: exactly one of them changes state.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .core import ArchiveError, canonical, checksum

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    root TEXT NOT NULL,
    generation INTEGER NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    policy_version INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'verified',
    reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS edges (
    edge_id TEXT PRIMARY KEY,
    from_id TEXT NOT NULL,
    to_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    policy_version INTEGER NOT NULL,
    proof TEXT NOT NULL DEFAULT 'null',
    kept TEXT NOT NULL DEFAULT '[]',
    categories TEXT NOT NULL DEFAULT '[]',
    archive_use TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'staged',
    reason TEXT NOT NULL DEFAULT '',
    fragments_hash TEXT NOT NULL DEFAULT '',
    expected_fragments INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS edge_fragments (
    edge_id TEXT NOT NULL,
    fragment_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (edge_id, fragment_id)
);
CREATE TABLE IF NOT EXISTS votes (
    vote_id TEXT PRIMARY KEY,
    edge_id TEXT NOT NULL,
    category TEXT NOT NULL,
    reviewer_id TEXT NOT NULL,
    institution_id TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    old_root TEXT NOT NULL,
    new_root TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    signature TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'verified',
    reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS revocations (
    vote_id TEXT PRIMARY KEY,
    revoked_at REAL NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    commit_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS aliases (
    alias TEXT PRIMARY KEY,
    subject TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS institutions (
    subject TEXT PRIMARY KEY,
    institution_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS publications (
    commit_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,
    request_hash TEXT NOT NULL,
    start_checkpoint TEXT NOT NULL,
    end_checkpoint TEXT NOT NULL,
    root TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    plan TEXT NOT NULL,
    proof TEXT NOT NULL,
    receipt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS consumption (
    vote_id TEXT PRIMARY KEY,
    commit_seq INTEGER NOT NULL,
    request_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    audit_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS edges_from ON edges(from_id, generation);
CREATE INDEX IF NOT EXISTS votes_edge ON votes(edge_id, category);
"""


def connect(path: str) -> sqlite3.Connection:
    target = Path(path)
    parent = target.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=60.0, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=60000")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def write_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


@contextmanager
def read_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN")
    try:
        yield conn
    finally:
        conn.execute("COMMIT")


def meta_get(conn: sqlite3.Connection, key: str, default: str = "0") -> str:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO meta(key, value) VALUES(?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))


def next_commit_seq(conn: sqlite3.Connection) -> int:
    """Reserve the next commit number; only valid inside a write transaction."""
    value = int(meta_get(conn, "commit_seq", "0")) + 1
    meta_set(conn, "commit_seq", str(value))
    return value


def audit(conn: sqlite3.Connection, kind: str, detail: Any) -> None:
    conn.execute("INSERT INTO audit(at, kind, detail) VALUES(?, ?, ?)",
                 (time.time(), kind, canonical(detail)))


# --------------------------------------------------------------------------- sync points

def sync_point(name: str) -> None:
    """Deterministic multi-process rendezvous used by the concurrency tests.

    ``SOLUTION_SYNC_DIR`` names a directory.  When it is set, ``sync_point(name)``
    drops ``<stem>.here`` and waits for ``<stem>.go``; the test harness creates the
    ``.go`` file when the process may continue.  ``SOLUTION_SYNC_POINTS`` narrows
    participation to a comma-separated list of names so a test waits only where it
    means to.  Without ``SOLUTION_SYNC_DIR`` the whole thing is a no-op, so
    production behaviour never depends on it.
    """
    directory = os.environ.get("SOLUTION_SYNC_DIR")
    if not directory:
        return
    wanted = os.environ.get("SOLUTION_SYNC_POINTS")
    if wanted is not None and name not in {p.strip() for p in wanted.split(",") if p.strip()}:
        return
    base = Path(directory).resolve()
    base.mkdir(parents=True, exist_ok=True)
    # Windows forbids ':' in a file name (it would create an NTFS stream), so the
    # sync point name is sanitised; both sides of the rendezvous use the same rule.
    stem = name.replace(":", "-")
    (base / f"{stem}.here").write_text(str(os.getpid()), encoding="utf-8")
    deadline = time.monotonic() + float(os.environ.get("SOLUTION_SYNC_TIMEOUT", "30"))
    go = base / f"{stem}.go"
    while not go.exists():
        if time.monotonic() > deadline:
            raise ArchiveError("SYNC_TIMEOUT", "env:SOLUTION_SYNC_DIR",
                               f"sync point {name} was never released")
        time.sleep(0.005)


# --------------------------------------------------------------------------- writes

def store_checkpoint(conn: sqlite3.Connection, data: dict[str, Any],
                     status: str = "verified", reason: str = "") -> None:
    conn.execute(
        "INSERT INTO checkpoints(checkpoint_id, root, generation, label, policy_version, "
        "status, reason) VALUES(?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(checkpoint_id) DO UPDATE SET "
        "generation = MAX(checkpoints.generation, excluded.generation), "
        "label = CASE WHEN excluded.label = '' THEN checkpoints.label "
        "ELSE excluded.label END, "
        "status = CASE WHEN checkpoints.status = 'verified' THEN 'verified' "
        "ELSE excluded.status END, reason = excluded.reason",
        (data["checkpoint_id"], data["root"], data["generation"], data.get("label", ""),
         data["policy_version"], status, reason),
    )


def store_edge(conn: sqlite3.Connection, edge: dict[str, Any], status: str,
               reason: str = "", frag_hash: str = "", expected: int = 1) -> None:
    conn.execute(
        "INSERT INTO edges(edge_id, from_id, to_id, generation, policy_version, proof, kept, "
        "categories, archive_use, label, status, reason, fragments_hash, expected_fragments) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(edge_id) DO UPDATE SET "
        "generation = MAX(edges.generation, excluded.generation), "
        "policy_version = excluded.policy_version, "
        "proof = excluded.proof, "
        "kept = excluded.kept, categories = excluded.categories, "
        "archive_use = CASE WHEN excluded.archive_use = '' THEN edges.archive_use "
        "ELSE excluded.archive_use END, label = excluded.label, "
        "status = CASE WHEN edges.status = 'verified' THEN 'verified' "
        "ELSE excluded.status END, "
        "reason = excluded.reason, fragments_hash = excluded.fragments_hash, "
        "expected_fragments = excluded.expected_fragments",
        (edge["edge_id"], edge["from"], edge["to"], edge["generation"],
         edge["policy_version"], canonical(edge.get("proof")),
         canonical(edge.get("kept_branches", [])), canonical(edge.get("categories", [])),
         edge.get("archive_use", ""), edge.get("label", ""), status, reason, frag_hash,
         expected),
    )


def store_fragment(conn: sqlite3.Connection, edge_id: str, fragment_id: str,
                   payload: Any) -> None:
    conn.execute(
        "INSERT INTO edge_fragments(edge_id, fragment_id, payload) VALUES(?, ?, ?) "
        "ON CONFLICT(edge_id, fragment_id) DO UPDATE SET payload = excluded.payload",
        (edge_id, fragment_id, canonical(payload)),
    )


def store_vote(conn: sqlite3.Connection, vote: dict[str, Any], status: str = "verified",
               reason: str = "") -> None:
    conn.execute(
        "INSERT INTO votes(vote_id, edge_id, category, reviewer_id, institution_id, "
        "policy_version, old_root, new_root, issued_at, expires_at, signature, status, reason) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(vote_id) DO UPDATE SET edge_id = excluded.edge_id, "
        "category = excluded.category, reviewer_id = excluded.reviewer_id, "
        "institution_id = excluded.institution_id, policy_version = excluded.policy_version, "
        "old_root = excluded.old_root, new_root = excluded.new_root, "
        "issued_at = excluded.issued_at, expires_at = excluded.expires_at, "
        "signature = excluded.signature, "
        "status = CASE WHEN votes.status = 'verified' THEN 'verified' ELSE excluded.status END, "
        "reason = excluded.reason",
        (vote["vote_id"], vote["edge_id"], vote["category"], vote["reviewer_id"],
         vote["institution_id"], vote["policy_version"], vote["old_root"], vote["new_root"],
         vote["issued_at"], vote["expires_at"], vote.get("signature", ""), status, reason),
    )


# --------------------------------------------------------------------------- reads

def load_world(conn: sqlite3.Connection, *, include_staged: bool = False):
    """Load a consistent snapshot of the ledger.

    Only ``verified`` checkpoints, edges and votes take part in queries, planning
    and publication.  ``include_staged`` is used by ingestion to resume work and
    by ``status`` to report on it.
    """
    from .ledger_model import Checkpoint, Edge, Vote, World

    world = World()
    for row in conn.execute("SELECT checkpoint_id, root, generation, label, policy_version "
                            "FROM checkpoints WHERE status = 'verified' ORDER BY checkpoint_id"):
        cid, root, generation, label, policy_version = row
        world.checkpoints[cid] = Checkpoint(cid, root, generation, label, policy_version)
    for row in conn.execute(
            "SELECT edge_id, from_id, to_id, generation, policy_version, proof, kept, "
            "categories, archive_use, label, status, reason FROM edges "
            "ORDER BY generation, edge_id"):
        (eid, from_id, to_id, generation, policy_version, proof, kept, categories,
         archive_use, label, status, reason) = row
        if status != "verified" and not include_staged:
            continue
        edge = Edge(eid, from_id, to_id, generation, policy_version, json.loads(proof),
                    tuple(json.loads(kept)), tuple(json.loads(categories)), archive_use, label)
        world.edges[eid] = edge
    for row in conn.execute(
            "SELECT vote_id, edge_id, category, reviewer_id, institution_id, policy_version, "
            "old_root, new_root, issued_at, expires_at, signature, status, reason "
            "FROM votes ORDER BY vote_id"):
        (vid, eid, category, reviewer, institution, policy_version, old_root, new_root,
         issued_at, expires_at, signature, status, reason) = row
        if status != "verified" and not include_staged:
            continue
        world.votes[vid] = Vote(vid, eid, category, reviewer, institution, policy_version,
                                old_root, new_root, issued_at, expires_at, signature)
    world.revoked = dict(conn.execute("SELECT vote_id, revoked_at FROM revocations"))
    world.consumed = dict(conn.execute("SELECT vote_id, request_id FROM consumption"))
    world.aliases = dict(conn.execute("SELECT alias, subject FROM aliases"))
    world.institutions = dict(conn.execute("SELECT subject, institution_id FROM institutions"))
    return world


def fragment_digest(fragments: list[dict[str, Any]]) -> str:
    ordered = sorted(fragments, key=lambda f: f["fragment_id"])
    return checksum([{"fragment_id": f["fragment_id"], "payload": f["payload"]}
                     for f in ordered])
