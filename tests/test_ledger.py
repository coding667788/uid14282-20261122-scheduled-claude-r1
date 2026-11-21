"""Ledger tests: checkpoint identity, ingestion staging, planning and publication.

The planner is cross-checked against an exhaustive independent search over
``(path x vote assignment)`` for small graphs, so "greedy per hop" solutions are
caught whenever they differ from the global optimum.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import itertools
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from solution import store
from solution.ledger_model import vote_options
from solution.refimpl import apply_patch

from tests.support import (DEPTH, ROOT, checkpoint, edge, fmt, request, run_cli, vote)


def new_db() -> Path:
    return Path(tempfile.mkdtemp(prefix="ledger-")) / "ledger.sqlite"


def ingest(db, case):
    code, payload = run_cli("ledger-ingest", case, db=db)
    assert code == 0, payload
    return payload


def plan(db, req):
    return run_cli("ledger-plan", req, db=db)


def publish(db, req):
    return run_cli("ledger-publish", req, db=db)


def refimpl_dual(old, new, keys, depth=DEPTH):
    from solution import refimpl

    return refimpl.dual_proof(old, new, keys, depth)


def popen(command, case, db, env=None, sync_dir=None):
    tmp = Path(tempfile.mkdtemp(prefix="case-"))
    path = tmp / "case.json"
    path.write_text(json.dumps(case), encoding="utf-8")
    argv = [sys.executable, "-m", "solution", command, str(path), "--db", str(db)]
    return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, cwd=str(ROOT),
                            env={**os.environ, **(env or {})}, encoding="utf-8")


def wait_for(sync_dir: Path, name: str, timeout: float = 20.0) -> bool:
    target = sync_dir / f"{name.replace(':', '-')}.here"
    deadline = time.time() + timeout
    while not target.exists():
        if time.time() > deadline:
            return False
        time.sleep(0.01)
    return True


def release(sync_dir: Path, name: str) -> None:
    (sync_dir / f"{name.replace(':', '-')}.go").write_text("go", encoding="utf-8")


# --------------------------------------------------------------------------- fixtures

class Chain:
    """Three checkpoints A -> B -> C with one edge and two reviews per hop."""

    def __init__(self) -> None:
        self.a = {"000100": "a", "001000": "b", "010000": "c", "100000": "d"}
        self.b = apply_patch(self.a, {"000100": "A"})
        self.c = apply_patch(self.b, {"010000": "C"})
        self.s = ["000100", "100000"]

    def base_case(self, extra_edges=(), extra_votes=(), categories=("privacy",),
                  policy_version=1, drop_votes=()):
        votes = [
            vote("v1", "e1", self.a, self.b, "alice", "inst-1", policy_version=policy_version),
            vote("v2", "e1", self.a, self.b, "bob", "inst-2", policy_version=policy_version),
            vote("v3", "e2", self.b, self.c, "carol", "inst-3", policy_version=policy_version),
            vote("v4", "e2", self.b, self.c, "dave", "inst-4", policy_version=policy_version),
            *extra_votes,
        ]
        return {
            "checkpoints": [
                checkpoint("cp-A", self.a, 10),
                checkpoint("cp-B", self.b, 11),
                checkpoint("cp-C", self.c, 12),
            ],
            "edges": [
                edge("e1", self.a, self.b, "cp-A", "cp-B", 11,
                     categories=categories, policy_version=policy_version),
                edge("e2", self.b, self.c, "cp-B", "cp-C", 12,
                     categories=categories, policy_version=policy_version),
                *extra_edges,
            ],
            "votes": [v for v in votes if v["vote_id"] not in set(drop_votes)],
        }

    def request(self, start="cp-A", end="cp-C", **kwargs):
        at = {"cp-A": self.a, "cp-B": self.b, "cp-C": self.c}[start]
        return request(start, end, self.s, at, **kwargs)


# --------------------------------------------------------------------------- ingestion

class IngestTest(unittest.TestCase):
    def test_checkpoint_identity_is_not_the_root(self):
        chain = Chain()
        db = new_db()
        ingest(db, {"checkpoints": [checkpoint("cp-A", chain.a, 10),
                                    checkpoint("cp-X", chain.a, 20)]})
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["checkpoints"], 2)

    def test_fragments_must_all_arrive_before_an_edge_is_verified(self):
        chain = Chain()
        db = new_db()
        proof = refimpl_dual(chain.a, chain.b, ["000100"])
        cut = len(proof["citations"]) // 2
        half = {"leaves": proof["leaves"], "citations": proof["citations"][:cut]}
        rest = {"leaves": [], "citations": proof["citations"][cut:]}
        base = {"edge_id": "e1", "from": "cp-A", "to": "cp-B", "generation": 11,
                "policy_version": 1, "categories": ["privacy"],
                "archive_use": "cold-archive",
                "policy": {"allowed_prefixes": ["0", "1"]},
                "expected_fragments": 2}
        ingest(db, {"checkpoints": [checkpoint("cp-A", chain.a, 10),
                                    checkpoint("cp-B", chain.b, 11),
                                    checkpoint("cp-C", chain.c, 12)],
                    "edges": [{**base, "fragment_id": "f1", "fragment": half}]})
        code, payload = run_cli("ledger-status", {}, db=db)
        self.assertEqual(payload["edges"], 0)
        self.assertIn("e1", payload["staged_edges"])
        code, planned = plan(db, chain.request())
        self.assertEqual(planned["error"]["code"], "STRUCTURE_BROKEN")
        ingest(db, {"edges": [{**base, "fragment_id": "f2", "fragment": rest}]})
        code, payload = run_cli("ledger-status", {}, db=db)
        self.assertEqual(payload["edges"], 1)
        self.assertEqual(payload["staged_edges"], [])
        # Only e1 exists: the target is registered, but no complete chain reaches it.
        code, planned = plan(db, chain.request())
        self.assertEqual(planned["error"]["code"], "STRUCTURE_BROKEN")
        self.assertEqual(planned["error"]["field"], "end_checkpoint")

    def test_fragment_conflict_rejects_the_edge(self):
        chain = Chain()
        db = new_db()
        proof = refimpl_dual(chain.a, chain.b, ["000100"])
        bad = {"leaves": [], "citations": [{"prefix": proof["citations"][0]["prefix"],
                                            "hash": "sha256:" + "ef" * 32}]}
        base = {"edge_id": "e1", "from": "cp-A", "to": "cp-B", "generation": 11,
                "policy_version": 1, "expected_fragments": 2}
        payload = ingest(db, {
            "checkpoints": [checkpoint("cp-A", chain.a, 10),
                            checkpoint("cp-B", chain.b, 11)],
            "edges": [{**base, "fragment_id": "f1", "fragment": proof},
                      {**base, "fragment_id": "f2", "fragment": bad}],
        })
        self.assertTrue(payload["edges"]["rejected"])

    def test_replayed_fragments_are_idempotent(self):
        """Shard re-delivery (a replay) must not fork an edge or double-register it."""
        chain = Chain()
        db = new_db()
        proof = refimpl_dual(chain.a, chain.b, ["000100"])
        cut = len(proof["citations"]) // 2
        base = {"edge_id": "e1", "from": "cp-A", "to": "cp-B", "generation": 11,
                "policy_version": 1, "categories": ["privacy"],
                "archive_use": "cold-archive", "expected_fragments": 2,
                "policy": {"allowed_prefixes": ["0", "1"]}}
        halves = [{"fragment_id": "f1",
                   "fragment": {"leaves": proof["leaves"],
                                "citations": proof["citations"][:cut]}},
                  {"fragment_id": "f2",
                   "fragment": {"leaves": [],
                                "citations": proof["citations"][cut:]}}]
        ingest(db, {"checkpoints": [checkpoint("cp-A", chain.a, 10),
                                    checkpoint("cp-B", chain.b, 11)],
                    "edges": [{**base, **halves[0]}]})
        first = ingest(db, {"edges": [{**base, **halves[1]}]})
        second = ingest(db, {"edges": [{**base, **halves[0]}, {**base, **halves[1]}]})
        self.assertEqual(first["edges"]["verified"], ["e1"])
        self.assertEqual(second["edges"]["verified"], ["e1"])
        conn = store.connect(str(db))
        try:
            rows = conn.execute("SELECT COUNT(*) FROM edges WHERE edge_id = 'e1'").fetchone()
            frags = conn.execute("SELECT COUNT(*) FROM edge_fragments").fetchone()
        finally:
            conn.close()
        self.assertEqual(rows[0], 1)
        self.assertEqual(frags[0], 2)

    def test_edge_proof_must_match_the_bound_roots(self):
        chain = Chain()
        db = new_db()
        wrong = edge("e1", chain.a, chain.c, "cp-A", "cp-B", 11)
        payload = ingest(db, {"checkpoints": [checkpoint("cp-A", chain.a, 10),
                                              checkpoint("cp-B", chain.b, 11)],
                              "edges": [wrong]})
        self.assertEqual(payload["edges"]["rejected"][0]["code"], "ROOT_MISMATCH")

    def test_edge_generation_order_is_enforced(self):
        chain = Chain()
        db = new_db()
        bad = edge("e1", chain.a, chain.b, "cp-A", "cp-B", 10)
        payload = ingest(db, {"checkpoints": [checkpoint("cp-A", chain.a, 10),
                                              checkpoint("cp-B", chain.b, 11)],
                              "edges": [bad]})
        self.assertEqual(payload["edges"]["rejected"][0]["code"], "GENERATION_ORDER")

    def test_vote_window_must_be_ordered(self):
        bad = vote("v1", "e1", {"000100": "a"}, {"000100": "b"}, "alice", "i1",
                   issued_at=10, expires_at=5)
        code, payload = run_cli("ledger-ingest", {"votes": [bad]}, db=new_db())
        self.assertEqual(payload["votes"]["rejected"][0]["code"], "BAD_WINDOW")

    def test_alias_collapses_review_subjects(self):
        chain = Chain()
        db = new_db()
        case = chain.base_case()
        case["aliases"] = [{"alias": "alice2", "subject": "alice"}]
        case["votes"].append(vote("v5", "e1", chain.a, chain.b, "alice2", "inst-9"))
        ingest(db, case)
        conn = store.connect(str(db))
        try:
            world = store.load_world(conn)
            self.assertEqual(world.subject("alice2"), "alice")
        finally:
            conn.close()

    def test_service_interrupted_before_commit_leaves_no_partial_state(self):
        chain = Chain()
        db = new_db()
        sync_dir = Path(tempfile.mkdtemp(prefix="sync-"))
        env = {"SOLUTION_SYNC_DIR": str(sync_dir), "SOLUTION_SYNC_TIMEOUT": "30"}
        proc = popen("ledger-ingest", chain.base_case(), db, env)
        try:
            self.assertTrue(wait_for(sync_dir, "ingest:before-commit"),
                            "ingestion never reached its commit sync point")
            proc.kill()
            proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.stdout.close()
            proc.stderr.close()
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["checkpoints"], 0)
        self.assertEqual(status["edges"], 0)
        self.assertEqual(status["votes"], 0)


# --------------------------------------------------------------------------- planning oracle

def brute_force_paths(world, start: str, end: str) -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = []

    def walk(node: str, trail: tuple[str, ...], seen: set[str]) -> None:
        for candidate in sorted(world.edges.values(), key=lambda e: e.edge_id):
            if candidate.from_id != node:
                continue
            if candidate.to_id == end:
                out.append(trail + (candidate.edge_id,))
                continue
            if candidate.to_id in seen:
                continue
            walk(candidate.to_id, trail + (candidate.edge_id,), seen | {candidate.to_id})

    walk(start, (), {start})
    return sorted(set(out))


def brute_force_best(world, start: str, end: str, clock: int, policy_version: int):
    """Independent exhaustive optimum over (path x vote assignment)."""
    best = None
    for path in brute_force_paths(world, start, end):
        hops = [world.edges[e] for e in path]
        if any(h.policy_version != policy_version for h in hops):
            continue
        slots = []
        dead = False
        for hop, h in enumerate(hops, start=1):
            for category in h.categories:
                options = vote_options(world, h, category, clock, policy_version)
                if not options:
                    dead = True
                    break
                slots.append((hop, category, options))
            if dead:
                break
        if dead:
            continue
        for combo in itertools.product(*[s[2] for s in slots]):
            votes: set[str] = set()
            subjects: set[str] = set()
            assignment = []
            for (hop, category, _), (v1, v2, s1, s2) in zip(slots, combo):
                if {v1, v2} & votes or {s1, s2} & subjects:
                    break
                votes |= {v1, v2}
                subjects |= {s1, s2}
                assignment += [(hop, category, v1), (hop, category, v2)]
            else:
                disclosed = len({k for h in hops for k in h.disclosed_keys()})
                key = (disclosed, len(path), path, tuple(sorted(assignment)))
                if best is None or key < best:
                    best = key
    return best


class PlanTest(unittest.TestCase):
    def make(self, chain=None, **kwargs):
        chain = chain or Chain()
        db = new_db()
        ingest(db, chain.base_case(**kwargs))
        return chain, db

    def test_plan_selects_the_only_path(self):
        chain, db = self.make()
        code, payload = plan(db, chain.request())
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["plan"]["edge_ids"], ["e1", "e2"])
        self.assertEqual(payload["final_root"], fmt(chain.c))
        self.assertEqual(len(payload["plan"]["votes"]), 4)

    def test_missing_end_checkpoint_reports_target_not_registered(self):
        chain, db = self.make()
        req = chain.request()
        req["end_checkpoint"] = "cp-missing"
        code, payload = plan(db, req)
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["code"], "TARGET_NOT_REGISTERED")

    def test_structurally_broken_graph_is_reported(self):
        chain = Chain()
        db = new_db()
        ingest(db, {"checkpoints": [checkpoint("cp-A", chain.a, 10),
                                    checkpoint("cp-C", chain.c, 12)], "edges": []})
        code, payload = plan(db, chain.request())
        self.assertEqual(payload["error"]["code"], "STRUCTURE_BROKEN")

    def test_insufficient_votes_is_reported(self):
        chain, db = self.make(drop_votes=("v4",))
        code, payload = plan(db, chain.request())
        self.assertEqual(payload["error"]["code"], "INSUFFICIENT_VOTES")

    def test_same_reviewer_alias_cannot_sign_twice(self):
        chain = Chain()
        case = chain.base_case(drop_votes=("v2",))
        case["aliases"] = [{"alias": "alice-work", "subject": "alice"}]
        case["votes"].append(vote("v2b", "e1", chain.a, chain.b, "alice-work", "inst-9"))
        db = new_db()
        ingest(db, case)
        code, payload = plan(db, chain.request())
        self.assertEqual(payload["error"]["code"], "INSUFFICIENT_VOTES")

    def test_two_votes_need_two_institutions(self):
        chain = Chain()
        case = chain.base_case()
        for item in case["votes"]:
            if item["vote_id"] == "v2":
                item["institution_id"] = "inst-1"
        db = new_db()
        ingest(db, case)
        code, payload = plan(db, chain.request())
        self.assertEqual(payload["error"]["code"], "INSUFFICIENT_VOTES")

    def test_vote_outside_window_is_unusable(self):
        chain = Chain()
        case = chain.base_case()
        for item in case["votes"]:
            item["expires_at"] = 5
        db = new_db()
        ingest(db, case)
        code, payload = plan(db, chain.request(clock=100))
        self.assertEqual(payload["error"]["code"], "INSUFFICIENT_VOTES")

    def test_same_vote_reused_across_hops_is_refused(self):
        """A vote bound to e1 cannot be presented for e2 as well."""
        chain = Chain()
        db = new_db()
        case = chain.base_case()
        case["votes"] = [v for v in case["votes"] if v["vote_id"] not in ("v3", "v4")]
        case["votes"].append(vote("v3", "e2", chain.a, chain.b, "carol", "inst-3"))
        ingest(db, case)
        code, payload = plan(db, chain.request())
        self.assertEqual(payload["error"]["code"], "INSUFFICIENT_VOTES")

    def test_privacy_key_disclosed_twice_counts_once(self):
        chain = Chain()
        b2 = apply_patch(chain.b, {"000100": "again"})
        db = new_db()
        case = {
            "checkpoints": [checkpoint("cp-A", chain.a, 10), checkpoint("cp-B", chain.b, 11),
                            checkpoint("cp-B2", b2, 12), checkpoint("cp-C", chain.c, 20)],
            "edges": [
                edge("e1", chain.a, chain.b, "cp-A", "cp-B", 11),
                edge("e2", chain.b, b2, "cp-B", "cp-B2", 12),
                edge("e3", b2, chain.c, "cp-B2", "cp-C", 21),
            ],
            "votes": [
                vote("v1", "e1", chain.a, chain.b, "a1", "i1"),
                vote("v2", "e1", chain.a, chain.b, "a2", "i2"),
                vote("v3", "e2", chain.b, b2, "a3", "i3"),
                vote("v4", "e2", chain.b, b2, "a4", "i4"),
                vote("v5", "e3", b2, chain.c, "a5", "i5"),
                vote("v6", "e3", b2, chain.c, "a6", "i6"),
            ],
        }
        ingest(db, case)
        code, payload = plan(db, request("cp-A", "cp-C", chain.s, chain.a))
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["plan"]["disclosed_keys"], 2)
        self.assertEqual(payload["plan"]["hops_count"], 3)

    def test_same_root_different_checkpoint_cannot_be_skipped(self):
        chain = Chain()
        db = new_db()
        # cp-B' carries the same root as cp-C but is a different checkpoint.
        case = chain.base_case()
        case["checkpoints"].append(checkpoint("cp-C-copy", chain.c, 12))
        ingest(db, case)
        req = request("cp-A", "cp-C-copy", chain.s, chain.a)
        code, payload = plan(db, req)
        self.assertEqual(payload["error"]["code"], "STRUCTURE_BROKEN")

    def test_old_policy_proof_is_refused_under_the_new_policy(self):
        """A registration and its votes belong to exactly one policy generation."""
        chain = Chain()
        db = new_db()
        ingest(db, chain.base_case())
        code, ok = plan(db, chain.request(policy_version=1))
        self.assertEqual(code, 0, ok)
        code, payload = plan(db, chain.request(policy_version=2))
        self.assertEqual(payload["error"]["code"], "STRUCTURE_BROKEN")

        # A policy rotation re-registers the same edges under a new policy version,
        # but a verified edge id is immutable, so it must use fresh edge ids.
        rotated = chain.base_case(policy_version=2)
        rotated["edges"] = [
            {**edge("e1-v2", chain.a, chain.b, "cp-A", "cp-B", 11,
                    policy_version=2), "policy_version": 2},
            {**edge("e2-v2", chain.b, chain.c, "cp-B", "cp-C", 12,
                    policy_version=2), "policy_version": 2},
        ]
        rotated["votes"] = []
        ingest(db, rotated)
        # Policy-1 votes are bound to policy 1 and cannot sign the policy-2 edges.
        code, denied = plan(db, chain.request(policy_version=2))
        self.assertEqual(denied["error"]["code"], "INSUFFICIENT_VOTES")

        # Re-using a verified edge id with different content is refused outright.
        conflicting = chain.base_case(policy_version=2)
        payload = ingest(db, {"edges": [conflicting["edges"][0]]})
        self.assertEqual(payload["edges"]["rejected"][0]["code"],
                         "EDGE_REGISTRATION_CONFLICT")

        # The policy-1 request is unaffected by the rotation.
        code, still = plan(db, chain.request(policy_version=1))
        self.assertEqual(code, 0, still)
        self.assertEqual(still["plan"]["edge_ids"], ["e1", "e2"])

    def test_plan_matches_exhaustive_search_on_small_graphs(self):
        import random

        rng = random.Random(4242)
        for trial in range(5):
            db = new_db()
            base = {"000100": "a", "001000": "b", "010000": "c"}
            states = [base]
            order = sorted(base)
            for i in range(5):
                states.append(apply_patch(states[-1], {order[i % 3]: f"v{i}"}))
            case = {"checkpoints": [checkpoint(f"cp{i}", m, 10 + i)
                                    for i, m in enumerate(states)],
                    "edges": [], "votes": []}
            edges = []
            for i in range(1, len(states)):
                edges.append(edge(f"e{i:02d}", states[i - 1], states[i],
                                  f"cp{i - 1}", f"cp{i}", 10 + i))
            for i in range(2, len(states)):
                edges.append(edge(f"x{i:02d}", states[i - 2], states[i],
                                  f"cp{i - 2}", f"cp{i}", 10 + i))
            reviewers = [f"r{k}" for k in range(8)]
            votes = []
            for item in edges:
                for j, reviewer in enumerate(rng.sample(reviewers, 2)):
                    src = int(item["from"][2:])
                    dst = int(item["to"][2:])
                    votes.append(vote(f"v-{item['edge_id']}-{j}", item["edge_id"],
                                      states[src], states[dst], reviewer,
                                      f"inst-{reviewer}"))
            case["edges"] = edges
            case["votes"] = votes
            ingest(db, case)
            req = request("cp0", "cp5", ["000100", "010000"], states[0])
            code, payload = plan(db, req)

            conn = store.connect(str(db))
            try:
                world = store.load_world(conn)
            finally:
                conn.close()
            expected = brute_force_best(world, "cp0", "cp5", req["logical_clock"], 1)
            if expected is None:
                self.assertEqual(code, 2, payload)
                continue
            self.assertEqual(code, 0, payload)
            disclosed, hops, path, assignment = expected
            self.assertEqual(payload["plan"]["edge_ids"], list(path))
            self.assertEqual(payload["plan"]["disclosed_keys"], disclosed)
            got = tuple(sorted((v["hop"], v["category"], v["vote_id"])
                               for v in payload["plan"]["votes"]))
            self.assertEqual(got, assignment)


class GlobalChoiceTest(unittest.TestCase):
    """States that reach the same checkpoint with different consumed votes differ.

    The planner enumerates whole paths, so two partial plans that share a
    checkpoint but hold different consumed-vote sets are never merged.  These
    tests pin that down and also check the tie-break order of the objective.
    """

    def diamond(self):
        base = {"000100": "a", "001000": "b", "010000": "c", "100000": "d"}
        left = apply_patch(base, {"000100": "L"})
        right = apply_patch(base, {"001000": "R"})
        end = apply_patch(base, {"000100": "L", "001000": "R"})
        return base, left, right, end

    def test_cheaper_path_that_burns_the_suffix_reviewers_is_passed_over(self):
        """The cheapest path is infeasible, so the next one wins.

        Path B (e1, e2) revisits one key and discloses only one distinct key, but
        both of its hops can only be signed by the same two reviewers.  Path A
        discloses two keys yet is the cheapest *executable* path -- greedy per-hop
        or first-path selection would return the wrong answer.
        """
        base = {"000100": "a", "001000": "b", "010000": "c"}
        mid = apply_patch(base, {"000100": "X"})
        end = apply_patch(base, {"000100": "A"})
        side = apply_patch(base, {"000100": "A", "001000": "Y"})
        db = new_db()
        case = {
            "checkpoints": [checkpoint("cp-0", base, 10), checkpoint("cp-M", mid, 11),
                            checkpoint("cp-N", side, 11), checkpoint("cp-E", end, 12)],
            "edges": [
                edge("e1", base, mid, "cp-0", "cp-M", 11, keys=["000100"]),
                edge("e2", mid, end, "cp-M", "cp-E", 12, keys=["000100"]),
                edge("f1", base, side, "cp-0", "cp-N", 11, keys=["000100", "001000"]),
                edge("f2", side, end, "cp-N", "cp-E", 12, keys=["001000"]),
            ],
            "votes": [
                # e1 and e2 are only signable by bea/ben, who may sign once per request.
                vote("p1", "e1", base, mid, "bea", "i3"),
                vote("p2", "e1", base, mid, "ben", "i4"),
                vote("p3", "e2", mid, end, "bea", "i3"),
                vote("p4", "e2", mid, end, "ben", "i4"),
                vote("q1", "f1", base, side, "amy", "i1"),
                vote("q2", "f1", base, side, "ann", "i2"),
                vote("q3", "f2", side, end, "cid", "i5"),
                vote("q4", "f2", side, end, "cat", "i6"),
            ],
        }
        ingest(db, case)
        req = request("cp-0", "cp-E", [], base)
        req["s_keys"] = ["010000"]
        from solution import refimpl

        req["inventory"] = {"root": fmt(base),
                            "proof": refimpl.value_proof(base, ["010000"], DEPTH)}
        code, payload = plan(db, req)
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["plan"]["edge_ids"], ["f1", "f2"])
        self.assertEqual(payload["plan"]["disclosed_keys"], 2)
        self.assertEqual(payload["final_root"], fmt(end))

    def test_same_checkpoint_different_vote_sets_are_distinct_states(self):
        base, left, right, end = self.diamond()
        db = new_db()
        case = {
            "checkpoints": [checkpoint("cp-0", base, 10), checkpoint("cp-L", left, 11),
                            checkpoint("cp-R", right, 11), checkpoint("cp-E", end, 12)],
            "edges": [edge("e-L", base, left, "cp-0", "cp-L", 11, keys=["000100"]),
                      edge("e-R", base, right, "cp-0", "cp-R", 11, keys=["001000"]),
                      edge("f-L", left, end, "cp-L", "cp-E", 12, keys=["001000"]),
                      edge("f-R", right, end, "cp-R", "cp-E", 12, keys=["000100"])],
            # Both prefixes are signable by distinct reviewers; the suffix then picks
            # whichever is free.  Merging the two cp-L states would lose f-R.
            "votes": [vote("a1", "e-L", base, left, "amy", "i1"),
                      vote("a2", "e-L", base, left, "ann", "i2"),
                      vote("b1", "e-R", base, right, "bea", "i3"),
                      vote("b2", "e-R", base, right, "ben", "i4"),
                      vote("c1", "f-L", left, end, "cid", "i5"),
                      vote("c2", "f-L", left, end, "cat", "i6"),
                      vote("d1", "f-R", right, end, "amy", "i1"),
                      vote("d2", "f-R", right, end, "bea", "i3")],
        }
        ingest(db, case)
        req = request("cp-0", "cp-E", [], base)
        req["s_keys"] = ["100000"]
        from solution import refimpl

        req["inventory"] = {"root": fmt(base),
                            "proof": refimpl.value_proof(base, ["100000"], DEPTH)}
        code, payload = plan(db, req)
        self.assertEqual(code, 0, payload)
        # Both two-hop paths disclose two keys, so the edge-id sequence decides.
        self.assertEqual(payload["plan"]["edge_ids"], ["e-L", "f-L"])
        self.assertEqual(payload["plan"]["disclosed_keys"], 2)

    def test_equal_cost_paths_break_ties_by_edge_ids_then_vote_list(self):
        base = {"000100": "a", "001000": "b"}
        variant = apply_patch(base, {"000100": "A"})
        db = new_db()
        case = {
            "checkpoints": [checkpoint("cp-0", base, 10), checkpoint("cp-1", variant, 11)],
            "edges": [edge("e-b", base, variant, "cp-0", "cp-1", 11, keys=["000100"]),
                      edge("e-a", base, variant, "cp-0", "cp-1", 11, keys=["000100"])],
            "votes": [vote("z9", "e-a", base, variant, "amy", "i1"),
                      vote("z8", "e-a", base, variant, "ann", "i2"),
                      vote("z7", "e-b", base, variant, "bea", "i3"),
                      vote("z6", "e-b", base, variant, "ben", "i4")],
        }
        ingest(db, case)
        req = request("cp-0", "cp-1", [], base)
        req["s_keys"] = ["001000"]
        from solution import refimpl

        req["inventory"] = {"root": fmt(base),
                            "proof": refimpl.value_proof(base, ["001000"], DEPTH)}
        code, payload = plan(db, req)
        self.assertEqual(payload["plan"]["edge_ids"], ["e-a"])
        self.assertEqual([v["vote_id"] for v in payload["plan"]["votes"]], ["z8", "z9"])

    def test_rebase_must_succeed_for_the_chosen_path(self):
        # e2 was registered before cp-B's root was known to match; the plan must
        # refuse it if its proof does not rebase S to the end root.
        base = {"000100": "a", "001000": "b"}
        mid = apply_patch(base, {"000100": "A"})
        end = apply_patch(mid, {"001000": "B"})
        db = new_db()
        case = {
            "checkpoints": [checkpoint("cp-0", base, 10), checkpoint("cp-1", mid, 11),
                            checkpoint("cp-2", end, 12)],
            "edges": [edge("e1", base, mid, "cp-0", "cp-1", 11, keys=["000100"]),
                      edge("e2", mid, end, "cp-1", "cp-2", 12, keys=["001000"])],
            "votes": [vote("v1", "e1", base, mid, "amy", "i1"),
                      vote("v2", "e1", base, mid, "ann", "i2"),
                      vote("v3", "e2", mid, end, "bea", "i3"),
                      vote("v4", "e2", mid, end, "ben", "i4")],
        }
        ingest(db, case)
        req = request("cp-0", "cp-2", ["000100", "001000"], base)
        code, payload = plan(db, req)
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["final_root"], fmt(end))
        from solution import refimpl

        expected = refimpl.value_proof(end, ["000100", "001000"], DEPTH)
        self.assertEqual(payload["projection"], expected)


class JointSearchCrossCheckTest(unittest.TestCase):
    """Random DAGs where votes, not paths, decide the answer.

    The exhaustive oracle tries every path times every vote assignment; the joint
    search must agree on the objective tuple for every instance.
    """

    def test_random_vote_constrained_graphs(self):
        import random

        rng = random.Random(99)
        for trial in range(8):
            size = 5
            base = {"000100": "a", "001000": "b", "010000": "c"}
            states = [base]
            order = sorted(base)
            for i in range(size):
                states.append(apply_patch(states[-1], {order[i % 3]: f"t{i}"}))
            checkpoints = [checkpoint(f"cp{i}", m, 10 + i)
                           for i, m in enumerate(states)]
            edges = []
            for i in range(1, len(states)):
                edges.append(edge(f"e{i:02d}", states[i - 1], states[i],
                                  f"cp{i - 1}", f"cp{i}", 10 + i))
            for i in range(2, len(states)):
                edges.append(edge(f"x{i:02d}", states[i - 2], states[i],
                                  f"cp{i - 2}", f"cp{i}", 10 + i))
            # A deliberately small reviewer pool forces real conflicts.
            reviewers = [f"r{k}" for k in range(4)]
            votes = []
            for item in edges:
                src = int(item["from"][2:])
                dst = int(item["to"][2:])
                pair = rng.sample(reviewers, 2)
                for j, reviewer in enumerate(pair):
                    votes.append(vote(f"v-{item['edge_id']}-{j}", item["edge_id"],
                                      states[src], states[dst], reviewer,
                                      f"inst-{reviewer}"))
            db = new_db()
            ingest(db, {"checkpoints": checkpoints, "edges": edges, "votes": votes})
            req = request("cp0", f"cp{size}", ["000100", "010000"], states[0])
            code, payload = plan(db, req)
            conn = store.connect(str(db))
            try:
                world = store.load_world(conn)
            finally:
                conn.close()
            expected = brute_force_best(world, "cp0", f"cp{size}",
                                        req["logical_clock"], 1)
            if expected is None:
                self.assertEqual(code, 2, payload)
                continue
            self.assertEqual(code, 0, payload)
            disclosed, hops, path, assignment = expected
            self.assertEqual(payload["plan"]["edge_ids"], list(path))
            self.assertEqual(payload["plan"]["disclosed_keys"], disclosed)
            got = tuple(sorted((v["hop"], v["category"], v["vote_id"])
                               for v in payload["plan"]["votes"]))
            self.assertEqual(got, assignment)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
