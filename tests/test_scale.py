"""Scale test: 150 edges, 30 review subjects, joint path/vote search.

A publication may use each review subject at most once, so with 30 candidate
subjects a request can cover at most 15 hops that each need two reviews.  The
fixture therefore asks for a target reachable in a few hops, and also checks
that an over-long request is refused for the *right* reason rather than merely
being slow.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import random
import time
import unittest

from solution import refimpl
from solution.core import ArchiveError
from solution.ledger import plan_case
from solution.ledger_model import Checkpoint, Edge, Vote, World
from tests.support import fmt

DEPTH = 8
UNIVERSE = [format(i, "08b") for i in range(6)]
SUBJECTS = 30


def build_world(seed: int = 7, edges_target: int = 150, depth: int = DEPTH):
    rng = random.Random(seed)
    base = {k: f"v{i}" for i, k in enumerate(UNIVERSE)}
    states = [base]
    while len(states) < edges_target + 1:
        key = UNIVERSE[rng.randrange(len(UNIVERSE))]
        states.append(refimpl.apply_patch(states[-1], {key: f"n{len(states)}"}))

    world = World()
    for i, mapping in enumerate(states):
        world.checkpoints[f"c{i}"] = Checkpoint(
            f"c{i}", refimpl.root(mapping, depth), i + 1, "", 1)

    def add_edge(edge_id: str, i: int, j: int) -> None:
        keys = sorted(k for k in UNIVERSE if states[i].get(k) != states[j].get(k))
        if not keys:
            keys = [UNIVERSE[0]]
        proof = refimpl.dual_proof(states[i], states[j], keys, depth)
        world.edges[edge_id] = Edge(
            edge_id, f"c{i}", f"c{j}", j + 1, 1, proof,
            tuple(c["prefix"] for c in proof["citations"]), ("privacy",), "cold-archive")

    count = 0
    for i in range(1, len(states)):
        add_edge(f"e{i:03d}", i - 1, i)
        count += 1
    while count < edges_target:
        i = rng.randrange(0, len(states) - 3)
        span = rng.randrange(2, 5)
        add_edge(f"s{count:03d}", i, min(i + span, len(states) - 1))
        count += 1

    # Two votes per edge, from distinct subjects and distinct institutions, drawn
    # from a pool of exactly ``SUBJECTS`` people across five institutions.
    n = 0
    for edge in sorted(world.edges.values(), key=lambda e: e.edge_id):
        for _slot in range(2):
            vid = f"v{n:04d}"
            subject = n % SUBJECTS
            n += 1
            world.votes[vid] = Vote(
                vid, edge.edge_id, "privacy", f"r{subject}", f"i{subject % 5}",
                1, world.checkpoints[edge.from_id].root,
                world.checkpoints[edge.to_id].root, 0, 10_000)
    return world, states


def inventory_case(states, end: str, s_keys, depth: int = DEPTH):
    return {
        "start_checkpoint": "c0", "end_checkpoint": end, "policy_version": 1,
        "logical_clock": 5, "archive_use": "cold-archive", "s_keys": s_keys,
        "inventory": {"root": fmt(states[0], depth),
                      "proof": refimpl.value_proof(states[0], s_keys, depth)},
        "max_paths": 20000,
    }


class ScaleTest(unittest.TestCase):
    def test_planner_handles_150_edges_quickly(self):
        world, states = build_world()
        self.assertGreaterEqual(len(world.edges), 150)
        req = inventory_case(states, "c12", [UNIVERSE[1]])
        started = time.time()
        result = plan_case(world, req)
        elapsed = time.time() - started
        self.assertLess(elapsed, 20.0, f"planning took {elapsed:.1f}s")
        self.assertEqual(result["final_root"], fmt(states[12], DEPTH))
        self.assertEqual(result["plan"]["edge_ids"][0], "e001")
        self.assertEqual(result["plan"]["edge_ids"][-1], "e012")
        self.assertEqual(result["plan"]["hops_count"], 12)
        per_slot: dict[tuple[int, str], set[str]] = {}
        for item in result["plan"]["votes"]:
            per_slot.setdefault((item["hop"], item["category"]), set()).add(item["subject"])
        for subjects in per_slot.values():
            self.assertEqual(len(subjects), 2)

    def test_chosen_path_rebases_independently(self):
        world, states = build_world(seed=11, edges_target=150)
        req = inventory_case(states, "c9", [UNIVERSE[2]])
        result = plan_case(world, req)
        expected = refimpl.value_proof(states[9], [UNIVERSE[2]], DEPTH)
        self.assertEqual(result["projection"], expected)

    def test_oversized_request_fails_for_lack_of_reviewers(self):
        world, states = build_world()
        req = inventory_case(states, "c150", [UNIVERSE[1]])
        started = time.time()
        with self.assertRaises(ArchiveError) as caught:
            plan_case(world, req)
        self.assertLess(time.time() - started, 20.0)
        self.assertEqual(caught.exception.code, "INSUFFICIENT_VOTES")

    def test_shortcut_path_is_used_when_it_is_cheaper(self):
        world, states = build_world(seed=3, edges_target=150)
        req = inventory_case(states, "c4", [UNIVERSE[1]])
        result = plan_case(world, req)
        self.assertLessEqual(result["plan"]["hops_count"], 4)
        self.assertLessEqual(result["plan"]["disclosed_keys"], 4)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
