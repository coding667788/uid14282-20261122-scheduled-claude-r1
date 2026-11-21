"""Tests for the sparse Merkle primitives and the offline proof commands.

The reference implementation in :mod:`solution.refimpl` builds complete small
trees, so every assertion here is checked against an independent full computation
that shares only the hash primitives.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import json
import unittest

from solution import refimpl
from solution.core import (
    ArchiveError,
    boundary,
    change_kind,
    empty_node,
    value_hash,
)
from solution.merkle import Scene, cite_text
from solution.proofs import (
    handle_merge,
    handle_proof_rebase,
    handle_split_verify,
    handle_verify,
)

DEPTH = 5


def roots(old, new, depth=DEPTH):
    return refimpl.fmt_root(old, depth), refimpl.fmt_root(new, depth)


def keys_of(*mappings):
    return sorted({k for m in mappings for k in m})


class VerifyTest(unittest.TestCase):
    def test_absent_and_empty_string_are_different(self):
        old = {"00101": ""}
        new = {"00101": None}
        self.assertNotEqual(value_hash(""), value_hash(None))
        case = {
            "old_root": refimpl.fmt_root(old, DEPTH),
            "new_root": refimpl.fmt_root(new, DEPTH),
            "proof": refimpl.dual_proof(old, new, ["00101"], DEPTH),
        }
        result = handle_verify(case)
        self.assertTrue(result["ok"])
        self.assertEqual(result["keys"][0]["kind"], "delete")
        self.assertEqual(result["counts"]["delete"], 1)

    def test_absent_leaf_equals_empty_subtree(self):
        # An all-absent key hashes to the canonical empty digest, so a full tree
        # over an empty map equals the empty root.
        self.assertEqual(refimpl.root({}, 3), empty_node(3))
        self.assertEqual(empty_node(0), value_hash(None))

    def test_insert_update_delete_classification(self):
        old = {"00010": "keep", "00100": "old", "01000": "gone"}
        new = {"00010": "keep", "00100": "new", "01100": "fresh"}
        case = {
            "old_root": refimpl.fmt_root(old, DEPTH),
            "new_root": refimpl.fmt_root(new, DEPTH),
            "proof": refimpl.dual_proof(old, new, keys_of(old, new), DEPTH),
        }
        result = handle_verify(case)
        kinds = {row["key"]: row["kind"] for row in result["keys"]}
        self.assertEqual(kinds, {"00010": "unchanged", "00100": "update",
                                 "01000": "delete", "01100": "insert"})
        self.assertEqual(result["counts"], {"insert": 1, "delete": 1, "update": 1,
                                            "unchanged": 1})

    def test_change_outside_audited_keys_breaks_root_check(self):
        old = {"00100": "a", "01000": "b"}
        new = {"00100": "a", "01000": "C"}
        # Audit only 00100: 01000 changed outside the audited set, so the shared
        # branch digest cannot restore both roots.
        with self.assertRaises(ValueError):
            refimpl.dual_proof(old, new, ["00100"], DEPTH)
        crafted = refimpl.dual_proof(old, new, ["00100"], DEPTH, allow_unsafe=True)
        case = {"old_root": refimpl.fmt_root(old, DEPTH),
                "new_root": refimpl.fmt_root(new, DEPTH), "proof": crafted}
        with self.assertRaises(ArchiveError) as caught:
            handle_verify(case)
        self.assertEqual(caught.exception.code, "ROOT_MISMATCH")

    def test_forged_branch_digest_is_rejected(self):
        """A citation that carries the wrong digest must break the root recovery."""
        old = {"00100": "a", "01000": "x"}
        new = {"00100": "b", "01000": "x"}
        proof = refimpl.dual_proof(old, new, ["00100"], DEPTH)
        forged = json.loads(json.dumps(proof))
        for cite in forged["citations"]:
            if cite["prefix"] == "01":
                cite["hash"] = "sha256:" + "9f" * 32
        with self.assertRaises(ArchiveError) as caught:
            handle_verify({"old_root": refimpl.fmt_root(old, DEPTH),
                           "new_root": refimpl.fmt_root(new, DEPTH), "proof": forged})
        self.assertEqual(caught.exception.code, "ROOT_MISMATCH")

    def test_wrong_trusted_root_is_rejected(self):
        old = {"00100": "a"}
        new = {"00100": "b"}
        case = {
            "old_root": refimpl.fmt_root(new, DEPTH),
            "new_root": refimpl.fmt_root(new, DEPTH),
            "proof": refimpl.dual_proof(old, new, ["00100"], DEPTH),
        }
        with self.assertRaises(ArchiveError) as caught:
            handle_verify(case)
        self.assertEqual(caught.exception.code, "ROOT_MISMATCH")

    def test_duplicate_citation_is_rejected(self):
        old = {"00100": "a"}
        new = {"00100": "b"}
        proof = refimpl.dual_proof(old, new, ["00100"], DEPTH)
        proof["citations"].append(dict(proof["citations"][0]))
        with self.assertRaises(ArchiveError) as caught:
            handle_verify({"old_root": refimpl.fmt_root(old, DEPTH),
                           "new_root": refimpl.fmt_root(new, DEPTH), "proof": proof})
        self.assertEqual(caught.exception.code, "DUP_CITE")

    def test_extra_citation_is_rejected(self):
        # The boundary always tiles the complement of the induced tree, so any extra
        # prefix either contains an audited key, covers a leaf, or nests under a
        # citation -- all of which must be refused.
        old = {"00100": "a"}
        new = {"00100": "b"}
        for extra in ("11", "0010", "001", "00100"):
            proof = refimpl.dual_proof(old, new, ["00100"], DEPTH)
            proof["citations"].append({"prefix": extra, "hash": "empty"})
            with self.assertRaises(ArchiveError) as caught:
                handle_verify({"old_root": refimpl.fmt_root(old, DEPTH),
                               "new_root": refimpl.fmt_root(new, DEPTH), "proof": proof})
            self.assertIn(caught.exception.code,
                          {"EXTRA_CITE", "PARENT_CHILD_OVERLAP", "COVERS_LEAF", "DUP_CITE"})

    def test_missing_citation_is_rejected(self):
        old = {"00100": "a"}
        new = {"00100": "b"}
        proof = refimpl.dual_proof(old, new, ["00100"], DEPTH)
        proof["citations"].pop(0)
        with self.assertRaises(ArchiveError) as caught:
            handle_verify({"old_root": refimpl.fmt_root(old, DEPTH),
                           "new_root": refimpl.fmt_root(new, DEPTH), "proof": proof})
        self.assertEqual(caught.exception.code, "MISSING_BOUNDARY")

    def test_citation_covering_a_leaf_is_rejected(self):
        old = {"00100": "a"}
        new = {"00100": "b"}
        proof = refimpl.dual_proof(old, new, ["00100"], DEPTH)
        proof["citations"].append({"prefix": "00100", "hash": "empty"})
        with self.assertRaises(ArchiveError) as caught:
            handle_verify({"old_root": refimpl.fmt_root(old, DEPTH),
                           "new_root": refimpl.fmt_root(new, DEPTH), "proof": proof})
        self.assertEqual(caught.exception.code, "COVERS_LEAF")

    def test_parent_child_citation_overlap_is_rejected(self):
        old = {"00100": "a"}
        new = {"00100": "b"}
        proof = refimpl.dual_proof(old, new, ["00100"], DEPTH)
        proof["citations"].append({"prefix": "001", "hash": "empty"})
        with self.assertRaises(ArchiveError) as caught:
            handle_verify({"old_root": refimpl.fmt_root(old, DEPTH),
                           "new_root": refimpl.fmt_root(new, DEPTH), "proof": proof})
        self.assertEqual(caught.exception.code, "PARENT_CHILD_OVERLAP")

    def test_policy_direction_and_prefix(self):
        old = {"00010": None, "01100": "x"}
        new = {"00010": "added", "01100": "y"}
        base = {"old_root": refimpl.fmt_root(old, DEPTH),
                "new_root": refimpl.fmt_root(new, DEPTH),
                "proof": refimpl.dual_proof(old, new, keys_of(old, new), DEPTH)}
        with self.assertRaises(ArchiveError) as caught:
            handle_verify({**base, "policy": {"allow_insert": False}})
        self.assertEqual(caught.exception.code, "POLICY_INSERT_FORBIDDEN")
        with self.assertRaises(ArchiveError) as caught:
            handle_verify({**base, "policy": {"allowed_prefixes": ["011"]}})
        self.assertEqual(caught.exception.code, "PREFIX_FORBIDDEN")
        with self.assertRaises(ArchiveError) as caught:
            handle_verify({**base, "policy": {"allow_update": False}})
        self.assertEqual(caught.exception.code, "POLICY_UPDATE_FORBIDDEN")
        ok = handle_verify({**base, "policy": {"allowed_prefixes": ["0001", "011"]}})
        self.assertTrue(ok["ok"])

    def test_declared_direction_mismatch(self):
        old = {"00100": "a"}
        new = {"00100": "b"}
        case = {"old_root": refimpl.fmt_root(old, DEPTH),
                "new_root": refimpl.fmt_root(new, DEPTH),
                "proof": refimpl.dual_proof(old, new, ["00100"], DEPTH),
                "declared": [{"key": "00100", "kind": "insert"}]}
        with self.assertRaises(ArchiveError) as caught:
            handle_verify(case)
        self.assertEqual(caught.exception.code, "DECLARED_KIND_MISMATCH")

    def test_declared_key_not_in_proof(self):
        old = {"00100": "a"}
        new = {"00100": "b"}
        case = {"old_root": refimpl.fmt_root(old, DEPTH),
                "new_root": refimpl.fmt_root(new, DEPTH),
                "proof": refimpl.dual_proof(old, new, ["00100"], DEPTH),
                "declared": [{"key": "00100", "kind": "update"},
                             {"key": "11111", "kind": "unchanged"}]}
        with self.assertRaises(ArchiveError) as caught:
            handle_verify(case)
        self.assertEqual(caught.exception.code, "DECLARED_KEY_UNPROVEN")

    def test_deep_key_without_full_tree(self):
        # A single depth-128 proof must recover the root without materialising 2^128
        # nodes: the scene walks only the induced path.
        depth = 128
        key = "1" * depth
        scene = Scene(depth, 2)
        scene.add_leaf(key, [value_hash("deep"), value_hash("deeper")])
        old_root, new_root = scene.roots()
        proof = refimpl_cites(scene, [key])
        result = handle_verify({"old_root": fmt(old_root), "new_root": fmt(new_root),
                                "proof": proof})
        self.assertEqual(result["depth"], 128)
        self.assertEqual(len(result["citations"]), depth)


def fmt(digest: str) -> str:
    return "sha256:" + digest


def refimpl_cites(scene: Scene, keys):
    """Minimal dual proof straight from a scene, for depths a full tree cannot reach."""
    cites = []
    for prefix in boundary(keys):
        claims = scene.claims(prefix)
        cites.append({"prefix": prefix, "hash": cite_text(claims[0], prefix, scene.depth)})
    return {"leaves": [{"key": k, "old_value": "deep", "new_value": "deeper"} for k in keys],
            "citations": cites}


class MergeTest(unittest.TestCase):
    """Both inputs must audit every changed key; they may audit different extras."""

    OLD = {"00010": "a", "01000": "x", "01010": "y", "10000": "q"}
    NEW = {"00010": "A", "01000": "x", "01010": "y", "10000": "q"}

    def base(self):
        return {"old_root": refimpl.fmt_root(self.OLD, DEPTH),
                "new_root": refimpl.fmt_root(self.NEW, DEPTH)}

    def test_branch_of_one_proof_is_expanded_by_the_other(self):
        left = refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01000"], DEPTH)
        right = refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01010"], DEPTH)
        left_cites = {c["prefix"] for c in left["citations"]}
        right_keys = {"01010"}
        expanded = [p for p in left_cites if any(k.startswith(p) for k in right_keys)]
        self.assertTrue(expanded, "expected a coarse branch in the first proof")
        result = handle_merge({**self.base(), "proofs": [left, right]})
        merged_cites = {c["prefix"] for c in result["proof"]["citations"]}
        for prefix in expanded:
            self.assertNotIn(prefix, merged_cites)

    def test_merged_proof_is_minimal_and_matches_union_boundary(self):
        first = refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01000"], DEPTH)
        second = refimpl.dual_proof(self.OLD, self.NEW, ["00010", "10000"], DEPTH)
        result = handle_merge({**self.base(), "proofs": [first, second]})
        union = ["00010", "01000", "10000"]
        self.assertEqual([c["prefix"] for c in result["proof"]["citations"]],
                         boundary(union))
        self.assertEqual(result["merged"]["audited"], 3)
        self.assertEqual(result["merged"]["counts"], {"insert": 0, "delete": 0,
                                                      "update": 1, "unchanged": 2})

    def test_merge_is_order_independent(self):
        proofs = [refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01000"], DEPTH),
                  refimpl.dual_proof(self.OLD, self.NEW, ["00010", "10000"], DEPTH),
                  refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01010"], DEPTH)]
        forward = handle_merge({**self.base(), "proofs": proofs})
        backward = handle_merge({**self.base(), "proofs": list(reversed(proofs))})
        shuffled = handle_merge({**self.base(),
                                 "proofs": [proofs[1], proofs[0], proofs[2]]})
        self.assertEqual(forward["proof"], backward["proof"])
        self.assertEqual(forward["proof"], shuffled["proof"])

    def test_overlapping_leaves_must_agree(self):
        good = refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01000"], DEPTH)
        bad = json.loads(json.dumps(good))
        bad["leaves"][0]["new_value"] = "tampered"
        with self.assertRaises(ArchiveError) as caught:
            handle_merge({**self.base(), "proofs": [good, bad]})
        self.assertIn(caught.exception.code, {"ROOT_MISMATCH", "LEAF_CONFLICT"})

    def test_expanded_branch_digest_must_match(self):
        left = refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01000"], DEPTH)
        right = refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01010"], DEPTH)
        expanded = [c for c in left["citations"]
                    if any("01010".startswith(c["prefix"]) for _ in (0,))]
        self.assertTrue(expanded)
        for cite in expanded:
            cite["hash"] = "sha256:" + "ab" * 32
        with self.assertRaises(ArchiveError) as caught:
            handle_merge({**self.base(), "proofs": [left, right]})
        self.assertIn(caught.exception.code,
                      {"ROOT_MISMATCH", "EXPANSION_MISMATCH", "CITE_CONFLICT"})

    def test_single_proof_merge_is_refused(self):
        with self.assertRaises(ArchiveError) as caught:
            handle_merge({**self.base(),
                          "proofs": [refimpl.dual_proof(self.OLD, self.NEW,
                                                        ["00010"], DEPTH)]})
        self.assertEqual(caught.exception.code, "MERGE_ARITY")

    def test_merge_keeps_trusted_roots_and_policy(self):
        proofs = [refimpl.dual_proof(self.OLD, self.NEW, ["00010", "01000"], DEPTH),
                  refimpl.dual_proof(self.OLD, self.NEW, ["00010", "10000"], DEPTH)]
        result = handle_merge({**self.base(), "proofs": proofs,
                               "policy": {"allowed_prefixes": ["0001"]}})
        self.assertEqual(result["old_root"], self.base()["old_root"])
        self.assertEqual(result["new_root"], self.base()["new_root"])
        self.assertTrue(result["checks"]["inputs"].startswith("each proof verified"))


class RebaseTest(unittest.TestCase):
    def build(self, n_hops=3):
        a = {"000100": "a", "010000": "x", "010100": "y", "100000": "p"}
        b = refimpl.apply_patch(a, {"000100": "A", "010000": "x2"})
        c = refimpl.apply_patch(b, {"010000": "x3", "010100": "Y"})
        d = refimpl.apply_patch(c, {"000100": "a"})
        states = [a, b, c, d]
        s = ["000100", "010000", "100000"]
        hops = []
        for i in range(n_hops):
            old, new = states[i], states[i + 1]
            keys = sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
            hops.append({"old_root": refimpl.fmt_root(old, 6),
                         "new_root": refimpl.fmt_root(new, 6),
                         "version": i + 1,
                         "proof": refimpl.dual_proof(old, new, keys, 6),
                         "policy": {"allowed_prefixes": ["0", "1"]}})
        case = {"inventory": {"root": refimpl.fmt_root(a, 6),
                              "proof": refimpl.value_proof(a, s, 6)},
                "s_keys": s, "chain": hops}
        return case, states

    def test_projection_tracks_each_hop(self):
        case, states = self.build()
        result = handle_proof_rebase(case)
        self.assertTrue(result["ok"])
        rows = {r["key"]: r for r in result["keys"]}
        self.assertEqual(rows["000100"]["value"], "a")
        self.assertEqual(rows["000100"]["first_change_hop"], 1)
        self.assertEqual(rows["000100"]["last_change_hop"], 3)
        self.assertEqual(rows["010000"]["value"], "x3")
        self.assertEqual(rows["010000"]["first_change_hop"], 1)
        self.assertEqual(rows["010000"]["last_change_hop"], 2)
        self.assertEqual(rows["100000"]["first_change_hop"], None)
        self.assertEqual(result["final_root"], refimpl.fmt_root(states[3], 6))

    def test_history_is_kept_when_value_returns_to_the_old_digest(self):
        case, _ = self.build()
        result = handle_proof_rebase(case)
        row = next(r for r in result["keys"] if r["key"] == "000100")
        self.assertEqual([c["hop"] for c in row["changes"]], [1, 3])
        self.assertEqual(row["initial"], row["value"])

    def test_final_proof_verifies_against_final_root(self):
        case, states = self.build()
        result = handle_proof_rebase(case)
        proof = result["proof"]
        final = states[3]
        s = ["000100", "010000", "100000"]
        expected = refimpl.value_proof(final, s, 6)
        self.assertEqual(sorted(proof["citations"], key=lambda c: c["prefix"]),
                         sorted(expected["citations"], key=lambda c: c["prefix"]))

    def test_s_and_t_disjoint_still_updates_branches(self):
        a = {"000100": "a", "100000": "p"}
        b = refimpl.apply_patch(a, {"011110": "new"})
        s = ["000100", "100000"]
        case = {"inventory": {"root": refimpl.fmt_root(a, 6),
                              "proof": refimpl.value_proof(a, s, 6)},
                "s_keys": s,
                "chain": [{"old_root": refimpl.fmt_root(a, 6),
                           "new_root": refimpl.fmt_root(b, 6),
                           "version": 1,
                           "proof": refimpl.dual_proof(a, b, ["011110"], 6)}]}
        result = handle_proof_rebase(case)
        self.assertEqual(result["audited_changed"], 0)
        self.assertEqual(result["disclosed_keys"], 3)
        self.assertEqual(result["final_root"], refimpl.fmt_root(b, 6))
        self.assertEqual([r["value"] for r in result["keys"]], ["a", "p"])

    def test_broken_chain_emits_no_final_proof(self):
        case, _ = self.build()
        case["chain"][1]["old_root"] = case["chain"][0]["old_root"]
        with self.assertRaises(ArchiveError) as caught:
            handle_proof_rebase(case)
        self.assertEqual(caught.exception.code, "CHAIN_BROKEN")
        self.assertNotIn("proof", getattr(caught.exception, "extra", {}))

    def test_version_order_must_increase(self):
        case, _ = self.build()
        case["chain"][2]["version"] = 1
        with self.assertRaises(ArchiveError) as caught:
            handle_proof_rebase(case)
        self.assertEqual(caught.exception.code, "VERSION_ORDER")

    def test_incomplete_hop_is_refused(self):
        case, _ = self.build()
        case["chain"][1]["proof"]["citations"].pop()
        with self.assertRaises(ArchiveError) as caught:
            handle_proof_rebase(case)
        self.assertIn(caught.exception.code, {"MISSING_BOUNDARY", "ROOT_MISMATCH"})

    def test_old_value_bound_twice_must_agree(self):
        a = {"000100": "a", "100000": "p"}
        b = refimpl.apply_patch(a, {"000100": "A"})
        s = ["000100"]
        chain = [{"old_root": refimpl.fmt_root(a, 6),
                  "new_root": refimpl.fmt_root(b, 6),
                  "version": 1,
                  "proof": refimpl.dual_proof(a, b, ["000100"], 6)}]
        # Second hop claims the old value of 000100 was "wrong", contradicting the
        # inventory and the first hop; the hop's own roots are shifted accordingly.
        wrong_old = {"000100": "wrong"}
        wrong_new = {"000100": "Z"}
        chain.append({"old_root": refimpl.fmt_root(wrong_old, 6),
                      "new_root": refimpl.fmt_root(wrong_new, 6),
                      "version": 2,
                      "proof": refimpl.dual_proof(wrong_old, wrong_new, ["000100"], 6)})
        case = {"inventory": {"root": refimpl.fmt_root(a, 6),
                              "proof": refimpl.value_proof(a, s, 6)},
                "s_keys": s, "chain": chain}
        with self.assertRaises(ArchiveError) as caught:
            handle_proof_rebase(case)
        self.assertIn(caught.exception.code, {"CHAIN_BROKEN", "OLD_VALUE_CONFLICT"})

    def test_nested_branches_partially_expanded(self):
        a = {"000101": "a", "000110": "b", "001000": "c"}
        b = refimpl.apply_patch(a, {"000101": "A"})
        s = ["001000"]
        case = {"inventory": {"root": refimpl.fmt_root(a, 6),
                              "proof": refimpl.value_proof(a, s, 6)},
                "s_keys": s,
                "chain": [{"old_root": refimpl.fmt_root(a, 6),
                           "new_root": refimpl.fmt_root(b, 6),
                           "version": 1,
                           "proof": refimpl.dual_proof(a, b, ["000101", "000110"], 6)}]}
        result = handle_proof_rebase(case)
        self.assertEqual(result["final_root"], refimpl.fmt_root(b, 6))
        # S sits at 001000; the emitted boundary for S is exactly what a plain
        # single-key proof needs, computed against the *final* tree.
        self.assertEqual([c["prefix"] for c in result["proof"]["citations"]],
                         boundary(["001000"]))
        self.assertEqual(result["proof"]["leaves"][0]["value"], "c")


class SplitVerifyTest(unittest.TestCase):
    def make_case(self, shards, proof=None, old=None, new=None):
        old = old or {"000100": "a", "010000": "x"}
        new = new or {"000100": "A", "010000": "x"}
        proof = proof or refimpl.dual_proof(old, new, ["000100", "010000"], 6)
        return {"old_root": refimpl.fmt_root(old, 6),
                "new_root": refimpl.fmt_root(new, 6),
                "proof": proof, "shards": shards}, proof

    def test_shards_assemble_regardless_of_order(self):
        old = {"000100": "a", "010000": "x"}
        new = {"000100": "A", "010000": "x"}
        proof = refimpl.dual_proof(old, new, ["000100", "010000"], 6)
        shards = [{"shard_id": "b", "citations": proof["citations"][1::2]},
                  {"shard_id": "a", "citations": proof["citations"][0::2]}]
        case, _ = self.make_case(shards, proof, old, new)
        result = handle_split_verify(case)
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidence"]["citations"], len(proof["citations"]))

    def test_missing_shard_is_reported(self):
        old = {"000100": "a", "010000": "x"}
        new = {"000100": "A", "010000": "x"}
        proof = refimpl.dual_proof(old, new, ["000100", "010000"], 6)
        shards = [{"shard_id": "a", "citations": proof["citations"][:2]}]
        case, _ = self.make_case(shards, proof, old, new)
        with self.assertRaises(ArchiveError) as caught:
            handle_split_verify(case)
        self.assertEqual(caught.exception.code, "MISSING_SHARD")

    def test_extra_shard_prefix_is_reported(self):
        old = {"000100": "a", "010000": "x"}
        new = {"000100": "A", "010000": "x"}
        proof = refimpl.dual_proof(old, new, ["000100", "010000"], 6)
        shards = [{"shard_id": "a", "citations": proof["citations"]},
                  {"shard_id": "b", "citations": [{"prefix": "111", "hash": "empty"}]}]
        case, _ = self.make_case(shards, proof, old, new)
        with self.assertRaises(ArchiveError) as caught:
            handle_split_verify(case)
        self.assertEqual(caught.exception.code, "EXTRA_SHARD_PREFIX")

    def test_conflicting_shard_is_reported(self):
        old = {"000100": "a", "010000": "x"}
        new = {"000100": "A", "010000": "x"}
        proof = refimpl.dual_proof(old, new, ["000100", "010000"], 6)
        bad = dict(proof["citations"][0])
        bad["hash"] = "sha256:" + "cd" * 32
        shards = [{"shard_id": "a", "citations": proof["citations"]},
                  {"shard_id": "b", "citations": [bad]}]
        case, _ = self.make_case(shards, proof, old, new)
        with self.assertRaises(ArchiveError) as caught:
            handle_split_verify(case)
        self.assertEqual(caught.exception.code, "SHARD_CONFLICT")

    def test_shard_bound_to_other_roots_is_refused(self):
        old = {"000100": "a", "010000": "x"}
        new = {"000100": "A", "010000": "x"}
        proof = refimpl.dual_proof(old, new, ["000100", "010000"], 6)
        shards = [{"shard_id": "a", "citations": proof["citations"],
                   "old_root": refimpl.fmt_root(new, 6),
                   "new_root": refimpl.fmt_root(old, 6)}]
        case, _ = self.make_case(shards, proof, old, new)
        with self.assertRaises(ArchiveError) as caught:
            handle_split_verify(case)
        self.assertEqual(caught.exception.code, "SHARD_ROOT_MISMATCH")

    def test_duplicate_shard_must_agree(self):
        old = {"000100": "a", "010000": "x"}
        new = {"000100": "A", "010000": "x"}
        proof = refimpl.dual_proof(old, new, ["000100", "010000"], 6)
        shards = [{"shard_id": "a", "citations": proof["citations"]},
                  {"shard_id": "b", "citations": proof["citations"]}]
        case, _ = self.make_case(shards, proof, old, new)
        result = handle_split_verify(case)
        self.assertEqual(result["evidence"]["shared"], len(proof["citations"]))


class CrossCheckTest(unittest.TestCase):
    """Full-tree oracle: every sparse root must equal the complete computation."""

    def test_random_small_trees(self):
        import random

        rng = random.Random(20261122)
        depth = 4
        universe = [format(i, f"0{depth}b") for i in range(1 << depth)]
        values = ["", "a", "bb", "ccc", "é", "\U0001f600", None]
        for _ in range(40):
            old = {k: rng.choice(values) for k in rng.sample(universe, rng.randint(1, 5))
                   if rng.random() < 0.8}
            old = {k: v for k, v in old.items() if v is not None}
            new = dict(old)
            for k in rng.sample(universe, rng.randint(1, 4)):
                new[k] = rng.choice(values)
            new = {k: v for k, v in new.items() if v is not None}
            changed = sorted({k for k in set(old) | set(new) if old.get(k) != new.get(k)})
            audited = sorted(set(changed) | set(rng.sample(universe, rng.randint(0, 2))))
            try:
                proof = refimpl.dual_proof(old, new, audited, depth)
            except ValueError:
                continue  # a change outside the audited set cannot be proven
            case = {"old_root": refimpl.fmt_root(old, depth),
                    "new_root": refimpl.fmt_root(new, depth), "proof": proof}
            result = handle_verify(case)
            self.assertTrue(result["verified"])
            for row in result["keys"]:
                self.assertEqual(row["kind"], change_kind(old.get(row["key"]),
                                                          new.get(row["key"])))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
