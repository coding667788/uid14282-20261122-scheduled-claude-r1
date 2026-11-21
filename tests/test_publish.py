"""Publication tests: atomicity, idempotency, concurrency, revocation and views."""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import json
import tempfile
import time
import unittest
from pathlib import Path

from solution.refimpl import apply_patch

from tests.support import checkpoint, edge, fmt, run_cli, vote
from tests.test_ledger import Chain, ingest, new_db, plan, popen, publish, release, wait_for


def planned_plan(chain, db, **kwargs):
    code, payload = plan(db, chain.request(**kwargs))
    assert code == 0, payload
    return payload["plan"]


class PublishTest(unittest.TestCase):
    def setUp(self):
        self.chain = Chain()
        self.db = new_db()
        ingest(self.db, self.chain.base_case())

    def request_with_plan(self, request_id="req-1", start="cp-A", end="cp-C", at=None):
        req = self.chain.request(start=start, end=end)
        plan_payload = planned_plan(self.chain, self.db)
        req["plan"] = {"edge_ids": plan_payload["edge_ids"],
                       "votes": plan_payload["votes"]}
        req["request_id"] = request_id
        return req

    def test_publish_commits_and_consumes_votes(self):
        req = self.request_with_plan()
        code, payload = publish(self.db, req)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["verified"])
        self.assertEqual(payload["receipt"]["end_checkpoint"], "cp-C")
        self.assertEqual(payload["receipt"]["root"], fmt(self.chain.c))
        self.assertEqual(payload["receipt"]["consumed_votes"], ["v1", "v2", "v3", "v4"])
        code, status = run_cli("ledger-status", {}, db=self.db)
        self.assertEqual(status["consumed"], ["v1", "v2", "v3", "v4"])

    def test_idempotent_repeat_returns_the_same_receipt(self):
        req = self.request_with_plan()
        first = publish(self.db, req)[1]
        second = publish(self.db, req)[1]
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["receipt"], second["receipt"])
        code, status = run_cli("ledger-status", {}, db=self.db)
        self.assertEqual(status["publications"], 1)

    def test_same_request_id_with_different_content_is_refused(self):
        req = self.request_with_plan()
        publish(self.db, req)
        changed = json.loads(json.dumps(req))
        changed["logical_clock"] = 11
        code, payload = publish(self.db, changed)
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["code"], "IDEMPOTENCY_CONFLICT")

    def test_vote_consumed_cannot_be_used_by_a_later_publication(self):
        req = self.request_with_plan(request_id="r1")
        publish(self.db, req)
        # A follow-on request cannot reuse the consumed votes.
        follow = self.chain.request(start="cp-C", end="cp-C")
        follow["request_id"] = "r2"
        follow["plan"] = {"edge_ids": ["e1"], "votes": [
            {"hop": 1, "category": "privacy", "vote_id": "v1"},
            {"hop": 1, "category": "privacy", "vote_id": "v2"}]}
        code, payload = publish(self.db, follow)
        self.assertEqual(payload["error"]["code"], "STRUCTURE_BROKEN")

    def test_revoked_vote_blocks_publication(self):
        req = self.request_with_plan()
        code, payload = run_cli("ledger-revoke", {"vote_id": "v2",
                                                 "reason": "conflict of interest"},
                                db=self.db)
        self.assertEqual(code, 0, payload)
        code, payload = publish(self.db, req)
        self.assertEqual(payload["error"]["code"], "VOTE_REVOKED")

    def test_request_must_start_at_the_previous_receipt(self):
        req = self.request_with_plan(request_id="r1")
        publish(self.db, req)
        # cp-B is not the previous receipt's end (cp-C), and equal roots do not help.
        b2 = apply_patch(self.chain.c, {"001000": "z"})
        ingest(self.db, {"checkpoints": [checkpoint("cp-D", b2, 13)],
                         "edges": [edge("e4", self.chain.c, b2, "cp-C", "cp-D", 13)],
                         "votes": [vote("v5", "e4", self.chain.c, b2, "erin", "i5"),
                                   vote("v6", "e4", self.chain.c, b2, "finn", "i6")]})
        jump = self.chain.request(start="cp-B", end="cp-D")
        jump["request_id"] = "r2"
        jump["plan"] = {"edge_ids": ["e2", "e4"], "votes": [
            {"hop": 1, "category": "privacy", "vote_id": "v3"},
            {"hop": 1, "category": "privacy", "vote_id": "v4"},
            {"hop": 2, "category": "privacy", "vote_id": "v5"},
            {"hop": 2, "category": "privacy", "vote_id": "v6"}]}
        code, payload = publish(self.db, jump)
        self.assertEqual(payload["error"]["code"], "START_NOT_CURRENT")

    def test_plan_must_not_skip_a_checkpoint_with_the_same_root(self):
        """A same-root checkpoint is still a node: plans cannot jump across it."""
        chain = self.chain
        a2 = apply_patch(chain.a, {"001000": "b2"})
        a3 = apply_patch(a2, {"001000": "b"})
        ingest(self.db, {
            "checkpoints": [checkpoint("cp-A2", a2, 30), checkpoint("cp-A3", a3, 31)],
            # e5 reaches a checkpoint that carries exactly the root of cp-A again.
            "edges": [edge("e5", chain.a, a2, "cp-A", "cp-A2", 30),
                      edge("e6", a2, a3, "cp-A2", "cp-A3", 31)],
            "votes": [vote("v5", "e5", chain.a, a2, "erin", "i5"),
                      vote("v6", "e5", chain.a, a2, "finn", "i6"),
                      vote("v7", "e6", a2, a3, "gina", "i7"),
                      vote("v8", "e6", a2, a3, "hank", "i8")],
        })
        code, payload = plan(self.db, chain.request(end="cp-A3"))
        # The only reachable path is cp-A -> cp-A2 -> cp-A3; it cannot be short-cut
        # by observing that cp-A3 carries the root of cp-A.
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["plan"]["edge_ids"], ["e5", "e6"])
        self.assertEqual(payload["final_root"], fmt(chain.a))

    def test_policy_generation_is_rechecked_at_publish(self):
        req = self.request_with_plan()
        req["policy_version"] = 2
        code, payload = publish(self.db, req)
        self.assertEqual(payload["error"]["code"], "POLICY_GENERATION")

    def test_fragment_hash_is_rechecked_at_publish(self):
        req = self.request_with_plan()
        req["plan"]["fragments_hash"] = "0" * 64
        code, payload = publish(self.db, req)
        self.assertEqual(payload["error"]["code"], "FRAGMENT_SET_MISMATCH")

    def test_reviewer_alias_reuse_is_rejected_at_publish(self):
        chain = self.chain
        db = new_db()
        case = chain.base_case(drop_votes=("v2",))
        case["aliases"] = [{"alias": "alice-2", "subject": "alice"}]
        case["votes"].append(vote("v2b", "e1", chain.a, chain.b, "alice-2", "inst-8"))
        ingest(db, case)
        req = chain.request()
        req["request_id"] = "r-alias"
        req["plan"] = {"edge_ids": ["e1", "e2"],
                       "votes": [{"hop": 1, "category": "privacy", "vote_id": "v1"},
                                 {"hop": 1, "category": "privacy", "vote_id": "v2b"},
                                 {"hop": 2, "category": "privacy", "vote_id": "v3"},
                                 {"hop": 2, "category": "privacy", "vote_id": "v4"}]}
        code, payload = publish(db, req)
        self.assertEqual(payload["error"]["code"], "REVIEWER_REUSED")

    def test_same_institution_pair_is_rejected_at_publish(self):
        chain = self.chain
        db = new_db()
        case = chain.base_case()
        for item in case["votes"]:
            if item["vote_id"] == "v2":
                item["institution_id"] = "inst-1"
        ingest(db, case)
        req = chain.request()
        req["request_id"] = "r-inst"
        req["plan"] = {"edge_ids": ["e1", "e2"],
                       "votes": [{"hop": 1, "category": "privacy", "vote_id": "v1"},
                                 {"hop": 1, "category": "privacy", "vote_id": "v2"},
                                 {"hop": 2, "category": "privacy", "vote_id": "v3"},
                                 {"hop": 2, "category": "privacy", "vote_id": "v4"}]}
        code, payload = publish(db, req)
        self.assertEqual(payload["error"]["code"], "INSTITUTION_CONFLICT")

    def test_history_view_is_immune_to_later_revocation(self):
        req = self.request_with_plan()
        first = publish(self.db, req)[1]
        run_cli("ledger-revoke", {"vote_id": "v1", "reason": "after the fact"}, db=self.db)
        code, view = run_cli("ledger-view", {"commit_seq": first["receipt"]["commit_seq"]},
                             db=self.db)
        self.assertEqual(code, 0, view)
        self.assertEqual(view["root"], first["receipt"]["root"])
        self.assertEqual(view["proof"], first["projection"])
        self.assertEqual(view["receipt"]["consumed_votes"],
                         first["receipt"]["consumed_votes"])

    def test_view_replays_each_commit(self):
        req = self.request_with_plan(request_id="r1")
        first = publish(self.db, req)[1]
        # Second publication from cp-C to a new cp-D.
        d = apply_patch(self.chain.c, {"100000": "D"})
        ingest(self.db, {"checkpoints": [checkpoint("cp-D", d, 13)],
                         "edges": [edge("e3", self.chain.c, d, "cp-C", "cp-D", 13)],
                         "votes": [vote("v5", "e3", self.chain.c, d, "erin", "i5"),
                                   vote("v6", "e3", self.chain.c, d, "finn", "i6")]})
        second_req = self.chain.request(start="cp-C", end="cp-D")
        second_req["request_id"] = "r2"
        second_req["plan"] = {"edge_ids": ["e3"],
                              "votes": [{"hop": 1, "category": "privacy", "vote_id": "v5"},
                                        {"hop": 1, "category": "privacy", "vote_id": "v6"}]}
        second = publish(self.db, second_req)[1]
        code, one = run_cli("ledger-view", {"commit_seq": first["receipt"]["commit_seq"]},
                            db=self.db)
        code, two = run_cli("ledger-view", {"commit_seq": second["receipt"]["commit_seq"]},
                            db=self.db)
        self.assertEqual(one["end_checkpoint"], "cp-C")
        self.assertEqual(two["end_checkpoint"], "cp-D")
        self.assertNotEqual(one["root"], two["root"])

    def test_unregistered_intermediate_state_cannot_be_queried(self):
        # A staged edge must never appear as verified, even through status/view.
        chain = Chain()
        db = new_db()
        proof = chain.base_case()["edges"][0]["proof"]
        half = {"leaves": proof["leaves"], "citations": proof["citations"][:2]}
        ingest(db, {"checkpoints": [checkpoint("cp-A", chain.a, 10),
                                    checkpoint("cp-B", chain.b, 11)],
                    "edges": [{"edge_id": "e1", "from": "cp-A", "to": "cp-B",
                               "generation": 11, "policy_version": 1,
                               "expected_fragments": 2, "fragment_id": "f1",
                               "fragment": half}]})
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["edges"], 0)
        self.assertIn("e1", status["staged_edges"])


class ConcurrencyTest(unittest.TestCase):
    """Two real processes, deterministic sync points, one shared database."""

    def build(self):
        chain = Chain()
        db = new_db()
        ingest(db, chain.base_case())
        code, payload = plan(db, chain.request())
        assert code == 0, payload
        req = chain.request()
        req["request_id"] = "req-race"
        req["plan"] = {"edge_ids": payload["plan"]["edge_ids"],
                       "votes": payload["plan"]["votes"]}
        return chain, db, req

    def env_at(self, sync, *points):
        return {"SOLUTION_SYNC_DIR": str(sync),
                "SOLUTION_SYNC_POINTS": ",".join(points),
                "SOLUTION_SYNC_TIMEOUT": "30"}

    def test_revoke_wins_the_lock_then_publish_must_fail(self):
        chain, db, req = self.build()
        sync = Path(tempfile.mkdtemp(prefix="sync-"))
        # The revoker stops while it holds the write transaction; the publisher is
        # started meanwhile and blocks on the same database lock.
        revoker = popen("ledger-revoke", {"vote_id": "v2", "reason": "race"}, db,
                        self.env_at(sync, "revoke:before-commit"))
        self.assertTrue(wait_for(sync, "revoke:before-commit"))
        publisher = popen("ledger-publish", req, db, None)
        time.sleep(0.4)
        release(sync, "revoke:before-commit")
        rev_out, _ = revoker.communicate(timeout=90)
        self.assertTrue(json.loads(rev_out)["ok"])
        out, _ = publisher.communicate(timeout=90)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "VOTE_REVOKED")
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["publications"], 0)
        self.assertEqual(status["consumed"], [])
        self.assertEqual(status["revoked"], ["v2"])

    def test_publish_wins_the_lock_then_revoke_only_affects_the_future(self):
        chain, db, req = self.build()
        sync = Path(tempfile.mkdtemp(prefix="sync-"))
        # The publisher stops while it holds the write transaction; the revoker is
        # started meanwhile and blocks until the publication commits.
        publisher = popen("ledger-publish", req, db,
                          self.env_at(sync, "publish:before-commit"))
        self.assertTrue(wait_for(sync, "publish:before-commit"))
        revoker = popen("ledger-revoke", {"vote_id": "v2", "reason": "after"}, db, None)
        time.sleep(0.4)
        release(sync, "publish:before-commit")
        out, _ = publisher.communicate(timeout=90)
        payload = json.loads(out)
        self.assertTrue(payload["ok"], payload)
        rev_out, _ = revoker.communicate(timeout=90)
        self.assertTrue(json.loads(rev_out)["ok"])
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["publications"], 1)
        self.assertEqual(status["revoked"], ["v2"])
        code, view = run_cli("ledger-view", {"commit_seq": payload["receipt"]["commit_seq"]},
                             db=db)
        self.assertEqual(view["receipt"]["consumed_votes"], ["v1", "v2", "v3", "v4"])
        self.assertEqual(view["root"], fmt(chain.c))

    def test_two_publishers_competing_for_the_same_votes(self):
        chain, db, req = self.build()
        sync = Path(tempfile.mkdtemp(prefix="sync-"))
        env = self.env_at(sync, "publish:before-begin")
        first = popen("ledger-publish", req, db, env)
        self.assertTrue(wait_for(sync, "publish:before-begin"))
        second_req = dict(req)
        second_req["request_id"] = "req-race-2"
        second = popen("ledger-publish", second_req, db, env)
        time.sleep(0.5)
        release(sync, "publish:before-begin")
        one, _ = first.communicate(timeout=90)
        two, _ = second.communicate(timeout=90)
        payloads = [json.loads(one), json.loads(two)]
        ok = [p for p in payloads if p["ok"]]
        failed = [p for p in payloads if not p["ok"]]
        self.assertEqual(len(ok), 1, payloads)
        self.assertEqual(len(failed), 1, payloads)
        self.assertIn(failed[0]["error"]["code"],
                      {"VOTE_CONSUMED", "START_NOT_CURRENT", "IDEMPOTENCY_CONFLICT"})
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["publications"], 1)
        self.assertEqual(sorted(status["consumed"]), ["v1", "v2", "v3", "v4"])

    def test_crash_before_commit_then_retry_is_clean(self):
        chain, db, req = self.build()
        sync = Path(tempfile.mkdtemp(prefix="sync-"))
        proc = popen("ledger-publish", req, db, self.env_at(sync, "publish:before-commit"))
        self.assertTrue(wait_for(sync, "publish:before-commit"))
        proc.kill()
        proc.wait(timeout=30)
        proc.stdout.close()
        proc.stderr.close()
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["publications"], 0)
        self.assertEqual(status["consumed"], [])
        code, payload = publish(db, req)
        self.assertEqual(code, 0, payload)
        code, again = publish(db, req)
        self.assertTrue(again["idempotent"])
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["publications"], 1)

    def test_lost_response_after_commit_is_recoverable(self):
        chain, db, req = self.build()
        sync = Path(tempfile.mkdtemp(prefix="sync-"))
        proc = popen("ledger-publish", req, db, self.env_at(sync, "publish:after-commit"))
        self.assertTrue(wait_for(sync, "publish:after-commit"))
        proc.kill()
        proc.wait(timeout=30)
        proc.stdout.close()
        proc.stderr.close()
        code, status = run_cli("ledger-status", {}, db=db)
        self.assertEqual(status["publications"], 1)
        code, payload = publish(db, req)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["idempotent"])
        self.assertEqual(payload["receipt"]["commit_seq"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
