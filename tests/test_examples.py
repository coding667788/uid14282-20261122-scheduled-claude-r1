"""Each fixture under ``examples/`` must run and satisfy its documented assertions."""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.support import ROOT, run_cli

EXAMPLES = ROOT / "examples"


class ExamplesTest(unittest.TestCase):
    def load(self, *parts):
        return json.loads((EXAMPLES.joinpath(*parts)).read_text(encoding="utf-8"))

    def test_verify_example(self):
        case = self.load("verify", "case.json")
        code, payload = run_cli("verify", case)
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["counts"],
                         {"insert": 1, "delete": 1, "update": 1, "unchanged": 2})
        kinds = {row["key"]: row["kind"] for row in payload["keys"]}
        self.assertEqual(kinds["0010"], "delete")   # "" -> absent is a delete, not a no-op
        self.assertEqual(kinds["1100"], "insert")

    def test_merge_example(self):
        case = self.load("merge", "case.json")
        code, payload = run_cli("merge", case)
        self.assertEqual(code, 0, payload)
        prefixes = [c["prefix"] for c in payload["proof"]["citations"]]
        self.assertEqual(prefixes, case["expected_union_boundary"])
        self.assertLess(payload["merged"]["citations"],
                        payload["merged"]["citations_before"])

    def test_proof_rebase_example(self):
        case = self.load("proof-rebase", "case.json")
        code, payload = run_cli("proof-rebase", case)
        self.assertEqual(code, 0, payload)
        rows = {row["key"]: row for row in payload["keys"]}
        self.assertEqual(rows["000100"]["first_change_hop"], 1)
        self.assertEqual(rows["000100"]["last_change_hop"], 3)
        self.assertEqual(rows["000100"]["initial"], rows["000100"]["value"])
        self.assertEqual(rows["010000"]["last_change_hop"], 2)
        self.assertFalse(rows["100000"]["changed"])
        self.assertEqual(payload["final_root"], case["chain"][-1]["new_root"])

    def test_split_verify_example(self):
        case = self.load("split-verify", "case.json")
        code, payload = run_cli("split-verify", case)
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["evidence"]["citations"],
                         len(case["proof"]["citations"]))
        self.assertEqual(len(payload["shards"]), 3)

    def test_ledger_example_flow(self):
        workdir = Path(tempfile.mkdtemp(prefix="example-"))
        db = workdir / "ledger.sqlite"
        try:
            code, ingested = run_cli("ledger-ingest", self.load("ledger", "ingest.json"), db=db)
            self.assertEqual(code, 0, ingested)
            self.assertEqual(ingested["edges"]["verified"], ["e1", "e2"])

            code, planned = run_cli("ledger-plan", self.load("ledger", "plan.json"), db=db)
            self.assertEqual(code, 0, planned)
            self.assertEqual(planned["plan"]["edge_ids"], ["e1", "e2"])
            self.assertEqual(planned["plan"]["disclosed_keys"], 2)

            code, published = run_cli("ledger-publish", self.load("ledger", "publish.json"),
                                      db=db)
            self.assertEqual(code, 0, published)
            self.assertEqual(published["receipt"]["commit_seq"], 1)

            code, viewed = run_cli("ledger-view", self.load("ledger", "view.json"), db=db)
            self.assertEqual(code, 0, viewed)
            self.assertEqual(viewed["root"], published["receipt"]["root"])

            code, revoked = run_cli("ledger-revoke", self.load("ledger", "revoke.json"),
                                    db=db)
            self.assertEqual(code, 0, revoked)

            # History survives the revocation.
            code, again = run_cli("ledger-view", self.load("ledger", "view.json"), db=db)
            self.assertEqual(again["receipt"], viewed["receipt"])

            code, status = run_cli("ledger-status", self.load("ledger", "status.json"), db=db)
            self.assertEqual(code, 0, status)
            self.assertEqual(status["publications"], 1)
            self.assertEqual(status["revoked"], ["v4"])
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def test_examples_match_the_generator(self):
        """Regenerating must reproduce the committed fixtures byte for byte."""
        import subprocess

        before = {path: path.read_bytes()
                  for path in EXAMPLES.rglob("*.json")}
        proc = subprocess.run([_sys.executable, str(EXAMPLES / "build_examples.py")],
                              cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        after = {path: path.read_bytes() for path in EXAMPLES.rglob("*.json")}
        self.assertEqual(before, after)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
