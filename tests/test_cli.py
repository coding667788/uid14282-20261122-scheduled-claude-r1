"""End-to-end tests of the documented CLI contract.

These exercise ``python -m solution <command> CASE.json`` exactly as the README
says to run it: real processes, real files, UTF-8 JSON on stdout, and stable
results for the same logical input.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.support import ROOT, fmt, run_cli
from tests.test_ledger import Chain


def raw_run(command, payload, db=None):
    tmp = Path(tempfile.mkdtemp(prefix="cli-"))
    path = tmp / "case.json"
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    argv = [_sys.executable, "-m", "solution", command, str(path)]
    if db:
        argv += ["--db", str(db)]
    proc = subprocess.run(argv, capture_output=True, cwd=str(ROOT))
    return proc.returncode, proc.stdout


class CliTest(unittest.TestCase):
    def test_verify_writes_utf8_json(self):
        from solution import refimpl

        old = {"001010": "café ☕"}
        new = {"001010": "café ☕!"}
        case = {"old_root": refimpl.fmt_root(old, 6),
                "new_root": refimpl.fmt_root(new, 6),
                "proof": refimpl.dual_proof(old, new, ["001010"], 6)}
        code, out = raw_run("verify", case)
        self.assertEqual(code, 0)
        text = out.decode("utf-8")
        self.assertIn("café ☕!", text)
        payload = json.loads(text)
        self.assertEqual(payload["keys"][0]["new"], "café ☕!")

    def test_results_are_stable_for_the_same_input(self):
        from solution import refimpl

        old = {"001010": "a", "110011": "b"}
        new = {"001010": "A", "110011": "b"}
        case = {"old_root": refimpl.fmt_root(old, 6),
                "new_root": refimpl.fmt_root(new, 6),
                "proof": refimpl.dual_proof(old, new, ["001010", "110011"], 6)}
        first = raw_run("verify", case)[1]
        second = raw_run("verify", case)[1]
        self.assertEqual(first, second)

    def test_structural_error_reports_code_and_field(self):
        code, out = raw_run("verify", {"old_root": "sha256:" + "00" * 32})
        self.assertEqual(code, 2)
        payload = json.loads(out.decode("utf-8"))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "BAD_FIELD")
        self.assertEqual(payload["error"]["field"], "new_root")

    def test_bad_digest_is_reported_with_its_field(self):
        code, out = raw_run("verify", {"old_root": "sha256:zz", "new_root": "sha256:" + "00" * 32,
                                       "proof": {"leaves": [], "citations": []}})
        self.assertEqual(code, 2)
        payload = json.loads(out.decode("utf-8"))
        self.assertEqual(payload["error"]["code"], "BAD_ROOT")
        self.assertEqual(payload["error"]["field"], "old_root")

    def test_missing_db_is_reported(self):
        code, payload = run_cli("ledger-status", {})
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["code"], "MISSING_DB")

    def test_unreadable_case_file(self):
        tmp = Path(tempfile.mkdtemp(prefix="cli-"))
        argv = [_sys.executable, "-m", "solution", "verify", str(tmp / "nope.json")]
        proc = subprocess.run(argv, capture_output=True, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["error"]["code"], "CASE_UNREADABLE")

    def test_invalid_json_reports_position(self):
        code, out = raw_run("verify", "{not json")
        self.assertEqual(code, 2)
        payload = json.loads(out.decode("utf-8"))
        self.assertEqual(payload["error"]["code"], "CASE_INVALID_JSON")
        self.assertIn(":1:", payload["error"]["field"])

    def test_full_ledger_flow_from_the_readme(self):
        chain = Chain()
        db = Path(tempfile.mkdtemp(prefix="cli-")) / "ledger.sqlite"
        code, ingested = run_cli("ledger-ingest", chain.base_case(), db=db)
        self.assertEqual(code, 0, ingested)
        code, planned = run_cli("ledger-plan", chain.request(), db=db)
        self.assertEqual(code, 0, planned)
        req = chain.request()
        req["request_id"] = "readme-1"
        req["plan"] = {"edge_ids": planned["plan"]["edge_ids"],
                       "votes": planned["plan"]["votes"]}
        code, published = run_cli("ledger-publish", req, db=db)
        self.assertEqual(code, 0, published)
        code, viewed = run_cli("ledger-view", {"commit_seq": 1}, db=db)
        self.assertEqual(code, 0, viewed)
        self.assertEqual(viewed["root"], fmt(chain.c))
        self.assertEqual(viewed["receipt"]["request_id"], "readme-1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
