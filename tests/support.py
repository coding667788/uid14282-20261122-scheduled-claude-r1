"""Shared fixtures: small deterministic manifests, ledgers and CLI helpers."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from solution import refimpl

ROOT = Path(__file__).resolve().parent.parent
DEPTH = 6


def fmt(mapping, depth=DEPTH):
    return refimpl.fmt_root(mapping, depth)


def checkpoint(cid, mapping, generation, policy_version=1, depth=DEPTH, label=""):
    return {"checkpoint_id": cid, "root": fmt(mapping, depth),
            "generation": generation, "policy_version": policy_version, "label": label}


def edge(eid, old, new, old_cp, new_cp, generation, keys=None, policy_version=1,
         categories=("privacy",), archive_use="cold-archive", policy=None, depth=DEPTH):
    keys = keys or sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
    proof = refimpl.dual_proof(old, new, keys, depth)
    return {
        "edge_id": eid, "from": old_cp, "to": new_cp, "generation": generation,
        "policy_version": policy_version,
        "proof": proof,
        "kept_branches": [c["prefix"] for c in proof["citations"]],
        "categories": list(categories),
        "archive_use": archive_use,
        "policy": policy or {"allowed_prefixes": ["0", "1"]},
    }


def vote(vid, eid, old, new, reviewer, institution, category="privacy",
         policy_version=1, issued_at=0, expires_at=1000, depth=DEPTH):
    return {"vote_id": vid, "edge_id": eid, "category": category,
            "reviewer_id": reviewer, "institution_id": institution,
            "policy_version": policy_version, "old_root": fmt(old, depth),
            "new_root": fmt(new, depth), "issued_at": issued_at,
            "expires_at": expires_at}


def request(start, end, s_keys, at, policy_version=1, clock=10, archive_use="cold-archive",
            depth=DEPTH):
    return {"start_checkpoint": start, "end_checkpoint": end,
            "policy_version": policy_version, "logical_clock": clock,
            "archive_use": archive_use, "s_keys": s_keys,
            "inventory": {"root": fmt(at, depth),
                          "proof": refimpl.value_proof(at, s_keys, depth)}}


def run_cli(command, case, db=None, cwd=None, env=None):
    """Invoke ``python -m solution`` in a subprocess; returns (exit code, payload)."""
    tmp = Path(tempfile.mkdtemp(prefix="case-"))
    path = tmp / "case.json"
    path.write_text(json.dumps(case), encoding="utf-8")
    argv = [sys.executable, "-m", "solution", command, str(path)]
    if db is not None:
        argv += ["--db", str(db)]
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=str(cwd or ROOT),
                          env={**os.environ, **(env or {})}, encoding="utf-8")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise AssertionError(f"non-JSON output: {proc.stdout!r} / {proc.stderr!r}")
    return proc.returncode, payload


def popen_cli(command, case, db=None, cwd=None, env=None):
    """Start a CLI invocation without waiting; the caller controls timing."""
    tmp = Path(tempfile.mkdtemp(prefix="case-"))
    path = tmp / "case.json"
    path.write_text(json.dumps(case), encoding="utf-8")
    argv = [sys.executable, "-m", "solution", command, str(path)]
    if db is not None:
        argv += ["--db", str(db)]
    return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, cwd=str(cwd or ROOT),
                            env={**os.environ, **(env or {})}, encoding="utf-8")
