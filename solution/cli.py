"""Command-line entry point: ``python -m solution <command> CASE.json [--db DB]``.

Results go to stdout as UTF-8 JSON with a stable key order.  Failures are
reported as ``{"ok": false, "error": {"code", "field", "detail"}}`` with exit
code 2, so a caller can distinguish a structural rejection from a crash (1).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

from .core import ArchiveError


# --------------------------------------------------------------------------- command table

def _table() -> dict[str, Callable[[dict[str, Any], str | None], dict[str, Any]]]:
    from . import proofs, ledger, ledger_ops

    def simple(fn):
        return lambda case, db: fn(case)

    return {
        "verify": simple(proofs.handle_verify),
        "merge": simple(proofs.handle_merge),
        "proof-rebase": simple(proofs.handle_proof_rebase),
        "split-verify": simple(proofs.handle_split_verify),
        "ledger-ingest": ledger.handle_ingest,
        "ledger-plan": ledger.handle_plan,
        "ledger-publish": ledger_ops.handle_publish,
        "ledger-view": ledger_ops.handle_view,
        "ledger-revoke": ledger_ops.handle_revoke,
        "ledger-status": ledger_ops.handle_status,
    }


DB_COMMANDS = frozenset({"ledger-ingest", "ledger-publish", "ledger-view",
                         "ledger-revoke", "ledger-status", "ledger-plan"})


# --------------------------------------------------------------------------- io

def load_case(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ArchiveError("CASE_UNREADABLE", str(path), f"cannot read case file: {exc}") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ArchiveError("CASE_INVALID_JSON", f"{path}:{exc.lineno}:{exc.colno}",
                           f"case file is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ArchiveError("CASE_NOT_OBJECT", str(path), "case file must hold a JSON object")
    return value


def emit(payload: dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def render_error(exc: ArchiveError, command: str) -> dict[str, Any]:
    return {"ok": False, "command": command, "verified": False, "error": exc.as_dict()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Offline sparse-Merkle manifest proof checker and archive ledger.",
    )
    parser.add_argument("command", help="verify | merge | proof-rebase | split-verify | "
                                        "ledger-*")
    parser.add_argument("case", help="path to the CASE.json input")
    parser.add_argument("--db", dest="db", default=None,
                        help="SQLite database path for commands that keep persistent state")
    args = parser.parse_args(argv)

    table = _table()
    if args.command not in table:
        emit({"ok": False, "command": args.command, "verified": False,
              "error": {"code": "UNKNOWN_COMMAND", "field": "command",
                        "detail": f"unknown command {args.command!r}; expected one of "
                                  f"{', '.join(sorted(table))}"}})
        return 2
    if args.command in DB_COMMANDS and not args.db:
        emit({"ok": False, "command": args.command, "verified": False,
              "error": {"code": "MISSING_DB", "field": "args.db",
                        "detail": f"{args.command} needs --db DB.sqlite"}})
        return 2

    try:
        case = load_case(Path(args.case))
    except ArchiveError as exc:
        emit(render_error(exc, args.command))
        return 2

    try:
        result = table[args.command](case, args.db)
    except ArchiveError as exc:
        emit(render_error(exc, args.command))
        return 2
    except Exception as exc:  # pragma: no cover - unexpected failures stay reported
        emit({"ok": False, "command": args.command, "verified": False,
              "error": {"code": "INTERNAL", "field": "", "detail": f"{type(exc).__name__}: {exc}"}})
        return 1
    emit(result)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
