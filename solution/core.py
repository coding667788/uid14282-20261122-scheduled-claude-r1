"""Shared primitives: hashing, canonical encodings, parsing and structural rules.

All hashes and JSON payloads travelling in and out of the tool are lowercase hex
strings, so logical equality of inputs equals byte equality of canonical
encodings.  Every structural violation is an :class:`ArchiveError` carrying a
stable code and the JSON path of the offending field.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

MAX_DEPTH = 128
SIZE_LIMIT = 0xFF_FF_FF_FF

EMPTY_HEX = hashlib.sha256(b"\x02").hexdigest()
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
BITS_RE = re.compile(r"^[01]+$")


class ArchiveError(Exception):
    """A reported error: stable code, JSON path of the offending field, detail."""

    def __init__(self, code: str, field: str, detail: str, **extra: Any) -> None:
        self.code = code
        self.field = field
        self.detail = detail
        self.extra = extra
        super().__init__(f"{code} at {field}: {detail}")

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "field": self.field, "detail": self.detail}
        out.update(self.extra)
        return out


def err(code: str, field: str, detail: str, **extra: Any) -> ArchiveError:
    return ArchiveError(code, field, detail, **extra)


def require(condition: bool, code: str, field: str, detail: str, **extra: Any) -> None:
    if not condition:
        raise ArchiveError(code, field, detail, **extra)


# --------------------------------------------------------------------------- hashing

def sha256_hex(*parts: bytes) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.hexdigest()


def value_hash(value: str | None) -> str:
    if value is None:
        return EMPTY_HEX
    data = value.encode("utf-8")
    return sha256_hex(b"\x00", len(data).to_bytes(4, "big"), data)


def branch_hash(left: str, right: str) -> str:
    return sha256_hex(b"\x01", bytes.fromhex(left), bytes.fromhex(right))


_EMPTY: list[str] = [EMPTY_HEX]


def empty_node(height: int) -> str:
    """Digest of an all-absent subtree whose height (remaining bits) is ``height``."""
    require(0 <= height <= MAX_DEPTH, "BAD_DEPTH", "depth",
            f"tree depth must be 0..{MAX_DEPTH}")
    while len(_EMPTY) <= height:
        _EMPTY.append(branch_hash(_EMPTY[-1], _EMPTY[-1]))
    return _EMPTY[height]


def digest(value: str | None) -> str:
    return value_hash(value)


# --------------------------------------------------------------------------- JSON

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def checksum(value: Any) -> str:
    return sha256_hex(canonical(value).encode("utf-8"))


def expect_object(raw: Any, field: str, what: str = "object") -> dict[str, Any]:
    require(isinstance(raw, dict), "BAD_FIELD", field, f"{what} must be a JSON object")
    return raw


def expect_list(raw: Any, field: str) -> list[Any]:
    require(isinstance(raw, list), "BAD_FIELD", field, "must be a JSON array")
    return raw


def expect_str(raw: Any, field: str, *, allow_empty: bool = False) -> str:
    require(isinstance(raw, str), "BAD_FIELD", field, "must be a string")
    require(allow_empty or raw != "", "BAD_FIELD", field, "must not be empty")
    return raw


def expect_int(raw: Any, field: str, *, minimum: int | None = None) -> int:
    require(isinstance(raw, int) and not isinstance(raw, bool), "BAD_FIELD", field,
            "must be an integer")
    if minimum is not None:
        require(raw >= minimum, "BAD_FIELD", field, f"must be >= {minimum}")
    return raw


def expect_bool(raw: Any, field: str) -> bool:
    require(isinstance(raw, bool), "BAD_FIELD", field, "must be a boolean")
    return raw


def reject_unknown(obj: dict[str, Any], allowed: Iterable[str], field: str) -> None:
    unknown = sorted(set(obj) - set(allowed))
    if unknown:
        raise err("UNKNOWN_FIELD", field, f"unknown field {unknown[0]!r}")


# --------------------------------------------------------------------------- keys and values

def check_key(raw: Any, field: str) -> str:
    text = expect_str(raw, field)
    bits = text[2:] if text.startswith("0b") else text
    require(1 <= len(bits) <= MAX_DEPTH, "BAD_KEY", field,
            f"key must be a binary string of length 1..{MAX_DEPTH}")
    require(bool(BITS_RE.match(bits)), "BAD_KEY", field, "key must contain only 0 and 1")
    return bits


def check_value(raw: Any, field: str) -> str | None:
    if raw is None:
        return None
    text = expect_str(raw, field, allow_empty=True)
    require(len(text.encode("utf-8")) <= SIZE_LIMIT, "VALUE_TOO_LONG", field,
            f"value exceeds {SIZE_LIMIT} UTF-8 bytes")
    return text


def check_digest(raw: Any, field: str) -> str:
    text = expect_str(raw, field)
    require(bool(DIGEST_RE.match(text)), "BAD_DIGEST", field,
            "must be sha256:<64 lowercase hex>")
    return text[7:]


def check_root(raw: Any, field: str, *, allow_empty: bool = True) -> str:
    text = expect_str(raw, field, allow_empty=allow_empty)
    if text in ("empty", "absent") and allow_empty:
        return EMPTY_HEX
    require(bool(DIGEST_RE.match(text)) or bool(HEX64_RE.match(text)), "BAD_ROOT", field,
            "root must be sha256:<64 lowercase hex>")
    return text[7:] if text.startswith("sha256:") else text


def check_prefix(raw: Any, field: str, depth: int) -> str:
    text = expect_str(raw, field, allow_empty=True)
    bits = text[2:] if text.startswith("0b") else text
    require(bits == "" or bool(BITS_RE.match(bits)), "BAD_PREFIX", field,
            "prefix must be a binary string")
    require(len(bits) <= depth, "BAD_PREFIX", field, f"prefix must not be longer than depth {depth}")
    return bits


def fmt_root(root: str) -> str:
    return "sha256:" + root


# --------------------------------------------------------------------------- policies

@dataclass
class Policy:
    allowed_prefixes: tuple[str, ...] = ()
    allow_insert: bool = True
    allow_delete: bool = True
    allow_update: bool = True

    def check(self, key: str, kind: str, field: str) -> None:
        if kind == "unchanged":
            return
        if kind == "insert" and not self.allow_insert:
            raise err("POLICY_INSERT_FORBIDDEN", field, f"insert of key {key} is not allowed")
        if kind == "delete" and not self.allow_delete:
            raise err("POLICY_DELETE_FORBIDDEN", field, f"delete of key {key} is not allowed")
        if kind == "update" and not self.allow_update:
            raise err("POLICY_UPDATE_FORBIDDEN", field, f"update of key {key} is not allowed")
        if self.allowed_prefixes and not any(key.startswith(p) for p in self.allowed_prefixes):
            raise err("PREFIX_FORBIDDEN", field,
                      f"change of key {key} falls outside the allowed prefixes")

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed_prefixes": list(self.allowed_prefixes),
            "allow_insert": self.allow_insert,
            "allow_delete": self.allow_delete,
            "allow_update": self.allow_update,
        }


def parse_policy(raw: Any, field: str) -> Policy:
    if raw is None:
        return Policy()
    obj = expect_object(raw, field, "policy")
    reject_unknown(obj, {"allowed_prefixes", "allow_insert", "allow_delete", "allow_update"}, field)
    prefixes: list[str] = []
    for i, p in enumerate(expect_list(obj.get("allowed_prefixes", []), field + ".allowed_prefixes")):
        checked = check_prefix(p, f"{field}.allowed_prefixes[{i}]", MAX_DEPTH)
        require(checked != "", "BAD_PREFIX", field + ".allowed_prefixes",
                "an empty prefix would allow any change")
        prefixes.append(checked)
    return Policy(
        allowed_prefixes=tuple(prefixes),
        allow_insert=expect_bool(obj["allow_insert"], field + ".allow_insert")
        if "allow_insert" in obj else True,
        allow_delete=expect_bool(obj["allow_delete"], field + ".allow_delete")
        if "allow_delete" in obj else True,
        allow_update=expect_bool(obj["allow_update"], field + ".allow_update")
        if "allow_update" in obj else True,
    )


def change_kind(old: str | None, new: str | None) -> str:
    if old is None and new is not None:
        return "insert"
    if old is not None and new is None:
        return "delete"
    if old != new:
        return "update"
    return "unchanged"


# --------------------------------------------------------------------------- induced tree

def boundary(targets: Iterable[str]) -> list[str]:
    """Sibling subtrees hanging off the induced tree of ``targets``.

    All targets share one depth.  A node on a target path contributes its
    off-path child only when that child holds no target.  Sorted by binary
    prefix order (a shorter prefix precedes its extensions).
    """
    tset = set(targets)
    ancestors: set[str] = set()
    for t in tset:
        for i in range(len(t)):
            ancestors.add(t[:i])
    req: set[str] = set()
    for t in tset:
        for i, bit in enumerate(t):
            sibling = t[:i] + ("1" if bit == "0" else "0")
            if sibling not in ancestors and sibling not in tset:
                req.add(sibling)
    return sorted(req)


def ancestor_set(targets: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for t in targets:
        for i in range(len(t)):
            out.add(t[:i])
    return out


# --------------------------------------------------------------------------- proofs

@dataclass
class Citation:
    prefix: str
    hash: str
    field: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"prefix": self.prefix, "hash": fmt_root(self.hash)}


@dataclass
class ProofData:
    """Parsed proof: uniform key depth, per-side values, boundary citations."""

    depth: int
    side_names: tuple[str, ...]
    keys: tuple[str, ...]
    values: dict[str, tuple[str | None, ...]]
    cites: dict[str, str]
    cite_fields: dict[str, str]
    source_field: str

    def hash(self, key: str, side: int) -> str:
        return value_hash(self.values[key][side])

    def present(self, side: int) -> set[str]:
        return {k for k in self.keys if self.values[k][side] is not None}

    def changed(self) -> list[str]:
        return [k for k in self.keys if self.values[k][0] != self.values[k][1]]

    def as_dict(self) -> dict[str, Any]:
        leaves = []
        for k in self.keys:
            leaf: dict[str, Any] = {"key": k}
            for i, name in enumerate(self.side_names):
                leaf[name] = self.values[k][i]
            leaves.append(leaf)
        return {"leaves": leaves, "citations": self.canonical_cites()}

    def canonical_cites(self) -> list[dict[str, Any]]:
        return [Citation(p, self.cites[p]).as_dict() for p in sorted(self.cites)]


PROOF_SIDE_NAMES = ("old_value", "new_value")
VALUE_SIDE_NAMES = ("value",)


def parse_proof(raw: Any, field: str, sides: Sequence[str]) -> ProofData:
    obj = expect_object(raw, field, "proof")
    reject_unknown(obj, {"leaves", "citations", "note"}, field)
    leaves_raw = expect_list(obj.get("leaves"), field + ".leaves")
    cites_raw = expect_list(obj.get("citations"), field + ".citations")
    require(leaves_raw, "EMPTY_PROOF", field + ".leaves", "proof must audit at least one key")
    values: dict[str, tuple[str | None, ...]] = {}
    depth: int | None = None
    for i, item in enumerate(leaves_raw):
        path = f"{field}.leaves[{i}]"
        leaf = expect_object(item, path, "leaf")
        reject_unknown(leaf, {"key", *sides}, path)
        key = check_key(leaf.get("key"), path + ".key")
        if depth is None:
            depth = len(key)
        else:
            require(len(key) == depth, "KEY_DEPTH_MISMATCH", path + ".key",
                    f"all audited keys must share depth {depth}")
        require(key not in values, "DUP_LEAF", path, f"key {key} repeated")
        vals = []
        for name in sides:
            require(name in leaf, "BAD_LEAF", path + "." + name, "missing value for this side")
            vals.append(check_value(leaf[name], f"{path}.{name}"))
        values[key] = tuple(vals)
    assert depth is not None
    cites: dict[str, str] = {}
    cite_fields: dict[str, str] = {}
    for i, item in enumerate(cites_raw):
        path = f"{field}.citations[{i}]"
        cite = expect_object(item, path, "citation")
        reject_unknown(cite, {"prefix", "hash", "depth"}, path)
        prefix = check_prefix(cite.get("prefix"), path + ".prefix", depth)
        if "depth" in cite:
            given = expect_int(cite["depth"], path + ".depth", minimum=0)
            require(given == len(prefix), "BAD_CITE", path + ".depth",
                    "depth, when present, must equal the prefix length")
        require(prefix not in cites, "DUP_CITE", path + ".prefix", f"duplicate citation {prefix}")
        raw_hash = cite.get("hash")
        if isinstance(raw_hash, str) and raw_hash in ("empty", "absent"):
            cites[prefix] = empty_node(depth - len(prefix))
        else:
            cites[prefix] = check_digest(raw_hash, path + ".hash")
        cite_fields[prefix] = path
    proof = ProofData(
        depth=depth,
        side_names=tuple(sides),
        keys=tuple(sorted(values)),
        values=values,
        cites=cites,
        cite_fields=cite_fields,
        source_field=field,
    )
    validate_citations(proof)
    return proof


def validate_citations(proof: ProofData) -> None:
    """Exact induced-tree boundary, no duplicates, no leaf coverage, no nesting."""
    field = proof.source_field + ".citations"
    targets = set(proof.keys)
    ancestors = ancestor_set(targets)
    for prefix in sorted(proof.cites):
        pos = proof.cite_fields.get(prefix, field)
        require(prefix not in targets, "COVERS_LEAF", pos,
                f"citation {prefix} covers audited key {prefix}")
        require(prefix not in ancestors, "PARENT_CHILD_OVERLAP", pos,
                f"citation {prefix} contains audited keys")
    for prefix in sorted(proof.cites):
        pos = proof.cite_fields.get(prefix, field)
        for i in range(1, len(prefix)):
            require(prefix[:i] not in proof.cites, "PARENT_CHILD_OVERLAP", pos,
                    f"citation {prefix} sits below citation {prefix[:i]}")
    required = boundary(proof.keys)
    req_set = set(required)
    for prefix in required:
        require(prefix in proof.cites, "MISSING_BOUNDARY", field,
                f"boundary citation {prefix} is required by the audited keys but missing")
    for prefix in sorted(proof.cites):
        pos = proof.cite_fields.get(prefix, field)
        require(prefix in req_set, "EXTRA_CITE", pos,
                f"citation {prefix} does not belong to the induced tree boundary")


def short(text: str, limit: int = 32) -> str:
    return text if len(text) <= limit else text[:limit] + "..."
