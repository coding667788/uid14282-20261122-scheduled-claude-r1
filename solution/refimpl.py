"""Reference implementation used by the tests and the examples.

This module builds *complete* small trees on purpose (depths of a handful of
bits), which makes it an independent oracle for the sparse production code: it
shares only the hash primitives, never the recovery logic.
"""

from __future__ import annotations

from typing import Iterable, Mapping

from .core import boundary, branch_hash, value_hash


def node(mapping: Mapping[str, str | None], prefix: str, depth: int) -> str:
    """Full hash of the sub-tree at ``prefix`` in a complete depth-``depth`` map."""
    if len(prefix) == depth:
        if prefix in mapping:
            return value_hash(mapping[prefix])
        return value_hash(None)
    left = node(mapping, prefix + "0", depth)
    right = node(mapping, prefix + "1", depth)
    return branch_hash(left, right)


def root(mapping: Mapping[str, str | None], depth: int) -> str:
    return node(mapping, "", depth)


def leaf_keys(mapping: Mapping[str, str | None], depth: int) -> list[str]:
    out = []
    for i in range(1 << depth):
        bits = format(i, f"0{depth}b")
        if bits in mapping:
            out.append(bits)
    return out


def value_proof(mapping: Mapping[str, str | None], keys: Iterable[str],
                depth: int) -> dict:
    keys = sorted(set(keys))
    cites = []
    for prefix in boundary(keys):
        digest = node(mapping, prefix, depth)
        cites.append({"prefix": prefix, "hash": _render(digest, prefix, depth)})
    return {"leaves": [{"key": k, "value": mapping.get(k)} for k in keys],
            "citations": cites}


def dual_proof(old: Mapping[str, str | None], new: Mapping[str, str | None],
               keys: Iterable[str], depth: int, *, allow_unsafe: bool = False) -> dict:
    """Minimal two-root proof for ``keys``.

    Every boundary region is shared by both roots, so its digest must be equal in
    ``old`` and ``new``.  ``allow_unsafe`` skips that assertion so a test can
    build a knowingly inconsistent proof.
    """
    keys = sorted(set(keys))
    cites = []
    for prefix in boundary(keys):
        old_digest = node(old, prefix, depth)
        new_digest = node(new, prefix, depth)
        if old_digest != new_digest and not allow_unsafe:
            raise ValueError(f"boundary {prefix} differs between the two roots; the change "
                             f"is outside the audited key set")
        cites.append({"prefix": prefix, "hash": _render(old_digest, prefix, depth)})
    leaves = [{"key": k, "old_value": old.get(k), "new_value": new.get(k)} for k in keys]
    return {"leaves": leaves, "citations": cites}


def _render(digest: str, prefix: str, depth: int) -> str:
    from .core import empty_node

    if digest == empty_node(depth - len(prefix)):
        return "empty"
    return "sha256:" + digest


def apply_patch(mapping: Mapping[str, str | None],
                patch: Mapping[str, str | None]) -> dict[str, str | None]:
    out = {k: v for k, v in mapping.items() if v is not None}
    for key, value in patch.items():
        if value is None:
            out.pop(key, None)
        else:
            out[key] = value
    return out


def root_of(mapping: Mapping[str, str | None], depth: int) -> str:
    return root(mapping, depth)


def fmt_root(mapping: Mapping[str, str | None], depth: int) -> str:
    return "sha256:" + root(mapping, depth)
