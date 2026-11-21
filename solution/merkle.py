"""Sparse sub-tree recovery for binary Merkle manifests (depth up to 128).

A proof is an *induced tree*: the audited leaves plus the digest of every sibling
sub-tree hanging off the boundary of that induced tree.  Recovery visits only
those nodes -- ``O(len(keys) * depth)`` -- so a full tree is never materialised.

The :class:`Scene` stores, for each side of a proof (``old``/``new``, or a single
``value`` side), a hash per disclosed leaf and one *shared* digest per cited
sub-tree.  Sharing one citation digest between both sides is exactly what makes
a single proof able to restore the old and the new root at once, and it is why a
change outside the audited key set must break one of the two roots.

Node shape follows from the disclosed content alone:

* a disclosed leaf is a leaf -- an absent leaf hashes to the canonical empty
  sub-tree at height 0, so "absent" and "empty" are the same value by design,
* a disclosed citation is an opaque sub-tree whose digest is known,
* a node with disclosed content below it is internal,
* every other node is the canonical empty sub-tree ``empty_node(height)``.

A citation above disclosed leaves is *expandable*: the digest it carries must
equal the digest recomputed from the disclosed content below it, and it is then
dropped.  Two disclosures of the same prefix or leaf must agree, otherwise the
merge is refused -- that is the "shared side branch" consistency rule.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from .core import (
    MAX_DEPTH,
    boundary,
    branch_hash,
    empty_node,
    err,
    value_hash,
)


class Scene:
    """Disclosed leaves and cited sub-trees for a fixed depth and side count."""

    __slots__ = ("depth", "sides", "leaves", "cites", "_memo")

    def __init__(self, depth: int, sides: int = 1) -> None:
        if not 0 <= depth <= MAX_DEPTH:
            raise ValueError("proof depth out of range")
        self.depth = depth
        self.sides = sides
        self.leaves: dict[str, list[str | None]] = {}
        self.cites: dict[str, str] = {}
        self._memo: dict[tuple[int, str], str] = {}

    # ------------------------------------------------------------------ build

    def clone(self) -> "Scene":
        out = Scene(self.depth, self.sides)
        out.leaves = {k: list(v) for k, v in self.leaves.items()}
        out.cites = dict(self.cites)
        return out

    def add_leaf(self, bits: str, hashes: Sequence[str | None], field: str = "") -> None:
        hashes = list(hashes)
        if len(hashes) != self.sides:
            raise ValueError("leaf hash count does not match the scene sides")
        if bits in self.leaves:
            raise err("DUP_LEAF", field or bits, f"leaf {bits} is disclosed twice")
        self.leaves[bits] = hashes
        self._memo.clear()

    def merge_leaf(self, bits: str, hashes: Sequence[str | None], field: str = "") -> None:
        """Add a leaf, or check that an already disclosed leaf agrees."""
        hashes = list(hashes)
        if bits not in self.leaves:
            self.add_leaf(bits, hashes, field)
            return
        known = self.leaves[bits]
        for side, h in enumerate(hashes):
            if h is None:
                continue
            if known[side] is not None and known[side] != h:
                raise err("LEAF_CONFLICT", field or bits,
                          f"two disclosures disagree about leaf {bits} on side {side}")
            known[side] = h
        self._memo.clear()

    def add_cite(self, prefix: str, digest: str, field: str = "") -> None:
        if prefix in self.cites:
            raise err("DUP_CITE", field or prefix, f"citation {prefix} is disclosed twice")
        self.cites[prefix] = digest
        self._memo.clear()

    def merge_cite(self, prefix: str, digest: str, field: str = "") -> None:
        if prefix in self.cites:
            if self.cites[prefix] != digest:
                raise err("CITE_CONFLICT", field or prefix,
                          f"two disclosures disagree about citation {prefix}")
            return
        self.add_cite(prefix, digest, field)

    def drop_cite(self, prefix: str) -> None:
        self.cites.pop(prefix)
        self._memo.clear()

    # ------------------------------------------------------------------ shape

    def _below(self, bits: str) -> bool:
        if any(k != bits and k.startswith(bits) for k in self.leaves):
            return True
        return any(p != bits and p.startswith(bits) for p in self.cites)

    def shape(self, bits: str) -> str:
        if bits in self.leaves:
            return "leaf"
        if bits in self.cites:
            return "cite"
        if self._below(bits):
            return "internal"
        return "empty"

    def height(self, bits: str) -> int:
        return self.depth - len(bits)

    # --------------------------------------------------------------- recovery

    def node(self, bits: str, side: int = 0) -> str:
        key = (side, bits)
        memo = self._memo.get(key)
        if memo is not None:
            return memo
        shape = self.shape(bits)
        if shape == "leaf":
            value = self.leaves[bits][side]
            if value is None:
                raise err("UNDISCLOSED_VALUE", bits,
                          f"no hash was disclosed for leaf {bits} on side {side}")
            out = value
        elif shape == "cite":
            out = self.cites[bits]
        elif shape == "internal":
            out = branch_hash(self.node(bits + "0", side), self.node(bits + "1", side))
        else:
            out = empty_node(self.height(bits))
        self._memo[key] = out
        return out

    def root(self, side: int = 0) -> str:
        return self.node("", side)

    def roots(self) -> list[str]:
        return [self.root(side) for side in range(self.sides)]

    def check_root(self, side: int, expected: str, field: str, label: str) -> None:
        got = self.root(side)
        if got != expected:
            raise err("ROOT_MISMATCH", field,
                      f"recomputed {label} root {fmt(got)} does not match the trusted root "
                      f"{fmt(expected)}")

    # ------------------------------------------------------- derived structures

    def hidden(self, bits: str) -> bool:
        """True when a citation strictly above ``bits`` keeps the region opaque."""
        return any(len(p) < len(bits) and bits.startswith(p) for p in self.cites)

    def claims(self, bits: str) -> list[str | None]:
        """Per-side digest this scene can prove for ``bits``, ``None`` if opaque."""
        if self.hidden(bits):
            return [None] * self.sides
        return [self.node(bits, side) for side in range(self.sides)]

    def expandable(self) -> list[str]:
        """Citations with disclosed leaves strictly beneath them."""
        return sorted(p for p in self.cites
                      if any(k != p and k.startswith(p) for k in self.leaves))

    def expand_cite(self, prefix: str, field: str = "") -> None:
        """Check an expandable citation against the disclosed content, then drop it."""
        claimed = self.cites[prefix]
        self.drop_cite(prefix)
        recomputed = self.node(prefix, 0)
        if recomputed != claimed:
            raise err("EXPANSION_MISMATCH", field or prefix,
                      f"citation {prefix} carries {fmt(claimed)} but the expanded sub-tree "
                      f"hashes to {fmt(recomputed)}")
        for side in range(1, self.sides):
            if self.node(prefix, side) != claimed:
                raise err("EXPANSION_MISMATCH", field or prefix,
                          f"citation {prefix} is shared by both sides but the expanded "
                          f"sub-trees differ")

    def expand_all(self, field: str = "") -> list[str]:
        done: list[str] = []
        while True:
            pending = self.expandable()
            if not pending:
                return done
            for prefix in pending:
                self.expand_cite(prefix, field or prefix)
                done.append(prefix)

    def boundary_cites(self, keys: Iterable[str]) -> dict[str, list[str | None]]:
        """Canonical boundary citations of ``keys``, digests taken from this scene."""
        return {prefix: self.claims(prefix) for prefix in boundary(set(keys))}

    def require_boundary(self, keys: Iterable[str], field: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for prefix in boundary(set(keys)):
            claims = self.claims(prefix)
            if any(c is None for c in claims):
                raise err("UNDISCLOSED_BRANCH", field or prefix,
                          f"the region below citation {prefix} is not disclosed "
                          f"by the available evidence")
            out[prefix] = claims  # type: ignore[assignment]
        return out

    def pruned(self, keys: Iterable[str]) -> "Scene":
        """Copy without leaves below a cited region unless they are in ``keys``."""
        keep = set(keys)
        out = self.clone()
        out.leaves = {k: v for k, v in out.leaves.items()
                      if k in keep or not out.hidden(k)}
        out._memo.clear()
        return out

    def overlap_cites(self, other: "Scene") -> int:
        return len(set(self.cites) & set(other.cites))


def fmt(digest: str) -> str:
    return "sha256:" + digest


def cite_text(digest: str, prefix: str, depth: int) -> str:
    """Render a canonical empty sub-tree as ``empty`` so proofs stay readable."""
    if digest == empty_node(depth - len(prefix)):
        return "empty"
    return "sha256:" + digest


def parse_cite_text(text: str, prefix: str, depth: int) -> str:
    if text in ("empty", "absent"):
        return empty_node(depth - len(prefix))
    return text[7:] if text.startswith("sha256:") else text


def render_value_proof(scene: Scene, keys: Iterable[str],
                       values: dict[str, str | None]) -> dict:
    """Minimal single-side proof for ``keys`` (citation order is canonical)."""
    keys = sorted(set(keys))
    leaves = [{"key": k, "value": values[k]} for k in keys]
    cites = []
    for prefix in boundary(keys):
        digest = scene.claims(prefix)[0]
        if digest is None:
            raise err("UNDISCLOSED_BRANCH", prefix,
                      f"the region below citation {prefix} is not disclosed "
                      f"by the available evidence")
        cites.append({"prefix": prefix, "hash": cite_text(digest, prefix, scene.depth)})
    return {"leaves": leaves, "citations": cites}


def render_dual_proof(scene: Scene, keys: Iterable[str],
                      values: dict[str, tuple[str | None, str | None]]) -> dict:
    keys = sorted(set(keys))
    leaves = [{"key": k, "old_value": values[k][0], "new_value": values[k][1]} for k in keys]
    cites = []
    for prefix in boundary(keys):
        digest = scene.claims(prefix)[0]
        if digest is None:
            raise err("UNDISCLOSED_BRANCH", prefix,
                      f"the region below citation {prefix} is not disclosed "
                      f"by the available evidence")
        cites.append({"prefix": prefix, "hash": cite_text(digest, prefix, scene.depth)})
    return {"leaves": leaves, "citations": cites}


def scene_of_value_proof(proof) -> Scene:
    scene = Scene(proof.depth, 1)
    for key in proof.keys:
        scene.add_leaf(key, [value_hash(proof.values[key][0])])
    for prefix, digest in proof.cites.items():
        scene.add_cite(prefix, digest)
    return scene


def scene_of_dual_proof(proof) -> Scene:
    scene = Scene(proof.depth, 2)
    for key in proof.keys:
        scene.add_leaf(key, [value_hash(proof.values[key][0]), value_hash(proof.values[key][1])])
    for prefix, digest in proof.cites.items():
        scene.add_cite(prefix, digest)
    return scene
