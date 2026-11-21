"""Offline model of the archive publication ledger: checkpoints, change edges,
review votes, and the global path/vote planner.

The SQLite layer (:mod:`solution.store`) provides durability; everything here is
pure and deterministic so the planner can be cross-checked exhaustively on small
instances.

Vocabulary
----------
checkpoint
    A version checkpoint.  Its identity is an opaque ``checkpoint_id``; the
    manifest root it carries is only *content*.  Rolling back to a byte-identical
    root creates a **new** checkpoint, never the old one.
edge
    A directed change edge binding ``from``/``to`` checkpoints, a two-root proof
    over the keys it modifies, the branches it keeps unchanged, and the prefix
    policy that allowed the change.  Edges carry a monotonically growing
    registration generation and form a DAG.
vote
    A review signature binding an edge, its root pair, a policy version, one
    sensitive category, a reviewer subject and that subject's institution, plus
    the logical validity window of the review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from .core import err


# --------------------------------------------------------------------------- records

@dataclass(frozen=True)
class Checkpoint:
    checkpoint_id: str
    root: str
    generation: int = 0
    label: str = ""
    policy_version: int = 1


@dataclass(frozen=True)
class Edge:
    edge_id: str
    from_id: str
    to_id: str
    generation: int
    policy_version: int
    proof: dict[str, Any]
    kept_branches: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    archive_use: str = ""
    label: str = ""

    def changed_keys(self) -> list[str]:
        return sorted({leaf["key"] for leaf in self.proof["leaves"]
                       if leaf.get("old_value") != leaf.get("new_value")})

    def disclosed_keys(self) -> set[str]:
        return {leaf["key"] for leaf in self.proof["leaves"]}


@dataclass(frozen=True)
class Vote:
    vote_id: str
    edge_id: str
    category: str
    reviewer_id: str
    institution_id: str
    policy_version: int
    old_root: str
    new_root: str
    issued_at: int
    expires_at: int
    signature: str = ""

    def valid_at(self, clock: int) -> bool:
        return self.issued_at <= clock < self.expires_at


@dataclass
class World:
    """All evidence visible to the planner (verified rows only)."""

    checkpoints: dict[str, Checkpoint] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)
    votes: dict[str, Vote] = field(default_factory=dict)
    revoked: dict[str, int] = field(default_factory=dict)
    consumed: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    institutions: dict[str, str] = field(default_factory=dict)
    fragments: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------ lookup

    def subject(self, reviewer_id: str) -> str:
        """Canonical review subject; aliases collapse onto one person."""
        seen: set[str] = set()
        current = reviewer_id
        while current in self.aliases and current not in seen:
            seen.add(current)
            current = self.aliases[current]
        return current

    def institution_of(self, vote: Vote) -> str:
        return self.institutions.get(self.subject(vote.reviewer_id), vote.institution_id)

    def usable_votes(self, clock: int) -> dict[str, Vote]:
        return {vid: v for vid, v in self.votes.items()
                if vid not in self.revoked and vid not in self.consumed and v.valid_at(clock)}

    def outgoing(self) -> dict[str, list[Edge]]:
        out: dict[str, list[Edge]] = {}
        for edge in self.edges.values():
            out.setdefault(edge.from_id, []).append(edge)
        for bucket in out.values():
            bucket.sort(key=lambda e: (e.generation, e.edge_id))
        return out


# --------------------------------------------------------------------------- votes

def vote_options(world: World, edge: Edge, category: str, clock: int,
                 policy_version: int) -> list[tuple[str, str, str, str]]:
    """Pairs of votes ``(v1, v2, subject1, subject2)`` usable for one slot.

    Both votes must bind this edge, its root pair, this policy version and this
    category, be inside their logical validity window, be neither revoked nor
    consumed, and have two distinct subjects and two distinct institutions.
    """
    from_id = world.checkpoints[edge.from_id].root
    to_id = world.checkpoints[edge.to_id].root
    eligible = []
    for vote in world.usable_votes(clock).values():
        if vote.edge_id != edge.edge_id or vote.category != category:
            continue
        if vote.policy_version != policy_version:
            continue
        if vote.old_root != from_id or vote.new_root != to_id:
            continue
        eligible.append(vote)
    eligible.sort(key=lambda v: v.vote_id)
    options = []
    for i, a in enumerate(eligible):
        for b in eligible[i + 1:]:
            sa, sb = world.subject(a.reviewer_id), world.subject(b.reviewer_id)
            if sa == sb:
                continue
            if world.institution_of(a) == world.institution_of(b):
                continue
            options.append((a.vote_id, b.vote_id, sa, sb))
    return options


def assign_votes(world: World, path: Sequence[Edge], clock: int, policy_version: int,
                 limit: int = 20000) -> tuple[list[tuple[int, str, str, str]], str] | None:
    """Smallest global, conflict-free vote assignment for ``path``.

    Returns ``(votes, "")`` where votes are ``(hop, category, vote_id, subject)``
    sorted by ``(hop, category, vote_id)``; or ``(None, reason)`` when no
    assignment exists.  The whole path is solved jointly: a vote or a subject may
    appear at most once across hops and categories, aliases included.
    """
    slots: list[tuple[int, str, list[tuple[str, str, str, str]]]] = []
    for hop, edge in enumerate(path, start=1):
        for category in edge.categories:
            options = vote_options(world, edge, category, clock, policy_version)
            if not options:
                return None, f"no valid vote pair for hop {hop} category {category}"
            slots.append((hop, category, options))
    slots.sort(key=lambda s: (len(s[2]), s[0], s[1]))

    best: list[tuple[int, str, str, str]] | None = None
    best_key: tuple | None = None
    explored = 0

    def dfs(index: int, used_votes: set[str], used_subjects: set[str],
            chosen: list[tuple[int, str, str, str]]) -> None:
        nonlocal best, best_key, explored
        explored += 1
        if explored > limit:
            return
        if index == len(slots):
            key = tuple(sorted(chosen))
            if best_key is None or key < best_key:
                best, best_key = list(chosen), key
            return
        hop, category, options = slots[index]
        for v1, v2, s1, s2 in options:
            if v1 in used_votes or v2 in used_votes:
                continue
            if s1 in used_subjects or s2 in used_subjects:
                continue
            used_votes.update((v1, v2))
            used_subjects.update((s1, s2))
            chosen.append((hop, category, v1, s1))
            chosen.append((hop, category, v2, s2))
            dfs(index + 1, used_votes, used_subjects, chosen)
            chosen.pop()
            chosen.pop()
            used_votes.difference_update((v1, v2))
            used_subjects.difference_update((s1, s2))

    dfs(0, set(), set(), [])
    if best is None:
        return None, f"no conflict-free global vote assignment over {len(slots)} review slots"
    return best, ""


# --------------------------------------------------------------------------- paths

def enumerate_paths(world: World, start: str, end: str, *, max_paths: int = 200000,
                    max_hops: int = 64) -> list[tuple[str, ...]]:
    """All simple paths from ``start`` to ``end``, sorted by edge-id sequence."""
    outgoing = world.outgoing()
    paths: list[tuple[str, ...]] = []
    stack: list[tuple[str, tuple[str, ...], frozenset[str]]] = [(start, (), frozenset({start}))]
    while stack:
        node, trail, seen = stack.pop()
        if len(trail) >= max_hops:
            continue
        for edge in outgoing.get(node, ()):
            if edge.to_id == edge.from_id:
                continue
            if edge.to_id == end:
                paths.append(trail + (edge.edge_id,))
                if len(paths) > max_paths:
                    raise err("PATH_EXPLOSION", "graph",
                              f"more than {max_paths} candidate paths; tighten the request")
                continue
            if edge.to_id in seen:
                continue
            stack.append((edge.to_id, trail + (edge.edge_id,), seen | {edge.to_id}))
    paths.sort()
    return paths


@dataclass
class Plan:
    edge_ids: tuple[str, ...]
    votes: tuple[tuple[int, str, str, str], ...]
    disclosed_keys: int
    roots: tuple[str, ...]
    rebase: Any = None

    def sort_key(self) -> tuple:
        return (self.disclosed_keys, len(self.edge_ids), self.edge_ids,
                tuple(sorted((h, c, v) for h, c, v, _ in self.votes)))


def check_path(world: World, edge_ids: Sequence[str], *, policy_version: int,
               start: str, end: str) -> str | None:
    """Continuity/registration problems of one candidate path, or ``None``."""
    node = start
    for i, eid in enumerate(edge_ids):
        edge = world.edges[eid]
        if edge.from_id != node:
            return f"hop {i + 1} does not start at the current checkpoint"
        if edge.policy_version != policy_version:
            return (f"hop {i + 1} was registered under policy version "
                    f"{edge.policy_version}, not {policy_version}")
        node = edge.to_id
    if node != end:
        return "the path does not end at the requested checkpoint"
    return None
