"""Joint path + review-vote search over the ledger DAG.

The planner must not assume that per-hop optimality implies global optimality:
a cheap edge can consume the only reviewers a later hop needs.  So the search
explores ``(checkpoint, consumed votes, consumed review subjects)`` labels and
only prunes a label when another label at the same checkpoint is provably at
least as good *and* leaves at least as much freedom:

    same checkpoint
    and used_votes   subset of the other
    and used_subjects subset of the other
    and disclosed    subset of the other
    and cost         <= the other

Two labels reaching the same checkpoint with different consumed vote sets are
never merged, which is exactly the rule the brief calls out.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Sequence

from .core import err
from .ledger_model import Edge, World, vote_options


@dataclass(frozen=True)
class Label:
    node: str
    used_votes: frozenset[str]
    used_subjects: frozenset[str]
    disclosed: frozenset[str]
    hops: tuple[str, ...]
    votes: tuple[tuple[int, str, str], ...]

    @property
    def key(self) -> tuple:
        return (len(self.disclosed), len(self.hops), self.hops, self.votes)


def _pairs(world: World, edge: Edge, clock: int, policy_version: int) -> list[list]:
    """Every internally consistent vote assignment for one edge.

    One two-vote pair per sensitive category of the edge; inside the edge the
    pairs must not share a vote or a review subject either, because the global
    "one vote, one subject per request" rule already applies across categories.
    """
    per_category = []
    for category in edge.categories:
        options = vote_options(world, edge, category, clock, policy_version)
        if not options:
            return []
        per_category.append([(category, o) for o in options])
    if not per_category:
        return [[]]

    out: list[list] = []

    def walk(index: int, votes: set[str], subjects: set[str], chosen: list) -> None:
        if index == len(per_category):
            out.append(list(chosen))
            return
        for category, (v1, v2, s1, s2) in per_category[index]:
            if {v1, v2} & votes or {s1, s2} & subjects:
                continue
            votes |= {v1, v2}
            subjects |= {s1, s2}
            chosen.append((category, v1, v2, s1, s2))
            walk(index + 1, votes, subjects, chosen)
            chosen.pop()
            votes -= {v1, v2}
            subjects -= {s1, s2}

    walk(0, set(), set(), [])
    return out


def search(world: World, start: str, end: str, *, clock: int, policy_version: int,
           max_states: int = 400_000, keep_labels: int = 3) -> Label:
    """Optimal feasible label from ``start`` to ``end``."""
    outgoing: dict[str, list[Edge]] = {}
    for edge in world.edges.values():
        if edge.policy_version != policy_version:
            continue
        if edge.from_id not in world.checkpoints or edge.to_id not in world.checkpoints:
            continue
        outgoing.setdefault(edge.from_id, []).append(edge)
    for bucket in outgoing.values():
        bucket.sort(key=lambda e: (e.generation, e.edge_id))

    start_label = Label(start, frozenset(), frozenset(), frozenset(), (), ())
    heap: list[tuple] = [(start_label.key, 0, start_label)]
    counter = 1
    best: dict[str, list[Label]] = {start: [start_label]}
    states = 0
    completed: Label | None = None

    while heap:
        key, _, label = heapq.heappop(heap)
        if completed is not None and key >= completed.key:
            break
        if label.node == end and label.hops:
            completed = label
            break
        states += 1
        if states > max_states:
            raise err("PLAN_BUDGET_EXCEEDED", "graph",
                      f"the joint path/vote search exceeded {max_states} states; "
                      f"narrow the request (fewer candidate edges or reviewers)")
        for edge in outgoing.get(label.node, ()):
            if edge.to_id in _visited(label.hops, world) and edge.to_id != end:
                continue
            if edge.to_id == label.node:
                continue
            for assignment in _pairs(world, edge, clock, policy_version):
                votes = set(label.used_votes)
                subjects = set(label.used_subjects)
                ok = True
                entries = []
                hop = len(label.hops) + 1
                for category, v1, v2, s1, s2 in assignment:
                    if {v1, v2} & votes or {s1, s2} & subjects:
                        ok = False
                        break
                    votes |= {v1, v2}
                    subjects |= {s1, s2}
                    entries += [(hop, category, v1), (hop, category, v2)]
                if not ok:
                    continue
                child = Label(
                    node=edge.to_id,
                    used_votes=frozenset(votes),
                    used_subjects=frozenset(subjects),
                    disclosed=label.disclosed | frozenset(edge.disclosed_keys()),
                    hops=label.hops + (edge.edge_id,),
                    votes=tuple(sorted(label.votes + tuple(entries))),
                )
                if not _admit(best, child, keep_labels):
                    continue
                heapq.heappush(heap, (child.key, counter, child))
                counter += 1

    if completed is None:
        return None  # type: ignore[return-value]
    return completed


def _visited(hops: Sequence[str], world: World) -> set[str]:
    seen = {world.edges[e].from_id for e in hops}
    seen |= {world.edges[e].to_id for e in hops}
    return seen


def _admit(best: dict[str, list[Label]], child: Label, keep_labels: int) -> bool:
    """Dominated-label pruning for one checkpoint."""
    bucket = best.setdefault(child.node, [])
    for other in bucket:
        if (other.disclosed <= child.disclosed
                and other.used_votes <= child.used_votes
                and other.used_subjects <= child.used_subjects
                and other.key <= child.key):
            return False
    bucket[:] = [other for other in bucket
                 if not (child.disclosed <= other.disclosed
                         and child.used_votes <= other.used_votes
                         and child.used_subjects <= other.used_subjects
                         and child.key <= other.key)]
    bucket.append(child)
    if len(bucket) > keep_labels * 64:
        bucket.sort(key=lambda l: l.key)
        del bucket[keep_labels * 64:]
    return True
