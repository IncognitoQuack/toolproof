"""Bounded exhaustive verification of an agent's tool policy.

Given your tools (what each one returns and how it is labelled), your policy, and the
safety invariants you care about, :func:`verify` searches **every** sequence of tool
calls up to ``depth`` steps that a fully compromised planner could issue, and reports
the shortest sequence that makes an *allowed* call break an invariant.

The planner model is deliberately the worst case: at each step it may call any tool with
any combination of the values it holds or any literal it can write, or mix values together
(modelling an LLM rewriting or concatenating text).  The search runs the same
:class:`~toolproof.policy.Policy` and the same output-labelling code as the runtime
monitor, so what is verified is what is enforced.

Invariants are judged against the *true* provenance of each value (always propagated through
every tool and mix), while the policy sees only the labels your configuration produces.  A tool
configured with ``propagate=False`` therefore shows up as a violation: the policy is blind to
data that the invariant can still see.

"No violation found" is a statement about this model and this depth only.
"""
from __future__ import annotations

import itertools
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .labels import Label, Value
from .monitor import Tool
from .policy import Policy, matches

__all__ = ["ToolSpec", "Spec", "NeverReaches", "NeverLeaks", "Counterexample", "Result", "verify",
           "invariant_from_dict"]


@dataclass(frozen=True)
class NeverReaches:
    """No allowed call may pass ``tool.arg`` data derived from a source matching ``source``.

    ``source`` and ``tool`` are glob patterns, so ``tool="*"`` covers every tool that has the
    argument, including ones added later or forgotten."""
    source: str
    tool: str
    arg: str

    def violated(self, tool: str, args: Mapping[str, Value]) -> Optional[str]:
        if not matches(tool, [self.tool]) or self.arg not in args:
            return None
        bad = sorted(s for s in args[self.arg].label.sources if matches(s, [self.source]))
        if bad:
            return f"{tool}.{self.arg} was derived from {', '.join(bad)}"
        return None

    def describe(self) -> str:
        return f"no data derived from '{self.source}' may reach {self.tool}.{self.arg}"


@dataclass(frozen=True)
class NeverLeaks:
    """Data derived from ``secret`` may go out through ``tool.arg`` only to ``allowed`` recipients."""
    secret: str
    tool: str
    arg: str
    recipient: str
    allowed: tuple = ()

    def violated(self, tool: str, args: Mapping[str, Value]) -> Optional[str]:
        if not matches(tool, [self.tool]) or self.arg not in args or self.recipient not in args:
            return None
        srcs = [s for s in args[self.arg].label.sources if matches(s, [self.secret])]
        if not srcs:
            return None
        who = args[self.recipient].data
        who = [who] if isinstance(who, str) else list(who)
        bad = [str(w) for w in who if w not in self.allowed]
        if bad:
            return f"{tool}.{self.arg} carried data from {', '.join(sorted(srcs))} to {', '.join(bad)}"
        return None

    def describe(self) -> str:
        return (f"data derived from '{self.secret}' may leave through {self.tool}.{self.arg} "
                f"only to {list(self.allowed)}")


def invariant_from_dict(d: dict):
    k = d["invariant"]
    if k == "never_reaches":
        return NeverReaches(d["source"], d["tool"], d["arg"])
    if k == "never_leaks":
        return NeverLeaks(d["secret"], d["tool"], d["arg"], d["recipient"], tuple(d.get("allowed", ())))
    raise ValueError(f"unknown invariant kind {k!r}")


@dataclass
class ToolSpec:
    name: str
    params: Sequence[str] = ()
    output_sources: tuple = ()
    output_readers: Optional[tuple] = None
    propagate: bool = True
    output: str = "result"

    def as_tool(self) -> Tool:
        out = self.output
        return Tool(self.name, lambda **_k: out, tuple(self.output_sources),
                    None if self.output_readers is None else tuple(self.output_readers), self.propagate)


@dataclass
class Spec:
    tools: List[ToolSpec]
    policy: Policy
    literals: Dict[str, List[str]] = field(default_factory=dict)
    seed: List[Value] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict) -> "Spec":
        tools = [ToolSpec(t["name"], tuple(t.get("params", ())), tuple(t.get("output_sources", ())),
                          None if t.get("output_readers") is None else tuple(t["output_readers"]),
                          t.get("propagate", True), t.get("output", "result")) for t in d["tools"]]
        seed = [Value(s.get("data", "seed"), Label.from_dict(s)) for s in d.get("seed_values", [])]
        return Spec(tools, Policy.from_dict(d.get("policy", [])), d.get("literals", {}), seed)


@dataclass
class Counterexample:
    invariant: str
    message: str
    steps: List[str]
    needs_approval: bool = False


@dataclass
class Result:
    violations: List[Counterexample]
    explored: int
    blocked: int
    depth: int
    truncated: bool
    unviolated: List[str]

    @property
    def ok(self) -> bool:
        return not self.violations

    def __str__(self) -> str:
        lines = [f"explored {self.explored} states to depth {self.depth}; "
                 f"{self.blocked} calls were blocked by the policy"
                 + ("; SEARCH TRUNCATED (raise --max-states for a complete search)" if self.truncated else "")]
        if not self.violations:
            lines.append("no invariant violation found within this bound"
                         + (" (incomplete: truncated)" if self.truncated else ""))
        for c in self.violations:
            tag = " [only after human approval]" if c.needs_approval else ""
            lines += ["", f"VIOLATION{tag}: {c.invariant}", f"  {c.message}", "  shortest sequence:"]
            lines += [f"    {i + 1}. {s}" for i, s in enumerate(c.steps)]
        for u in self.unviolated:
            lines.append(f"holds within bound: {u}")
        return "\n".join(lines)


@dataclass(frozen=True)
class _Item:
    val: Value      # carries the label the *policy* sees
    true: Label     # ground-truth provenance, always propagated


def _describe(v: Value, idx: Optional[int], literal: Optional[str]) -> str:
    if literal is not None:
        return f"literal {literal!r}"
    src = ",".join(sorted(v.label.sources)) or "-"
    return f"#{idx} [{src}]"


def verify(spec: Spec, invariants: Sequence[Any], depth: int = 4, max_states: int = 200_000) -> Result:
    tools = {t.name: t.as_tool() for t in spec.tools}
    specs = {t.name: t for t in spec.tools}

    def literal_values(tool: str, param: str) -> List[Tuple[_Item, str]]:
        lits = spec.literals.get(f"{tool}.{param}", spec.literals.get(param, ["<literal>"]))
        return [(_Item(Value.const(x, ("planner",)), Label.make(("planner",))), x) for x in lits]

    def key(items: Sequence[_Item]) -> frozenset:
        return frozenset((repr(i.val.data), i.val.label, i.true) for i in items)

    seed = list(spec.seed) if spec.seed else [Value.const("<user text>", ("user",))]
    start = [_Item(v, v.label) for v in seed]
    queue: deque = deque([(start, [])])
    seen = {key(start)}
    found: Dict[int, Counterexample] = {}
    explored = blocked = 0
    truncated = False

    for _level in range(depth):
        nxt: deque = deque()
        while queue:
            values, steps = queue.popleft()
            options: List[Tuple[str, Optional[Dict[str, _Item]], Optional[str], Optional[_Item]]] = []
            # tool calls
            for name, ts in specs.items():
                per_param = []
                for p in ts.params:
                    cands = [(v, _describe(v.val, i + 1, None)) for i, v in enumerate(values)]
                    cands += [(v, _describe(v.val, None, lit)) for v, lit in literal_values(name, p)]
                    per_param.append(cands)
                for combo in itertools.product(*per_param) if per_param else [()]:
                    args = {p: c[0] for p, c in zip(ts.params, combo)}
                    desc = f"{name}({', '.join(f'{p}={c[1]}' for p, c in zip(ts.params, combo))})"
                    options.append((name, args, desc, None))
            # mixing two held values (an LLM rewriting or concatenating text)
            for i, j in itertools.combinations(range(len(values)), 2):
                a, b = values[i], values[j]
                data = "+".join(sorted({str(a.val.data), str(b.val.data)}))
                options.append(("", None, f"mix(#{i + 1}, #{j + 1})",
                                _Item(Value(data, a.val.label.join(b.val.label)), a.true.join(b.true))))

            for name, args, desc, mixed in options:
                explored += 1
                if explored > max_states:
                    truncated = True
                    break
                if mixed is not None:
                    new_values = values + [mixed]
                    k = key(new_values)
                    if k not in seen:
                        seen.add(k)
                        nxt.append((new_values, steps + [desc]))
                    continue
                seen_by_policy = {p: it.val for p, it in args.items()}
                dec = spec.policy.evaluate(name, seen_by_policy)
                if not dec.allowed:
                    blocked += 1
                    continue
                truth = {p: Value(it.val.data, it.true) for p, it in args.items()}
                for n, inv in enumerate(invariants):
                    msg = inv.violated(name, truth)
                    if msg and (n not in found or (found[n].needs_approval and not dec.needs_confirm)):
                        found[n] = Counterexample(inv.describe(), msg, steps + [desc], dec.needs_confirm)
                ts = specs[name]
                out_true = Label.join_all([
                    Label.make(ts.output_sources or (f"tool:{name}",), ts.output_readers),
                    *(it.true for it in args.values())])
                out = _Item(Value(ts.output, tools[name].output_label(seen_by_policy)), out_true)
                new_values = values + [out]
                k = key(new_values)
                if k not in seen:
                    seen.add(k)
                    nxt.append((new_values, steps + [desc]))
            if truncated:
                break
        queue = nxt
        if truncated or not queue:
            break
        if len(found) == len(invariants) and all(not c.needs_approval for c in found.values()):
            break

    unviolated = [inv.describe() for n, inv in enumerate(invariants) if n not in found]
    return Result([found[n] for n in sorted(found)], explored, blocked, depth, truncated, unviolated)
