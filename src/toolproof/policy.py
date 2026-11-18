"""Declarative policy rules over labelled tool-call arguments."""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

from .labels import TRUSTED_DEFAULT, Value

__all__ = ["Violation", "Policy", "Integrity", "Deny", "Confidentiality", "Confirm", "Forbid",
           "matches", "rule_from_dict"]


def matches(source: str, patterns: Iterable[str]) -> bool:
    return any(fnmatchcase(source, p) for p in patterns)


@dataclass(frozen=True)
class Violation:
    rule: str
    tool: str
    arg: Optional[str]
    message: str
    sources: tuple = ()

    def to_dict(self) -> dict:
        return {"rule": self.rule, "tool": self.tool, "arg": self.arg,
                "message": self.message, "sources": list(self.sources)}


class Rule:
    kind = "rule"

    def check(self, tool: str, args: Mapping[str, Value]) -> List[Violation]:
        return []

    def to_dict(self) -> dict:
        raise NotImplementedError


@dataclass(frozen=True)
class Integrity(Rule):
    """``arg`` of ``tool`` may be derived only from ``trusted`` sources (glob patterns)."""
    tool: str
    arg: str
    trusted: tuple = TRUSTED_DEFAULT
    kind = "integrity"

    def check(self, tool, args):
        if tool != self.tool or self.arg not in args:
            return []
        bad = sorted(s for s in args[self.arg].label.sources if not matches(s, self.trusted))
        if not bad:
            return []
        return [Violation(self.kind, tool, self.arg,
                          f"{tool}.{self.arg} is derived from untrusted source(s): {', '.join(bad)}",
                          tuple(bad))]

    def to_dict(self):
        return {"rule": self.kind, "tool": self.tool, "arg": self.arg, "trusted": list(self.trusted)}


@dataclass(frozen=True)
class Deny(Rule):
    """``arg`` of ``tool`` must not be derived from any source matching ``sources``."""
    tool: str
    arg: str
    sources: tuple = ()
    kind = "deny"

    def check(self, tool, args):
        if tool != self.tool or self.arg not in args:
            return []
        bad = sorted(s for s in args[self.arg].label.sources if matches(s, self.sources))
        if not bad:
            return []
        return [Violation(self.kind, tool, self.arg,
                          f"{tool}.{self.arg} is derived from denied source(s): {', '.join(bad)}",
                          tuple(bad))]

    def to_dict(self):
        return {"rule": self.kind, "tool": self.tool, "arg": self.arg, "sources": list(self.sources)}


@dataclass(frozen=True)
class Confidentiality(Rule):
    """Recipients named in ``recipient`` must be allowed readers of ``arg``.

    If ``arg``'s label has ``readers=None`` it is unrestricted and passes; otherwise every
    recipient (a string or a list of strings) must be in ``readers``."""
    tool: str
    arg: str
    recipient: str
    kind = "confidentiality"

    def check(self, tool, args):
        if tool != self.tool or self.arg not in args or self.recipient not in args:
            return []
        readers = args[self.arg].label.readers
        if readers is None:
            return []
        who = args[self.recipient].data
        who = [who] if isinstance(who, str) else list(who)
        bad = sorted(str(w) for w in who if w not in readers)
        if not bad:
            return []
        return [Violation(self.kind, tool, self.arg,
                          f"{tool}.{self.arg} may only be read by {sorted(readers)}, "
                          f"but {self.recipient} includes {bad}", tuple(bad))]

    def to_dict(self):
        return {"rule": self.kind, "tool": self.tool, "arg": self.arg, "recipient": self.recipient}


@dataclass(frozen=True)
class Confirm(Rule):
    """Calls to ``tool`` need a human to approve them (fails closed with no approver)."""
    tool: str
    kind = "confirm"

    def to_dict(self):
        return {"rule": self.kind, "tool": self.tool}


@dataclass(frozen=True)
class Forbid(Rule):
    """``tool`` may never be called."""
    tool: str
    kind = "forbid"

    def check(self, tool, args):
        if tool == self.tool:
            return [Violation(self.kind, tool, None, f"{tool} is forbidden")]
        return []

    def to_dict(self):
        return {"rule": self.kind, "tool": self.tool}


def rule_from_dict(d: dict) -> Rule:
    k = d["rule"]
    if k == "integrity":
        return Integrity(d["tool"], d["arg"], tuple(d.get("trusted", TRUSTED_DEFAULT)))
    if k == "deny":
        return Deny(d["tool"], d["arg"], tuple(d["sources"]))
    if k == "confidentiality":
        return Confidentiality(d["tool"], d["arg"], d["recipient"])
    if k == "confirm":
        return Confirm(d["tool"])
    if k == "forbid":
        return Forbid(d["tool"])
    raise ValueError(f"unknown rule kind {k!r}")


@dataclass
class Decision:
    allowed: bool
    violations: List[Violation] = field(default_factory=list)
    needs_confirm: bool = False


class Policy:
    """A list of rules.  Tools with no rule of any kind are still callable; add ``Forbid`` or
    set ``Monitor(default_deny=True)`` to refuse tools that were never registered."""

    def __init__(self, rules: Sequence[Rule] = ()):
        self.rules = list(rules)

    def evaluate(self, tool: str, args: Mapping[str, Value]) -> Decision:
        violations: List[Violation] = []
        for r in self.rules:
            violations.extend(r.check(tool, args))
        confirm = any(isinstance(r, Confirm) and r.tool == tool for r in self.rules)
        return Decision(not violations, violations, confirm)

    def to_dict(self) -> list:
        return [r.to_dict() for r in self.rules]

    @staticmethod
    def from_dict(items: Iterable[dict]) -> "Policy":
        return Policy([rule_from_dict(d) for d in items])
