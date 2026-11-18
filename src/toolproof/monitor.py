"""Runtime reference monitor: every tool call passes through :meth:`Monitor.call`."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional

from .labels import Label, Value
from .policy import Decision, Policy, Violation

__all__ = ["Tool", "Monitor", "PolicyViolation", "AuditLog", "AuditError"]


class PolicyViolation(Exception):
    def __init__(self, tool: str, violations: List[Violation]):
        self.tool = tool
        self.violations = violations
        super().__init__("; ".join(v.message for v in violations) or f"{tool} denied")


class AuditError(Exception):
    pass


@dataclass
class Tool:
    """A callable the agent may use.

    ``output_sources`` / ``output_readers`` label what the tool returns (a tool that reads
    attacker-controllable content must say so).  With ``propagate=True`` (the safe default) the
    result also inherits the labels of every argument, so data cannot be laundered by passing
    it through the tool.
    """
    name: str
    fn: Callable[..., Any]
    output_sources: tuple = ()
    output_readers: Optional[tuple] = None
    propagate: bool = True

    def output_label(self, args: Mapping[str, Value]) -> Label:
        label = Label.make(self.output_sources or (f"tool:{self.name}",), self.output_readers)
        if self.propagate:
            label = Label.join_all([label, *(v.label for v in args.values())])
        return label


class AuditLog:
    """Hash-chained record of every decision.  Raw data is never stored: only labels."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.records: List[dict] = []
        self.head = "0" * 64

    def append(self, body: dict) -> dict:
        body = dict(body, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")) + self.head
        digest = hashlib.sha256(payload.encode()).hexdigest()
        rec = {"body": body, "prev": self.head, "hash": digest}
        self.head = digest
        self.records.append(rec)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    @staticmethod
    def verify_records(records: List[dict]) -> str:
        prev = "0" * 64
        for i, rec in enumerate(records):
            try:
                body, h, p = rec["body"], rec["hash"], rec["prev"]
            except (KeyError, TypeError):
                raise AuditError(f"record {i + 1}: malformed")
            if p != prev:
                raise AuditError(f"record {i + 1}: chain broken (record removed, reordered or edited)")
            payload = json.dumps(body, sort_keys=True, separators=(",", ":")) + prev
            if hashlib.sha256(payload.encode()).hexdigest() != h:
                raise AuditError(f"record {i + 1}: hash mismatch (record edited)")
            prev = h
        return prev

    @classmethod
    def verify_file(cls, path: str) -> str:
        recs = []
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if line.strip():
                    try:
                        recs.append(json.loads(line))
                    except ValueError:
                        raise AuditError(f"line {i + 1}: not valid JSON")
        return cls.verify_records(recs)


def _summary(v: Value) -> dict:
    d = v.data
    return {"type": type(d).__name__, "sources": sorted(v.label.sources),
            "restricted": v.label.readers is not None}


class Monitor:
    """Enforces a :class:`Policy` on every tool call and keeps an audit trail.

    Arguments that are not :class:`Value` are treated as written by the planner (label source
    ``"planner"``).  That is only safe if the planner never sees untrusted content; give it
    handles (see :meth:`execute`) instead of raw data.
    """

    def __init__(self, policy: Policy, tools: List[Tool] = (), approver: Optional[Callable[..., bool]] = None,
                 audit_path: Optional[str] = None, default_deny: bool = True):
        self.policy = policy
        self.tools: Dict[str, Tool] = {t.name: t for t in tools}
        self.approver = approver
        self.default_deny = default_deny
        self.audit = AuditLog(audit_path)
        self._store: Dict[str, Value] = {}

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    # -- core ----------------------------------------------------------------

    @staticmethod
    def _wrap(args: Mapping[str, Any]) -> Dict[str, Value]:
        return {k: (v if isinstance(v, Value) else Value.const(v, ("planner",))) for k, v in args.items()}

    def check(self, tool: str, args: Mapping[str, Any]) -> Decision:
        """Decision for a call without running it."""
        wrapped = self._wrap(args)
        if tool not in self.tools and self.default_deny:
            return Decision(False, [Violation("unknown-tool", tool, None, f"{tool} is not a registered tool")])
        return self.policy.evaluate(tool, wrapped)

    def call(self, tool: str, **args: Any) -> Value:
        wrapped = self._wrap(args)
        labels = {k: v.label.to_dict() for k, v in wrapped.items()}
        dec = self.check(tool, wrapped)
        if not dec.allowed:
            self.audit.append({"event": "deny", "tool": tool, "args": labels,
                               "violations": [v.to_dict() for v in dec.violations]})
            raise PolicyViolation(tool, dec.violations)
        if dec.needs_confirm:
            approved = bool(self.approver and self.approver(tool, {k: _summary(v) for k, v in wrapped.items()}))
            if not approved:
                v = Violation("confirm", tool, None, f"{tool} needs human approval and none was given")
                self.audit.append({"event": "deny", "tool": tool, "args": labels, "violations": [v.to_dict()]})
                raise PolicyViolation(tool, [v])
        t = self.tools[tool]
        result = t.fn(**{k: v.data for k, v in wrapped.items()})
        out = Value(result, t.output_label(wrapped))
        self.audit.append({"event": "allow", "tool": tool, "args": labels,
                           "confirmed": dec.needs_confirm, "result": out.label.to_dict()})
        return out

    # -- planner-facing, data-free interface --------------------------------------

    def store(self, value: Value) -> str:
        ref = f"v{len(self._store) + 1}"
        self._store[ref] = value
        return ref

    def execute(self, call: Mapping[str, Any]) -> dict:
        """Run a JSON-style tool call from a planner and return a JSON-safe reply.

        ``{"tool": "send", "args": {"to": "a@x.com", "body": {"$ref": "v3"}}}``.  Results are stored
        and returned as handles with a metadata summary, so the planner never reads the data.
        """
        args = {}
        for k, v in call.get("args", {}).items():
            if isinstance(v, dict) and set(v) == {"$ref"}:
                if v["$ref"] not in self._store:
                    return {"ok": False, "error": f"unknown reference {v['$ref']}"}
                args[k] = self._store[v["$ref"]]
            else:
                args[k] = v
        try:
            out = self.call(call["tool"], **args)
        except PolicyViolation as e:
            return {"ok": False, "error": "denied by policy",
                    "violations": [v.to_dict() for v in e.violations]}
        except KeyError as e:
            return {"ok": False, "error": f"bad call: missing {e}"}
        return {"ok": True, "ref": self.store(out), "summary": _summary(out)}
