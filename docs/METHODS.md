# Methods

## Labels

A label is a pair `(sources, readers)`: a set of provenance strings and either `None` (anyone may read) or a set of principals. The join of two labels is `(sources ∪ sources', readers ∩ readers')` with `None` as the identity for the readers intersection. The join is commutative, associative and idempotent (tested on random labels), so the label of a computed value does not depend on evaluation order.

## Policy rules

Rules are evaluated on the labels of a call's arguments before the call runs.

- **Integrity(tool, arg, trusted)**: every source of `arg` must match a pattern in `trusted` (glob, default `user`, `planner`).
- **Deny(tool, arg, sources)**: no source of `arg` may match a denied pattern.
- **Confidentiality(tool, arg, recipient)**: if `arg` has restricted readers, every recipient named in the `recipient` argument must be among them.
- **Confirm(tool)**: a human approver must say yes; with no approver the call is refused.
- **Forbid(tool)**: the tool may never run.

Unregistered tools are refused by default.

## Tool output labelling

A tool's result is labelled with its declared `output_sources` (or `tool:<name>`) and `output_readers`, joined with the labels of all its arguments when `propagate=True` (the default). Setting `propagate=False` is a declaration that the output is independent of the inputs, which is rarely true of anything that transforms text.

## The verification model

The verifier searches the transition system whose state is the set of values the planner holds. Each value has two labels:

- the **configured label**, computed exactly as the runtime monitor computes it (the same `Policy.evaluate` and `Tool.output_label` code), which is what policy rules see;
- the **true provenance**, computed by always propagating every input through every tool and every mix, which is what invariants are judged against.

At each step a worst-case planner may:

1. call any tool with, for each parameter, any held value or any literal listed for that parameter (`literals` in the spec; unlisted parameters get one placeholder literal);
2. mix two held values (modelling an LLM rewriting or concatenating text): the result has the join of both labels.

A call is *allowed* if the policy accepts the configured labels. An allowed call that breaks an invariant on the true provenance is a violation. The search is breadth-first with states merged by the set of `(data, configured label, true provenance)` triples, so the first counterexample for each invariant is a shortest one. If a violation is reachable only through a call that needs human approval, it is reported as such.

**Invariants.** `never_reaches(source, tool, arg)`: no allowed call passes `arg` data whose true sources match `source`. `never_leaks(secret, tool, arg, recipient, allowed)`: no allowed call passes data derived from `secret` to a recipient outside `allowed`. `source` and `tool` are glob patterns, so `tool: "*"` covers every tool with that argument.

**What a verdict means.** A reported counterexample is a sequence the model says is allowed and harmful; the tests replay one on the live monitor. "No violation found" means none exists within the depth, for these tools, labels and literals; it is not a proof about unmodelled behaviour, and a truncated search (`--max-states`) is incomplete.

## Audit log

Each record stores the previous record's hash and `SHA-256(canonical_json(body) || prev)`. Editing, removing or reordering a record breaks the chain; truncating the tail does not, so anchor the head hash somewhere you do not control. Records contain labels and decisions, never argument data.
