"""Command line: toolproof verify SPEC.json | toolproof audit LOG.jsonl."""
from __future__ import annotations

import argparse
import json
import sys

from .monitor import AuditError, AuditLog
from .verify import Spec, invariant_from_dict, verify


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="toolproof", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="search for tool-call sequences that break your invariants")
    v.add_argument("spec", help="JSON file: tools, policy, literals, invariants")
    v.add_argument("--depth", type=int, default=4)
    v.add_argument("--max-states", type=int, default=200_000)
    v.add_argument("--json", action="store_true")
    a = sub.add_parser("audit", help="verify the hash chain of an audit log and summarise it")
    a.add_argument("log")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "verify":
            with open(args.spec, encoding="utf-8") as fh:
                raw = json.load(fh)
            spec = Spec.from_dict(raw)
            invs = [invariant_from_dict(d) for d in raw.get("invariants", [])]
            if not invs:
                print("toolproof: the spec lists no invariants", file=sys.stderr)
                return 2
            res = verify(spec, invs, args.depth, args.max_states)
            if args.json:
                print(json.dumps({
                    "ok": res.ok, "explored": res.explored, "blocked": res.blocked, "depth": res.depth,
                    "truncated": res.truncated,
                    "violations": [c.__dict__ for c in res.violations],
                    "holds": res.unviolated}, indent=2))
            else:
                print(res)
            return 0 if res.ok and not res.truncated else 1
        head = AuditLog.verify_file(args.log)
        with open(args.log, encoding="utf-8") as fh:
            recs = [json.loads(ln) for ln in fh if ln.strip()]
        allow = sum(r["body"]["event"] == "allow" for r in recs)
        deny = sum(r["body"]["event"] == "deny" for r in recs)
        print(f"ok: {len(recs)} records ({allow} allowed, {deny} denied), head {head[:16]}")
        return 0
    except (AuditError, OSError, ValueError, KeyError) as e:
        print(f"toolproof: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
