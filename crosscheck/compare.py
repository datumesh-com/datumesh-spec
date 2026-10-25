# SPDX-License-Identifier: Apache-2.0
"""Compare runner outputs field by field: python vs javascript vs reference.

A field absent from an output counts as null."""
import json
import sys
from collections import Counter

FIELDS = ("error", "canonical", "sha256", "sig", "level", "code", "object", "https", "key_id", "key_ids",
          "unit", "outcome", "trust", "receipt_hash",
          # spec-0.4.0: slices and the formula dialect
          "slice_id", "members_hash", "entry", "ast_sha256", "body", "inputs", "returns", "asof_dependent", "token",
          "value", "lineage", "tx", "receipt_asof", "fuel_used", "results",
          # spec-0.4.1: mesh documents
          "bindings", "endpoints")
runs = {name: [json.loads(l) for l in open(path)] for name, path in (a.split("=") for a in sys.argv[1:])}
names = list(runs)
n = len(runs[names[0]])
assert all(len(r) == n for r in runs.values()), {k: len(v) for k, v in runs.items()}
mismatches, codes, skipped = [], Counter(), Counter()
for i in range(n):
    rows = {k: runs[k][i] for k in names}
    ids = {r["id"] for r in rows.values()}
    assert len(ids) == 1, ids
    # A runner that does not implement a kind prints {"id", "error": null, "skipped": "<kind>"}
    # (SPEC 11): it is not compared on that case. The reference never skips.
    for k, r in rows.items():
        if "skipped" in r:
            assert r.get("error") is None and set(r) <= {"id", "error", "skipped"}, (k, r)
            skipped[(k, r["skipped"])] += 1
    rows = {k: r for k, r in rows.items() if "skipped" not in r}
    for f in FIELDS:
        vals = {k: rows[k].get(f) for k in rows}
        if len({json.dumps(x, sort_keys=True) for x in vals.values()}) > 1:  # member order is not data
            mismatches.append((ids.pop() if ids else i, f, vals))
            break
    if rows:
        codes[next(iter(rows.values())).get("error") or "OK"] += 1
print(f"{n} cases, runners: {', '.join(names)}")
print("outcomes:", dict(codes.most_common()))
if skipped:
    print("skipped:", {f"{k}:{kind}": c for (k, kind), c in sorted(skipped.items())})
print(f"{len(mismatches)} mismatching cases")
for m in mismatches[:20]:
    print("  ", m)
sys.exit(1 if mismatches else 0)
