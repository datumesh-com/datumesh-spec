# SPDX-License-Identifier: Apache-2.0
"""Compare URI runner outputs (error, object, canonical, sha256, https) and show mismatches."""
import json
import sys
from collections import Counter

FIELDS = ("error", "object", "canonical", "sha256", "https")
cases = [json.loads(l) for l in open(sys.argv[1])]
runs = {name: [json.loads(l) for l in open(path)] for name, path in (a.split("=") for a in sys.argv[2:])}
bad = Counter()
examples = {}
for i, case in enumerate(cases):
    rows = {k: v[i] for k, v in runs.items()}
    for f in FIELDS:
        vals = tuple(json.dumps(r.get(f), sort_keys=True) for r in rows.values())
        if len(set(vals)) > 1:
            key = " vs ".join(f"{k}={r.get('error') or 'OK'}" for k, r in rows.items())
            bad[key] += 1
            examples.setdefault(key, case["input"])
            break
print(f"{len(cases)} URI cases; {sum(bad.values())} mismatching")
for k, c in bad.most_common():
    print(f"  {c:4d}  {k}   e.g. {examples[k]}")
