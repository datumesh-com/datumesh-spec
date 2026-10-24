# SPDX-License-Identifier: Apache-2.0
"""Generate N slice-lineage receipt cases (JSON lines, vector format; spec-0.4.0).

Computed receipts whose inputs are slice entries (random weighted means over 2-20 stations,
running totals over random date ranges, joins), with a recompute object carrying the manifests
and members. About half carry one corruption each, aimed at every new check: the entry's form,
order and count, a missing or mismatched manifest, its schema and order, an undeclared slice, a
missing, invalid, outside, duplicate or late member, the tx rule over members, a value mismatch,
and supersession (a later member or version in the evaluation's lineage: E_INPUT_SUPERSEDED).
The reference tool signs and evaluates them; the libraries under test only verify.

    python generate_slices.py SPEC_REPO N SEED > slices.jsonl
"""

import json
import random
import sys

SPEC, N, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path.insert(0, f"{SPEC}/tools")
import canon  # noqa: E402
import formula as F  # noqa: E402
import gen_formula as G  # noqa: E402

rng = random.Random(SEED)
KP = G.keypair(F.ENGINE_HOST)


def resign(r):
    return canon.sign_receipt({k: v for k, v in r.items() if k != "sig"}, F.host_seed(F.ENGINE_HOST))


def weighted():
    spec = G.world_weighted(rng.randrange(2, 21))
    w, a = G._answer(spec, G.WMEAN, {"date": G.D("2026-03-01")}, G.LATER)
    return spec["functions"][G.WMEAN]["descriptor"], w, a


def running():
    days = rng.randrange(1, 30)
    spec = G.world_running(days)
    w, a = G._answer(spec, G.RUNNING, {"date": G.D(G.day(rng.randrange(days)))}, G.LATER)
    return spec["functions"][G.RUNNING]["descriptor"], w, a


def join():
    fns, _ = G._base()
    d = G.define(G.E, {}, [], "sum(data.example.org/price(*) * data.example.org/qty(*))", "EUR", fns)
    w, a = G._answer(G.world_for(d), G.E, {}, G.LATER)
    return d, w, a


def corrupt(desc, w, a, rec):
    r = dict(a.receipt)
    slices = [e for e in r["inputs"] if e.startswith("slice:")]
    e = rng.choice(slices)
    m = json.loads(rec["manifests"][e])
    kind = rng.randrange(13)
    if kind == 0:  # malformed entry
        bad = rng.choice([e.upper().replace("SLICE", "slice"), e[:-1], "Slice" + e[5:], e + "0", e.replace(":", "-", 1)])
        r["inputs"] = sorted([bad if x == e else x for x in r["inputs"]], key=canon._utf16_key)
        return resign(r), rec
    if kind == 1 and len(r["inputs"]) > 1:  # unsorted
        r["inputs"] = list(reversed(r["inputs"]))
        return resign(r), rec
    if kind == 2:  # no manifest
        rec = dict(rec, manifests={k: v for k, v in rec["manifests"].items() if k != e})
        return a.receipt, rec
    if kind == 3 and m["members"]:  # manifest that does not hash to the entry
        rec = dict(rec, manifests=dict(rec["manifests"], **{e: json.dumps({"members": m["members"][1:], "slice": m["slice"]})}))
        return a.receipt, rec
    if kind == 4 and len(m["members"]) > 1:  # unsorted members
        rec = dict(rec, manifests=dict(rec["manifests"], **{e: json.dumps({"members": m["members"][::-1], "slice": m["slice"]})}))
        return a.receipt, rec
    if kind == 5:  # manifest schema
        rec = dict(rec, manifests=dict(rec["manifests"], **{e: json.dumps({"members": m["members"]})}))
        return a.receipt, rec
    if kind == 6 and m["members"]:  # a member missing
        h = rng.choice(m["members"])
        rec = dict(rec, inputs={k: v for k, v in rec["inputs"].items() if k != h})
        return a.receipt, rec
    if kind == 7 and m["members"]:  # a member tampered
        h = rng.choice(m["members"])
        t = json.loads(rec["inputs"][h])
        t["summary"] = "Tampered."
        rec = dict(rec, inputs=dict(rec["inputs"], **{h: json.dumps(t)}))
        return a.receipt, rec
    if kind == 8:  # a member from another slice: rebuild the entry around it
        others = [h for h, t in rec["inputs"].items() if h not in m["members"] and json.loads(t)["cell"]["fn"] != m["slice"].get("fn")]
        if others:
            members = sorted(m["members"] + [rng.choice(others)])
            new = F.slice_entry(m["slice"], members)
            r["inputs"] = sorted([new if x == e else x for x in r["inputs"]], key=canon._utf16_key)
            rec = dict(rec, manifests=dict(rec["manifests"], **{new: json.dumps(F.manifest(m["slice"], members))}))
            return resign(r), rec
    if kind == 9:  # tx not the latest
        r["tx"] = "2020-01-01T00:00:00.000000Z"
        return resign(r), rec
    if kind == 10:  # value mismatch
        return a.receipt, dict(rec, value={"type": "number", "value": "123456"})
    if kind == 11:  # an undeclared slice: the receipt cites a slice of a function the descriptor does not read
        obj = dict(m["slice"], fn="undeclared") if "fn" in m["slice"] else m["slice"]
        new = F.slice_entry(obj, m["members"])
        r["inputs"] = sorted([new if x == e else x for x in r["inputs"]], key=canon._utf16_key)
        rec = dict(rec, manifests=dict(rec["manifests"], **{new: json.dumps(F.manifest(obj, m["members"]))}))
        return resign(r), rec
    # supersession: a lineage with the same slice and other members
    other = F.slice_entry(m["slice"], [])
    rec = dict(rec, value={"type": "number", "value": "123456"}, lineage=sorted(
        [other if x == e else x for x in r["inputs"]], key=canon._utf16_key))
    return a.receipt, rec


def main():
    for i in range(N):
        desc, w, a = rng.choice([weighted, running, join])()
        rec = G._recompute(w, desc, {"type": "number", "value": a.receipt["value"]})
        receipt = a.receipt
        if rng.random() < 0.5:
            receipt, rec = corrupt(desc, w, a, rec)
        vec = {"id": f"slices/{i}", "kind": "receipt", "description": "generated", "valid": True,
               "input": json.dumps(receipt), "keypair": KP, "keys": G.KEYS}
        if rng.random() < 0.9:
            vec["recompute"] = rec
        print(json.dumps(vec, ensure_ascii=True))


main()
