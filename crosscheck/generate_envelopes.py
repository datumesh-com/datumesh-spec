# SPDX-License-Identifier: Apache-2.0
"""Adversarial envelope cases (JSON lines, SPEC.md section 11 vector format): the request binding.

Every case is a well-formed envelope around a validly signed receipt. What varies is what the
request asked for, and how the outcome presents the answer:
- the requested cell: the receipt's own, a sibling differing in one argument, the same arguments
  under another function hash or namespace, or another function entirely;
- the requested asof: none, equal, earlier or later than the receipt's, by a microsecond or a year;
- the outcome: ok or stale (with age_seconds), with the HTTP status and trust label that match.
So the cases aim at stale/ok confusion and at a receipt for a different cell. The reference tool
signs; the libraries only run.

    python generate_envelopes.py SPEC_REPO N SEED > envelopes.jsonl
"""

import json
import random
import sys

SPEC, N, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path[:0] = [f"{SPEC}/tools"]
import canon  # noqa: E402

rng = random.Random(SEED)
SEEDS = {h: bytes([i + 41]) * 32 for i, h in enumerate(["rates.example.org", "mirror.example.net"])}
KEYS = {}
for host, seed in SEEDS.items():
    _, public = canon.keypair(seed)
    doc = {"host": host, "keys": [{"alg": "ed25519", "id": canon.key_id(public), "public": public.hex(),
                                   "valid_from": "2020-01-01T00:00:00.000000Z"}], "proto": canon.PROTO}
    KEYS[host] = {"https": {"status": 200, "body": json.dumps(doc)}}

ASOFS = ["2024-03-16T09:00:00.000000Z", "2024-03-16T09:00:00.000001Z", "2024-06-30T23:59:59.999999Z"]
NEAR = {  # instants around each asof: (label, instant)
    a: [("same", a), ("minus-1us", a[:-2] + str(int(a[-2]) - 1) + "Z" if a[-2] != "0" else "2024-03-16T08:59:59.999999Z"),
        ("plus-1us", a[:-2] + str(int(a[-2]) + 1) + "Z" if a[-2] != "9" else "2024-07-01T00:00:00.000000Z"),
        ("year-earlier", "2023" + a[4:]), ("year-later", "2025" + a[4:])]
    for a in ASOFS
}


def cell(ns="rates.example.org", fn="fx_rate", fn_hash="1" * 64, **args):
    base = {"base": {"type": "string", "value": "EUR"}, "date": {"type": "date", "value": "2024-03-15"},
            "quote": {"type": "string", "value": "USD"}}
    base.update({k: {"type": "string", "value": v} for k, v in args.items()})
    return {"args": base, "fn": fn, "fn_hash": fn_hash, "ns": ns}


def cell_id(c):
    return canon.sha256_hex(canon.jcs(c))


def receipt(c, signer, asof, inputs=()):
    _, public = canon.keypair(SEEDS[signer])
    r = {"asof": asof, "cell": c, "computed_by": f"{signer}#{canon.key_id(public)}", "inputs": list(inputs),
         "issued": asof, "licence": "CC-BY-4.0", "proto": canon.PROTO, "publisher": c["ns"],
         "summary": "A rate.", "tx": "2024-03-15T16:00:00.000000Z", "type": "number",
         "valid": {"date": c["args"]["date"]}, "value": "1.0892"}
    return canon.sign_receipt(r, SEEDS[signer])


CELL = cell()
SIBLINGS = {  # cells a mesh could wrongly answer with
    "same": CELL,
    "other-quote": cell(quote="GBP"),
    "other-base": cell(base="CHF"),
    "other-fn-hash": cell(fn_hash="2" * 64),
    "other-namespace": cell(ns="rates.example.org/archive"),
    "other-function": cell(fn="fx_close"),
}


def is_primary(r):
    return r["computed_by"].split("#")[0] == r["cell"]["ns"].split("/")[0] and not r["inputs"]


for i in range(N):
    answered = "same" if rng.random() < 0.6 else rng.choice(list(SIBLINGS))
    asof = rng.choice(ASOFS)
    signer = rng.choice(["rates.example.org", "rates.example.org", "mirror.example.net"])
    inputs = ["a" * 64] if rng.random() < 0.2 else []
    r = receipt(SIBLINGS[answered], signer, asof, inputs)
    outcome = rng.choice(["ok", "stale"])
    env = {"outcome": outcome, "receipt": r,
           "trust": "primary" if is_primary(r) else rng.choice(["verified", "unverified"])}
    if outcome == "stale":
        env["age_seconds"] = rng.choice([0, 1, 3600, 31536000])
    if rng.random() < 0.1:  # the mesh mislabels the outcome's trust
        env["trust"] = rng.choice(["primary", "verified", "unverified"])
    request = {"cell_id": cell_id(SIBLINGS["same"] if rng.random() < 0.7 else rng.choice(list(SIBLINGS.values())))}
    label, requested_asof = rng.choice([("none", None)] + NEAR[asof])
    if requested_asof is not None:
        request["asof"] = requested_asof
    print(json.dumps({"id": f"envelope-adv/{i:04d}-{outcome}-{answered}-{label}", "kind": "envelope",
                      "description": "adversarial request binding", "valid": True,
                      "input": json.dumps(env, indent=rng.choice([None, 1])), "status": 200,
                      "keys": KEYS, "request": request}))
