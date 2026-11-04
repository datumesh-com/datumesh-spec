# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.3 cases (JSON lines, SPEC.md section 11 vector format):

- licence: random multisets of input licences (every open id, unlisted SPDX ids, case variants,
  licence URLs), random declarations (open, closed, opening later, for another function or
  licence) and issued instants, through the inheritance rule (8.5);
- keys: key documents with declarations, about half mutated (another host, a subdomain, a bad
  name, licence or instant, valid_to not after valid_from, members missing or extra, empty
  arrays and objects, the limits crossed), each E_KEY_DOC or the document's key ids and
  declarations (9.2);
- entitlement: computed receipts over stored inputs (and slices) of random licences, carrying
  the licence the rule gives or another, under random declarations (10.3);
- envelope: error envelopes with E_FOREIGN_UNAVAILABLE or another code, with and without detail
  (one of the six, or not), with 502 or another status, or under another outcome (5.5).
The reference tool signs; the libraries only run.

    python generate_043.py SPEC_REPO N SEED > spec043.jsonl
"""

import json
import random
import sys

SPEC, N, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path[:0] = [f"{SPEC}/tools"]
import canon  # noqa: E402

rng = random.Random(SEED)
T0 = "2020-01-01T00:00:00.000000Z"
INSTANTS = ["2021-06-01T00:00:00.000000Z", "2023-01-01T00:00:00.000000Z", "2024-03-16T09:00:00.000000Z",
            "2024-03-16T09:00:00.000001Z", "2025-01-01T00:00:00.000000Z"]
URLS = ["https://rates.example.org/licences/restricted", "https://rates.example.org/licences/other",
        "https://tanach.us/License.html"]
OPEN = [x for tier in canon.LICENCE_TIERS for x in tier]
UNLISTED = ["CC-BY-NC-4.0", "GPL-3.0-only", "cc0-1.0", "CC-BY-4.0+", "ODbL-1.0.1"]
FN = "calc.example.net/convert"
FNS = [FN, "calc.example.net/other", "calc.example.net/fx/cross"]


def licence():
    r = rng.random()
    return rng.choice(OPEN) if r < 0.75 else rng.choice(URLS) if r < 0.9 else rng.choice(UNLISTED)


def entry(lic=None):
    a, b = sorted(rng.sample([T0] + INSTANTS, 2))
    e = {"licence": lic or licence(), "valid_from": a}
    if rng.random() < 0.5:
        e["valid_to"] = b
    return e


def declarations(host="calc.example.net", restricted=()):
    if rng.random() < 0.2:
        return {}
    names = [f.replace("calc.example.net", host) for f in rng.sample(FNS, rng.randint(1, len(FNS)))]
    return {n: [entry(rng.choice(list(restricted) + URLS + UNLISTED[:1])) for _ in range(rng.randint(1, 3))]
            for n in names}


def licence_case(i):
    ls = [licence() for _ in range(rng.choice([0, 1, 1, 2, 2, 3, 4, 6]))]
    restricted = [x for x in ls if canon.licence_tier(x) == 4]
    return {"id": f"licence-fuzz/{i:04d}", "kind": "licence", "description": "spec-0.4.3: licence inheritance",
            "valid": True, "licences": ls, "declarations": declarations(restricted=restricted), "fn": FN,
            "issued": rng.choice(INSTANTS), "mesh_licence": licence()}


SEEDS = {h: bytes([i + 131]) * 32 for i, h in enumerate(["rates.example.org", "calc.example.net"])}
KEYS = {}
for host, seed in SEEDS.items():
    _, public = canon.keypair(seed)
    KEYS[host] = {"alg": "ed25519", "id": canon.key_id(public), "public": public.hex(), "valid_from": T0}


def keydoc_env(host, decl):
    doc = {"host": host, "keys": [KEYS[host]], "proto": canon.PROTO}
    if decl is not None:
        doc["declarations"] = decl
    return {"https": {"status": 200, "body": json.dumps(doc)}}


def keys_case(i):
    decl = declarations(restricted=URLS) or {FN: [entry()]}
    m = rng.randrange(16)
    name = next(iter(decl))
    if m == 0:
        decl = {name.replace("calc.example.net", "other.example.net"): decl[name]}
    elif m == 1:
        decl = {name.replace("calc.example.net", "eu.calc.example.net"): decl[name]}
    elif m == 2:
        decl = {rng.choice(["calc.example.net", "convert", "@convert", "calc.example.net/Convert", "Calc.example.net/x",
                            "calc.example.net/a__b"]): decl[name]}
    elif m == 3:
        decl[name][0]["licence"] = rng.choice(["CC BY 4.0", "", "http://x.example", "https://a b", "A" * 65])
    elif m == 4:
        decl[name][0]["valid_from"] = rng.choice(["2024-01-01", "2024-01-01T00:00:00Z", "2023-02-29T00:00:00.000000Z"])
    elif m == 5:
        decl[name][0]["valid_to"] = rng.choice([decl[name][0]["valid_from"], "2019-01-01T00:00:00.000000Z"])
    elif m == 6:
        decl[name][0][rng.choice(["note", "valid_until", "Licence"])] = "x"
    elif m == 7:
        del decl[name][0][rng.choice(["licence", "valid_from"])]
    elif m == 8:
        decl[name][0]["valid_from"] = rng.choice([1, None, True, ["x"]])
    elif m == 9:
        decl[name] = rng.choice([[], {}, "x", None])
    elif m == 10:
        decl = rng.choice([{}, [], "x", None, 1])
    elif m == 11:
        decl = {f"calc.example.net/f{k}": [entry()] for k in range(rng.choice([64, 65]))}
    elif m == 12:
        decl = {FN: [entry() for _ in range(rng.choice([16, 17]))]}
    else:
        pass  # valid
    env = keydoc_env("calc.example.net", decl)
    if m == 13:
        env = keydoc_env("calc.example.net", None)
    return {"id": f"keys-fuzz/{i:04d}-{m}", "kind": "keys", "description": "spec-0.4.3: declarations",
            "valid": True, "host": "calc.example.net", "env": env}


FX = {"code": {"body": "", "lang": "stored"}, "inputs": [],
      "signature": {"args": {"quote": {"type": "string", "valid": False}}, "returns": {"type": "number", "unit": "1"}}}
FXH = canon.function_hash(FX)
CALC_CELL = {"args": {}, "fn": "convert", "fn_hash": "c" * 64, "ns": "calc.example.net"}
ASOF = "2024-03-16T09:00:00.000000Z"


def stored(quote, lic):
    r = {"asof": ASOF, "cell": {"args": {"quote": {"type": "string", "value": quote}}, "fn": "fx_rate", "fn_hash": FXH,
                                "ns": "rates.example.org"},
         "computed_by": f"rates.example.org#{KEYS['rates.example.org']['id']}", "inputs": [], "issued": ASOF,
         "licence": lic, "proto": canon.PROTO, "publisher": "rates.example.org", "summary": "A rate.",
         "tx": "2024-03-15T16:00:00.000000Z", "type": "number", "valid": {}, "value": "1.5"}
    return canon.sign_receipt(r, SEEDS["rates.example.org"])


def entitlement_case(i):
    quotes = rng.sample(["CHF", "GBP", "JPY", "NOK", "USD"], rng.randint(0, 4))
    inputs = [stored(q, licence()) for q in quotes]
    receipts = {canon.receipt_hash(r): json.dumps(r) for r in inputs}
    entries, manifests = sorted(receipts), {}
    if inputs and rng.random() < 0.3:  # read them as one slice
        sl = {"args": {"quote": "*"}, "fn": "fx_rate", "fn_hash": FXH, "ns": "rates.example.org"}
        members = sorted(receipts)
        entries = [canon.slice_entry(sl, members)]
        manifests[entries[0]] = json.dumps({"members": members, "slice": sl})
    restricted = [r["licence"] for r in inputs if canon.licence_tier(r["licence"]) == 4]
    decl = declarations(restricted=restricted)
    issued = rng.choice(INSTANTS[2:])
    rule = canon.inherit_licence([r["licence"] for r in inputs], decl, FN, issued, "CC-BY-4.0")
    lic = rule["licence"] if rule["licence"] and rng.random() < 0.6 else licence()
    r = {"asof": ASOF, "cell": CALC_CELL, "computed_by": f"calc.example.net#{KEYS['calc.example.net']['id']}",
         "inputs": entries, "issued": issued, "licence": lic, "proto": canon.PROTO, "publisher": "calc.example.net",
         "summary": "Computed.", "tx": "2024-03-15T16:00:00.000000Z" if inputs else ASOF, "type": "number",
         "valid": {}, "value": "1"}
    r = canon.sign_receipt(r, SEEDS["calc.example.net"])
    keys = {"rates.example.org": keydoc_env("rates.example.org", None),
            "calc.example.net": keydoc_env("calc.example.net", decl or None)}
    vec = {"id": f"entitlement-fuzz/{i:04d}", "kind": "entitlement", "description": "spec-0.4.3: entitlement",
           "valid": True, "input": json.dumps(r), "keys": keys, "receipts": receipts}
    if manifests:
        vec["manifests"] = manifests
    return vec


def foreign_case(i):
    body = {"outcome": rng.choice(["error"] * 4 + ["not_covered", "bad_request"]),
            "error": rng.choice(["E_FOREIGN_UNAVAILABLE"] * 3 + ["E_EVAL_UNAVAILABLE", "E_MESH_DOC"])}
    if rng.random() < 0.8:
        body["detail"] = rng.choice(list(canon.FOREIGN_DETAILS) * 2 + ["Offline", "", "unreachable", 1])
    if rng.random() < 0.2:
        body["fn_hash"] = "ab" * 32
    status = rng.choice([502, 502, 502, 500, 503, 404, 400])
    return {"id": f"foreign-fuzz/{i:04d}", "kind": "envelope", "description": "spec-0.4.3: E_FOREIGN_UNAVAILABLE",
            "valid": True, "input": json.dumps(body), "status": status, "keys": {}, "request": {"cell_id": "a" * 64}}


for gen in (licence_case, keys_case, entitlement_case, foreign_case):
    for i in range(N // 4 or 1):
        print(json.dumps(gen(i)))
