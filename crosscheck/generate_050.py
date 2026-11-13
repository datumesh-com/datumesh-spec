# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0 (part one) cases (JSON lines, SPEC.md section 11 vector format):

- mesh: mesh documents of an unrooted host (local.invalid) or a rooted one, their URLs on the host,
  on a loopback origin (127.0.0.1, [::1], localhost, with or without a port) or elsewhere, some
  mixing two origins or misspelling the address or the port (9.6);
- envelope: pending envelopes whose poll is loopback, on the host or elsewhere, against requests
  naming an unrooted mesh, a rooted one, or none (5.5);
- licence: the inheritance rule's arguments, some malformed (8.5);
- entitlement: computed receipts whose inputs or manifests are missing, of another hash or not
  signature-valid (10.3);
- key: object key encodings (16.5), nested and of every type, some mutated (spaces, order, quotes,
  number forms, a missing parenthesis);
- normalisation: string key values in Latin, Hebrew, Greek and Arabic, pointed or not, under each rule
  of 16.4.

    python generate_050.py SPEC_REPO N SEED > spec050.jsonl
"""

import json
import random
import sys

SPEC, N, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path[:0] = [f"{SPEC}/tools"]
import canon  # noqa: E402

rng = random.Random(SEED)
T0 = "2020-01-01T00:00:00.000000Z"
UNROOTED, ROOTED = "local.invalid", "mesh.example.org"
ORIGINS = ["http://127.0.0.1", "http://127.0.0.1:8471", "http://[::1]", "http://[::1]:9", "http://localhost",
           "http://localhost:65535", "http://localhost:65536", "http://localhost:0", "http://localhost:080",
           "http://LOCALHOST", "http://127.0.0.2", "http://10.0.0.1", "http://local.invalid", "https://127.0.0.1",
           "http://[0:0:0:0:0:0:0:1]", "http://localhost:"]
SEEDS = {h: bytes([i + 151]) * 32 for i, h in enumerate([UNROOTED, ROOTED])}
KEYS = {}
for host, seed in SEEDS.items():
    _, public = canon.keypair(seed)
    KEYS[host] = {"host": host, "keys": [{"alg": "ed25519", "id": canon.key_id(public), "public": public.hex(),
                                          "valid_from": T0}], "proto": canon.PROTO}
EPS = {"cell": "/cell/{cell}", "descriptor": "/descriptor/{hash}", "jobs": "/jobs/{job}",
       "manifest": "/manifest/{slice_id}/{members_hash}", "receipt": "/receipt/{hash}"}


def origin(host):
    return rng.choice(ORIGINS + [f"https://{host}"] * 3)


def mesh_case(i):
    host = rng.choice([UNROOTED, UNROOTED, ROOTED])
    base = origin(host)
    endpoints = {k: (origin(host) if rng.random() < 0.15 else base) + v for k, v in EPS.items()}
    doc = {"bindings": (origin(host) if rng.random() < 0.15 else base) + "/bindings", "endpoints": endpoints,
           "host": host, "proto": canon.PROTO}
    env = {"keys": {"https": {"status": 200, "body": json.dumps(KEYS[host])}},
           "mesh": {"https": {"status": 200, "body": json.dumps(doc)}}}
    return {"id": f"mesh-fuzz/{i:04d}", "kind": "mesh", "description": "spec-0.5.0: loopback URLs", "valid": True,
            "host": host, "env": env}


JOB = "0123456789abcdef0123456789abcdef"


def poll_case(i):
    req = {"cell_id": "a" * 64}
    mesh = rng.choice([UNROOTED, ROOTED, None])
    if mesh:
        req["mesh"] = mesh
    body = {"estimate_seconds": 1, "job": JOB, "outcome": "pending",
            "poll": origin(mesh or ROOTED) + rng.choice(["", "/x"]) + f"/jobs/{JOB}", "request": {"cell_id": "a" * 64}}
    return {"id": f"poll-fuzz/{i:04d}", "kind": "envelope", "description": "spec-0.5.0: loopback poll", "valid": True,
            "input": json.dumps(body), "status": 202, "keys": {}, "request": req}


def licence_case(i):
    pick = lambda good, bad: rng.choice(bad) if rng.random() < 0.25 else good  # noqa: E731
    return {"id": f"licence-args-fuzz/{i:04d}", "kind": "licence", "description": "spec-0.5.0: arguments",
            "valid": True, "licences": [pick(rng.choice(["MIT", "CC0-1.0", "https://x.example/l"]),
                                             ["MIT License", "", "A" * 65, "https://a b"]) for _ in range(rng.randint(0, 3))],
            "declarations": {}, "fn": pick("calc.example.net/convert", ["convert", "calc.example.net", "C.example/f"]),
            "issued": pick("2024-03-16T09:00:00.000000Z", ["2024-03-16", "2024-03-16T09:00:00Z"]),
            "mesh_licence": pick("CC-BY-4.0", ["CC BY 4.0"])}


FX = {"code": {"body": "", "lang": "stored"}, "inputs": [],
      "signature": {"args": {"quote": {"type": "string", "valid": False}}, "returns": {"type": "number", "unit": "1"}}}
FXH = canon.function_hash(FX)
ASOF = "2024-03-16T09:00:00.000000Z"
RSEED = bytes([171]) * 32
_, RPUB = canon.keypair(RSEED)
RKEYS = {"host": "rates.example.org", "keys": [{"alg": "ed25519", "id": canon.key_id(RPUB), "public": RPUB.hex(),
                                                "valid_from": T0}], "proto": canon.PROTO}


def stored(quote):
    r = {"asof": ASOF, "cell": {"args": {"quote": {"type": "string", "value": quote}}, "fn": "fx_rate", "fn_hash": FXH,
                                "ns": "rates.example.org"}, "computed_by": f"rates.example.org#{canon.key_id(RPUB)}",
         "inputs": [], "issued": ASOF, "licence": "CC0-1.0", "proto": canon.PROTO, "publisher": "rates.example.org",
         "summary": "A rate.", "tx": "2024-03-15T16:00:00.000000Z", "type": "number", "valid": {}, "value": "1.5"}
    return canon.sign_receipt(r, RSEED)


def entitlement_case(i):
    inputs = [stored(q) for q in rng.sample(["CHF", "GBP", "USD"], rng.randint(1, 3))]
    receipts = {canon.receipt_hash(r): json.dumps(r) for r in inputs}
    entries, manifests = sorted(receipts), {}
    if rng.random() < 0.4:
        sl = {"args": {"quote": "*"}, "fn": "fx_rate", "fn_hash": FXH, "ns": "rates.example.org"}
        entries = [canon.slice_entry(sl, sorted(receipts))]
        manifests[entries[0]] = json.dumps({"members": sorted(receipts), "slice": sl})
    m = rng.randrange(5)
    if m == 0:
        receipts.pop(rng.choice(sorted(receipts)))
    elif m == 1 and manifests:
        manifests.clear()
    elif m == 2:
        h = rng.choice(sorted(receipts))
        receipts[h] = json.dumps(dict(json.loads(receipts[h]), value="9"))
    elif m == 3:
        a = sorted(receipts)
        receipts[a[0]] = receipts[a[-1]] if len(a) > 1 else json.dumps(stored("NOK"))
    cseed = bytes([173]) * 32
    _, cpub = canon.keypair(cseed)
    r = {"asof": ASOF, "cell": {"args": {}, "fn": "convert", "fn_hash": "c" * 64, "ns": "calc.example.net"},
         "computed_by": f"calc.example.net#{canon.key_id(cpub)}", "inputs": entries, "issued": ASOF,
         "licence": "CC0-1.0", "proto": canon.PROTO, "publisher": "calc.example.net", "summary": "Computed.",
         "tx": "2024-03-15T16:00:00.000000Z", "type": "number", "valid": {}, "value": "1"}
    r = canon.sign_receipt(r, cseed)
    ckeys = {"host": "calc.example.net", "keys": [{"alg": "ed25519", "id": canon.key_id(cpub), "public": cpub.hex(),
                                                   "valid_from": T0}], "proto": canon.PROTO}
    vec = {"id": f"entitlement-inputs-fuzz/{i:04d}-{m}", "kind": "entitlement", "description": "spec-0.5.0: L",
           "valid": True, "input": json.dumps(r), "receipts": receipts,
           "keys": {"rates.example.org": {"https": {"status": 200, "body": json.dumps(RKEYS)}},
                    "calc.example.net": {"https": {"status": 200, "body": json.dumps(ckeys)}}}}
    if manifests:
        vec["manifests"] = manifests
    return vec


VALUES = [{"type": "string", "value": "EUR"}, {"type": "string", "value": 'say "hi"'},
          {"type": "number", "value": "-1.5"}, {"type": "number", "value": "255"},
          {"type": "date", "value": "2024-03-15"}, {"type": "instant", "value": "2024-03-15T16:00:00.000000Z"},
          {"type": "boolean", "value": True}]


def key_case(i):
    def obj(depth):
        keys = {}
        for k in rng.sample(["base", "book", "code", "quote", "verse", "x"], rng.randint(0, 3)):
            keys[k] = obj(depth + 1) if depth < 2 and rng.random() < 0.25 else rng.choice(VALUES)
        return {"class": rng.choice(["iso.example.org/currency", "rates.example.org/fx_pair", "a.example/k"]),
                "keys": keys}
    text = canon.encode_decoded(obj(0))
    m = rng.randrange(6)
    if m == 1:
        text = text.replace(":", ": ", 1)
    elif m == 2:
        text = text.replace('"', "", 2)
    elif m == 3:
        text = text[:-1]
    elif m == 4:
        text = text.replace("255", "0255")
    return {"id": f"key-fuzz/{i:04d}-{m}", "kind": "key", "description": "spec-0.5.0: key encodings", "valid": True,
            "input": text}


TEXTS = ["EUR", "eur", "1M", "Zürich", "New  York", "a\u200db", "בראשית", "בְּרֵאשִׁית", "λογος", "λόγος",
         "بسم ٱلله", "بِسْمِ ٱللَّهِ", "اللـه", "", " x"]


def normalisation_case(i):
    import json as _json
    return {"id": f"normalisation-fuzz/{i:04d}", "kind": "normalisation", "description": "spec-0.5.0: key values",
            "valid": True, "rule": rng.choice(canon.KEY_NORMALISATIONS), "text": _json.loads('"' + rng.choice(TEXTS) + '"')}


for gen in (mesh_case, poll_case, licence_case, entitlement_case, key_case, normalisation_case):
    for i in range(N // 6 or 1):
        print(json.dumps(gen(i)))
