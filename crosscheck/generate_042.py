# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.2 cases (JSON lines, SPEC.md section 11 vector format):

- uri: cell URIs pinned with fn_hash=, mutated (the pin moved among the arguments, after asof,
  repeated, uppercase, short, a slice marker, an argument named fn_hash);
- envelope: answers to pinned and unpinned requests with and without the fn_hash echo, trust
  computed / verified / unverified / primary against receipts signed by the mesh asked or by
  another host, with and without the request naming the mesh, not_covered with E_NAME_UNBOUND,
  bad_request with E_SLICE_AT_CELL;
- envelope (slice endpoint): pages of member envelopes, shuffled, duplicated, with a member outside
  the slice or after the asof, a cursor, next on the mesh asked or another host;
- batch: arrays of items in request order, swapped, short, with wrong item statuses, or a refusal.
The reference tool signs; the libraries only run.

    python generate_042.py SPEC_REPO N SEED > spec042.jsonl
"""

import json
import random
import sys

SPEC, N, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path[:0] = [f"{SPEC}/tools"]
import canon  # noqa: E402

rng = random.Random(SEED)
HOSTS = ["rates.example.org", "mesh.example.net", "other.example.net"]
SEEDS = {h: bytes([i + 91]) * 32 for i, h in enumerate(HOSTS)}
KEYS = {}
KIDS = {}
for host, seed in SEEDS.items():
    _, public = canon.keypair(seed)
    KIDS[host] = canon.key_id(public)
    KEYS[host] = {"https": {"status": 200, "body": json.dumps({"host": host, "keys": [{
        "alg": "ed25519", "id": KIDS[host], "public": public.hex(), "valid_from": "2020-01-01T00:00:00.000000Z"}],
        "proto": canon.PROTO})}}
SIG = {"args": {"base": {"type": "string", "valid": False}, "date": {"type": "date", "valid": True},
                "quote": {"type": "string", "valid": False}}, "returns": {"type": "number", "unit": "1"}}
DESC = {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": SIG}
H = canon.function_hash(DESC)
H2 = "7" * 64
ASOF = "2024-03-16T09:00:00.000000Z"
ASOFS = ["2024-03-16T08:59:59.999999Z", ASOF, "2024-03-17T00:00:00.000000Z"]
QUOTES = ["CHF", "GBP", "JPY", "NOK", "USD"]


def cell(quote="USD", fn_hash=H):
    return {"args": {"base": {"type": "string", "value": "EUR"}, "date": {"type": "date", "value": "2024-03-15"},
                     "quote": {"type": "string", "value": quote}}, "fn": "fx_rate", "fn_hash": fn_hash,
            "ns": "rates.example.org"}


def receipt(signer, quote="USD", fn_hash=H, asof=ASOF):
    inputs = [] if signer == "rates.example.org" else ["e" * 64]
    c = cell(quote, fn_hash)
    r = {"asof": asof, "cell": c, "computed_by": f"{signer}#{KIDS[signer]}", "inputs": inputs, "issued": asof,
         "licence": "CC0-1.0", "proto": canon.PROTO, "publisher": "rates.example.org", "summary": "A rate.",
         "tx": "2024-03-15T16:00:00.000000Z", "type": "number", "valid": {"date": c["args"]["date"]},
         "value": "1.0892"}
    return canon.sign_receipt(r, SEEDS[signer])


RECEIPTS = {(s, q, h): receipt(s, q, h) for s in HOSTS for q in QUOTES for h in (H, H2)}
LATE = receipt("rates.example.org", "NOK", H, "2024-03-18T00:00:00.000000Z")


def cid(c):
    return canon.sha256_hex(canon.jcs(c))


def uri_case(i):
    base = "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=" + rng.choice(["USD", "*", "CHF"])
    pin = rng.choice([H, H, H.upper(), H[:63], "*", "", H + "0"])
    params = base.split("?")[1].split("&")
    m = rng.randrange(8)
    if m == 0:
        params.insert(rng.randrange(len(params) + 1), f"fn_hash={pin}")
    elif m == 1:
        params += [f"fn_hash={pin}", f"fn_hash={pin}"]
    elif m == 2:
        params += [f"asof={ASOF}", f"fn_hash={pin}"]
    else:
        params.append(f"fn_hash={pin}")
        if rng.random() < 0.5:
            params.append(f"asof={rng.choice(ASOFS)}")
    sig = SIG
    if rng.random() < 0.08:
        sig = {"args": dict(SIG["args"], fn_hash={"type": "string", "valid": False}), "returns": SIG["returns"]}
        params.insert(1, "fn_hash=" + rng.choice(["x", H]))
    uri = "cell://rates.example.org/fx_rate?" + "&".join(params)
    return {"id": f"pin-uri/{i:04d}", "kind": "uri", "description": "spec-0.4.2: pinned URIs", "valid": True,
            "input": uri, "signature": sig}


def envelope_case(i):
    signer = rng.choice(HOSTS)
    quote = rng.choice(QUOTES)
    r = RECEIPTS[(signer, quote, H)]
    request = {"asof": rng.choice(ASOFS), "cell_id": cid(r["cell"] if rng.random() < 0.85 else cell("XXX"))}
    if rng.random() < 0.5:
        request["fn_hash"] = H if rng.random() < 0.85 else H2
    if rng.random() < 0.6:
        request["mesh"] = rng.choice(["mesh.example.net", "other.example.net"])
    kind = rng.choice(["receipt", "receipt", "receipt", "not_covered", "bad_request", "rate_limited"])
    if kind == "receipt":
        env = {"outcome": rng.choice(["ok", "stale"]), "receipt": r,
               "trust": rng.choice(["primary", "computed", "verified", "unverified"])}
        if env["outcome"] == "stale":
            env["age_seconds"] = 5
        status = 200
    elif kind == "not_covered":
        env = {"outcome": "not_covered"}
        if rng.random() < 0.4:
            env["error"] = rng.choice(["E_NAME_UNBOUND", "E_NAME_UNBOUND", "E_SLICE_AT_CELL", "E_PARSE_URI"])
        status = 404
    elif kind == "bad_request":
        env = {"error": rng.choice(["E_SLICE_AT_CELL", "E_CANON_HEX", "E_NAME_UNBOUND"]), "outcome": "bad_request"}
        status = 400
    else:
        env = {"outcome": "rate_limited", "retry_after_seconds": 1}
        status = 429
    if rng.random() < 0.6:
        env["fn_hash"] = rng.choice([H, H, H2, H.upper()])
    return {"id": f"pin-envelope/{i:04d}-{kind}", "kind": "envelope", "description": "spec-0.4.2: echo and trust",
            "valid": True, "input": json.dumps(env, indent=rng.choice([None, 1])), "status": status, "keys": KEYS,
            "request": request}


SLICE = {"args": {"base": {"type": "string", "value": "EUR"}, "date": {"type": "date", "value": "2024-03-15"},
                  "quote": "*"}, "fn": "fx_rate", "fn_hash": H, "ns": "rates.example.org"}
SLICE_ID = canon.slice_id(SLICE)


def slice_case(i):
    quotes = sorted(rng.sample(QUOTES, rng.randrange(len(QUOTES) + 1)))
    members = []
    for q in quotes:
        signer = rng.choice(["rates.example.org", "rates.example.org", "mesh.example.net"])
        r = RECEIPTS[(signer, q, H)]
        trust = "primary" if signer == "rates.example.org" else rng.choice(["computed", "computed", "verified"])
        members.append({"outcome": "ok", "receipt": r, "trust": trust})
    m = rng.randrange(10)
    if m == 0 and len(members) > 1:
        rng.shuffle(members)
    elif m == 1 and members:
        members.append(members[-1])
    elif m == 2:
        members.append({"outcome": "ok", "receipt": RECEIPTS[("rates.example.org", "USD", H2)],
                        "trust": "primary"})
    elif m == 3:
        members.append({"outcome": "ok", "receipt": LATE, "trust": "primary"})
    elif m == 4 and members:
        members[0] = {"outcome": "not_covered"}
    env = {"members": members, "outcome": "ok", "slice": SLICE}
    if rng.random() < 0.4:
        env["next"] = rng.choice(["https://mesh.example.net/slice/x?after=1", "https://other.example.net/slice/x",
                                  "https:///slice/x", "http://mesh.example.net/slice/x"])
    request = {"asof": ASOF, "slice_id": SLICE_ID if rng.random() < 0.9 else "0" * 64}
    if rng.random() < 0.5:
        request["mesh"] = "mesh.example.net"
    if rng.random() < 0.3:
        request["after"] = rng.choice([{"quote": {"type": "string", "value": rng.choice(QUOTES)}},
                                       {"quote": {"type": "string", "value": "GBP"}, "x": {"type": "string", "value": "1"}},
                                       {"quote": {"type": "number", "value": "1"}}, {"base": {"type": "string", "value": "EUR"}}])
    if rng.random() < 0.1:
        env["fn_hash"] = rng.choice([H, H2])
    return {"id": f"slice-page/{i:04d}-{m}", "kind": "envelope", "description": "spec-0.4.2: slice pages",
            "valid": True, "input": json.dumps(env), "status": 200, "keys": KEYS, "request": request}


def batch_case(i):
    n = rng.randrange(1, 5)
    items, requests = [], []
    for _ in range(n):
        q = rng.choice(QUOTES)
        r = RECEIPTS[("rates.example.org", q, H)]
        requests.append({"asof": ASOF, "cell_id": cid(r["cell"])})
        if rng.random() < 0.7:
            items.append({"envelope": {"outcome": "ok", "receipt": r, "trust": "primary"}, "status": 200})
        else:
            items.append({"envelope": {"outcome": "not_covered"}, "status": rng.choice([404, 404, 200])})
    m = rng.randrange(8)
    status = 200
    body = items
    if m == 0 and n > 1:
        body = items[::-1]
    elif m == 1:
        body = items[:-1]
    elif m == 2:
        body = [dict(items[0], extra=1)] + items[1:]
    elif m == 3:
        body, status = {"outcome": "rate_limited", "retry_after_seconds": 2}, 429
    elif m == 4:
        body, status = {"outcome": "ok", "receipt": RECEIPTS[("rates.example.org", "USD", H)], "trust": "primary"}, 200
    text = json.dumps(body)
    if m == 5:
        text = text.replace('"status": 200', '"status": 200.0', 1)
    return {"id": f"batch-fuzz/{i:04d}-{m}", "kind": "batch", "description": "spec-0.4.2: batches", "valid": True,
            "input": text, "status": status, "keys": KEYS, "requests": requests}


for gen in (uri_case, envelope_case, slice_case, batch_case):
    for i in range(N // 4 or 1):
        print(json.dumps(gen(i)))
