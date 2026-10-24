# SPDX-License-Identifier: Apache-2.0
"""Generate N random unit and envelope cases (JSON lines, SPEC.md section 11 vector format).

Units: random signatures whose units are drawn from valid forms and near misses, as `function`
vectors (descriptor checks, E_CANON_UNIT order) and `unit` vectors (resolution against a cell).
Envelopes: random outcomes, members, HTTP statuses and trust labels around receipts from a small
signed pool, about half of them perturbed. The reference tool signs; the libraries only run.

    python generate_02.py SPEC_REPO N SEED > cases-02.jsonl
"""

import json
import os
import random
import sys

SPEC = sys.argv[1]
N = int(sys.argv[2])
SEED = int(sys.argv[3])
sys.path[:0] = [f"{SPEC}/tools"]
import canon  # noqa: E402

rng = random.Random(SEED)
LITERALS = sorted(set().union(*canon.UNITS.values()))
if os.environ.get("LIBS") == "0.3":  # libraries of spec-0.3.0 list the units of that revision
    LITERALS = [u for u in LITERALS if u not in ("min", "h", "d", "km", "deg")]
CURRENCIES = sorted(canon.CURRENCIES)
NEAR_MISSES = ["usd", "Usd", "EUR ", " EUR", "USD/EUR", "°C", "degc", "KWH", "kwh", "%", "percent ", "", "XXX",
               "index:2015=100.0", "index:2015=0", "index:2015-02-30=100", "index:15=100", "index:2015=-1",
               "index:2015=1e2", "m/s ", "M", "1.0", "Count"]
INDEX = ["index:2015=100", "index:2020-01=100", "index:1984-01-03=1000", "index:2000-12-31=0.5"]


def literal(valid):
    if valid:
        return rng.choice(LITERALS + INDEX)
    return rng.choice(NEAR_MISSES)


def unit_form(names, valid):
    """A unit in a signature. names: argument name -> type."""
    strings = [n for n, t in names.items() if t == "string"]
    kind = rng.choice(["literal", "literal", "arg", "rate"])
    if kind == "arg" and (strings or not valid):
        return {"arg": rng.choice(strings) if valid else rng.choice(["nope"] + [n for n, t in names.items() if t != "string"])}
    if kind == "rate":
        def side():
            if strings and rng.random() < 0.5:
                return {"arg": rng.choice(strings)}
            return rng.choice(CURRENCIES) if valid else rng.choice(["kg", "usd", "percent", "EURO"])
        unit = {"of": side(), "per": side()}
        if not valid and rng.random() < 0.3:
            unit = rng.choice([dict(unit, extra="x"), {"of": unit["of"]}, {"of": {"of": "USD", "per": "EUR"}, "per": "EUR"}])
        return unit
    if not valid and rng.random() < 0.15:
        return rng.choice([1, None, ["EUR"], {}, {"arg": 3}])
    return literal(valid)


def random_descriptor():
    names = {}
    for i in range(rng.randint(0, 4)):
        names[f"a{i}"] = rng.choice(["string", "string", "number", "date", "boolean", "blob"])
    good = rng.random() < 0.5
    args = {}
    for name, type_ in names.items():
        decl = {"type": type_, "valid": type_ == "date" and rng.random() < 0.5}
        if type_ == "number":
            decl["unit"] = unit_form(names, good or rng.random() < 0.7)
        if not good and rng.random() < 0.1:
            decl.pop("unit", None) if type_ == "number" else decl.update(unit="1")
        args[name] = decl
    ret_type = rng.choice(["number"] * 8 + ["string", "boolean", "blob", "date"])
    if ret_type == "number":
        returns = {"type": "number", "unit": unit_form(names, good or rng.random() < 0.5)}
        if not good and rng.random() < 0.15:
            returns = rng.choice(["number", {"type": "number"}])
    else:
        returns = ret_type
        if not good and rng.random() < 0.15:
            returns = rng.choice([{"type": ret_type}, {"type": ret_type, "unit": "1"}])
    return {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": {"args": args, "returns": returns}}


def random_cell(desc):
    args = {}
    for name, decl in desc["signature"]["args"].items():
        if not isinstance(decl, dict):
            continue
        t = decl.get("type")
        if t == "string":
            value = rng.choice(CURRENCIES[:20] + LITERALS[-12:] + ["dollars", "usd", "", "EUR "])
        elif t == "number":
            value = str(rng.randint(0, 1000))
        elif t == "date":
            value = "2024-03-15"
        elif t == "boolean":
            value = True
        else:
            value = "0" * 64 + ":0:text/plain"
        args[name] = {"type": t, "value": value} if rng.random() > 0.1 else "*"
    if args and rng.random() < 0.1:
        args.pop(rng.choice(sorted(args)))
    fn_hash = canon.sha256_hex(canon.jcs(desc)) if rng.random() > 0.05 else "0" * 64
    return {"args": args, "fn": "f", "fn_hash": fn_hash, "ns": "units.example.org"}


# --- envelopes --------------------------------------------------------------

SEEDS = {h: bytes([i + 7]) * 32 for i, h in enumerate(["rates.example.org", "calc.example.net"])}
KEYS = {}
for host, seed in SEEDS.items():
    _, public = canon.keypair(seed)
    doc = {"host": host, "keys": [{"alg": "ed25519", "id": canon.key_id(public), "public": public.hex(),
                                   "valid_from": "2020-01-01T00:00:00.000000Z"}], "proto": canon.PROTO}
    KEYS[host] = {"https": {"status": 200, "body": json.dumps(doc)}}


def pool_receipt(signer, ns, inputs, value):
    _, public = canon.keypair(SEEDS[signer])
    r = {"asof": "2024-03-16T09:00:00.000000Z",
         "cell": {"args": {"date": {"type": "date", "value": "2024-03-15"}}, "fn": "f", "fn_hash": "1" * 64, "ns": ns},
         "computed_by": f"{signer}#{canon.key_id(public)}", "inputs": inputs, "issued": "2024-03-16T09:00:00.000000Z",
         "licence": "CC-BY-4.0", "proto": canon.PROTO, "publisher": ns, "summary": "A value.",
         "tx": "2024-03-15T16:00:00.000000Z", "type": "number", "valid": {"date": {"type": "date", "value": "2024-03-15"}},
         "value": value}
    return canon.sign_receipt(r, SEEDS[signer])


POOL = [
    pool_receipt("rates.example.org", "rates.example.org", [], "1.5"),                   # primary
    pool_receipt("rates.example.org", "rates.example.org/stats/eu", [], "2"),           # primary, path
    pool_receipt("calc.example.net", "rates.example.org", [], "1.5"),                    # mirror
    pool_receipt("calc.example.net", "calc.example.net", ["a" * 64], "3"),               # computed
    pool_receipt("rates.example.org", "rates.example.org", ["b" * 64, "c" * 64], "4"),  # computed by publisher
]
STATUS = {"ok": 200, "stale": 200, "not_covered": 404, "unlicensed": 403, "payment_required": 402,
          "rate_limited": 429, "error": 503, "bad_request": 400}


def is_primary(r):
    return r["computed_by"].split("#")[0] == r["cell"]["ns"].split("/")[0] and not r["inputs"]


def random_envelope():
    outcome = rng.choice(sorted(STATUS))
    env = {"outcome": outcome}
    if outcome in ("ok", "stale"):
        r = json.loads(json.dumps(rng.choice(POOL)))
        env["receipt"] = r
        env["trust"] = "primary" if is_primary(r) else rng.choice(["verified", "unverified"])
        if outcome == "stale":
            env["age_seconds"] = rng.choice([0, 1, 86400, 2**53 - 1])
        if rng.random() < 0.3:
            env["superseded_by"] = "d" * 64
            if rng.random() < 0.5:
                env["reason"] = "Corrected after republication."
    elif outcome == "payment_required":
        env["quote"] = {"amount": rng.choice(["0.05", "12", "0.001"]), "authorise": "https://mesh.example/pay",
                        "currency": rng.choice(CURRENCIES)}
    elif outcome == "rate_limited":
        env["retry_after_seconds"] = rng.choice([0, 30, 3600])
    elif outcome == "error":
        env["error"] = rng.choice(canon.ERROR_CODES)
    elif outcome == "bad_request":
        env["error"] = rng.choice(canon.URI_CODES + ("E_SIGNATURE",))
    status = STATUS[outcome] if outcome != "error" else rng.choice([500, 502, 503, 599])
    request = None
    if rng.random() < 0.5:
        status, env, request = perturb(status, env)
    if request is None:  # the request the receipt answers, with or without asof
        cell = env["receipt"]["cell"] if isinstance(env.get("receipt"), dict) and "cell" in env["receipt"] else POOL[0]["cell"]
        request = {"cell_id": canon.sha256_hex(canon.jcs(cell))}
        if rng.random() < 0.5:  # the pool's asof is 2024-03-16T09:00: equal, later or earlier than requested
            request["asof"] = rng.choice(["2024-03-16T09:00:00.000000Z", "2024-03-17T09:00:00.000000Z",
                                          "2024-03-16T08:59:59.999999Z"])
    return status, env, request


def perturb(status, env):
    """Returns (status, env, request); request None means the matching one."""
    env = json.loads(json.dumps(env))
    if rng.random() < 0.1:
        return status, env, {"asof": rng.choice(["2024-03-16T09:00:00.000000Z", "2024-03-17T09:00:00.000000Z"]),
                             "cell_id": rng.choice(["e" * 64, canon.sha256_hex(canon.jcs(POOL[0]["cell"]))])}
    op = rng.choice(["status", "outcome", "drop", "add", "trust", "seconds", "quote", "error", "reason",
                     "self", "receipt-value", "receipt-sig", "receipt-shape", "request"])
    if op == "status":
        status = rng.choice([200, 201, 204, 301, 400, 402, 403, 404, 418, 429, 500, 600])
    elif op == "outcome":
        env["outcome"] = rng.choice(["OK", "fresh", "", "not covered"] + sorted(STATUS))
    elif op == "drop" and len(env) > 1:
        env.pop(rng.choice(sorted(k for k in env if k != "outcome")))
    elif op == "add":
        env[rng.choice(["trust", "receipt", "age_seconds", "quote", "error", "retry_after_seconds", "note"])] = \
            rng.choice(["primary", 5, "E_SIGNATURE", {}, None, -1])
    elif op == "trust":
        env["trust"] = rng.choice(["primary", "verified", "unverified", "Primary", ""])
    elif op == "seconds":
        env[rng.choice(["age_seconds", "retry_after_seconds"])] = rng.choice([-1, 1.5, 30.0, "30", 2**53, True])
    elif op == "quote":
        env["quote"] = rng.choice([{"amount": "0", "authorise": "https://x.example", "currency": "EUR"},
                                   {"amount": "1.50", "authorise": "https://x.example", "currency": "EUR"},
                                   {"amount": "1", "authorise": "http://x.example", "currency": "EUR"},
                                   {"amount": "1", "authorise": "https://x.example", "currency": "eur"},
                                   {"amount": "1", "currency": "EUR"}])
    elif op == "error":
        env["error"] = rng.choice(["E_NOPE", "OK", "", "e_signature"])
    elif op == "reason":
        env["reason"] = rng.choice(["", "x\u0007y", "Zürich"])
    elif op == "self" and "receipt" in env:
        env["superseded_by"] = canon.receipt_hash(env["receipt"])
    elif op == "receipt-value" and "receipt" in env:
        env["receipt"]["value"] = "9"
    elif op == "receipt-sig" and "receipt" in env:
        env["receipt"]["sig"] = env["receipt"]["sig"][::-1]
    elif op == "receipt-shape" and "receipt" in env:
        env["receipt"] = rng.choice(["receipt", [], {"proto": "datumesh/1"}])
    return status, env, None


for i in range(N):
    if i % 2 == 0:
        desc = random_descriptor()
        print(json.dumps({"id": f"cross02/{i:04d}-fn", "kind": "function", "description": "random", "valid": True,
                          "input": json.dumps(desc)}))
        print(json.dumps({"id": f"cross02/{i:04d}-unit", "kind": "unit", "description": "random", "valid": True,
                          "input": json.dumps({"cell": random_cell(desc), "descriptor": desc})}))
    else:
        status, env, request = random_envelope()
        body = json.dumps(env, ensure_ascii=rng.random() < 0.5, indent=rng.choice([None, 1]))
        print(json.dumps({"id": f"cross02/{i:04d}-env", "kind": "envelope", "description": "random", "valid": True,
                          "input": body, "status": status, "keys": KEYS,
                          "request": request}))
