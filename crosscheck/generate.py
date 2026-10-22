# SPDX-License-Identifier: Apache-2.0
"""Generate N random receipt cases (JSON lines, SPEC.md section 11 vector format).

About half are valid; the rest carry one corruption each, chosen to reach
every verification step. Blob values come with their content (sometimes
altered) for step 7.7. The spec repo's reference tool signs them; the
libraries under test are only ever run on the output.

After those N cases come N // 4 lineage cases (spec-0.3.0) with a recompute
object: computed receipts over stored inputs whose asofs are earlier than,
equal to or later than the receipt's (D17), with tx right or wrong, and with
an evaluation value that matches, differs or is absent (E_EVAL_UNAVAILABLE);
sometimes the descriptor or an input is missing, or blob content follows.

    python generate.py SPEC_REPO N SEED > cases.jsonl
"""

import json
import random
import sys

SPEC = sys.argv[1]
N = int(sys.argv[2])
SEED = int(sys.argv[3])
sys.path[:0] = [f"{SPEC}/tools", f"{SPEC}/tests"]  # reference tool and fuzz generators
import canon  # noqa: E402
from test_fuzz import random_cell, random_instant, random_scalar, random_text  # noqa: E402

rng = random.Random(SEED)
CONTENT = {}  # blob value -> its content
HOSTS = ["rates.example.org", "calc.example.net", "a1.example"]
SEEDS = {h: [bytes([i + 1, j + 1]) * 16 for j in range(2)] for i, h in enumerate(HOSTS)}
WINDOWS = [("2020-01-01T00:00:00.000000Z", "2024-06-01T00:00:00.000000Z"), ("2024-06-01T00:00:00.000000Z", None)]


def keydoc(host, extra=None):
    keys = []
    for seed, (frm, to) in zip(SEEDS[host], WINDOWS):
        _, public = canon.keypair(seed)
        entry = {"alg": "ed25519", "id": canon.key_id(public), "public": public.hex(), "valid_from": frm}
        if to:
            entry["valid_to"] = to
        keys.append(entry)
    doc = {"host": host, "keys": keys, "proto": canon.PROTO}
    if extra:
        extra(doc)
    return json.dumps(doc, indent=rng.choice([None, 2]))


def env():
    return {h: {"https": {"status": 200, "body": keydoc(h)}} for h in HOSTS}


def make_receipt():
    host = rng.choice(HOSTS)
    cell = random_cell(rng)
    cell["args"] = {k: v for k, v in cell["args"].items() if v != canon.SLICE}
    cell["ns"] = host + rng.choice(["", "/stats"])
    type_ = rng.choice(canon.TYPES)
    value = random_scalar(rng, type_)["value"]
    if type_ == "blob":  # real content, so step 7.7 can pass
        content = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 50, 300])))
        value = f"{canon.sha256_hex(content)}:{len(content)}:{rng.choice(['text/csv', 'image/png', 'application/ld+json'])}"
        CONTENT[value] = content
    times = sorted(random_instant(rng) for _ in range(3))
    tx, asof = times[0], times[1]
    # issued inside one of the two key windows
    k = rng.randrange(2)
    issued = max(asof, WINDOWS[k][0])
    if k == 0 and issued >= WINDOWS[0][1]:
        k, issued = 1, max(asof, WINDOWS[1][0])
    valid = {n: v for n, v in cell["args"].items() if v["type"] in ("date", "instant") and rng.random() < 0.7}
    _, public = canon.keypair(SEEDS[host][k])
    r = {
        "asof": asof, "cell": cell, "computed_by": f"{host}#{canon.key_id(public)}",
        "inputs": sorted({"".join(rng.choice("0123456789abcdef") for _ in range(64)) for _ in range(rng.randint(0, 3))}),
        "issued": issued, "licence": rng.choice(["CC-BY-4.0", "Apache-2.0", "https://example.org/licence?v=1"]),
        "proto": canon.PROTO, "publisher": cell["ns"], "summary": random_text(rng, 30) or "A value.",
        "tx": tx, "type": type_, "valid": valid, "value": value,
    }
    return r, SEEDS[host][k]


def serialise(obj):
    return json.dumps(obj, ensure_ascii=rng.random() < 0.5, indent=rng.choice([None, 1]))


def corrupt(r, seed, keys):
    """Apply one corruption. Returns (input text or bytes, keys env)."""
    kind = rng.choice([
        "tamper-value", "bit-flip", "sig-bit", "unknown-key", "key-window", "doc-bad-id", "doc-404",
        "doc-error", "non-canonical-number", "nfd-summary", "unsorted-inputs", "missing-member",
        "publisher", "time-order", "slice", "duplicate-member", "uppercase-hex", "valid-mismatch",
    ])
    s = canon.sign_receipt(r, seed)
    if kind == "tamper-value":
        s["summary"] = s["summary"] + "!"
    elif kind == "bit-flip":
        b = bytearray(canon.jcs(s))
        i = rng.randrange(len(b) * 8)
        b[i // 8] ^= 1 << (i % 8)
        return bytes(b), keys
    elif kind == "sig-bit":
        sig = bytearray.fromhex(s["sig"]); i = rng.randrange(512); sig[i // 8] ^= 1 << (i % 8); s["sig"] = sig.hex()
    elif kind == "unknown-key":
        s = canon.sign_receipt(dict(r, computed_by=r["computed_by"][:-16] + "0123456789abcdef"), seed)
    elif kind == "key-window":
        s = canon.sign_receipt(dict(r, issued="2019-06-01T00:00:00.000000Z", asof=min(r["asof"], "2019-06-01T00:00:00.000000Z"),
                                    tx=min(r["tx"], "2019-06-01T00:00:00.000000Z")), seed)
    elif kind in ("doc-bad-id", "doc-404", "doc-error"):
        host = r["computed_by"].split("#")[0]
        keys = dict(keys)
        keys[host] = {"https": {"status": 200, "body": keydoc(host, lambda d: d["keys"][0].update(id="ffffffffffffffff"))}} \
            if kind == "doc-bad-id" else {"https": {"status": 404 if kind == "doc-404" else "error"}}
    elif kind == "non-canonical-number":
        s = canon.sign_receipt(dict(r, type="number", value=rng.choice(["1.50", "-0", "1e3", "01"])), seed)
    elif kind == "nfd-summary":
        s = canon.sign_receipt(dict(r, summary="Zürich rate."), seed)
    elif kind == "unsorted-inputs":
        s = canon.sign_receipt(dict(r, inputs=["f" * 64, "0" * 64]), seed)
    elif kind == "missing-member":
        del s[rng.choice(sorted(s))]
    elif kind == "publisher":
        s = canon.sign_receipt(dict(r, publisher="other.example"), seed)
    elif kind == "time-order":
        s = canon.sign_receipt(dict(r, tx=r["issued"][:4] + "9" + r["issued"][5:] if False else "9999-12-31T23:59:59.999999Z"), seed)
    elif kind == "slice" and r["cell"]["args"]:
        cell = json.loads(json.dumps(r["cell"])); cell["args"][rng.choice(sorted(cell["args"]))] = "*"
        s = canon.sign_receipt(dict(r, cell=cell, valid={}), seed)
    elif kind == "duplicate-member":
        return serialise(s)[:-1] + ', "value": "1"}', keys
    elif kind == "uppercase-hex":
        s["sig"] = s["sig"].upper()
    elif kind == "valid-mismatch":
        s = canon.sign_receipt(dict(r, valid={"zz": {"type": "date", "value": "2024-01-01"}}), seed)
    return serialise(s), keys


for i in range(N):
    r, seed = make_receipt()
    keys = env()
    if rng.random() < 0.5:
        data = serialise(canon.sign_receipt(r, seed))
    else:
        data, keys = corrupt(r, seed, keys)
    vec = {"id": f"cross/{i:04d}", "kind": "receipt", "description": "random", "valid": True, "keys": keys}
    if r["value"] in CONTENT and rng.random() < 0.8:  # step 7.7: right content, or one flipped bit
        content = bytearray(CONTENT[r["value"]])
        if content and rng.random() < 0.3:
            j = rng.randrange(len(content) * 8)
            content[j // 8] ^= 1 << (j % 8)
        vec["blob_hex"] = bytes(content).hex()
    if isinstance(data, bytes):
        vec["input_hex"] = data.hex()
    else:
        vec["input"] = data
    print(json.dumps(vec, ensure_ascii=True))


# --- lineage (spec-0.3.0: SPEC 8.2, 10.1 steps 7.5-7.7) ------------------------------------------
# A separate random stream, so the cases above stay what they were for a given seed.

lin = random.Random(SEED * 7919 + 1)
STORED = {"code": {"body": "", "lang": "stored"}, "inputs": [],
          "signature": {"args": {"date": {"type": "date", "valid": True}, "series": {"type": "string", "valid": False}},
                        "returns": {"type": "number", "unit": "1"}}}
STORED_HASH = canon.sha256_hex(canon.jcs(STORED))


def computed_descriptor(returns):
    return {"code": {"body": "sum(rates.example.org/series(date: date, series: s) for s in inputs)\n", "lang": "expr"},
            "inputs": ["rates.example.org/series"],
            "signature": {"args": {"date": {"type": "date", "valid": True}}, "returns": returns}}


def lineage_instant(day, second):
    return f"2023-05-{day:02d}T{second // 3600:02d}:{second // 60 % 60:02d}:{second % 60:02d}.000000Z"


def stored_input(name, tx, asof):
    key = SEEDS["rates.example.org"][0]  # 2020-2024 window; every lineage time is in 2023
    _, public = canon.keypair(key)
    r = {"asof": asof, "cell": {"args": {"date": {"type": "date", "value": "2023-05-01"}, "series": {"type": "string", "value": name}},
                                "fn": "series", "fn_hash": STORED_HASH, "ns": "rates.example.org"},
         "computed_by": f"rates.example.org#{canon.key_id(public)}", "inputs": [], "issued": asof, "licence": "CC-BY-4.0",
         "proto": canon.PROTO, "publisher": "rates.example.org", "summary": f"Series {name}.", "tx": tx, "type": "number",
         "valid": {"date": {"type": "date", "value": "2023-05-01"}}, "value": str(lin.randint(1, 99))}
    return canon.sign_receipt(r, key)


for i in range(N // 4):
    asof = lineage_instant(10, lin.randrange(3600, 80000))
    stored = []
    for j in range(lin.randint(1, 3)):
        relation = lin.choice(["earlier", "earlier", "equal", "later"])
        input_asof = {"earlier": lineage_instant(lin.randint(2, 9), lin.randrange(86400)), "equal": asof,
                      "later": lineage_instant(lin.randint(11, 20), lin.randrange(86400))}[relation]
        tx = input_asof if lin.random() < 0.6 else lineage_instant(1, lin.randrange(86400))  # asof = tx, or earlier
        stored.append((relation, stored_input(f"s{j}", tx, input_asof)))
    hashes = {canon.receipt_hash(r): r for _, r in stored}
    blob = lin.random() < 0.2
    if blob:
        content = bytes(lin.randrange(256) for _ in range(lin.choice([0, 7, 40])))
        type_, value = "blob", f"{canon.sha256_hex(content)}:{len(content)}:text/csv"
        desc = computed_descriptor("blob")
    else:
        type_, value = "number", str(sum(int(r["value"]) for _, r in stored))
        desc = computed_descriptor({"type": "number", "unit": "1"})
    tx = max(r["tx"] for _, r in stored)
    if lin.random() < 0.1:  # not the latest input tx
        tx = lineage_instant(1, 0)
    if lin.random() < 0.3:  # the SHOULD of 8.2: the latest input asof
        asof = max(max(r["asof"] for _, r in stored), tx)
    signer = SEEDS["calc.example.net"][0]
    _, public = canon.keypair(signer)
    receipt = canon.sign_receipt({
        "asof": asof, "cell": {"args": {"date": {"type": "date", "value": "2023-05-01"}}, "fn": "total",
                               "fn_hash": canon.sha256_hex(canon.jcs(desc)), "ns": "calc.example.net"},
        "computed_by": f"calc.example.net#{canon.key_id(public)}", "inputs": sorted(hashes), "issued": asof,
        "licence": "CC-BY-4.0", "proto": canon.PROTO, "publisher": "calc.example.net", "summary": "A total.",
        "tx": min(tx, asof), "type": type_, "valid": {"date": {"type": "date", "value": "2023-05-01"}}, "value": value,
    }, signer)
    recompute = {"descriptor": desc, "inputs": {h: serialise(r) for h, r in hashes.items()}}
    evaluation = lin.choice(["match", "match", "absent", "absent", "differs"])
    if evaluation == "match":
        recompute["value"] = {"type": type_, "value": value}
    elif evaluation == "differs":
        recompute["value"] = {"type": "number", "value": "100000"}
    if lin.random() < 0.05:
        del recompute["descriptor"]
    if lin.random() < 0.05:
        recompute["inputs"].pop(sorted(hashes)[0])
    relations = "-".join(sorted({rel for rel, _ in stored}))
    vec = {"id": f"cross-lineage/{i:04d}-{relations}-{evaluation}", "kind": "receipt", "description": "random lineage",
           "valid": True, "keys": env(), "recompute": recompute, "input": serialise(receipt)}
    if blob and lin.random() < 0.8:
        vec["blob_hex"] = (content if lin.random() < 0.7 else content + b"x").hex()
    print(json.dumps(vec, ensure_ascii=True))
