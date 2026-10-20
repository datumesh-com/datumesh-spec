# SPDX-License-Identifier: Apache-2.0
"""Generate N random receipt cases (JSON lines, SPEC.md section 11 vector format).

About half are valid; the rest carry one corruption each, chosen to reach
every verification step. The spec repo's reference tool signs them; the
libraries under test are only ever run on the output.

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
    if isinstance(data, bytes):
        vec["input_hex"] = data.hex()
    else:
        vec["input"] = data
    print(json.dumps(vec, ensure_ascii=True))
