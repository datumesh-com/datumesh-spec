#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""spec-0.6.1 vectors (SPEC.md section 11 vector format), written tests-first.

spec-0.6.1 (CONTRACT-build2-spec-0.6.1.md S1-S3, ANSWERS-build2-names.md): a namespace segment after the
host may be a DNS name, as a label only (2.3); the test_case convention (7.3); `publisher` in a describe
answer (16.8).

Like generate_060.py the vectors are built from the fixtures and keys of tools/gen_vectors.py (imported,
never run) and signed with the same vector keys (rates-2020, calc-2020). The reference tools of spec-0.6.0
refuse a dotted later segment, so no expected output asks them: canonical bytes, hashes, signatures and
receipt hashes come from the pure helpers of canon.py (JCS, SHA-256, the receipt payload), and every
expected code is stated by hand from the text of SPEC.md 2.3, 5.1, 15.2 and 16.8. The reference tools must
then be made to agree with them. The only outputs that depend on an evaluator are those of the three
`formula-eval` vectors (value, lineage, fuel and receipt hash): they are written in EVAL_OUTPUT below, taken
once from a copy of the reference with the 0.6.1 lexer rule applied (the committed tools of spec-0.6.1 reproduce them: tests/test_spec_0_6_1.py), and the value of
each was also worked by hand (see the comments).

Only new files are written under vectors/. Every existing vector stays byte for byte as it is.

    python3 crosscheck/generate_061.py            # write the vectors
    python3 -c "import generate_061"              # (from crosscheck/) build them in memory: VECTORS
"""

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "tools"), str(HERE)]
import canon  # noqa: E402
import gen_vectors as gv  # noqa: E402  (the fixtures and keys; its main() is not run)
import generate_060 as g60  # noqa: E402  (describe fixtures; its vectors are built in memory, never written)

OUT = ROOT / "vectors"
VECTORS = []


def add(id_, kind, description, input=None, error=None, **extra):
    vec = {"id": id_, "kind": kind, "description": "spec-0.6.1: " + description, "valid": error is None}
    if input is not None:
        vec["input"] = input
    vec.update(extra)
    if error is not None:
        vec["error"] = error
    VECTORS.append(vec)


S, N, D = gv.S, gv.N, gv.D
text = gv.text
ASOF = gv.ASOF
FX, FX_HASH, FX_CELL, FX_ARGS, SIG = gv.FX, gv.FX_HASH, gv.FX_CELL, gv.FX_ARGS, gv.SIG
cell_id = gv.cell_id
sha = canon.sha256_hex


def jcs_text(obj):
    return canon.jcs(obj).decode()


# ---------------------------------------------------------------------------
# S1: DNS-name segments (2.3). One table; each row becomes a define, a cell and a uri vector.

R = "datumesh.com/relay"


def dns_of_length(n, last="a"):
    """A DNS name of exactly n characters: labels of at most 63 characters, the last label not all digits."""
    labels, left = [], n
    while left > 0:
        size = min(63, left)
        if left - size == 1:  # a label of 1 would leave a bare dot
            size -= 1
        labels.append(size)
        left -= size + (1 if left - size > 0 else 0)
    return ".".join(("a" * size) for size in labels)


assert len(dns_of_length(253)) == 253 and len(dns_of_length(254)) == 254 and len(dns_of_length(240)) == 240
LONG_253, LONG_254, LONG_240 = dns_of_length(253), dns_of_length(254), dns_of_length(240)
NAME_64 = "a" * 64
NAME_65 = "a" * 65

# (slug, full function name, expected code or None, what it shows)
NAMES = [
    ("relay-ecb", f"{R}/ecb.europa.eu/fx_reference", None,
     "A DNS name as a namespace segment after the host: the relay of the ECB's reference rates (2.3)."),
    ("hyphen", f"{R}/bank-x.example/rate", None, "A hyphenated domain segment."),
    ("punycode", f"{R}/xn--bcher-kva.example/rate", None, "A punycode (A-label) segment, opaque as in 2.1."),
    ("three-labels", f"{R}/bankofengland.co.uk/bank_rate", None, "A DNS segment of three labels."),
    ("two-dns-segments", f"{R}/ecb.europa.eu/v2.example/rate", None, "Two DNS segments in one namespace."),
    ("host-hyphen", "bank-x.example/relay/ecb.europa.eu/rate", None, "A hyphenated host and a DNS segment."),
    ("max-253", f"datumesh.com/{LONG_253}/rate", None,
     "A DNS segment of 253 characters: the 64-character limit is for name segments only (2.3)."),
    ("max-512", f"datumesh.com/{LONG_253}/{LONG_240}/rate", None,
     "A function name of exactly 512 characters, with two DNS segments: the limit is the whole name's (2.3)."),
    ("uppercase", f"{R}/ECB.europa.eu/rate", "E_CANON_NAME", "An uppercase letter in a DNS segment."),
    ("trailing-dot", f"{R}/ecb.europa.eu./rate", "E_CANON_NAME", "A trailing dot in a DNS segment."),
    ("underscore", f"{R}/ecb_x.europa.eu/rate", "E_CANON_NAME", "An underscore inside a DNS segment."),
    ("empty-label", f"{R}/ecb..eu/rate", "E_CANON_NAME", "An empty label in a DNS segment."),
    ("leading-hyphen", f"{R}/-ecb.europa.eu/rate", "E_CANON_NAME", "A label of a DNS segment with a leading hyphen."),
    ("inner-trailing-hyphen", f"{R}/ecb-.europa.eu/rate", "E_CANON_NAME",
     "A label of a DNS segment with a trailing hyphen."),
    ("last-label-hyphen", f"{R}/ecb.europa.eu-/rate", "E_CANON_NAME",
     "The last label of a DNS segment ends with a hyphen."),
    ("all-digit-last-label", f"{R}/10.0.0.1/rate", "E_CANON_NAME",
     "The last label of a DNS segment is not all digits: an IPv4 address is not a segment."),
    ("leading-dot", f"{R}/.europa.eu/rate", "E_CANON_NAME", "A DNS segment may not start with a dot."),
    ("u-label", f"{R}/bücher.example/rate", "E_CANON_NAME", "A U-label is refused, as in 2.1: A-labels only."),
    ("hyphen-without-dot", f"{R}/bank-x/rate", "E_CANON_NAME",
     "A segment with a hyphen and no dot is neither a name nor a DNS name."),
    ("last-segment", f"{R}/ecb.europa.eu", "E_CANON_NAME",
     "A DNS name as the last segment: the function stays a name (2.3)."),
    ("label-64", f"{R}/{NAME_64}.example/rate", "E_CANON_NAME", "A label of 64 characters: labels are at most 63."),
    ("segment-254", f"datumesh.com/{LONG_254}/rate", "E_CANON_NAME", "A DNS segment of 254 characters."),
    ("name-65", f"{R}/{NAME_65}/rate", "E_CANON_LIMIT",
     "A name segment of 65 characters is still E_CANON_LIMIT: the 64 limit holds for names."),
    ("too-long", f"datumesh.com/{LONG_253}/{LONG_253}/rate", "E_CANON_LIMIT",
     "A function name of 525 characters: the whole name keeps its 512."),
]
assert len(NAMES[7][1]) == 512 and len(NAMES[-1][1]) > 512

STORED = FX


def split(full):
    ns, _, fn = full.rpartition("/")
    return ns, fn


def ref_of(ns, fn):
    return {"args": FX_ARGS, "fn": fn, "ns": ns}


def uri_of(full):
    return f"cell://{full}?base=EUR&date=2024-03-15&quote=USD"


def uri_outputs(full):
    ns, fn = split(full)
    ref = ref_of(ns, fn)
    return {"object": ref, "canonical": jcs_text(ref), "sha256": sha(canon.jcs(ref)), "uri": uri_of(full),
            "https": "https://mesh.example/cell/" + uri_of(full)[len("cell://"):]}


for slug, full, error, why in NAMES:
    ns, fn = split(full)
    cell = FX_CELL | {"ns": ns, "fn": fn}
    if error is None:
        add(f"define/dns-segment-{slug}", "define", why + f" The name {full} is defined.", text(STORED), name=full,
            canonical=jcs_text(STORED), sha256=sha(canon.jcs(STORED)))
        add(f"cell/dns-segment-{slug}", "cell", why, text(cell), canonical=jcs_text(cell), sha256=sha(canon.jcs(cell)))
        add(f"uri/dns-segment-{slug}", "uri", why, uri_of(full), signature=SIG, **uri_outputs(full))
    else:
        add(f"invalid/define-dns-segment-{slug}", "define", why, text(STORED), error, name=full)
        add(f"invalid/cell-dns-segment-{slug}", "cell", why, text(cell), error)
        add(f"invalid/uri-dns-segment-{slug}", "uri", why, uri_of(full), error, signature=SIG)

# A refused name inside a descriptor's inputs (7), and a valid one.
RELAY_FN = f"{R}/ecb.europa.eu/fx_reference"
DERIVED = {"code": {"body": f"{RELAY_FN}(base: base, date: date, quote: quote)\n", "lang": "expr"},
           "inputs": [RELAY_FN], "signature": FX["signature"]}
add("function/inputs-dns-segment", "function", "A DNS segment in the fully qualified names of `inputs` (7).",
    text(DERIVED), canonical=jcs_text(DERIVED), sha256=sha(canon.jcs(DERIVED)))
add("invalid/function-inputs-dns-segment-uppercase", "function",
    "An input name with an uppercase letter in a DNS segment is E_CANON_NAME.",
    text(DERIVED | {"inputs": [f"{R}/ECB.europa.eu/fx_reference"]}), "E_CANON_NAME")
add("invalid/function-inputs-dns-segment-last", "function",
    "An input name whose last segment is a DNS name is E_CANON_NAME.",
    text(DERIVED | {"inputs": [f"{R}/ecb.europa.eu"]}), "E_CANON_NAME")

# ---------------------------------------------------------------------------
# S1: the host alone decides rooted or unrooted (2.5): `.invalid` in a later segment changes nothing.

ROOTED = "rates.example.org/x/foo.invalid/f"
ROOTED_READ = "calc.example.net/x/foo.invalid/g"
UNROOTED_HOST = "local.invalid/x/foo.example/g"


def reads(*names, body="x\n"):
    return {"code": {"body": body, "lang": "expr"}, "inputs": sorted(names),
            "signature": {"args": {}, "returns": {"type": "number", "unit": "1"}}}


for slug, name, d, why in [
    ("invalid-segment-rooted-reads-rooted", ROOTED, reads(ROOTED_READ),
     f"{ROOTED} is rooted (its host is rates.example.org): it may read the rooted {ROOTED_READ}."),
    ("invalid-segment-unrooted-reads-rooted", UNROOTED_HOST, reads(ROOTED),
     f"{UNROOTED_HOST} is unrooted (its host is local.invalid): it may read the rooted {ROOTED}."),
]:
    add(f"define/dns-segment-{slug}", "define", why, text(d), name=name, canonical=jcs_text(d),
        sha256=sha(canon.jcs(d)))
add("invalid/define-dns-segment-invalid-segment-reads-unrooted", "define",
    f"{ROOTED} is rooted: a `.invalid` later segment makes nothing unrooted, so it may not read local.invalid/g "
    "(E_UNROOTED_INPUT, 2.5).", text(reads("local.invalid/g")), "E_UNROOTED_INPUT", name=ROOTED)
add("invalid/define-dns-segment-rooted-reads-unrooted-host", "define",
    f"A rooted function may not read {UNROOTED_HOST}: its host is unrooted, whatever the later segments (E_UNROOTED_INPUT).",
    text(reads(UNROOTED_HOST)), "E_UNROOTED_INPUT", name="rates.example.org/f")

# ---------------------------------------------------------------------------
# S1: receipts and envelopes with DNS segments. Signed with the existing vector keys: a receipt that
# verifies is signed by rates-2020 (host rates.example.org) or calc-2020 (host calc.example.net); the
# reserved example domains are used for everything signed (section 11).

KEYENV = gv.KEYENV
SRC = {"name": "ecb.europa.eu", "url": "https://data.ecb.europa.eu/data/datasets/EXR",
       "retrieved": "2024-03-15T15:30:00.000000Z", "sha256": sha(b"example fetched bytes, invented for a test vector"),
       "takeover": "https://ecb.europa.eu/publish/takeover"}


def make_receipt(ns, key, value="1.0892", source=None, type_="number", fn="fx_reference", args=FX_ARGS,
                 fn_hash=FX_HASH, summary=None):
    cell = {"args": args, "fn": fn, "fn_hash": fn_hash, "ns": ns}
    r = gv.receipt(cell, type_, value, summary or "1 EUR was worth 1.0892 USD at the 15 March 2024 reference rate.",
                   key)
    if source is not None:
        r["source"] = source
    return gv.signed(r, key)


def valid_receipt(id_, why, r, key="rates-2020", recompute=None):
    payload = canon.receipt_payload(r)
    extra = {"keypair": gv.keypair_fields(key), "keys": KEYENV}
    if recompute is not None:
        extra["recompute"] = recompute
    add(id_, "receipt", why, text(r), canonical=payload.decode(), sha256=sha(payload), sig=r["sig"],
        level="recomputed" if recompute else "signed", **extra)


def invalid_receipt(id_, why, r, error, key="rates-2020"):
    add(id_, "receipt", why, text(r), error, keypair=gv.keypair_fields(key), keys=KEYENV)


RELAY_NS = "rates.example.org/relay/ecb.europa.eu"
R_RELAY = make_receipt(RELAY_NS, "rates-2020", source=SRC)
valid_receipt("receipt/dns-segment-relay", "A relayed receipt (8.1) for rates.example.org/relay/ecb.europa.eu/"
              "fx_reference: the later segment is a label, and source names the domain the value came from. It "
              "signs and verifies like any receipt; nothing is fetched for ecb.europa.eu.", R_RELAY,
              recompute={"descriptor": FX, "inputs": {}, "value": N("1.0892")})
R_PLAIN = make_receipt("rates.example.org/relay/bank-x.example", "rates-2020", fn="rate")
valid_receipt("receipt/dns-segment-stored", "A stored receipt under a namespace with a hyphenated DNS segment; its "
              "publisher is the namespace, as always.", R_PLAIN)
R_ROOTED = make_receipt("rates.example.org/x/foo.invalid", "rates-2020", fn="f")
valid_receipt("receipt/dns-segment-invalid-rooted", "A receipt whose namespace has a later segment foo.invalid: it "
              "is rooted (2.5), signs with the key of rates.example.org and verifies as any rooted receipt.", R_ROOTED)
R_BAD = make_receipt("rates.example.org/relay/ECB.europa.eu", "rates-2020")
invalid_receipt("invalid/receipt-dns-segment-uppercase", "An uppercase letter in a DNS segment of cell.ns is "
                "E_CANON_NAME, signed or not.", R_BAD, "E_CANON_NAME")
R_BAD_PUB = make_receipt("rates.example.org/relay/ecb.europa.eu", "rates-2020")
R_BAD_PUB = dict(R_BAD_PUB)
R_BAD_PUB.pop("sig")
R_BAD_PUB["publisher"] = "rates.example.org/relay/ecb.europa.eu."
R_BAD_PUB = gv.signed(R_BAD_PUB, "rates-2020")
invalid_receipt("invalid/receipt-dns-segment-publisher-trailing-dot", "publisher is a namespace (2.3): a trailing dot "
                "in a DNS segment is E_CANON_NAME.", R_BAD_PUB, "E_CANON_NAME")


def envelope(id_, why, env, status, error=None, request=None, **extra):
    if request is None:
        request = {"asof": ASOF, "cell_id": cell_id(env["receipt"]["cell"])}
    add(id_, "envelope", why, text(env), error, status=status, keys=gv.ALL_KEYS, request=request, **extra)


def valid_envelope(id_, why, env, status=200, request=None):
    envelope(id_, why, env, status, request=request, outcome=env["outcome"], trust=env["trust"],
             receipt_hash=canon.receipt_hash(env["receipt"]))


valid_envelope("envelope/dns-segment-relayed", "Trust relayed (5.5): the signer, rates.example.org, is the host of "
               "cell.ns, which is the first segment. The later segment ecb.europa.eu plays no part.",
               {"outcome": "ok", "receipt": R_RELAY, "trust": "relayed"})
envelope("invalid/envelope-dns-segment-relayed-as-primary", "The same receipt has a source: primary is E_ENVELOPE.",
         {"outcome": "ok", "receipt": R_RELAY, "trust": "primary"}, 200, "E_ENVELOPE")
valid_envelope("envelope/dns-segment-primary", "Trust primary: the signer is the host of cell.ns "
               "(rates.example.org), inputs is empty and there is no source.",
               {"outcome": "ok", "receipt": R_PLAIN, "trust": "primary"})
# A namespace whose later segment names the signer's own domain: the label gives it no authority.
R_LABEL = make_receipt("calc.example.net/relay/rates.example.org", "rates-2020", fn="fx_reference")
valid_envelope("envelope/dns-segment-label-only", "cell.ns is calc.example.net/relay/rates.example.org and "
               "rates.example.org signed it. The host of cell.ns is calc.example.net, so the receipt is not primary, "
               "whatever the later segment says: trust unverified.",
               {"outcome": "ok", "receipt": R_LABEL, "trust": "unverified"})
envelope("invalid/envelope-dns-segment-label-primary", "The signer's domain appears as a later segment of cell.ns, "
         "but only the first segment decides primary (5.5): trust primary is E_ENVELOPE.",
         {"outcome": "ok", "receipt": R_LABEL, "trust": "primary"}, 200, "E_ENVELOPE")
envelope("invalid/envelope-dns-segment-host-not-primary", "The signer is the host of cell.ns: the receipt is "
         "primary, and unverified is E_ENVELOPE (primary exactly when its condition holds).",
         {"outcome": "ok", "receipt": R_PLAIN, "trust": "unverified"}, 200, "E_ENVELOPE")

# ---------------------------------------------------------------------------
# S1: classes (16.1, 16.2): a class name is a full name; the steward namespace is a namespace; a method is a name.

FX_PAIR = json.loads((OUT / "class" / "fx-pair.json").read_text(encoding="utf-8"))
FX_PAIR_INPUT = json.loads(FX_PAIR["input"])


def class_vector(id_, why, name, desc, error=None):
    extra = {"env": FX_PAIR["env"], "name": name}
    if error is None:
        flat = jcs_text(desc)
        extra |= {"flattened": flat, "class_hash": sha(flat.encode())}
    add(id_, "class", why, text(desc), error, **extra)


assert FX_PAIR["flattened"] == jcs_text(FX_PAIR_INPUT)
class_vector("class/dns-segment-name", "A class under a namespace with a DNS segment (2.3): the class name is "
             "a full name. The class hash does not hold the name, so it is the hash of fx-pair.",
             "rates.example.org/relay/ecb.europa.eu/fx_pair", FX_PAIR_INPUT)
class_vector("class/dns-segment-steward", "The steward's namespace has a DNS segment (16.1).",
             "rates.example.org/fx_pair",
             FX_PAIR_INPUT | {"steward": dict(FX_PAIR_INPUT["steward"], namespace="rates.example.org/relay/ecb.europa.eu")})
class_vector("invalid/class-dns-segment-last", "A class name's last segment stays a name: a DNS name is "
             "E_CANON_NAME.", "rates.example.org/relay/ecb.europa.eu", FX_PAIR_INPUT, "E_CANON_NAME")
class_vector("invalid/class-dns-segment-method-name", "A method name is a name (2.2): a dotted one is E_CANON_NAME, "
             "in a class whose own namespace has a DNS segment, which is valid.",
             "rates.example.org/relay/ecb.europa.eu/fx_pair",
             FX_PAIR_INPUT | {"methods": {"ecb.europa.eu": FX_PAIR_INPUT["methods"]["rate"]}}, "E_CANON_NAME")
class_vector("invalid/class-dns-segment-steward-uppercase", "An uppercase letter in the steward's DNS segment.",
             "rates.example.org/fx_pair",
             FX_PAIR_INPUT | {"steward": dict(FX_PAIR_INPUT["steward"], namespace="rates.example.org/relay/ECB.europa.eu")},
             "E_CANON_NAME")

# ---------------------------------------------------------------------------
# S1: formulas (15.2 L3, 15.3, 15.4). Bodies: a run after "/" holding "." or "-" is a DNS segment only
# when "/" follows it; the last segment is a name. Outputs of the `formula` vectors are written by hand
# (AST, printed body, inputs, returns) from 15.5 and 15.6.

STD_ARGS = {"d": {"type": "date", "valid": True}}
F_ORDER = ["d"]


def rate_fn(unit="1"):
    return {"code": {"body": "", "lang": "stored"}, "inputs": [],
            "signature": {"args": {"d": {"type": "date", "valid": True}}, "returns": {"type": "number", "unit": unit},
                          "order": ["d"]}}


def f_env(names, returns="1"):
    return {"aliases": {}, "functions": {n: rate_fn() for n in names}, "name": "calc.example.net/f",
            "signature": {"args": STD_ARGS, "order": F_ORDER, "returns": {"type": "number", "unit": returns}}}


def read(fn):
    return {"args": {"d": {"name": "d", "node": "var"}}, "fn": fn, "node": "read"}


def op(o, a, b):
    return {"args": [a, b], "node": "op", "op": o}


ONE = {"node": "num", "value": "1"}
ECB_RATE = f"{R}/ecb.europa.eu/rate"
BANK_RATE = f"{R}/bank-x.example/rate"
TSY_YIELD = f"{R}/treasury.gov/yield"
D_ARG = "(d: d)"


def formula_vector(id_, why, source, ast, body, inputs, fns=None, returns="1"):
    ast_text = jcs_text(ast)
    add(id_, "formula", why, source, env=f_env(fns if fns is not None else inputs, returns),
        ast=ast_text, ast_sha256=sha(ast_text.encode()), body=body, inputs=sorted(inputs),
        returns={"type": "number", "unit": returns}, asof_dependent=False)


formula_vector("formula/dns-segment-minus", "A read whose namespace has a DNS segment, then minus with no space: the "
               "segment is a DNS name because \"/\" follows it, and the last segment is a name (15.2 L3).",
               f"{ECB_RATE}{D_ARG}-1", op("-", read(ECB_RATE), ONE), f"{ECB_RATE}{D_ARG} - 1\n", [ECB_RATE])
formula_vector("formula/dns-segment-minus-spaced", "The same, with spaces round the minus.",
               f"{ECB_RATE}{D_ARG} - 1", op("-", read(ECB_RATE), ONE), f"{ECB_RATE}{D_ARG} - 1\n", [ECB_RATE])
formula_vector("formula/dns-segment-minus-left", "A subtraction whose right operand is a read with a hyphenated DNS "
               "segment: with spaces, 1 is a number and the hyphen an operator.",
               f"1 - {BANK_RATE}{D_ARG}", op("-", ONE, read(BANK_RATE)), f"1 - {BANK_RATE}{D_ARG}\n", [BANK_RATE])
# The contract's `1-datumesh.com/...` without spaces: longest match (15.4, hyphenated hosts) reads 1-datumesh.com as a host.
HY_HOST_RATE = "1-datumesh.com/relay/bank-x.example/rate"
formula_vector("formula/dns-segment-digit-hyphen-host", "No spaces: 1-datumesh.com is one host (15.4, hyphenated hosts: "
               "longest match), so this is a read of 1-datumesh.com/relay/bank-x.example/rate, not a subtraction.",
               f"{HY_HOST_RATE}{D_ARG}", read(HY_HOST_RATE), f"{HY_HOST_RATE}{D_ARG}\n", [HY_HOST_RATE])
add("invalid/formula-dns-segment-digit-hyphen-host-unbound", "formula", "Written without spaces, "
    "1-datumesh.com/relay/bank-x.example/rate(d: d) is a read of a function under the host 1-datumesh.com, which "
    "nothing binds: E_FORMULA_UNRESOLVED. It is not 1 minus the read of datumesh.com/relay/bank-x.example/rate "
    "(write the spaces).", f"{HY_HOST_RATE}{D_ARG}", "E_FORMULA_UNRESOLVED", env=f_env([BANK_RATE]))
formula_vector("formula/dns-segment-divide", "A DNS-segment read divided by another: the \"/\" after the closing "
               "parenthesis is the operator, the \"/\" inside a name is not (15.4).",
               f"{ECB_RATE}{D_ARG}/{TSY_YIELD}{D_ARG}", op("/", read(ECB_RATE), read(TSY_YIELD)),
               f"{ECB_RATE}{D_ARG} / {TSY_YIELD}{D_ARG}\n", [ECB_RATE, TSY_YIELD])
formula_vector("formula/dns-segment-two-segments", "Two DNS segments in one name.",
               f"{R}/ecb.europa.eu/v2.example/rate{D_ARG}", read(f"{R}/ecb.europa.eu/v2.example/rate"),
               f"{R}/ecb.europa.eu/v2.example/rate{D_ARG}\n", [f"{R}/ecb.europa.eu/v2.example/rate"])
formula_vector("formula/dns-segment-punycode", "A punycode segment in a body.",
               f"{R}/xn--bcher-kva.example/rate{D_ARG}", read(f"{R}/xn--bcher-kva.example/rate"),
               f"{R}/xn--bcher-kva.example/rate{D_ARG}\n", [f"{R}/xn--bcher-kva.example/rate"])

# A method call after a read: `.status()` is still a method (15.3), and a dotted string is only a string.
REG_KEYS = {"code": {"key_normalisation": "none", "type": "string"},
            "source": {"key_normalisation": "none", "type": "string"}}
REG_STATUS = {"code": {"body": "", "lang": "stored"}, "inputs": [],
              "signature": {"args": {"code": {"type": "string", "valid": False},
                                     "source": {"type": "string", "valid": False}},
                            "order": ["source", "code"], "returns": "string"}}
REG_CLASS = {"keys": REG_KEYS, "methods": {"status": canon.function_hash(REG_STATUS)}, "order": ["source", "code"],
             "steward": {"namespace": "datumesh.com/register", "process": "https://datumesh.com/register/change"}}
REG = "datumesh.com/register/dataset"
REG_SOURCE = f'{REG}(source: "ecb.europa.eu", code: "reference_rates").status()'
REG_AST = {"args": {"code": {"node": "str", "value": "reference_rates"}, "source": {"node": "str", "value": "ecb.europa.eu"}},
           "fn": f"{REG}/status", "node": "read"}
REG_ENV = {"aliases": {}, "classes": {REG: REG_CLASS}, "functions": {f"{REG}/status": REG_STATUS},
           "name": "calc.example.net/f", "signature": {"args": {}, "order": [], "returns": "string"}}
reg_ast_text = jcs_text(REG_AST)
add("formula/dns-segment-method-call", "formula", "A method call after a read, with a domain in a string literal: "
    "`.status()` after `)` stays a method call (15.3), as in 0.6.0; the register's `source` key holds a domain as a string.",
    REG_SOURCE, env=REG_ENV, ast=reg_ast_text, ast_sha256=sha(reg_ast_text.encode()),
    body=f'{REG}/status(code: "reference_rates", source: "ecb.europa.eu")\n', inputs=[f"{REG}/status"],
    returns={"type": "string"}, asof_dependent=False)

for slug, source, error, why in [
    ("last-before-paren", f"{R}/ecb.europa.eu{D_ARG}", "E_FORMULA_SYNTAX",
     "A dotted run as the last segment before \"(\": the last segment is a name, so the name ends at ecb and the "
     "rest, `.europa.eu`, is not a call of it (15.3: a qualified name not followed by \"(\")."),
    ("uppercase", f"{R}/ECB.europa.eu/rate{D_ARG}", "E_FORMULA_NAME", "A DNS segment with an uppercase letter."),
    ("trailing-dot", f"{R}/ecb.europa.eu./rate{D_ARG}", "E_FORMULA_NAME", "A DNS segment with a trailing dot."),
    ("underscore", f"{R}/ecb_x.europa.eu/rate{D_ARG}", "E_FORMULA_NAME", "A DNS segment with an underscore."),
    ("empty-label", f"{R}/ecb..eu/rate{D_ARG}", "E_FORMULA_NAME", "A DNS segment with an empty label."),
    ("leading-hyphen", f"{R}/-ecb.europa.eu/rate{D_ARG}", "E_FORMULA_NAME",
     "A DNS segment whose first label starts with a hyphen."),
    ("all-digit-last-label", f"{R}/10.0.0.1/rate{D_ARG}", "E_FORMULA_NAME",
     "A DNS segment whose last label is all digits."),
    ("hyphen-without-dot", f"{R}/bank-x/rate{D_ARG}", "E_FORMULA_NAME",
     "A run with a hyphen and no dot, followed by \"/\", is neither a name nor a DNS name."),
]:
    add(f"invalid/formula-dns-segment-{slug}", "formula", why, source, error,
        env=f_env([ECB_RATE]))
# formula-eval: one computed function calc.example.net/e per vector over a small world.
BOUND = "2026-01-01T00:00:00.000000Z"
LATER = "2026-06-01T00:00:00.000000Z"
TX = "2026-03-02T16:00:00.000000Z"
E = "calc.example.net/e"
EVAL_ARGS = {"d": {"type": "date", "valid": True}}


def eval_vector(id_, why, body, inputs, receipts, returns="1"):
    """inputs: {fully qualified name: value of its stored cell for d = 2026-03-02}."""
    descriptor = {"code": {"body": body, "lang": "formula"}, "inputs": sorted(inputs),
                  "signature": {"args": EVAL_ARGS, "order": ["d"], "returns": {"type": "number", "unit": returns}}}
    world = {"functions": {E: {"bound": BOUND, "descriptor": descriptor}} | {
                 n: {"bound": BOUND, "descriptor": rate_fn()} for n in sorted(inputs)},
             "receipts": receipts}
    out = EVAL_OUTPUT.get(id_, {})
    add(id_, "formula-eval", why, world=world, cell={"args": {"d": D("2026-03-02")}, "fn": E}, asof=LATER, **out)


def stored(name, value):
    import formula as F  # the reference's helpers for stored receipts only: no lexer rule is involved
    return F.stored_receipt(rate_fn(), name, {"d": D("2026-03-02")}, N(value), TX)


# Values worked by hand: 1.25 - 1 = 0.25; 1 - 0.9 = 0.1; 1.25 / 0.05 = 25. The other outputs come from the scratch
# reference with the 0.6.1 lexer rule (lineage is the stored receipts' hashes, which are computed here and compared).
EVAL_OUTPUT = {'formula-eval/dns-segment-minus': {'receipt_hash': 'f1601e7b4e127b84b31903743d935371afb230cbc0bd6e00cd62b400dd330c34',
                                    'value': {'type': 'number', 'value': '0.25'},
                                    'lineage': ['8274ea83a5996e3f5c94277c94f175a5674079203093afa410ac691ee0a81a4f'],
                                    'tx': '2026-03-02T16:00:00.000000Z',
                                    'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                    'fuel_used': 5},
 'formula-eval/dns-segment-minus-left': {'receipt_hash': '5e8293c78668bf3eaa7b4dd44dafc3902c65f48a18b821595d0334d6710b2902',
                                         'value': {'type': 'number', 'value': '0.1'},
                                         'lineage': ['4ba4ba8e81d1f8bb0ecc809b0d0a9b3840d83062bc1a9fc56d7a09fb146095cf'],
                                         'tx': '2026-03-02T16:00:00.000000Z',
                                         'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                         'fuel_used': 5},
 'formula-eval/dns-segment-divide': {'receipt_hash': 'e36be44cb5f6b4cd07b1d53083091dc9fbc817691676d0908cb25e486e856850',
                                     'value': {'type': 'number', 'value': '25'},
                                     'lineage': ['1410d497556304e2d53c3f3305375e62845fc8b6603fd49cfa577c5753507195',
                                                 '8274ea83a5996e3f5c94277c94f175a5674079203093afa410ac691ee0a81a4f'],
                                     'tx': '2026-03-02T16:00:00.000000Z',
                                     'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                     'fuel_used': 7}}
EVAL_VECTORS = [
    ("formula-eval/dns-segment-minus", "datumesh.com/relay/ecb.europa.eu/rate(d: d)-1, with the read 1.25: 0.25. "
     "The body is the printed form, which has spaces.", f"{ECB_RATE}{D_ARG} - 1\n", {ECB_RATE: "1.25"}),
    ("formula-eval/dns-segment-minus-left", "1 - datumesh.com/relay/bank-x.example/rate(d: d), with the read 0.9: 0.1.",
     f"1 - {BANK_RATE}{D_ARG}\n", {BANK_RATE: "0.9"}),
    ("formula-eval/dns-segment-divide", "ecb.europa.eu rate / treasury.gov yield, 1.25 / 0.05: 25.",
     f"{ECB_RATE}{D_ARG} / {TSY_YIELD}{D_ARG}\n", {ECB_RATE: "1.25", TSY_YIELD: "0.05"}),
]

for id_, why, body, inputs in EVAL_VECTORS:
    receipts = [stored(n, v) for n, v in sorted(inputs.items())]
    eval_vector(id_, why, body, inputs, receipts)
    assert EVAL_OUTPUT[id_]["lineage"] == sorted(canon.receipt_hash(r) for r in receipts), id_

# ---------------------------------------------------------------------------
# S2: the test_case convention (7.3).

TEST_CASE = {"code": {"body": "", "lang": "stored"}, "inputs": [],
             "signature": {"args": {"case": {"type": "string", "valid": False},
                                    "function_hash": {"type": "string", "valid": False}},
                           "order": ["function_hash", "case"], "returns": "boolean"}}
TEST_CASE_HASH = canon.function_hash(TEST_CASE)
TEST = {"asof": ASOF, "call": 'rates.example.org/fx_rate(base: "EUR", date: 2024-03-15, quote: "USD")',
        "expect": N("1.0892")}
TEST_JCS = canon.jcs(TEST)
CASE = sha(TEST_JCS)[:16]
add("jcs/test-case-id", "jcs", "The case of a test_case cell (7.3) is the first 16 hex digits of the SHA-256 of the "
    f"test's JCS: here {CASE}. The test has call, asof and expect; inputs is absent.", json.dumps(TEST, indent=2),
    canonical=TEST_JCS.decode(), sha256=sha(TEST_JCS))
add("function/test-case", "function", "The test_case function of a host (7.3): function_hash and case, both "
    "strings, and a boolean value. One per host, under the host itself.", text(TEST_CASE),
    canonical=jcs_text(TEST_CASE), sha256=TEST_CASE_HASH)
TC_SIG = TEST_CASE["signature"]
tc_args = {"case": S(CASE), "function_hash": S(FX_HASH)}
tc_uri = f"cell://rates.example.org/test_case?case={CASE}&function_hash={FX_HASH}"
tc_ref = {"args": tc_args, "fn": "test_case", "ns": "rates.example.org"}
add("uri/test-case", "uri", "The URI of a test_case cell: the host's own test_case, with the function hash and the "
    "case as string arguments.", tc_uri, signature=TC_SIG, object=tc_ref, canonical=jcs_text(tc_ref),
    sha256=sha(canon.jcs(tc_ref)), uri=tc_uri, https="https://mesh.example/cell/" + tc_uri[len("cell://"):])
TC_SUMMARY = "The function gives the expected result for this test: true."
R_TC_TRUE = make_receipt("rates.example.org", "rates-2020", value=True, type_="boolean", fn="test_case",
                         args=tc_args, fn_hash=TEST_CASE_HASH, summary=TC_SUMMARY)
valid_receipt("receipt/test-case-true", "A test_case cell: its host signs, with no inputs and no source, a boolean "
              "that says the function whose hash is function_hash gives the expected result of this case (7.3).",
              R_TC_TRUE)
R_TC_FALSE = make_receipt("calc.example.net", "calc-2020", value=False, type_="boolean", fn="test_case",
                          args=tc_args, fn_hash=TEST_CASE_HASH,
                          summary="calc.example.net found that this function does not give this expected result.")
valid_receipt("receipt/test-case-counterexample", "A host that does not own the function publishes its own test_case "
              "cell for the function hash, with value false: an open counterexample (7.3). A receipt like any other.",
              R_TC_FALSE, key="calc-2020")
valid_envelope("envelope/test-case-primary", "A test cell is signed by its host with no inputs: trust primary "
               "(5.5, D16).", {"outcome": "ok", "receipt": R_TC_TRUE, "trust": "primary"})
valid_envelope("envelope/test-case-counterexample", "A counterexample from another host is that host's own primary "
               "statement.", {"outcome": "ok", "receipt": R_TC_FALSE, "trust": "primary"})
envelope("invalid/envelope-test-case-computed", "A test cell is not `computed`: the host signs it with no inputs, so "
         "it is primary (D16).", {"outcome": "ok", "receipt": R_TC_TRUE, "trust": "computed"}, 200, "E_ENVELOPE")

# ---------------------------------------------------------------------------
# S3: describe: `publisher` (16.8), optional, additive.

ANSWER, HELD, FUNCTION_ANSWER, TESTS, RELAY = g60.ANSWER, g60.HELD, g60.FUNCTION_ANSWER, g60.TESTS, g60.RELAY
CLASS_NAME = ANSWER["class"]
assert CLASS_NAME == "rates.example.org/fx_pair"


def describe(id_, why, doc, error=None, **extra):
    add(id_, "describe", why, doc if isinstance(doc, str) else text(doc), error, classes=HELD, **extra)


def renamed_class(name):
    out = dict(ANSWER, **{"class": name})
    out["methods"] = {m: dict(e, fn=f"{name}/{m}") for m, e in ANSWER["methods"].items()}
    return out


describe("describe/class-publisher", "A class answer with publisher: the host of its namespace (16.8).",
         dict(ANSWER, publisher="rates.example.org"))
describe("describe/class-without-publisher", "publisher is optional: an answer without it, as every answer of "
         "spec-0.6.0, still passes.", ANSWER)
describe("describe/class-dns-segment-publisher", "A class under a namespace with a DNS segment: the publisher is the "
         "host, rates.example.org, not the domain inside the name.",
         dict(renamed_class("rates.example.org/relay/ecb.europa.eu/fx_pair"), publisher="rates.example.org"))
describe("describe/class-dns-segment-without-publisher", "The same without publisher: the class name with a DNS "
         "segment is valid by itself.", renamed_class("rates.example.org/relay/ecb.europa.eu/fx_pair"))
RELAY_FN_ANSWER = dict(FUNCTION_ANSWER, fn=RELAY_FN.replace("datumesh.com", "rates.example.org"),
                       source={"name": "ecb.europa.eu", "relayed_by": "rates.example.org",
                               "takeover": "https://ecb.europa.eu/publish/takeover"})
describe("describe/function-publisher", "A function answer with publisher.",
         dict(FUNCTION_ANSWER, publisher="rates.example.org"), functions=[FX])
describe("describe/function-without-publisher", "A function answer without publisher passes as before.",
         FUNCTION_ANSWER, functions=[FX])
describe("describe/function-relay-publisher-source", "A relayed function: publisher is the host, rates.example.org, and "
         "source.name is the domain the values came from, ecb.europa.eu, which is also inside the function's name. "
         "They are separate members, and the domain in the name is never the publisher.",
         dict(RELAY_FN_ANSWER, publisher="rates.example.org"), functions=[FX])
describe("describe/function-relay-without-publisher", "The same without publisher: a name with a DNS segment is valid.",
         RELAY_FN_ANSWER, functions=[FX])
describe("describe/function-counterexamples", "tests.counterexamples is a count of this mesh's failing tests and of "
         "the false test_case cells it holds for the hash, from any host (7.3). A client reads four integers; the "
         "number is the mesh's statement.", dict(FUNCTION_ANSWER, publisher="rates.example.org",
                                                  tests=dict(TESTS, counterexamples=2)), functions=[FX])
describe("invalid/describe-publisher-is-segment", "publisher is the host of the name's namespace: the domain of a "
         "later segment is not.", dict(RELAY_FN_ANSWER, publisher="ecb.europa.eu"), "E_DESCRIBE", functions=[FX])
describe("invalid/describe-publisher-other-host", "publisher is the host of fn: another host is E_DESCRIBE.",
         dict(FUNCTION_ANSWER, publisher="calc.example.net"), "E_DESCRIBE", functions=[FX])
describe("invalid/describe-publisher-namespace", "publisher is a host, a DNS name (2.1): a namespace with a path is "
         "not.", dict(RELAY_FN_ANSWER, publisher="rates.example.org/relay"), "E_DESCRIBE", functions=[FX])
describe("invalid/describe-publisher-uppercase", "publisher is lowercase.",
         dict(FUNCTION_ANSWER, publisher="Rates.example.org"), "E_DESCRIBE", functions=[FX])
describe("invalid/describe-publisher-not-string", "publisher is a string.",
         dict(FUNCTION_ANSWER, publisher=7), "E_DESCRIBE", functions=[FX])
describe("invalid/describe-class-publisher-segment", "A class answer's publisher is the host of its name: not the "
         "domain of a later segment.",
         dict(renamed_class("rates.example.org/relay/ecb.europa.eu/fx_pair"), publisher="ecb.europa.eu"), "E_DESCRIBE")
describe("invalid/describe-class-publisher-other-host", "A class answer's publisher is the host of its name.",
         dict(ANSWER, publisher="calc.example.net"), "E_DESCRIBE")
describe("invalid/describe-object-publisher", "An object answer has no publisher: only class and function answers do.",
         dict(gv.CW_OBJECT_ANSWER, publisher="scripture.example.org"), "E_DESCRIBE")
describe("invalid/describe-function-name-uppercase-segment", "A function answer's fn is a function name (2.3): an "
         "uppercase DNS segment is not.", dict(RELAY_FN_ANSWER, fn="rates.example.org/relay/ECB.europa.eu/fx_reference"),
         "E_DESCRIBE")
describe("invalid/describe-function-name-dns-last", "A function answer's fn ends with a name: a DNS name as the last "
         "segment is not valid.", dict(RELAY_FN_ANSWER, fn="rates.example.org/relay/ecb.europa.eu"), "E_DESCRIBE")


def main():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for vec in VECTORS:
        if vec["kind"] == "formula-eval" and not any(f in vec for f in ("value", "receipt_hash")):
            raise SystemExit(f"{vec['id']}: no computed outputs yet (generate_061_eval.py)")
        path = OUT / f"{vec['id']}.json"
        if path.exists():
            existing = json.loads(path.read_text(encoding="utf-8"))
            assert existing == vec, f"{vec['id']} would overwrite a different vector"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(vec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    valid = sum(v["valid"] for v in VECTORS)
    print(f"wrote {len(VECTORS)} vectors ({valid} valid, {len(VECTORS) - valid} invalid)")


if __name__ == "__main__":
    main()
