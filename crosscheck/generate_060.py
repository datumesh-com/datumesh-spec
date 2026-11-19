#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""spec-0.6.0 vectors (SPEC.md section 11 vector format), written tests-first.

The vectors are built from the same fixtures and keys as tools/gen_vectors.py (it is imported, never
run: nothing it writes is touched) and signed with the same vector keys. Unlike gen_vectors.py this
generator does not ask tools/canon.py for a valid vector's outputs: the rules are new, so the
reference tools do not know them yet. The expected outputs of a valid vector are computed here from
the pure helpers of canon.py (JCS, SHA-256, the receipt payload) or written by hand, and the expected
code of an invalid one is stated by hand, from the contract (CONTRACT-build2-part1-spec.md C2, C3, C5,
C6, C7). The reference tools must then be made to agree with them.

Only new files are written under vectors/. Every existing vector stays byte for byte as it is.

    python3 crosscheck/generate_060.py            # write the vectors
    python3 -c "import generate_060"              # (from crosscheck/) build them in memory: VECTORS

Codes the contract leaves to inference, each inferred from the SPEC's existing code rules:
- a request token that is a digit-led word where a number is expected is E_CANON_TYPE (C3 says so);
- `2024-03-15x` is E_PARSE_URI (C3 says so);
- a describe answer's faults are all E_DESCRIBE (C7);
- an envelope fault in a scenario, a cycle or the trust value is E_ENVELOPE (C2, C5, C6);
- a whatif endpoint with a placeholder is E_MESH_DOC: 9.6's rule that a template holds only the
  placeholders of its endpoint, and whatif has none (C5: "no placeholders").
"""

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "tools")]
import canon  # noqa: E402
import gen_vectors as gv  # noqa: E402  (the fixtures and keys; its main() is not run)

OUT = ROOT / "vectors"
VECTORS = []


def add(id_, kind, description, input=None, error=None, **extra):
    vec = {"id": id_, "kind": kind, "description": "spec-0.6.0: " + description, "valid": error is None}
    if input is not None:
        vec["input"] = input
    vec.update(extra)
    if error is not None:
        vec["error"] = error
    VECTORS.append(vec)


S, N, D = gv.S, gv.N, gv.D
text = gv.text
ASOF = gv.ASOF
FX_CELL, FX_HASH, FX = gv.FX_CELL, gv.FX_HASH, gv.FX
GBP_CELL = gv.GBP_CELL
cell_id = gv.cell_id

# ---------------------------------------------------------------------------
# receipt: source (C2). Stored receipts signed by the publisher's own key (rates-2020).

SRC_BYTES = b"example fetched bytes, invented for a test vector"
SRC = {"name": "bank.example.com", "url": "https://bank.example.com/reference/rates.xml",
       "retrieved": "2024-03-15T15:30:00.000000Z", "sha256": hashlib.sha256(SRC_BYTES).hexdigest(),
       "takeover": "https://bank.example.com/publish/takeover"}
SRC_REQUIRED = {k: SRC[k] for k in ("name", "retrieved", "url")}
SUMMARY = "1 EUR was worth 1.0892 USD at the 15 March 2024 reference rate, relayed from bank.example.com."


def src_receipt(source, summary=SUMMARY, key="rates-2020", cell=FX_CELL, inputs=(), **kw):
    r = gv.receipt(cell, "number", "1.0892", summary, key, inputs=inputs, **kw)
    if source is not None:
        r["source"] = source
    return gv.signed(r, key)


def valid_receipt(id_, why, r, recompute=None):
    payload = canon.receipt_payload(r)
    extra = {"keypair": gv.keypair_fields("rates-2020"), "keys": gv.KEYENV}
    if recompute is not None:
        extra["recompute"] = recompute
    add(id_, "receipt", why, text(r), canonical=payload.decode(), sha256=canon.sha256_hex(payload), sig=r["sig"],
        level="recomputed" if recompute else "signed", **extra)


def invalid_receipt(id_, why, r, error, key="rates-2020"):
    add(id_, "receipt", why, text(r), error, keypair=gv.keypair_fields(key), keys=gv.KEYENV)


R_RELAYED = src_receipt(SRC)
R_RELAYED_MIN = src_receipt(SRC_REQUIRED, summary="The same cell, relayed with the three required members of source.")
valid_receipt("receipt/relayed-full", "A stored receipt with source, all five members: the publisher signs a value "
              "taken from bank.example.com (8.1). Verification does not fetch the url.", R_RELAYED,
              recompute={"descriptor": FX, "inputs": {}, "value": N("1.0892")})
valid_receipt("receipt/relayed-required", "A stored receipt whose source has only name, retrieved and url.",
              R_RELAYED_MIN)

# A computed receipt (calc.example.net) with inputs: source is E_SCHEMA there.
R_WITH_INPUTS = gv.signed(dict(gv.receipt(gv.convert_cell, "number", "108.92", "A computed cell that claims a source.",
                                          "calc-2020", inputs=[gv.H_FX], issued="2024-03-16T09:00:01.250000Z"),
                               source=SRC), "calc-2020")
invalid_receipt("invalid/receipt-source-with-inputs", "source is allowed only when inputs is empty (a stored receipt).",
                R_WITH_INPUTS, "E_SCHEMA", key="calc-2020")
invalid_receipt("invalid/receipt-source-extra-member", "source has exactly name, url, retrieved and, optionally, "
                "sha256 and takeover: no other member.", src_receipt(dict(SRC, origin="the bank")), "E_SCHEMA")
invalid_receipt("invalid/receipt-source-missing-retrieved", "retrieved is required.",
                src_receipt({k: v for k, v in SRC.items() if k != "retrieved"}), "E_SCHEMA")
invalid_receipt("invalid/receipt-source-missing-url", "url is required.",
                src_receipt({k: v for k, v in SRC.items() if k != "url"}), "E_SCHEMA")
invalid_receipt("invalid/receipt-source-name-is-publisher", "A publisher does not relay itself: name is not the host "
                "of cell.ns (E_SCHEMA).", src_receipt(dict(SRC, name="rates.example.org")), "E_SCHEMA")
invalid_receipt("invalid/receipt-source-name-bad", "name is a DNS name (2.1): uppercase is not.",
                src_receipt(dict(SRC, name="Bank.Example.com")), "E_CANON_NAME")
invalid_receipt("invalid/receipt-source-retrieved-bad", "retrieved is an instant with six fractional digits and Z.",
                src_receipt(dict(SRC, retrieved="2024-03-15T15:30:00Z")), "E_CANON_INSTANT")
invalid_receipt("invalid/receipt-source-sha256-uppercase", "sha256 is lowercase hex.",
                src_receipt(dict(SRC, sha256=SRC["sha256"].upper())), "E_CANON_HEX")
invalid_receipt("invalid/receipt-source-sha256-short", "sha256 is 64 hex digits.",
                src_receipt(dict(SRC, sha256=SRC["sha256"][:63])), "E_CANON_HEX")
invalid_receipt("invalid/receipt-source-url-http", "url is https:// (the licence URL rule).",
                src_receipt(dict(SRC, url="http://bank.example.com/reference/rates.xml")), "E_CANON_LICENCE")
invalid_receipt("invalid/receipt-source-url-non-ascii", "url is printable ASCII.",
                src_receipt(dict(SRC, url="https://bank.example.com/réf")), "E_CANON_LICENCE")
LONG_URL = "https://bank.example.com/" + "a" * (513 - len("https://bank.example.com/"))
assert len(LONG_URL) == 513
invalid_receipt("invalid/receipt-source-url-too-long", "url is at most 512 characters; this one has 513.",
                src_receipt(dict(SRC, url=LONG_URL)), "E_CANON_LIMIT")
invalid_receipt("invalid/receipt-source-takeover-bad", "takeover is an https:// URL by the same rule.",
                src_receipt(dict(SRC, takeover="ftp://bank.example.com/publish")), "E_CANON_LICENCE")
invalid_receipt("invalid/receipt-source-retrieved-after-issued", "retrieved <= issued (8.2): this one was retrieved "
                "an hour after the receipt was issued.",
                src_receipt(dict(SRC, retrieved="2024-03-16T10:00:00.000000Z")), "E_TIME_ORDER")

# ---------------------------------------------------------------------------
# envelope: relayed (C2), scenario (C5), cycle (C6)


def envelope(id_, why, env, status, error=None, request=None, **extra):
    if request is None:
        cell = env["receipt"]["cell"] if env and isinstance(env.get("receipt"), dict) else FX_CELL
        request = {"asof": ASOF, "cell_id": cell_id(cell)}
    add(id_, "envelope", why, text(env), error, status=status, keys=gv.ALL_KEYS, request=request, **extra)


def valid_envelope(id_, why, env, status, request=None):
    out = {"outcome": env["outcome"]}
    if "receipt" in env:
        out |= {"trust": env["trust"], "receipt_hash": canon.receipt_hash(env["receipt"])}
    envelope(id_, why, env, status, request=request, **out)


valid_envelope("envelope/relayed", "A stored receipt with source, signed by its publisher's host: trust is relayed "
               "(5.5).", {"outcome": "ok", "receipt": R_RELAYED, "trust": "relayed"}, 200)
envelope("invalid/envelope-trust-primary-with-source", "primary requires a receipt with no source: with source the "
         "trust is relayed.", {"outcome": "ok", "receipt": R_RELAYED, "trust": "primary"}, 200, "E_ENVELOPE")
envelope("invalid/envelope-trust-relayed-without-source", "relayed requires source: a plain stored receipt is primary.",
         {"outcome": "ok", "receipt": gv.R_FX, "trust": "relayed"}, 200, "E_ENVELOPE")
envelope("invalid/envelope-trust-relayed-mirror", "relayed needs the signer to be the host of cell.ns: a mirror that "
         "signed a receipt with source is not relayed.",
         {"outcome": "ok", "receipt": gv.signed(dict(gv.receipt(FX_CELL, "number", "1.0892", "A mirror's receipt.",
                                                              "calc-2020"), source=SRC), "calc-2020"),
          "trust": "relayed"}, 200, "E_ENVELOPE")

# The scenario outcome. Requested: the computed cell convert(100 EUR -> USD, 2024-03-15).
CONVERT_CELL = gv.convert_cell
FX_18 = FX_CELL | {"args": FX_CELL["args"] | {"date": D("2024-03-18")}}
SLICE_FX = FX_CELL | {"args": FX_CELL["args"] | {"date": "*"}}


def by_id(items, key=None):
    return sorted(items, key=lambda x: cell_id(x[key] if key else x))


def value_override(cell, value):
    return {"cell": cell, "value": N(value)}


OV_FX, OV_GBP = value_override(FX_CELL, "1.2"), value_override(GBP_CELL, "0.9")
OV_TWO = by_id([OV_FX, OV_GBP], "cell")
OV_SLICE = {"add": [{"cell": FX_18, "value": N("1.2")}], "remove": [FX_CELL], "slice": SLICE_FX}


def scenario(cell, value, overrides, **extra):
    return {"outcome": "scenario", "scenario": {"asof": ASOF, "cell": cell, "overrides": overrides, "type": "number",
                                                 "value": value, **extra}}


def whatif_request(cell, overrides, **extra):
    return {"asof": ASOF, "cell_id": cell_id(cell), "overrides": overrides, **extra}


valid_envelope("envelope/scenario-value-override", "A scenario with two value overrides, sorted by cell id: never a "
               "fact, so no receipt and no trust (5.9).",
               scenario(CONVERT_CELL, "120", OV_TWO), 200, whatif_request(CONVERT_CELL, OV_TWO))
valid_envelope("envelope/scenario-slice-override", "A scenario with a slice override: a member added, another "
               "removed; the cell asked is the added one, which answers its override value.",
               scenario(FX_18, "1.2", [OV_SLICE]), 200, whatif_request(FX_18, [OV_SLICE]))
SOLVED = {"value": N("1.2"), "vary": FX_CELL}
valid_envelope("envelope/scenario-solved", "A scenario with solve: solved states the value of vary found, and value "
               "is the target's value under it. The request description carries solve, the vary cell id.",
               scenario(CONVERT_CELL, "120", [], solved=SOLVED), 200,
               whatif_request(CONVERT_CELL, [], solve=cell_id(FX_CELL)))
valid_envelope("envelope/scenario-no-asof-sent", "No asof was sent: the scenario's asof is the mesh's now, any "
               "instant.", scenario(CONVERT_CELL, "120", [OV_FX]), 200,
               {"cell_id": cell_id(CONVERT_CELL), "overrides": [OV_FX]})
valid_envelope("envelope/scenario-not-covered", "not_covered is an answer at whatif (a name unbound, a fault): "
               "allowed with overrides in the request.",
               {"outcome": "not_covered"}, 404, whatif_request(CONVERT_CELL, [OV_FX]))

for name, why, env, request in [
    ("wrong-cell", "scenario.cell is not the requested cell.", scenario(GBP_CELL, "120", OV_TWO),
     whatif_request(CONVERT_CELL, OV_TWO)),
    ("wrong-asof", "scenario.asof is not the asof requested.",
     {"outcome": "scenario", "scenario": dict(scenario(CONVERT_CELL, "120", OV_TWO)["scenario"],
                                              asof="2024-03-17T09:00:00.000000Z")},
     whatif_request(CONVERT_CELL, OV_TWO)),
    ("wrong-overrides", "scenario.overrides is not the request's overrides: a value differs.",
     scenario(CONVERT_CELL, "120", by_id([value_override(FX_CELL, "1.3"), OV_GBP], "cell")),
     whatif_request(CONVERT_CELL, OV_TWO)),
    ("unsorted-overrides", "scenario.overrides is the request's overrides in another order: overrides are sorted by "
     "cell or slice id.", scenario(CONVERT_CELL, "120", OV_TWO[::-1]), whatif_request(CONVERT_CELL, OV_TWO)),
    ("no-overrides-in-request", "A scenario answers a request with overrides: this request has none.",
     scenario(CONVERT_CELL, "120", []), {"asof": ASOF, "cell_id": cell_id(CONVERT_CELL)}),
    ("solved-missing", "solve was sent, so solved is present.", scenario(CONVERT_CELL, "120", []),
     whatif_request(CONVERT_CELL, [], solve=cell_id(FX_CELL))),
    ("solved-unrequested", "solved is present exactly when the request had solve.",
     scenario(CONVERT_CELL, "120", OV_TWO, solved=SOLVED), whatif_request(CONVERT_CELL, OV_TWO)),
    ("solved-wrong-vary", "solved.vary has the id of the cell the request said to vary.",
     scenario(CONVERT_CELL, "120", [], solved={"value": N("1.2"), "vary": GBP_CELL}),
     whatif_request(CONVERT_CELL, [], solve=cell_id(FX_CELL))),
    ("extra-member", "scenario has exactly cell, type, value, asof, overrides and solved: no other member.",
     scenario(CONVERT_CELL, "120", OV_TWO, note="a what-if"), whatif_request(CONVERT_CELL, OV_TWO)),
    ("missing-member", "scenario has overrides, always: here it is missing.",
     {"outcome": "scenario", "scenario": {k: v for k, v in scenario(CONVERT_CELL, "120", OV_TWO)["scenario"].items()
                                          if k != "overrides"}}, whatif_request(CONVERT_CELL, OV_TWO)),
]:
    envelope(f"invalid/envelope-scenario-{name}", why, env, 200, "E_ENVELOPE", request=request)
envelope("invalid/envelope-ok-with-overrides", "With overrides in the request, ok is not an answer: a scenario is "
         "never served as the cell's receipt.", {"outcome": "ok", "receipt": gv.R_FX, "trust": "primary"}, 200,
         "E_ENVELOPE", request=whatif_request(FX_CELL, [OV_GBP]))
envelope("invalid/envelope-stale-with-overrides", "stale is not an answer at whatif either.",
         {"age_seconds": 60, "outcome": "stale", "receipt": gv.R_FX, "trust": "primary"}, 200, "E_ENVELOPE",
         request=whatif_request(FX_CELL, [OV_GBP]))
envelope("invalid/envelope-scenario-status", "scenario is HTTP 200.", scenario(CONVERT_CELL, "120", OV_TWO), 202,
         "E_ENVELOPE", request=whatif_request(CONVERT_CELL, OV_TWO))

# cycle (C6): an E_EVAL_UNAVAILABLE error names its path.
CYC_A = 'calc.example.net/budget(month: 2024-03-01, unit: "ops")'
CYC_B = 'calc.example.net/forecast(month: 2024-03-01, unit: "ops")'
CYC_REQUEST = {"asof": ASOF, "cell_id": cell_id(CONVERT_CELL)}


def cycle_env(path, fixes, error="E_EVAL_UNAVAILABLE", **kw):
    return {"cycle": {"fixes": fixes, "path": path} | kw, "error": error, "outcome": "error"}


valid_envelope("envelope/error-cycle", "An error envelope with E_EVAL_UNAVAILABLE names the cycle: the cell that "
               "reappeared and the reads between (5.5).", cycle_env([CYC_A, CYC_B, CYC_A], ["asof", "lag"]), 503,
               CYC_REQUEST)
valid_envelope("envelope/error-cycle-all-fixes", "All four fixes, in the order asof, lag, step, solver.",
               cycle_env([CYC_A, CYC_B, CYC_A], ["asof", "lag", "step", "solver"]), 503, CYC_REQUEST)
valid_envelope("envelope/error-cycle-self", "A cell that reads itself: the shortest path has two calls, equal.",
               cycle_env([CYC_A, CYC_A], ["step"]), 503, CYC_REQUEST)
for name, why, env in [
    ("path-ends-differ", "The path's first and last calls are equal: the cell that reappeared.",
     cycle_env([CYC_A, CYC_B, CYC_B], ["asof"])),
    ("path-of-one", "The path has at least 2 calls.", cycle_env([CYC_A], ["asof"])),
    ("path-empty", "An empty path is not a path.", cycle_env([], ["asof"])),
    ("path-not-string", "Each call of the path is a string.", cycle_env([CYC_A, 7, CYC_A], ["asof"])),
    ("fix-unknown", "A fix is one of asof, lag, step and solver.", cycle_env([CYC_A, CYC_B, CYC_A], ["asof", "wait"])),
    ("fixes-unordered", "fixes are in the order asof, lag, step, solver.",
     cycle_env([CYC_A, CYC_B, CYC_A], ["lag", "asof"])),
    ("fixes-duplicate", "fixes are distinct.", cycle_env([CYC_A, CYC_B, CYC_A], ["asof", "asof"])),
    ("fixes-empty", "fixes is non-empty.", cycle_env([CYC_A, CYC_B, CYC_A], [])),
    ("other-code", "cycle is allowed only with E_EVAL_UNAVAILABLE.",
     cycle_env([CYC_A, CYC_B, CYC_A], ["asof"], error="E_INPUT_UNAVAILABLE")),
    ("extra-member", "cycle has exactly path and fixes.", cycle_env([CYC_A, CYC_B, CYC_A], ["asof"], note="x")),
    ("not-error", "cycle belongs to an error envelope.",
     {"cycle": {"fixes": ["asof"], "path": [CYC_A, CYC_B, CYC_A]}, "outcome": "not_covered"}),
]:
    envelope(f"invalid/envelope-cycle-{name}", why, env, 404 if env["outcome"] == "not_covered" else 503, "E_ENVELOPE",
             request=CYC_REQUEST)

# ---------------------------------------------------------------------------
# call: digit-led words in a request (C3)

VERSE = {"code": {"body": "", "lang": "stored"}, "inputs": [],
         "signature": {"args": {"book": {"type": "string", "valid": False},
                                "chapter": {"type": "number", "unit": "1", "valid": False},
                                "corpus": {"type": "string", "valid": False},
                                "verse": {"type": "number", "unit": "1", "valid": False}},
                       "order": ["corpus", "book", "chapter", "verse"], "returns": "string"}}
VERSE_NAME = "datumesh.example.org/verse"
VERSE_ENV = {"aliases": {}, "functions": {VERSE_NAME: VERSE}}


def uri_of(book):
    """The URI of verse("bible", book, 1, 1): what the unquoted spelling must give (C3)."""
    got = canon.parse_call(f'{VERSE_NAME}("bible", "{book}", 1, 1)', VERSE_ENV)
    return got["uri"]


for name, book, why in [
    ("digit-led-2chr", "2Chr", "2Chr is a digit-led word: in a string position it is the string \"2Chr\" (5.8)."),
    ("digit-led-1cor", "1Cor", "1Cor is a digit-led word."),
    ("digit-led-3john", "3John", "3John is a digit-led word."),
    ("digit-led-underscore", "1_kings", "A digit-led word may continue with underscores."),
    ("period-token-as-string", "2D", "2D stays a period token; in a string position it is the string \"2D\"."),
    ("number-token-as-string", "1e3", "1e3 is not a number (L5) and no digit-led word is rejected here: in a string "
     "position it is the string \"1e3\"."),
]:
    add(f"call/{name}", "call", why, f"{VERSE_NAME}(bible, {book}, 1, 1)", env=VERSE_ENV, uri=uri_of(book))
add("call/digit-led-labelled", "call", "A digit-led word as a labelled string argument.",
    f"{VERSE_NAME}(book: 2Chr, chapter: 1, corpus: bible, verse: 1)", env=VERSE_ENV, uri=uri_of("2Chr"))
add("call/digit-led-quoted-same", "call", "Quoted or unquoted, the call is the same: nothing that parsed before "
    "changes.", f'{VERSE_NAME}("bible", "2Chr", 1, 1)', env=VERSE_ENV, uri=uri_of("2Chr"))
for name, call, error, why in [
    ("digit-led-number-position", f"{VERSE_NAME}(bible, John, 1Cor, 1)", "E_CANON_TYPE",
     "A digit-led word is a value only in a string position: chapter is a number."),
    ("digit-led-number-labelled", f"{VERSE_NAME}(bible, John, chapter: 2Chr, verse: 1)", "E_CANON_TYPE",
     "The same, labelled."),
    ("date-with-suffix", f"{VERSE_NAME}(bible, 2024-03-15x, 1, 1)", "E_PARSE_URI",
     "A run such as 2024-03-15x is still E_PARSE_URI: the date lexer does not accept the whole run, and it is not a "
     "digit-led word (it holds a hyphen)."),
]:
    add(f"invalid/call-{name}", "call", why, call, error, env=VERSE_ENV)

# ---------------------------------------------------------------------------
# describe: tests, source, the function answer (C7)

TESTS = {"branches": 4, "count": 7, "counterexamples": 0, "covered": 3}
RELAY = {"name": "bank.example.com", "relayed_by": "rates.example.org",
         "takeover": "https://bank.example.com/publish/takeover"}
ANSWER = gv.CW_CLASS_ANSWER
HELD = gv.CW_HELD


def with_method(m, **change):
    return gv.cw_method(ANSWER, m, **change)


FUNCTION_ANSWER = {"args": FX["signature"]["args"], "description": "The reference rate: units of quote per unit of base.",
                   "fn": "rates.example.org/fx_rate", "fn_hash": FX_HASH, "kind": "function",
                   "returns": FX["signature"]["returns"]}


def describe(id_, why, doc, error=None, **extra):
    add(id_, "describe", why, doc if isinstance(doc, str) else text(doc), error, classes=HELD, **extra)


describe("describe/class-tests-source", "A class answer whose rate method has tests and a relayed source (16.8).",
         with_method("rate", tests=TESTS, source=RELAY))
describe("describe/class-tests-zero", "tests of zero: no test is held, none covers a branch.",
         with_method("rate", tests={"branches": 0, "count": 0, "counterexamples": 0, "covered": 0}))
describe("invalid/describe-tests-covered-over-branches", "covered is at most branches.",
         with_method("rate", tests=dict(TESTS, covered=5)), "E_DESCRIBE")
describe("invalid/describe-tests-missing-member", "tests has all four members.",
         with_method("rate", tests={"branches": 4, "count": 7, "covered": 3}), "E_DESCRIBE")
describe("invalid/describe-tests-extra-member", "tests has exactly four members.",
         with_method("rate", tests=dict(TESTS, failing=1)), "E_DESCRIBE")
describe("invalid/describe-tests-negative", "A count is a non-negative integer.",
         with_method("rate", tests=dict(TESTS, counterexamples=-1)), "E_DESCRIBE")
describe("invalid/describe-source-missing-takeover", "source has name, relayed_by and takeover, all required.",
         with_method("rate", source={k: v for k, v in RELAY.items() if k != "takeover"}), "E_DESCRIBE")
describe("invalid/describe-source-takeover-http", "takeover is an https URL.",
         with_method("rate", source=dict(RELAY, takeover="http://bank.example.com/publish")), "E_DESCRIBE")
describe("invalid/describe-source-name-bad", "name is a DNS name.",
         with_method("rate", source=dict(RELAY, name="Bank")), "E_DESCRIBE")

describe("describe/function-not-held", "A function answer: kind function, fn, fn_hash, args and returns, with the "
         "descriptor not held: its shape only.", FUNCTION_ANSWER)
describe("describe/function-held", "The same with the descriptor of fn_hash held: args and returns are its "
         "signature's, all the arguments.", FUNCTION_ANSWER, functions=[FX])
describe("describe/function-tests-source", "A function answer with tests and a relayed source.",
         dict(FUNCTION_ANSWER, source=RELAY, tests=TESTS), functions=[FX])
describe("describe/function-minimal", "description, tests and source are optional.",
         {k: v for k, v in FUNCTION_ANSWER.items() if k != "description"})
describe("invalid/describe-function-args-differ", "With the descriptor held, args are its signature's: a missing "
         "argument fails.", dict(FUNCTION_ANSWER, args={k: v for k, v in FX["signature"]["args"].items()
                                                         if k != "quote"}), "E_DESCRIBE", functions=[FX])
describe("invalid/describe-function-returns-differ", "With the descriptor held, returns is its signature's.",
         dict(FUNCTION_ANSWER, returns={"type": "number", "unit": "1"}), "E_DESCRIBE", functions=[FX])
describe("invalid/describe-function-extra-member", "A function answer has exactly the listed members.",
         dict(FUNCTION_ANSWER, class_hash="0" * 64), "E_DESCRIBE")
describe("invalid/describe-function-missing-returns", "returns is required.",
         {k: v for k, v in FUNCTION_ANSWER.items() if k != "returns"}, "E_DESCRIBE")
describe("invalid/describe-function-hash-uppercase", "fn_hash is 64 lowercase hex digits.",
         dict(FUNCTION_ANSWER, fn_hash=FX_HASH.upper()), "E_DESCRIBE")
describe("invalid/describe-function-name", "fn is a function name (2.3): a bare name is not.",
         dict(FUNCTION_ANSWER, fn="fx_rate"), "E_DESCRIBE")
describe("invalid/describe-function-description-empty", "A description is 1 to 1024 bytes.",
         dict(FUNCTION_ANSWER, description=""), "E_DESCRIBE")

_one = text(dict(FUNCTION_ANSWER, tests=dict(TESTS, count=1)))
assert _one.count('"count": 1\n') == 1 or _one.count('"count": 1,') == 1
describe("invalid/describe-tests-count-decimal", "An integer written 1.0 is not an integer (5.5's integer rule).",
         _one.replace('"count": 1,', '"count": 1.0,').replace('"count": 1\n', '"count": 1.0\n'), "E_DESCRIBE")
describe("invalid/describe-tests-count-exponent", "An integer written 1e0 is not an integer either.",
         _one.replace('"count": 1,', '"count": 1e0,').replace('"count": 1\n', '"count": 1e0\n'), "E_DESCRIBE")

# ---------------------------------------------------------------------------
# mesh: the whatif endpoint (C5)

WHATIF = f"{gv.MB}/whatif"
WHATIF_ENDPOINTS = canon.resolve_mesh(gv.MESH_HOST, gv.mesh_env())["endpoints"] | {"whatif": WHATIF}
add("mesh/whatif", "mesh", "A mesh document with a whatif endpoint, which has no placeholders (9.6).",
    host=gv.MESH_HOST, env=gv.mesh_env(gv.mesh_doc({"whatif": WHATIF})), bindings=f"{gv.MB}/bindings",
    endpoints=WHATIF_ENDPOINTS)
REQ_PLUS = {k: v for k, v in gv.MESH_ENDPOINTS.items() if k in canon.MESH_REQUIRED} | {"whatif": WHATIF}
add("mesh/whatif-required-only", "mesh", "whatif is optional and may come with the required endpoints only.",
    host=gv.MESH_HOST, env=gv.mesh_env(gv.mesh_doc() | {"endpoints": REQ_PLUS}), bindings=f"{gv.MB}/bindings",
    endpoints=REQ_PLUS)
add("invalid/mesh-whatif-placeholder", "mesh", "whatif has no placeholders: a {cell} in it fails.",
    host=gv.MESH_HOST, env=gv.mesh_env(gv.mesh_doc({"whatif": f"{WHATIF}/{{cell}}"})), error="E_MESH_DOC")
add("invalid/mesh-whatif-lone-brace", "mesh", "Every brace of a template belongs to one of its placeholders.",
    host=gv.MESH_HOST, env=gv.mesh_env(gv.mesh_doc({"whatif": f"{WHATIF}}}"})), error="E_MESH_DOC")
add("invalid/mesh-whatif-other-host", "mesh", "whatif is a URL on the mesh's host, like every endpoint.",
    host=gv.MESH_HOST, env=gv.mesh_env(gv.mesh_doc({"whatif": "https://other.example.org/whatif"})),
    error="E_MESH_DOC")


def main():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for vec in VECTORS:
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
