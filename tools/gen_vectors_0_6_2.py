#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""spec-0.6.2 vectors (SPEC.md section 11 vector format), written tests-first.

spec-0.6.2 (CONTRACT-spec-0.6.2.md, P1-P4): `shares` and `pure` and money per share (units.md, 7.1);
`last_by` and `first_by` (15.7, 15.13); the named `test_case` convention (7.3); the `public:` licence
(8.1, 8.5, 10.3).

Like crosscheck/generate_061.py this builds the vectors from the fixtures and keys of tools/gen_vectors.py
(imported, never run) and signs with the same vector keys (rates-2020, calc-2020; `data.example.org` for
the stored cells of the formula-eval vectors, as formula.stored_receipt does). Nothing here depends on a
new check of the reference tools: canonical bytes, hashes, signatures and receipt hashes come from the
pure helpers of canon.py (JCS, SHA-256, the receipt payload), and every expected code and value is stated
by hand from the text of the contract. The only outputs that need an evaluator are those of the
`formula-eval` vectors for `last_by` and `first_by` (receipt hash, lineage, fuel): they are in EVAL_OUTPUT,
taken once from a scratch copy of the 0.6.1 reference with the two built-ins added (the committed tools of
spec-0.6.2 must reproduce them: tests/test_spec_0_6_2.py), and each value was also worked by hand (see
the comments at each vector).

Only new files are written under vectors/. Every existing vector stays byte for byte as it is.

    python3 tools/gen_vectors_0_6_2.py            # write the vectors
    python3 -c "import gen_vectors_0_6_2"         # (from tools/) build them in memory: VECTORS
"""

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))
import canon  # noqa: E402
import gen_formula as gf  # noqa: E402  (the formula fixtures; nothing is run)
import gen_vectors as gv  # noqa: E402  (the fixtures and keys; its main() is not run)

OUT = ROOT / "vectors"
VECTORS = []


def add(id_, kind, description, input=None, error=None, **extra):
    vec = {"id": id_, "kind": kind, "description": "spec-0.6.2: " + description, "valid": error is None}
    if input is not None:
        vec["input"] = input
    vec.update(extra)
    if error is not None:
        vec["error"] = error
    VECTORS.append(vec)


S, N, D = gv.S, gv.N, gv.D
text = gv.text
sha = canon.sha256_hex


def jcs_text(obj):
    return canon.jcs(obj).decode()


# ---------------------------------------------------------------------------
# P1: units (units.md, 7.1). function vectors (the descriptor) and unit vectors (resolution).

SARG = {"type": "string", "valid": False}
DARG = {"type": "date", "valid": True}


def stored(args, returns):
    return {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": {"args": args, "returns": returns}}


def NUM(unit):
    return {"type": "number", "unit": unit}


def function_vector(slug, why, desc, error=None):
    if error is None:
        add(f"function/{slug}", "function", why, text(desc), canonical=jcs_text(desc), sha256=sha(canon.jcs(desc)))
    else:
        add(f"invalid/function-{slug}", "function", why, text(desc), error)


for slug, desc, why in [
    ("unit-shares", stored({"company": SARG, "date": DARG}, NUM("shares")),
     "`shares` is a literal unit: a number of shares of the issuer's equity, as a securities filing counts them."),
    ("unit-pure", stored({"company": SARG, "date": DARG}, NUM("pure")),
     "`pure` is a literal unit: XBRL's pure number, a different string from `1`."),
    ("unit-rate-per-shares", stored({"company": SARG, "date": DARG}, NUM({"of": "USD", "per": "shares"})),
     "A rate may have `shares` on the per side: US dollars per share."),
    ("unit-rate-arg-per-shares", stored({"company": SARG, "currency": SARG, "date": DARG},
                                        NUM({"of": {"arg": "currency"}, "per": "shares"})),
     "A rate's `of` may be an argument reference while `per` is the literal `shares`."),
    ("unit-rate-arg-per-arg", stored({"company": SARG, "date": DARG, "of": SARG, "per": SARG},
                                     NUM({"of": {"arg": "of"}, "per": {"arg": "per"}})),
     "Both sides argument references: whether `per` resolves to a currency or `shares` is a question for resolution."),
    ("unit-shares-argument", stored({"count": {"type": "number", "unit": "shares", "valid": False}, "date": DARG},
                                    NUM("shares")),
     "`shares` as the unit of a number argument as well as of the return."),
    ("unit-pure-argument", stored({"ratio": {"type": "number", "unit": "pure", "valid": False}, "date": DARG},
                                  NUM("pure")),
     "`pure` as the unit of a number argument as well as of the return."),
    ("unit-argument-as-filed", stored({"concept": SARG, "date": DARG, "unit": SARG}, NUM({"arg": "unit"})),
     "The unit as filed: a whole-unit argument reference, which may now hold `USD`, `shares`, `USD/shares` or `pure`."),
]:
    function_vector(slug, why, desc)

for slug, desc, error, why in [
    ("unit-rate-of-shares", stored({"date": DARG}, NUM({"of": "shares", "per": "USD"})), "E_CANON_UNIT",
     "`shares` is allowed on the per side only: `of` is a currency code or an argument reference."),
    ("unit-rate-shares-both", stored({"date": DARG}, NUM({"of": "shares", "per": "shares"})), "E_CANON_UNIT",
     "`shares` is not a currency, so it cannot be `of` even when it is also `per`."),
    ("unit-rate-per-pure", stored({"date": DARG}, NUM({"of": "USD", "per": "pure"})), "E_CANON_UNIT",
     "`pure` is not a currency or `shares`: it cannot be a side of a rate."),
    ("unit-rate-of-pure", stored({"date": DARG}, NUM({"of": "pure", "per": "EUR"})), "E_CANON_UNIT",
     "`pure` cannot be the `of` side either."),
    ("unit-rate-per-count", stored({"date": DARG}, NUM({"of": "USD", "per": "count"})), "E_CANON_UNIT",
     "Only `shares` joins the currency codes on the per side: `count` does not."),
    ("unit-shares-per-string", stored({"date": DARG}, NUM("USD/shares")), "E_CANON_UNIT",
     "`USD/shares` as a literal string is not a unit: a rate has only the object form."),
    ("unit-shares-singular", stored({"date": DARG}, NUM("share")), "E_CANON_UNIT",
     "The plural is XBRL's spelling, kept as filed: `share` is not a unit."),
    ("unit-shares-capital", stored({"date": DARG}, NUM("Shares")), "E_CANON_UNIT",
     "Units are compared byte for byte: `Shares` is not `shares`."),
    ("unit-pure-capital", stored({"date": DARG}, NUM("Pure")), "E_CANON_UNIT",
     "Units are compared byte for byte: `Pure` is not `pure`."),
    ("unit-rate-per-index", stored({"date": DARG}, NUM({"of": "USD", "per": "index:2015=100"})), "E_CANON_UNIT",
     "An index unit is still not a side of a rate."),
]:
    function_vector(slug, why, desc, error)

# unit vectors: resolution of the unit of a cell's value (units.md 3).


def cell_of(desc, ns, fn, args):
    return {"args": args, "fn": fn, "fn_hash": canon.function_hash(desc), "ns": ns}


def unit_input(desc, cell):
    return text({"cell": cell, "descriptor": desc})


REPORTED = stored({"concept": SARG, "date": DARG, "unit": SARG}, NUM({"arg": "unit"}))


def reported_cell(unit):
    return cell_of(REPORTED, "data.example.org", "reported",
                   {"concept": S("EarningsPerShareBasic"), "date": D("2025-12-31"), "unit": S(unit)})


for slug, value, why in [
    ("usd", "USD", "A currency as filed: the unit is `USD`."),
    ("shares", "shares", "`shares` as filed: the unit is `shares`."),
    ("pure", "pure", "`pure` as filed: the unit is `pure`, not `1`."),
    ("usd-per-shares", "USD/shares", "A rate's resolved form as the argument value: `USD/shares`, money per share."),
    ("eur-per-usd", "EUR/USD", "A rate's resolved form with two currencies: `EUR/USD`."),
    ("listed-slash-literal", "m/s", "`m/s` is a listed literal, so it is a listed unit as it stands and is not split at its slash."),
    ("listed-slash-literal-kmh", "km/h", "`km/h` is a listed literal too."),
    ("percent", "percent", "A listed literal from the ratio section, as before."),
]:
    add(f"unit/arg-unit-{slug}", "unit", why, unit_input(REPORTED, reported_cell(value)), unit=value)

for slug, value, why in [
    ("two-slashes", "USD/shares/x", "Two slashes: the one place a unit string is split is at its single `/`."),
    ("empty-of", "/shares", "An empty side."),
    ("empty-per", "USD/", "An empty side."),
    ("shares-of", "shares/USD", "`shares` is not a currency, so not an `of` side."),
    ("pure-of", "pure/USD", "`pure` is not a currency, so not an `of` side."),
    ("per-pure", "USD/pure", "`pure` is not allowed on the per side."),
    ("per-count", "USD/count", "`count` is not allowed on the per side."),
    ("not-a-unit", "foo", "A value that is neither a listed literal nor a rate's resolved form."),
    ("double-slash", "USD//shares", "Two slashes, with an empty middle."),
    ("lowercase-of", "usd/shares", "Units are compared byte for byte: `usd` is not a currency code."),
    ("of-not-currency", "kWh/shares", "`kWh` is a listed unit but not a currency code, and the string is not a literal."),
    ("shares-slash-shares", "shares/shares", "`shares` is not an `of` side."),
    ("uppercase-shares", "USD/Shares", "Units are compared byte for byte: `Shares` is not `shares`."),
]:
    add(f"invalid/unit-arg-unit-{slug}", "unit", why, unit_input(REPORTED, reported_cell(value)), "E_CANON_UNIT")

RATE_SHARES = stored({"company": SARG, "date": DARG}, NUM({"of": "USD", "per": "shares"}))
add("unit/rate-literal-per-shares", "unit", "A rate with `per` the literal `shares`: `USD/shares`.",
    unit_input(RATE_SHARES, cell_of(RATE_SHARES, "data.example.org", "eps", {"company": S("0000320193"),
                                                                           "date": D("2025-12-31")})),
    unit="USD/shares")
SHARES_FN = stored({"company": SARG, "date": DARG}, NUM("shares"))
add("unit/literal-shares", "unit", "A literal `shares` resolves to itself.",
    unit_input(SHARES_FN, cell_of(SHARES_FN, "data.example.org", "outstanding", {"company": S("0000320193"),
                                                                                "date": D("2025-12-31")})),
    unit="shares")
PURE_FN = stored({"company": SARG, "date": DARG}, NUM("pure"))
add("unit/literal-pure", "unit", "A literal `pure` resolves to itself, not to `1`.",
    unit_input(PURE_FN, cell_of(PURE_FN, "data.example.org", "margin", {"company": S("0000320193"),
                                                                       "date": D("2025-12-31")})),
    unit="pure")

RATE_ARGS = stored({"date": DARG, "of": SARG, "per": SARG}, NUM({"of": {"arg": "of"}, "per": {"arg": "per"}}))


def rate_cell(of, per):
    return cell_of(RATE_ARGS, "data.example.org", "ratio", {"date": D("2025-12-31"), "of": S(of), "per": S(per)})


add("unit/rate-arg-per-shares", "unit", "Both sides argument references, `per` resolving to `shares`: `EUR/shares`.",
    unit_input(RATE_ARGS, rate_cell("EUR", "shares")), unit="EUR/shares")
add("unit/rate-arg-per-currency", "unit", "Both sides argument references resolving to currencies: `USD/EUR`.",
    unit_input(RATE_ARGS, rate_cell("USD", "EUR")), unit="USD/EUR")
for slug, of, per, why in [
    ("arg-per-pure", "USD", "pure", "A `per` reference must resolve to a currency or `shares`: `pure` is neither."),
    ("arg-of-shares", "shares", "USD", "An `of` reference must resolve to a currency: `shares` is not one."),
    ("arg-per-rate", "USD", "USD/shares", "A side of a rate is not itself a rate: `USD/shares` is not a currency or `shares`."),
    ("arg-per-count", "USD", "count", "A `per` reference may not resolve to `count`."),
    ("arg-of-rate", "USD/shares", "EUR", "An `of` reference may not resolve to a rate."),
]:
    add(f"invalid/unit-rate-{slug}", "unit", why, unit_input(RATE_ARGS, rate_cell(of, per)), "E_CANON_UNIT")


# ---------------------------------------------------------------------------
# P2: last_by and first_by (15.7, 15.13): `formula` vectors (check, parse, print) and `formula-eval` vectors.

DX = "data.example.org"
SA = {"type": "string", "valid": False}
FUNCS = {
    f"{DX}/fact": gf.stored({"accession": SA}, ["accession"], "EUR"),
    f"{DX}/revenue": gf.stored({"accession": SA, "period": DARG}, ["accession", "period"], "EUR"),
    f"{DX}/filed": gf.stored({"accession": SA}, ["accession"], "date"),
    f"{DX}/rank": gf.stored({"accession": SA}, ["accession"], "count"),
    f"{DX}/active": gf.stored({"accession": SA}, ["accession"], "boolean"),
    f"{DX}/held": gf.stored({"accession": SA, "unit": SA}, ["accession", "unit"], "EUR"),
    f"{DX}/size": gf.stored({"accession": SA, "unit": SA}, ["accession", "unit"], {"arg": "unit"}),
    f"{DX}/seq": gf.stored({"accession": {"type": "number", "unit": "1", "valid": False}}, ["accession"], "EUR"),
}
# stored() above takes returns as a unit; `filed` returns a date and `active` a boolean (gf.ret handles the names)
D_CALC = "calc.example.net/f"


def read_ast(fn, **stars):
    return {"args": {k: {"node": "open"} for k in sorted(stars)}, "fn": fn, "node": "read"}


def call_ast(fn, a, b):
    return {"args": [a, b], "fn": fn, "named": {}, "node": "call"}


def f_env(names, returns):
    return {"aliases": {}, "functions": {n: FUNCS[n] for n in sorted(names)}, "name": D_CALC,
            "signature": gf.std_sig(returns)}


def formula_vector(id_, why, source, ast, body, names, returns):
    ast_text = jcs_text(ast)
    add(id_, "formula", why, source, env=f_env(names, returns), ast=ast_text, ast_sha256=sha(ast_text.encode()),
        body=body, inputs=sorted(names), returns={"type": "number", "unit": returns}, asof_dependent=False)


def invalid_formula(id_, why, source, error, names, returns="EUR"):
    add(id_, "formula", why, source, error, env=f_env(names, returns))


FACT, FILED, REV = f"{DX}/fact", f"{DX}/filed", f"{DX}/revenue"
LB_ONE = f"last_by({FACT}(accession: *), {FILED}(accession: *))"
FACT_R, FILED_R = read_ast(FACT, accession=1), read_ast(FILED, accession=1)
REV_R = read_ast(REV, accession=1, period=1)

formula_vector("formula/last-by", "last_by of a slice and a slice that orders it: one dimension, a scalar result "
               "(15.7). The body prints both arguments positionally.", LB_ONE,
               call_ast("last_by", FACT_R, FILED_R), LB_ONE + "\n", [FACT, FILED], "EUR")
FB_ONE = f"first_by({FACT}(accession: *), {FILED}(accession: *))"
formula_vector("formula/first-by", "first_by, the same with the least by value.", FB_ONE,
               call_ast("first_by", FACT_R, FILED_R), FB_ONE + "\n", [FACT, FILED], "EUR")
LB_GROUP = f"sum(last_by({REV}(accession: *, period: *), {FILED}(accession: *)))"
formula_vector("formula/last-by-group-key", "A group key: `period` is open in the slice and not in `by`, so the "
               "result is a slice over `period`, summed.", LB_GROUP,
               {"args": [call_ast("last_by", REV_R, FILED_R)], "fn": "sum", "named": {}, "node": "call"},
               LB_GROUP + "\n", [REV, FILED], "EUR")
formula_vector("formula/last-by-labelled", "Both parameters may be given by label (15.7); the printer writes "
               "required arguments positionally, so the body is the positional form.",
               f"last_by(slice: {FACT}(accession: *), by: {FILED}(accession: *))",
               call_ast("last_by", FACT_R, FILED_R), LB_ONE + "\n", [FACT, FILED], "EUR")
formula_vector("formula/last-by-positional-star", "Positional stars in the reads: the printer writes the labelled "
               "form.", f"last_by({FACT}(*), {FILED}(*))", call_ast("last_by", FACT_R, FILED_R), LB_ONE + "\n",
               [FACT, FILED], "EUR")
formula_vector("formula/last-by-round-trip", "The printed body is itself a source that prints to itself.",
               LB_ONE + "\n", call_ast("last_by", FACT_R, FILED_R), LB_ONE + "\n", [FACT, FILED], "EUR")
formula_vector("formula/first-by-round-trip", "The same for first_by.", FB_ONE + "\n",
               call_ast("first_by", FACT_R, FILED_R), FB_ONE + "\n", [FACT, FILED], "EUR")
BOTH = f"{LB_ONE} - {FB_ONE}"
formula_vector("formula/last-by-first-by", "Both built-ins in one body: the inputs are the two functions once each.",
               f"{LB_ONE}-{FB_ONE}",
               {"args": [call_ast("last_by", FACT_R, FILED_R), call_ast("first_by", FACT_R, FILED_R)], "node": "op",
                "op": "-"}, BOTH + "\n", [FACT, FILED], "EUR")
RANK = f"{DX}/rank"
formula_vector("formula/last-by-number-by", "A by slice of numbers (a count) orders the slice.",
               f"last_by({FACT}(accession: *), {RANK}(accession: *))",
               call_ast("last_by", FACT_R, read_ast(RANK, accession=1)),
               f"last_by({FACT}(accession: *), {RANK}(accession: *))\n", [FACT, RANK], "EUR")

invalid_formula("invalid/formula-last-by-arg-not-open", "`by` has an open argument, `period`, that is not an open "
                "argument of `slice`: refused (E_FORMULA_JOIN, 15.11).",
                f"last_by({FACT}(accession: *), {REV}(accession: *, period: *))", "E_FORMULA_JOIN", [FACT, REV])
invalid_formula("invalid/formula-last-by-arg-bound", "`by` leaves `period` open while `slice` binds it: `period` is "
                "not an open argument of `slice`.",
                f"last_by({REV}(accession: *, period: 2025-12-31), {REV}(accession: *, period: *))",
                "E_FORMULA_JOIN", [REV])
invalid_formula("invalid/formula-last-by-key-type", "The open argument has the same name and a different key type in "
                "the two slices (a number in `slice`, a string in `by`): a mismatched join.",
                f"last_by({DX}/seq(accession: *), {FILED}(accession: *))", "E_FORMULA_JOIN", [f"{DX}/seq", FILED])
invalid_formula("invalid/formula-first-by-arg-not-open", "first_by has the same rule.",
                f"first_by({FACT}(accession: *), {REV}(accession: *, period: *))", "E_FORMULA_JOIN", [FACT, REV])
invalid_formula("invalid/formula-last-by-boolean", "A `by` of booleans: not orderable, the code `max` gives for one "
                "(E_FORMULA_TYPE).", f"last_by({FACT}(accession: *), {DX}/active(accession: *))", "E_FORMULA_TYPE",
                [FACT, f"{DX}/active"])
invalid_formula("invalid/formula-first-by-boolean", "first_by has the same rule.",
                f"first_by({FACT}(accession: *), {DX}/active(accession: *))", "E_FORMULA_TYPE",
                [FACT, f"{DX}/active"])
invalid_formula("invalid/formula-last-by-units-vary", "The `by` values are in units that depend on the open argument "
                "`unit`: the cells have different units, so they cannot be ordered (the code `max` gives, "
                "E_FORMULA_UNIT_UNKNOWN: a unit that cannot be determined statically).",
                f"last_by({DX}/held(accession: *, unit: *), {DX}/size(accession: *, unit: *))",
                "E_FORMULA_UNIT_UNKNOWN", [f"{DX}/held", f"{DX}/size"])
invalid_formula("invalid/formula-last-by-by-scalar", "`by` is a slice: a scalar is E_FORMULA_TYPE.",
                f"last_by({FACT}(accession: *), 1 EUR)", "E_FORMULA_TYPE", [FACT])
invalid_formula("invalid/formula-last-by-slice-scalar", "`slice` is a slice: a single-cell read is E_FORMULA_TYPE.",
                f"last_by({FACT}(accession: \"a1\"), {FILED}(accession: *))", "E_FORMULA_TYPE", [FACT, FILED])
invalid_formula("invalid/formula-last-by-arity-one", "Two arguments are required.", f"last_by({FACT}(accession: *))",
                "E_FORMULA_ARITY", [FACT])
invalid_formula("invalid/formula-last-by-arity-three", "Two arguments only: no optional parameter.",
                f"last_by({FACT}(accession: *), {FILED}(accession: *), accession)", "E_FORMULA_ARITY", [FACT, FILED])
invalid_formula("invalid/formula-last-by-return-slice", "A group key leaves a slice: the body is not a scalar.",
                f"last_by({REV}(accession: *, period: *), {FILED}(accession: *))", "E_FORMULA_SLICE_VALUE",
                [REV, FILED])

# formula-eval: one computed function calc.example.net/e per vector over a small world of stored cells.
BOUND = "2026-01-01T00:00:00.000000Z"
LATER = "2026-06-01T00:00:00.000000Z"
TX = "2026-03-02T16:00:00.000000Z"
E = "calc.example.net/e"
P1, P2, P3 = "2025-12-31", "2026-03-31", "2026-06-30"


def spec_receipts(rows):
    import formula as F  # the reference's helpers for stored receipts only: no lexer rule is involved
    out = []
    for fq, args, value in rows:
        out.append(F.stored_receipt(FUNCS[fq], fq, args, value, TX))
    return out


def fact_rows(values):
    return [(FACT, {"accession": S(a)}, N(v)) for a, v in values]


def filed_rows(values):
    return [(FILED, {"accession": S(a)}, D(v)) for a, v in values]


def rev_rows(values):
    return [(REV, {"accession": S(a), "period": D(p)}, N(v)) for a, p, v in values]


def eval_vector(id_, why, body, names, rows, returns="EUR", error=None):
    descriptor = {"code": {"body": body, "lang": "formula"}, "inputs": sorted(names),
                  "signature": {"args": {}, "order": [], "returns": gf.ret(returns)}}
    world = {"functions": {n: {"bound": BOUND, "descriptor": d} for n, d in
                           sorted(({E: descriptor} | {n: FUNCS[n] for n in names}).items())},
             "receipts": spec_receipts(rows)}
    cell = {"args": {}, "fn": E}
    if error is not None:
        add("invalid/formula-eval-" + id_.split("/", 1)[1], "formula-eval", why, None, error, world=world, cell=cell,
            asof=LATER)
        return
    add(id_, "formula-eval", why, world=world, cell=cell, asof=LATER)


BASE_FACT = [("a1", "100"), ("a2", "110"), ("a3", "120")]
LB_BODY = LB_ONE + "\n"
# Filing dates: a1 on 10 Feb, a2 on 5 Mar, a3 on 20 Jan. The latest filing is a2, the earliest a3; the greatest
# accession, a3, is neither.
FILED_BASE = [("a1", "2026-02-10"), ("a2", "2026-03-05"), ("a3", "2026-01-20")]
eval_vector("formula-eval/last-by", "last_by(fact(accession: *), filed(accession: *)): the member of fact whose filing "
            "date is greatest is a2, 110. Both slices are read, so the lineage has two slice entries (15.13): fuel 3 "
            "nodes + (1 + 3) + (1 + 3) = 11.", LB_BODY, [FACT, FILED], fact_rows(BASE_FACT) + filed_rows(FILED_BASE))
eval_vector("formula-eval/first-by", "first_by: the least filing date is a3's, 120.", FB_ONE + "\n", [FACT, FILED],
            fact_rows(BASE_FACT) + filed_rows(FILED_BASE))
eval_vector("formula-eval/last-by-tie", "Two members with the same greatest by value, a1 and a2 both filed on 10 "
            "Feb: last_by gives the later one in key order, a2, 110.", LB_BODY, [FACT, FILED],
            fact_rows(BASE_FACT) + filed_rows([("a1", "2026-02-10"), ("a2", "2026-02-10"), ("a3", "2026-01-20")]))
eval_vector("formula-eval/first-by-tie", "Two members with the same least by value, a1 and a2 both filed on 20 Jan: "
            "first_by gives the earlier one in key order, a1, 100.", FB_ONE + "\n", [FACT, FILED],
            fact_rows(BASE_FACT) + filed_rows([("a1", "2026-01-20"), ("a2", "2026-01-20"), ("a3", "2026-03-01")]))
eval_vector("formula-eval/last-by-join-miss", "An inner join: a3 has the greatest accession and no filing date, so it is "
            "not a candidate, and a4 has a filing date later than all and no fact. The latest filed of the members "
            "that have both is a1 (5 Mar), 100.", LB_BODY, [FACT, FILED],
            fact_rows(BASE_FACT) + filed_rows([("a1", "2026-03-05"), ("a2", "2026-02-10"), ("a4", "2026-04-01")]))
eval_vector("formula-eval/first-by-join-miss", "The same inner join for first_by: a3 has no filing date, so it is not "
            "the least; the earliest of a1 (10 Feb) and a2 (5 Mar) is a1, 100.", FB_ONE + "\n", [FACT, FILED],
            fact_rows(BASE_FACT) + filed_rows([("a1", "2026-02-10"), ("a2", "2026-03-05"), ("a4", "2026-01-01")]))
eval_vector("formula-eval/last-by-group-key", "sum(last_by(revenue(accession: *, period: *), filed(accession: *))): "
            "for period 2025-12-31 the candidates are a1 (10 Feb, 10), a2 (5 Mar, 20) and a3 (20 Jan, 30): a2, 20. "
            "For 2026-03-31 they are a1 (11) and a3 (31): a1 filed later, 11. For 2026-06-30 the only member, a9, has "
            "no filing date: that group has no candidate and is not in the result. 20 + 11 = 31.",
            LB_GROUP + "\n", [REV, FILED],
            rev_rows([("a1", P1, "10"), ("a1", P2, "11"), ("a2", P1, "20"), ("a3", P1, "30"), ("a3", P2, "31"),
                      ("a9", P3, "99")]) + filed_rows(FILED_BASE))
eval_vector("formula-eval/first-by-group-key", "sum(first_by(revenue(...), filed(...))) over the same cells: for "
            "2025-12-31 the earliest is a3 (20 Jan), 30; for 2026-03-31 a3 again (31); 2026-06-30 has no candidate. "
            "30 + 31 = 61.", f"sum(first_by({REV}(accession: *, period: *), {FILED}(accession: *)))\n", [REV, FILED],
            rev_rows([("a1", P1, "10"), ("a1", P2, "11"), ("a2", P1, "20"), ("a3", P1, "30"), ("a3", P2, "31"),
                      ("a9", P3, "99")]) + filed_rows(FILED_BASE))
eval_vector("formula-eval/last-by-group-at", "at(last_by(...), d): the result with a group key is a slice over "
            "`period`, so a lookup applies to it. Over the cells of last-by-group-key, 2026-03-31 gives a1's 11.",
            f"at(last_by({REV}(accession: *, period: *), {FILED}(accession: *)), {P2})\n", [REV, FILED],
            rev_rows([("a1", P1, "10"), ("a1", P2, "11"), ("a2", P1, "20"), ("a3", P1, "30"), ("a3", P2, "31"),
                      ("a9", P3, "99")]) + filed_rows(FILED_BASE))
RANK_ROWS = [(f"{DX}/rank", {"accession": S(a)}, N(v)) for a, v in [("a1", "3"), ("a2", "10"), ("a3", "2")]]
eval_vector("formula-eval/last-by-number-by", "A by of numbers is ordered numerically, not as text: ranks 3, 10 and 2 "
            "give a2 (10), 110 (as text, '3' would be the greatest).",
            f"last_by({FACT}(accession: *), {RANK}(accession: *))\n", [FACT, RANK], fact_rows(BASE_FACT) + RANK_ROWS)
eval_vector("formula-eval/last-by-both", "last_by minus first_by over the same two slices: one lineage entry for each "
            "slice (the same slice read twice is one entry, 15.13): 110 - 120 = -10.", BOTH + "\n", [FACT, FILED],
            fact_rows(BASE_FACT) + filed_rows(FILED_BASE))
eval_vector("formula-eval/last-by-all-missing", "No member of fact has a filing date: no candidate, E_FORMULA_ABSENT "
            "as for lookups.", LB_BODY, [FACT, FILED], fact_rows(BASE_FACT) + filed_rows([("a8", "2026-01-01"),
                                                                                       ("a9", "2026-02-01")]),
            error="E_FORMULA_ABSENT")
eval_vector("formula-eval/first-by-all-missing", "The same for first_by.", FB_ONE + "\n", [FACT, FILED],
            fact_rows(BASE_FACT) + filed_rows([("a8", "2026-01-01")]), error="E_FORMULA_ABSENT")
eval_vector("formula-eval/last-by-empty-by", "A by slice with no cell at all: no candidate, E_FORMULA_ABSENT.", LB_BODY,
            [FACT, FILED], fact_rows(BASE_FACT), error="E_FORMULA_ABSENT")
EVAL_VECTORS = [v for v in VECTORS if v["kind"] == "formula-eval"]

# ---------------------------------------------------------------------------
# P3: the named test_case convention (7.3).

KEYENV = gv.KEYENV
FX_HASH = gv.FX_HASH


def make_receipt(ns, key, value, type_, fn, args, fn_hash, summary, licence="CC-BY-4.0"):
    cell = {"args": args, "fn": fn, "fn_hash": fn_hash, "ns": ns}
    return gv.signed(gv.receipt(cell, type_, value, summary, key, licence=licence), key)


def valid_receipt(id_, why, r, key="rates-2020", keys=None):
    payload = canon.receipt_payload(r)
    add(id_, "receipt", why, text(r), canonical=payload.decode(), sha256=sha(payload), sig=r["sig"], level="signed",
        keypair=gv.keypair_fields(key), keys=keys or KEYENV)


def invalid_receipt(id_, why, r, error, key="rates-2020"):
    add(id_, "receipt", why, text(r), error, keypair=gv.keypair_fields(key), keys=KEYENV)


def envelope(id_, why, env, status, error=None, **extra):
    request = {"asof": gv.ASOF, "cell_id": gv.cell_id(env["receipt"]["cell"])}
    add(id_, "envelope", why, text(env), error, status=status, keys=gv.ALL_KEYS, request=request, **extra)


def valid_envelope(id_, why, env):
    envelope(id_, why, env, 200, outcome=env["outcome"], trust=env["trust"],
             receipt_hash=canon.receipt_hash(env["receipt"]))


TEST_CASE_NAMED = {"code": {"body": "", "lang": "stored"}, "inputs": [],
                   "signature": {"args": {"case": SARG, "function": SARG, "function_hash": SARG},
                                 "order": ["case", "function", "function_hash"], "returns": "boolean"}}
TEST_CASE_NAMED_HASH = canon.function_hash(TEST_CASE_NAMED)
FN_UNDER_TEST = "rates.example.org/fx_rate"
TEST = {"asof": gv.ASOF, "call": f'{FN_UNDER_TEST}(base: "EUR", date: 2024-03-15, quote: "USD")',
        "expect": N("1.0892")}
CASE = sha(canon.jcs(TEST))[:16]
add("function/test-case-named", "function", "The named test_case function of a host (7.3): case, function and "
    "function_hash, three strings, and a boolean value. `function` is the full name of the function under test, as "
    "the test's call names it. A different descriptor from function/test-case, so a different hash.",
    text(TEST_CASE_NAMED), canonical=jcs_text(TEST_CASE_NAMED), sha256=TEST_CASE_NAMED_HASH)
TC_ARGS = {"case": S(CASE), "function": S(FN_UNDER_TEST), "function_hash": S(FX_HASH)}
R_NAMED_TRUE = make_receipt("rates.example.org", "rates-2020", True, "boolean", "test_case", TC_ARGS,
                            TEST_CASE_NAMED_HASH, "The function gives the expected result for this test: true.")
valid_receipt("receipt/test-case-named-true", "A named test_case cell: its host signs, with no inputs and no source, a "
              "boolean that says the function named and hashed gives the expected result of this case (7.3).",
              R_NAMED_TRUE)
R_NAMED_FALSE = make_receipt("calc.example.net", "calc-2020", False, "boolean", "test_case", TC_ARGS,
                             TEST_CASE_NAMED_HASH,
                             "calc.example.net found that this function does not give this expected result.")
valid_receipt("receipt/test-case-named-counterexample", "A host that does not own the function publishes its own "
              "named test_case cell with value false: an open counterexample that also names the function (7.3). "
              "`function` is the signer's statement, as the value is; a verifier cannot check it from the case hash.",
              R_NAMED_FALSE, key="calc-2020")
valid_envelope("envelope/test-case-named-counterexample", "A named counterexample from another host is that host's own "
               "primary statement.", {"outcome": "ok", "receipt": R_NAMED_FALSE, "trust": "primary"})
valid_envelope("envelope/test-case-named-primary", "A named test cell signed by its host with no inputs: trust primary "
               "(5.5, D16).", {"outcome": "ok", "receipt": R_NAMED_TRUE, "trust": "primary"})
envelope("invalid/envelope-test-case-named-computed", "A named test cell is not `computed`: the host signs it with no "
         "inputs, so it is primary (D16).", {"outcome": "ok", "receipt": R_NAMED_FALSE, "trust": "computed"}, 200,
         "E_ENVELOPE")
envelope("invalid/envelope-test-case-named-computed-true", "The same for a true named cell.",
         {"outcome": "ok", "receipt": R_NAMED_TRUE, "trust": "computed"}, 200, "E_ENVELOPE")
envelope("invalid/envelope-test-case-named-relayed", "A named test cell has no source, so `relayed` is not its trust "
         "either.", {"outcome": "ok", "receipt": R_NAMED_FALSE, "trust": "relayed"}, 200, "E_ENVELOPE")
# ---------------------------------------------------------------------------
# P4: the `public:` licence (8.1, 8.5, 10.3).

PUB_SEC = "public:https://www.sec.gov/privacy"
PUB_TSY = "public:https://home.treasury.gov/privacy-policy-and-legal-notices-and-more"
PUB_A = "public:https://a.example/terms"
PUB_A2 = "public:https://a.example/terms/v2"
RESTRICTED_L, OTHER_L, SA_L = gv.RESTRICTED_L, gv.OTHER_L, gv.SA_L
DECL_FN, ISSUED_L, OPEN_DECL = gv.DECL_FN, gv.ISSUED_L, gv.OPEN_DECL


def pad(prefix, size):
    return prefix + "x" * (size - len(prefix))


PUB_512 = pad("public:https://a.example/", 512)
PUB_513 = pad("public:https://a.example/", 513)
assert len(PUB_512) == 512 and len(PUB_513) == 513

for slug, licences, declarations, licence, reason, why in [
    ("alone", [PUB_SEC], {}, PUB_SEC, "open", "One public input: it is open, so it needs no declaration, and the result carries it."),
    ("twice", [PUB_SEC, PUB_SEC], {}, PUB_SEC, "open", "One public licence from two inputs."),
    ("cc0", [PUB_SEC, "CC0-1.0"], {}, PUB_SEC, "open", "Public with public domain: tier 2 is above tier 1, so public."),
    ("pddl", ["PDDL-1.0", PUB_SEC], {}, PUB_SEC, "open", "Public with PDDL-1.0, in the other order: public."),
    ("cc0-pddl", ["CC0-1.0", PUB_SEC, "PDDL-1.0"], {}, PUB_SEC, "open", "Public over both public-domain licences."),
    ("cc-by", [PUB_SEC, "CC-BY-4.0"], {}, "CC-BY-4.0", "open", "Public with attribution: tier 3 is above tier 2, so CC-BY-4.0."),
    ("mit", ["MIT", PUB_SEC], {}, "MIT", "open", "Public with MIT: MIT."),
    ("cc0-public-cc-by", ["CC0-1.0", PUB_SEC, "CC-BY-4.0"], {}, "CC-BY-4.0", "open", "One input of three open tiers."),
    ("cc-by-sa", [PUB_SEC, "CC-BY-SA-4.0"], {}, "CC-BY-SA-4.0", "open", "Public with share-alike: CC-BY-SA-4.0."),
    ("odbl", ["ODbL-1.0", PUB_SEC], {}, "ODbL-1.0", "open", "Public with ODbL-1.0: share-alike with public gives the share-alike licence."),
    ("two-different", [PUB_SEC, PUB_TSY], {}, PUB_SEC, "open",
     "Two different public licences: the one greatest in byte order, `www` over `home`, wins; the other stays in the lineage."),
    ("two-different-reversed", [PUB_TSY, PUB_SEC], {}, PUB_SEC, "open",
     "The order of the inputs does not matter."),
    ("two-different-prefix", [PUB_A, PUB_A2], {}, PUB_A2, "open",
     "One licence is a prefix of the other: the longer is the greater in byte order."),
    ("three-different", [PUB_A2, PUB_TSY, PUB_A, PUB_SEC], {}, PUB_SEC, "open", "Four public licences, three different URLs among them: the greatest."),
    ("two-different-with-cc0", [PUB_TSY, "CC0-1.0", PUB_SEC], {}, PUB_SEC, "open",
     "SEC facts and a CC0 source and another public source: SEC's `public:` licence."),
    ("two-different-with-cc-by", [PUB_TSY, "CC-BY-4.0", PUB_SEC], {}, "CC-BY-4.0", "open",
     "Two public licences and an attribution licence: the attribution tier wins."),
    ("max-length", [PUB_512, PUB_SEC], {}, PUB_SEC, "open", "A public licence of exactly 512 characters is valid."),
    ("restricted-declared", [PUB_SEC, RESTRICTED_L], OPEN_DECL, RESTRICTED_L, "declared",
     "Public with a restricted licence the publisher declared for this function: the restricted licence."),
    ("restricted-declared-first", [RESTRICTED_L, "CC0-1.0", PUB_SEC, "MIT"], OPEN_DECL, RESTRICTED_L, "declared",
     "A declared restricted licence wins over public, public domain and attribution."),
    ("restricted-undeclared", [PUB_SEC, RESTRICTED_L], {}, None, "not_declared",
     "Public with a restricted licence nobody declared: refused, not_declared."),
    ("restricted-declaration-closed", [PUB_SEC, RESTRICTED_L],
     {DECL_FN: [gv.decl(RESTRICTED_L, gv.T0, "2024-01-01T00:00:00.000000Z")]}, None, "declaration_not_open",
     "Public with a restricted licence whose declaration was closed before issued."),
    ("restricted-two-different", [PUB_SEC, RESTRICTED_L, OTHER_L], {}, None, "restricted_conflict",
     "Public with two different restricted licences: restricted_conflict."),
    ("share-alike-two-ids", [PUB_SEC, "CC-BY-SA-4.0", "ODbL-1.0"], {}, None, "share_alike_conflict",
     "Public with two different share-alike licences: step 2 is unchanged."),
    ("share-alike-with-restricted", [PUB_SEC, "CC-BY-SA-4.0", RESTRICTED_L], OPEN_DECL, None, "share_alike_conflict",
     "Public with share-alike and a restricted licence, declared or not: step 2 is unchanged, share_alike_conflict."),
    ("share-alike-with-restricted-undeclared", [PUB_SEC, "ODbL-1.0", RESTRICTED_L], {}, None, "share_alike_conflict",
     "share_alike_conflict comes before not_declared, with public inputs too."),
    ("no-inputs-own", [], {}, "CC-BY-4.0", "no_inputs", "No inputs: the mesh's own licence, as before."),
]:
    add(f"licence/public-{slug}", "licence", why, licences=licences, declarations=declarations, fn=DECL_FN,
        issued=ISSUED_L, mesh_licence="CC-BY-4.0", licence=licence, reason=reason)
add("licence/public-own-licence", "licence", "The mesh's own licence may be a public licence: no inputs, it carries it, "
    "and the rule does not constrain it.", licences=[], declarations={}, fn=DECL_FN, issued=ISSUED_L,
    mesh_licence=PUB_SEC, licence=PUB_SEC, reason="no_inputs")

BAD_PUBLIC = [
    ("no-url", "public:", "E_CANON_LICENCE", "`public:` with no URL."),
    ("http", "public:http://www.sec.gov/privacy", "E_CANON_LICENCE", "An http: URL is not an https URL."),
    ("spdx", "public:CC0-1.0", "E_CANON_LICENCE", "Followed by an SPDX identifier, not a URL."),
    ("bare-https", "public:https://", "E_CANON_LICENCE", "`https://` with nothing after it is not a valid URL."),
    ("space", "public:https://www.sec.gov/pri vacy", "E_CANON_LICENCE", "A space in the URL."),
    ("leading-space", "public: https://www.sec.gov/privacy", "E_CANON_LICENCE", "A space after the colon."),
    ("uppercase", "PUBLIC:https://www.sec.gov/privacy", "E_CANON_LICENCE",
     "The prefix is lowercase: this is neither an SPDX identifier nor an https URL."),
    ("double", "public:public:https://www.sec.gov/privacy", "E_CANON_LICENCE", "A `public:` in place of the URL."),
    ("non-ascii", "public:https://www.sec.gov/privacyé", "E_CANON_LICENCE", "A character outside printable ASCII."),
    ("no-colon", "publichttps://www.sec.gov/privacy", "E_CANON_LICENCE", "Without the colon it is an identifier with a slash."),
    ("too-long", PUB_513, "E_CANON_LIMIT", "The whole string, prefix included, keeps 8.1's limit of 512 characters: 513 is too long."),
]
for slug, licence, error, why in BAD_PUBLIC:
    add(f"invalid/licence-public-{slug}", "licence", why, licences=[licence], declarations={}, fn=DECL_FN,
        issued=ISSUED_L, mesh_licence="CC-BY-4.0", error=error)
add("invalid/licence-public-mesh-licence", "licence", "The mesh's own licence is checked by 8.1 too.", licences=[],
    declarations={}, fn=DECL_FN, issued=ISSUED_L, mesh_licence="public:", error="E_CANON_LICENCE")

# receipts: a stored receipt with a public licence verifies; malformed forms are refused in step 3.
FX_CELL = gv.FX_CELL
R_PUBLIC = gv.signed(gv.receipt(FX_CELL, "number", "1.0892", "A public figure from a source's own terms page.",
                                "rates-2020", licence=PUB_SEC), "rates-2020")
valid_receipt("receipt/licence-public", "`public:https://www.sec.gov/privacy` is a valid receipt licence (8.1): the "
              "grammar is `public:` and an https URL.", R_PUBLIC)
R_PUBLIC_512 = gv.signed(gv.receipt(FX_CELL, "number", "1.0892", "A public licence of exactly 512 characters.",
                                    "rates-2020", licence=PUB_512), "rates-2020")
valid_receipt("receipt/licence-public-max-length", "The whole string may be 512 characters.", R_PUBLIC_512)
for slug, licence, error, why in BAD_PUBLIC:
    r = gv.signed(gv.receipt(FX_CELL, "number", "1.0892", "A malformed public licence.", "rates-2020",
                             licence=licence), "rates-2020")
    invalid_receipt(f"invalid/receipt-licence-public-{slug}", why, r, error)


# entitlement (10.3): a computed receipt, its input receipts, the key documents.
def fx_input(quote, licence):
    return gv.fx_input(quote, licence)


def computed(inputs, licence, summary):
    return gv.computed(sorted(canon.receipt_hash(x) for x in inputs), licence, summary)


def entitlement(slug, why, r, inputs=(), declarations=None, error=None, **outputs):
    keys = {gv.RATES: gv.RATES_ENV,
            gv.CALC: gv.keydoc_env(gv.CALC, gv.CALC_KEYS, declarations) if declarations else gv.CALC_ENV}
    extra = {"keys": keys, "receipts": {canon.receipt_hash(x): text(x) for x in inputs}}
    id_ = f"entitlement/{slug}" if error is None else f"invalid/entitlement-{slug}"
    add(id_, "entitlement", why, text(r), error, **extra, **outputs)


I_SEC, I_TSY = fx_input("USD", PUB_SEC), fx_input("GBP", PUB_TSY)
I_CC0, I_CCBY, I_SA = fx_input("JPY", "CC0-1.0"), fx_input("CHF", "CC-BY-4.0"), fx_input("SEK", SA_L)
I_RESTRICTED = fx_input("NOK", RESTRICTED_L)
entitlement("public-open", "A computed receipt over one public input, carrying that licence: entitled, `open`, with no "
            "declaration (10.3: no new reason).",
            computed([I_SEC], PUB_SEC, "Over a public input."), [I_SEC], entitled=True, reason="open")
entitlement("public-with-cc0", "Public with CC0-1.0, the receipt carrying the public licence: entitled.",
            computed([I_SEC, I_CC0], PUB_SEC, "Over a public and a CC0 input."), [I_SEC, I_CC0],
            entitled=True, reason="open")
entitlement("public-with-cc0-mismatch", "Public with CC0-1.0, the receipt carrying CC0-1.0: the rule gives the public "
            "licence, so licence_mismatch.", computed([I_SEC, I_CC0], "CC0-1.0", "Over a public and a CC0 input, "
            "claiming CC0-1.0."), [I_SEC, I_CC0], entitled=False, reason="licence_mismatch")
entitlement("public-with-cc-by", "Public with CC-BY-4.0, carrying CC-BY-4.0: entitled.",
            computed([I_SEC, I_CCBY], "CC-BY-4.0", "Over a public and a CC-BY input."), [I_SEC, I_CCBY],
            entitled=True, reason="open")
entitlement("public-with-cc-by-mismatch", "Public with CC-BY-4.0, carrying the public licence: the rule gives "
            "CC-BY-4.0, so licence_mismatch.", computed([I_SEC, I_CCBY], PUB_SEC, "Over a public and a CC-BY input, "
            "claiming public."), [I_SEC, I_CCBY], entitled=False, reason="licence_mismatch")
entitlement("public-two-greatest", "Two different public licences, the receipt carrying the byte-greatest: entitled.",
            computed([I_SEC, I_TSY], PUB_SEC, "Over two public inputs."), [I_SEC, I_TSY], entitled=True, reason="open")
entitlement("public-two-lesser-mismatch", "Two different public licences, the receipt carrying the lesser: "
            "licence_mismatch.", computed([I_SEC, I_TSY], PUB_TSY, "Over two public inputs, claiming the lesser."),
            [I_SEC, I_TSY], entitled=False, reason="licence_mismatch")
entitlement("public-with-share-alike", "Public with CC-BY-SA-4.0, carrying CC-BY-SA-4.0: entitled.",
            computed([I_SEC, I_SA], SA_L, "Over a public and a share-alike input."), [I_SEC, I_SA],
            entitled=True, reason="open")
entitlement("public-with-restricted-declared", "Public with a declared restricted input: the restricted licence, "
            "`declared`.", computed([I_SEC, I_RESTRICTED], RESTRICTED_L, "Over a public and a restricted input, declared."),
            [I_SEC, I_RESTRICTED], declarations=OPEN_DECL, entitled=True, reason="declared")
entitlement("public-with-restricted-declared-mismatch", "Public with a declared restricted input, the receipt "
            "carrying the public licence: the restricted licence wins, so licence_mismatch.",
            computed([I_SEC, I_RESTRICTED], PUB_SEC, "Over a public and a restricted input, claiming public."),
            [I_SEC, I_RESTRICTED], declarations=OPEN_DECL, entitled=False, reason="licence_mismatch")
entitlement("public-with-restricted-undeclared", "Public with a restricted input nobody declared: not entitled, "
            "not_declared.", computed([I_SEC, I_RESTRICTED], RESTRICTED_L, "Over a public and a restricted input."),
            [I_SEC, I_RESTRICTED], declarations={"calc.example.net/other": [gv.decl(RESTRICTED_L)]}, entitled=False,
            reason="not_declared")
entitlement("public-share-alike-conflict", "Public with a share-alike and a restricted input: share_alike_conflict, "
            "as without the public input.", computed([I_SEC, I_SA, I_RESTRICTED], SA_L, "Over three inputs."),
            [I_SEC, I_SA, I_RESTRICTED], declarations=OPEN_DECL, entitled=False, reason="share_alike_conflict")
entitlement("stored-public", "A stored receipt with a public licence has no input receipt: entitled, `no_inputs`.",
            R_PUBLIC, entitled=True, reason="no_inputs")
R_BAD_PUB = gv.signed(gv.receipt(FX_CELL, "number", "1.0892", "A malformed public licence.", "rates-2020",
                                 licence="public:"), "rates-2020")
entitlement("public-malformed-receipt", "A receipt whose own licence is `public:` fails verification first, with "
            "E_CANON_LICENCE.", R_BAD_PUB, error="E_CANON_LICENCE")
R_BAD_PUB_HTTP = gv.signed(gv.receipt(FX_CELL, "number", "1.0892", "A malformed public licence.", "rates-2020",
                                      licence="public:http://www.sec.gov/privacy"), "rates-2020")
entitlement("public-http-receipt", "An http: URL after `public:` is E_CANON_LICENCE.", R_BAD_PUB_HTTP,
            error="E_CANON_LICENCE")

# ---------------------------------------------------------------------------
# The expected outputs of the formula-eval vectors that need an evaluator (see the docstring).

# Values worked by hand (see each description); the rest taken from the scratch reference with last_by and first_by.
EVAL_OUTPUT = {'formula-eval/first-by': {'fuel_used': 11,
                           'lineage': ['slice:573da1107cd04e7f26cc1afabd6ec6f2d7ef8be05c210ca87f72e7cd9ea55bc9:0f168c0673f4fec2ef949ee8226b64b5a952c3daae11f3f2d953fb73972c5fb7',
                                       'slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:c09513a7be17b1dc419e9403bdb93ed6f1bedc8493585f26b8304e8e7d1193c5'],
                           'receipt_asof': '2026-03-02T16:00:00.000000Z',
                           'receipt_hash': '76980a2f04e38ee59aca39e7ce5f5d86858d51ca6ede01be6d1619dc06f41605',
                           'tx': '2026-03-02T16:00:00.000000Z',
                           'value': {'type': 'number', 'value': '120'}},
 'formula-eval/first-by-group-key': {'fuel_used': 17,
                                     'lineage': ['slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:c09513a7be17b1dc419e9403bdb93ed6f1bedc8493585f26b8304e8e7d1193c5',
                                                 'slice:961063d6be023cbbe5563057ab1d654e10323f5adaf92f422b0e6633b2825601:7639b82f0f23f574df297512aba25a1f363a28c5d19c53466682e7791ff7dbe9'],
                                     'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                     'receipt_hash': 'edb509ec26798c5a2bab7c350a6774e6af7033201fe2a2d1d60cbf8cb6640ef4',
                                     'tx': '2026-03-02T16:00:00.000000Z',
                                     'value': {'type': 'number', 'value': '61'}},
 'formula-eval/first-by-join-miss': {'fuel_used': 11,
                                     'lineage': ['slice:573da1107cd04e7f26cc1afabd6ec6f2d7ef8be05c210ca87f72e7cd9ea55bc9:0f168c0673f4fec2ef949ee8226b64b5a952c3daae11f3f2d953fb73972c5fb7',
                                                 'slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:12d40e54ce95b44d5fcd1316ebb61099fe492def98d2be740806f545283f57e0'],
                                     'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                     'receipt_hash': 'd0c7521ec1f7e1fe0b3fc134a282e83ab93581bbe817d325426dff41b76b7bb4',
                                     'tx': '2026-03-02T16:00:00.000000Z',
                                     'value': {'type': 'number', 'value': '100'}},
 'formula-eval/first-by-tie': {'fuel_used': 11,
                               'lineage': ['slice:573da1107cd04e7f26cc1afabd6ec6f2d7ef8be05c210ca87f72e7cd9ea55bc9:0f168c0673f4fec2ef949ee8226b64b5a952c3daae11f3f2d953fb73972c5fb7',
                                           'slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:c306c0db308c23e0503480a7eb7192c30cc311a5b40fed811f4db60366e27c23'],
                               'receipt_asof': '2026-03-02T16:00:00.000000Z',
                               'receipt_hash': '98b5c48aa76db4bc778d52da1870c5e772f3af0590b9f4a252814b67c981a8cb',
                               'tx': '2026-03-02T16:00:00.000000Z',
                               'value': {'type': 'number', 'value': '100'}},
 'formula-eval/last-by': {'fuel_used': 11,
                          'lineage': ['slice:573da1107cd04e7f26cc1afabd6ec6f2d7ef8be05c210ca87f72e7cd9ea55bc9:0f168c0673f4fec2ef949ee8226b64b5a952c3daae11f3f2d953fb73972c5fb7',
                                      'slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:c09513a7be17b1dc419e9403bdb93ed6f1bedc8493585f26b8304e8e7d1193c5'],
                          'receipt_asof': '2026-03-02T16:00:00.000000Z',
                          'receipt_hash': 'a2583d89b1314027b9ce54da8ae5c4b4e9e66fed2aeb0cbf64c4906ef7b440d1',
                          'tx': '2026-03-02T16:00:00.000000Z',
                          'value': {'type': 'number', 'value': '110'}},
 'formula-eval/last-by-both': {'fuel_used': 23,
                               'lineage': ['slice:573da1107cd04e7f26cc1afabd6ec6f2d7ef8be05c210ca87f72e7cd9ea55bc9:0f168c0673f4fec2ef949ee8226b64b5a952c3daae11f3f2d953fb73972c5fb7',
                                           'slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:c09513a7be17b1dc419e9403bdb93ed6f1bedc8493585f26b8304e8e7d1193c5'],
                               'receipt_asof': '2026-03-02T16:00:00.000000Z',
                               'receipt_hash': '09effb27b1546f5be17d9f9a1d5823d1cad1ef98cbc85b33bb867eff1da50d36',
                               'tx': '2026-03-02T16:00:00.000000Z',
                               'value': {'type': 'number', 'value': '-10'}},
 'formula-eval/last-by-group-at': {'fuel_used': 18,
                                   'lineage': ['slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:c09513a7be17b1dc419e9403bdb93ed6f1bedc8493585f26b8304e8e7d1193c5',
                                               'slice:961063d6be023cbbe5563057ab1d654e10323f5adaf92f422b0e6633b2825601:7639b82f0f23f574df297512aba25a1f363a28c5d19c53466682e7791ff7dbe9'],
                                   'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                   'receipt_hash': 'e40f103b6875756e680a1c949a291af33722f5d3de9d55bd38a8d8c10f799882',
                                   'tx': '2026-03-02T16:00:00.000000Z',
                                   'value': {'type': 'number', 'value': '11'}},
 'formula-eval/last-by-group-key': {'fuel_used': 17,
                                    'lineage': ['slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:c09513a7be17b1dc419e9403bdb93ed6f1bedc8493585f26b8304e8e7d1193c5',
                                                'slice:961063d6be023cbbe5563057ab1d654e10323f5adaf92f422b0e6633b2825601:7639b82f0f23f574df297512aba25a1f363a28c5d19c53466682e7791ff7dbe9'],
                                    'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                    'receipt_hash': '565852180c41dcf3017bf03975a9538cf4e89c985d0bc65673323de52387f296',
                                    'tx': '2026-03-02T16:00:00.000000Z',
                                    'value': {'type': 'number', 'value': '31'}},
 'formula-eval/last-by-join-miss': {'fuel_used': 11,
                                    'lineage': ['slice:573da1107cd04e7f26cc1afabd6ec6f2d7ef8be05c210ca87f72e7cd9ea55bc9:0f168c0673f4fec2ef949ee8226b64b5a952c3daae11f3f2d953fb73972c5fb7',
                                                'slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:804806b8c22fa6fdea24d52abfbfbdbf3daf9f12773764c95554af7759b26d65'],
                                    'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                    'receipt_hash': '0eee9d688470064ecccac7794768933982a0cf59a4fbb4040c0a600fd5b42559',
                                    'tx': '2026-03-02T16:00:00.000000Z',
                                    'value': {'type': 'number', 'value': '100'}},
 'formula-eval/last-by-number-by': {'fuel_used': 11,
                                    'lineage': ['slice:573da1107cd04e7f26cc1afabd6ec6f2d7ef8be05c210ca87f72e7cd9ea55bc9:0f168c0673f4fec2ef949ee8226b64b5a952c3daae11f3f2d953fb73972c5fb7',
                                                'slice:d83a37752bb8ee5365ac8de6986174bf1c174abbb246a96bb6b3ed6cce49796e:b8895eda01e9a14c694d867477ba2dbdf7148b10bb1eef9a51885bf4c1b7e77f'],
                                    'receipt_asof': '2026-03-02T16:00:00.000000Z',
                                    'receipt_hash': 'c19b13d095de858ddd7efe5da33fb375ae223db0de09d7e9ea36e4b8f802fd2e',
                                    'tx': '2026-03-02T16:00:00.000000Z',
                                    'value': {'type': 'number', 'value': '110'}},
 'formula-eval/last-by-tie': {'fuel_used': 11,
                              'lineage': ['slice:573da1107cd04e7f26cc1afabd6ec6f2d7ef8be05c210ca87f72e7cd9ea55bc9:0f168c0673f4fec2ef949ee8226b64b5a952c3daae11f3f2d953fb73972c5fb7',
                                          'slice:7003c5251a09c52c264249e19931e204b92c4daa60ed2c06b4dd092985d8c901:7bd8d50e386091bd74115b487dd830fb28a22725ddc28eb7c01812cbf1cbb943'],
                              'receipt_asof': '2026-03-02T16:00:00.000000Z',
                              'receipt_hash': 'b492e4455e3dcd6ed8f3c5fb38433220f1d9a1e52a4f3082ef8fbc9dddc93124',
                              'tx': '2026-03-02T16:00:00.000000Z',
                              'value': {'type': 'number', 'value': '110'}}}
for v in EVAL_VECTORS:
    if v["valid"]:
        v.update(EVAL_OUTPUT.get(v["id"], {}))


def main():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for vec in VECTORS:
        if vec["kind"] == "formula-eval" and vec["valid"] and "receipt_hash" not in vec:
            raise SystemExit(f"{vec['id']}: no computed outputs yet")
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
