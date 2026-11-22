#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Round-0.7 vectors (SPEC.md section 11 vector format), written tests-first.

CONTRACT-round-0.7.md, R1 (withdrawal: the null version), R3 (a slice override may replace the whole member set) and
the one K8 vector pair R1 replaces. R2 (closed names) has no vector: the bindings answer (9.7) has no vector kind, and
a read of a closed name is the existing `envelope/not-covered-name-unbound`.

Like tools/gen_vectors_classes_round.py this builds the vectors from the fixtures of tools/gen_vectors.py,
tools/gen_formula.py and crosscheck/generate_060.py (imported, never run), signs every receipt with the vector keys of
those fixtures, and states every expected result by hand from the contract: the reference tools cannot produce them yet.
Where a valid `formula-eval` vector's outputs coincide with what the spec-0.6.2 tools give for an equivalent world (the
withdrawn cell simply has no version, which is what the contract says a withdrawn cell is to a read), they are taken from
there; `fuel_used` is not stated, since what a read of a withdrawn version costs is the evaluator's.

Files written under vectors/: new ones only. tools/gen_vectors_classes_round.py (not this file) rewrites the two K8
vectors invalid/call-class-lookup-withdrawn and invalid/call-class-lookup-withdrawn-cased, whose expected error changes.

    python3 tools/gen_vectors_round_0_7.py        # write the vectors
    python3 -c "import gen_vectors_round_0_7"      # (from tools/) build them in memory: VECTORS

Choices the contract leaves open are listed in tests/test_round_0_7.py (the module docstring).
"""

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
for p in (HERE, ROOT / "crosscheck"):
    if str(p) not in sys.path:
        sys.path.append(str(p))
import canon  # noqa: E402
import formula as F  # noqa: E402
import gen_formula as gf  # noqa: E402  (the formula-eval base world; its main is not run)
import gen_vectors as gv  # noqa: E402  (the fixtures and keys; its main() is not run)
import generate_060 as g60  # noqa: E402  (the scenario fixtures; its vectors are built in memory, never written)

OUT = ROOT / "vectors"
VECTORS = []
PREFIX = "spec-0.7.0: "

text = gv.text
S, N, D = gv.S, gv.N, gv.D
ASOF = gv.ASOF
FX_CELL, GBP_CELL = gv.FX_CELL, gv.GBP_CELL
cell_id = gv.cell_id


def add(id_, kind, description, input=None, error=None, **extra):
    vec = {"id": id_, "kind": kind, "description": PREFIX + description, "valid": error is None}
    if input is not None:
        vec["input"] = input
    vec.update(extra)
    if error is not None:
        vec["error"] = error
    VECTORS.append(vec)


# ---------------------------------------------------------------------------
# R1: the withdrawal receipt (8.1): `withdrawn` takes the place of `type` and `value`.

REASON = "The 15 March 2024 reference rate was published in error and is withdrawn."
SUMMARY = "The EUR/USD reference rate for 15 March 2024 is withdrawn: the cell has no value from its asof on."
SRC = g60.SRC


def withdrawal(cell=FX_CELL, withdrawn=REASON, key="rates-2020", summary=SUMMARY, source=None, drop=(), extra=None,
               **kw):
    """An unsigned-then-signed stored withdrawal: gv.receipt without type and value, plus `withdrawn`."""
    r = gv.receipt(cell, "number", "1", summary, key, **kw)
    del r["type"], r["value"]
    r["withdrawn"] = withdrawn
    if source is not None:
        r["source"] = source
    r.update(extra or {})
    for k in drop:
        r.pop(k, None)
    return gv.signed(r, key)


def valid_receipt(id_, why, r):
    payload = canon.receipt_payload(r)
    add(id_, "receipt", why, text(r), canonical=payload.decode(), sha256=canon.sha256_hex(payload), sig=r["sig"],
        level="signed", keypair=gv.keypair_fields("rates-2020"), keys=gv.KEYENV)


def invalid_receipt(id_, why, r, error, key="rates-2020", raw=None):
    add(id_, "receipt", why, raw if raw is not None else text(r), error, keypair=gv.keypair_fields(key), keys=gv.KEYENV)


R_WD = withdrawal()
R_WD_RELAYED = withdrawal(source=SRC, summary="The EUR/USD reference rate for 15 March 2024 is withdrawn, "
                          "as relayed from bank.example.com.")
H_WD = canon.receipt_hash(R_WD)

valid_receipt("receipt/withdrawn-primary", "A stored cell's withdrawal, signed by its publisher: `withdrawn` (the "
              "reason) takes the place of type and value; inputs is empty. It is hashed and verified as any stored "
              "receipt (R1, 8.1, 10.1).", R_WD)
valid_receipt("receipt/withdrawn-relayed", "A withdrawal with `source`: the publisher withdraws a value it had taken "
              "from another party, and the receipt verifies like any stored one.", R_WD_RELAYED)
valid_receipt("receipt/withdrawn-non-ascii", "The reason is a string under the string rules (3.5): NFC text, any "
              "script.", withdrawal(withdrawn="Le taux a été retiré (撤回): publié par erreur."))
# 1024 UTF-8 bytes, the summary limit (4.5): the longest reason.
valid_receipt("receipt/withdrawn-max-length", "The reason is at most 1024 UTF-8 bytes, the summary limit.",
              withdrawal(withdrawn="x" * 1024))
invalid_receipt("invalid/receipt-withdrawn-too-long", "A reason of 1025 bytes is over the summary limit: the code a "
                "summary of that length gets.", withdrawal(withdrawn="x" * 1025), "E_CANON_LIMIT")
invalid_receipt("invalid/receipt-withdrawn-not-nfc", "The reason follows the string rules (3.5): decomposed text is "
                "not NFC, E_CANON_STRING as for a summary.", withdrawal(withdrawn="Le taux a e\u0301te\u0301 retire\u0301."),
                "E_CANON_STRING")
invalid_receipt("invalid/receipt-withdrawn-control", "A control character in the reason: E_CANON_STRING as for a "
                "summary.", withdrawal(withdrawn="published\u0001in error"), "E_CANON_STRING")
R_WD_NUM = dict(withdrawal(withdrawn="x"), withdrawn=5)
invalid_receipt("invalid/receipt-withdrawn-not-string", "The reason is a string: a number is E_SCHEMA.", R_WD_NUM,
                "E_SCHEMA", raw=json.dumps(R_WD_NUM, indent=2))
invalid_receipt("invalid/receipt-withdrawn-empty", "The reason is non-empty: a withdrawal says why.",
                withdrawal(withdrawn=""), "E_SCHEMA")
R_WD_NULL = dict(withdrawal(withdrawn="x"), withdrawn=None)
invalid_receipt("invalid/receipt-withdrawn-null", "There is no null (3.6): the reason is a string.",
                R_WD_NULL, "E_SCHEMA", raw=json.dumps(R_WD_NULL, indent=2))
invalid_receipt("invalid/receipt-withdrawn-and-value", "A receipt with both withdrawn and a value (type and value) "
                "says two things about the cell.",
                withdrawal(extra={"type": "number", "value": "1.0892"}), "E_SCHEMA")
invalid_receipt("invalid/receipt-withdrawn-and-value-only", "withdrawn and value, without type: still both.",
                withdrawal(extra={"value": "1.0892"}), "E_SCHEMA")
invalid_receipt("invalid/receipt-withdrawn-and-type-only", "withdrawn takes the place of type as well as value: type "
                "beside it is a member too many (the most conservative reading of 8.1).",
                withdrawal(extra={"type": "number"}), "E_SCHEMA")
invalid_receipt("invalid/receipt-withdrawn-neither", "A receipt with neither withdrawn nor type and value is a "
                "receipt missing its value.", withdrawal(drop=("withdrawn",)), "E_SCHEMA")
R_WD_CALC = gv.signed(dict({k: v for k, v in gv.receipt(
    gv.convert_cell, "number", "1", "A computed cell that claims a withdrawal.", "calc-2020", inputs=[gv.H_FX],
    issued="2024-03-16T09:00:01.250000Z").items() if k not in ("type", "value")}, withdrawn=REASON), "calc-2020")
invalid_receipt("invalid/receipt-withdrawn-with-inputs", "Only a stored cell can be withdrawn: inputs is empty. A "
                "computed cell over a withdrawn input has no value, not a withdrawal.", R_WD_CALC, "E_SCHEMA",
                key="calc-2020")
invalid_receipt("invalid/receipt-withdrawn-tampered", "The reason was changed after signing: the signature covers "
                "withdrawn like any member.", dict(R_WD, withdrawn=REASON + " Not."), "E_SIGNATURE")
invalid_receipt("invalid/receipt-withdrawn-publisher-mismatch", "A withdrawal is checked as any stored receipt: "
                "publisher equals cell.ns.", withdrawal(publisher="other.example.org"), "E_PUBLISHER_MISMATCH")
invalid_receipt("invalid/receipt-withdrawn-valid-mismatch", "A withdrawal has no value, but its valid echo is "
                "still checked as any stored receipt's (E_VALID_MISMATCH).",
                withdrawal(valid={"date": D("2024-03-14")}), "E_VALID_MISMATCH")
invalid_receipt("invalid/receipt-withdrawn-time-order", "tx <= asof <= issued (8.2) holds for a withdrawal.",
                withdrawal(tx="2024-03-17T00:00:00.000000Z"), "E_TIME_ORDER")

# ---------------------------------------------------------------------------
# R1: envelopes (5.5). not_covered carries `receipt` (the withdrawal) and `reason` (its `withdrawn`).


def envelope(id_, why, env, status, error=None, request=None, **extra):
    if request is None:
        request = {"asof": ASOF, "cell_id": cell_id(FX_CELL)}
    add(id_, "envelope", why, text(env), error, status=status, keys=gv.ALL_KEYS, request=request, **extra)


def withdrawn_envelope(receipt=R_WD, trust="primary", **over):
    env = {"outcome": "not_covered", "reason": receipt.get("withdrawn", REASON), "receipt": receipt, "trust": trust}
    env.update(over)
    return env


envelope("envelope/not-covered-withdrawn", "A read whose latest version as of the asof is a withdrawal: not_covered "
         "with the withdrawal as `receipt` and its `withdrawn` text as `reason` (R1, 5.5).", withdrawn_envelope(), 404,
         outcome="not_covered", trust="primary", receipt_hash=H_WD)
envelope("envelope/not-covered-withdrawn-relayed", "A withdrawal that carries `source` is checked as any stored receipt "
         "and answered the same way.", withdrawn_envelope(R_WD_RELAYED, "relayed"), 404, outcome="not_covered", trust="relayed",
         receipt_hash=canon.receipt_hash(R_WD_RELAYED))
envelope("envelope/not-covered-withdrawn-later-asof", "The withdrawal's asof is at or before the requested asof: it "
         "stands until the cell's next version.", withdrawn_envelope(), 404,
         request={"asof": "2024-03-18T09:00:00.000000Z", "cell_id": cell_id(FX_CELL)}, outcome="not_covered",
         trust="primary", receipt_hash=H_WD)
envelope("envelope/not-covered-withdrawn-no-asof", "A request without asof asks for the mesh's now: any asof of the "
         "withdrawal is accepted.", withdrawn_envelope(), 404, request={"cell_id": cell_id(FX_CELL)},
         outcome="not_covered", trust="primary", receipt_hash=H_WD)
envelope("envelope/not-covered-reason-label", "The label case: a request through a label whose lookup cell is "
         "withdrawn resolved no cell, so not_covered has `reason` and no receipt (R1, 16.7).",
         {"outcome": "not_covered", "reason": "The label is no longer given."}, 404, outcome="not_covered")

for name, env, status, request, why in [
    ("not-covered-withdrawn-reason-mismatch", withdrawn_envelope(reason="Another reason."), 404, None,
     "`reason` must equal the receipt's `withdrawn`."),
    ("not-covered-withdrawn-no-reason", {"outcome": "not_covered", "receipt": R_WD, "trust": "primary"}, 404, None,
     "A withdrawal in not_covered is answered with its reason (the most conservative reading of R1): `reason` is "
     "required with the receipt."),
    ("not-covered-receipt-not-withdrawal", {"outcome": "not_covered", "reason": "A reason.", "receipt": gv.R_FX, "trust": "primary"}, 404,
     None, "not_covered with a receipt that is not a withdrawal."),
    ("not-covered-reason-empty", {"outcome": "not_covered", "reason": ""}, 404, None,
     "`reason` is a non-empty string (3.5): empty is E_ENVELOPE."),
    ("not-covered-withdrawn-no-trust", {k: v for k, v in withdrawn_envelope().items() if k != "trust"}, 404, None,
     "A not_covered with a withdrawal requires `trust`, as ok does (coordinator decision 1)."),
    ("not-covered-withdrawn-wrong-trust", withdrawn_envelope(R_WD_RELAYED, "primary"), 404, None,
     "`trust` is checked against the receipt as for ok: a withdrawal with `source` is relayed, not primary."),
    ("not-covered-withdrawn-wrong-trust-relayed", withdrawn_envelope(R_WD, "relayed"), 404, None,
     "relayed needs `source`: a plain withdrawal is primary."),
    ("not-covered-trust-without-receipt", {"outcome": "not_covered", "reason": "The label is no longer given.",
                                           "trust": "primary"}, 404, None,
     "`trust` stays forbidden on not_covered without a receipt."),
    ("ok-withdrawal", {"outcome": "ok", "receipt": R_WD, "trust": "primary"}, 200, None,
     "ok carries a value: a withdrawal is never an ok receipt."),
    ("stale-withdrawal", {"age_seconds": 60, "outcome": "stale", "receipt": R_WD, "trust": "primary"}, 200, None,
     "stale carries a value too."),
    ("not-covered-withdrawn-other-cell", withdrawn_envelope(), 404, {"asof": ASOF, "cell_id": cell_id(GBP_CELL)},
     "Step 5: the withdrawal's cell id must be the requested cell's."),
    ("not-covered-withdrawn-before-asof", withdrawn_envelope(), 404,
     {"asof": "2024-03-15T09:00:00.000000Z", "cell_id": cell_id(FX_CELL)},
     "Step 5: the withdrawal's asof is after the requested asof."),
    ("not-covered-withdrawn-with-fault", withdrawn_envelope(fault="E_FORMULA_ABSENT"), 404, None,
     "A withdrawal is not a fault: with a receipt, `fault` is not allowed."),
    ("not-covered-withdrawn-bad-signature", withdrawn_envelope(dict(R_WD, withdrawn=REASON + " Not."),
                                                               reason=REASON + " Not."), 404, None,
     "Step 4: the withdrawal is verified through 10.1 step 6 like any receipt."),
]:
    code = "E_SIGNATURE" if name.endswith("bad-signature") else "E_ENVELOPE"
    envelope(f"invalid/envelope-{name}", why, env, status, code, request=request)

# A slice page leaves a withdrawn cell out of its members (5.6).
SLICE_REQUEST = gv.SLICE_REQUEST
R_WD_CHF = withdrawal(cell=FX_CELL | {"args": gv.FX_ARGS | {"quote": S("CHF")}},
                      summary="The EUR/CHF rate for 15 March 2024 is withdrawn.")
add_page = [("slice-member-withdrawn", gv.slice_page([gv.M(R_WD_CHF), gv.M(gv.R_FX)]),
             "A member is an ok or stale envelope: a withdrawn cell is not a member, and a withdrawal in an ok "
             "member is E_ENVELOPE."),
            ("slice-member-not-covered-withdrawn", gv.slice_page([{"outcome": "not_covered", "reason": REASON,
                                                                    "receipt": R_WD_CHF, "trust": "primary"}, gv.M(gv.R_FX)]),
             "A member that is a not_covered answer with the withdrawal is not a member either: a slice leaves the "
             "withdrawn cell out.")]
for name, env, why in add_page:
    envelope(f"invalid/envelope-{name}", why, env, 200, "E_ENVELOPE", request=SLICE_REQUEST)

# ---------------------------------------------------------------------------
# R1: the lookup return type no longer allows "" (16.1): the K8 vectors (replaced, in gen_vectors_classes_round.py)
# and the labels of a withdrawn lookup cell as an envelope (the call kind cannot express not_covered).
# R1 in a formula (15.12, 15.13): a withdrawn cell read alone is absent, in a slice it is not a member. The world is
# tools/gen_formula.py's base world; a withdrawal is a stored receipt of the cell's publisher.

FNS, RECEIPTS = gf._base()
PRICE = "data.example.org/price"
DAILY = "data.example.org/daily"


def stored_withdrawal(fq, args, reason, tx):
    ns, _, fn = fq.rpartition("/")
    host = ns.split("/")[0]
    descriptor = FNS[fq]
    unsigned = {
        "asof": tx,
        "cell": {"args": args, "fn": fn, "fn_hash": canon.function_hash(descriptor), "ns": ns},
        "computed_by": f"{host}#{F.host_key_id(host)}",
        "inputs": [],
        "issued": max(tx, F.KEY_FROM),
        "licence": "CC-BY-4.0",
        "proto": canon.PROTO,
        "publisher": ns,
        "summary": f"A withdrawal of {fn}.",
        "tx": tx,
        "valid": {k: v for k, v in args.items() if descriptor["signature"]["args"][k]["valid"]},
        "withdrawn": reason,
    }
    return canon.sign_receipt(unsigned, F.host_seed(host))


def stored_value(fq, args, value, tx):
    return F.stored_receipt(FNS[fq], fq, args, value, tx)


def wd_world(source, returns, args, extra_receipts, hide=()):
    """(world with the extra receipts, the equivalent world): the equivalent world has no withdrawal, and none of the
    stored versions of the cells in `hide` (a withdrawn cell has no value: it is as a cell with no receipt)."""
    names = list(args)
    descriptor = gf.define(gf.E, {n: d for n, (d, _) in args.items()}, names, source, returns, FNS)
    with_ = gf.world_for(descriptor)
    without = json.loads(json.dumps(with_))
    with_["receipts"] = with_["receipts"] + list(extra_receipts)
    gone = {canon.jcs(dict(zip(("ns", "fn", "args"), (f.rpartition("/")[0], f.rpartition("/")[2], a)))) for f, a in hide}
    without["receipts"] = [r for r in without["receipts"]
                           if canon.jcs({"ns": r["cell"]["ns"], "fn": r["cell"]["fn"], "args": r["cell"]["args"]})
                           not in gone]
    without["receipts"] += [r for r in extra_receipts if "withdrawn" not in r]
    return with_, without


BOLT = {"item": S("bolt")}
DAY4 = {"date": D("2026-03-04")}
WD_BOLT = stored_withdrawal(PRICE, BOLT, "The price was withdrawn: the item is no longer sold.", "2026-05-01T09:00:00.000000Z")
WD_DAY4 = stored_withdrawal(DAILY, DAY4, "The reading of 4 March was withdrawn as a sensor fault.",
                            "2026-03-20T18:00:00.000000Z")
BOLT_BACK = stored_value(PRICE, BOLT, N("3"), "2026-05-20T09:00:00.000000Z")


def eval_vector(vid, why, source, returns, args, extra, asof, error=None, hand=None, hide=()):
    world, equivalent = wd_world(source, returns, args, extra, hide)
    cell = {"args": {n: v for n, (_, v) in args.items()}, "fn": gf.E}
    vec = {"kind": "formula-eval", "world": world, "cell": cell, "asof": asof}
    if error is None:
        base = dict(vec, world=equivalent)
        got = F.run_vector(base)
        assert "error" not in got, (vid, got)
        out = {k: got[k] for k in ("receipt_hash", "value", "lineage", "tx", "receipt_asof")}
        if hand:
            assert got["value"]["value"] == hand, (vid, got["value"], hand)
        add(vid, "formula-eval", why, None, None, world=world, cell=cell, asof=asof, **out)
    else:
        add(vid, "formula-eval", why, None, error, world=world, cell=cell, asof=asof)


NUM, STR = gf.NUM1, gf.STR
PRICE_READ = {"s": (STR, S("bolt"))}
eval_vector("formula-eval/withdrawn-before-asof", "R1: bolt's price is withdrawn at 2026-05-01, but read as of "
            "2026-04-15 the withdrawal is not yet its latest version: the value stands, 2.75 (15.12).",
            f"{PRICE}(s)", "EUR", PRICE_READ, [WD_BOLT], "2026-04-15T00:00:00.000000Z", hand="2.75")
eval_vector("invalid/formula-eval-withdrawn-read-alone", "R1: bolt's price is withdrawn at 2026-05-01: read alone as of "
            "2026-06-01 its latest version is a withdrawal, so the cell has no value (as a cell with "
            "no receipt: E_FORMULA_NOT_COVERED, 15.11).", f"{PRICE}(s)", "EUR", PRICE_READ, [WD_BOLT], gf.LATER,
            error="E_FORMULA_NOT_COVERED")
eval_vector("formula-eval/withdrawn-ended", "R1: a later version with a value ends the withdrawal: bolt's price is "
            "withdrawn at 2026-05-01 and 3 again from 2026-05-20, so the read as of 2026-06-01 is 3.",
            f"{PRICE}(s)", "EUR", PRICE_READ, [WD_BOLT, BOLT_BACK], gf.LATER, hand="3",
            hide=[(PRICE, BOLT)])
eval_vector("formula-eval/withdrawn-slice-count", "R1: the reading of 4 March is withdrawn: in the slice read by count "
            "it is not a member, 9 of the 10.", f"count({DAILY}(*))", "count", {}, [WD_DAY4], gf.LATER, hand="9",
            hide=[(DAILY, DAY4)])
eval_vector("formula-eval/withdrawn-slice-sum", "R1: the same slice summed: 118 - 15 = 103; the withdrawn reading is "
            "not a member and is not in the slice's lineage.", f"sum({DAILY}(*))", "EUR", {}, [WD_DAY4], gf.LATER,
            hand="103", hide=[(DAILY, DAY4)])
eval_vector("formula-eval/withdrawn-slice-before-asof", "R1: as of 2026-03-10 the withdrawal (2026-03-20) is not yet "
            "the reading's latest version: all 10 are members.", f"count({DAILY}(*))", "count", {}, [WD_DAY4],
            "2026-03-10T18:00:00.000000Z", hand="10")
eval_vector("invalid/formula-eval-withdrawn-at", "R1: at(slice, d) of a withdrawn reading is absent: not a member, so "
            "no member qualifies.", f"at({DAILY}(*), d)", "EUR", {"d": (gf.DATEA, D("2026-03-04"))}, [WD_DAY4],
            gf.LATER, error="E_FORMULA_ABSENT")
eval_vector("formula-eval/withdrawn-at-otherwise", "R1: the absence of a withdrawn member is catchable: "
            "otherwise(at(slice, d), -1) is -1.", f"otherwise(at({DAILY}(*), d), -1)", "EUR",
            {"d": (gf.DATEA, D("2026-03-04"))}, [WD_DAY4], gf.LATER, hand="-1",
            hide=[(DAILY, DAY4)])
eval_vector("formula-eval/withdrawn-slice-others-unchanged", "R1: a withdrawal of one reading leaves the others: at "
            "2026-03-05 the slice still answers 11.", f"at({DAILY}(*), d)", "EUR", {"d": (gf.DATEA, D("2026-03-05"))},
            [WD_DAY4], gf.LATER, hand="11",
            hide=[(DAILY, DAY4)])

# ---------------------------------------------------------------------------
# R3: whatif (5.9). A slice override `members` replaces the slice's whole member set, which may be empty.

CONVERT_CELL = g60.CONVERT_CELL
FX_18, SLICE_FX = g60.FX_18, g60.SLICE_FX
TOTAL_CELL = {"args": {}, "fn": "total", "fn_hash": canon.sha256_hex(b"a function summing the fx_rate slice"),
              "ns": "calc.example.net"}


def members_override(*pairs, slice=SLICE_FX):
    """{"slice", "members": [{"cell", "value"}, ...]}, the members sorted by cell id (5.9, R3)."""
    return {"members": sorted(({"cell": c, "value": v} for c, v in pairs), key=lambda m: cell_id(m["cell"])),
            "slice": slice}


OV_MEM_TWO = members_override((FX_CELL, N("1.1")), (FX_18, N("1.2")))
OV_MEM_ONE = members_override((FX_18, N("1.2")))
OV_MEM_EMPTY = members_override()


def scenario_vector(id_, why, cell, value, overrides, request=None, **extra):
    request = request or g60.whatif_request(cell, overrides)
    envelope(id_, why, g60.scenario(cell, value, overrides, **extra), 200, request=request, outcome="scenario")


scenario_vector("envelope/scenario-slice-members", "R3: a scenario with a slice override `members`: the whole member "
                "set is replaced by two cells, echoed as {slice, members}, the members sorted by cell id.",
                FX_18, "1.2", [OV_MEM_TWO])
scenario_vector("envelope/scenario-slice-members-one", "R3: a replacement with one member; the cell asked is that "
                "member and answers its override value.", FX_18, "1.2", [OV_MEM_ONE])
scenario_vector("envelope/scenario-slice-members-empty", "R3: the empty replacement: `members` is present and empty in "
                "the echo (never omitted), and the slice read by a function is empty: sum is 0.", TOTAL_CELL, "0",
                [OV_MEM_EMPTY])
OV_VALUE = g60.value_override(GBP_CELL, "0.9")  # another cell than the members': no cell is overridden twice
MIXED = sorted([OV_VALUE, OV_MEM_TWO], key=lambda o: cell_id(o["cell"]) if "cell" in o else cell_id(o["slice"]))
scenario_vector("envelope/scenario-slice-members-with-value", "R3: a value override and a members override together, "
                "sorted by their cell or slice id.", CONVERT_CELL, "120", MIXED)
OTHER_SLICE = SLICE_FX | {"args": SLICE_FX["args"] | {"quote": S("GBP")}}
GBP_18 = GBP_CELL | {"args": GBP_CELL["args"] | {"date": D("2024-03-18")}}
MIXED_SLICES = sorted([OV_MEM_ONE, members_override((GBP_18, N("0.9")), slice=OTHER_SLICE)],
                      key=lambda o: cell_id(o["slice"]))
scenario_vector("envelope/scenario-slice-members-two-slices", "R3: two slices replaced, sorted by slice id.",
                CONVERT_CELL, "120", MIXED_SLICES)
OV_ADD = {"add": [{"cell": FX_18, "value": N("1.2")}], "remove": [], "slice": SLICE_FX}
scenario_vector("envelope/scenario-slice-add-unchanged", "R3: the add and remove form is unchanged: the echo has add "
                "and remove, sorted, present even when empty, and no `members`.", FX_18, "1.2", [OV_ADD])

SC_REQ = g60.whatif_request(FX_18, [OV_MEM_TWO])
SC_OK = g60.scenario(FX_18, "1.2", [OV_MEM_TWO])["scenario"]
for name, why, overrides, request in [
    ("members-unsorted", "The echo's members are in another order than the request's: members are sorted by cell id.",
     [dict(OV_MEM_TWO, members=OV_MEM_TWO["members"][::-1])], SC_REQ),
    ("members-missing-when-empty", "The request replaced the set with the empty one: the echo has `members`, empty, "
     "not nothing.", [{"slice": SLICE_FX}], g60.whatif_request(TOTAL_CELL, [OV_MEM_EMPTY])),
    ("members-as-add", "The echo gives the members as `add` and `remove`: it is not the request's override.",
     [{"add": OV_MEM_TWO["members"], "remove": [], "slice": SLICE_FX}], SC_REQ),
    ("members-with-add", "An echo with both `members` and `add` (members excludes add and remove).",
     [dict(OV_MEM_TWO, add=[], remove=[])], SC_REQ),
    ("members-wrong-value", "The echo's member value differs from the request's.",
     [members_override((FX_CELL, N("1.1")), (FX_18, N("1.3")))], SC_REQ),
    ("members-extra-member", "The echo has a member the request did not.",
     [members_override((FX_CELL, N("1.1")), (FX_18, N("1.2")), (FX_CELL | {"args": FX_CELL["args"] | {"date": D("2024-03-19")}}, N("1.3")))],
     SC_REQ),
    ("members-empty-for-two", "The request had two members and the echo none: the override is not the request's.",
     [OV_MEM_EMPTY], SC_REQ),
    ("add-for-members", "The request replaced the set (`members`), the echo is the add and remove form.",
     [OV_ADD], SC_REQ),
]:
    scen = {"outcome": "scenario", "scenario": dict(SC_OK, overrides=overrides)}
    if name == "members-missing-when-empty":
        scen = {"outcome": "scenario", "scenario": dict(g60.scenario(TOTAL_CELL, "0", [OV_MEM_EMPTY])["scenario"],
                                                        overrides=overrides)}
    envelope(f"invalid/envelope-scenario-{name}", "R3: " + why, scen, 200, "E_ENVELOPE", request=request)

# bad_request answers at the whatif endpoint (5.5, 5.9). The request description cannot carry `members` with `add`
# (that is a malformed description, the caller's error), so those two answers have a description without overrides.
BARE = {"asof": ASOF, "cell_id": cell_id(FX_18)}
envelope("envelope/whatif-bad-request-members-with-add", "R3: a slice override with `members` and `add` is a "
         "bad_request with E_SLICE_MEMBER: members excludes add and remove (5.9). The request description carries no "
         "overrides: it could not hold both.", {"error": "E_SLICE_MEMBER", "outcome": "bad_request"}, 400, request=BARE,
         outcome="bad_request")
envelope("envelope/whatif-bad-request-members-with-remove", "R3: `members` with `remove`: E_SLICE_MEMBER likewise.",
         {"error": "E_SLICE_MEMBER", "outcome": "bad_request"}, 400, request=BARE, outcome="bad_request")
NOT_A_MEMBER = members_override((GBP_18, N("0.9")))  # a GBP cell is not in the EUR/USD slice
envelope("envelope/whatif-bad-request-members-not-member", "R3: every cell of `members` must be a member of the slice "
         "by its arguments: a GBP cell in the EUR/USD slice is E_SLICE_MEMBER.",
         {"error": "E_SLICE_MEMBER", "outcome": "bad_request"}, 400, request=g60.whatif_request(FX_18, [NOT_A_MEMBER]),
         outcome="bad_request")

# ---------------------------------------------------------------------------
# R3: a test's case hash (7.3) takes `inputs` as the JSON value it is: a slice override in a test's inputs is
# {"members": {<cell call>: <typed scalar>}} beside the existing {"add": {...}, "remove": [...]}, and a cell may give
# {"withdrawn": "<reason>"} in place of a typed scalar (R1).

TEST_CALL = 'calc.example.net/fx_mean(base: "EUR", quote: "USD")'
SLICE_CALL = 'rates.example.org/fx_rate(base: "EUR", date: *, quote: "USD")'
CELL_A = 'rates.example.org/fx_rate(base: "EUR", date: 2024-03-15, quote: "USD")'
CELL_B = 'rates.example.org/fx_rate(base: "EUR", date: 2024-03-18, quote: "USD")'
CASES = {}


def case_vector(slug, why, inputs):
    test = {"asof": ASOF, "call": TEST_CALL, "expect": N("1.15")}
    if inputs is not None:
        test["inputs"] = inputs
    canonical = canon.jcs(test)
    digest = canon.sha256_hex(canonical)
    CASES[slug] = digest[:16]
    add(f"jcs/test-case-id-{slug}", "jcs", f"R3: The case of a test_case cell (7.3) is the first 16 hex digits of the "
        f"SHA-256 of the test's JCS: here {digest[:16]}. {why}", text(test), canonical=canonical.decode(), sha256=digest)


case_vector("inputs-none", "The test has no inputs (the control: it differs from every one below).", None)
case_vector("inputs-members", "inputs replaces the slice's whole member set with two cells.",
            {SLICE_CALL: {"members": {CELL_A: N("1.1"), CELL_B: N("1.2")}}})
case_vector("inputs-members-empty", "inputs replaces the member set with the empty one.",
            {SLICE_CALL: {"members": {}}})
case_vector("inputs-add", "The same two cells as `add`: a different case from the members form.",
            {SLICE_CALL: {"add": {CELL_A: N("1.1"), CELL_B: N("1.2")}}})
case_vector("inputs-remove", "`remove` of one cell: a different case again.", {SLICE_CALL: {"remove": [CELL_A]}})
case_vector("inputs-members-one", "One member only: a different case from the two-member replacement.",
            {SLICE_CALL: {"members": {CELL_B: N("1.2")}}})
case_vector("inputs-withdrawn", "A cell given as withdrawn, `{\"withdrawn\": \"<reason>\"}` in place of a typed scalar "
            "(R1).", {CELL_A: {"withdrawn": "published in error"}})
case_vector("inputs-withdrawn-in-members", "A withdrawn cell beside a member: it enters the hash as the JSON value it "
            "is.", {CELL_A: {"withdrawn": "published in error"}, SLICE_CALL: {"members": {CELL_B: N("1.2")}}})


def main():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids)), "duplicate ids"
    assert len(set(CASES.values())) == len(CASES), "case ids must differ"
    for vec in VECTORS:
        path = OUT / f"{vec['id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(vec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    valid = sum(v["valid"] for v in VECTORS)
    print(f"wrote {len(VECTORS)} vectors ({valid} valid, {len(VECTORS) - valid} invalid)")


if __name__ == "__main__":
    main()
