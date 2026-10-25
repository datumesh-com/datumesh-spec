# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.1: the six text-only items of the 1.3 report, as the reference applies them.

1. asof(c, T): the times, then the cell's arguments, then its name as of T.
2. Fixed transcendental fuel is charged at the call, before the arguments.
3. The members of a slice over a computed function are evaluated in key order; the first without
   a value ends the read, and no later member is evaluated or charged.
4. A rebound callee is checked against the binding seen at each read (as of the evaluation asof,
   or as of T in asof(c, T)); a callee not read does not make the evaluation fail.
5. Evaluation codes that are neither faults nor plain absence are the mesh's failures.
6. A value resting on a fault the formula caught (otherwise) counts, among its asof candidates,
   the latest input asof and binding start of the faulted evaluation.
"""

import unittest

from helpers import ROOT, canon  # noqa: F401
import formula  # noqa: E402
import gen_formula as G  # noqa: E402

A = "2026-05-01T00:00:00.000000Z"
REBOUND = "2026-04-01T00:00:00.000000Z"


def S(v):
    return {"type": "string", "value": v}


def N(v):
    return {"type": "number", "value": v}


def B(v):
    return {"type": "boolean", "value": v}


def num(unit):
    return {"type": "number", "unit": unit, "valid": False}


STR = {"type": "string", "valid": False}
V = "data.example.org/v"
V_EUR = G.stored({"item": STR}, ["item"], "EUR")
V_TEXT = G.stored({"item": STR}, ["item"], "string")  # the same name, rebound to another signature
F = "calc.example.net/g"


def world(body, args, returns="EUR", rebind=True, extra=None):
    """g reads v; v is bound to V_EUR, and from REBOUND to V_TEXT."""
    sig = {"args": args, "order": sorted(args), "returns": G.ret(returns)}
    g = formula.define(F, sig, body, {"functions": {V: V_EUR}})
    bindings = [{"bound": G.BOUND, "descriptor": V_EUR}]
    if rebind:
        bindings.append({"bound": REBOUND, "descriptor": V_TEXT})
    functions = {V: bindings, F: {"bound": G.BOUND, "descriptor": g}}
    functions.update(extra or {})
    receipts = [formula.stored_receipt(V_EUR, V, {"item": S("bolt")}, N("2.5"), "2026-02-01T09:00:00.000000Z"),
                formula.stored_receipt(V_TEXT, V, {"item": S("bolt")}, S("two and a half"), "2026-04-02T09:00:00.000000Z")]
    return formula.World(functions, receipts)


def get(w, args, asof=A, fuel=None):
    try:
        return w.get(F, args, asof, fuel=fuel).receipt
    except formula.FormulaError as e:
        return e.code


class Item1AsofOrder(unittest.TestCase):
    def test_arguments_before_the_name(self):
        late = "data.example.org/late"
        late_d = G.stored({"x": STR}, ["x"], "EUR")
        sig = {"args": {}, "order": [], "returns": G.ret("EUR")}
        g = formula.define(F, sig, "asof(data.example.org/late(x: text(1 / 0)), 2026-03-01T00:00:00.000000Z)",
                           {"functions": {late: late_d}})
        w = formula.World({late: {"bound": REBOUND, "descriptor": late_d}, F: {"bound": REBOUND, "descriptor": g}})
        self.assertEqual(get(w, {}), "E_FORMULA_DIV_ZERO")  # not E_FORMULA_UNRESOLVED: the arguments come first
        g2 = formula.define(F, sig, 'asof(data.example.org/late(x: "a"), 2026-03-01T00:00:00.000000Z)',
                            {"functions": {late: late_d}})
        w2 = formula.World({late: {"bound": REBOUND, "descriptor": late_d}, F: {"bound": REBOUND, "descriptor": g2}})
        self.assertEqual(get(w2, {}), "E_FORMULA_UNRESOLVED")  # the name as of T: no binding yet


class Item2FixedFuel(unittest.TestCase):
    def test_charged_before_the_arguments(self):
        sig = {"args": {}, "order": [], "returns": G.ret("1")}
        g = formula.define(F, sig, "ln(1 / 0)", {"functions": {}})
        w = formula.World({F: {"bound": G.BOUND, "descriptor": g}})
        self.assertEqual(get(w, {}, fuel=50), "E_FORMULA_BUDGET")  # 1 node + 80 for ln, before 1 / 0
        self.assertEqual(get(w, {}, fuel=100), "E_FORMULA_DIV_ZERO")


class Item3MemberOrder(unittest.TestCase):
    def test_key_order_and_the_first_fault_ends_the_read(self):
        recip = "math.example.net/recip"
        d = formula.define(recip, {"args": {"n": {"type": "number", "unit": "1", "valid": False,
                                                  "extent": {"hi": "3", "lo": "0"}}},
                                   "order": ["n"], "returns": G.ret("1")}, "1 / n", {"functions": {}})
        g = formula.define(F, {"args": {}, "order": [], "returns": G.ret("1")}, "otherwise(sum(math.example.net/recip(*)), 0)",
                           {"functions": {recip: d}})
        w = formula.World({recip: {"bound": G.BOUND, "descriptor": d}, F: {"bound": G.BOUND, "descriptor": g}})
        self.assertEqual(w.get(F, {}, A).receipt["value"], "0")
        evaluated = sorted(key[0] for key in w.memo)
        self.assertEqual(w.evaluations, 1)  # g; recip(0) faulted, recip(1..3) were never evaluated
        self.assertEqual(len(evaluated), 2)  # the memo holds g and the fault of recip(0) only
        self.assertEqual(w.fuel_used, 7)  # as formula-eval/member-fault-caught


class Item4Rebinding(unittest.TestCase):
    ARGS = {"flag": {"type": "boolean", "valid": False}, "s": STR}

    def test_a_callee_not_read_does_not_fail_the_evaluation(self):
        w = world("if flag then data.example.org/v(item: s) + 1 EUR else 0 EUR", self.ARGS)
        self.assertEqual(get(w, {"flag": B(False), "s": S("bolt")})["value"], "0")

    def test_a_read_checks_against_the_binding_it_sees(self):
        w = world("if flag then data.example.org/v(item: s) + 1 EUR else 0 EUR", self.ARGS)
        self.assertEqual(get(w, {"flag": B(True), "s": S("bolt")}), "E_FORMULA_TYPE")  # string + EUR
        self.assertEqual(get(w, {"flag": B(True), "s": S("bolt")}, asof="2026-03-15T00:00:00.000000Z")["value"], "3.5")

    def test_a_read_as_of_t_checks_against_the_binding_as_of_t(self):
        w = world("asof(data.example.org/v(item: s), 2026-03-15T00:00:00.000000Z) + 1 EUR", {"s": STR})
        self.assertEqual(get(w, {"s": S("bolt")})["value"], "3.5")  # v as of T is still the EUR function
        w2 = world("asof(data.example.org/v(item: s), 2026-04-15T00:00:00.000000Z) + 1 EUR", {"s": STR})
        self.assertEqual(get(w2, {"s": S("bolt")}), "E_FORMULA_TYPE")  # as of T it is the string function


class Item5Envelopes(unittest.TestCase):
    def test_only_faults_go_in_not_covered(self):
        for code in formula.EVAL_CODES + formula.DEFINE_CODES:
            body = ('{"fault": "%s", "outcome": "not_covered"}' % code).encode()
            ok = True
            try:
                canon.check_envelope(404, body, {}, {"cell_id": "0" * 64})
            except canon.DatumeshError:
                ok = False
            self.assertEqual(ok, code in formula.FAULT_CODES, code)


class Item6CaughtFault(unittest.TestCase):
    def test_the_faulted_evaluation_counts_among_the_asof_candidates(self):
        """h(k) reads a stored cell recorded late, then faults; g catches the absence. g's receipt
        asof is at least that cell's asof, so it recomputes at its own asof."""
        stored_fn = "data.example.org/w"
        w_d = G.stored({"k": num("1")}, ["k"], "1")
        h = "math.example.net/h"
        h_d = formula.define(h, {"args": {"k": {"type": "number", "unit": "1", "valid": False,
                                                "extent": {"hi": "1", "lo": "0"}}}, "order": ["k"], "returns": G.ret("1")},
                             "1 / (data.example.org/w(k: k) - data.example.org/w(k: k))", {"functions": {stored_fn: w_d}})
        g = formula.define(F, {"args": {}, "order": [], "returns": G.ret("1")}, "otherwise(sum(math.example.net/h(*)), 0)",
                           {"functions": {h: h_d}})
        late = "2026-03-20T12:00:00.000000Z"
        receipts = [formula.stored_receipt(w_d, stored_fn, {"k": N("0")}, N("5"), late),
                    formula.stored_receipt(w_d, stored_fn, {"k": N("1")}, N("6"), "2026-02-01T00:00:00.000000Z")]
        wd = formula.World({stored_fn: {"bound": G.BOUND, "descriptor": w_d}, h: {"bound": G.BOUND, "descriptor": h_d},
                            F: {"bound": G.BOUND, "descriptor": g}}, receipts)
        r = wd.get(F, {}, A).receipt
        self.assertEqual(r["value"], "0")
        self.assertEqual(r["inputs"], [])  # the failed read is in no lineage
        self.assertEqual(r["asof"], late)  # the faulted evaluation's input asof, not just the binding start


if __name__ == "__main__":
    unittest.main()
