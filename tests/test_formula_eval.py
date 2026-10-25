# SPDX-License-Identifier: Apache-2.0
"""Brief tests 6-9 on the reference evaluator, and the evaluation vectors.

6: fib(90) in formula gives the exact decimal; a bootstrapped curve over ten tenors evaluates and
   each tenor is a memoised cell.
7: a weighted mean over 1,000 stations records one entry per slice (two: temperatures and weights;
   accepted by the user); the receipt verifies at recomputed; a correction to one station changes
   the temperature entry; the old receipt still verifies; the members are fetchable from the slice.
8: last_before with a staleness bound over unsynchronised sensors returns the right reading or
   no value; latest is a pure function of the slice and the asof, shown at two asofs.
9: a running total over 3,650 daily values is one cell per day with slice lineage; a correction to
   one day changes only the cells on and after it.
"""

import json
import unittest

from helpers import ROOT, canon  # noqa: F401
import formula  # noqa: E402
import gen_formula as G  # noqa: E402

EVAL = [v for v in canon.load_vectors() if v["kind"] == "formula-eval"]


def S(v):
    return {"type": "string", "value": v}


def N(v):
    return {"type": "number", "value": v}


def D(v):
    return {"type": "date", "value": v}


def I(v):
    return {"type": "instant", "value": v}


def resolver(world, descriptor, value, lineage=None):
    rec = {"descriptor": descriptor, "inputs": dict(world.receipts), "manifests": dict(world.manifests), "value": value}
    if lineage is not None:
        rec["lineage"] = lineage
    return rec


class Fib(unittest.TestCase):
    def test_fib_90_is_exact(self):
        world = formula.world_of(G.world_fib())
        a = world.get(G.FIB, {"n": N("90")}, G.LATER)
        self.assertEqual(a.receipt["value"], "2880067194370816120")
        self.assertEqual(world.evaluations, 91)  # fib(0) .. fib(90), each once: memoised cells
        self.assertEqual(len(a.receipt["inputs"]), 2)  # fib(89) and fib(88)
        self.assertEqual(a.receipt["asof"], G.BOUND)  # the binding start: no input has a later asof
        r = canon.verify_receipt(a.text.encode(), G.KEYS, resolver(world, world.functions[G.FIB]["descriptor"],
                                                                    N("2880067194370816120")))
        self.assertEqual(r["level"], "recomputed")

    def test_bootstrapped_curve(self):
        world = formula.world_of(G.world_curve())
        a = world.get(G.DF, {"tenor": N("10")}, G.LATER)
        self.assertEqual(world.evaluations, 10)  # each tenor is one memoised cell
        for n in range(1, 11):
            b = world.get(G.DF, {"tenor": N(str(n))}, G.LATER)
            entries = b.receipt["inputs"]
            slices = [e for e in entries if e.startswith("slice:")]
            self.assertEqual(len(slices), 0 if n == 1 else 1)
            if n > 1:
                self.assertEqual(len(json.loads(world.manifests[slices[0]])["members"]), n - 1)
        self.assertEqual(world.evaluations, 10)  # the second pass recomputed nothing
        self.assertEqual(a.receipt["value"], G.expected_df(10))


class WeightedMean(unittest.TestCase):
    def test_one_entry_per_slice_verifies_and_dirties(self):
        spec = G.world_weighted(1000)
        world = formula.world_of(spec)
        a = world.get(G.WMEAN, {"date": D("2026-03-01")}, G.LATER)
        self.assertEqual(len(a.receipt["inputs"]), 2)
        self.assertTrue(all(e.startswith("slice:") for e in a.receipt["inputs"]))
        manifests = [json.loads(world.manifests[e]) for e in a.receipt["inputs"]]
        self.assertEqual(sorted(len(m["members"]) for m in manifests), [1000, 1000])
        for e, m in zip(a.receipt["inputs"], manifests):  # the members are fetchable from the slice
            self.assertEqual(canon.slice_entry(m["slice"], m["members"]), e)
            for h in m["members"]:
                self.assertEqual(canon.receipt_hash(json.loads(world.receipts[h])), h)
        descriptor = world.functions[G.WMEAN]["descriptor"]
        value = {"type": "number", "value": a.receipt["value"]}
        r = canon.verify_receipt(a.text.encode(), G.KEYS, resolver(world, descriptor, value))
        self.assertEqual(r["level"], "recomputed")

        world.add_receipt(G.weighted_correction())  # one station corrected
        b = world.get(G.WMEAN, {"date": D("2026-03-01")}, G.AFTER_CORRECTION)
        self.assertNotEqual(b.receipt["value"], a.receipt["value"])
        changed = set(a.receipt["inputs"]) ^ set(b.receipt["inputs"])
        self.assertEqual(len(changed), 2)  # the temperature entry; the weights entry is unchanged
        self.assertEqual(len({e.split(":")[1] for e in changed}), 1)  # the same slice, other members
        r = canon.verify_receipt(a.text.encode(), G.KEYS, resolver(world, descriptor, value))
        self.assertEqual(r["level"], "recomputed")  # the old receipt still verifies


class Weather(unittest.TestCase):
    def test_last_before_with_a_staleness_bound(self):
        world = formula.world_of(G.world_weather())
        for station, t, expected in G.WEATHER_CASES:
            with self.subTest(station=station, t=t):
                if expected is None:
                    with self.assertRaises(formula.FormulaError) as e:
                        world.get(G.TEMP_AT, {"station": S(station), "t": I(t)}, G.LATER)
                    self.assertEqual(e.exception.code, "E_FORMULA_ABSENT")
                else:
                    a = world.get(G.TEMP_AT, {"station": S(station), "t": I(t)}, G.LATER)
                    self.assertEqual(a.receipt["value"], expected)
                    entry = a.receipt["inputs"][0]
                    window = json.loads(world.manifests[entry])["slice"]["args"]["t"]
                    self.assertEqual(window["hi"], t)  # the bound narrowed the recorded slice

    def test_latest_is_a_function_of_the_slice_and_the_asof(self):
        world = formula.world_of(G.world_weather())
        early = world.get(G.LATEST, {"station": S("kew")}, G.BEFORE_LATE_SAMPLE)
        again = formula.world_of(G.world_weather()).get(G.LATEST, {"station": S("kew")}, G.BEFORE_LATE_SAMPLE)
        self.assertEqual(early.text, again.text)  # the same asof: the same receipt, byte for byte
        late = world.get(G.LATEST, {"station": S("kew")}, G.LATER)
        self.assertNotEqual(early.receipt["value"], late.receipt["value"])  # a late sample changed the choice
        self.assertLessEqual(early.receipt["asof"], G.BEFORE_LATE_SAMPLE)
        descriptor = world.functions[G.LATEST]["descriptor"]
        for a in (early, late):
            r = canon.verify_receipt(a.text.encode(), G.KEYS,
                                     resolver(world, descriptor, {"type": "number", "value": a.receipt["value"]}))
            self.assertEqual(r["level"], "recomputed")

    def test_real_time_mean_at_a_cadence(self):
        world = formula.world_of(G.world_weather())
        a = world.get(G.MEAN_TEMP, {"t": I("2026-03-01T10:08:00.000000Z")}, G.LATER)
        self.assertEqual(a.receipt["value"], "10.475")
        self.assertEqual(len(a.receipt["inputs"]), 1)


class RunningTotal(unittest.TestCase):
    def test_one_cell_per_day_and_a_correction_dirties_only_later_days(self):
        days = 3650
        spec = G.world_running(days)
        world = formula.world_of(spec)
        sample = [0, 1, 999, 1000, 1001, 2500, days - 1]
        before = {}
        for i in sample:
            d = G.day(i)
            a = world.get(G.RUNNING, {"date": D(d)}, G.LATER)
            self.assertEqual(len(a.receipt["inputs"]), 1)  # one slice entry, not a recurrence chain
            entry = a.receipt["inputs"][0]
            self.assertEqual(len(json.loads(world.manifests[entry])["members"]), i + 1)
            self.assertEqual(a.receipt["value"], str(G.running_expected(i)))
            before[i] = a.hash
        world.add_receipt(G.running_correction(1000))
        for i in sample:
            a = world.get(G.RUNNING, {"date": D(G.day(i))}, G.AFTER_CORRECTION)
            if i < 1000:
                self.assertEqual(a.hash, before[i], f"day {i} is before the correction")
            else:
                self.assertNotEqual(a.hash, before[i], f"day {i} is on or after the correction")


class TimeAndSupersession(unittest.TestCase):
    def test_asof_dependent_receipts_take_the_evaluation_asof(self):
        world = formula.world_of(G.world_weather())
        a = world.get(G.FRESH, {"station": S("kew")}, "2026-03-01T10:09:00.000000Z")
        b = world.get(G.FRESH, {"station": S("kew")}, "2026-03-01T10:10:00.000000Z")
        self.assertEqual(a.receipt["asof"], "2026-03-01T10:09:00.000000Z")
        self.assertEqual(b.receipt["asof"], "2026-03-01T10:10:00.000000Z")
        self.assertNotEqual(a.hash, b.hash)
        with self.assertRaises(formula.FormulaError) as e:  # the reading is now older than the bound
            world.get(G.FRESH, {"station": S("kew")}, "2026-03-01T11:00:00.000000Z")
        self.assertEqual(e.exception.code, "E_FORMULA_ABSENT")

    def test_backdated_correction_is_reported_as_superseded(self):
        spec = G.world_supersede()
        world = formula.world_of(spec)
        a = world.get(G.TOTAL, {"item": S("bolt")}, G.LATER)
        descriptor = world.functions[G.TOTAL]["descriptor"]
        world.add_receipt(G.backdated_correction())
        b = world.get(G.TOTAL, {"item": S("bolt")}, a.receipt["asof"])  # re-evaluated at the receipt's asof
        self.assertNotEqual(a.receipt["value"], b.receipt["value"])
        rec = resolver(world, descriptor, {"type": "number", "value": b.receipt["value"]}, b.receipt["inputs"])
        r = canon.verify_receipt(a.text.encode(), G.KEYS, rec)
        self.assertEqual((r["level"], r.get("code")), ("signed", "E_INPUT_SUPERSEDED"))
        rec.pop("lineage")
        with self.assertRaises(canon.DatumeshError) as e:
            canon.verify_receipt(a.text.encode(), G.KEYS, rec)
        self.assertEqual(e.exception.code, "E_VALUE_MISMATCH")

    def test_faults_give_no_value_with_the_fault_code(self):
        world = formula.world_of(G.world_fib())
        with self.assertRaises(formula.FormulaError) as e:
            world.get(G.RATIO, {"x": N("1"), "y": N("0")}, G.LATER)
        self.assertEqual(e.exception.code, "E_FORMULA_DIV_ZERO")
        body = json.dumps({"outcome": "not_covered", "fault": e.exception.code})
        self.assertEqual(canon.check_envelope(404, body.encode(), {}, {"cell_id": "0" * 64})["outcome"], "not_covered")


class EvalVectors(unittest.TestCase):
    def test_every_vector_passes(self):
        for vec in EVAL:
            with self.subTest(vec["id"]):
                self.assertEqual(canon.check_vector(vec), [])

    def test_counts_and_coverage(self):
        self.assertGreaterEqual(len(EVAL), 100)
        used = {v["error"] for v in EVAL if not v["valid"]}
        self.assertEqual(set(formula.EVAL_CODES) - used, set())

    def test_valid_vectors_record_lineage_and_times(self):
        for vec in EVAL:
            if vec["valid"]:
                with self.subTest(vec["id"]):
                    for field in ("value", "lineage", "tx", "receipt_asof", "fuel_used", "receipt_hash"):
                        self.assertIn(field, vec)


if __name__ == "__main__":
    unittest.main()


class ReferenceDefects(unittest.TestCase):
    """Defects the independent Rust crate found in the reference (its SPEC-FINDINGS.md, E1-E4)."""

    SIG = {"args": {"a": {"type": "number", "unit": "1", "valid": False}, "flag": {"type": "boolean", "valid": False},
                    "s": {"type": "string", "valid": False}, "d": {"type": "date", "valid": True}},
           "order": ["a", "flag", "s", "d"], "returns": "string"}

    def code(self, source, returns="string", args=None):
        sig = dict(self.SIG, returns=returns)
        try:
            d = formula.define("calc.example.net/f", sig, source, {"functions": {}})
            w = formula.World({"calc.example.net/f": {"descriptor": d, "bound": G.BOUND}})
            values = {"a": N("1"), "flag": {"type": "boolean", "value": True}, "s": S("Datumesh"), "d": D("2026-03-02")}
            values.update(args or {})
            return w.get("calc.example.net/f", values, G.LATER).receipt["value"]
        except formula.FormulaError as e:
            return e.code

    def test_e1_if_with_four_arguments(self):
        self.assertEqual(self.code("if(flag, s, s, s)"), "E_FORMULA_ARITY")

    def test_e2_non_integer_where_an_integer_is_required(self):
        for source, returns in [('text(find("m", s, start: 1.5))', "string"), ("substr(s, 1.5, 1)", "string"),
                                ("text(round(a, 1.5))", "string"), ("fixed(a, 1.5)", "string"),
                                ("date(2024, 2.5, 1)", "date"), ("add_days(d, 1.5)", "date"),
                                ("add_months(d, 1.5)", "date")]:
            with self.subTest(source):
                self.assertEqual(self.code(source, returns), "E_FORMULA_DOMAIN")

    def test_e3_fixed_respects_the_string_limit(self):
        self.assertEqual(self.code("fixed(a, 2000)"), "E_FORMULA_RANGE")
        self.assertEqual(len(self.code("fixed(a, 1000)")), 1002)

    def test_e4_long_operator_chains(self):
        """Chains up to the node limit compile and evaluate; beyond it, E_FORMULA_LIMIT."""
        sig = {"args": {"a": {"type": "number", "unit": "1", "valid": False}}, "order": ["a"],
               "returns": {"type": "number", "unit": "1"}}
        ok = " + ".join(["a"] * 20000)
        d = formula.define("calc.example.net/f", sig, ok, {"functions": {}})
        w = formula.World({"calc.example.net/f": {"descriptor": d, "bound": G.BOUND}})
        self.assertEqual(w.get("calc.example.net/f", {"a": N("1")}, G.LATER).receipt["value"], "20000")
        with self.assertRaises(formula.FormulaError) as e:
            formula.define("calc.example.net/f", sig, " + ".join(["a"] * 40000), {"functions": {}})
        self.assertEqual(e.exception.code, "E_FORMULA_LIMIT")


class ReceiptConventions(unittest.TestCase):
    """SPEC 11: the computed receipt behind a formula-eval or excel vector's receipt_hash, rebuilt
    from the conventions the text states (the Rust crate's SPEC-FINDINGS.md, A1 and A2)."""

    def test_every_receipt_hash_follows_the_stated_conventions(self):
        engine = f"mesh.example.net#{formula.host_key_id('mesh.example.net')}"
        self.assertEqual(engine, "mesh.example.net#cd42547c321bfc08")
        checked = 0
        for vec in [v for v in canon.load_vectors() if v["kind"] in ("formula-eval", "excel") and v["valid"]]:
            fq = vec["cell"]["fn"]
            if vec["kind"] == "excel":
                body = vec["body"]
                inputs = sorted({x for x in vec["world"]["functions"]})
                descriptor = {"code": {"body": body, "lang": "formula"}, "inputs": inputs, "signature": vec["signature"]}
            else:
                descriptor = vec["world"]["functions"][fq]["descriptor"]
            ns, _, fn = fq.rpartition("/")
            sig = descriptor["signature"]["args"]
            receipt = {
                "asof": vec["receipt_asof"],
                "cell": {"args": vec["cell"]["args"], "fn": fn, "fn_hash": canon.function_hash(descriptor), "ns": ns},
                "computed_by": engine, "inputs": vec["lineage"], "issued": max(vec["receipt_asof"], "2020-01-01T00:00:00.000000Z"),
                "licence": "CC0-1.0", "proto": "datumesh/1", "publisher": ns,
                "summary": "Computed by the Datumesh formula reference evaluator.", "tx": vec["tx"],
                "type": vec["value"]["type"], "valid": {k: v for k, v in vec["cell"]["args"].items() if sig[k]["valid"]},
                "value": vec["value"]["value"]}
            with self.subTest(vec["id"]):
                self.assertEqual(canon.receipt_hash(receipt), vec["receipt_hash"])
                checked += 1
        self.assertGreater(checked, 190)
