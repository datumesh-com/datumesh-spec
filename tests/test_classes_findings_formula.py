# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0, classes: clarifications from the formula library (BRIEF-spec-0.5.0-clarifications-2).

The formula library implemented spec-0.5.0 from the text, the reference run as a black box
(datumesh-formula SPEC-FINDINGS.md, sections H and I). Each point below makes the text say one thing
and the reference and the vectors agree with it.

H1. A method rebound since define, at evaluation (15.8, 15.11, 16.6).
H2. A well-formed key of the class not canonical under the class's rules (16.6).
H3. A quoted key encoding in a class-typed position (16.5, 16.3, 5.8).
H4. A call that needs a now and has none (16.7).
H5, I1, I2. The details of `resolved` (16.7).
H6. The order of checks in a method call (5.8).
H7. In a call, the lookup method on an object, and an extension method whose arguments don't match.
H10. 15.6's round trip and the dispatch node.
I3. The parent's name for `super` (16.1, 16.3).
I4. What a dispatch relies on (16.6, 8.2).
"""

import copy
import unittest

from helpers import ROOT, canon
import class_world as W
import formula as F

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
FX, CCY, CUR, NDF, BOND = W.FX, W.CCY_PAIR, W.CURRENCY, W.NDF, W.BOND
NUM = {"type": "number", "unit": "1"}
T2 = "2026-04-01T00:00:00.000000Z"


def section(start, end):
    return SPEC[SPEC.index(start):SPEC.index(end)]


S58 = section("### 5.8 Calls", "## 6. Canonical encoding")
S156 = section("### 15.6 The printer", "### 15.7 Built-ins")
S158 = section("### 15.8 Types and checking", "### 15.9 Numbers")
S1511 = section("### 15.11 Error codes", "### 15.12 Evaluation")
S161 = section("### 16.1 The class descriptor", "### 16.2 Define and flattening")
S163 = section("### 16.3 Method calls", "### 16.4 Key normalisation")
S165 = section("### 16.5 Object keys", "### 16.6 Bounded dispatch")
S166 = section("### 16.6 Bounded dispatch", "### 16.7 Defaults")
S167 = section("### 16.7 Defaults", "### 16.8 describe")
S14 = section("### spec-0.5.0 (in progress, part one)", "### spec-0.4.3")


def check_vectors(test, ids):
    for vid in ids:
        with test.subTest(vid):
            test.assertTrue(vid in VECTORS, f"no vector {vid}")
            test.assertEqual(canon.check_vector(VECTORS[vid]), [])


def call(text, env=None):
    try:
        return canon.parse_call(text, env or W.call_env())
    except canon.DatumeshError as e:
        return e.code


def body(src, sig=None, method_of=None, env=None):
    s = sig or {"args": {}, "order": [], "returns": NUM}
    e = env or W.env("calc.example.net/e", s, method_of)
    try:
        return F.compile(src, e).body
    except F.FormulaError as err:
        return err.code


RECEIPTS = [W.price_receipt(BOND, "XS0001", "101.25"), W.price_receipt(W.SWAP, "XS0002", "99.5")]
OTHER_PRICE = dict(W.BOND_PRICE, code={"body": "other prices\n", "lang": "stored"})  # another hash


def world(change=None):
    spec = copy.deepcopy(W.world_spec(RECEIPTS))
    if change:
        change(spec)
    return spec


def evaluate(spec, isin='calc.example.net/bond(isin:"XS0001")'):
    args = {"date": W.D(W.DAY), "instrument": W.S(isin)}
    try:
        return F.evaluate_vector({"cell": {"args": args, "fn": "calc.example.net/price_of"}, "asof": W.ASOF},
                                 F.world_of(spec))
    except F.FormulaError as e:
        return e


class H1MethodReboundSinceDefine(unittest.TestCase):
    def test_bound_to_another_hash_is_dispatch(self):
        def rebind(spec):
            spec["functions"][f"{BOND}/price"]["descriptor"] = OTHER_PRICE
        e = evaluate(world(rebind))
        self.assertIsInstance(e, F.FormulaError)
        self.assertEqual(e.code, "E_FORMULA_DISPATCH")
        self.assertFalse(F._no_value(e), "the mesh's failure, not a fault")

    def test_rebound_later_is_dispatch(self):
        def rebind(spec):
            spec["functions"][f"{BOND}/price"] = [spec["functions"][f"{BOND}/price"],
                                                  {"bound": T2, "descriptor": OTHER_PRICE}]
        self.assertEqual(evaluate(world(rebind)).code, "E_FORMULA_DISPATCH")

    def test_not_bound_is_unresolved(self):
        def later_method(spec):
            spec["functions"][f"{BOND}/price"]["bound"] = "2026-07-01T00:00:00.000000Z"

        def later_class(spec):
            spec["classes"][BOND]["bound"] = "2026-07-01T00:00:00.000000Z"
        for change in (later_method, later_class):
            with self.subTest(change.__name__):
                e = evaluate(world(change))
                self.assertEqual(e.code, "E_FORMULA_UNRESOLVED")
                self.assertFalse(F._no_value(e))

    def test_consistent_rebinding_reads_the_new_method(self):
        def rebind(spec):
            spec["functions"][f"{BOND}/price"] = [spec["functions"][f"{BOND}/price"],
                                                  {"bound": T2, "descriptor": OTHER_PRICE}]
            desc = copy.deepcopy(spec["classes"][BOND]["descriptor"])
            desc["methods"]["price"] = canon.function_hash(OTHER_PRICE)
            spec["classes"][BOND] = [spec["classes"][BOND], {"bound": T2, "descriptor": desc}]
        self.assertEqual(evaluate(world(rebind)).code, "E_FORMULA_NOT_COVERED")

    def test_vector(self):
        check_vectors(self, ["invalid/formula-eval-class-dispatch-rebound"])
        self.assertEqual(VECTORS.get("invalid/formula-eval-class-dispatch-rebound", {}).get("error", {}), "E_FORMULA_DISPATCH")

    def test_text(self):
        for s in (S166, S1511):
            self.assertIn("E_FORMULA_UNRESOLVED", s)
        self.assertIn("not the define-time `E_FORMULA_METHOD`", S166)
        self.assertIn("invalid/formula-eval-class-dispatch-rebound", S166)
        self.assertIn("16.6", S158)


class H2KeyNotCanonicalForItsClass(unittest.TestCase):
    def test_reference(self):
        e = evaluate(world(), 'calc.example.net/bond(isin:"xs0001")')
        self.assertEqual(e.code, "E_FORMULA_KEY")
        self.assertTrue(F._no_value(e), "a fault")

    def test_text(self):
        self.assertIn("is still a key of that class", S166)
        self.assertIn("key names and types", S166)


class H3QuotedEncodingInClassTypedPosition(unittest.TestCase):
    LOW = f'"{CUR}(code:""eur"")"'
    UP = f'"{CUR}(code:""USD"")"'
    WRONG = f'"{CUR}(iso:""EUR"")"'

    def test_body(self):
        self.assertEqual(body(f"{CCY}({self.LOW}, {self.UP}).rate(2026-03-16)"), "E_FORMULA_KEY")
        self.assertEqual(body(f"{CCY}/rate({self.LOW}, {self.UP}, 2026-03-16)"), "E_FORMULA_KEY")
        self.assertEqual(body(f"{CCY}({self.WRONG}, {self.UP}).rate(2026-03-16)"), "E_FORMULA_TYPE")
        self.assertIsInstance(body(f'{CCY}("{CUR}(code:""EUR"")", {self.UP}).rate(2026-03-16)'), str)
        self.assertFalse(body(f'{CCY}("{CUR}(code:""EUR"")", {self.UP}).rate(2026-03-16)').startswith("E_"))

    def test_object_literal_with_a_variable_key(self):
        self.assertEqual(body(f"{CCY}({CUR}(eur), {CUR}(USD)).rate(2026-03-16)"), "E_FORMULA_PLACEMENT")

    def test_call(self):
        self.assertEqual(call(f"{CCY}({self.LOW}, {self.UP}).rate(2026-03-16)"), "E_KEY_NORMALISATION")
        self.assertEqual(call(f"{CCY}/rate({self.LOW}, {self.UP}, 2026-03-16)"), "E_KEY_NORMALISATION")
        self.assertEqual(call(f"{CCY}({self.WRONG}, {self.UP}).rate(2026-03-16)"), "E_CANON_TYPE")
        ok = call(f'{CCY}("{CUR}(code:""EUR"")", {self.UP}).rate(2026-03-16)')
        self.assertEqual(ok["uri"], call(f"{CCY}({CUR}(EUR), {CUR}(USD)).rate(2026-03-16)")["uri"])

    def test_vectors(self):
        check_vectors(self, ["invalid/formula-class-quoted-key-not-canonical",
                             "invalid/call-class-quoted-key-normalisation"])
        self.assertEqual(VECTORS.get("invalid/formula-class-quoted-key-not-canonical", {}).get("error", {}), "E_FORMULA_KEY")
        self.assertEqual(VECTORS.get("invalid/call-class-quoted-key-normalisation", {}).get("error", {}), "E_KEY_NORMALISATION")

    def test_text(self):
        self.assertIn("exactly as an object literal is", S165)
        self.assertIn("`E_FORMULA_PLACEMENT`", S163)
        self.assertIn("a bare lowercase word as an object literal's key is a variable", S163)


class H4NoNow(unittest.TestCase):
    def test_reference(self):
        self.assertEqual(call("rates.example.org/fx_rate(EUR, GBP)"), "E_ARG_MISSING")
        self.assertEqual(call(f"{FX}[cable].rate(2026-03-16)", W.call_env(lookups=W.LOOKUPS)), "E_ARG_MISSING")
        self.assertIn("uri", call("rates.example.org/fx_rate(EUR, GBP)", W.call_env(now=W.ASOF)))

    def test_vectors(self):
        check_vectors(self, ["invalid/call-class-default-no-now", "invalid/call-class-lookup-no-now"])
        for vid in ("invalid/call-class-default-no-now", "invalid/call-class-lookup-no-now"):
            self.assertNotIn("now", VECTORS.get(vid, {}).get("env", {}))

    def test_text(self):
        self.assertIn("A mesh always answers with its own now", S167)
        self.assertIn("invalid/call-class-lookup-no-now", S167)


class H5I1I2Resolved(unittest.TestCase):
    def test_reference(self):
        env = W.call_env(aliases={"fx": FX}, lookups=W.LOOKUPS)
        r = call("@fx(EUR, USD).rate(2026-03-16)", env)["resolved"]
        self.assertEqual([x["from"] for x in r["resolutions"]], ["@fx", f"{FX}(...).rate"])
        self.assertNotIn("aliases_tx", r, "no snapshot known")
        r = call("@fx(EUR, USD).rate(2026-03-16)", W.call_env(aliases={"fx": FX}, aliases_tx=W.BOUND))["resolved"]
        self.assertEqual(r["aliases_tx"], W.BOUND)
        self.assertNotIn("resolved", call(f"{FX}/rate(EUR, USD, 2026-03-16)", W.call_env(aliases_tx=W.BOUND)))
        h = canon.function_hash(W.FX_RATE_D)
        r = call(f"@fr@{h}(EUR, GBP, 2026-03-16)", W.call_env(aliases={"fr": "rates.example.org/fx_rate"}))["resolved"]
        self.assertEqual(r["call"], f'rates.example.org/fx_rate@{h}(base: "EUR", date: 2026-03-16, quote: "GBP")')
        self.assertEqual(r["resolutions"], [{"from": "@fr", "kind": "alias", "to": "rates.example.org/fx_rate"}])
        r = call(f"{FX}(EUR, USD).calc.example.net/fx_extra/carry(2026-03-16)")["resolved"]
        self.assertEqual(r["resolutions"][0]["from"], f"{FX}(...).calc.example.net/fx_extra/carry")
        r = call("fx_rate(EUR, GBP)?asof=2026-03-16T18:00:00.000000Z",
                 W.call_env(aliases={"fx_rate": "rates.example.org/fx_rate"}))["resolved"]
        self.assertEqual([x["kind"] for x in r["resolutions"]], ["alias", "default"])

    def test_text(self):
        for phrase in ("alias, lookup, method, default", "present exactly when an alias was resolved",
                       "`resolved` is absent when nothing was resolved", "Every alias is a resolution",
                       "`<class full name>(...).<method as written>`"):
            with self.subTest(phrase):
                self.assertIn(phrase, S167)


class H6CheckOrder(unittest.TestCase):
    def test_reference(self):
        self.assertEqual(call(f"{FX}(EUR, usd).rate(notadate)"), "E_KEY_NORMALISATION")
        self.assertEqual(call(f"{FX}(eur, USD).rate()"), "E_KEY_NORMALISATION")

    def test_text(self):
        self.assertIn("The receiver is read first", S58)
        self.assertIn("normalisation included", S58)


class H7CallMethodCodes(unittest.TestCase):
    def test_reference(self):
        self.assertEqual(call(f"{FX}(EUR, USD).named(cable)"), VECTORS.get("invalid/call-class-no-method", {}).get("error", {}))
        self.assertEqual(call(f"{FX}(EUR, USD).named(cable)"), "E_NAME_UNBOUND")
        self.assertEqual(call(f"{FX}(EUR, USD).calc.example.net/price_of(2026-03-16)"), "E_ARG_UNKNOWN")
        self.assertEqual(call(f"{FX}(EUR, USD).calc.example.net/fx_extra/carry()"), "E_ARG_MISSING")
        self.assertEqual(call(f"{FX}(EUR, USD).calc.example.net/fx_extra/carry(2026-03-16, 1)"), "E_ARG_UNKNOWN")

    def test_vectors(self):
        ids = {"invalid/call-class-lookup-on-object": "E_NAME_UNBOUND",
               "invalid/call-class-extension-without-keys": "E_ARG_UNKNOWN",
               "invalid/call-class-extension-missing": "E_ARG_MISSING"}
        check_vectors(self, ids)
        for vid, c in ids.items():
            self.assertEqual(VECTORS.get(vid, {}).get("error", {}), c)

    def test_text(self):
        self.assertIn("the class's `lookup` method called on an object", S58)
        self.assertIn("does not take the class keys first", S58)


class H10RoundTrip(unittest.TestCase):
    def test_text(self):
        self.assertIn("but a dispatch", S156)
        self.assertIn("with the function's signature", S156)


class I3ParentName(unittest.TestCase):
    def test_reference(self):
        env = W.env(f"{NDF}/rate", W.RATE["signature"], NDF)
        self.assertFalse(body("super.rate(date) * 1", W.RATE["signature"], NDF, env).startswith("E_"))
        env = W.env(f"{NDF}/rate", W.RATE["signature"], NDF)
        del env["classes"][FX]  # no name bound to the parent's hash in the definer's environment
        self.assertEqual(body("super.rate(date) * 1", W.RATE["signature"], NDF, env), "E_CLASS_PARENT")
        self.assertEqual(body("super.rate(date)", W.RATE["signature"], FX), "E_FORMULA_METHOD")

    def test_text(self):
        self.assertIn("in the definer's environment at define", S163)
        self.assertIn("`E_CLASS_PARENT`", S163)
        self.assertIn("stays a hash", S161)


class I4DispatchReliance(unittest.TestCase):
    def test_reference(self):
        def rebind_class(spec):  # the same descriptor bound again later: not a candidate
            spec["classes"][BOND] = [spec["classes"][BOND], {"bound": T2, "descriptor": spec["classes"][BOND]["descriptor"]}]
        got = evaluate(world(rebind_class))
        self.assertEqual(got["receipt_asof"], "2026-03-16T16:00:00.000000Z")

    def test_text(self):
        self.assertIn("no separate class binding is read", S166)


class Record(unittest.TestCase):
    def test_section_14(self):
        self.assertIn("**Library findings (formula, spec-0.5.0)**", S14)
        part = S14[S14.index("**Library findings (formula, spec-0.5.0)**"):]
        for pid in ("H1", "H2", "H3", "H4", "H5", "H6", "H7", "H10", "I1", "I2", "I3", "I4"):
            with self.subTest(pid):
                self.assertIn(f"**{pid}", part)


if __name__ == "__main__":
    unittest.main()
