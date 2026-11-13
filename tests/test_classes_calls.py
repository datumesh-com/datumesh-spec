# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0, classes (step 1.3b part A), second pair: method calls (16.3), dispatch (16.6),
defaults and short calls (16.7), in bodies and in requests (5.8).

The brief's test 2: for each example, the call form and the plain read give byte-identical
canonical cells and cell ids: here, identical canonical ASTs (so identical bodies, inputs and
function hashes) and identical cell URIs (so identical cell ids).
"""

import json
import unittest

from helpers import ROOT, canon
import class_world as W
import formula

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
E = "calc.example.net/e"


def sig(returns):
    return {"args": {}, "order": [], "returns": returns}


RATE_RET = W.RATE_RET
EQUIVALENT = W.EQUIVALENT

def code(fn, *args):
    try:
        return fn(*args)
    except (formula.FormulaError, canon.DatumeshError) as e:
        return e.code


class Equivalence(unittest.TestCase):
    def test_call_form_is_the_plain_read(self):
        for name, call, plain, ret, aliases in EQUIVALENT:
            with self.subTest(name):
                env = W.env(E, sig(ret), aliases=aliases)
                a, b = formula.compile(call, env), formula.compile(plain, env)
                self.assertEqual(canon.jcs(a.ast), canon.jcs(b.ast))
                self.assertEqual(a.body, b.body)
                self.assertEqual(a.inputs, b.inputs)

    def test_default_is_asof_dependent(self):
        c = formula.compile("rates.example.org/fx_rate(EUR, GBP)",
                            W.env(E, sig({"type": "number", "unit": {"of": "GBP", "per": "EUR"}})))
        self.assertTrue(c.asof_dependent)

    def test_vectors(self):
        for name, *_ in EQUIVALENT:
            with self.subTest(name):
                a, b = VECTORS[f"formula/class-{name}"], VECTORS[f"formula/class-{name}-plain"]
                self.assertEqual(a["ast_sha256"], b["ast_sha256"])
                self.assertEqual(a["body"], b["body"])
                self.assertEqual(canon.check_vector(a), [])
                self.assertEqual(canon.check_vector(b), [])


class MethodBodies(unittest.TestCase):
    def test_this_and_super_are_plain_reads(self):
        fwd = W.SCENARIO["functions"][f"{W.FX}/forward"]
        self.assertNotIn("this", fwd["code"]["body"])
        self.assertIn(f"{W.FX}/rate(base: base, date: date, quote: quote)", fwd["code"]["body"])
        self.assertEqual(fwd["inputs"], ["rates.example.org/deposit", f"{W.FX}/rate", f"{W.FX}/spot"])
        ndf = W.SCENARIO["functions"][f"{W.NDF}/rate"]
        self.assertIn(f"{W.FX}/rate@{canon.function_hash(W.RATE)}(", ndf["code"]["body"])  # super: the parent's hash
        price = W.SCENARIO["functions"]["calc.example.net/price_of"]
        self.assertEqual(price["inputs"], [f"{W.BOND}/price", f"{W.SWAP}/price"])

    def test_rules(self):
        num = {"type": "number", "unit": "1"}
        cases = [
            ("this.rate(2026-03-16)", sig(RATE_RET), None, "E_FORMULA_RESERVED"),
            (f"{W.FX}(EUR, USD).points(2026-03-16)", sig(RATE_RET), None, "E_FORMULA_METHOD"),
            (f"{W.FX}(EUR, USD) = 1", sig("boolean"), None, "E_FORMULA_METHOD"),
            (f'{W.FX}("eur", "USD").rate(2026-03-16)', sig(RATE_RET), None, "E_FORMULA_KEY"),
            (f'{W.VERSE}(Tanakh, "Gen", One, 1).text("uxlc")', sig("blob"), None, "E_FORMULA_TYPE"),
            ('rates.example.org/deposit("EUR", "1M", 2026-03-16).rate()', sig(num), None, "E_FORMULA_RESERVED"),
            (f'{W.FX}(EUR, USD).calc.example.net/price_of(2026-03-16)', sig(num), None, "E_FORMULA_METHOD"),
            (f'calc.example.net/price_of(instrument: {W.FX}(EUR, USD), date: 2026-03-16)', sig(num), None,
             "E_FORMULA_TYPE"),
            (f'{W.FX}/rate@{canon.function_hash(W.RATE)}(base: "EUR", quote: "USD", date: 2026-03-16)', sig(RATE_RET),
             None, "E_FORMULA_PLACEMENT"),
            ("1M", sig("string"), None, "E_FORMULA_RESERVED"),
            ("super.rate(date)", W.RATE["signature"], W.FX, "E_FORMULA_METHOD"),  # fx_pair has no parent
        ]
        for source, s, method_of, expected in cases:
            with self.subTest(source):
                self.assertEqual(code(formula.compile, source, W.env(E, s, method_of)), expected)

    def test_dispatch_needs_one_signature(self):
        env = W.env(E, {"args": {"i": {"type": "string", "classes": [W.BOND, W.FX], "valid": False}},
                        "order": ["i"], "returns": RATE_RET})
        self.assertEqual(code(formula.compile, "i.rate(2026-03-16)", env), "E_FORMULA_METHOD")  # bond has no rate
        env = W.env(E, {"args": {"i": {"type": "string", "classes": [W.FX, W.CCY_PAIR], "valid": False}},
                        "order": ["i"], "returns": RATE_RET})
        self.assertEqual(code(formula.compile, "i.rate(2026-03-16)", env), "E_FORMULA_DISPATCH")

    def test_vectors(self):
        invalid = [v for v in VECTORS.values() if v["id"].startswith("invalid/formula-class-")]
        self.assertGreaterEqual(len(invalid), 8)
        for v in invalid:
            with self.subTest(v["id"]):
                self.assertEqual(canon.check_vector(v), [])


class Evaluation(unittest.TestCase):
    def test_vectors(self):
        expected = {"formula-eval/class-forward": 4, "formula-eval/class-super": 1, "formula-eval/class-dispatch-bond": 1,
                    "formula-eval/class-dispatch-swap": 1, "formula-eval/class-default-asof": 1}
        for vid, n in expected.items():
            with self.subTest(vid):
                v = VECTORS[vid]
                self.assertEqual(len(v["lineage"]), n)
                self.assertEqual(canon.check_vector(v), [])
        self.assertEqual(VECTORS["invalid/formula-eval-class-dispatch-outside"]["error"], "E_FORMULA_DISPATCH_KEY")
        self.assertEqual(canon.check_vector(VECTORS["invalid/formula-eval-class-dispatch-outside"]), [])

    def test_lineage_names_the_hash_called(self):
        v = VECTORS["formula-eval/class-dispatch-swap"]
        receipt = W.price_receipt(W.SWAP, "XS0002", "99.5")
        self.assertEqual(v["lineage"], [canon.receipt_hash(receipt)])
        self.assertEqual(receipt["cell"]["fn_hash"], canon.function_hash(W.SWAP_PRICE))


class Calls(unittest.TestCase):
    def uri(self, text, env=None):
        try:
            return canon.parse_call(text, env or W.call_env())
        except canon.DatumeshError as e:
            return e.code

    def test_method_call_is_the_plain_call(self):
        pairs = [
            (f"{W.FX}(EUR, USD).rate(2026-03-16)", f'{W.FX}/rate("EUR", "USD", 2026-03-16)'),
            (f'{W.FX}("EUR", "USD").forward(1M, 2026-03-16)?asof=2026-06-01T00:00:00.000000Z',
             f'{W.FX}/forward("EUR", "USD", "1M", 2026-03-16)?asof=2026-06-01T00:00:00.000000Z'),
            (f'{W.VERSE}("quran", "2", 1, 255).text("uthmani")', f'{W.VERSE}/text("quran", "2", 1, 255, "uthmani")'),
            (f"{W.CCY_PAIR}({W.CURRENCY}(EUR), {W.CURRENCY}(USD)).rate(2026-03-16)",
             f'{W.CCY_PAIR}/rate("{W.CURRENCY}(code:""EUR"")", "{W.CURRENCY}(code:""USD"")", 2026-03-16)'),
            (f"{W.FX}(EUR, USD).calc.example.net/fx_extra/carry(2026-03-16)",
             'calc.example.net/fx_extra/carry("EUR", "USD", 2026-03-16)'),
        ]
        for call, plain in pairs:
            with self.subTest(call):
                self.assertEqual(self.uri(call)["uri"], self.uri(plain)["uri"])

    def test_short_calls_and_resolved(self):
        env = W.call_env(aliases={"fx_rate": "rates.example.org/fx_rate"}, aliases_tx="2026-05-01T00:00:00.000000Z")
        got = self.uri("fx_rate(EUR, GBP)?asof=2026-03-16T18:00:00.000000Z", env)
        self.assertEqual(got["uri"], "cell://rates.example.org/fx_rate?base=EUR&date=2026-03-16&quote=GBP"
                                     "&asof=2026-03-16T18:00:00.000000Z")
        self.assertEqual(got["resolved"], {
            "aliases_tx": "2026-05-01T00:00:00.000000Z",
            "call": 'rates.example.org/fx_rate(base: "EUR", date: 2026-03-16, quote: "GBP")'
                    "?asof=2026-03-16T18:00:00.000000Z",
            "resolutions": [{"from": "fx_rate", "kind": "alias", "to": "rates.example.org/fx_rate"},
                            {"from": "date", "kind": "default", "to": "2026-03-16"}]})
        old = W.call_env(aliases={"fx_rate": f"{W.FX}/rate"}, aliases_tx="2026-01-01T00:00:00.000000Z")
        self.assertEqual(self.uri("fx_rate(EUR, GBP, 2026-03-16)", old)["uri"],
                         f"cell://{W.FX}/rate?base=EUR&date=2026-03-16&quote=GBP")
        self.assertEqual(self.uri("fx_rate(EUR, GBP)", W.call_env(aliases={"fx_rate": "rates.example.org/fx_rate"},
                                                                  now="2026-04-02T10:00:00.000000Z"))["uri"],
                         "cell://rates.example.org/fx_rate?base=EUR&date=2026-04-02&quote=GBP")

    def test_errors(self):
        self.assertEqual(self.uri(f'{W.FX}("eur", "USD").rate(2026-03-16)'), "E_KEY_NORMALISATION")
        self.assertEqual(self.uri(f"{W.FX}(EUR, USD).points(2026-03-16)"), "E_NAME_UNBOUND")
        self.assertEqual(self.uri(f"{W.FX}(EUR, USD)"), "E_PARSE_URI")
        self.assertEqual(self.uri("fx_rate(EUR, GBP)", W.call_env()), "E_NAME_UNBOUND")
        self.assertEqual(self.uri(f"{W.FX}(EUR).rate(2026-03-16)"), "E_ARG_MISSING")
        self.assertEqual(self.uri(f'{W.VERSE}("quran", 2, one, 255).text("uthmani")'), "E_CANON_TYPE")

    def test_vectors(self):
        for a, b in [("call/class-method", "call/class-method-plain")]:
            self.assertEqual(VECTORS[a]["uri"], VECTORS[b]["uri"])
        for vid in ("call/class-method", "call/class-method-plain", "call/class-short", "call/class-short-old-snapshot",
                    "call/class-typed-key", "call/class-extension", "invalid/call-class-normalisation",
                    "invalid/call-class-no-method", "invalid/call-class-without-method"):
            with self.subTest(vid):
                self.assertEqual(canon.check_vector(VECTORS[vid]), [])
        self.assertIn("resolved", VECTORS["call/class-short"])
        self.assertNotEqual(VECTORS["call/class-short"]["uri"], VECTORS["call/class-short-old-snapshot"]["uri"])


class Text(unittest.TestCase):
    def test_statements(self):
        for phrase in ("### 16.3 Method calls", "### 16.6 Bounded dispatch", "### 16.7 Defaults and short calls",
                       "the same cell, with the same cell id", "| D86 |", "| D87 |", "| D88 |"):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)


if __name__ == "__main__":
    unittest.main()
