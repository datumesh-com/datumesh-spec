# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0, classes (step 1.3b part A): the user's answers to classes Q1, Q6, Q10, answer 5 and
answer 11 (BRIEF-1.3b-partA-answers).

- Q1: arguments in requests are read by the declared type of their position (5.8, 16.3); bodies
  are unchanged (D37). Unquoted request values are single tokens of the dialect.
- Q6 b: a function's string argument may carry `key_normalisation` (7); absent means `none`;
  enforced on every read, plain or method (a call, a body literal at define, a computed argument
  at evaluation as a fault); define refuses a class whose methods do not carry the class's rules.
- Q10 a: the class member `lookup` (16.1, 16.2) and labels in requests (16.7), resolution `lookup`.
- Answer 5: a value outside the dispatch set at evaluation is the fault E_FORMULA_DISPATCH_KEY.
- Answer 11: one-way reads within a class work (fx_pair's forward reads this.spot and this.rate).
"""

import json
import unittest

from helpers import ROOT, canon
import class_world as W
import formula

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
STR, DATE = {"type": "string", "valid": False}, {"type": "date", "valid": True}
UKEY = dict(STR, key_normalisation="upper_ascii")
NUM = {"type": "number", "unit": "1"}
ASOF = "2026-06-01T00:00:00.000000Z"
CABLE = 'rates.example.org/fx_pair(base:"GBP",quote:"USD")'


def fn(args, order, returns, lang="stored", body="", inputs=()):
    return {"code": {"body": body, "lang": lang}, "inputs": list(inputs),
            "signature": {"args": args, "order": order, "returns": returns}}


def code(f, *args):
    try:
        return f(*args)
    except (formula.FormulaError, canon.DatumeshError) as e:
        return e.code


def call(text, env=None):
    return code(canon.parse_call, text, env or W.call_env())


def lookup_env(**kw):
    return W.call_env(lookups={W.FX: {"cable": CABLE, "fiber": 'rates.example.org/fx_pair(base:"EUR",quote:"USD")'}},
                      **kw)


class RequestsByPositionType(unittest.TestCase):
    """Q1: requests have no variables; every argument is read by its position's declared type."""

    def test_the_brief_example(self):
        a = call(f"{W.VERSE}(quran, 2, 1, 255).text(uthmani)")
        b = call(f'{W.VERSE}("quran", "2", 1, 255).text("uthmani")')
        self.assertEqual(a["uri"], b["uri"])
        self.assertEqual(a["resolved"]["call"], b["resolved"]["call"])
        self.assertEqual(a["uri"], "cell://scripture.example.org/verse/text?book=2&chapter=1&corpus=quran"
                                   "&edition=uthmani&verse=255")

    def test_position_types(self):
        # 2 is the string "2" in a string position, the number 2 in a number position.
        self.assertEqual(call(f"{W.VERSE}(quran, 2, 1, 255).text(uthmani)")["uri"],
                         call(f'{W.VERSE}/text("quran", "2", 1, 255, "uthmani")')["uri"])
        self.assertEqual(call(f"{W.VERSE}/text(quran, 2, 1, 255, uthmani)")["uri"],
                         call(f'{W.VERSE}/text("quran", "2", 1, 255, "uthmani")')["uri"])
        # A date token is a string in a string position, and a string is never a date.
        self.assertEqual(call('rates.example.org/fx_rate("EUR", "USD", "2026-03-16")'), "E_CANON_TYPE")
        self.assertEqual(call(f"{W.VERSE}(quran, 2, one, 255).text(uthmani)"), "E_CANON_TYPE")
        # Labels still work, and quotes are always allowed.
        self.assertEqual(call(f"{W.VERSE}(corpus: quran, book: 2, chapter: 1, verse: 255).text(edition: uthmani)")["uri"],
                         call(f'{W.VERSE}("quran", "2", 1, 255).text("uthmani")')["uri"])

    def test_tokens_that_need_quotes(self):
        for text in (f"{W.VERSE}(quran, 2, 1, 255).text(uxlc edition)", f"{W.VERSE}(quran, 2, 1, 255).text(ux-lc)",
                     f"{W.VERSE}(quran, 2:1, 1, 255).text(uthmani)", f"{W.VERSE}(quran, a.b, 1, 255).text(uthmani)"):
            with self.subTest(text):
                self.assertEqual(call(text), "E_PARSE_URI")
        self.assertEqual(call(f"{W.VERSE}(quran, 1.50, 1, 255).text(uthmani)"), "E_CANON_NUMBER")
        self.assertEqual(call(f'{W.VERSE}(quran, "ux-lc", 1, 255).text("a b")')["uri"],
                         "cell://scripture.example.org/verse/text?book=ux-lc&chapter=1&corpus=quran&edition=a%20b&verse=255")

    def test_unquoted_is_checked_by_normalisation(self):
        self.assertEqual(call(f"{W.FX}(eur, USD).rate(2026-03-16)"), "E_KEY_NORMALISATION")
        self.assertEqual(call(f"{W.FX}(EUR, USD).rate(2026-03-16)")["uri"],
                         call(f'{W.FX}("EUR", "USD").rate(2026-03-16)')["uri"])

    def test_bare_word_argument_is_never_an_alias(self):
        env = W.call_env(aliases={"quran": "rates.example.org/fx_rate"})
        self.assertEqual(call(f"{W.VERSE}(quran, 2, 1, 255).text(uthmani)", env)["uri"],
                         call(f'{W.VERSE}("quran", "2", 1, 255).text("uthmani")')["uri"])

    def test_class_typed_position_is_a_key_encoding(self):
        enc = 'iso.example.org/currency(code:"EUR")'
        quoted = '"' + enc.replace('"', '""') + '"'
        usd = 'iso.example.org/currency(code:""USD"")'
        self.assertEqual(call(f'{W.CCY_PAIR}({quoted}, "{usd}").rate(2026-03-16)')["uri"],
                         call(f"{W.CCY_PAIR}({W.CURRENCY}(EUR), {W.CURRENCY}(USD)).rate(2026-03-16)")["uri"])
        self.assertEqual(call(f'{W.CCY_PAIR}("iso.example.org/currency(code: ""EUR"")", {W.CURRENCY}(USD))'
                              ".rate(2026-03-16)"), "E_KEY_ENCODING")
        self.assertEqual(call(f"{W.CCY_PAIR}(eur, {W.CURRENCY}(USD)).rate(2026-03-16)"), "E_CANON_TYPE")

    def test_vectors(self):
        a, b = VECTORS["call/class-unquoted"], VECTORS["call/class-unquoted-quoted"]
        self.assertEqual(a["uri"], b["uri"])
        self.assertEqual(a["resolved"]["call"], b["resolved"]["call"])
        self.assertIn("book=2&", VECTORS["call/class-unquoted-number-as-string"]["uri"])
        self.assertEqual(VECTORS["invalid/call-class-unquoted-needs-quotes"]["error"], "E_PARSE_URI")
        self.assertEqual(VECTORS["invalid/call-class-unquoted-normalisation"]["error"], "E_KEY_NORMALISATION")
        for vid in ("call/class-unquoted", "call/class-unquoted-quoted", "call/class-unquoted-number-as-string",
                    "invalid/call-class-unquoted-needs-quotes", "invalid/call-class-unquoted-normalisation"):
            with self.subTest(vid):
                self.assertEqual(canon.check_vector(VECTORS[vid]), [])

    def test_text(self):
        s58 = SPEC[SPEC.index("### 5.8 Calls"):SPEC.index("## 6. Canonical encoding")]
        self.assertIn("declared type of its position", s58)
        self.assertIn("never an alias", s58)
        s163 = SPEC[SPEC.index("### 16.3 Method calls"):SPEC.index("### 16.4 Key normalisation")]
        self.assertIn("scripture.example.org/verse(quran, 2, 1, 255).text(uthmani)", s163)
        self.assertIn('scripture.example.org/verse("quran", "2", 1, 255).text("uthmani")', s163)


class NormalisationOnFunctions(unittest.TestCase):
    """Q6 b: key_normalisation on a function's string argument; absent means none."""

    def test_member(self):
        ok = fn({"isin": UKEY, "date": DATE}, ["isin", "date"], NUM)
        self.assertEqual(code(canon.check_function, ok), ok)
        cases = [
            (fn({"isin": dict(STR, key_normalisation="none")}, ["isin"], NUM), "E_SCHEMA"),
            (fn({"isin": dict(STR, key_normalisation="lower")}, ["isin"], NUM), "E_SCHEMA"),
            (fn({"isin": dict(STR, key_normalisation=1)}, ["isin"], NUM), "E_SCHEMA"),
            (fn({"n": dict(NUM, valid=False, key_normalisation="upper_ascii")}, ["n"], NUM), "E_CANON_TYPE"),
            (fn({"k": dict(STR, classes=[W.FX], key_normalisation="upper_ascii")}, ["k"], NUM), "E_CANON_TYPE"),
        ]
        for d, expected in cases:
            with self.subTest(d["signature"]["args"]):
                self.assertEqual(code(canon.check_function, d), expected)

    def test_old_descriptors_unchanged(self):
        # No existing function hash changes: the seeded descriptors carry no rule and match a key declared none.
        self.assertNotIn("key_normalisation", json.dumps(W.TEXT))
        self.assertIn(W.VERSE, W.SCENARIO["classes"])

    def test_define_refuses_a_mismatch(self):
        rate = fn({"base": STR, "date": DATE, "quote": STR}, ["base", "quote", "date"], NUM)
        rate_u = fn({"base": UKEY, "date": DATE, "quote": UKEY}, ["base", "quote", "date"], NUM)
        rate_n = fn({"base": dict(STR, key_normalisation="nfc_strict"), "date": DATE, "quote": UKEY},
                    ["base", "quote", "date"], NUM)
        upper = {"key_normalisation": "upper_ascii", "type": "string"}
        none = {"key_normalisation": "none", "type": "string"}
        steward = {"namespace": "rates.example.org", "process": "https://rates.example.org/classes/change"}
        env = {"functions": [rate, rate_u, rate_n], "classes": []}

        def desc(keys, h):
            return {"keys": {"base": keys, "quote": keys}, "methods": {"rate": h}, "order": ["base", "quote"],
                    "steward": steward}

        self.assertEqual(code(canon.define_class, W.FX, desc(upper, canon.function_hash(rate)), env), "E_CLASS_METHOD")
        self.assertEqual(code(canon.define_class, W.FX, desc(none, canon.function_hash(rate_u)), env), "E_CLASS_METHOD")
        self.assertEqual(code(canon.define_class, W.FX, dict(desc(upper, canon.function_hash(rate_n))), env),
                         "E_CLASS_METHOD")
        self.assertIn("methods", canon.define_class(W.FX, desc(upper, canon.function_hash(rate_u)), env))
        self.assertIn("methods", canon.define_class(W.FX, desc(none, canon.function_hash(rate)), env))

    def test_world_methods_carry_their_rules(self):
        fns = W.SCENARIO["functions"]
        for m in ("rate", "cross", "forward", "spot"):
            sig = fns[f"{W.FX}/{m}"]["signature"]["args"]
            self.assertEqual((sig["base"].get("key_normalisation"), sig["quote"].get("key_normalisation")),
                             ("upper_ascii", "upper_ascii"), m)
        for cls in (W.BOND, W.SWAP):
            self.assertEqual(fns[f"{cls}/price"]["signature"]["args"]["isin"].get("key_normalisation"), "upper_ascii")
        self.assertNotIn("key_normalisation", fns[f"{W.VERSE}/text"]["signature"]["args"]["corpus"])

    def test_plain_read_in_a_call(self):
        self.assertEqual(call(f'{W.BOND}/price("xs0001", 2026-03-16)'), "E_KEY_NORMALISATION")
        self.assertEqual(call(f"{W.BOND}/price(xs0001, 2026-03-16)"), "E_KEY_NORMALISATION")
        self.assertEqual(call(f"{W.BOND}/price(XS0001, 2026-03-16)")["uri"],
                         f"cell://{W.BOND}/price?date=2026-03-16&isin=XS0001")

    def test_body_literal_at_define(self):
        env = W.env("calc.example.net/e", {"args": {}, "order": [], "returns": NUM})
        self.assertEqual(code(formula.compile, f'{W.BOND}/price("xs0001", 2026-03-16)', env), "E_FORMULA_KEY")
        self.assertEqual(code(formula.compile, f'{W.BOND}/price(xs0001, 2026-03-16)', env), "E_FORMULA_UNKNOWN_NAME")
        self.assertNotIsInstance(code(formula.compile, f'{W.BOND}/price("XS0001", 2026-03-16)', env), str)

    def test_computed_argument_faults_at_evaluation(self):
        v = VECTORS["invalid/formula-eval-class-key-computed"]
        self.assertEqual(v["error"], "E_FORMULA_KEY")
        self.assertEqual(canon.check_vector(v), [])
        world = formula.world_of(v["world"])
        with self.assertRaises(formula.FormulaError) as first:
            world.get(v["cell"]["fn"], v["cell"]["args"], v["asof"])
        self.assertEqual(first.exception.code, "E_FORMULA_KEY")
        evaluations = world.evaluations
        memo = [x for x in world.memo.values() if isinstance(x, formula.FormulaError)]
        self.assertEqual([e.code for e in memo], ["E_FORMULA_KEY"])  # memoized as a property of the cell
        with self.assertRaises(formula.FormulaError):
            world.get(v["cell"]["fn"], v["cell"]["args"], v["asof"])
        self.assertEqual(world.evaluations, evaluations)

    def test_fault_in_envelope(self):
        for fault in ("E_FORMULA_KEY", "E_FORMULA_DISPATCH_KEY"):
            body = json.dumps({"fault": fault, "outcome": "not_covered"}).encode()
            self.assertEqual(canon.check_envelope(404, body, {}, {"cell_id": "a" * 64})["outcome"], "not_covered")
        self.assertIn("E_FORMULA_KEY", formula.FAULT_CODES)
        self.assertIn("E_FORMULA_DISPATCH_KEY", formula.FAULT_CODES)

    def test_vectors(self):
        expected = {"function/argument-key-normalisation": None,
                    "invalid/function-key-normalisation-none": "E_SCHEMA",
                    "invalid/function-key-normalisation-number": "E_CANON_TYPE",
                    "class/keyed-none-ruleless-methods": None,
                    "invalid/class-method-normalisation": "E_CLASS_METHOD",
                    "invalid/call-class-plain-normalisation": "E_KEY_NORMALISATION",
                    "invalid/formula-class-plain-key-literal": "E_FORMULA_KEY",
                    "invalid/formula-eval-class-key-computed": "E_FORMULA_KEY",
                    "envelope/not-covered-fault-key": None}
        for vid, error in expected.items():
            with self.subTest(vid):
                v = VECTORS[vid]
                self.assertEqual(v.get("error"), error)
                self.assertEqual(canon.check_vector(v), [])

    def test_text(self):
        s7 = SPEC[SPEC.index("## 7. Function descriptors"):SPEC.index("### 7.1 Units")]
        self.assertIn("key_normalisation", s7)
        self.assertIn("new descriptor", s7)
        s163 = SPEC[SPEC.index("### 16.3 Method calls"):SPEC.index("### 16.4 Key normalisation")]
        s164 = SPEC[SPEC.index("### 16.4 Key normalisation"):SPEC.index("### 16.5 Object keys")]
        self.assertNotIn("is not checked against the class", s163)
        self.assertNotIn("is not checked against the class", s164)
        self.assertNotIn("neither checks it", s163)
        row = next(l for l in SPEC.splitlines() if l.startswith("| `E_CLASS_METHOD` |"))
        self.assertIn("key_normalisation", row)


class Lookup(unittest.TestCase):
    """Q10 a: the class member lookup, and labels in requests."""

    def setUp(self):
        self.named = fn({"label": STR}, ["label"], {"type": "string", "classes": [W.FX]})
        self.rate = fn({"base": UKEY, "date": DATE, "quote": UKEY}, ["base", "quote", "date"], NUM)
        self.other = fn({"label": STR}, ["label"], {"type": "string", "classes": [W.VERSE]})
        self.two = fn({"label": STR, "x": STR}, ["label", "x"], {"type": "string", "classes": [W.FX]})
        self.number = fn({"label": dict(NUM, valid=False)}, ["label"], {"type": "string", "classes": [W.FX]})
        self.keyed = fn({"base": UKEY, "label": STR, "quote": UKEY}, ["base", "quote", "label"],
                        {"type": "string", "classes": [W.FX]})
        self.env = {"functions": [self.named, self.rate, self.other, self.two, self.number, self.keyed], "classes": []}
        self.desc = {"keys": {"base": W.UPPER, "quote": W.UPPER}, "lookup": "named",
                     "methods": {"named": canon.function_hash(self.named), "rate": canon.function_hash(self.rate)},
                     "order": ["base", "quote"], "steward": W.steward("rates.example.org")}

    def test_valid(self):
        flat = canon.define_class(W.FX, self.desc, self.env)
        self.assertEqual(flat["lookup"], "named")
        self.assertEqual(W.SCENARIO["classes"][W.FX]["lookup"], "named")

    def test_rules(self):
        H = canon.function_hash
        cases = [
            (dict(self.desc, lookup="by_name"), "E_CLASS_MEMBER"),  # not a method
            (dict(self.desc, lookup=7), "E_SCHEMA"),
            (dict(self.desc, methods=dict(self.desc["methods"], named=H(self.other))), "E_CLASS_MEMBER"),
            (dict(self.desc, methods=dict(self.desc["methods"], named=H(self.two))), "E_CLASS_MEMBER"),
            (dict(self.desc, methods=dict(self.desc["methods"], named=H(self.number))), "E_CLASS_MEMBER"),
            (dict(self.desc, methods=dict(self.desc["methods"], named=H(self.keyed))), "E_CLASS_MEMBER"),
            (dict(self.desc, methods=dict(self.desc["methods"], named="cd" * 32)), "E_CLASS_METHOD"),
        ]
        for d, expected in cases:
            with self.subTest(d.get("lookup"), m=d["methods"].get("named")):
                self.assertEqual(code(canon.define_class, W.FX, d, self.env), expected)
        # Without lookup, the same method takes the class keys first.
        self.assertEqual(code(canon.define_class, W.FX, {k: v for k, v in self.desc.items() if k != "lookup"},
                              self.env), "E_CLASS_METHOD")

    def test_label_in_a_request(self):
        got = call(f"{W.FX}[cable].rate(2026-03-16)?asof={ASOF}", lookup_env())
        self.assertEqual(got["uri"], f"cell://{W.FX}/rate?base=GBP&date=2026-03-16&quote=USD&asof={ASOF}")
        self.assertIn({"asof": ASOF, "from": "cable", "kind": "lookup", "to": CABLE}, got["resolved"]["resolutions"])
        quoted = call(f'{W.FX}["cable"].rate(2026-03-16)?asof={ASOF}', lookup_env())
        self.assertEqual(quoted, got)
        now = call(f"{W.FX}[cable].rate(2026-03-16)", lookup_env(now="2026-04-02T10:00:00.000000Z"))
        self.assertEqual(now["resolved"]["resolutions"][0]["asof"], "2026-04-02T10:00:00.000000Z")
        self.assertEqual(call(f"{W.FX}[sterling].rate(2026-03-16)?asof={ASOF}", lookup_env()), "E_NAME_UNBOUND")
        self.assertEqual(call(f"{W.VERSE}[kursi].text(uthmani)?asof={ASOF}", lookup_env()), "E_NAME_UNBOUND")
        self.assertEqual(call(f"{W.FX}[cable]?asof={ASOF}", lookup_env()), "E_PARSE_URI")

    def test_labels_stay_out_of_bodies(self):
        env = W.env("calc.example.net/e", {"args": {}, "order": [], "returns": NUM})
        self.assertEqual(code(formula.compile, f"{W.FX}[cable].rate(2026-03-16)", env), "E_FORMULA_SYNTAX")

    def test_resolved_in_envelope(self):
        res = {"call": f'{W.FX}/rate(base: "GBP", date: 2026-03-16, quote: "USD")',
               "resolutions": [{"asof": ASOF, "from": "cable", "kind": "lookup", "to": CABLE}]}

        def check(r):
            body = json.dumps({"outcome": "not_covered", "resolved": r}).encode()
            try:
                return canon.check_envelope(404, body, {}, {"cell_id": "a" * 64})["outcome"]
            except canon.DatumeshError as e:
                return e.code

        self.assertEqual(check(res), "not_covered")
        self.assertEqual(check(dict(res, resolutions=[{"from": "cable", "kind": "lookup", "to": CABLE}])), "E_ENVELOPE")
        self.assertEqual(check(dict(res, resolutions=[{"asof": ASOF, "from": "x", "kind": "alias", "to": "y"}])),
                         "E_ENVELOPE")
        self.assertEqual(check(dict(res, resolutions=[{"asof": "2026-06-01", "from": "cable", "kind": "lookup",
                                                       "to": CABLE}])), "E_ENVELOPE")
        self.assertEqual(check(dict(res, resolutions=[{"from": "x", "kind": "label", "to": "y"}])), "E_ENVELOPE")

    def test_vectors(self):
        expected = {"class/lookup": None, "invalid/class-lookup-not-a-method": "E_CLASS_MEMBER",
                    "invalid/class-lookup-signature": "E_CLASS_MEMBER", "invalid/class-lookup-returns": "E_CLASS_MEMBER",
                    "call/class-lookup": None, "invalid/call-class-lookup-unknown-label": "E_NAME_UNBOUND",
                    "invalid/call-class-lookup-none": "E_NAME_UNBOUND", "envelope/resolved-lookup": None,
                    "invalid/envelope-resolved-lookup-asof": "E_ENVELOPE"}
        for vid, error in expected.items():
            with self.subTest(vid):
                v = VECTORS[vid]
                self.assertEqual(v.get("error"), error)
                self.assertEqual(canon.check_vector(v), [])
        kinds = [r["kind"] for r in VECTORS["call/class-lookup"]["resolved"]["resolutions"]]
        self.assertIn("lookup", kinds)

    def test_text(self):
        s161 = SPEC[SPEC.index("### 16.1 The class descriptor"):SPEC.index("### 16.2 Define")]
        self.assertIn("`lookup`", s161)
        s167 = SPEC[SPEC.index("### 16.7 Defaults"):SPEC.index("### 16.8 describe")]
        self.assertIn("`lookup`", s167)
        self.assertIn("[cable]", s167)


class DispatchKeyFault(unittest.TestCase):
    """Answer 5 overruled: a value outside the dispatch set is a formula fault."""

    def test_vectors(self):
        for vid in ("invalid/formula-eval-class-dispatch-outside", "invalid/formula-eval-class-dispatch-malformed",
                    "invalid/formula-eval-class-dispatch-keys"):
            with self.subTest(vid):
                v = VECTORS[vid]
                self.assertEqual(v["kind"], "formula-eval")
                self.assertEqual(v["error"], "E_FORMULA_DISPATCH_KEY")
                self.assertEqual(canon.check_vector(v), [])
        self.assertEqual(canon.check_vector(VECTORS["envelope/not-covered-fault-dispatch-key"]), [])

    def test_memoized(self):
        v = VECTORS["invalid/formula-eval-class-dispatch-outside"]
        world = formula.world_of(v["world"])
        with self.assertRaises(formula.FormulaError):
            world.get(v["cell"]["fn"], v["cell"]["args"], v["asof"])
        self.assertEqual([e.code for e in world.memo.values() if isinstance(e, formula.FormulaError)],
                         ["E_FORMULA_DISPATCH_KEY"])

    def test_text(self):
        row = next(l for l in SPEC.splitlines() if l.startswith("| `E_FORMULA_DISPATCH_KEY` |"))
        self.assertIn("Fault", row)
        s55 = SPEC[SPEC.index("### 5.5 Response envelope"):SPEC.index("### 5.6 Slices")]
        self.assertIn("`E_FORMULA_DISPATCH_KEY`", s55)
        self.assertIn("`E_FORMULA_KEY`", s55)
        d58 = next(l for l in SPEC.splitlines() if l.startswith("| D58 |"))
        self.assertIn("E_FORMULA_DISPATCH_KEY", d58)


class OneWayReads(unittest.TestCase):
    """Answer 11: a method reads another method of its own class one way, by name."""

    def test_forward_reads_spot_and_rate(self):
        fwd = W.SCENARIO["functions"][f"{W.FX}/forward"]
        self.assertEqual(fwd["inputs"], ["rates.example.org/deposit", f"{W.FX}/rate", f"{W.FX}/spot"])
        spot = W.SCENARIO["functions"][f"{W.FX}/spot"]
        self.assertEqual(spot["inputs"], [f"{W.FX}/rate"])
        self.assertIn("spot", W.SCENARIO["classes"][W.FX]["methods"])

    def test_vectors(self):
        fwd, spot = VECTORS["formula-eval/class-forward"], VECTORS["formula-eval/class-spot"]
        self.assertEqual(len(fwd["lineage"]), 4)  # spot (computed), rate, two deposits
        self.assertEqual(len(spot["lineage"]), 1)
        for v in (fwd, spot):
            self.assertEqual(canon.check_vector(v), [])

    def test_text(self):
        s163 = SPEC[SPEC.index("### 16.3 Method calls"):SPEC.index("### 16.4 Key normalisation")]
        self.assertIn("one way", s163)
        self.assertIn("mutual", s163)


class Decisions(unittest.TestCase):
    def test_rows_and_changes(self):
        for d in ("D91", "D92", "D93", "D94", "D95"):
            self.assertTrue(any(l.startswith(f"| {d} |") for l in SPEC.splitlines()), d)
        entry = SPEC[SPEC.index("### spec-0.5.0"):SPEC.index("### spec-0.4.3")]
        for phrase in ("E_FORMULA_DISPATCH_KEY", "key_normalisation", "lookup", "spot"):
            self.assertIn(phrase, entry)


if __name__ == "__main__":
    unittest.main()
