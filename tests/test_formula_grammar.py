# SPDX-License-Identifier: Apache-2.0
"""Brief tests 1 and 3: grammar vectors with canonical AST hashes and error codes, every rule
covered, every invalid vector naming its rule; derived inputs equal the hand-written sets."""

import json
import re
import unittest

from helpers import ROOT, canon
import formula  # noqa: E402

VECTORS = [v for v in canon.load_vectors() if v["kind"] == "formula"]
VALID = [v for v in VECTORS if v["valid"]]
INVALID = [v for v in VECTORS if not v["valid"]]
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")

# Every hazard of SPEC 15.4, both readings where there are two.
HAZARDS = """
formula/qualified-division formula/qualified-call-divided formula/hyphenated-host formula/hyphen-subtraction
formula/alias formula/alias-division invalid/formula-alias-unknown invalid/formula-qualified-not-called
formula/unit-suffix-percent formula/unit-suffix-rate formula/unit-division invalid/formula-juxtaposition
formula/range-integers formula/range-decimal formula/range-dates invalid/formula-range-three-dots
invalid/formula-neg-power formula/neg-power-left formula/neg-power-right formula/power-negative-exponent
invalid/formula-power-chain formula/power-chain-left formula/power-chain-right
invalid/formula-comparison-chain formula/comparison-and
invalid/formula-if-operand formula/if-operand-parenthesised formula/if-function-form formula/if-keyword-paren
formula/if-extent formula/let-extent formula/let-equality
formula/date-literal formula/date-subtraction-spaced formula/instant-literal invalid/formula-instant-short
invalid/formula-date-impossible
formula/keyword-uppercase formula/builtin-uppercase formula/variable-named-count formula/label-keyword
invalid/formula-this invalid/formula-super invalid/formula-keyword-argument
formula/asof-zero-arity formula/asof-two-arguments formula/open-marker formula/multiply-in-argument
invalid/formula-open-outside-read invalid/formula-lambda-outside-map
formula/spatial-filter-now invalid/formula-spatial-example
""".split()


class GrammarVectors(unittest.TestCase):
    def test_every_vector_passes(self):
        for vec in VECTORS:
            with self.subTest(vec["id"]):
                self.assertEqual(canon.check_vector(vec), [])

    def test_counts(self):
        """Brief test 1: at least 100 valid and 60 invalid; this revision has more."""
        self.assertGreaterEqual(len(VALID), 160)
        self.assertGreaterEqual(len(INVALID), 110)

    def test_every_define_time_rule_has_an_invalid_vector(self):
        used = {v["error"] for v in INVALID}
        # E_FORMULA_ORDER, E_FORMULA_INPUTS and E_FORMULA_NOT_CANONICAL are about descriptors,
        # not sources: test_descriptor_rules covers them.
        expected = set(formula.DEFINE_CODES) - {"E_FORMULA_ORDER", "E_FORMULA_INPUTS", "E_FORMULA_NOT_CANONICAL"}
        self.assertEqual(expected - used, set())
        self.assertEqual(used - set(formula.DEFINE_CODES), set())

    def test_every_invalid_vector_names_its_rule(self):
        for vec in INVALID:
            with self.subTest(vec["id"]):
                self.assertIn(vec["error"], formula.DEFINE_CODES)
                self.assertTrue(vec["description"])

    def test_hazards_are_pinned(self):
        ids = {v["id"] for v in VECTORS}
        self.assertEqual([h for h in HAZARDS if h not in ids], [])

    def test_every_valid_vector_states_its_outputs(self):
        for vec in VALID:
            with self.subTest(vec["id"]):
                for field in ("ast", "ast_sha256", "body", "inputs", "returns", "asof_dependent"):
                    self.assertIn(field, vec)
                self.assertEqual(canon.sha256_hex(vec["ast"].encode("utf-8")), vec["ast_sha256"])
                self.assertTrue(vec["body"].endswith("\n") and "\n" not in vec["body"][:-1])

    def test_inputs_are_derived(self):
        """Brief test 3: the derived input set equals the vector's hand-written set (the generator
        states each one by hand and stops if the parser disagrees), and is exactly the read
        nodes' function names."""
        for vec in VALID:
            with self.subTest(vec["id"]):
                c = formula.compile(vec["input"], vec["env"])
                self.assertEqual(c.inputs, vec["inputs"])
                self.assertEqual(set(c.inputs), set(re.findall(r'"fn":"([a-z0-9.\-]+(?:/[a-z0-9_]+)+)"', vec["ast"])))

    def test_body_is_a_fixed_point(self):
        for vec in VALID:
            with self.subTest(vec["id"]):
                again = formula.compile(vec["body"], vec["env"])
                self.assertEqual(again.ast_sha256, vec["ast_sha256"])
                self.assertEqual(again.body, vec["body"])
                self.assertEqual(formula.canonical_ast(vec["body"]), json.loads(vec["ast"]))

    def test_dynamic_names_fail_at_parse(self):
        """Brief test 3: a body with a dynamically constructed name fails at parse, before any
        environment is consulted."""
        for source in ['("rates.example.org/" & "fx_rate")(base: "EUR")', '"rates.example.org/fx_rate"(1)',
                       "(x)(1)", "rates.example.org/fx_rate(base: \"EUR\")(1)", "sum(x)(y)"]:
            with self.subTest(source):
                with self.assertRaises(formula.FormulaError) as e:
                    formula.parse(source)
                self.assertEqual(e.exception.code, "E_FORMULA_DYNAMIC_NAME")
        for source in ['indirect("rates.example.org/fx_rate")', 'INDIRECT("A1")']:
            with self.assertRaises(formula.FormulaError) as e:
                formula.parse(source)
            self.assertEqual(e.exception.code, "E_FORMULA_FORBIDDEN")

    def test_spatial_example_parses(self):
        """The decision log's composed example parses; it is refused at check time until 1.3b."""
        vec = next(v for v in VECTORS if v["id"] == "invalid/formula-spatial-example")
        formula.canonical_ast(vec["input"], vec["env"])  # parses and resolves
        self.assertEqual(vec["error"], "E_FORMULA_UNSUPPORTED")


class DescriptorRules(unittest.TestCase):
    """E_FORMULA_ORDER, E_FORMULA_INPUTS and E_FORMULA_NOT_CANONICAL: define and check_descriptor."""

    SIG = {"args": {"x": {"type": "number", "unit": "1", "valid": False}}, "order": ["x"],
           "returns": {"type": "number", "unit": "1"}}

    def test_define_requires_order(self):
        sig = {k: v for k, v in self.SIG.items() if k != "order"}
        with self.assertRaises(formula.FormulaError) as e:
            formula.define("calc.example.net/f", sig, "x + 1", {"functions": {}})
        self.assertEqual(e.exception.code, "E_FORMULA_ORDER")

    def test_define_prints_and_derives(self):
        d = formula.define("calc.example.net/f", self.SIG, "x  +\t1", {"functions": {}})
        self.assertEqual(d["code"], {"body": "x + 1\n", "lang": "formula"})
        with self.assertRaises(formula.FormulaError):  # X is not the argument x: words with capitals are reserved
            formula.define("calc.example.net/f", self.SIG, "X + 1", {"functions": {}})
        d = formula.define("calc.example.net/f", self.SIG, "SUM(x,1)", {"functions": {}})
        self.assertEqual(d["code"], {"body": "sum(x, 1)\n", "lang": "formula"})
        self.assertEqual(d["inputs"], [])
        canon.check_function(d)
        formula.check_descriptor(d, "calc.example.net/f", {"functions": {}})

    def test_non_canonical_body_and_wrong_inputs(self):
        d = formula.define("calc.example.net/f", self.SIG, "x + 1", {"functions": {}})
        bad = dict(d, code={"body": "x+1\n", "lang": "formula"})
        with self.assertRaises(formula.FormulaError) as e:
            formula.check_descriptor(bad, "calc.example.net/f", {"functions": {}})
        self.assertEqual(e.exception.code, "E_FORMULA_NOT_CANONICAL")
        bad = dict(d, inputs=["calc.example.net/g"])
        with self.assertRaises(formula.FormulaError) as e:
            formula.check_descriptor(bad, "calc.example.net/f", {"functions": {}})
        self.assertEqual(e.exception.code, "E_FORMULA_INPUTS")
        bad = dict(d, signature={k: v for k, v in self.SIG.items() if k != "order"})
        with self.assertRaises(formula.FormulaError) as e:
            formula.check_descriptor(bad, "calc.example.net/f", {"functions": {}})
        self.assertEqual(e.exception.code, "E_FORMULA_ORDER")


class SpecTables(unittest.TestCase):
    def test_formula_code_table_matches_tool(self):
        table = re.findall(r"^\| `(E_FORMULA_[A-Z_]+)` \|", SPEC, re.M)
        self.assertEqual(tuple(table), formula.CODES)

    def test_builtin_table_matches_tool(self):
        section = SPEC[SPEC.index("### 15.7 Built-ins"):SPEC.index("### 15.8")]
        listed = []
        for line in section.splitlines():
            if line.startswith("| `"):
                listed += re.findall(r"`([a-z_0-9]+)\(", line.split(" | ")[0])
        self.assertEqual(sorted(set(listed)), sorted(formula.BUILTINS))

    def test_appendix_has_the_formula_grammar(self):
        appendix = SPEC[SPEC.index("## Appendix A"):]
        for rule in ("formula-body", "if-expr", "let-expr", "read-arg", "range", "lambda", "unit-suffix",
                     "qualified-name", "alias"):
            self.assertRegex(appendix, rf"(?m)^{rule}\s+=")


if __name__ == "__main__":
    unittest.main()
