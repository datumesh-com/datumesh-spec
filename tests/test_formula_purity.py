# SPDX-License-Identifier: Apache-2.0
"""Brief test 4: any token resembling a forbidden function fails at parse with a code naming it
(E_FORMULA_FORBIDDEN, the token reported), whatever its case and wherever it is."""

import unittest

from helpers import ROOT  # noqa: F401
import formula  # noqa: E402

CASES = [
    "NOW()", "now()", "Now()", "TODAY()", "today()", "RAND()", "rand()", "RANDBETWEEN(1, 6)", "RandArray(3)",
    'INDIRECT("A1")', "indirect(x)", "OFFSET(x, 1, 1)", 'INFO("system")', 'CELL("row")', "clock()", "time()",
    "random()", "sleep(1)", 'fetch("https://example.org")', 'http("x")', 'eval("1 + 1")',
    "1 + now()", "if today() > d then 1 else 2", "sum(x.org/f(*)) * RAND()", "let t = NOW() in t",
    "map(x.org/f(*), v -> v * rand())",
]


class Purity(unittest.TestCase):
    def test_forbidden_names_fail_at_parse_naming_the_token(self):
        for source in CASES:
            with self.subTest(source):
                with self.assertRaises(formula.FormulaError) as e:
                    formula.parse(source)
                self.assertEqual(e.exception.code, "E_FORMULA_FORBIDDEN")
                name = e.exception.token
                self.assertIn(name.lower(), formula.FORBIDDEN)
                self.assertIn(name + "(", source)
                self.assertIn(name, str(e.exception))

    def test_without_a_call_the_word_is_a_name(self):
        """time is a plausible argument name: only a call is forbidden."""
        env = {"name": "calc.example.net/f", "functions": {},
               "signature": {"args": {"time": {"type": "instant", "valid": True}}, "order": ["time"],
                             "returns": "instant"}}
        self.assertEqual(formula.compile("time", env).body, "time\n")
        with self.assertRaises(formula.FormulaError) as e:
            formula.compile("now", env)
        self.assertEqual(e.exception.code, "E_FORMULA_UNKNOWN_NAME")

    def test_no_clock_randomness_or_io_among_the_builtins(self):
        self.assertEqual(set(formula.BUILTINS) & set(formula.FORBIDDEN), set())
        for name in ("now", "today", "rand", "random", "clock", "fetch", "read", "write", "print", "open"):
            self.assertNotIn(name, formula.BUILTINS)

    def test_asof_is_the_only_time_and_it_is_flagged(self):
        env = {"name": "calc.example.net/f", "functions": {},
               "signature": {"args": {}, "order": [], "returns": "instant"}}
        c = formula.compile("ASOF()", env)
        self.assertEqual(c.body, "asof()\n")
        self.assertTrue(c.asof_dependent)


if __name__ == "__main__":
    unittest.main()
