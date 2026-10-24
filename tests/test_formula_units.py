# SPDX-License-Identifier: Apache-2.0
"""Brief test 5: ten unit mismatch cases fail at define; FX forward's unit resolves to
quote-per-base."""

import unittest

from helpers import ROOT, canon  # noqa: F401
import formula  # noqa: E402


def num(unit):
    return {"type": "number", "unit": unit, "valid": False}


STR = {"type": "string", "valid": False}
DATE = {"type": "date", "valid": True}
FX = {"code": {"body": "", "lang": "stored"}, "inputs": [],
      "signature": {"args": {"base": STR, "date": DATE, "quote": STR}, "order": ["base", "quote", "date"],
                    "returns": {"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}}}}
RATE = {"code": {"body": "", "lang": "stored"}, "inputs": [],
        "signature": {"args": {"currency": STR, "tenor": STR}, "order": ["currency", "tenor"],
                      "returns": {"type": "number", "unit": "1"}}}
RATE_PCT = {"code": {"body": "", "lang": "stored"}, "inputs": [],
            "signature": {"args": {"currency": STR, "tenor": STR}, "order": ["currency", "tenor"],
                          "returns": {"type": "number", "unit": "percent"}}}
FUNCTIONS = {"rates.example.org/fx_rate": FX, "rates.example.org/rate": RATE, "rates.example.org/rate_pct": RATE_PCT}
ARGS = {"a": num("EUR"), "b": num("USD"), "amount": num({"arg": "base"}), "base": STR, "quote": STR, "r": num("percent"),
        "t1": num("degC"), "t2": num("degC"), "k": num("1"), "dist": num("m"), "secs": num("s"), "date": DATE,
        "tenor": STR}


def env(returns):
    return {"name": "calc.example.net/f", "functions": FUNCTIONS,
            "signature": {"args": ARGS, "order": sorted(ARGS), "returns": returns}}


MISMATCHES = [  # (source, returns, code)
    ("a + b", {"type": "number", "unit": "EUR"}, "E_FORMULA_UNIT_MISMATCH"),
    ("a > b", "boolean", "E_FORMULA_UNIT_MISMATCH"),
    ("if k > 0 then a else b", {"type": "number", "unit": "EUR"}, "E_FORMULA_UNIT_MISMATCH"),
    ("a * k", {"type": "number", "unit": "USD"}, "E_FORMULA_RETURN_UNIT"),
    ("1 + r", {"type": "number", "unit": "percent"}, "E_FORMULA_UNIT_MISMATCH"),
    ("t1 + t2", {"type": "number", "unit": "degC"}, "E_FORMULA_UNIT_OFFSET"),
    ("dist / secs", {"type": "number", "unit": "m/s"}, "E_FORMULA_RETURN_UNIT"),
    ("a ^ k", {"type": "number", "unit": "EUR"}, "E_FORMULA_EXPONENT"),
    ("amount + a", {"type": "number", "unit": "EUR"}, "E_FORMULA_UNIT_MISMATCH"),
    ('rates.example.org/fx_rate(base: base & "", date: date, quote: quote)',
     {"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}}, "E_FORMULA_UNIT_UNKNOWN"),
    ("sqrt(dist)", {"type": "number", "unit": "m"}, "E_FORMULA_EXPONENT"),
    ('convert(a, "m")', {"type": "number", "unit": "m"}, "E_FORMULA_UNIT_MISMATCH"),
    ("sum(t1, t2)", {"type": "number", "unit": "degC"}, "E_FORMULA_UNIT_OFFSET"),
]


class Units(unittest.TestCase):
    def test_mismatches_fail_at_define(self):
        self.assertGreaterEqual(len(MISMATCHES), 10)
        for source, returns, code in MISMATCHES:
            with self.subTest(source):
                with self.assertRaises(formula.FormulaError) as e:
                    formula.define("calc.example.net/f", env(returns)["signature"], source, {"functions": FUNCTIONS})
                self.assertEqual(e.exception.code, code, str(e.exception))

    def test_fx_forward_is_quote_per_base(self):
        returns = {"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}}
        source = ("rates.example.org/fx_rate(base, quote, date) * (1 + rates.example.org/rate(quote, tenor))"
                  " / (1 + rates.example.org/rate(base, tenor))")
        c = formula.compile(source, env(returns))
        self.assertEqual(c.ty.unit, formula.unit_mul(formula.U("arg:quote"), formula.U("arg:base"), -1))
        sig = {"args": {"base": STR, "date": DATE, "quote": STR, "tenor": STR}, "order": ["base", "quote", "tenor", "date"],
               "returns": returns}
        d = formula.define("calc.example.net/fx_forward", sig, source, {"functions": FUNCTIONS})
        self.assertEqual(d["inputs"], ["rates.example.org/fx_rate", "rates.example.org/rate"])
        cell = {"args": {"base": {"type": "string", "value": "EUR"}, "date": {"type": "date", "value": "2026-10-24"},
                         "quote": {"type": "string", "value": "USD"}, "tenor": {"type": "string", "value": "1M"}},
                "fn": "fx_forward", "fn_hash": canon.function_hash(d), "ns": "calc.example.net"}
        self.assertEqual(canon.resolved_unit(d, cell), "USD/EUR")

    def test_percent_rates_need_an_explicit_conversion(self):
        returns = {"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}}
        bad = "rates.example.org/fx_rate(base, quote, date) * (1 + rates.example.org/rate_pct(quote, tenor))"
        with self.assertRaises(formula.FormulaError) as e:
            formula.compile(bad, env(returns))
        self.assertEqual(e.exception.code, "E_FORMULA_UNIT_MISMATCH")
        for fix in ("rates.example.org/fx_rate(base, quote, date) * (1 + rates.example.org/rate_pct(quote, tenor) / 100 percent)",
                    'rates.example.org/fx_rate(base, quote, date) * (1 + convert(rates.example.org/rate_pct(quote, tenor), "1"))'):
            formula.compile(fix, env(returns))

    def test_bare_literals_take_their_context(self):
        for source, returns in [("a + 10", {"type": "number", "unit": "EUR"}), ("a > 0", "boolean"),
                                ("a * 1.2", {"type": "number", "unit": "EUR"}), ("r + 0", {"type": "number", "unit": "percent"}),
                                ("t1 + 5", {"type": "number", "unit": "degC"}), ("t1 - t2", {"type": "number", "unit": "K"}),
                                ("mean(t1, t2)", {"type": "number", "unit": "degC"}), ("date + 30", "date")]:
            with self.subTest(source):
                formula.compile(source, env(returns))


if __name__ == "__main__":
    unittest.main()
