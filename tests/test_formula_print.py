# SPDX-License-Identifier: Apache-2.0
"""SPEC 15.6: parse(print(ast)) = ast for every canonical AST, on fuzzed trees.

DATUMESH_FORMULA_FUZZ_N sets the number of trees (default 100000)."""

import os
import random
import unittest

from helpers import ROOT  # noqa: F401
import formula  # noqa: E402

N = int(os.environ.get("DATUMESH_FORMULA_FUZZ_N", "100000"))
SEED = int(os.environ.get("DATUMESH_FORMULA_FUZZ_SEED", "20261024"))

NAMES = ["a", "b", "x", "amount", "count", "sum", "first", "t", "d", "station", "time", "v2_final", "m", "s"]
FUNCTIONS = ["rates.example.org/fx_rate", "open-meteo.com/temp", "a-b.org/f", "1password.example/x_y",
             "example.org/central_bank/stats/rate", "x.y/z"]
UNITS = [None, None, None, "EUR", "m/s", "degC", "percent", "index:2015=100", "d", "min", "km", "W/m2", "count"]
STRINGS = ["", "a", 'say "hi"', "Zürich", "→", "a b", "100 EUR", "if", "'"]
BINARY = ["+", "-", "*", "/", "^", "&", "=", "<>", "<", "<=", ">", ">=", "and", "or"]


class Gen:
    def __init__(self, rng):
        self.rng = rng

    def num(self):
        r = self.rng
        text = str(r.choice([0, 1, 2, 10, 42, 1000, r.randrange(10 ** 6)]))
        if r.random() < 0.4:
            text += "." + str(r.randrange(1, 10 ** r.randrange(1, 6))).rstrip("0") if r.random() < 0.9 else ".5"
            if text.endswith("."):
                text = text[:-1]
        node = {"node": "num", "value": text}
        unit = r.choice(UNITS)
        if unit:
            node["unit"] = unit
        return node

    def leaf(self):
        r = self.rng
        k = r.randrange(7)
        if k == 0:
            return self.num()
        if k == 1:
            return {"node": "str", "value": r.choice(STRINGS)}
        if k == 2:
            return {"node": "bool", "value": r.random() < 0.5}
        if k == 3:
            return {"node": "date", "value": r.choice(["2024-03-15", "0001-01-01", "9999-12-31", "2024-02-29"])}
        if k == 4:
            return {"node": "instant", "value": "2024-03-15T16:00:00.000000Z"}
        return {"node": "var", "name": r.choice(NAMES)}

    def expr(self, depth):
        r = self.rng
        if depth <= 0 or r.random() < 0.25:
            return self.leaf()
        k = r.randrange(12)
        if k <= 3:
            return {"node": "op", "op": r.choice(BINARY), "args": [self.expr(depth - 1), self.expr(depth - 1)]}
        if k == 4:
            return {"node": "op", "op": r.choice(["neg", "not"]), "args": [self.expr(depth - 1)]}
        if k == 5:
            return {"node": "if", "cond": self.expr(depth - 1), "then": self.expr(depth - 1), "else": self.expr(depth - 1)}
        if k == 6:
            return {"node": "let", "name": r.choice(NAMES), "value": self.expr(depth - 1), "body": self.expr(depth - 1)}
        if k == 7:
            return self.read(depth)
        if k == 8:
            return {"node": "call", "fn": r.choice(formula.AGGREGATES), "args": [self.expr(depth - 1) for _ in range(r.randrange(1, 4))],
                    "named": {}}
        if k == 9:
            named = {}
            if r.random() < 0.5:
                named["bound"] = self.expr(depth - 1)
            if r.random() < 0.3:
                named["along"] = {"node": "key", "name": r.choice(NAMES)}
            return {"node": "call", "fn": r.choice(["last_before", "first_after", "nearest"]),
                    "args": [self.read(depth), self.expr(depth - 1)], "named": named}
        if k == 10:
            params = r.sample(NAMES, r.randrange(1, 3))
            return {"node": "call", "fn": r.choice(["map", "filter"]),
                    "args": [self.read(depth), {"node": "lambda", "params": params, "body": self.expr(depth - 1)}],
                    "named": {}}
        if r.random() < 0.5:
            return {"node": "call", "fn": "window", "args": [self.read(depth), self.expr(depth - 1),
                                                             {"node": "agg", "name": r.choice(formula.AGGREGATES)}],
                    "named": {}}
        if r.random() < 0.5:
            return {"node": "call", "fn": "asof", "args": [], "named": {}}
        return {"node": "call", "fn": "round", "args": [self.expr(depth - 1)], "named": {"digits": self.expr(depth - 1)}}

    def read(self, depth):
        r = self.rng
        args = {}
        for name in r.sample(NAMES, r.randrange(0, 4)):
            k = r.randrange(4)
            if k == 0:
                args[name] = {"node": "open"}
            elif k == 1:
                args[name] = {"node": "range", "lo": self.expr(depth - 1), "hi": self.expr(depth - 1)}
            else:
                args[name] = self.expr(depth - 1)
        return {"node": "read", "fn": r.choice(FUNCTIONS), "args": args}


class RoundTrip(unittest.TestCase):
    def test_parse_of_print_is_identity(self):
        gen = Gen(random.Random(SEED))
        for i in range(N):
            ast = gen.expr(gen.rng.randrange(1, 7))
            text = formula.print_ast(ast)
            with self.subTest(i=i, text=text):
                self.assertEqual(formula.canonical_ast(text), ast)
                self.assertEqual(formula.print_ast(formula.canonical_ast(text)), text)

    def test_hand_picked(self):
        cases = {
            "-(2 ^ 2)": None, "(-2) ^ 2": None, "2 ^ -1": None, "(2 ^ 3) ^ 2": None, "2 ^ (3 ^ 2)": None,
            "a - (b - c)": None, "a - b - c": None, "not (a and b)": None, "(not a) = b": None,
            "1 + (if a then b else c)": None, "if a then b else c + 1": None, "--x": None, "a * -b": None,
            '"say ""hi"""': None, "5 m / s": None, "5 m/s": None, "[1..2]": "x.org/f(a: [1..2])",
            "a-b.org/f(x: 1) - a": None, "a - b.org/f(x: 1)": None,
        }
        for text, wrapped in cases.items():
            text = wrapped or text
            with self.subTest(text):
                self.assertEqual(formula.print_ast(formula.canonical_ast(text)), text)


if __name__ == "__main__":
    unittest.main()
