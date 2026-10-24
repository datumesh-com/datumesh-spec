# SPDX-License-Identifier: Apache-2.0
"""Brief test 2 (determinism half): fuzzed expressions, each defined and evaluated twice in two
independent worlds, give byte-identical receipts (or the same error code).

DATUMESH_FORMULA_FUZZ_N sets the number of expressions (default 100000)."""

import os
import random
import unittest

from helpers import ROOT  # noqa: F401
import formula  # noqa: E402
import gen_formula as G  # noqa: E402

N = int(os.environ.get("DATUMESH_FORMULA_FUZZ_N", "100000"))
SEED = int(os.environ.get("DATUMESH_FORMULA_FUZZ_SEED", "20261024"))


class Determinism(unittest.TestCase):
    def test_fuzzed_expressions_evaluate_identically_twice(self):
        rng = random.Random(SEED)
        spec = G.world_fuzz()
        worlds = [formula.world_of(spec), formula.world_of(spec)]
        env = {"functions": {n: f["descriptor"] for n, f in spec["functions"].items()}}  # the bodies read only these
        outcomes = {"value": 0, "fault": 0}
        for i in range(N):
            source, returns = G.random_expression(rng)
            fq = f"fuzz.example.net/f{i}"
            sig = G.fuzz_signature(returns)
            results = []
            for world in worlds:
                try:
                    descriptor = formula.define(fq, sig, source, env)
                    world.bind(fq, descriptor, G.BOUND)
                    a = world.get(fq, G.FUZZ_ARGS, G.LATER)
                    results.append(("receipt", a.text))
                except formula.FormulaError as e:
                    results.append(("error", e.code))
            with self.subTest(i=i, source=source):
                self.assertEqual(results[0], results[1])
                kind = results[0][0]
                if kind == "error":
                    self.assertIn(results[0][1], formula.CODES)
                    self.assertNotIn(results[0][1], formula.DEFINE_CODES, "the generator writes well-typed bodies")
                    outcomes["fault"] += 1
                else:
                    outcomes["value"] += 1
        self.assertGreater(outcomes["value"], N // 2)


if __name__ == "__main__":
    unittest.main()
