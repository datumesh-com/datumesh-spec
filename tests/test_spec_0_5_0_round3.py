# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0: E_NAMESPACE_SUSPENDED as not_covered's error (Q13 c, accepted 2026-11-13).

A mesh that refuses a cross-mesh import because the source namespace is suspended answers
not_covered with E_NAMESPACE_SUSPENDED, as E_NAME_UNBOUND is carried; never in an error envelope,
never a verification result.
"""

import json
import unittest

from helpers import ROOT, canon

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")


def env(body, status):
    try:
        return canon.check_envelope(status, json.dumps(body).encode(), {}, {"cell_id": "a" * 64})["outcome"]
    except canon.DatumeshError as e:
        return e.code


class Suspended(unittest.TestCase):
    def test_not_covered_only(self):
        self.assertEqual(env({"error": "E_NAMESPACE_SUSPENDED", "outcome": "not_covered"}, 404), "not_covered")
        self.assertEqual(env({"error": "E_NAMESPACE_SUSPENDED", "outcome": "error"}, 500), "E_ENVELOPE")
        self.assertEqual(env({"error": "E_NAMESPACE_SUSPENDED", "outcome": "bad_request"}, 400), "E_ENVELOPE")
        self.assertEqual(env({"error": "E_NAMESPACE_SUSPENDED", "fault": "E_FORMULA_DIV_ZERO",
                              "outcome": "not_covered"}, 404), "E_ENVELOPE")
        self.assertEqual(env({"error": "E_UNROOTED_INPUT", "outcome": "not_covered"}, 404), "E_ENVELOPE")

    def test_vectors(self):
        v = VECTORS["envelope/not-covered-namespace-suspended"]
        self.assertEqual((v["valid"], v["outcome"]), (True, "not_covered"))
        self.assertEqual(json.loads(v["input"])["error"], "E_NAMESPACE_SUSPENDED")
        self.assertEqual(VECTORS["invalid/envelope-namespace-suspended-in-error"]["error"], "E_ENVELOPE")
        for vid in ("envelope/not-covered-namespace-suspended", "invalid/envelope-namespace-suspended-in-error"):
            self.assertEqual(canon.check_vector(VECTORS[vid]), [])

    def test_text(self):
        s99 = SPEC[SPEC.index("### 9.9 Suspension"):SPEC.index("## 10. Verification")]
        self.assertIn("cross-mesh import", s99)
        self.assertIn("`not_covered`", s99)
        row = next(l for l in SPEC.splitlines() if l.startswith("| `not_covered` | 404 |"))
        self.assertIn("E_NAMESPACE_SUSPENDED", row)
        d81 = next(l for l in SPEC.splitlines() if l.startswith("| D81 |"))
        self.assertIn("not_covered", d81)


if __name__ == "__main__":
    unittest.main()
