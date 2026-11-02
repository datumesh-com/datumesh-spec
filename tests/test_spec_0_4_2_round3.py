# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.2, round 3 (before the tag): text, with the reference made to agree.

1. A malformed member of a request description (cell_id, asof, job, fn_hash, mesh, slice_id, a
   cursor or its values) is the caller's error, never an E_* code (JavaScript library entry 52,
   the Python library's DEF-53 note): the reference raises ValueError.
2. The order of a page's checks (JavaScript library entry 54): the page first, then each member
   completely, receipt verification included, before the next.
"""

import json
import unittest

from helpers import ROOT, canon
from test_spec_0_4_2_round2 import KEYENV, SLICE, SREQ, T, page, receipt

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
CELL_REQ = {"asof": T, "cell_id": "a" * 64}


def run(env, request, status=200):
    return canon.check_envelope(status, json.dumps(env).encode(), KEYENV, request)


class CallersError(unittest.TestCase):
    def test_malformed_members_raise(self):
        nc = {"outcome": "not_covered"}
        for request in [dict(CELL_REQ, cell_id="A" * 64), dict(CELL_REQ, asof="2024-03-16"),
                        dict(CELL_REQ, fn_hash="AB" * 32), dict(CELL_REQ, fn_hash="ab"),
                        dict(CELL_REQ, mesh="Mesh.example"), dict(CELL_REQ, mesh="mesh.example:443"),
                        dict(CELL_REQ, job="0" * 31), dict(CELL_REQ, job="G" * 32), {"asof": T},
                        dict(SREQ, slice_id="x"), dict(SREQ, after=[]),
                        dict(SREQ, after={"quote": "USD"}), dict(SREQ, after={"quote": {"type": "string", "value": 1}}),
                        dict(SREQ, after={"quote": {"type": "colour", "value": "red"}})]:
            with self.subTest(request):
                status, env = (200, page([])) if "slice_id" in request else (404, nc)
                with self.assertRaises(ValueError):
                    run(env, request, status)

    def test_well_formed_members_pass(self):
        self.assertEqual(run({"outcome": "not_covered"}, dict(CELL_REQ, job="0" * 32, mesh="mesh.example"), 404)["outcome"],
                         "not_covered")
        self.assertEqual(run(page([]), dict(SREQ, after={"quote": {"type": "string", "value": "GBP"},
                                                         "x": {"type": "number", "value": "1"}}))["outcome"], "ok")

    def test_batch_requests_too(self):
        with self.assertRaises(ValueError):
            canon.check_batch(200, b'[{"envelope": {"outcome": "not_covered"}, "status": 404}]', {},
                              [{"cell_id": "a" * 63}])


class PageOrder(unittest.TestCase):
    def test_each_member_completely_before_the_next(self):
        bad = dict(receipt("CHF"), value="9")
        good = receipt("USD")
        env = page([bad, good])
        env["members"][1]["status"] = 200  # a stray member in the second member
        with self.assertRaises(canon.DatumeshError) as e:
            run(env, SREQ)
        self.assertEqual(e.exception.code, "E_SIGNATURE")

    def test_the_page_before_its_members(self):
        bad = dict(receipt("CHF"), value="9")
        with self.assertRaises(canon.DatumeshError) as e:
            run(page([bad], fn_hash="cd" * 32), SREQ)
        self.assertEqual(e.exception.code, "E_ENVELOPE")

    def test_vector(self):
        v = VECTORS["invalid/envelope-slice-member-checks-in-order"]
        self.assertEqual(v["error"], "E_SIGNATURE")
        self.assertEqual(canon.check_vector(v), [])


class Text(unittest.TestCase):
    def test_statements(self):
        for phrase in ("each member completely", "a request `job`", "a `mesh` that is not a DNS name",
                       "values are not typed scalars"):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)


if __name__ == "__main__":
    unittest.main()
