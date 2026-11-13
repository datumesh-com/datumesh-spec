# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.3, round 2 (the user's answers of 2026-11-04 to the first report):

S1 a: declarations are read from the publisher's host (the host of cell.ns), whatever host signed.
S2 b: a restricted input together with a share-alike input is refused (`share_alike_conflict`),
      declared or not; this revises "the strictest ancestor wins" for the share-alike case (D75).
S4 a: the release note names @datumesh/verify < 0.4.3 too.
O1 a: a new envelope code, E_FOREIGN_UNAVAILABLE: outcome error, HTTP 502, with `detail` saying
      which failure; a resolution and envelope code, never a verification result.
"""

import json
import unittest

from helpers import ROOT, canon

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
DETAILS = ("offline", "network", "dns", "tls", "timeout", "refused")


def env(body, status, request=None):
    try:
        return canon.check_envelope(status, json.dumps(body).encode(), {}, request or {"cell_id": "a" * 64})["outcome"]
    except canon.DatumeshError as e:
        return e.code


FOREIGN = {"detail": "offline", "error": "E_FOREIGN_UNAVAILABLE", "outcome": "error"}


class ForeignUnavailable(unittest.TestCase):
    def test_code_table(self):
        i = canon.ERROR_CODES.index("E_NAME_UNBOUND")  # spec-0.5.0 appends define and write codes after it
        self.assertEqual(canon.ERROR_CODES[i + 1], "E_FOREIGN_UNAVAILABLE")
        self.assertRegex(SPEC, r"\| `E_FOREIGN_UNAVAILABLE` \|")
        self.assertEqual(canon.FOREIGN_DETAILS, DETAILS)

    def test_an_error_envelope_with_502_and_detail(self):
        for detail in DETAILS:
            self.assertEqual(env(dict(FOREIGN, detail=detail), 502), "error")
        self.assertEqual(env(dict(FOREIGN, fn_hash="ab" * 32), 502, {"cell_id": "a" * 64, "fn_hash": "ab" * 32}), "error")

    def test_rules(self):
        self.assertEqual(env(FOREIGN, 500), "E_ENVELOPE")  # 502 exactly
        self.assertEqual(env(FOREIGN, 503), "E_ENVELOPE")
        self.assertEqual(env({"error": "E_FOREIGN_UNAVAILABLE", "outcome": "error"}, 502), "E_ENVELOPE")
        for bad in ("Offline", "", "unknown", 1, None):
            self.assertEqual(env(dict(FOREIGN, detail=bad), 502), "E_ENVELOPE")
        self.assertEqual(env({"detail": "offline", "error": "E_EVAL_UNAVAILABLE", "outcome": "error"}, 503),
                         "E_ENVELOPE")
        self.assertEqual(env({"error": "E_FOREIGN_UNAVAILABLE", "outcome": "not_covered"}, 404), "E_ENVELOPE")
        self.assertEqual(env({"error": "E_FOREIGN_UNAVAILABLE", "outcome": "bad_request"}, 400), "E_ENVELOPE")
        self.assertEqual(env({"detail": "offline", "outcome": "not_covered"}, 404), "E_ENVELOPE")
        # Other error codes keep any 5xx and have no detail.
        self.assertEqual(env({"error": "E_EVAL_UNAVAILABLE", "outcome": "error"}, 502), "error")

    def test_not_a_verification_code(self):
        self.assertNotIn("E_FOREIGN_UNAVAILABLE", canon.FORMULA_FAULTS)
        table = SPEC[SPEC.index("### 10.2 Error codes"):SPEC.index("### 10.3")]
        self.assertIn("E_FOREIGN_UNAVAILABLE", table[:table.index("| Code |")])  # named in the intro

    def test_vectors(self):
        for name in ("envelope/error-foreign-unavailable", "envelope/error-foreign-unavailable-timeout"):
            with self.subTest(name):
                v = VECTORS[name]
                self.assertEqual((v["valid"], v["outcome"], v["status"]), (True, "error", 502))
                self.assertEqual(json.loads(v["input"])["error"], "E_FOREIGN_UNAVAILABLE")
                self.assertEqual(canon.check_vector(v), [])
        for name in ("status-500", "no-detail", "bad-detail", "detail-other-code", "not-covered"):
            with self.subTest(name):
                v = VECTORS[f"invalid/envelope-foreign-unavailable-{name}"]
                self.assertEqual(v["error"], "E_ENVELOPE")
                self.assertEqual(canon.check_vector(v), [])

    def test_schema(self):
        schema = json.loads((ROOT / "schemas" / "envelope.schema.json").read_text())
        self.assertIn("E_FOREIGN_UNAVAILABLE", json.dumps(schema))
        self.assertIn("detail", json.dumps(schema))


class ShareAlikeWithRestricted(unittest.TestCase):
    def test_vectors(self):
        for name in ("restricted-with-share-alike-conflict", "restricted-declared-with-share-alike",
                     "restricted-undeclared-with-share-alike", "two-restricted-with-share-alike"):
            with self.subTest(name):
                v = VECTORS[f"licence/{name}"]
                self.assertEqual((v["licence"], v["reason"]), (None, "share_alike_conflict"))
                self.assertEqual(canon.check_vector(v), [])
        self.assertEqual(VECTORS["licence/restricted-declared-with-share-alike"]["declarations"],
                         {"calc.example.net/convert": [{"licence": "https://rates.example.org/licences/restricted",
                                                        "valid_from": "2020-01-01T00:00:00.000000Z"}]})
        self.assertEqual(VECTORS["licence/restricted-undeclared-with-share-alike"]["declarations"], {})
        v = VECTORS["licence/restricted-with-open-declared"]
        self.assertFalse(any(canon.licence_tier(x) == 3 for x in v["licences"]))
        self.assertEqual(v["reason"], "declared")


class Text(unittest.TestCase):
    def test_publisher_host(self):
        for phrase in ("even when `computed_by` names another host",):
            self.assertIn(phrase, SPEC)
        for wrong in ("key document of `computed_by`", "`computed_by`'s host", "computed_by's host"):
            self.assertNotIn(wrong, SPEC)

    def test_share_alike_rule_and_d75(self):
        s85 = SPEC[SPEC.index("### 8.5 Licence inheritance"):SPEC.index("## 9. Keys")]
        self.assertIn("**Share-alike with anything it cannot be carried with.**", s85)
        self.assertLess(s85.index("**Share-alike with anything"), s85.index("**Two restricted licences.**"))
        d75 = next(line for line in SPEC.splitlines() if line.startswith("| D75 |"))
        self.assertIn("revised in `spec-0.4.3`", d75)
        self.assertIn("no single licence satisfies both", d75)

    def test_release_notes(self):
        bold = ("**A mesh that serves `declarations` is unverifiable by clients on core < 0.3.7 or datumesh < 0.4.3; "
                "publishers should wait for their consumers to upgrade before declaring.**")
        self.assertIn(bold + " The same holds for @datumesh/verify < 0.4.3.", SPEC)
        entry = SPEC[SPEC.index("### spec-0.4.3"):SPEC.index("### spec-0.4.2")]
        self.assertIn("E_FOREIGN_UNAVAILABLE", entry)
        self.assertIn("core < 0.3.7, datumesh < 0.4.3 and @datumesh/verify < 0.4.3", entry)

    def test_distinguished(self):
        for phrase in ("Unlike `E_MESH_DOC`", "Unlike `E_INPUT_UNAVAILABLE`", "| D78 |"):
            self.assertIn(phrase, SPEC)


if __name__ == "__main__":
    unittest.main()
