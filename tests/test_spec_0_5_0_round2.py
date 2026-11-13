# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0, part one, round 2 (the user's answers of 2026-11-13):

S1 a: E_UNROOTED_INPUT (define) and E_NAMESPACE_SUSPENDED (write) are codes only, in 10.2's table,
      never verification results and never in a read envelope; a new vector kind `define`
      ({name, descriptor} -> the descriptor's canonical bytes and hash, or a code) tests
      E_UNROOTED_INPUT; a normative paragraph on suspension; write and define answer formats are
      a later step.
S2 a: an unrooted host's mesh document is supplied out of band, as its key document is (9.6).
"""

import json
import unittest

from helpers import ROOT, canon

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
DESC = {"code": {"body": "", "lang": "expr"}, "inputs": ["rates.example.org/fx_rate"],
        "signature": {"args": {}, "returns": "string"}}


def code(fn, *args):
    try:
        return fn(*args)
    except canon.DatumeshError as e:
        return e.code


class Codes(unittest.TestCase):
    def test_table(self):
        i = canon.ERROR_CODES.index("E_UNROOTED_INPUT")  # the class codes follow (spec-0.5.0, section 16)
        self.assertEqual(canon.ERROR_CODES[i:i + 2], ("E_UNROOTED_INPUT", "E_NAMESPACE_SUSPENDED"))
        self.assertRegex(SPEC, r"\| `E_UNROOTED_INPUT` \| define \|")
        self.assertRegex(SPEC, r"\| `E_NAMESPACE_SUSPENDED` \| write \|")

    def test_not_in_read_envelopes(self):
        for c in ("E_UNROOTED_INPUT", "E_NAMESPACE_SUSPENDED"):
            with self.subTest(c):
                self.assertEqual(code(canon.check_envelope, 500, json.dumps({"error": c, "outcome": "error"}).encode(),
                                      {}, {"cell_id": "a" * 64}), "E_ENVELOPE")


class Define(unittest.TestCase):
    def test_rule(self):
        unrooted = dict(DESC, inputs=["local.invalid/notes/fx"])
        self.assertEqual(code(canon.check_define, "calc.example.net/f", unrooted), "E_UNROOTED_INPUT")
        self.assertEqual(code(canon.check_define, "calc.example.net/f",
                              dict(DESC, inputs=["a.local.invalid/f", "rates.example.org/fx_rate"])), "E_UNROOTED_INPUT")
        self.assertEqual(canon.check_define("local.invalid/f", unrooted)["sha256"], canon.function_hash(unrooted))
        self.assertEqual(canon.check_define("local.invalid/f", DESC)["sha256"], canon.function_hash(DESC))
        self.assertEqual(canon.check_define("calc.example.net/f", DESC)["sha256"], canon.function_hash(DESC))
        # Order: the name, then the descriptor (section 7), then the rule of 2.5.
        self.assertEqual(code(canon.check_define, "f", unrooted), "E_CANON_NAME")
        self.assertEqual(code(canon.check_define, "calc.example.net/f",
                              dict(unrooted, inputs=["z.example/b", "local.invalid/a"])), "E_CANON_SET")

    def test_vectors(self):
        for name in ("rooted-reads-rooted", "unrooted-reads-unrooted", "unrooted-reads-rooted"):
            with self.subTest(name):
                v = VECTORS[f"define/{name}"]
                self.assertEqual((v["kind"], v["valid"]), ("define", True))
                self.assertEqual(canon.check_vector(v), [])
        for name, c in [("rooted-reads-unrooted", "E_UNROOTED_INPUT"), ("rooted-reads-unrooted-path", "E_UNROOTED_INPUT"),
                        ("bad-name", "E_CANON_NAME"), ("bad-descriptor-first", "E_CANON_SET")]:
            with self.subTest(name):
                v = VECTORS[f"invalid/define-{name}"]
                self.assertEqual((v["kind"], v["error"]), ("define", c))
                self.assertEqual(canon.check_vector(v), [])

    def test_schema(self):
        kinds = json.loads((ROOT / "schemas" / "vector.schema.json").read_text())["properties"]["kind"]["enum"]
        self.assertIn("define", kinds)


class Text(unittest.TestCase):
    def test_statements(self):
        for phrase in ("### 9.9 Suspension", "a mesh may suspend a namespace whose host's key document cannot be validated",
                       "| D80 |", "| D81 |", "| `define` (since `spec-0.5.0`)",
                       "an unrooted host's mesh document is supplied out of band, as its key document is",
                       "answer formats are a later step"):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC.replace("A mesh may suspend", "a mesh may suspend"))
        s99 = SPEC[SPEC.index("### 9.9 Suspension"):SPEC.index("## 10. Verification")]
        for word in ("put_version", "bind_name", "define", "reads", "verification", "existing receipts", "key document"):
            self.assertIn(word, s99)


if __name__ == "__main__":
    unittest.main()
