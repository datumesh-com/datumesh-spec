# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0, classes (step 1.3b part A), third pair: what a mesh says about classes.

- The envelope's `resolved` (16.7, 5.5) and `shadows` (16.9) members.
- `describe` (16.8): a class answer and an object answer, against their schemas and the rules the
  schemas cannot state (hashes, ids); the short id; an ambiguous short id is `bad_request` with
  `E_SHORT_ID_AMBIGUOUS`; the mesh document's optional `describe` endpoint.
- Migration (the brief's test 9) is test_migration_0_5_0.py: every spec-0.4.3 file byte-identical,
  every expected result reproduced.
"""

import copy
import json
import unittest

from helpers import ROOT, canon
import class_world as W

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
RESOLVED = {"aliases_tx": "2026-05-01T00:00:00.000000Z",
            "call": 'rates.example.org/fx_rate(base: "EUR", date: 2026-03-16, quote: "GBP")',
            "resolutions": [{"from": "fx_rate", "kind": "alias", "to": "rates.example.org/fx_rate"},
                            {"from": "date", "kind": "default", "to": "2026-03-16"}]}


def env(body, status, request=None):
    try:
        return canon.check_envelope(status, json.dumps(body).encode(), {}, request or {"cell_id": "a" * 64})["outcome"]
    except canon.DatumeshError as e:
        return e.code


class Envelope(unittest.TestCase):
    def test_resolved(self):
        self.assertEqual(env({"outcome": "not_covered", "resolved": RESOLVED}, 404), "not_covered")
        self.assertEqual(env({"outcome": "unlicensed", "resolved": RESOLVED}, 403), "unlicensed")
        bad = [dict(RESOLVED, extra=1), {k: v for k, v in RESOLVED.items() if k != "call"},
               dict(RESOLVED, resolutions=[{"from": "x", "kind": "guess", "to": "y"}]),
               dict(RESOLVED, resolutions=[{"from": "x", "kind": "alias"}]), dict(RESOLVED, aliases_tx="2026-05-01"),
               dict(RESOLVED, call=""), "fx_rate"]
        for r in bad:
            with self.subTest(r):
                self.assertEqual(env({"outcome": "not_covered", "resolved": r}, 404), "E_ENVELOPE")
        self.assertEqual(env({"outcome": "rate_limited", "resolved": RESOLVED, "retry_after_seconds": 1}, 429),
                         "E_ENVELOPE")

    def test_shadows(self):
        sh = {"class": W.FX, "reference": "ab" * 32}
        self.assertEqual(env({"outcome": "not_covered", "shadows": sh}, 404), "not_covered")
        for bad in (dict(sh, reference="x"), dict(sh, extra=1), dict(sh, **{"class": "fx_pair"})):
            self.assertEqual(env({"outcome": "not_covered", "shadows": bad}, 404), "E_ENVELOPE")

    def test_short_id_ambiguous(self):
        self.assertEqual(canon.ERROR_CODES[-2:], ("E_SHORT_ID_AMBIGUOUS", "E_DESCRIBE"))
        self.assertIn("E_SHORT_ID_AMBIGUOUS", canon.REQUEST_CODES)
        self.assertEqual(env({"error": "E_SHORT_ID_AMBIGUOUS", "outcome": "bad_request"}, 400), "bad_request")
        self.assertEqual(env({"error": "E_SHORT_ID_AMBIGUOUS", "outcome": "error"}, 500), "E_ENVELOPE")

    def test_vectors(self):
        for vid in ("envelope/resolved-short-call", "envelope/shadows-reference-class",
                    "envelope/bad-request-short-id-ambiguous"):
            with self.subTest(vid):
                self.assertTrue(VECTORS[vid]["valid"])
                self.assertEqual(canon.check_vector(VECTORS[vid]), [])
        for vid in ("invalid/envelope-resolved-kind", "invalid/envelope-resolved-member",
                    "invalid/envelope-shadows-hash", "invalid/envelope-short-id-in-error"):
            with self.subTest(vid):
                self.assertEqual(VECTORS[vid]["error"], "E_ENVELOPE")
                self.assertEqual(canon.check_vector(VECTORS[vid]), [])


FX_DESC = W.SCENARIO["classes"][W.FX]


def class_answer():
    return canon.describe_class(W.FX, FX_DESC, W.SCENARIO["functions"],
                                {"rate": "The reference rate: units of quote per unit of base."})


def object_answer():
    keys = {"book": W.S("Gen"), "chapter": W.N("1"), "corpus": W.S("tanakh"), "verse": W.N("1")}
    return canon.describe_object(W.VERSE, W.SCENARIO["classes"][W.VERSE], keys,
                                 same_as=['bible.example.org/passage(osis:"Gen.1.1")'])


class Describe(unittest.TestCase):
    def test_class_answer(self):
        a = class_answer()
        self.assertEqual(a["kind"], "class")
        self.assertEqual(a["class_hash"], canon.class_hash(FX_DESC))
        self.assertEqual(set(a["methods"]), {"cross", "forward", "named", "rate", "spot"})
        self.assertEqual(a["methods"]["rate"]["fn"], f"{W.FX}/rate")
        self.assertEqual(a["methods"]["rate"]["returns"], {"type": "number", "unit": {"of": {"arg": "quote"},
                                                                                     "per": {"arg": "base"}}})
        self.assertEqual(a["methods"]["forward"]["args"], {"date": W.DATE, "tenor": W.STR})
        canon.check_describe(a)

    def test_object_answer(self):
        a = object_answer()
        self.assertEqual(a["kind"], "object")
        self.assertEqual(a["object_id"], canon.object_id(a["object"]))
        self.assertEqual(a["short_id"], a["object_id"][:12])
        self.assertEqual(a["call"], f'{W.VERSE}(book: "Gen", chapter: 1, corpus: "tanakh", verse: 1)')
        self.assertEqual(a["methods"], ["consonantal", "next", "text"])
        canon.check_describe(a)

    def test_rules(self):
        c, o = class_answer(), object_answer()
        bad = [dict(c, class_hash="ab" * 32), dict(c, kind="interface"), {k: v for k, v in c.items() if k != "methods"},
               dict(c, methods=dict(c["methods"], points=c["methods"]["rate"])),
               dict(o, object_id="ab" * 32), dict(o, short_id=o["object_id"][:11]), dict(o, short_id="0" * 12),
               dict(o, call="x"), dict(o, methods=["text"]), dict(o, same_as=["not a key"]), dict(o, extra=1)]
        for d in bad:
            with self.subTest(d.get("kind")):
                with self.assertRaises(canon.DatumeshError) as e:
                    canon.check_describe(d, W.SCENARIO["classes"])
                self.assertEqual(e.exception.code, "E_DESCRIBE")

    def test_schemas(self):
        from test_vectors import validator
        validator("describe-class").validate(class_answer())
        validator("describe-object").validate(object_answer())

    def test_vectors(self):
        vs = [v for v in VECTORS.values() if v["kind"] == "describe"]
        self.assertTrue(any(v["valid"] for v in vs) and any(not v["valid"] for v in vs))
        for v in vs:
            with self.subTest(v["id"]):
                self.assertEqual(canon.check_vector(v), [])

    def test_mesh_endpoint(self):
        self.assertEqual(canon.MESH_ENDPOINTS["describe"], ("id",))
        self.assertNotIn("describe", canon.MESH_REQUIRED)
        self.assertEqual(canon.check_vector(VECTORS["mesh/describe-endpoint"]), [])


class Text(unittest.TestCase):
    def test_statements(self):
        for phrase in ("### 16.8 describe and short ids", "### 16.9 Shadowing and reference classes",
                       "`resolved`", "`shadows`", "| `describe` (since `spec-0.5.0`)", "| D89 |", "| D90 |",
                       "| `E_SHORT_ID_AMBIGUOUS` |", "| `E_DESCRIBE` |"):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)


if __name__ == "__main__":
    unittest.main()
