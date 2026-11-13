# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0, classes (step 1.3b part A), first pair: class descriptors and keys.

- The class descriptor, the third hashed object (16.1): members, check order and codes.
- Define (16.2): flattening onto the parent, the class hash over the flattened descriptor, method
  signatures against the keys, overrides (signature, return, unit), final and open, interfaces,
  the owner, `same_as`, `inverse`, `extent`.
- Key normalisation (16.4): the closed list of rules, each with canonical and non-canonical input.
- Object keys as one canonical string (16.5): encode, decode, round trip, nesting; the object id.
- Function descriptors (7): `classes` on string arguments and returns, and `default` ("asof").
"""

import copy
import json
import unicodedata
import unittest

from helpers import ROOT, canon

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")

STR, DATE = {"type": "string", "valid": False}, {"type": "date", "valid": True}
KEY = dict(STR, key_normalisation="upper_ascii")  # a method's key argument carries its key's rule (16.2)
RATE_UNIT = {"of": {"arg": "quote"}, "per": {"arg": "base"}}


def fn(args, order, returns, lang="stored", body="", inputs=()):
    return {"code": {"body": body, "lang": lang}, "inputs": list(inputs),
            "signature": {"args": args, "order": order, "returns": returns}}


RATE = fn({"base": KEY, "date": DATE, "quote": KEY}, ["base", "quote", "date"], {"type": "number", "unit": RATE_UNIT})
CROSS = fn({"base": KEY, "date": DATE, "quote": KEY, "via": STR}, ["base", "quote", "via", "date"],
           {"type": "number", "unit": RATE_UNIT}, "expr", "rate(base, via, date) * rate(via, quote, date)\n",
           ["rates.example.org/fx_pair/rate"])
RATE_ALT = fn({"base": KEY, "date": DATE, "quote": KEY}, ["base", "quote", "date"], {"type": "number", "unit": RATE_UNIT},
              "expr", "a re-derived rate\n", ["rates.example.org/fx_pair/rate"])
H = canon.function_hash
STEWARD = {"namespace": "rates.example.org", "process": "https://rates.example.org/classes/change"}
UPPER = {"key_normalisation": "upper_ascii", "type": "string"}
FX_PAIR = {"keys": {"base": UPPER, "quote": UPPER}, "methods": {"cross": H(CROSS), "rate": H(RATE)},
           "order": ["base", "quote"], "steward": STEWARD}
ENV = {"functions": [RATE, CROSS, RATE_ALT], "classes": [], "definer": "rates.example.org"}


def code(f, *args):
    try:
        return f(*args)
    except canon.DatumeshError as e:
        return e.code


def define(name, desc, env=ENV):
    return canon.define_class(name, desc, env)


class Descriptor(unittest.TestCase):
    def test_valid_and_hash(self):
        flat = define("rates.example.org/fx_pair", FX_PAIR)
        self.assertEqual(flat, FX_PAIR)  # no parent: the flattened descriptor is the descriptor
        self.assertEqual(canon.class_hash(flat), canon.sha256_hex(canon.jcs(FX_PAIR)))
        # Member order is not data.
        reordered = {k: FX_PAIR[k] for k in reversed(list(FX_PAIR))}
        self.assertEqual(canon.class_hash(define("rates.example.org/fx_pair", reordered)), canon.class_hash(flat))

    def test_members(self):
        cases = {
            "E_SCHEMA": [{k: v for k, v in FX_PAIR.items() if k != "steward"}, dict(FX_PAIR, extra=1),
                         dict(FX_PAIR, final=False), dict(FX_PAIR, keys={"base": {"class": "a.example/x", "type": "string"},
                                                                         "quote": UPPER}),
                         dict(FX_PAIR, methods={"rate": 1}), dict(FX_PAIR, open=[]), dict(FX_PAIR, maps=[])],
            "E_CANON_ARG_NAME": [dict(FX_PAIR, keys={"asof": UPPER, "quote": UPPER}, order=["asof", "quote"])],
            "E_CANON_TYPE": [dict(FX_PAIR, keys={"base": {"type": "blob"}, "quote": UPPER}),
                             dict(FX_PAIR, keys={"base": {"type": "colour"}, "quote": UPPER})],
            "E_CANON_UNIT": [dict(FX_PAIR, keys={"base": {"type": "number"}, "quote": UPPER}),
                             dict(FX_PAIR, keys={"base": dict(UPPER, unit="1"), "quote": UPPER})],
            "E_CANON_SET": [dict(FX_PAIR, order=["base"]), dict(FX_PAIR, order=["quote", "base", "base"]),
                            dict(FX_PAIR, final=True, open=["rate", "cross"])],
            "E_CANON_HEX": [dict(FX_PAIR, methods={"rate": "AB" * 32}), dict(FX_PAIR, parent="1234")],
            "E_CANON_NAME": [dict(FX_PAIR, methods={"Rate": H(RATE)}),
                             dict(FX_PAIR, keys={"base": {"class": "currency"}, "quote": UPPER})],
            "E_CLASS_MEMBER": [dict(FX_PAIR, keys={"base": dict(UPPER, key_normalisation="lower"), "quote": UPPER}),
                               dict(FX_PAIR, keys={"base": {"type": "string"}, "quote": UPPER}),
                               dict(FX_PAIR, keys={"base": {"key_normalisation": "none", "type": "date"},
                                                   "quote": UPPER}),
                               dict(FX_PAIR, steward=dict(STEWARD, process="ftp://x")),
                               dict(FX_PAIR, open=["rate"]),  # open without final
                               dict(FX_PAIR, final=True, open=["points"]),  # not a method
                               dict(FX_PAIR, inverse=["isin"]),  # no by_isin method
                               dict(FX_PAIR, maps=["not a uri"])],
        }
        for expected, descs in cases.items():
            for d in descs:
                with self.subTest(expected=expected, desc=d):
                    self.assertEqual(code(canon.check_class, d), expected)

    def test_vectors(self):
        valid = [v for v in VECTORS.values() if v["kind"] == "class" and v["valid"]]
        invalid = [v for v in VECTORS.values() if v["kind"] == "class" and not v["valid"]]
        self.assertGreaterEqual(len(valid), 8)
        self.assertGreaterEqual(len(invalid), 20)
        for v in valid + invalid:
            with self.subTest(v["id"]):
                self.assertEqual(canon.check_vector(v), [])
        codes = {v["error"] for v in invalid}
        self.assertTrue({"E_CLASS_MEMBER", "E_CLASS_METHOD", "E_CLASS_OVERRIDE", "E_CLASS_FINAL", "E_CLASS_PARENT",
                         "E_CLASS_INHERIT", "E_CLASS_OWNER", "E_CLASS_INTERFACE"} <= codes, codes)


NDF_OWN = {"keys": {"fixing": {"key_normalisation": "none", "type": "string"}}, "methods": {"rate": H(RATE_ALT)},
           "order": ["fixing"], "parent": None,
           "steward": {"namespace": "calc.example.net", "process": "https://calc.example.net/classes"}}


class Inheritance(unittest.TestCase):
    def setUp(self):
        self.parent = define("rates.example.org/fx_pair", FX_PAIR)
        self.ph = canon.class_hash(self.parent)
        self.env = dict(ENV, classes=[self.parent], definer="calc.example.net")
        self.own = dict(NDF_OWN, parent=self.ph)

    def test_flattened(self):
        flat = define("calc.example.net/fx_ndf", self.own, self.env)
        self.assertEqual(flat["order"], ["base", "quote", "fixing"])
        self.assertEqual(set(flat["keys"]), {"base", "quote", "fixing"})
        self.assertEqual(flat["methods"], {"cross": H(CROSS), "rate": H(RATE_ALT)})  # rate overridden
        self.assertEqual(flat["parent"], self.ph)

    def test_child_hash_stays_until_redefined(self):
        flat = define("calc.example.net/fx_ndf", self.own, self.env)
        # The parent is redefined (a new method): the child's flattened descriptor still names the old
        # parent and keeps its hash; redefining the child against the new parent gives a new hash.
        p2 = define("rates.example.org/fx_pair", dict(FX_PAIR, maps=["https://schema.example/fx"]))
        self.assertNotEqual(canon.class_hash(p2), self.ph)
        self.assertEqual(canon.class_hash(define("calc.example.net/fx_ndf", self.own, self.env)), canon.class_hash(flat))
        env2 = dict(self.env, classes=[self.parent, p2])
        again = define("calc.example.net/fx_ndf", dict(self.own, parent=canon.class_hash(p2)), env2)
        self.assertNotEqual(canon.class_hash(again), canon.class_hash(flat))

    def test_rules(self):
        cross_unit = fn({"base": KEY, "date": DATE, "quote": KEY}, ["base", "quote", "date"],
                        {"type": "number", "unit": "1"}, "expr", "x\n")
        extra_arg = fn({"base": KEY, "date": DATE, "quote": KEY, "x": STR}, ["base", "quote", "date", "x"],
                       {"type": "number", "unit": RATE_UNIT}, "expr", "x\n")
        env = dict(self.env, functions=ENV["functions"] + [cross_unit, extra_arg])
        cases = [
            (dict(self.own, methods={"rate": H(cross_unit)}), env, "E_CLASS_OVERRIDE"),  # unit changed
            (dict(self.own, methods={"rate": H(extra_arg)}), env, "E_CLASS_OVERRIDE"),  # signature changed
            (dict(self.own, keys={"base": {"key_normalisation": "none", "type": "string"}}, order=["base"]), env,
             "E_CLASS_INHERIT"),  # a parent key redeclared (retyped)
            (dict(self.own, parent="ab" * 32), env, "E_CLASS_PARENT"),
            (self.own, dict(env, definer="other.example.org"), "E_CLASS_OWNER"),
        ]
        for d, e, expected in cases:
            with self.subTest(expected):
                self.assertEqual(code(canon.define_class, "calc.example.net/fx_ndf", d, e), expected)

    def test_final_and_open(self):
        final = define("rates.example.org/fx_pair", dict(FX_PAIR, final=True))
        fh = canon.class_hash(final)
        env = dict(self.env, classes=[final])
        self.assertEqual(code(define, "calc.example.net/fx_ndf", dict(self.own, parent=fh), env), "E_CLASS_FINAL")
        # Adding is allowed under a final class; overriding an open method too.
        add_only = dict(self.own, parent=fh, methods={})
        self.assertIn("rate", define("calc.example.net/fx_ndf", add_only, env)["methods"])
        open_ = define("rates.example.org/fx_pair", dict(FX_PAIR, final=True, open=["rate"]))
        env = dict(self.env, classes=[open_])
        self.assertEqual(define("calc.example.net/fx_ndf", dict(self.own, parent=canon.class_hash(open_)), env)
                         ["methods"]["rate"], H(RATE_ALT))

    def test_method_signatures(self):
        wrong_keys = fn({"pair": STR, "date": DATE}, ["pair", "date"], {"type": "number", "unit": "1"})
        no_order = {"code": {"body": "", "lang": "stored"}, "inputs": [],
                    "signature": {"args": {"base": STR, "quote": STR}, "returns": "string"}}
        env = dict(ENV, functions=ENV["functions"] + [wrong_keys, no_order])
        for m in (wrong_keys, no_order):
            self.assertEqual(code(define, "rates.example.org/fx_pair", dict(FX_PAIR, methods={"x": H(m)}), env),
                             "E_CLASS_METHOD")
        self.assertEqual(code(define, "rates.example.org/fx_pair", dict(FX_PAIR, methods={"x": "cd" * 32})),
                         "E_CLASS_METHOD")  # no descriptor for the hash


class Normalisation(unittest.TestCase):
    CASES = {
        "none": (["anything at all", "eur", ""], []),
        "upper_ascii": (["EUR", "1M", "XAMS:ASML"], ["eur", "Eur", "ÉUR", "E R", ""]),
        "nfc_strict": (["Zürich", "New York"], ["a‍b", "New  York", " lead", "trail ", "‮bidi"]),
        "hebrew_consonantal": (["בראשית ברא אלהים", "את־השמים"], ["בְּרֵאשִׁית", "בָּרָ֣א"]),
        "greek_unaccented": (["Εν αρχη ην ο λογος"], ["Ἐν ἀρχῇ ἦν ὁ λόγος", "λόγος"]),
        "arabic_skeleton": (["بسم ٱلله ٱلرحمن ٱلرحيم"], ["بِسْمِ ٱللَّهِ", "ٱلرَّحْمَٰنِ", "اللـه"]),
    }

    def test_rules(self):
        self.assertEqual(canon.KEY_NORMALISATIONS, ("none", "upper_ascii", "nfc_strict", "arabic_skeleton",
                                                     "hebrew_consonantal", "greek_unaccented"))
        for rule, (good, bad) in self.CASES.items():
            for v in good:
                with self.subTest(rule=rule, value=v):
                    canon.check_key_value(rule, unicodedata.normalize("NFC", v), "$")
            for v in bad:
                with self.subTest(rule=rule, value=v):
                    self.assertEqual(code(canon.check_key_value, rule, unicodedata.normalize("NFC", v), "$"),
                                     "E_KEY_NORMALISATION")

    def test_vectors(self):
        vs = [v for v in VECTORS.values() if v["kind"] == "normalisation"]
        for rule in canon.KEY_NORMALISATIONS:
            self.assertTrue(any(v["rule"] == rule and v["valid"] for v in vs), rule)
            if rule != "none":
                self.assertTrue(any(v["rule"] == rule and not v["valid"] for v in vs), rule)
        for v in vs:
            with self.subTest(v["id"]):
                self.assertEqual(canon.check_vector(v), [])


class Keys(unittest.TestCase):
    def test_encode_decode(self):
        cur = canon.encode_key("iso.example.org/currency", {"code": {"type": "string", "value": "EUR"}})
        self.assertEqual(cur, 'iso.example.org/currency(code:"EUR")')
        pair = canon.encode_key("rates.example.org/fx_pair", {"quote": {"type": "string", "value": "U\"SD"},
                                                              "base": canon.decode_key(cur)})
        self.assertEqual(pair, 'rates.example.org/fx_pair(base:iso.example.org/currency(code:"EUR"),quote:"U""SD")')
        dec = canon.decode_key(pair)
        self.assertEqual(dec["class"], "rates.example.org/fx_pair")
        self.assertEqual(dec["keys"]["base"], {"class": "iso.example.org/currency",
                                               "keys": {"code": {"type": "string", "value": "EUR"}}})
        self.assertEqual(canon.encode_decoded(dec), pair)
        v = canon.decode_key('s.example.org/verse(book:"Gen",chapter:1,corpus:"tanakh",d:2024-03-15,t:true,verse:1)')
        self.assertEqual(v["keys"]["chapter"], {"type": "number", "value": "1"})
        self.assertEqual(v["keys"]["d"], {"type": "date", "value": "2024-03-15"})
        self.assertEqual(v["keys"]["t"], {"type": "boolean", "value": True})

    def test_not_canonical(self):
        for text in ['iso.example.org/currency(code: "EUR")', 'iso.example.org/currency(code:EUR)',
                     'b.example/x(z:1,a:2)', 'b.example/x(a:01)', 'b.example/x(a:1,a:2)', 'b.example/x()x',
                     'currency(code:"EUR")', 'b.example/x(a:"\u0001")', 'b.example/x(a:"x"', '']:
            with self.subTest(text):
                self.assertEqual(code(canon.decode_key, text), "E_KEY_ENCODING")
        self.assertEqual(canon.decode_key("b.example/x()"), {"class": "b.example/x", "keys": {}})

    def test_object_id(self):
        obj = canon.object_of("rates.example.org/fx_pair", "ab" * 32,
                              {"base": {"type": "string", "value": "EUR"}, "quote": {"type": "string", "value": "USD"}})
        self.assertEqual(obj, {"class": "rates.example.org/fx_pair", "class_hash": "ab" * 32,
                               "keys": {"base": {"type": "string", "value": "EUR"},
                                        "quote": {"type": "string", "value": "USD"}}})
        self.assertEqual(canon.object_id(obj), canon.sha256_hex(canon.jcs(obj)))
        self.assertEqual(canon.short_id(canon.object_id(obj)), canon.object_id(obj)[:12])

    def test_vectors(self):
        vs = [v for v in VECTORS.values() if v["kind"] == "key"]
        self.assertTrue(any(v["valid"] for v in vs) and any(not v["valid"] for v in vs))
        for v in vs:
            with self.subTest(v["id"]):
                self.assertEqual(canon.check_vector(v), [])


class FunctionDescriptor(unittest.TestCase):
    def test_classes_and_default(self):
        ok = fn({"pair": dict(STR, classes=["rates.example.org/fx_pair"]), "date": dict(DATE, default="asof")},
                ["pair", "date"], {"type": "string", "classes": ["iso.example.org/currency"]})
        canon.check_function(ok)
        bad = [
            (fn({"n": {"type": "number", "unit": "1", "valid": False, "classes": ["a.example/x"]}}, ["n"], "string"),
             "E_CANON_TYPE"),
            (fn({"s": dict(STR, classes=[])}, ["s"], "string"), "E_CANON_SET"),
            (fn({"s": dict(STR, classes=["b.example/y", "a.example/x"])}, ["s"], "string"), "E_CANON_SET"),
            (fn({"s": dict(STR, classes=["x"])}, ["s"], "string"), "E_CANON_NAME"),
            (fn({"d": dict(DATE, default="today")}, ["d"], "string"), "E_SCHEMA"),
            (fn({"d": dict(DATE, valid=False, default="asof")}, ["d"], "string"), "E_CANON_TYPE"),
            (fn({"s": {"type": "string", "valid": True, "default": "asof"}}, ["s"], "string"), "E_CANON_TYPE"),
            (fn({"s": STR}, ["s"], {"type": "string"}), "E_CANON_UNIT"),
            (fn({"s": STR}, ["s"], {"type": "date", "classes": ["a.example/x"]}), "E_CANON_TYPE"),
        ]
        for d, expected in bad:
            with self.subTest(d=d):
                self.assertEqual(code(canon.check_function, d), expected)

    def test_old_descriptors_unchanged(self):
        for v in VECTORS.values():
            if v["kind"] == "function" and v["valid"]:
                self.assertEqual(canon.check_vector(v), [])


class Text(unittest.TestCase):
    def test_statements(self):
        for phrase in ("## 16. Classes", "### 16.1 The class descriptor", "### 16.2 Define and flattening",
                       "### 16.4 Key normalisation", "### 16.5 Object keys", "class hash",
                       "| `class` (since `spec-0.5.0`)", "| `normalisation` (since `spec-0.5.0`)",
                       "| `key` (since `spec-0.5.0`)", "| D82 |"):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)
        for c in ("E_CLASS_MEMBER", "E_CLASS_PARENT", "E_CLASS_INHERIT", "E_CLASS_OVERRIDE", "E_CLASS_FINAL",
                  "E_CLASS_METHOD", "E_CLASS_INTERFACE", "E_CLASS_OWNER", "E_KEY_NORMALISATION", "E_KEY_ENCODING"):
            self.assertIn(c, canon.ERROR_CODES)
            self.assertRegex(SPEC, rf"\| `{c}` \| class \|")


if __name__ == "__main__":
    unittest.main()
