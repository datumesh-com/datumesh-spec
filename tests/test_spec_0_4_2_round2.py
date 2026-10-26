# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.2, round 2 (before the tag):

A. Two formula built-ins (the user's decision 3a): text_of(b), a text/plain blob's content as a
   string; remove_chars(s, chars). Blob content comes from the resolver by sha256; content it does
   not have is E_FORMULA_BLOB_UNAVAILABLE, the evaluator's failure (E_EVAL_UNAVAILABLE), not a fault.
B. The Python library's findings on 810761d (DEF-52 to DEF-56).
"""

import hashlib
import json
import unicodedata
import unittest

from helpers import ROOT, canon
import formula  # noqa: E402
import gen_formula as G  # noqa: E402

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
A = "2026-05-01T00:00:00.000000Z"
F = "calc.example.net/g"
SRC = "data.example.org/doc"
STR = {"type": "string", "valid": False}


def blob_of(content, media="text/plain"):
    return f"{hashlib.sha256(content).hexdigest()}:{len(content)}:{media}"


def run(body, content=b"hello", media="text/plain", store=True, returns="string", fuel=None, blobs=None):
    doc = G.stored({"k": STR}, ["k"], "blob")
    g = formula.define(F, {"args": {}, "order": [], "returns": G.ret(returns)}, body, {"functions": {SRC: doc}})
    value = blob_of(content, media)
    r = formula.stored_receipt(doc, SRC, {"k": {"type": "string", "value": "a"}}, {"type": "blob", "value": value},
                               "2026-02-01T00:00:00.000000Z")
    if blobs is None:
        blobs = {hashlib.sha256(content).hexdigest(): content} if store else {}
    w = formula.World({SRC: {"bound": G.BOUND, "descriptor": doc}, F: {"bound": G.BOUND, "descriptor": g}}, [r],
                      blobs=blobs)
    try:
        receipt = w.get(F, {}, A, fuel=fuel).receipt
        return receipt["value"], w.fuel_used
    except formula.FormulaError as e:
        return e.code, None


TEXT = 'text_of(data.example.org/doc(k: "a"))'
# Hebrew points and accents (U+0591-U+05C7), keeping maqaf U+05BE, paseq U+05C0, sof pasuq U+05C3
# and nun hafukha U+05C6, which are punctuation.
MARKS = "".join(chr(c) for c in range(0x0591, 0x05C8) if c not in (0x05BE, 0x05C0, 0x05C3, 0x05C6))
MARKS_LITERAL = unicodedata.normalize("NFC", MARKS)
# Genesis 1:1 with a maqaf, a paseq and sof pasuq added, pointed and accented (NFC).
POINTED = unicodedata.normalize("NFC", "בְּרֵאשִׁ֖ית בָּרָ֣א אֱלֹהִ֑ים ׀ אֵ֥ת־הַשָּׁמַ֖יִם וְאֵ֥ת הָאָֽרֶץ׃")
CONSONANTAL = "בראשית ברא אלהים ׀ את־השמים ואת הארץ׃"


class TextOf(unittest.TestCase):
    def test_value(self):
        self.assertEqual(run(TEXT)[0], "hello")
        nfd = unicodedata.normalize("NFD", "Zürich").encode()
        self.assertEqual(run(TEXT, nfd)[0], "Zürich")  # every string result is NFC
        self.assertEqual(run(TEXT, b"")[0], "")

    def test_faults_and_failures(self):
        self.assertEqual(run(TEXT, media="text/csv")[0], "E_FORMULA_DOMAIN")
        self.assertEqual(run(TEXT, media="application/octet-stream")[0], "E_FORMULA_DOMAIN")
        self.assertEqual(run(TEXT, b"\xff\xfe")[0], "E_FORMULA_DOMAIN")
        self.assertEqual(run(TEXT, b"line\n")[0], "E_FORMULA_DOMAIN")  # a string has no controls (3.5)
        self.assertEqual(run(TEXT, b"a" * 1024)[0], "a" * 1024)
        self.assertEqual(run(TEXT, b"a" * 1025)[0], "E_FORMULA_RANGE")
        self.assertEqual(run(TEXT, store=False)[0], "E_FORMULA_BLOB_UNAVAILABLE")
        wrong = {hashlib.sha256(b"hello").hexdigest(): b"hellO"}
        self.assertEqual(run(TEXT, blobs=wrong)[0], "E_FORMULA_BLOB_UNAVAILABLE")
        self.assertNotIn("E_FORMULA_BLOB_UNAVAILABLE", formula.FAULT_CODES)
        self.assertIn("E_FORMULA_BLOB_UNAVAILABLE", formula.EVAL_CODES)

    def test_media_type_checked_before_content(self):
        self.assertEqual(run(TEXT, media="text/csv", store=False)[0], "E_FORMULA_DOMAIN")

    def test_types(self):
        with self.assertRaises(formula.FormulaError) as e:
            formula.define(F, {"args": {}, "order": [], "returns": G.ret("string")}, 'text_of("x")', {"functions": {}})
        self.assertEqual(e.exception.code, "E_FORMULA_TYPE")

    def test_fuel(self):
        # nodes: text_of, the read, "a" (3), the read (1); then 1 + content bytes / 64, rounded down
        self.assertEqual(run(TEXT, b"a" * 130)[1], 3 + 1 + 1 + 2)
        self.assertEqual(run(TEXT, b"a" * 130, fuel=5)[0], "E_FORMULA_BUDGET")


class RemoveChars(unittest.TestCase):
    def test_value(self):
        self.assertEqual(run('remove_chars("a-b-c", "-")')[0], "abc")
        self.assertEqual(run('remove_chars("abcabc", "cb")')[0], "aa")
        self.assertEqual(run('remove_chars("abc", "")')[0], "abc")
        self.assertEqual(run('remove_chars("Zürich", "ü")')[0], "Zrich")  # NFC code points: ü is one

    def test_hebrew_consonantal(self):
        body = f'remove_chars(text_of(data.example.org/doc(k: "a")), "{MARKS_LITERAL}")'
        self.assertEqual(run(body, POINTED.encode())[0], CONSONANTAL)

    def test_fuel(self):
        self.assertEqual(run('remove_chars("a-b-c", "-")')[1], 3 + 1)

    def test_types(self):
        with self.assertRaises(formula.FormulaError) as e:
            formula.define(F, {"args": {}, "order": [], "returns": G.ret("string")}, "remove_chars(1, \"a\")",
                           {"functions": {}})
        self.assertEqual(e.exception.code, "E_FORMULA_TYPE")


class Vectors(unittest.TestCase):
    def test_vectors(self):
        for name in ("formula-eval/text-of", "formula-eval/text-of-nfc", "formula-eval/remove-chars",
                     "formula-eval/hebrew-consonantal", "excel/substitute"):
            with self.subTest(name):
                self.assertTrue(VECTORS[name]["valid"])
                self.assertEqual(canon.check_vector(VECTORS[name]), [])
        self.assertEqual(VECTORS["formula-eval/hebrew-consonantal"]["value"]["value"], CONSONANTAL)
        for name, code in [("invalid/formula-eval-text-of-media-type", "E_FORMULA_DOMAIN"),
                           ("invalid/formula-eval-text-of-utf8", "E_FORMULA_DOMAIN"),
                           ("invalid/formula-eval-text-of-control", "E_FORMULA_DOMAIN"),
                           ("invalid/formula-eval-text-of-long", "E_FORMULA_RANGE"),
                           ("invalid/formula-eval-text-of-unavailable", "E_FORMULA_BLOB_UNAVAILABLE"),
                           ("invalid/formula-text-of-string", "E_FORMULA_TYPE")]:
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["error"], code)
                self.assertEqual(canon.check_vector(VECTORS[name]), [])


# B. The library's findings.
SEED = bytes([81]) * 32
_, PUB = canon.keypair(SEED)
HOST = "rates.example.org"
KEYENV = {HOST: {"https": {"status": 200, "body": json.dumps({"host": HOST, "keys": [{
    "alg": "ed25519", "id": canon.key_id(PUB), "public": PUB.hex(), "valid_from": "2020-01-01T00:00:00.000000Z"}],
    "proto": canon.PROTO})}}}
H = "ab" * 32
T = "2024-03-16T09:00:00.000000Z"


def receipt(quote, quote_type="string"):
    cell = {"args": {"base": {"type": "string", "value": "EUR"}, "quote": {"type": quote_type, "value": quote}},
            "fn": "fx_rate", "fn_hash": H, "ns": HOST}
    r = {"asof": T, "cell": cell, "computed_by": f"{HOST}#{canon.key_id(PUB)}", "inputs": [], "issued": T,
         "licence": "CC0-1.0", "proto": canon.PROTO, "publisher": HOST, "summary": "A rate.",
         "tx": "2024-03-15T16:00:00.000000Z", "type": "number", "valid": {}, "value": "1.0892"}
    return canon.sign_receipt(r, SEED)


SLICE = {"args": {"base": {"type": "string", "value": "EUR"}, "quote": "*"}, "fn": "fx_rate", "fn_hash": H, "ns": HOST}
SREQ = {"asof": T, "slice_id": canon.slice_id(SLICE)}


def page(members, **over):
    return dict({"members": [{"outcome": "ok", "receipt": r, "trust": "primary"} for r in members], "outcome": "ok",
                 "slice": SLICE}, **over)


def check(env, request, status=200):
    try:
        return canon.check_envelope(status, json.dumps(env).encode(), KEYENV, request)["outcome"]
    except canon.DatumeshError as e:
        return e.code


class Findings(unittest.TestCase):
    def test_def52_page_fn_hash_is_the_slice_s(self):
        self.assertEqual(check(page([receipt("USD")], fn_hash=H), SREQ), "ok")
        self.assertEqual(check(page([receipt("USD")], fn_hash="cd" * 32), SREQ), "E_ENVELOPE")

    def test_def53_def55_cursors(self):
        usd = receipt("USD")
        self.assertEqual(check(page([usd]), dict(SREQ, after={"quote": {"type": "string", "value": "GBP"}})), "ok")
        extra = {"quote": {"type": "string", "value": "GBP"}, "tenor": {"type": "string", "value": "x"}}
        self.assertEqual(check(page([usd]), dict(SREQ, after=extra)), "ok")  # other names are ignored
        self.assertEqual(check(page([usd]), dict(SREQ, after={"tenor": {"type": "string", "value": "x"}})), "E_ENVELOPE")
        typed = {"quote": {"type": "number", "value": "1"}}
        self.assertEqual(check(page([usd]), dict(SREQ, after=typed)), "E_ENVELOPE")  # was a TypeError

    def test_def55_members_of_another_key_type(self):
        self.assertEqual(check(page([receipt("USD"), receipt("1", "number")]), SREQ), "E_ENVELOPE")

    def test_def56_the_pin_echo_comes_before_the_receipt(self):
        bad = dict(receipt("USD"), value="9")  # its signature no longer verifies
        cell_id = canon.sha256_hex(canon.jcs(bad["cell"]))
        env = {"outcome": "ok", "receipt": bad, "trust": "primary"}
        self.assertEqual(check(env, {"asof": T, "cell_id": cell_id, "fn_hash": H}), "E_ENVELOPE")
        self.assertEqual(check(dict(env, fn_hash=H), {"asof": T, "cell_id": cell_id, "fn_hash": H}), "E_SIGNATURE")

    def test_vectors(self):
        for name in ("invalid/envelope-slice-cursor-type", "invalid/envelope-slice-cursor-missing",
                     "invalid/envelope-slice-fn-hash", "invalid/envelope-pin-not-echoed-bad-receipt"):
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["error"], "E_ENVELOPE")
                self.assertEqual(canon.check_vector(VECTORS[name]), [])


class Text(unittest.TestCase):
    def test_statements(self):
        for phrase in ("| `text_of(blob)` |", "| `remove_chars(text, chars)` |", "`E_FORMULA_BLOB_UNAVAILABLE`",
                       "| `SUBSTITUTE` | partial |", "`text/plain`", "it MUST equal `slice`'s `fn_hash`",
                       "an item's `status` in a batch", "3a.", "a cursor"):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)


if __name__ == "__main__":
    unittest.main()
