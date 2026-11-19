# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0, classes: clarifications from the verifier libraries (BRIEF-spec-0.5.0-clarifications).

Three libraries (Rust core, Python, JS) implemented spec-0.5.0 from the text; each point below makes
the text say one thing and the reference and the vectors agree with it.

1. JS-1/RS-a/PY-2: exactly which codes an `error` envelope may not carry (5.5).
2. RS-b/PY-1: E_KEY_NORMALISATION and E_KEY_ENCODING are `bad_request` codes, never `error`.
3. JS-2/RS-d/PY-5: a key value is first a string by 3.5; `none` is any such string; nfc_strict's
   spaces are the White_Space characters.
4. JS-3/RS-g: an unknown rule, "none" on a non-string argument, an empty `classes`.
5. JS-4/RS-f/PY-6: the describe check as a numbered procedure; RS-j's AttributeError.
6. JS-5/RS-e/PY-3: a class-typed key in the object JSON is a typed string scalar.
7. PY-4/RS-f: limits and codes inside a key encoding.
8. JS-6: a lookup method taking the class keys is E_CLASS_MEMBER.
9. PY-7: define receives the interfaces' method descriptors.
10. PY-8: the short id of a malformed id is E_CANON_HEX.
11. RS-c/PY-9: code counts and order.
"""

import copy
import json
import unicodedata
import unittest

from helpers import ROOT, canon
import class_world as W

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
CLASSES = W.SCENARIO["classes"]
FUNCS = W.SCENARIO["functions"]


def section(start, end):
    return SPEC[SPEC.index(start):SPEC.index(end)]


S55 = section("### 5.5 Response envelope", "### 5.6 Slices")
S7 = section("## 7. Function descriptors", "### 7.1 Units")
S164 = section("### 16.4 Key normalisation", "### 16.5 Object keys")
S165 = section("### 16.5 Object keys", "### 16.6 Bounded dispatch")
S168 = section("### 16.8 describe and short ids", "### 16.9 Shadowing")
S162 = section("### 16.2 Define and flattening", "### 16.3 Method calls")
S14 = section("### spec-0.5.0", "### spec-0.4.3")


def env(body, status):
    try:
        return canon.check_envelope(status, json.dumps(body).encode(), {}, {"cell_id": "a" * 64})["outcome"]
    except canon.DatumeshError as e:
        return e.code


def code(f, *args):
    try:
        f(*args)
        return None
    except canon.DatumeshError as e:
        return e.code


def check_vectors(test, ids):
    for vid in ids:
        with test.subTest(vid):
            test.assertTrue(vid in VECTORS, f"no vector {vid}")
            test.assertEqual(canon.check_vector(VECTORS[vid]), [])


CLASS_CODES = ("E_CLASS_MEMBER", "E_CLASS_PARENT", "E_CLASS_INHERIT", "E_CLASS_OVERRIDE", "E_CLASS_FINAL",
               "E_CLASS_METHOD", "E_CLASS_INTERFACE", "E_CLASS_OWNER")
NOT_IN_ERROR = ("E_ENVELOPE", "E_DESCRIBE", "E_JOB_UNKNOWN", "E_SLICE_AT_CELL", "E_NAME_UNBOUND",
                "E_SHORT_ID_AMBIGUOUS", "E_KEY_NORMALISATION", "E_KEY_ENCODING", "E_UNROOTED_INPUT",
                "E_NAMESPACE_SUSPENDED", "E_WHATIF_UNSUPPORTED", "E_WHATIF_NO_SOLUTION") + CLASS_CODES


class ErrorEnvelopeCodes(unittest.TestCase):
    """Points 1 and 2 (5.5)."""

    def test_error_excludes_exactly_the_listed_codes(self):
        for c in canon.ERROR_CODES:
            with self.subTest(c):
                body = {"error": c, "outcome": "error"}
                if c == "E_FOREIGN_UNAVAILABLE":
                    body["detail"] = "offline"
                self.assertEqual(env(body, 502 if c == "E_FOREIGN_UNAVAILABLE" else 500),
                                 "E_ENVELOPE" if c in NOT_IN_ERROR else "error")

    def test_key_codes_are_bad_request_codes(self):
        for c in ("E_KEY_NORMALISATION", "E_KEY_ENCODING"):
            with self.subTest(c):
                self.assertIn(c, canon.REQUEST_CODES)
                self.assertEqual(env({"error": c, "outcome": "bad_request"}, 400), "bad_request")
                self.assertEqual(env({"error": c, "outcome": "error"}, 500), "E_ENVELOPE")

    def test_envelope_schema(self):
        from test_vectors import validator
        v = validator("envelope")
        for c in ("E_KEY_NORMALISATION", "E_KEY_ENCODING"):
            self.assertTrue(v.is_valid({"error": c, "outcome": "bad_request"}), c)
            self.assertFalse(v.is_valid({"error": c, "outcome": "error"}), c)

    def test_vectors(self):
        check_vectors(self, ("envelope/bad-request-key-normalisation", "envelope/bad-request-key-encoding",
                             "invalid/envelope-key-normalisation-in-error", "invalid/envelope-key-encoding-in-error",
                             "invalid/envelope-class-code-in-error", "invalid/envelope-describe-in-error"))
        self.assertTrue(VECTORS["envelope/bad-request-key-normalisation"]["valid"])
        self.assertEqual(VECTORS["invalid/envelope-class-code-in-error"]["error"], "E_ENVELOPE")

    def test_text(self):
        err = next(l for l in S55.splitlines() if l.startswith("- `error`: what failed."))
        bad_request, _, rest = err.partition("For `not_covered`")
        for c in ("E_KEY_NORMALISATION", "E_KEY_ENCODING"):
            self.assertIn(f"`{c}`", bad_request)
        error_part = rest[rest.index("For `error`"):]
        for c in NOT_IN_ERROR:
            with self.subTest(c):
                self.assertIn(f"`{c}`", error_part)
        self.assertIn("exactly these", error_part)


class NormalisationAndStrings(unittest.TestCase):
    """Point 3 (16.4 against 3.5)."""

    def test_a_key_value_is_first_a_string(self):
        for text in ("a\tb", "a\nb", "a\x00b", unicodedata.normalize("NFD", "Zürich"), "\u0378"):
            for rule in canon.KEY_NORMALISATIONS:
                with self.subTest(rule=rule, text=text):
                    self.assertEqual(code(canon.check_key_value, rule, text, "$"), "E_CANON_STRING")
        self.assertEqual(code(canon.check_key_value, "none", "x" * 1025, "$"), "E_CANON_LIMIT")
        self.assertIsNone(code(canon.check_key_value, "none", "", "$"))
        for rule in canon.KEY_NORMALISATIONS[1:]:
            self.assertEqual(code(canon.check_key_value, rule, "", "$"), "E_KEY_NORMALISATION")

    def test_nfc_strict_white_space(self):
        for c in ("\u00a0", "\u1680", "\u2002", "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000"):
            with self.subTest(hex(ord(c))):
                self.assertEqual(code(canon.check_key_value, "nfc_strict", f"a{c}b", "$"), "E_KEY_NORMALISATION")
        self.assertIsNone(code(canon.check_key_value, "nfc_strict", "a b", "$"))
        # U+2000 and U+2001 are not NFC (they decompose to U+2002 and U+2003): refused by 3.5 first.
        self.assertEqual(code(canon.check_key_value, "nfc_strict", "a\u2000b", "$"), "E_CANON_STRING")
        self.assertEqual(code(canon.check_key_value, "nfc_strict", "a\u200bb", "$"), "E_KEY_NORMALISATION")  # Cf

    def test_vectors(self):
        check_vectors(self, ("normalisation/none-empty", "invalid/normalisation-none-tab",
                             "invalid/normalisation-none-newline", "invalid/normalisation-none-nul",
                             "invalid/normalisation-none-nfd", "invalid/normalisation-nfc-strict-nbsp",
                             "invalid/normalisation-upper-ascii-empty"))
        for vid in ("invalid/normalisation-none-tab", "invalid/normalisation-none-newline",
                    "invalid/normalisation-none-nul", "invalid/normalisation-none-nfd"):
            self.assertEqual(VECTORS[vid]["error"], "E_CANON_STRING")

    def test_text(self):
        self.assertNotIn("Every rule but `none` rejects the empty string and a value that is not NFC", S164)
        self.assertIn("| `none` | is any string valid by 3.5, the empty string included |", S164)
        self.assertIn("White_Space", S164)
        self.assertIn("first a string value (3.5)", S164)
        row = next(l for l in SPEC.splitlines() if l.startswith("| `normalisation` (since `spec-0.5.0`)"))
        self.assertIn("E_CANON_STRING", row)


class RulesOnArguments(unittest.TestCase):
    """Point 4."""

    def fn(self, decl, returns="string"):
        return {"code": {"body": "", "lang": "stored"}, "inputs": [],
                "signature": {"args": {"a": decl}, "order": ["a"], "returns": returns}}

    def test_codes(self):
        str_ = {"type": "string", "valid": False}
        num = {"type": "number", "unit": "1", "valid": False}
        self.assertEqual(code(canon.check_function, self.fn(dict(str_, key_normalisation="lowercase"))), "E_SCHEMA")
        self.assertEqual(code(canon.check_function, self.fn(dict(num, key_normalisation="none"))), "E_SCHEMA")
        self.assertEqual(code(canon.check_function, self.fn(dict(num, key_normalisation="upper_ascii"))),
                         "E_CANON_TYPE")
        self.assertEqual(code(canon.check_function, self.fn(dict(str_, classes=[]))), "E_CANON_SET")
        self.assertEqual(code(canon.check_function, self.fn(str_, {"type": "string", "classes": []})), "E_CANON_SET")

    def test_vectors(self):
        check_vectors(self, ("invalid/function-key-normalisation-unknown",
                             "invalid/function-key-normalisation-none-number", "invalid/function-classes-empty",
                             "invalid/function-returns-classes-empty"))
        self.assertEqual(VECTORS["invalid/function-key-normalisation-none-number"]["error"], "E_SCHEMA")
        self.assertEqual(VECTORS["invalid/function-classes-empty"]["error"], "E_CANON_SET")

    def test_text(self):
        item = next(l for l in S7.splitlines() if l.startswith("- A `string` argument declaration without `classes`"))
        self.assertIn("structure is checked first", item)
        cls = next(l for l in S7.splitlines() if l.startswith("- A `string` argument declaration may have `classes`"))
        self.assertIn("an empty array is `E_CANON_SET`", cls)


FX_ANSWER = canon.describe_class(W.FX, CLASSES[W.FX], FUNCS, {"rate": "The reference rate."})
VERSE_KEYS = {"book": W.S("Gen"), "chapter": W.N("1"), "corpus": W.S("tanakh"), "verse": W.N("1")}
VERSE_ANSWER = canon.describe_object(W.VERSE, CLASSES[W.VERSE], VERSE_KEYS)


def describe(doc, classes=None, functions=None):
    try:
        canon.check_describe(doc, classes, functions)
        return None
    except canon.DatumeshError as e:
        return e.code


class Describe(unittest.TestCase):
    """Point 5 (16.8)."""

    def test_parse_codes_are_their_own(self):
        self.assertEqual(canon.run_vector({"kind": "describe", "input": "{", "valid": False})["error"], "E_PARSE_JSON")
        self.assertEqual(canon.run_vector({"kind": "describe", "input": '{"kind": "class", "kind": "class"}',
                                           "valid": False})["error"], "E_PARSE_DUPLICATE_KEY")

    def test_shape(self):
        for bad in (dict(FX_ANSWER, **{"class": True}), dict(FX_ANSWER, class_hash=7), dict(VERSE_ANSWER, call=1),
                    dict(VERSE_ANSWER, object=dict(VERSE_ANSWER["object"], **{"class": True})),
                    dict(VERSE_ANSWER, methods="text"), dict(FX_ANSWER, descriptor=[]),
                    dict(FX_ANSWER, methods=dict(FX_ANSWER["methods"], rate=dict(FX_ANSWER["methods"]["rate"],
                                                                                 description="")))):
            with self.subTest(bad):
                self.assertEqual(describe(bad), "E_DESCRIBE")
                self.assertEqual(describe(bad, CLASSES, FUNCS), "E_DESCRIBE")
        long = dict(FX_ANSWER, methods=dict(FX_ANSWER["methods"], rate=dict(FX_ANSWER["methods"]["rate"],
                                                                            description="x" * 1025)))
        self.assertEqual(describe(long), "E_DESCRIBE")

    def test_same_as_ascending_and_unique(self):
        a, b = 'bible.example.org/passage(osis:"Gen.1.1")', 'bible.example.org/passage(osis:"Gen.1.2")'
        good = canon.describe_object(W.VERSE, CLASSES[W.VERSE], VERSE_KEYS, same_as=[a, b])
        self.assertIsNone(describe(good, CLASSES))
        self.assertEqual(describe(dict(good, same_as=[b, a]), CLASSES), "E_DESCRIBE")
        self.assertEqual(describe(dict(good, same_as=[a, a]), CLASSES), "E_DESCRIBE")
        self.assertEqual(describe(dict(good, same_as=[]), CLASSES), "E_DESCRIBE")

    def test_held_class_found_by_hash(self):
        # The held classes are found by class_hash, whatever name they are held under.
        renamed = {"x.example.org/other": CLASSES[W.VERSE]}
        wrong_type = canon.describe_object(W.VERSE, CLASSES[W.VERSE], dict(VERSE_KEYS, chapter=W.S("1")))
        self.assertEqual(describe(wrong_type, renamed), "E_DESCRIBE")
        self.assertIsNone(describe(wrong_type, {}))  # nothing held: internal consistency only
        self.assertIsNone(describe(wrong_type))

    def test_object_against_held_class(self):
        fx = lambda keys: canon.describe_object(W.FX, CLASSES[W.FX], keys)
        self.assertIsNone(describe(fx({"base": W.S("EUR"), "quote": W.S("USD")}), CLASSES))
        self.assertEqual(describe(fx({"base": W.S("eur"), "quote": W.S("USD")}), CLASSES), "E_DESCRIBE")
        self.assertIsNone(describe(fx({"base": W.S("eur"), "quote": W.S("USD")})))
        self.assertEqual(describe(fx({"base": W.S("EUR")}), CLASSES), "E_DESCRIBE")
        self.assertEqual(describe(fx({"base": W.N("1"), "quote": W.S("USD")}), CLASSES), "E_DESCRIBE")
        self.assertEqual(describe(dict(fx({"base": W.S("EUR"), "quote": W.S("USD")}), methods=["rate"]), CLASSES),
                         "E_DESCRIBE")

    def test_class_typed_key_in_object(self):
        eur, usd = 'iso.example.org/currency(code:"EUR")', 'iso.example.org/currency(code:"USD")'
        ok = canon.describe_object(W.CCY_PAIR, CLASSES[W.CCY_PAIR], {"base": W.S(eur), "quote": W.S(usd)})
        self.assertIsNone(describe(ok, CLASSES))
        self.assertEqual(ok["call"], f'{W.CCY_PAIR}(base: "iso.example.org/currency(code:""EUR"")", '
                                     'quote: "iso.example.org/currency(code:""USD"")")')
        other = canon.describe_object(W.CCY_PAIR, CLASSES[W.CCY_PAIR],
                                      {"base": W.S('rates.example.org/fx_pair(base:"EUR",quote:"USD")'),
                                       "quote": W.S(usd)})
        self.assertEqual(describe(other, CLASSES), "E_DESCRIBE")

    def test_args_and_returns_only_with_functions(self):
        changed = copy.deepcopy(FX_ANSWER)
        changed["methods"]["rate"]["args"] = {}
        self.assertIsNone(describe(changed, CLASSES))
        self.assertEqual(describe(changed, CLASSES, list(FUNCS.values())), "E_DESCRIBE")
        ret = copy.deepcopy(FX_ANSWER)
        ret["methods"]["rate"]["returns"] = {"type": "number", "unit": "1"}
        self.assertIsNone(describe(ret, CLASSES))
        self.assertEqual(describe(ret, CLASSES, list(FUNCS.values())), "E_DESCRIBE")
        self.assertIsNone(describe(FX_ANSWER, CLASSES, list(FUNCS.values())))

    def test_nothing_held_still_checks_consistency(self):
        self.assertEqual(describe(dict(VERSE_ANSWER, call="x")), "E_DESCRIBE")
        self.assertEqual(describe(dict(VERSE_ANSWER, short_id="0" * 12)), "E_DESCRIBE")
        self.assertEqual(describe(dict(FX_ANSWER, class_hash="ab" * 32)), "E_DESCRIBE")

    def test_vectors(self):
        ids = ("invalid/describe-not-json", "invalid/describe-duplicate-member", "invalid/describe-class-not-string",
               "invalid/describe-description-empty", "invalid/describe-same-as-unsorted",
               "invalid/describe-same-as-duplicate", "invalid/describe-object-key-type",
               "invalid/describe-object-key-normalisation", "invalid/describe-object-key-names",
               "describe/object-not-held", "invalid/describe-object-not-held-call", "describe/class-functions",
               "invalid/describe-class-args", "invalid/describe-class-returns", "describe/class-args-unchecked",
               "describe/object-class-typed-key")
        check_vectors(self, ids)
        self.assertEqual(VECTORS["invalid/describe-not-json"]["error"], "E_PARSE_JSON")
        self.assertEqual(VECTORS["invalid/describe-duplicate-member"]["error"], "E_PARSE_DUPLICATE_KEY")
        self.assertIn("functions", VECTORS["describe/class-functions"])
        self.assertNotIn("functions", VECTORS["describe/class-args-unchecked"])

    def test_text(self):
        for phrase in ("1. **Parse**", "2. **Shape**", "3. **Consistency**", "4. **The held class**",
                       "5. **Against the held class**", "6. **Against the held functions**", "`E_PARSE_JSON`",
                       "byte for byte", "ascending and unique", "1 to 1024 bytes"):
            with self.subTest(phrase):
                self.assertIn(phrase, S168)
        row = next(l for l in SPEC.splitlines() if l.startswith("| `describe` (since `spec-0.5.0`)"))
        self.assertIn("`functions`", row)


NESTED = (f'{W.CCY_PAIR}(base:iso.example.org/currency(code:"EUR"),quote:iso.example.org/currency(code:"USD"))')


class ClassTypedKeyInObject(unittest.TestCase):
    """Point 6 (16.5)."""

    def test_object_of_key(self):
        h = canon.class_hash(CLASSES[W.CCY_PAIR])
        obj = canon.object_of_key(NESTED, h)
        self.assertEqual(obj, {"class": W.CCY_PAIR, "class_hash": h,
                               "keys": {"base": W.S('iso.example.org/currency(code:"EUR")'),
                                        "quote": W.S('iso.example.org/currency(code:"USD")')}})

    def test_vector(self):
        v = VECTORS["key/nested-object"]
        self.assertEqual(canon.check_vector(v), [])
        self.assertEqual(v["object"]["keys"]["base"], W.S('iso.example.org/currency(code:"EUR")'))
        self.assertEqual(v["object_id"], canon.object_id(v["object"]))

    def test_text(self):
        self.assertIn('`{"type": "string", "value": <its key encoding>}`', S165)
        self.assertIn("object id", S165)
        row = next(l for l in SPEC.splitlines() if l.startswith("| `key` (since `spec-0.5.0`)"))
        self.assertIn("`object_id`", row)


class KeyEncodingLimits(unittest.TestCase):
    """Point 7 (16.5)."""

    def test_codes(self):
        for text in ('a.example.org/k(d:2024-02-30)', 'a.example.org/k(i:2024-03-15T24:00:00.000000Z)',
                     'a.example.org/k(s:"' + unicodedata.normalize("NFD", "é") + '")', 'a.example.org/k(s:"a\tb")',
                     'a.example.org/k(s:"' + "x" * 1010 + '")'):
            with self.subTest(text[:40]):
                self.assertEqual(code(canon.decode_key, text), "E_KEY_ENCODING")
        at_limit = 'a.example.org/k(s:"' + "x" * (1024 - len('a.example.org/k(s:"")')) + '")'
        self.assertEqual(len(at_limit.encode()), 1024)
        self.assertIsNone(code(canon.decode_key, at_limit))

    def test_vectors(self):
        check_vectors(self, ("key/at-limit", "invalid/key-too-long", "invalid/key-date-calendar",
                             "invalid/key-string-nfd", "invalid/key-string-control"))

    def test_text(self):
        self.assertIn("at most 1024 bytes", S165)
        self.assertIn("calendar day", S165)


class LookupSignature(unittest.TestCase):
    """Point 8 (16.1)."""

    def test_vectors(self):
        check_vectors(self, ("invalid/class-lookup-signature", "invalid/class-lookup-keys-only"))
        for vid in ("invalid/class-lookup-signature", "invalid/class-lookup-keys-only"):
            self.assertEqual(VECTORS[vid]["error"], "E_CLASS_MEMBER")


class InterfacesAtDefine(unittest.TestCase):
    """Point 9 (16.2 step 8)."""

    def test_text(self):
        step8 = S162[S162.index("8. **Interfaces.**"):]
        self.assertIn("interface methods' function descriptors", step8)


class ShortIds(unittest.TestCase):
    """Point 10 (16.8)."""

    def test_malformed(self):
        for bad in ("ab" * 31, "AB" * 32, "x" * 64, "ab" * 33, ""):
            with self.subTest(bad):
                self.assertEqual(code(canon.short_id, bad), "E_CANON_HEX")
        self.assertEqual(canon.short_id("ab" * 32), "ab" * 6)

    def test_text(self):
        line = next(l for l in S168.splitlines() if l.startswith("- **Short ids.**"))
        self.assertIn("`E_CANON_HEX`", line)


class CodeCounts(unittest.TestCase):
    """Point 11 (10.2, 14)."""

    def test_counts_and_order(self):
        rows = [l for l in SPEC.splitlines() if l.startswith("| `E_") and "| class |" in l]
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(l.startswith("| `E_CLASS_") for l in rows), 8)
        self.assertLess(SPEC.index("| `E_SHORT_ID_AMBIGUOUS` |"), SPEC.index("| `E_DESCRIBE` |"))
        self.assertEqual(canon.ERROR_CODES[-2:], ("E_WHATIF_UNSUPPORTED", "E_WHATIF_NO_SOLUTION"))  # spec-0.6.0 appends its codes
        self.assertIn("the eight `E_CLASS_*` codes, `E_KEY_NORMALISATION` and `E_KEY_ENCODING`", S14)


class Changes(unittest.TestCase):
    def test_section_14(self):
        self.assertIn("**Library findings (verifier libraries, spec-0.5.0)**", S14)
        for pid in ("JS-1", "RS-a", "PY-2", "RS-b", "PY-1", "JS-2", "RS-d", "PY-5", "JS-3", "RS-g", "JS-4", "RS-f",
                    "PY-6", "RS-j", "JS-5", "RS-e", "PY-3", "PY-4", "JS-6", "PY-7", "PY-8", "RS-c", "PY-9"):
            with self.subTest(pid):
                self.assertIn(pid, S14)


if __name__ == "__main__":
    unittest.main()
