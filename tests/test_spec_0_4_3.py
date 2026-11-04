# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.3: licence inheritance, `declarations` in the key document, unrooted namespaces
(CONTRACT-spec-0.4.3, the user's decisions 1-4).

1. A computed receipt's licence is the strictest of its inputs' licences (8.5): three open tiers,
   the last of the listed ids within tiers 1 and 2, two share-alike ids refused, restricted
   licences only where the function's publisher declared them, open at `issued`; a refusal is
   `unlicensed`.
2. The key document's optional `declarations` (9.2): dated licence entries per function name under
   the document's own host; anything malformed rejects the document (E_KEY_DOC); 64 names, 16
   entries. A document with declarations verifies receipts exactly as one without. The verifier's
   entitlement check (10.3) is separate from verification and reports a named reason.
3. Unrooted namespaces are names under `.invalid` (2.5); `local.invalid` is a DNS name by 2.1.
4. README.md ("Test vectors"): formula and Excel evaluation vectors are defined against an
   isolated mesh; two are evaluator-only. The note is in the top-level README, not in vectors/,
   whose consumers read every entry there as a group directory of vector files.
"""

import json
import unittest

from helpers import ROOT, canon

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
T0 = "2020-01-01T00:00:00.000000Z"
T1 = "2024-01-01T00:00:00.000000Z"
ISSUED = "2024-03-16T09:00:00.000000Z"
FN = "calc.example.net/convert"
RESTRICTED = "https://rates.example.org/licences/restricted"
OTHER_RESTRICTED = "https://rates.example.org/licences/other"


def code(fn, *args):
    try:
        return fn(*args)
    except canon.DatumeshError as e:
        return e.code


def inherit(licences, declarations=None, fn=FN, issued=ISSUED, own="CC-BY-4.0"):
    got = canon.inherit_licence(licences, declarations or {}, fn, issued, own)
    return got["licence"], got["reason"]


def entry(licence, valid_from=T0, valid_to=None):
    e = {"licence": licence, "valid_from": valid_from}
    if valid_to:
        e["valid_to"] = valid_to
    return e


# ---------------------------------------------------------------------------
# 1. Licence inheritance (8.5)


class Tiers(unittest.TestCase):
    def test_the_three_open_tiers_in_order(self):
        self.assertEqual(canon.LICENCE_TIERS, (("CC0-1.0", "PDDL-1.0"),
                                               ("MIT", "Apache-2.0", "CC-BY-4.0", "OGL-UK-3.0"),
                                               ("CC-BY-SA-4.0", "ODbL-1.0")))
        for tier, ids in enumerate(canon.LICENCE_TIERS, 1):
            for licence in ids:
                self.assertEqual(canon.licence_tier(licence), tier)

    def test_everything_else_is_restricted(self):
        for licence in ("CC-BY-NC-4.0", "GPL-3.0-only", "cc0-1.0", "CC0", RESTRICTED, "https://tanach.us/License.html"):
            with self.subTest(licence):
                self.assertEqual(canon.licence_tier(licence), 4)


class Inherit(unittest.TestCase):
    def test_no_inputs_is_the_mesh_own_licence(self):
        self.assertEqual(inherit([]), ("CC-BY-4.0", "no_inputs"))
        self.assertEqual(inherit([], own=RESTRICTED), (RESTRICTED, "no_inputs"))

    def test_one_open_input(self):
        for ids in canon.LICENCE_TIERS:
            for licence in ids:
                self.assertEqual(inherit([licence]), (licence, "open"))

    def test_highest_tier_wins(self):
        self.assertEqual(inherit(["CC0-1.0", "MIT"]), ("MIT", "open"))
        self.assertEqual(inherit(["CC-BY-SA-4.0", "PDDL-1.0"]), ("CC-BY-SA-4.0", "open"))
        self.assertEqual(inherit(["MIT", "ODbL-1.0", "CC0-1.0"]), ("ODbL-1.0", "open"))

    def test_within_tiers_one_and_two_the_last_listed(self):
        self.assertEqual(inherit(["CC0-1.0", "PDDL-1.0"]), ("PDDL-1.0", "open"))
        self.assertEqual(inherit(["PDDL-1.0", "CC0-1.0"]), ("PDDL-1.0", "open"))
        self.assertEqual(inherit(["CC-BY-4.0", "MIT"]), ("CC-BY-4.0", "open"))
        self.assertEqual(inherit(["MIT", "Apache-2.0"]), ("Apache-2.0", "open"))
        self.assertEqual(inherit(["OGL-UK-3.0", "CC-BY-4.0", "MIT"]), ("OGL-UK-3.0", "open"))
        self.assertEqual(inherit(["CC-BY-4.0", "CC-BY-4.0"]), ("CC-BY-4.0", "open"))

    def test_two_share_alike_ids_are_refused(self):
        self.assertEqual(inherit(["CC-BY-SA-4.0", "ODbL-1.0"]), (None, "share_alike_conflict"))
        self.assertEqual(inherit(["CC0-1.0", "ODbL-1.0", "CC-BY-SA-4.0"]), (None, "share_alike_conflict"))
        self.assertEqual(inherit(["ODbL-1.0", "ODbL-1.0"]), ("ODbL-1.0", "open"))

    def test_restricted_needs_a_declaration_open_at_issued(self):
        self.assertEqual(inherit([RESTRICTED]), (None, "not_declared"))
        self.assertEqual(inherit([RESTRICTED], {FN: [entry(RESTRICTED)]}), (RESTRICTED, "declared"))
        self.assertEqual(inherit([RESTRICTED], {FN: [entry(RESTRICTED, T0, T1)]}), (None, "declaration_not_open"))
        self.assertEqual(inherit([RESTRICTED], {FN: [entry(RESTRICTED, "2025-01-01T00:00:00.000000Z")]}),
                         (None, "declaration_not_open"))
        # The window is the key window of 9.5: valid_from <= issued < valid_to.
        self.assertEqual(inherit([RESTRICTED], {FN: [entry(RESTRICTED, ISSUED)]}), (RESTRICTED, "declared"))
        self.assertEqual(inherit([RESTRICTED], {FN: [entry(RESTRICTED, T0, ISSUED)]}), (None, "declaration_not_open"))
        # Closed, then declared again.
        self.assertEqual(inherit([RESTRICTED], {FN: [entry(RESTRICTED, T0, T1), entry(RESTRICTED, ISSUED)]}),
                         (RESTRICTED, "declared"))

    def test_a_declaration_names_one_function_and_one_licence(self):
        self.assertEqual(inherit([RESTRICTED], {"calc.example.net/other": [entry(RESTRICTED)]}), (None, "not_declared"))
        self.assertEqual(inherit([RESTRICTED], {FN: [entry(OTHER_RESTRICTED)]}), (None, "not_declared"))
        self.assertEqual(inherit(["CC-BY-NC-4.0"], {FN: [entry("cc-by-nc-4.0")]}), (None, "not_declared"))

    def test_restricted_wins_over_public_domain_and_attribution(self):
        d = {FN: [entry(RESTRICTED)]}
        self.assertEqual(inherit(["CC0-1.0", RESTRICTED, "CC-BY-4.0"], d), (RESTRICTED, "declared"))
        self.assertEqual(inherit(["OGL-UK-3.0", RESTRICTED, "MIT", "PDDL-1.0"], d), (RESTRICTED, "declared"))
        self.assertEqual(inherit(["CC0-1.0", RESTRICTED]), (None, "not_declared"))

    def test_restricted_with_share_alike_is_refused(self):
        """The user's S2 b (2026-11-04): share-alike requires the result to carry it, a restricted
        licence forbids that; refused whether or not the restricted licence is declared, and
        share_alike_conflict comes before every restricted outcome."""
        d = {FN: [entry(RESTRICTED), entry(OTHER_RESTRICTED)]}
        for licences in (["CC-BY-SA-4.0", RESTRICTED], [RESTRICTED, "ODbL-1.0"], ["CC0-1.0", RESTRICTED, "CC-BY-SA-4.0"],
                         ["CC-BY-SA-4.0", "ODbL-1.0", RESTRICTED], ["ODbL-1.0", "ODbL-1.0", RESTRICTED],
                         ["CC-BY-SA-4.0", RESTRICTED, OTHER_RESTRICTED], ["CC-BY-NC-4.0", "CC-BY-SA-4.0"]):
            for declarations in (d, {}, {FN: [entry(RESTRICTED, T0, T1)]}):
                with self.subTest(licences=licences, declarations=declarations):
                    self.assertEqual(inherit(licences, declarations), (None, "share_alike_conflict"))
        # One share-alike id with open ones only is still that id.
        self.assertEqual(inherit(["ODbL-1.0", "ODbL-1.0", "CC0-1.0"]), ("ODbL-1.0", "open"))

    def test_two_different_restricted_licences_are_refused(self):
        d = {FN: [entry(RESTRICTED), entry(OTHER_RESTRICTED)]}
        self.assertEqual(inherit([RESTRICTED, OTHER_RESTRICTED], d), (None, "restricted_conflict"))
        self.assertEqual(inherit([RESTRICTED, OTHER_RESTRICTED]), (None, "restricted_conflict"))
        self.assertEqual(inherit([RESTRICTED, RESTRICTED], d), (RESTRICTED, "declared"))
        self.assertEqual(inherit(["CC-BY-NC-4.0", RESTRICTED], d), (None, "restricted_conflict"))

    def test_unlisted_spdx_ids_are_restricted(self):
        self.assertEqual(inherit(["CC-BY-NC-4.0"]), (None, "not_declared"))
        self.assertEqual(inherit(["CC-BY-NC-4.0"], {FN: [entry("CC-BY-NC-4.0")]}), ("CC-BY-NC-4.0", "declared"))
        self.assertEqual(inherit(["cc0-1.0"]), (None, "not_declared"))


# ---------------------------------------------------------------------------
# 2. declarations in the key document (9.2)

KEY = {"alg": "ed25519", "id": "d712b32a2cc5cb7c",
       "public": "843baeb22bfd0364fb1b7262b367fb3202e7886c69a070fecf8e343fedb1eabf", "valid_from": T0}


def keydoc(declarations, host="rates.example.org"):
    doc = {"host": host, "keys": [KEY], "proto": "datumesh/1"}
    if declarations is not ...:
        doc["declarations"] = declarations
    return json.dumps(doc)


class Declarations(unittest.TestCase):
    NAME = "rates.example.org/cross_rate"

    def test_limits(self):
        self.assertEqual(canon.LIMITS["declarations"], 64)
        self.assertEqual(canon.LIMITS["declaration_entries"], 16)

    def test_optional_and_returned(self):
        self.assertEqual(canon.parse_key_document(keydoc(...), "rates.example.org")["declarations"], {})
        d = {self.NAME: [entry(RESTRICTED, T0, T1), entry(RESTRICTED, T1)],
             "rates.example.org/stats/mean_rate": [entry("CC-BY-NC-4.0")]}
        got = canon.parse_key_document(keydoc(d), "rates.example.org")
        self.assertEqual(got["declarations"], d)
        self.assertEqual([k["id"] for k in got["keys"]], [KEY["id"]])
        self.assertEqual([k["id"] for k in canon.parse_key_doc(keydoc(d), "rates.example.org")], [KEY["id"]])

    def test_at_the_limits(self):
        names = {f"rates.example.org/f{i}": [entry(RESTRICTED)] for i in range(64)}
        names["rates.example.org/f0"] = [entry(RESTRICTED, f"20{10 + i}-01-01T00:00:00.000000Z",
                                               f"20{11 + i}-01-01T00:00:00.000000Z") for i in range(16)]
        self.assertEqual(len(canon.parse_key_document(keydoc(names), "rates.example.org")["declarations"]), 64)

    def test_malformed_rejects_the_document(self):
        n = self.NAME
        cases = {
            "other host": {"other.example.org/cross_rate": [entry(RESTRICTED)]},
            "subdomain": {"eu.rates.example.org/cross_rate": [entry(RESTRICTED)]},
            "no function": {"rates.example.org": [entry(RESTRICTED)]},
            "bare name": {"cross_rate": [entry(RESTRICTED)]},
            "alias": {"@cross": [entry(RESTRICTED)]},
            "uppercase": {"rates.example.org/CrossRate": [entry(RESTRICTED)]},
            "bad licence": {n: [entry("CC BY 4.0")]},
            "licence too long": {n: [entry("A" * 65)]},
            "bad instant": {n: [entry(RESTRICTED, "2024-01-01")]},
            "bad valid_to": {n: [entry(RESTRICTED, T0, "2024-01-01T00:00:00Z")]},
            "valid_to equal": {n: [entry(RESTRICTED, T1, T1)]},
            "valid_to before": {n: [entry(RESTRICTED, T1, T0)]},
            "extra member": {n: [entry(RESTRICTED) | {"note": "x"}]},
            "missing licence": {n: [{"valid_from": T0}]},
            "missing valid_from": {n: [{"licence": RESTRICTED}]},
            "not a string": {n: [{"licence": RESTRICTED, "valid_from": T0, "valid_to": 1}]},
            "entry not an object": {n: [RESTRICTED]},
            "not an array": {n: entry(RESTRICTED)},
            "empty array": {n: []},
            "empty object": {},
            "not an object": [n],
            "null": None,
            "65 names": {f"rates.example.org/f{i}": [entry(RESTRICTED)] for i in range(65)},
            "17 entries": {n: [entry(RESTRICTED, f"20{10 + i}-01-01T00:00:00.000000Z",
                                     f"20{11 + i}-01-01T00:00:00.000000Z") for i in range(17)]},
        }
        for why, d in cases.items():
            with self.subTest(why):
                self.assertEqual(code(canon.parse_key_doc, keydoc(d), "rates.example.org"), "E_KEY_DOC")
                self.assertEqual(code(canon.resolve_keys, "rates.example.org",
                                      {"https": {"status": 200, "body": keydoc(d)}}), "E_KEY_DOC")

    def test_other_members_still_rejected(self):
        doc = json.loads(keydoc(...))
        doc["licences"] = {}
        self.assertEqual(code(canon.parse_key_doc, json.dumps(doc), "rates.example.org"), "E_KEY_DOC")

    def test_vectors(self):
        v = VECTORS["keys/declarations"]
        self.assertTrue(v["valid"])
        self.assertIn("declarations", v)
        self.assertEqual(canon.check_vector(v), [])
        self.assertTrue(VECTORS["keys/declarations-at-limits"]["valid"])
        for name in ("other-host", "subdomain", "not-function-name", "bad-licence", "bad-instant", "valid-to-equal",
                     "valid-to-before", "extra-member", "missing-member", "not-string", "empty-array",
                     "empty-object", "not-object", "65-names", "17-entries"):
            with self.subTest(name):
                vec = VECTORS[f"invalid/keys-declarations-{name}"]
                self.assertEqual(vec["error"], "E_KEY_DOC")
                self.assertEqual(canon.check_vector(vec), [])

    def test_existing_keys_vectors_have_no_declarations_output(self):
        self.assertNotIn("declarations", VECTORS["keys/https-document"])

    def test_receipts_verify_exactly_as_without(self):
        a, b = VECTORS["receipt/computed-with-lineage"], VECTORS["receipt/keydoc-declarations"]
        for field in ("input", "canonical", "sha256", "sig", "level", "keypair", "recompute"):
            self.assertEqual(a[field], b[field], field)
        self.assertNotEqual(a["keys"], b["keys"])
        for host, env in b["keys"].items():
            self.assertIn("declarations", json.loads(env["https"]["body"]), host)
        self.assertEqual(canon.check_vector(b), [])

    def test_mesh_resolution_accepts_declarations(self):
        v = VECTORS["mesh/keydoc-declarations"]
        self.assertIn("declarations", json.loads(v["env"]["keys"]["https"]["body"]))
        self.assertEqual(canon.check_vector(v), [])


class Entitlement(unittest.TestCase):
    def test_vectors(self):
        expected = {
            "entitlement/open-inherited": (True, "open"),
            "entitlement/stored-no-inputs": (True, "no_inputs"),
            "entitlement/restricted-declared": (True, "declared"),
            "entitlement/slice-members": (True, "open"),
            "entitlement/licence-mismatch": (False, "licence_mismatch"),
            "entitlement/restricted-licence-mismatch": (False, "licence_mismatch"),
            "entitlement/restricted-undeclared": (False, "not_declared"),
            "entitlement/declaration-closed": (False, "declaration_not_open"),
            "entitlement/declaration-opens-later": (False, "declaration_not_open"),
            "entitlement/share-alike-conflict": (False, "share_alike_conflict"),
            "entitlement/restricted-with-share-alike": (False, "share_alike_conflict"),
        }
        for name, (entitled, reason) in expected.items():
            with self.subTest(name):
                v = VECTORS[name]
                self.assertEqual((v["kind"], v["valid"], v["entitled"], v["reason"]), ("entitlement", True, entitled, reason))
                self.assertEqual(canon.check_vector(v), [])

    def test_procedure(self):
        r = {"cell": {"args": {}, "fn": "convert", "fn_hash": "a" * 64, "ns": "calc.example.net"},
             "computed_by": "calc.example.net#" + "0" * 16, "inputs": ["b" * 64], "issued": ISSUED,
             "licence": RESTRICTED}
        doc = {"host": "calc.example.net", "keys": [], "declarations": {FN: [entry(RESTRICTED)]}}
        self.assertEqual(canon.check_entitlement(r, [RESTRICTED, "CC0-1.0"], doc), {"entitled": True, "reason": "declared"})
        self.assertEqual(canon.check_entitlement(r, ["CC0-1.0"], doc), {"entitled": False, "reason": "licence_mismatch"})
        self.assertEqual(canon.check_entitlement(r, [RESTRICTED], dict(doc, declarations={})),
                         {"entitled": False, "reason": "not_declared"})
        self.assertEqual(canon.check_entitlement(dict(r, inputs=[]), [], doc), {"entitled": True, "reason": "no_inputs"})
        # The key document is the publisher's: another host's is the caller's error.
        with self.assertRaises(ValueError):
            canon.check_entitlement(r, [RESTRICTED], dict(doc, host="rates.example.org"))

    def test_not_a_verification_code(self):
        for reason in ("licence_mismatch", "not_declared", "declaration_not_open", "share_alike_conflict",
                       "restricted_conflict", "no_inputs", "open", "declared"):
            self.assertIn(f"`{reason}`", SPEC)
        self.assertNotIn("E_ENTITLEMENT", SPEC)
        self.assertNotIn("E_UNLICENSED", SPEC)


class LicenceVectors(unittest.TestCase):
    def test_kind(self):
        vs = [v for v in VECTORS.values() if v["kind"] == "licence"]
        self.assertGreaterEqual(len(vs), 40)
        for v in vs:
            with self.subTest(v["id"]):
                self.assertTrue(v["id"].startswith("licence/"))
                self.assertTrue(v["valid"])
                self.assertEqual(canon.check_vector(v), [])
        reasons = {v["reason"] for v in vs}
        self.assertEqual(reasons, {"no_inputs", "open", "declared", "share_alike_conflict", "restricted_conflict",
                                   "not_declared", "declaration_not_open"})
        self.assertTrue(all(v["licence"] is None for v in vs
                            if v["reason"] not in ("no_inputs", "open", "declared")))

    def test_named_cases(self):
        expected = {
            "licence/no-inputs": "no_inputs", "licence/cc0-mit": "open", "licence/within-attribution-all": "open",
            "licence/share-alike-two-ids": "share_alike_conflict", "licence/restricted-declared": "declared",
            "licence/restricted-undeclared": "not_declared",
            "licence/restricted-declaration-closed": "declaration_not_open",
            "licence/restricted-declaration-opens-later": "declaration_not_open",
            "licence/restricted-two-different": "restricted_conflict",
            "licence/unlisted-spdx-undeclared": "not_declared",
            "licence/restricted-with-open-declared": "declared",
            "licence/restricted-with-share-alike-conflict": "share_alike_conflict",
            "licence/restricted-declared-with-share-alike": "share_alike_conflict",
            "licence/restricted-undeclared-with-share-alike": "share_alike_conflict",
            "licence/two-restricted-with-share-alike": "share_alike_conflict",
        }
        for name, reason in expected.items():
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["reason"], reason)


# ---------------------------------------------------------------------------
# 3. Unrooted namespaces (2.5)


class Unrooted(unittest.TestCase):
    def test_local_invalid_is_a_dns_name(self):
        canon.check_dns_name("local.invalid", "$")
        canon.check_namespace("local.invalid/notes", "$")
        canon.check_key_ref("local.invalid#" + "0" * 16, "$")

    def test_unrooted(self):
        for ns in ("local.invalid", "local.invalid/notes", "agent-7.local.invalid", "x.invalid"):
            self.assertTrue(canon.is_unrooted(ns), ns)
        for ns in ("rates.example.org", "invalid.example.org", "invalid.example/x", "example.invalidx"):
            self.assertFalse(canon.is_unrooted(ns), ns)

    def test_vectors(self):
        self.assertTrue(VECTORS["cell/unrooted-namespace"]["valid"])
        self.assertTrue(VECTORS["receipt/unrooted-key-supplied"]["valid"])
        self.assertEqual(VECTORS["invalid/receipt-unrooted-no-key-document"]["error"], "E_KEY_UNAVAILABLE")
        for name in ("cell/unrooted-namespace", "receipt/unrooted-key-supplied",
                     "invalid/receipt-unrooted-no-key-document"):
            self.assertEqual(canon.check_vector(VECTORS[name]), [])


# ---------------------------------------------------------------------------
# Text, schemas, README


class Text(unittest.TestCase):
    def test_statements(self):
        for phrase in (
            "Status: draft, revision `spec-0.4.3`.",
            "### 2.5 Unrooted namespaces",
            "### 8.5 Licence inheritance",
            "### 10.3 Licence entitlement",
            "RFC 6761",
            "`local.invalid`",
            "`host`, `keys`, `proto`, and optionally `declarations`",
            "Entries are never removed",
            "the mesh may not compute this cell under the inheritance rule",
            "Later revisions may widen what a declaration permits",
            "A mesh that serves `declarations` is unverifiable by clients on core < 0.3.7 or datumesh < 0.4.3; "
            "publishers should wait for their consumers to upgrade before declaring.",
            "| `declarations` | 64 |", "| `declaration_entries` | 16 |",
            "### spec-0.4.3",
            "| D75 |", "| D76 |", "| D77 |",
            "| `licence` (since `spec-0.4.3`)", "| `entitlement` (since `spec-0.4.3`)",
            "`README.md`",
        ):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)

    def test_vectors_readme(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        readme = readme[readme.index("## Test vectors"):]
        # vectors/ holds group directories of vector files only: its consumers read it that way.
        self.assertEqual([p.name for p in (ROOT / "vectors").iterdir() if not p.is_dir()], [])
        for phrase in ("isolated mesh", "formula-eval", "excel", "invalid/formula-eval-depth",
                       "invalid/formula-eval-budget", "E_FORMULA_DEPTH", "evaluator-only"):
            self.assertIn(phrase, readme)
        for vid in ("invalid/formula-eval-depth", "invalid/formula-eval-budget"):
            self.assertIn(vid, VECTORS)
            self.assertNotIn("evaluator_only", VECTORS[vid])

    def test_crosscheck_readme(self):
        text = (ROOT / "crosscheck" / "README.md").read_text(encoding="utf-8")
        for phrase in ("spec-0.4.3", "generate_043.py", "`licence`", "`entitlement`", "LIBS=0.4.2"):
            self.assertIn(phrase, text)
        self.assertTrue((ROOT / "crosscheck" / "generate_043.py").exists())


class Schemas(unittest.TestCase):
    def test_keydoc_and_vector_schemas(self):
        from test_vectors import validator
        check = validator("keydoc")
        good = json.loads(keydoc({"rates.example.org/cross_rate": [entry(RESTRICTED, T0, T1)]}))
        check.validate(good)
        for bad in ({"rates.example.org/cross_rate": []}, {"rates.example.org/cross_rate": [entry(RESTRICTED) | {"x": "1"}]},
                    {"rates.example.org/cross_rate": [{"valid_from": T0}]}, {}):
            with self.subTest(bad):
                self.assertFalse(check.is_valid(dict(good, declarations=bad)))
        kinds = json.loads((ROOT / "schemas" / "vector.schema.json").read_text())["properties"]["kind"]["enum"]
        self.assertIn("licence", kinds)
        self.assertIn("entitlement", kinds)


if __name__ == "__main__":
    unittest.main()
