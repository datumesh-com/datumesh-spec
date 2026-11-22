# SPDX-License-Identifier: Apache-2.0
"""spec-0.6.2 (CONTRACT-spec-0.6.2.md, P1-P4), tests first:

P1 `shares` and `pure` units and a rate per share (units.md, SPEC 7.1); P2 `last_by` and `first_by`
(15.7, 15.13); P3 the named `test_case` convention (7.3); P4 the `public:` licence (8.1, 8.5, 10.3).

(a) every new vector is on disk as tools/gen_vectors_0_6_2.py builds it, and every spec-0.6.1 file is
    byte-identical and still passes (read from git at the spec-0.6.1 tag; this needs git and the full history);
(b) the reference tools reproduce every new vector's expected result (the vectors were written first, so
    these fail until tools/canon.py and tools/formula.py are written);
(c) SPEC.md and units.md state each rule;
(d) the schemas know the new forms.

Choices (where the contract leaves something open, and what the vectors take):

* E_FORMULA_JOIN exists (15.11: "an operator over two slices with different key names or types"), so a `by`
  slice with an open argument that is not an open argument of `slice`, or with the same name and another key
  type, is E_FORMULA_JOIN, not the E_FORMULA_TYPE fallback. 15.11's row is to be widened to say so.
* A boolean `by` is E_FORMULA_TYPE (what `max` gives, define time). The contract's "different units in `by`"
  is E_FORMULA_UNIT_UNKNOWN, also what `max` gives (the unit depends on an open argument, so it cannot be
  determined statically): E_FORMULA_UNIT, which the contract names, is the code for a bad unit suffix and is
  not reachable. A scalar `by` or `slice`, and a group-key result used as a body, take the codes of the
  other lookups (E_FORMULA_TYPE, E_FORMULA_SLICE_VALUE); wrong arity is E_FORMULA_ARITY.
* The tie rule is key order of `slice` (open arguments ascending by name, 15.13 "Order"): `last_by` takes the
  later member, `first_by` the earlier one (the contract's rule; vectors `last-by-tie`, `first-by-tie`).
* Fuel: "charged as for the two reads" is taken literally: the nodes, plus 1 + members for each slice read,
  and nothing extra for the lookup itself (a lookup over n members is charged n for `at`, `last_before` and
  the others; `last_by` and `first_by` are not charged that n). A scalar over the result, for example `sum`,
  is charged as always. Vectors: formula-eval/last-by has fuel 11 = 3 + 4 + 4.
* A group that has no candidate is left out of the result slice (as for lookups); a scalar result with no
  candidate is E_FORMULA_ABSENT (also when `by` has no member at all).
* The same slice read twice (`last_by(f, g) - first_by(f, g)`) is one `inputs` entry (15.13), the fuel of
  both reads is charged.
* The whole `public:` string, prefix included, keeps 8.1's 512-character limit (E_CANON_LIMIT for 513, after
  the grammar is checked); `public:` followed by anything but an `https://` URL with at least one character
  after the scheme is E_CANON_LICENCE, as is an uppercase prefix. Within tier 2 the byte order is the order of
  the UTF-8 bytes of the whole string (so a prefix is smaller than its extension): vector
  licence/public-two-different-prefix.
* `function` of the named test_case is `string` with no further check; the argument order of the descriptor
  is the contract's: case, function, function_hash. The named-convention vectors need no new check of the
  reference tools (a test cell is a stored cell), so the P3 vectors already pass against the 0.6.1 tools; the
  descriptor and the receipts are pinned by hash, signature and trust here.
* P1: the contract splits a unit string at its single `/` only when it is not a listed literal (`m/s`,
  `km/h` stay literals), otherwise the rate's resolved form. `USD/USD` would be accepted (a currency on both
  sides); no vector asserts it.
* Decision rows: one per item, D111 to D114 (the contract's D44-D47 are the coordinator's numbers in
  QUESTIONS-build2.md, not SPEC rows).
* Schemas: `defs.schema.json` lists `shares` and `pure` (test_vectors already ties the list to units.md),
  allows `shares` as the `per` of a rate, and allows `public:<https URL>` as a licence (<= 512 characters).
"""

import json
import re
import shutil
import subprocess
import sys
import unittest

import jsonschema
import referencing

from helpers import ROOT, canon, ROUND_0_7_CHANGED

sys.path.insert(0, str(ROOT / "tools"))
import gen_vectors_0_6_2  # noqa: E402  (builds the vectors in memory)

SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
UNITS = (ROOT / "units.md").read_text(encoding="utf-8")
FLAT = re.sub(r"\s+", " ", SPEC)
UNITS_FLAT = re.sub(r"\s+", " ", UNITS)
NEW = {v["id"]: v for v in gen_vectors_0_6_2.VECTORS}
ON_DISK = {v["id"]: {k: x for k, x in v.items() if k != "_file"} for v in canon.load_vectors() if v["id"] in NEW}
OLD_COMMIT = "42979b5"  # tagged spec-0.6.1
K5_REWRITTEN = {"vectors/formula/class-inherited.json", "vectors/formula/class-inherited-plain.json"}


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def section(start, end):
    a = SPEC.index(start)
    return re.sub(r"\s+", " ", SPEC[a:SPEC.index(end, a + 1)])


def run(vec):
    try:
        return canon.check_vector(vec)
    except Exception as e:
        return [f"{type(e).__name__}: {e}"]


def count(kind, valid=None):
    return sum(v["kind"] == kind and (valid is None or v["valid"] == valid) for v in NEW.values())


class VectorFiles(unittest.TestCase):
    def test_every_new_vector_is_on_disk_unchanged(self):
        self.assertEqual(set(ON_DISK), set(NEW))
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertEqual(ON_DISK[id_], vec)

    def test_ids_match_paths(self):
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertTrue((ROOT / "vectors" / f"{id_}.json").is_file())
                self.assertEqual(vec["valid"], not id_.startswith("invalid/"))
                self.assertTrue(vec["description"].startswith("spec-0.6.2: "))

    def test_counts(self):
        self.assertEqual(len(NEW), 159)
        self.assertEqual({k: (count(k, True), count(k, False)) for k in
                          ("unit", "function", "formula", "formula-eval", "licence", "entitlement", "receipt",
                           "envelope")},
                         {"unit": (13, 18), "function": (9, 10), "formula": (9, 12), "formula-eval": (11, 3),
                          "licence": (27, 12), "entitlement": (13, 2), "receipt": (4, 11), "envelope": (2, 3)})

    def test_contract_vectors_exist(self):
        """Every vector the contract lists (P1-P4), by id."""
        want = {
            # P1
            "function/unit-shares", "function/unit-pure", "function/unit-rate-per-shares",
            "invalid/function-unit-rate-of-shares", "invalid/function-unit-shares-per-string",
            "unit/arg-unit-usd", "unit/arg-unit-shares", "unit/arg-unit-pure", "unit/arg-unit-usd-per-shares",
            "unit/arg-unit-eur-per-usd", "invalid/unit-arg-unit-two-slashes", "invalid/unit-arg-unit-empty-of",
            "invalid/unit-arg-unit-shares-of", "invalid/unit-arg-unit-per-pure", "invalid/unit-arg-unit-not-a-unit",
            # P2
            "formula-eval/last-by", "formula-eval/first-by", "formula-eval/last-by-group-key",
            "formula-eval/last-by-tie", "formula-eval/last-by-join-miss", "invalid/formula-eval-last-by-all-missing",
            "invalid/formula-last-by-arg-not-open", "invalid/formula-last-by-boolean",
            "invalid/formula-last-by-units-vary", "formula/last-by", "formula/first-by",
            "formula/last-by-round-trip", "formula/last-by-labelled",
            # P3
            "function/test-case-named", "receipt/test-case-named-counterexample",
            "envelope/test-case-named-counterexample", "invalid/envelope-test-case-named-computed",
            # P4
            "receipt/licence-public", "invalid/receipt-licence-public-no-url", "invalid/receipt-licence-public-http",
            "invalid/receipt-licence-public-spdx", "licence/public-cc0", "licence/public-cc-by",
            "licence/public-two-different", "licence/public-cc-by-sa", "licence/public-restricted-declared",
            "licence/public-restricted-undeclared", "entitlement/public-open",
        }
        self.assertEqual(want - set(NEW), set())

    def test_codes_the_contract_names(self):
        self.assertEqual(NEW["invalid/formula-last-by-arg-not-open"]["error"], "E_FORMULA_JOIN")
        self.assertEqual(NEW["invalid/formula-last-by-key-type"]["error"], "E_FORMULA_JOIN")
        self.assertEqual(NEW["invalid/formula-last-by-boolean"]["error"], "E_FORMULA_TYPE")
        self.assertEqual(NEW["invalid/formula-eval-last-by-all-missing"]["error"], "E_FORMULA_ABSENT")
        for slug in ("two-slashes", "empty-of", "shares-of", "per-pure", "not-a-unit"):
            self.assertEqual(NEW[f"invalid/unit-arg-unit-{slug}"]["error"], "E_CANON_UNIT")
        self.assertEqual(NEW["invalid/function-unit-rate-of-shares"]["error"], "E_CANON_UNIT")
        self.assertEqual(NEW["invalid/function-unit-shares-per-string"]["error"], "E_CANON_UNIT")
        for slug in ("no-url", "http", "spdx"):
            self.assertEqual(NEW[f"invalid/licence-public-{slug}"]["error"], "E_CANON_LICENCE")
            self.assertEqual(NEW[f"invalid/receipt-licence-public-{slug}"]["error"], "E_CANON_LICENCE")
        self.assertEqual(NEW["invalid/licence-public-too-long"]["error"], "E_CANON_LIMIT")
        reasons = {v["id"]: (v["licence"], v["reason"]) for v in NEW.values() if v["kind"] == "licence" and v["valid"]}
        sec = "public:https://www.sec.gov/privacy"
        self.assertEqual(reasons["licence/public-cc0"], (sec, "open"))
        self.assertEqual(reasons["licence/public-cc-by"], ("CC-BY-4.0", "open"))
        self.assertEqual(reasons["licence/public-two-different"], (sec, "open"))
        self.assertEqual(reasons["licence/public-cc-by-sa"], ("CC-BY-SA-4.0", "open"))
        self.assertEqual(reasons["licence/public-restricted-declared"][1], "declared")
        self.assertEqual(reasons["licence/public-restricted-undeclared"], (None, "not_declared"))
        self.assertEqual(NEW["entitlement/public-open"]["reason"], "open")
        self.assertTrue(NEW["entitlement/public-open"]["entitled"])

    def test_lineage_has_two_entries(self):
        for id_, vec in NEW.items():
            if vec["kind"] == "formula-eval" and vec["valid"]:
                with self.subTest(id_):
                    self.assertEqual(len(vec["lineage"]), 2)
                    self.assertTrue(all(x.startswith("slice:") for x in vec["lineage"]))

    def test_named_test_case_descriptor(self):
        d = json.loads(NEW["function/test-case-named"]["input"])
        sig = d["signature"]
        self.assertEqual(sorted(sig["args"]), ["case", "function", "function_hash"])
        self.assertTrue(all(a == {"type": "string", "valid": False} for a in sig["args"].values()))
        self.assertEqual(sig["returns"], "boolean")
        self.assertEqual(d["code"], {"body": "", "lang": "stored"})
        old = json.loads((ROOT / "vectors" / "function" / "test-case.json").read_text())
        self.assertNotEqual(NEW["function/test-case-named"]["sha256"], old["sha256"], "a different descriptor")
        r = json.loads(NEW["receipt/test-case-named-counterexample"]["input"])
        self.assertEqual(r["cell"]["fn"], "test_case")
        self.assertEqual(r["cell"]["fn_hash"], NEW["function/test-case-named"]["sha256"])
        self.assertEqual(r["value"], False)
        self.assertEqual(sorted(r["cell"]["args"]), ["case", "function", "function_hash"])
        self.assertEqual(r["inputs"], [])
        self.assertNotIn("source", r)


@unittest.skipUnless(shutil.which("git"), "git is needed to read the spec-0.6.1 files")
class Migration062(unittest.TestCase):
    """No spec-0.6.1 vector changes: vectors/ only gains files, and they all still pass."""

    @classmethod
    def setUpClass(cls):
        try:
            git("cat-file", "-e", f"{OLD_COMMIT}^{{commit}}")
        except subprocess.CalledProcessError:
            raise AssertionError(f"commit {OLD_COMMIT} (spec-0.6.1) is not in this clone; fetch the full history")
        names = git("ls-tree", "-r", "--name-only", OLD_COMMIT, "--", "vectors", "examples").decode().split("\n")
        cls.old = {n: git("show", f"{OLD_COMMIT}:{n}") for n in names if n.endswith(".json")}

    def test_every_file_is_byte_identical_and_still_passes(self):
        self.assertEqual(sum(p.startswith("vectors/") for p in self.old), 1711)
        for path, data in self.old.items():
            if path in ROUND_0_7_CHANGED:  # spec-0.7.0: rewritten (step 7.5 bounds tx by the latest input's)
                continue
            if path in K5_REWRITTEN:  # classes round (K5, breaking): rewritten on the classes-round branch
                continue
            with self.subTest(path):
                new = ROOT / path
                self.assertTrue(new.exists(), "a spec-0.6.1 file was removed or moved")
                self.assertEqual(new.read_bytes(), data)
                if path.startswith("vectors/"):
                    self.assertEqual(canon.check_vector(json.loads(data)), [])

    def test_the_new_files_are_all_the_generator_wrote(self):
        now = {str(p.relative_to(ROOT)) for p in (ROOT / "vectors").rglob("*.json")}
        added = now - set(self.old)
        # (the classes round and later revisions add files of their own: only that these are all there)
        self.assertLessEqual({f"vectors/{i}.json" for i in NEW}, added)


class ReferenceTools(unittest.TestCase):
    """(b): tools/canon.py and tools/formula.py implement spec-0.6.2."""

    def test_every_new_vector(self):
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertEqual(run(vec), [])

    def test_printer_round_trip(self):
        """The printed body of a valid `last_by`/`first_by` formula vector is a source that prints to itself."""
        import formula
        for id_, vec in NEW.items():
            if vec["kind"] == "formula" and vec["valid"]:
                with self.subTest(id_):
                    again = formula.run_vector(dict(vec, input=vec["body"]))
                    self.assertEqual((again.get("body"), again.get("ast"), again.get("inputs")),
                                     (vec["body"], vec["ast"], vec["inputs"]), again.get("detail"))

    def test_units_directly(self):
        self.assertIn("shares", canon.UNITS["ratio"])
        self.assertIn("pure", canon.UNITS["ratio"])
        self.assertTrue(canon.is_unit_literal("shares") and canon.is_unit_literal("pure"))
        self.assertFalse(canon.is_unit_literal("USD/shares"))

    def test_licence_directly(self):
        canon.check_licence("public:https://www.sec.gov/privacy", "$")
        for bad in ("public:", "public:http://x.example/t", "public:MIT", "PUBLIC:https://x.example/t"):
            with self.subTest(bad), self.assertRaises(canon.DatumeshError) as cm:
                canon.check_licence(bad, "$")
            self.assertEqual(cm.exception.code, "E_CANON_LICENCE")
        with self.assertRaises(canon.DatumeshError) as cm:
            canon.check_licence("public:https://a.example/" + "x" * 500, "$")
        self.assertEqual(cm.exception.code, "E_CANON_LIMIT")
        got = canon.inherit_licence(["public:https://www.sec.gov/privacy", "CC0-1.0"], {}, "calc.example.net/f",
                                    "2024-03-16T09:00:00.000000Z", "CC-BY-4.0")
        self.assertEqual(got, {"licence": "public:https://www.sec.gov/privacy", "reason": "open"})


class SpecText(unittest.TestCase):
    def test_status_line_names_this_revision(self):
        self.assertRegex(SPEC, r"(?m)^Status: draft, revision `spec-0\.6\.2`")
        self.assertRegex(SPEC, r"(?m)^### spec-0\.6\.2\s*$")
        self.assertIn("revision `spec-0.6.2`", (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertRegex(UNITS, r"(?m)^Status: [^\n]*`spec-0\.6\.2`")

    def test_p1_units_section_7_1(self):
        flat = section("### 7.1 Units", "### 7.2")
        for word in ("`shares`", "`pure`", "`USD/shares`", "E_CANON_UNIT"):
            self.assertIn(word, flat)
        self.assertIn('{"of": "USD", "per": "shares"}', flat)
        self.assertIn("a rate's resolved form", flat)
        self.assertIn("exactly one `/`", flat)
        self.assertIn("the one place a unit string is split", flat)
        self.assertRegex(flat, r"`\"?USD/EUR\"?` written as a string is not a unit")  # stays refused
        self.assertRegex(flat, r"per.{0,200}`shares`")

    def test_p1_units_md(self):
        block = re.search(r"```units-ratio\n(.*?)```", UNITS, re.S).group(1).split()
        self.assertEqual(block, ["percent", "permille", "bp", "1", "count", "shares", "pure"])
        self.assertIn("a number of shares of the issuer's equity, as a securities filing counts them", UNITS_FLAT)
        self.assertIn("a pure number, XBRL's `pure`: a ratio of two amounts of one unit", UNITS_FLAT)
        self.assertIn("same meaning", UNITS_FLAT)
        self.assertIn("keep the filed spelling", UNITS_FLAT)
        self.assertIn('{"of": "USD", "per": "shares"}', UNITS)
        self.assertIn("`USD/shares`", UNITS)
        self.assertRegex(UNITS_FLAT, r"(?i)single `/`")
        self.assertRegex(UNITS_FLAT, r"the literal `shares`")

    def test_p2_last_by_first_by(self):
        self.assertIn("`last_by(slice, by)`", SPEC)
        self.assertIn("`first_by(slice, by)`", SPEC)
        self.assertIn("`last_by(a, b)`", SPEC)  # the printer's positional form
        flat = section("### 15.13", "### 15.14")
        for word in ("`last_by`", "`first_by`", "inner join", "ordering dimension", "group keys", "E_FORMULA_JOIN",
                     "E_FORMULA_ABSENT", "orderable"):
            self.assertIn(word, flat)
        self.assertRegex(flat, r"tie.{0,160}later")
        self.assertRegex(flat, r"tie.{0,160}earlier")
        self.assertRegex(flat, r"fuel.{0,80}two reads")
        self.assertRegex(flat, r"(?i)each is an `inputs` entry")
        join = re.search(r"\| `E_FORMULA_JOIN` \|([^\n]*)\|", SPEC).group(1)
        self.assertIn("last_by", join)
        table = section("### 15.7 Built-ins", "### 15.8")
        self.assertRegex(table, r"`last_by\(slice, by\)`.{0,40}`first_by\(slice, by\)`")

    def test_p3_named_test_case(self):
        flat = section("### 7.3 Test cells", "## 8. Receipts")
        self.assertIn("<host>/test_case(case: string, function: string, function_hash: string) -> boolean", flat)
        self.assertIn("`function/test-case-named`", flat)
        self.assertIn("<host>/test_case(function_hash: string, case: string) -> boolean", flat)  # 0.6.1 form stays
        self.assertRegex(flat, r"callee of `call`")
        self.assertIn("full name (2.3)", flat)
        self.assertRegex(flat, r"two-argument form.{0,200}(valid|served|counted)")
        self.assertRegex(flat, r"rebind")
        self.assertRegex(flat, r"signer's statement")
        self.assertRegex(flat, r"MUST set")
        self.assertIn("`case` is unchanged", flat)
        self.assertRegex(FLAT, r"three-argument cell counts for a function when both `function_hash` and `function`")
        self.assertRegex(FLAT, r"two-argument cell counts by `function_hash` alone")

    def test_p4_public_licence_8_1(self):
        flat = section("### 8.1 Members", "### 8.2")
        self.assertIn("`public:<https URL>`", flat)
        self.assertIn("terms page", flat)
        self.assertRegex(flat, r"public-url|public:")
        self.assertRegex(flat, r"`public:` with no URL")
        self.assertIn("E_CANON_LICENCE", flat)
        self.assertRegex(flat, r"whole string.{0,80}512|512.{0,80}whole string")

    def test_p4_public_licence_8_5_and_10_3(self):
        flat = section("### 8.5 Licence inheritance", "## 9. Keys")
        self.assertRegex(flat, r"\| 1 \| public domain \|")
        self.assertRegex(flat, r"\| 2 \| public information \|[^|]*`public:")
        self.assertRegex(flat, r"\| 3 \| attribution \|")
        self.assertRegex(flat, r"\| 4 \| share-alike \|")
        self.assertRegex(flat, r"\| 5 \| \*\*restricted\*\* \|")
        self.assertIn("Tiers 1 to 4 are the **open** licences", flat)
        self.assertNotIn("Tiers 1 to 3", flat)
        self.assertIn("share-alike licence (tier 4)", flat)
        self.assertIn("greatest in byte order", flat)
        self.assertRegex(flat, r"one licence; the other sources' terms stay in the lineage")
        self.assertRegex(flat, r"inherits without a declaration")
        self.assertRegex(flat, r"CC0-1\.0.{0,80}public domain|public domain.{0,80}CC0")
        entitlement = section("### 10.3 Licence entitlement", "## 11. Test vectors")
        self.assertIn("`public:`", entitlement)
        self.assertRegex(entitlement, r"no new reason")

    def test_section_14_and_decisions(self):
        self.assertIn("### spec-0.6.2", SPEC)
        entry = SPEC[SPEC.index("### spec-0.6.2"):SPEC.index("### spec-0.6.1")]
        low = entry.lower()
        for word in ("shares", "pure", "last_by", "first_by", "test_case", "public:", "159", "gen_vectors_0_6_2"):
            self.assertIn(word, low, word)
        for d in ("D111", "D112", "D113", "D114"):
            self.assertRegex(SPEC, rf"(?m)^\| {d} \|")
        self.assertIn("tools/gen_vectors_0_6_2.py", section("## 11. Test vectors", "## 12"))


def validator(name):
    resources = []
    for path in sorted((ROOT / "schemas").glob("*.json")):
        schema = json.loads(path.read_text())
        resources.append((schema["$id"], referencing.Resource.from_contents(schema)))
    registry = referencing.Registry().with_resources(resources)
    schema = registry.contents(f"https://datumesh.com/schemas/1/{name}.schema.json")
    return jsonschema.Draft202012Validator(schema, registry=registry)


def defs_validator(name):
    return validator("defs").evolve(schema={"$ref": f"#/$defs/{name}",
                                            "$defs": json.loads((ROOT / "schemas" / "defs.schema.json")
                                                                .read_text())["$defs"]})


class Schemas(unittest.TestCase):
    def test_vectors_match_vector_schema(self):
        check = validator("vector")
        for id_, vec in NEW.items():
            with self.subTest(id_):
                check.validate(vec)

    def test_valid_function_and_receipt_vectors_satisfy_schema(self):
        for id_, vec in NEW.items():
            if vec["valid"] and vec["kind"] in ("function", "receipt"):
                with self.subTest(id_):
                    validator(vec["kind"]).validate(canon.parse_json(vec["input"]))

    def test_unit_schema(self):
        unit = defs_validator("unit")
        for ok in ("shares", "pure", {"of": "USD", "per": "shares"}, {"of": {"arg": "c"}, "per": "shares"},
                   {"of": "USD", "per": {"arg": "p"}}):
            with self.subTest(str(ok)):
                self.assertTrue(unit.is_valid(ok))
        for bad in ({"of": "shares", "per": "USD"}, {"of": "USD", "per": "pure"}, {"of": "USD", "per": "count"},
                    "USD/shares", "share"):
            with self.subTest(str(bad)):
                self.assertFalse(unit.is_valid(bad))

    def test_licence_schema(self):
        licence = defs_validator("licence")
        for ok in ("public:https://www.sec.gov/privacy", "public:https://a.example/" + "x" * 487, "CC0-1.0",
                   "https://a.example/t"):
            with self.subTest(ok[:40]):
                self.assertTrue(licence.is_valid(ok))
        for bad in ("public:", "public:https://", "public:http://a.example/t", "public:MIT",
                    "PUBLIC:https://a.example/t", "public: https://a.example/t", "public:https://a b",
                    "public:https://a.example/" + "x" * 488):
            with self.subTest(bad[:40]):
                self.assertFalse(licence.is_valid(bad))

    def test_receipt_schema_licence(self):
        r = json.loads(NEW["receipt/licence-public"]["input"])
        self.assertEqual([], list(validator("receipt").iter_errors(r)))
        for slug in ("no-url", "http", "spdx", "space", "uppercase"):
            doc = json.loads(NEW[f"invalid/receipt-licence-public-{slug}"]["input"])
            with self.subTest(slug):
                self.assertTrue(list(validator("receipt").iter_errors(doc)))


if __name__ == "__main__":
    unittest.main()
