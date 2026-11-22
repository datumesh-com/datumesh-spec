# SPDX-License-Identifier: Apache-2.0
"""The classes round (CONTRACT-classes-round.md): the spec side of K5, K8, K9, K10, K11, K13, C2 and C7, tests first.

(a) every new vector is on disk as tools/gen_vectors_classes_round.py builds it; the only existing vector files
    that changed since spec-0.6.2 (39d6849) are the two K5 rewrites, formula/class-inherited and
    formula/class-inherited-plain, and every other existing file is byte-identical;
(b) the reference tools (tools/canon.py, tools/formula.py) reproduce every new vector (these fail until they are
    written);
(c) SPEC.md states each rule, and the schemas know the new forms.

Choices (where the contract leaves a detail open, and what the vectors take):

K5
* The world has three subclasses added to the class_world scenario by the generator: calc.example.net/fx_cash
  (parent fx_pair, key venue), calc.example.net/fx_ndf_term (parent fx_ndf, key tenor) and
  calc.example.net/green_bond (parent bond, key grade), none with a method of its own. Under the new rule the
  environments bind S/m for S's own methods only (fx_ndf/rate; none for the three), so the plain read of an inherited
  method is E_FORMULA_UNRESOLVED (body) or E_NAME_UNBOUND (request). Two vectors keep a name bound by an older library
  (fx_ndf/cross) to show it does not help once D is unbound.
* The two rewritten files keep their ids and paths: formula/class-inherited (valid: AST, ast_sha256, body, inputs now
  name rates.example.org/fx_pair/cross) and formula/class-inherited-plain (now valid false, error
  E_FORMULA_UNRESOLVED, although it lives under formula/ and not invalid/). The new file formula/class-inherited-
  defining-plain is the plain read of D/m that the call form now equals. tools/class_world.py drops the "inherited" row
  of EQUIVALENT (a call form and a plain read under the same class name are no longer one read).
* A dispatch over a class and its subclass for an inherited method lists the one function D/m once in `inputs`.
* No formula-eval vector: their receipt hashes and lineage need an evaluator that implements the rule.
* In a `resolved` method entry, `from` stays `<class as written>(...).<m>` and `to` is `D/m`.

K8
* label_fold: a value is canonical when it equals its folding: Unicode default (full) case folding, then NFC, each
  run of White_Space one U+0020, leading and trailing spaces removed. E_KEY_NORMALISATION for a value that is not,
  E_CANON_STRING (3.5, first, as for every rule) for a tab or an NFD string. The empty string is not tested.
* A request label is folded by the mesh; the `lookups` table of a call vector holds the folded labels (publish
  refuses an unfolded one) and "" for a withdrawn one. The lookup resolution's `from` is the label as written, `to`
  the key, `asof` the instant: only the fold is new. A label in brackets with spaces inside is quoted:
  ["  Green   APPLE "] (an unquoted label is one token, as before).
* Keys stay strict: invalid/call-class-label-fold-keys-strict (and -quoted) are E_KEY_NORMALISATION.
* describe of N[label]: an object answer with the optional member `resolved` ({call, resolutions: [the lookup
  resolution]}), `call` the object's own call, `to` its key encoding. No request-level vector (HTTP is the mesh's).

K9
* extensions: a non-empty array of {fn, fn_hash, publisher}, ascending and unique by fn, `publisher` the host of fn
  (D108); an empty list is E_DESCRIBE (the member is omitted when there is none). Object answers only.
  The catalogue entry's `extends` and its publish check are the mesh's, not a vector.

K10
* The vector env gains `cells`: {canonical call of a cell without its asof: the key encoding the cell holds}, the cells
  of the methods that return a key, as of the call's asof (the analogue of `lookups`).
* One chain entry per method whose key is read: {asof, from: the method as written (its name, no arguments), kind:
  "chain", to: the key encoding read}, after the lookup entry and before the method entry of the last cell. A chain
  needs an asof or the mesh's now (E_ARG_MISSING). A cell value outside the declared classes is
  E_FORMULA_DISPATCH_KEY, given as the error of a call vector. The absent intermediate (not_covered) is an outcome
  of a mesh, not a call vector's: not a vector here.

K11
* A call vector with the CIK 0000320193 and the accession 0000320193-24-000123 unquoted, in key and argument
  positions, each the same cell as the quoted spelling; the same runs in a number position give E_CANON_NUMBER, and
  1-1 gives E_PARSE_URI, as today.

K13
* A literal default is a JSON string, the lexical value of the argument's type; a wrong one is E_SCHEMA (a
  function vector: a formula-kind vector would break tests/test_formula_grammar, which holds every invalid formula
  vector to an E_FORMULA_ code). The body vector with the
  argument left out has the AST, body and inputs of the one with it written. A `default` resolution in `resolved`
  carries the lexical value as `to` (also valid in an envelope).

C2
* facets: an object of at most the five keys, a non-empty list of 1 to 8 names (2.2) of at most 32 bytes, ascending and
  unique, in a function answer and a class answer (not an object answer, not a method entry); a non-empty object.
* A find result is a new vector kind, `find-result` (the input is one result: a JSON object whose members are the
  mesh's, of which only publisher, source and facets are checked). The reference's run_vector and the vector schema
  need the kind; until then `python tools/canon.py check` stops at the first of them with a ValueError.

C7
* describe kind catalog: host (a DNS name), domains, rule (the https URL `https://<host>/catalog/rule`), each domain
  {domain (a name), label, names and subjects (non-negative integers), top (1 to 5 of {subject: a key encoding,
  label, source: a full name})}; domains by subjects descending, then by name. An empty domains list is valid.
"""

import json
import re
import shutil
import subprocess
import sys
import unittest

import jsonschema
import referencing

from helpers import ROOT, canon

sys.path.insert(0, str(ROOT / "tools"))
import class_world as W  # noqa: E402
import formula  # noqa: E402
import gen_vectors_classes_round as G  # noqa: E402  (builds the vectors in memory)

SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
FLAT = re.sub(r"\s+", " ", SPEC)
NEW = {v["id"]: v for v in G.VECTORS}
ALL = {v["id"]: v for v in canon.load_vectors()}
ON_DISK = {i: {k: x for k, x in ALL[i].items() if k != "_file"} for i in NEW if i in ALL}
BASE = "39d6849"  # spec-0.6.2, untagged: where the classes-round branch starts
REWRITTEN = {"vectors/formula/class-inherited.json", "vectors/formula/class-inherited-plain.json"}


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def section(start, end):
    a = SPEC.index(start)
    return re.sub(r"\s+", " ", SPEC[a:SPEC.index(end, a + 1)])


def run(vec):
    try:
        return canon.check_vector(vec)
    except Exception as e:  # a kind the reference does not know yet raises
        return [f"{type(e).__name__}: {e}"]


def count(kind=None, valid=None, prefix=""):
    return sum((kind is None or v["kind"] == kind) and (valid is None or v["valid"] == valid)
               and v["id"].startswith(prefix) for v in NEW.values())


def code(fn, *args):
    try:
        fn(*args)
        return None
    except (formula.FormulaError, canon.DatumeshError) as e:
        return e.code


class VectorFiles(unittest.TestCase):
    def test_every_new_vector_is_on_disk_unchanged(self):
        self.assertEqual(set(ON_DISK), set(NEW))
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertEqual(ON_DISK[id_], vec)

    def test_ids_match_paths_and_descriptions(self):
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertTrue((ROOT / "vectors" / f"{id_}.json").is_file())
                self.assertTrue(vec["description"].startswith("classes-round: "))
                if id_ not in ("formula/class-inherited-plain",):  # K5's rewrite stays at its old id
                    self.assertEqual(vec["valid"], not id_.startswith("invalid/"))

    def test_counts(self):
        self.assertEqual(len(NEW), 190)
        self.assertEqual({k: (count(k, True), count(k, False)) for k in
                          ("call", "describe", "find-result", "formula", "function", "normalisation", "class",
                           "envelope")},
                         {"call": (25, 16), "describe": (22, 56), "find-result": (6, 10), "formula": (16, 4),
                          "function": (6, 7), "normalisation": (5, 12), "class": (1, 1), "envelope": (2, 1)})

    def test_contract_vectors_exist(self):
        want = {
            # K5
            "formula/class-inherited", "formula/class-inherited-plain", "formula/class-inherited-stored",
            "formula/class-inherited-middle", "formula/class-inherited-two-levels", "formula/class-override",
            "formula/class-inherited-this", "formula/class-inherited-this-stored", "formula/class-override-this",
            "formula/class-inherited-dispatch", "invalid/formula-inherited-unbound-definer",
            "invalid/formula-inherited-plain-stored", "call/class-inherited", "call/class-inherited-stored",
            "call/class-inherited-two-levels", "call/class-inherited-middle", "call/class-override",
            "invalid/call-class-inherited-plain", "invalid/call-class-inherited-unbound-definer",
            # K8
            "normalisation/label-fold-lower", "normalisation/label-fold-non-ascii", "invalid/normalisation-label-fold-upper",
            "invalid/normalisation-label-fold-double-space", "invalid/normalisation-label-fold-leading-space",
            "invalid/normalisation-label-fold-trailing-space", "function/lookup-label-fold", "class/lookup-label-fold",
            "call/class-label-fold-canonical", "call/class-label-fold-upper", "call/class-label-fold-spaces",
            "call/class-label-fold-quoted-inner", "invalid/call-class-lookup-withdrawn",
            "invalid/call-class-label-fold-keys-strict", "describe/object-label",
            # K9
            "describe/object-extensions", "describe/object-extensions-absent", "invalid/describe-object-extensions-unsorted",
            # K10
            "call/class-chain-one-link", "call/class-chain-two-links", "call/class-chain-from-label",
            "invalid/call-class-chain-after-non-key", "envelope/resolved-chain",
            # K11
            "call/class-unquoted-digits-key", "call/class-unquoted-digits-argument", "call/class-unquoted-digits-both",
            "invalid/call-class-unquoted-digits-number-cik", "invalid/call-class-unquoted-digits-number-accession",
            # K13
            "function/default-literal-number", "call/default-literal", "formula/default-literal-left-out",
            "formula/default-literal-written", "invalid/function-default-number-word",
            # C2
            "describe/function-facets", "describe/class-facets", "describe/find-result-facets",
            "invalid/describe-function-facets-unknown-key", "invalid/describe-class-facets-unsorted",
            "invalid/describe-find-result-facets-too-long",
            # C7
            "describe/catalog", "invalid/describe-catalog-subjects-order", "invalid/describe-catalog-top-six",
        }
        self.assertEqual(want - set(NEW), set())

    def test_k5_rewrites(self):
        a, b = NEW["formula/class-inherited"], NEW["formula/class-inherited-plain"]
        self.assertTrue(a["valid"])
        self.assertEqual(a["inputs"], ["rates.example.org/fx_pair/cross"])
        self.assertIn("rates.example.org/fx_pair/cross(", a["body"])
        self.assertIn('"fn":"rates.example.org/fx_pair/cross"', a["ast"])
        self.assertEqual((b["valid"], b["error"]), (False, "E_FORMULA_UNRESOLVED"))
        self.assertEqual(NEW["invalid/call-class-inherited-unbound-definer"]["error"], "E_NAME_UNBOUND")
        self.assertEqual(NEW["call/class-inherited"]["resolved"]["resolutions"][0]["to"], "rates.example.org/fx_pair/cross")
        # the call form equals the plain read of D/m
        plain = NEW["formula/class-inherited-defining-plain"]
        for member in ("ast", "ast_sha256", "body", "inputs"):
            self.assertEqual(a[member], plain[member])

    def test_k10_resolved_order(self):
        for vid in ("call/class-chain-one-link", "call/class-chain-two-links", "call/class-chain-from-label",
                    "call/class-chain-from-label-two-links"):
            kinds = [r["kind"] for r in NEW[vid]["resolved"]["resolutions"]]
            with self.subTest(vid):
                self.assertEqual(kinds[-1], "method")
                self.assertEqual(kinds, sorted(kinds, key={"lookup": 0, "chain": 1, "method": 2}.get))
                self.assertGreaterEqual(kinds.count("chain"), 1)
        self.assertEqual([r["kind"] for r in NEW["call/class-chain-from-label"]["resolved"]["resolutions"]],
                         ["lookup", "chain", "method"])
        self.assertEqual(sum(r["kind"] == "chain" for r in NEW["call/class-chain-two-links"]["resolved"]["resolutions"]), 2)

    def test_k13_same_ast_left_out_and_written(self):
        a, b = NEW["formula/default-literal-left-out"], NEW["formula/default-literal-written"]
        for member in ("ast", "ast_sha256", "body", "inputs", "returns"):
            self.assertEqual(a[member], b[member])
        self.assertEqual(NEW["call/default-literal"]["resolved"]["resolutions"],
                         [{"from": "rank", "kind": "default", "to": "1"}])
        self.assertEqual(NEW["call/default-literal"]["uri"], NEW["call/default-literal-given-equal"]["uri"])
        self.assertNotEqual(NEW["function/default-literal-number"]["sha256"], NEW["function/default-literal-hash-differs"]["sha256"])


@unittest.skipUnless(shutil.which("git"), "git is needed to read the spec-0.6.2 files")
class Migration(unittest.TestCase):
    """Only the two K5 rewrites change an existing vector; every other spec-0.6.2 file is byte-identical."""

    @classmethod
    def setUpClass(cls):
        try:
            git("cat-file", "-e", f"{BASE}^{{commit}}")
        except subprocess.CalledProcessError:
            raise AssertionError(f"commit {BASE} (spec-0.6.2) is not in this clone; fetch the full history")
        names = git("ls-tree", "-r", "--name-only", BASE, "--", "vectors", "examples").decode().split("\n")
        cls.old = {n: git("show", f"{BASE}:{n}") for n in names if n.endswith(".json")}

    def test_existing_files(self):
        self.assertEqual(sum(p.startswith("vectors/") for p in self.old), 1870)
        changed = set()
        for path, data in self.old.items():
            new = ROOT / path
            self.assertTrue(new.exists(), f"{path} was removed or moved")
            if new.read_bytes() != data:
                changed.add(path)
        self.assertEqual(changed, REWRITTEN)

    def test_untouched_vectors_still_pass(self):
        for path, data in self.old.items():
            if path in REWRITTEN or not path.startswith("vectors/"):
                continue
            with self.subTest(path):
                self.assertEqual(run(json.loads(data)), [])

    def test_the_new_files_are_all_the_generator_wrote(self):
        now = {str(p.relative_to(ROOT)) for p in (ROOT / "vectors").rglob("*.json")}
        added = now - set(self.old)
        # (later revisions add files of their own: only that these are all there)
        self.assertEqual({f"vectors/{i}.json" for i in NEW} - REWRITTEN - added, set())


class ReferenceTools(unittest.TestCase):
    """(b): tools/canon.py and tools/formula.py implement the classes round."""

    def test_every_new_vector(self):
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertEqual(run(vec), [])

    def test_invalid_describe_vectors_fail_for_their_new_member_only(self):
        """An invalid describe vector is E_DESCRIBE today for the member it adds, whatever its fault: so check that
        without the added member (facets, extensions, resolved) the answer is a valid one, and the fault is the member's."""
        checked = 0
        for id_, vec in NEW.items():
            if vec["kind"] != "describe" or vec["valid"]:
                continue
            doc = json.loads(vec["input"])
            for member in ("facets", "extensions", "resolved"):
                if member in doc:
                    stripped = {k: v for k, v in doc.items() if k != member}
                    control = {k: x for k, x in vec.items() if k != "error"}
                    control.update(valid=True, input=json.dumps(stripped))
                    with self.subTest(id_):
                        self.assertEqual(run(control), [])
                        checked += 1
        self.assertGreaterEqual(checked, 30)

    def test_label_fold_directly(self):
        for value in ("apple", "green apple", "zürich", "strasse"):
            canon.check_key_value("label_fold", value)
        for value, expected in [("Apple", "E_KEY_NORMALISATION"), ("a  b", "E_KEY_NORMALISATION"),
                                (" a", "E_KEY_NORMALISATION"), ("a ", "E_KEY_NORMALISATION"),
                                ("straße", "E_KEY_NORMALISATION"), ("a b", "E_KEY_NORMALISATION"),
                                ("a\tb", "E_CANON_STRING")]:
            with self.subTest(value):
                self.assertEqual(code(canon.check_key_value, "label_fold", value), expected)
        self.assertIn("label_fold", canon.KEY_NORMALISATIONS)

    def test_label_fold_is_refused_as_a_class_key_rule(self):
        """K8: keys stay strict. label_fold is a label's rule, so a class key declaring it is E_CLASS_MEMBER."""
        vec = next(v for v in G.VECTORS if v["id"] == "invalid/class-key-label-fold")
        self.assertEqual(vec["error"], "E_CLASS_MEMBER")
        self.assertIn("label_fold", vec["input"])
        self.assertEqual(canon.check_vector(vec), [])

    def test_inherited_method_compiles_to_the_defining_class(self):
        """K5 directly: the call form of an inherited method is the plain read of D/m; S/m is not bound."""
        env = G.k5_env(G.OLD_ENV_SIG)
        a = formula.compile(f'{W.NDF}(EUR, USD, "F1").cross("GBP", 2026-03-16)', env)
        b = formula.compile(f'{W.FX}/cross(base: "EUR", quote: "USD", via: "GBP", date: 2026-03-16)', env)
        self.assertEqual(canon.jcs(a.ast), canon.jcs(b.ast))
        self.assertEqual((a.body, a.inputs), (b.body, b.inputs))
        self.assertEqual(code(formula.compile, f'{W.NDF}/cross(base: "EUR", quote: "USD", via: "GBP", date: 2026-03-16)', env),
                         "E_FORMULA_UNRESOLVED")
        # an override stays the subclass's own
        c = formula.compile(f'{W.NDF}(EUR, USD, "F1").rate(2026-03-16)', env)
        self.assertEqual(c.inputs, [f"{W.NDF}/rate"])
        # D unbound
        self.assertEqual(code(formula.compile, f'{W.NDF}(EUR, USD, "F1").cross("GBP", 2026-03-16)',
                              G.k5_env(G.OLD_ENV_SIG, classes=G.NO_FX)), "E_FORMULA_UNRESOLVED")

    def test_binding_a_class_binds_own_methods_only(self):
        """The class_world scenario still binds every flattened method (16.3 of spec-0.6.2): once the rule changes the
        environments of the new vectors, which bind own methods only, are the model."""
        self.assertEqual(set(G.OWN[W.NDF]), {"rate"})
        self.assertNotIn(f"{W.NDF}/cross", G.K5_FUNCTIONS)
        self.assertIn(f"{W.NDF}/rate", G.K5_FUNCTIONS)


SCHEMA_NAMES = ("describe-catalog", "describe-class", "describe-function", "describe-object", "envelope", "function",
                "vector")


def registry():
    resources = []
    for path in sorted((ROOT / "schemas").glob("*.json")):
        schema = json.loads(path.read_text())
        resources.append((schema["$id"], referencing.Resource.from_contents(schema)))
    return referencing.Registry().with_resources(resources)


def validator(name):
    reg = registry()
    return jsonschema.Draft202012Validator(reg.contents(f"https://datumesh.com/schemas/1/{name}.schema.json"), registry=reg)


# Invalid new vectors whose rule a JSON Schema can state (shape, bounds, patterns): the schemas must reject them.
SCHEMA_REJECTS = (
    {f"invalid/describe-{t}-facets-{s}" for t in ("function", "class")
     for s in ("unknown-key", "empty-list", "nine", "too-long", "not-a-name", "not-a-list", "not-a-string", "empty",
               "duplicate")}
    | {"invalid/describe-object-extensions-" + s for s in ("member", "no-publisher", "hash", "not-array", "empty", "duplicate")}
    | {"invalid/describe-object-resolved-kind", "invalid/describe-object-resolved-asof", "invalid/describe-object-facets",
       "invalid/describe-method-facets", "invalid/describe-class-extensions"}
    | {"invalid/describe-catalog-" + s for s in ("top-six", "top-empty", "top-member", "top-no-label", "subjects-string",
                                                "names-negative", "domain-name", "domain-missing", "domain-member",
                                                "rule-http", "no-rule", "no-host", "member", "host")}
)
ANSWER_SCHEMA = {"class": "describe-class", "object": "describe-object", "function": "describe-function",
                 "catalog": "describe-catalog"}


class Schemas(unittest.TestCase):
    def test_new_schema_exists(self):
        self.assertTrue((ROOT / "schemas" / "describe-catalog.schema.json").is_file())

    def test_valid_answers_satisfy_their_schema(self):
        for id_, vec in NEW.items():
            if vec["kind"] == "describe" and vec["valid"]:
                doc = json.loads(vec["input"])
                with self.subTest(id_):
                    validator(ANSWER_SCHEMA[doc["kind"]]).validate(doc)

    def test_schemas_reject_the_expressible_invalid_answers(self):
        for id_ in sorted(SCHEMA_REJECTS):
            doc = json.loads(NEW[id_]["input"])
            with self.subTest(id_):
                self.assertFalse(validator(ANSWER_SCHEMA[doc["kind"]]).is_valid(doc))

    def test_function_schema_takes_literal_defaults_and_label_fold(self):
        check = validator("function")
        for id_ in (i for i in NEW if i.startswith("function/default-literal-") or i == "function/lookup-label-fold"):
            with self.subTest(id_):
                check.validate(json.loads(NEW[id_]["input"]))
        for id_ in (i for i in NEW if i.startswith("invalid/function-default-")):
            with self.subTest(id_):
                self.assertFalse(check.is_valid(json.loads(NEW[id_]["input"])))

    def test_envelope_schema_takes_chain_and_default_resolutions(self):
        check = validator("envelope")
        for id_ in ("envelope/resolved-chain", "envelope/resolved-default-literal"):
            with self.subTest(id_):
                check.validate(json.loads(NEW[id_]["input"]))
        self.assertFalse(check.is_valid(json.loads(NEW["invalid/envelope-resolved-chain-asof"]["input"])))

    def test_vector_schema_knows_find_result(self):
        self.assertIn("find-result", json.loads((ROOT / "schemas" / "vector.schema.json").read_text())["properties"]["kind"]["enum"])
        check = validator("vector")
        for id_, vec in NEW.items():
            with self.subTest(id_):
                check.validate({k: v for k, v in vec.items()})


class SpecText(unittest.TestCase):
    def test_k5_inherited_methods_read_the_defining_class(self):
        s = section("### 16.3", "### 16.4")
        self.assertNotIn("inherited ones included", s)
        self.assertRegex(s, r"(?i)binding `?N`? binds `?N/m`?[^.]*(adds or overrides|own)")
        self.assertRegex(s, r"(?i)inherits? [^.]*without overriding|nearest ancestor")
        self.assertIn("E_NAME_UNBOUND", s)
        self.assertIn("E_FORMULA_UNRESOLVED", s)
        self.assertRegex(FLAT, r"formula/class-inherited")

    def test_k8_label_fold(self):
        s = section("### 16.4", "### 16.5")
        self.assertIn("`label_fold`", s)
        self.assertRegex(s, r"(?i)default case folding")
        self.assertRegex(s, r"(?i)White_Space")
        self.assertRegex(section("### 16.1", "### 16.2"), r"(?i)withdr")  # an empty string withdraws a label
        s87 = section("### 16.7", "### 16.8")
        self.assertRegex(s87, r"(?i)folded by the mesh")
        self.assertRegex(s87, r"(?i)keys (stay|are) strict|never repair")

    def test_k9_extensions(self):
        s = section("### 16.8", "### 16.9")
        self.assertIn("`extensions`", s)
        self.assertRegex(s, r"(?i)ascending")

    def test_k10_chaining(self):
        s = section("### 5.8", "### 5.9")
        self.assertRegex(s, r"(?i)chain")
        self.assertIn("`chain`", FLAT)
        self.assertRegex(s, r"E_PARSE_URI")

    def test_k11_unquoted_digit_runs(self):
        s = section("### 5.8", "### 5.9")
        self.assertIn("0000320193-24-000123", s)
        self.assertRegex(s, r"(?i)digits and `?-`?")

    def test_k13_literal_default(self):
        s = section("## 7. Function descriptors", "## 8. Receipts")
        self.assertRegex(s, r'"default": "1"')
        self.assertRegex(s, r"(?i)lexical value of its type")

    def test_c2_facets(self):
        s = section("### 16.8", "### 16.9")
        self.assertIn("`facets`", s)
        for key in ("domain", "thing", "measure", "region", "frequency"):
            self.assertIn(f"`{key}`", s)
        self.assertRegex(FLAT, r"(?i)find[^.]*`facets`|`facets`[^.]*find")

    def test_c7_catalog_answer(self):
        s = section("### 16.8", "### 16.9")
        self.assertRegex(s, r'"?kind"?:? ?"?`?catalog')
        self.assertIn("/catalog/rule", s)


if __name__ == "__main__":
    unittest.main()
