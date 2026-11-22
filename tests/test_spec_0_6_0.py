# SPDX-License-Identifier: Apache-2.0
"""spec-0.6.0 (CONTRACT-build2-part1-spec.md), tests first:

C1 no backdating (mesh-side: text only); C2 `source` on stored receipts and the trust value `relayed`;
C3 digit-led words in requests; C4 tests for publicly published calculated functions (text only);
C5 `whatif`, the outcome `scenario`, request `overrides` and `solve`; C6 a cycle names its path
(`cycle`); C7 describe: `tests`, `source` and the function answer.

(a) every new vector's result from the reference tools is its expected result (the vectors are
    written by crosscheck/generate_060.py);
(b) SPEC.md states each rule;
(c) the schemas know the new members.

These fail until the text, the schemas and the reference tools of spec-0.6.0 are written.
"""

import json
import re
import sys
import unittest

import jsonschema
import referencing

from helpers import ROOT, canon

sys.path.insert(0, str(ROOT / "crosscheck"))
import generate_060  # noqa: E402  (builds the vectors in memory)

SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
FLAT = re.sub(r"\s+", " ", SPEC)
NEW = {v["id"]: v for v in generate_060.VECTORS}
ON_DISK = {v["id"]: {k: x for k, x in v.items() if k != "_file"} for v in canon.load_vectors() if v["id"] in NEW}


def section(start, end):
    """The text from the line starting `start` up to the line starting `end`."""
    a = SPEC.index(start)
    return SPEC[a:SPEC.index(end, a + len(start))]


def run(vec):
    """The reference's result, a failure to run (an exception) being a mismatch too."""
    try:
        return canon.check_vector(vec)
    except Exception as e:  # a request description the tool does not know yet is a ValueError
        return [f"{type(e).__name__}: {e}"]


def by_kind(kind, valid=None):
    return [v for v in NEW.values() if v["kind"] == kind and (valid is None or v["valid"] == valid)]


# ---------------------------------------------------------------------------
# (a) The vectors


class VectorFiles(unittest.TestCase):
    def test_every_new_vector_is_on_disk_unchanged(self):
        self.assertEqual(set(ON_DISK), set(NEW))
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertEqual(ON_DISK[id_], vec)

    def test_counts(self):
        """The contract's minimums."""
        self.assertGreaterEqual(len(by_kind("receipt", True)), 2)
        self.assertGreaterEqual(len(by_kind("receipt", False)), 11)
        self.assertGreaterEqual(len([v for v in by_kind("envelope")
                                     if "scenario" in v["id"] or "relayed" in v["id"] or "cycle" in v["id"]
                                     or "overrides" in v["id"] or "trust" in v["id"]]), 25)
        self.assertGreaterEqual(len(by_kind("call", True)), 5)
        self.assertGreaterEqual(len(by_kind("call", False)), 2)
        self.assertGreaterEqual(len(by_kind("describe", True)), 5)
        self.assertGreaterEqual(len(by_kind("describe", False)), 5)
        self.assertGreaterEqual(len(by_kind("mesh", True)), 1)
        self.assertGreaterEqual(len(by_kind("mesh", False)), 1)

    def test_invalid_codes_are_the_contracts(self):
        codes = {i: v["error"] for i, v in NEW.items() if not v["valid"]}
        expected = {
            "invalid/receipt-source-with-inputs": "E_SCHEMA",
            "invalid/receipt-source-extra-member": "E_SCHEMA",
            "invalid/receipt-source-missing-retrieved": "E_SCHEMA",
            "invalid/receipt-source-name-is-publisher": "E_SCHEMA",
            "invalid/receipt-source-name-bad": "E_CANON_NAME",
            "invalid/receipt-source-retrieved-bad": "E_CANON_INSTANT",
            "invalid/receipt-source-sha256-uppercase": "E_CANON_HEX",
            "invalid/receipt-source-url-http": "E_CANON_LICENCE",
            "invalid/receipt-source-url-too-long": "E_CANON_LIMIT",
            "invalid/receipt-source-takeover-bad": "E_CANON_LICENCE",
            "invalid/receipt-source-retrieved-after-issued": "E_TIME_ORDER",
            "invalid/call-digit-led-number-position": "E_CANON_TYPE",
            "invalid/call-date-with-suffix": "E_PARSE_URI",
            "invalid/mesh-whatif-placeholder": "E_MESH_DOC",
        }
        for id_, code in expected.items():
            with self.subTest(id_):
                self.assertEqual(codes[id_], code)


class Receipts(unittest.TestCase):
    """C2: source on a stored receipt, in 10.1's order, hashed and signed with the rest."""

    def test_receipt_vectors(self):
        for vec in by_kind("receipt"):
            with self.subTest(vec["id"]):
                self.assertEqual(run(vec), [])

    def test_source_is_part_of_the_payload(self):
        r = json.loads(NEW["receipt/relayed-full"]["input"])
        self.assertIn(b'"source":{', canon.receipt_payload(r))
        without = {k: v for k, v in r.items() if k != "source"}
        self.assertNotEqual(canon.sha256_hex(canon.receipt_payload(r)), canon.sha256_hex(canon.receipt_payload(without)))

    def test_old_receipts_have_no_source(self):
        for vec in canon.load_vectors():
            if vec["kind"] == "receipt" and vec["id"] not in NEW and vec["valid"] and "dns-segment" not in vec["id"]:
                # (spec-0.6.1's relayed receipt under a DNS segment, receipt/dns-segment-relay, has one)
                if "withdrawn" in json.loads(vec["input"]):
                    continue  # spec-0.7.0 R1: a withdrawal may carry source (receipt/withdrawn-relayed)
                self.assertNotIn("source", json.loads(vec["input"]), vec["id"])


class Envelopes(unittest.TestCase):
    def test_relayed(self):
        for vec in by_kind("envelope"):
            if "relayed" in vec["id"] or "trust" in vec["id"]:
                with self.subTest(vec["id"]):
                    self.assertEqual(run(vec), [])

    def test_scenario(self):
        for vec in by_kind("envelope"):
            if "scenario" in vec["id"] or "overrides" in vec["id"]:
                with self.subTest(vec["id"]):
                    self.assertEqual(run(vec), [])

    def test_scenario_outcome_is_known(self):
        self.assertIn("scenario", canon.ENVELOPE_MEMBERS)
        required, optional = canon.ENVELOPE_MEMBERS["scenario"]
        self.assertEqual(tuple(required), ("outcome", "scenario"))
        self.assertEqual(set(optional), {"fn_hash", "resolved"})
        self.assertEqual(canon.ENVELOPE_STATUS["scenario"], range(200, 201))

    def test_relayed_is_a_trust_value(self):
        self.assertEqual(canon.TRUST, ("primary", "verified", "unverified", "computed", "relayed"))

    def test_cycle(self):
        for vec in by_kind("envelope"):
            if "cycle" in vec["id"]:
                with self.subTest(vec["id"]):
                    self.assertEqual(run(vec), [])

    def test_a_request_description_may_carry_overrides_and_solve(self):
        req = NEW["envelope/scenario-solved"]["request"]
        self.assertEqual(set(req), {"asof", "cell_id", "overrides", "solve"})
        canon.check_request(req)  # a malformed description raises ValueError

    def test_scenario_is_never_a_cell_answer(self):
        """A scenario envelope without overrides in the request is E_ENVELOPE (5.9)."""
        vec = NEW["invalid/envelope-scenario-no-overrides-in-request"]
        self.assertEqual(canon.run_vector(vec).get("error"), "E_ENVELOPE")


class Calls(unittest.TestCase):
    """C3: a digit-led word is a string value in a string position of a request."""

    def test_call_vectors(self):
        for vec in by_kind("call"):
            with self.subTest(vec["id"]):
                self.assertEqual(run(vec), [])

    def test_quoted_and_unquoted_are_one_call(self):
        env = NEW["call/digit-led-2chr"]["env"]
        quoted = canon.parse_call('datumesh.example.org/verse("bible", "2Chr", 1, 1)', env)
        self.assertEqual(canon.parse_call("datumesh.example.org/verse(bible, 2Chr, 1, 1)", env), quoted)


class Describe(unittest.TestCase):
    def test_describe_vectors(self):
        for vec in by_kind("describe"):
            with self.subTest(vec["id"]):
                self.assertEqual(run(vec), [])

    def test_a_count_written_1_0_is_not_an_integer(self):
        vec = NEW["invalid/describe-tests-count-decimal"]
        self.assertIn('"count": 1.0', vec["input"])
        self.assertEqual(canon.run_vector(vec).get("error"), "E_DESCRIBE")


class Meshes(unittest.TestCase):
    def test_mesh_vectors(self):
        for vec in by_kind("mesh"):
            with self.subTest(vec["id"]):
                self.assertEqual(run(vec), [])

    def test_whatif_has_no_placeholders(self):
        self.assertEqual(list(canon.MESH_ENDPOINTS["whatif"]), [])
        self.assertNotIn("whatif", canon.MESH_REQUIRED)


class ErrorCodes(unittest.TestCase):
    def test_new_codes_are_in_the_tool_in_order(self):
        for c in ("E_WHATIF_UNSUPPORTED", "E_WHATIF_NO_SOLUTION"):
            self.assertIn(c, canon.ERROR_CODES)
        table = re.findall(r"^\| `(E_[A-Z_]+)` \|", SPEC, re.M)
        self.assertEqual(tuple(c for c in table if not c.startswith("E_FORMULA_")), canon.ERROR_CODES)


# ---------------------------------------------------------------------------
# (b) The text


class SpecText(unittest.TestCase):
    def test_c1_no_backdating(self):
        self.assertRegex(FLAT, r"MUST refuse to record a binding whose start is earlier than its own clock")
        self.assertRegex(FLAT, r"`valid_from`[^.]*`valid_to`[^.]*earlier than that clock|"
                               r"`valid_to`[^.]*`valid_from`[^.]*earlier than that clock")
        self.assertRegex(FLAT, r"(?i)absent start means the write instant|absent start is the write instant")
        self.assertRegex(FLAT, r"(?i)future starts are allowed")
        self.assertRegex(FLAT, r"(?i)imports the history of a namespace it does not otherwise publish under")
        self.assertRegex(FLAT, r"(?i)SHOULD log the import")
        self.assertRegex(FLAT, r"(?i)stored receipts' `tx`[^.]*backdated corrections|"
                               r"backdated corrections[^.]*stored receipts' `tx`")

    def test_status_line_names_this_revision(self):
        self.assertRegex(SPEC, r"(?m)^Status: draft, revision `spec-0\.6\.[012]`")  # spec-0.6.1 and 0.6.2 bump the revision
        self.assertNotIn("in progress, part one", SPEC)
        self.assertRegex(SPEC, r"(?m)^### spec-0\.5\.0\s*$")

    def test_c2_source_and_relayed(self):
        self.assertRegex(FLAT, r"`source` \(since `spec-0\.6\.0`\)")
        for member in ("`name`", "`url`", "`retrieved`", "`sha256`", "`takeover`"):
            self.assertIn(member, FLAT)
        self.assertRegex(FLAT, r"(?i)`source`[^.]*only when `inputs` is empty|only when `inputs` is empty[^.]*`source`")
        self.assertIn("`relayed`", FLAT)
        self.assertRegex(FLAT, r"`primary`[^.]*no `source`|no `source`[^.]*`primary`")
        self.assertIn("`retrieved <= issued`", FLAT)
        self.assertIn("A mesh that serves receipts with `source` is unverifiable by clients on core < 0.3.9 or "
                      "datumesh < 0.6.0 (@datumesh/verify < 0.6.0); such receipts are new, and every receipt signed "
                      "before them verifies unchanged.", FLAT)
        self.assertRegex(FLAT, r"\| `relayed` \|")

    def test_c3_digit_led_words(self):
        self.assertIn("digit-led word", FLAT)
        self.assertIn("`2Chr`", FLAT)
        self.assertIn("`1Cor`", FLAT)
        self.assertIn("`3John`", FLAT)
        self.assertIn("1*DIGIT 1*( ALPHA / DIGIT / \"_\" )", FLAT)
        appendix = SPEC[SPEC.index("## Appendix A"):]
        self.assertRegex(appendix, r"(?m)^request-token\s*=")

    def test_c4_tests_for_public_functions(self):
        self.assertIn("Only publicly published functions require tests", FLAT)
        self.assertRegex(FLAT, r"(?i)public mesh")
        self.assertRegex(FLAT, r"(?i)MUST refuse to publish a computed function[^.]*no tests")
        self.assertRegex(FLAT, r"(?i)private or local mesh never requires tests")
        self.assertRegex(FLAT, r"(?i)tests are not part of the descriptor or its hash")
        self.assertRegex(FLAT, r"(?i)datumesh-http")

    def test_c5_whatif(self):
        self.assertRegex(SPEC, r"(?m)^### 5\.9\b")
        self.assertIn("`whatif`", FLAT)
        self.assertIn("`scenario`", FLAT)
        self.assertIn("`overrides`", FLAT)
        self.assertIn("`solve`", FLAT)
        self.assertIn("`solved`", FLAT)
        self.assertRegex(FLAT, r"(?i)MUST NOT be signed")
        self.assertRegex(FLAT, r"(?i)MUST NOT be served at `/cell`")
        self.assertRegex(FLAT, r"\| `scenario` \| 200 \|")
        mesh = section("### 9.6", "### 9.7")
        self.assertRegex(mesh, r"`whatif`")

    def test_c5_codes_in_10_2(self):
        table = section("### 10.2", "### 10.3") if "### 10.3" in SPEC else section("### 10.2", "## 11.")
        for code in ("E_WHATIF_UNSUPPORTED", "E_WHATIF_NO_SOLUTION"):
            self.assertRegex(table, rf"(?m)^\| `{code}` \|")
            self.assertRegex(table, rf"(?m)^\| `{code}` \| whatif \|")
        self.assertRegex(SPEC, r"E_WHATIF_NO_SOLUTION[^\n]*request fault")

    def test_c6_cycle(self):
        self.assertIn("`cycle`", FLAT)
        self.assertIn("(since `spec-0.6.0`)", FLAT)
        for fix in ("`asof`", "`lag`", "`step`", "`solver`"):
            self.assertIn(fix, FLAT)
        self.assertRegex(FLAT, r"(?i)cycle check is keyed on the cell together with the instant")

    def test_c7_describe(self):
        self.assertRegex(FLAT, r'kind[^.]{0,60}"function"')
        self.assertIn("describe-function.schema.json", SPEC)
        for member in ("`tests`", "`covered`", "`branches`", "`counterexamples`", "`relayed_by`"):
            self.assertIn(member, FLAT)

    def test_section_14_and_decisions(self):
        self.assertRegex(SPEC, r"(?m)^### spec-0\.6\.0\b")
        entry = section("### spec-0.6.0", "### spec-0.5.0")
        for word in ("source", "relayed", "whatif", "scenario", "cycle", "digit-led", "backdat", "tests"):
            self.assertIn(word, entry.lower(), word)
        self.assertRegex(SPEC, r"(?m)^\| D92 \|")


# ---------------------------------------------------------------------------
# (c) The schemas


def registry():
    resources = []
    for path in sorted((ROOT / "schemas").glob("*.json")):
        schema = json.loads(path.read_text())
        resources.append((schema["$id"], referencing.Resource.from_contents(schema)))
    return referencing.Registry().with_resources(resources)


def validator(name):
    reg = registry()
    return jsonschema.Draft202012Validator(reg.contents(f"https://datumesh.com/schemas/1/{name}.schema.json"),
                                           registry=reg)


class Schemas(unittest.TestCase):
    def test_describe_function_schema_exists(self):
        self.assertTrue((ROOT / "schemas" / "describe-function.schema.json").exists())

    def test_valid_function_answers_satisfy_it(self):
        check = validator("describe-function")
        for vec in by_kind("describe", True):
            if json.loads(vec["input"]).get("kind") == "function":
                with self.subTest(vec["id"]):
                    check.validate(json.loads(vec["input"]))

    def test_function_answer_shape_is_rejected_when_wrong(self):
        check = validator("describe-function")
        good = json.loads(NEW["describe/function-not-held"]["input"])
        for name, bad in [("extra", dict(good, class_hash="0" * 64)),
                          ("uppercase hash", dict(good, fn_hash=good["fn_hash"].upper())),
                          ("no returns", {k: v for k, v in good.items() if k != "returns"})]:
            with self.subTest(name):
                self.assertFalse(check.is_valid(bad))

    def test_valid_class_answers_with_tests_satisfy_the_class_schema(self):
        check = validator("describe-class")
        doc = json.loads(NEW["describe/class-tests-source"]["input"])
        check.validate(doc)

    def test_receipt_schema_knows_source(self):
        check = validator("receipt")
        for id_ in ("receipt/relayed-full", "receipt/relayed-required"):
            with self.subTest(id_):
                check.validate(json.loads(NEW[id_]["input"]))
        for id_ in ("invalid/receipt-source-with-inputs", "invalid/receipt-source-extra-member",
                    "invalid/receipt-source-missing-retrieved", "invalid/receipt-source-name-bad",
                    "invalid/receipt-source-retrieved-bad", "invalid/receipt-source-sha256-uppercase",
                    "invalid/receipt-source-url-http", "invalid/receipt-source-takeover-bad"):
            with self.subTest(id_):
                self.assertFalse(check.is_valid(json.loads(NEW[id_]["input"])))

    def test_envelope_schema_knows_the_new_outcome_and_trust(self):
        check = validator("envelope")
        for id_ in ("envelope/relayed", "envelope/scenario-value-override", "envelope/scenario-slice-override",
                    "envelope/scenario-solved", "envelope/error-cycle"):
            with self.subTest(id_):
                check.validate(json.loads(NEW[id_]["input"]))

    def test_mesh_schema_knows_whatif(self):
        check = validator("mesh")
        doc = json.loads(NEW["mesh/whatif"]["env"]["mesh"]["https"]["body"])
        check.validate(doc)
        self.assertIn("whatif", json.dumps(json.loads((ROOT / "schemas" / "mesh.schema.json").read_text())))


if __name__ == "__main__":
    unittest.main()
