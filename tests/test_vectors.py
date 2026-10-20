# SPDX-License-Identifier: Apache-2.0
"""Every vector passes, the set covers every rule, and the schemas agree."""

import json
import re
import unittest

import jsonschema
import referencing

from helpers import ROOT, canon

VECTORS = canon.load_vectors()


def schema_registry():
    resources = []
    for path in sorted((ROOT / "schemas").glob("*.json")):
        schema = json.loads(path.read_text())
        resources.append((schema["$id"], referencing.Resource.from_contents(schema)))
    return referencing.Registry().with_resources(resources)


REGISTRY = schema_registry()


def validator(name):
    schema = REGISTRY.contents(f"https://datumesh.com/schemas/1/{name}.schema.json")
    return jsonschema.Draft202012Validator(schema, registry=REGISTRY)


class Vectors(unittest.TestCase):
    def test_valid_vectors_round_trip(self):
        """Test 1: parse -> canonicalise -> bytes and hash equal the vector's."""
        for vec in VECTORS:
            if vec["valid"] and "canonical" in vec:
                with self.subTest(vec["id"]):
                    self.assertEqual(canon.check_vector(vec), [])
                    canonical = vec["canonical"].encode("utf-8")
                    self.assertEqual(canon.sha256_hex(canonical), vec["sha256"])
                    # The canonical bytes are a fixed point.
                    if vec["kind"] != "receipt":
                        self.assertEqual(canon.jcs(canon.parse_json(canonical)), canonical)

    def test_invalid_vectors_fail_with_stated_code(self):
        """Test 2: every invalid vector fails with exactly its error code."""
        for vec in VECTORS:
            if not vec["valid"]:
                with self.subTest(vec["id"]):
                    self.assertEqual(canon.run_vector(vec).get("error"), vec["error"])

    def test_other_valid_vectors(self):
        for vec in VECTORS:
            if vec["valid"] and "canonical" not in vec:
                with self.subTest(vec["id"]):
                    self.assertEqual(canon.check_vector(vec), [])

    def test_uri_identity(self):
        """Test 5: URI -> canonical object -> URI is the identity."""
        uris = [v for v in VECTORS if v["kind"] == "uri" and v["valid"]]
        self.assertGreaterEqual(len(uris), 10)
        for vec in uris:
            with self.subTest(vec["id"]):
                ref = canon.parse_uri(vec["input"], vec["signature"])
                self.assertEqual(ref, vec["object"])
                self.assertEqual(canon.format_uri(ref), vec["input"])
                again = canon.parse_uri(canon.format_uri(vec["object"]), vec["signature"])
                self.assertEqual(again, vec["object"])
                self.assertEqual(vec["https"], "https://mesh.example/cell/" + vec["input"][len("cell://"):])


class Coverage(unittest.TestCase):
    def test_counts(self):
        self.assertGreaterEqual(len(VECTORS), 60)
        self.assertGreaterEqual(sum(not v["valid"] for v in VECTORS), 5)

    def test_unique_ids_match_files(self):
        ids = [v["id"] for v in VECTORS]
        self.assertEqual(len(ids), len(set(ids)))
        for vec in VECTORS:
            self.assertEqual(vec["_file"], f"vectors/{vec['id']}.json")

    def test_every_error_code_has_a_vector(self):
        used = {v["error"] for v in VECTORS if not v["valid"]}
        self.assertEqual(set(canon.ERROR_CODES) - used, set())
        self.assertEqual(used - set(canon.ERROR_CODES), set())

    def test_every_type_appears_valid_and_invalid(self):
        for type_ in canon.TYPES:
            scalars = [v for v in VECTORS if v["kind"] == "scalar" and f'"{type_}"' in v.get("input", "")]
            self.assertTrue(any(v["valid"] for v in scalars), type_)
            self.assertTrue(any(not v["valid"] for v in scalars), type_)
            receipts = [v for v in VECTORS if v["kind"] == "receipt" and v["valid"]]
            self.assertTrue(any(json.loads(v["input"])["type"] == type_ for v in receipts), type_)

    def test_vectors_match_vector_schema(self):
        check = validator("vector")
        for vec in VECTORS:
            with self.subTest(vec["id"]):
                check.validate({k: v for k, v in vec.items() if k != "_file"})

    def test_generator_is_reproducible(self):
        """vectors/ is exactly what tools/gen_vectors.py writes."""
        import gen_vectors  # runs the generator in memory

        produced = {v["id"]: v for v in gen_vectors.VECTORS}
        on_disk = {v["id"]: {k: x for k, x in v.items() if k != "_file"} for v in VECTORS}
        self.assertEqual(produced, on_disk)


class SpecConsistency(unittest.TestCase):
    SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")

    def test_error_table_matches_tool(self):
        table = re.findall(r"^\| `(E_[A-Z_]+)` \|", self.SPEC, re.M)
        self.assertEqual(tuple(table), canon.ERROR_CODES)

    def test_limits_table_matches_tool(self):
        for name, value in canon.LIMITS.items():
            self.assertRegex(self.SPEC, rf"\| `{name}` \| {value} \|")


# Error codes whose rule a JSON Schema can express. Vectors failing with these
# must also fail the schema; the others (NFC, calendars, signatures...) are
# beyond JSON Schema and are the verification procedure's job.
SCHEMA_EXPRESSIBLE = {
    "E_SCHEMA", "E_CANON_NAME", "E_CANON_ARG_NAME", "E_CANON_TYPE", "E_CANON_NUMBER",
    "E_CANON_HEX", "E_CANON_LICENCE", "E_CANON_INSTANT", "E_KEY_DOC",
}
SCHEMA_FOR_KIND = {"scalar": "scalar", "cell": "cell", "ref": "cell-ref", "function": "function", "receipt": "receipt"}


class Schemas(unittest.TestCase):
    def test_schemas_are_valid_2020_12(self):
        for path in (ROOT / "schemas").glob("*.json"):
            with self.subTest(path.name):
                jsonschema.Draft202012Validator.check_schema(json.loads(path.read_text()))

    def test_valid_vectors_satisfy_schema(self):
        for vec in VECTORS:
            if vec["valid"] and vec["kind"] in SCHEMA_FOR_KIND:
                with self.subTest(vec["id"]):
                    validator(SCHEMA_FOR_KIND[vec["kind"]]).validate(canon.parse_json(vec["input"]))
            if vec["valid"] and vec["kind"] == "keys":
                body = vec["env"]["https"].get("body")
                if body:
                    validator("keydoc").validate(json.loads(body))
            if vec["valid"] and vec["kind"] == "uri":
                validator("cell-ref").validate(vec["object"])

    def test_schema_rejects_expressible_invalid_vectors(self):
        checked = 0
        for vec in VECTORS:
            if vec["valid"] or vec["kind"] not in SCHEMA_FOR_KIND or vec["error"] not in SCHEMA_EXPRESSIBLE:
                continue
            try:
                doc = canon.parse_json(canon.vector_input(vec))
            except canon.DatumeshError:
                continue
            with self.subTest(vec["id"]):
                self.assertFalse(validator(SCHEMA_FOR_KIND[vec["kind"]]).is_valid(doc))
                checked += 1
        self.assertGreater(checked, 30)


if __name__ == "__main__":
    unittest.main()
