# SPDX-License-Identifier: Apache-2.0
"""spec-0.1.1 -> spec-0.2.0: every old vector still exists with the same expected result,
exactly the listed ones changed, each says why, and the receipts whose descriptors have
no number member are byte-identical (the envelope and blob changes touched nothing hashed).

tests/data/vectors-spec-0.1.1.json was taken from the spec-0.1.1 tag: per vector, a digest of
its content without the description, its expected result, and for URI vectors a digest of the
outputs alone."""

import hashlib
import json
import unittest

from helpers import ROOT, canon

import gen_vectors  # noqa: E402  (tools/ is on the path through helpers)

OLD = json.loads((ROOT / "tests" / "data" / "vectors-spec-0.1.1.json").read_text())
NEW = {v["id"]: v for v in canon.load_vectors()}
NOTE = "Changed in spec-0.2.0:"


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def content(vec, *without):
    return digest({k: x for k, x in vec.items() if k not in ("_file", "description", *without)})


class Migration(unittest.TestCase):
    def test_every_old_vector_remains_with_the_same_result(self):
        for id_, old in OLD.items():
            with self.subTest(id_):
                self.assertIn(id_, NEW)
                self.assertEqual(NEW[id_]["valid"], old["valid"])
                self.assertEqual(NEW[id_].get("error"), old.get("error"))

    def test_changed_vectors_are_exactly_the_noted_ones(self):
        changed = {id_ for id_, old in OLD.items() if content(NEW[id_]) != old["content"]}
        self.assertEqual(changed, set(gen_vectors.CHANGED_IDS))
        for id_ in OLD:
            with self.subTest(id_):
                self.assertEqual(NOTE in NEW[id_]["description"], id_ in changed)
        self.assertEqual(sum(NOTE in v["description"] for v in NEW.values()), len(changed))

    def test_number_free_receipts_are_byte_identical(self):
        """Test 3 of the step 0.2b brief."""
        number_free = [id_ for id_, old in OLD.items() if old.get("number_free_descriptor")]
        self.assertEqual(sorted(number_free), ["receipt/boolean-namespace-path", "receipt/instant-no-valid-time"])
        for id_ in number_free:
            with self.subTest(id_):
                self.assertEqual(content(NEW[id_]), OLD[id_]["content"])
                self.assertEqual(NEW[id_]["sha256"], OLD[id_]["sha256"])

    def test_only_descriptors_with_numbers_changed_hashes(self):
        for id_, old in OLD.items():
            if "sha256" in old and NEW[id_]["sha256"] != old["sha256"]:
                with self.subTest(id_):
                    self.assertIn(NEW[id_]["kind"], ("function", "cell", "receipt"))

    def test_uri_outputs_are_unchanged(self):
        for id_, old in OLD.items():
            if "outputs" in old:
                with self.subTest(id_):
                    self.assertEqual(content(NEW[id_], "signature"), old["outputs"])


if __name__ == "__main__":
    unittest.main()
