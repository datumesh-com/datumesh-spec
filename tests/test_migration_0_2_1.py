# SPDX-License-Identifier: Apache-2.0
"""spec-0.2.0 -> spec-0.2.1 is a text-only revision: every spec-0.2.0 vector file is byte-identical
(so no canonical form, hash, signature or expected result changed), except two descriptions that were
out of date, which are checked to be the only change; vectors were only added.

tests/data/vectors-spec-0.2.0.json holds the SHA-256 of every vector file at the spec-0.2.0 tag.

Since spec-0.3.0 this test is scoped to the files spec-0.3.0 left byte-identical: the vectors whose
expected result spec-0.3.0 changed (test_migration_0_3_0.CHANGED) are checked member by member there."""

import hashlib
import json
import unittest

from helpers import ROOT
from test_migration_0_3_0 import CHANGED as CHANGED_0_3_0

# Outdated descriptions corrected in spec-0.2.1: the only bytes that changed.
DESCRIPTION_FIXED = {
    "vectors/invalid/scalar-type-unknown.json": ("There are exactly five types.", "There are exactly six types."),
    "vectors/invalid/envelope-unknown-outcome.json": ("outcome is one of seven values.", "outcome is one of eight values."),
}
OLD = json.loads((ROOT / "tests" / "data" / "vectors-spec-0.2.0.json").read_text())


class TextOnlyRevision(unittest.TestCase):
    def test_every_spec_0_2_0_vector_is_byte_identical(self):
        self.assertEqual(len(OLD), 319)
        for path, digest in OLD.items():
            if path in DESCRIPTION_FIXED or path in CHANGED_0_3_0:
                continue
            with self.subTest(path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)

    def test_changes_in_spec_0_3_0_are_to_spec_0_2_0_vectors(self):
        self.assertLessEqual(set(CHANGED_0_3_0), set(OLD))
        self.assertFalse(set(CHANGED_0_3_0) & set(DESCRIPTION_FIXED))

    def test_description_fixes_change_only_the_description(self):
        for path, (old_text, new_text) in DESCRIPTION_FIXED.items():
            with self.subTest(path):
                data = (ROOT / path).read_bytes()
                self.assertIn(new_text.encode(), data)
                restored = data.replace(new_text.encode(), old_text.encode())
                self.assertEqual(hashlib.sha256(restored).hexdigest(), OLD[path])

    def test_vectors_were_only_added(self):
        now = {str(p.relative_to(ROOT)) for p in (ROOT / "vectors").rglob("*.json")}
        self.assertLessEqual(set(OLD), now)


if __name__ == "__main__":
    unittest.main()
