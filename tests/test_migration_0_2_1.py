# SPDX-License-Identifier: Apache-2.0
"""spec-0.2.0 -> spec-0.2.1 is a text-only revision: every spec-0.2.0 vector file is byte-identical
(so no canonical form, hash, signature or expected result changed); vectors were only added.

tests/data/vectors-spec-0.2.0.json holds the SHA-256 of every vector file at the spec-0.2.0 tag."""

import hashlib
import json
import unittest

from helpers import ROOT

OLD = json.loads((ROOT / "tests" / "data" / "vectors-spec-0.2.0.json").read_text())


class TextOnlyRevision(unittest.TestCase):
    def test_every_spec_0_2_0_vector_is_byte_identical(self):
        self.assertEqual(len(OLD), 319)
        for path, digest in OLD.items():
            with self.subTest(path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)

    def test_vectors_were_only_added(self):
        now = {str(p.relative_to(ROOT)) for p in (ROOT / "vectors").rglob("*.json")}
        self.assertLessEqual(set(OLD), now)


if __name__ == "__main__":
    unittest.main()
