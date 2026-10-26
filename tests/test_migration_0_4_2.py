# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.1 -> spec-0.4.2: the step 1.4 answers (text), pinning by hash and trust computed; no
spec-0.4.1 vector's expected result changes.

The spec-0.4.1 files are read from git at the spec-0.4.1 tag's commit (3f79313), so this test
needs git and that commit (a full clone).

- Every spec-0.4.1 vector file and example exists at the same path and is byte-identical.
- The reference tool of this revision reproduces every one of their expected results.
- SPEC.md, units.md and README name the revision spec-0.4.2."""

import json
import shutil
import subprocess
import unittest

from helpers import ROOT, canon

OLD_COMMIT = "3f79313"  # tagged spec-0.4.1


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


@unittest.skipUnless(shutil.which("git"), "git is needed to read the spec-0.4.1 files")
class Migration042(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            git("cat-file", "-e", f"{OLD_COMMIT}^{{commit}}")
        except subprocess.CalledProcessError:
            raise AssertionError(f"commit {OLD_COMMIT} (spec-0.4.1) is not in this clone; fetch the full history")
        names = git("ls-tree", "-r", "--name-only", OLD_COMMIT, "--", "vectors", "examples").decode().split("\n")
        cls.old = {n: git("show", f"{OLD_COMMIT}:{n}") for n in names if n.endswith(".json")}

    def test_counts(self):
        self.assertEqual(sum(p.startswith("vectors/") for p in self.old), 1037)

    def test_every_file_is_byte_identical_and_still_passes(self):
        for path, data in self.old.items():
            with self.subTest(path):
                new = ROOT / path
                self.assertTrue(new.exists(), "a spec-0.4.1 file was removed or moved")
                self.assertEqual(new.read_bytes(), data)
                if path.startswith("vectors/"):
                    self.assertEqual(canon.check_vector(json.loads(data)), [])

    def test_revision_strings(self):
        self.assertIn("Status: draft, revision `spec-0.4.2`.", (ROOT / "SPEC.md").read_text(encoding="utf-8"))
        self.assertIn("### spec-0.4.2", (ROOT / "SPEC.md").read_text(encoding="utf-8"))
        self.assertIn("`spec-0.4.2`", (ROOT / "units.md").read_text(encoding="utf-8"))
        self.assertIn("revision `spec-0.4.2`", (ROOT / "README.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
