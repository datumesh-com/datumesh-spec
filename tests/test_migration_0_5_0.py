# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.3 -> spec-0.5.0 (in progress, part one): the loopback mesh document for unrooted
hosts and the library findings; no spec-0.4.3 vector's expected result changes and no hash changes.

The spec-0.4.3 files are read from git at the spec-0.4.3 tag's commit (99123b2), so this test
needs git and that commit (a full clone).

- Every spec-0.4.3 vector file and example exists at the same path and is byte-identical.
- The reference tool of this revision reproduces every one of their expected results.
- SPEC.md, units.md and README name the revision spec-0.5.0 (in progress, part one)."""

import json
import shutil
import subprocess
import unittest

from helpers import ROOT, canon, ROUND_0_7_CHANGED

OLD_COMMIT = "99123b2"  # tagged spec-0.4.3


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


@unittest.skipUnless(shutil.which("git"), "git is needed to read the spec-0.4.3 files")
class Migration050(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            git("cat-file", "-e", f"{OLD_COMMIT}^{{commit}}")
        except subprocess.CalledProcessError:
            raise AssertionError(f"commit {OLD_COMMIT} (spec-0.4.3) is not in this clone; fetch the full history")
        names = git("ls-tree", "-r", "--name-only", OLD_COMMIT, "--", "vectors", "examples").decode().split("\n")
        cls.old = {n: git("show", f"{OLD_COMMIT}:{n}") for n in names if n.endswith(".json")}

    def test_counts(self):
        self.assertEqual(sum(p.startswith("vectors/") for p in self.old), 1236)

    def test_every_file_is_byte_identical_and_still_passes(self):
        for path, data in self.old.items():
            if path in ROUND_0_7_CHANGED:  # spec-0.7.0: rewritten (step 7.5 bounds tx by the latest input's)
                continue
            with self.subTest(path):
                new = ROOT / path
                self.assertTrue(new.exists(), "a spec-0.4.3 file was removed or moved")
                self.assertEqual(new.read_bytes(), data)
                if path.startswith("vectors/"):
                    self.assertEqual(canon.check_vector(json.loads(data)), [])

    def test_revision_strings(self):
        spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
        self.assertRegex(spec, r"(?m)^### spec-0\.5\.0\b")
        self.assertRegex((ROOT / "units.md").read_text(encoding="utf-8"), r"`spec-0\.6\.[02]`")  # coordinator, round 2; spec-0.6.2 bumps it
        self.assertRegex((ROOT / "README.md").read_text(encoding="utf-8"), r"revision `spec-0\.6\.[012]`")  # coordinator, round 2; spec-0.6.1 and 0.6.2 bump it


if __name__ == "__main__":
    unittest.main()
