# SPDX-License-Identifier: Apache-2.0
"""spec-0.2.1 -> spec-0.3.0: the time rules became more permissive and no hash changed.

The spec-0.2.1 files are read from git at the spec-0.2.1 tag's commit (710dabb), so this test
needs git and that commit (a full clone; CI checks out with fetch-depth 0).

- Every vector file and example of spec-0.2.1 still exists at the same path.
- Every one of them is byte-identical, except the vectors in CHANGED below.
- In a CHANGED vector only the members of MAY_DIFFER differ; every input and every hash
  (input/input_hex, canonical, sha256, sig, key ids, keypair, keys, recompute, request, status,
  object, https, unit, and every other member) is identical.
- No receipt hash changed: the receipt hash of every receipt in every spec-0.2.1 vector (receipt
  inputs, the receipts offered in recompute.inputs, and receipts inside envelopes) is recomputed
  from the old and the new file and compared."""

import json
import shutil
import subprocess
import unittest

from helpers import ROOT, canon

OLD_COMMIT = "710dabb"  # tagged spec-0.2.1

# The spec-0.2.1 vectors whose expected result changed in spec-0.3.0, each with the reason.
CHANGED = {
    "vectors/invalid/envelope-wrong-asof.json":
        "ok now binds to a receipt asof at or before the requested asof (5.5 step 5, D31): a receipt a day "
        "earlier is valid, no longer E_ENVELOPE",
}
# The only members a CHANGED vector may differ in.
MAY_DIFFER = {"valid", "error", "level", "outcome", "trust", "receipt_hash", "code", "description"}
# Members that must be identical in every vector (listed for the reader; every member not in
# MAY_DIFFER is compared anyway).
IDENTICAL = {"input", "input_hex", "canonical", "sha256", "sig", "key_id", "key_ids", "keypair", "keys",
             "recompute", "request", "status", "object", "https", "unit"}
assert not IDENTICAL & MAY_DIFFER


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def old_files():
    """{path: bytes} of every vector file and example at spec-0.2.1."""
    names = git("ls-tree", "-r", "--name-only", OLD_COMMIT, "--", "vectors", "examples").decode().split("\n")
    return {name: git("show", f"{OLD_COMMIT}:{name}") for name in names if name.endswith(".json")}


def receipts_in(vec):
    """Every receipt object a vector carries, as (where, receipt)."""
    found = []

    def parsed(text):
        try:
            return canon.parse_json(text.encode("utf-8") if isinstance(text, str) else text)
        except canon.DatumeshError:
            return None  # deliberately unparseable; its text is compared byte for byte anyway

    if vec["kind"] == "receipt":
        found.append(("input", parsed(canon.vector_input(vec))))
        for h, text in sorted(vec.get("recompute", {}).get("inputs", {}).items()):
            found.append((f"recompute.inputs.{h}", parsed(text)))
    if vec["kind"] == "envelope":
        env = parsed(canon.vector_input(vec))
        if isinstance(env, dict):
            found.append(("envelope receipt", env.get("receipt")))
    return [(where, r) for where, r in found if isinstance(r, dict)]


@unittest.skipUnless(shutil.which("git"), "git is needed to read the spec-0.2.1 files")
class Migration030(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            git("cat-file", "-e", f"{OLD_COMMIT}^{{commit}}")
        except subprocess.CalledProcessError:
            raise AssertionError(f"commit {OLD_COMMIT} (spec-0.2.1) is not in this clone; fetch the full history")
        cls.old = old_files()

    def test_counts(self):
        self.assertEqual(sum(p.startswith("vectors/") for p in self.old), 339)
        self.assertTrue(set(CHANGED) <= set(self.old))

    def test_every_file_remains_byte_identical_unless_changed(self):
        for path, data in self.old.items():
            with self.subTest(path):
                new = ROOT / path
                self.assertTrue(new.exists(), "a spec-0.2.1 file was removed or moved")
                if path not in CHANGED:
                    self.assertEqual(new.read_bytes(), data)

    def test_changed_vectors_differ_only_in_allowed_members(self):
        for path, reason in CHANGED.items():
            with self.subTest(path):
                self.assertTrue(reason)
                old = json.loads(self.old[path])
                new = json.loads((ROOT / path).read_text(encoding="utf-8"))
                differing = {k for k in old.keys() | new.keys() if old.get(k) != new.get(k)}
                self.assertTrue(differing, "listed as changed but unchanged")
                self.assertLessEqual(differing, MAY_DIFFER)
                self.assertIn("Changed in spec-0.3.0", new["description"])

    def test_wrong_asof_became_valid(self):
        new = json.loads((ROOT / "vectors/invalid/envelope-wrong-asof.json").read_text(encoding="utf-8"))
        self.assertTrue(new["valid"])
        self.assertNotIn("error", new)
        self.assertEqual((new["outcome"], new["trust"]), ("ok", "primary"))
        env = json.loads(new["input"])
        self.assertLess(env["receipt"]["asof"], new["request"]["asof"])
        self.assertEqual(new["receipt_hash"], canon.receipt_hash(env["receipt"]))

    def test_no_receipt_hash_changed(self):
        compared = 0
        for path, data in self.old.items():
            if not path.startswith("vectors/"):
                continue
            old_vec = json.loads(data)
            new_vec = json.loads((ROOT / path).read_text(encoding="utf-8"))
            old_receipts, new_receipts = receipts_in(old_vec), receipts_in(new_vec)
            with self.subTest(path):
                self.assertEqual([w for w, _ in old_receipts], [w for w, _ in new_receipts])
                for (where, old_r), (_, new_r) in zip(old_receipts, new_receipts):
                    self.assertEqual(canon.receipt_hash(new_r), canon.receipt_hash(old_r), where)
                    compared += 1
                if old_vec["kind"] == "receipt" and "sha256" in old_vec:
                    self.assertEqual(new_vec["sha256"], old_vec["sha256"])
                if "receipt_hash" in old_vec:
                    self.assertEqual(new_vec["receipt_hash"], old_vec["receipt_hash"])
        self.assertEqual(compared, 88)  # receipts in the 339 spec-0.2.1 vectors that parse as objects


if __name__ == "__main__":
    unittest.main()
