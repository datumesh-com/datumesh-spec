# SPDX-License-Identifier: Apache-2.0
"""The 0.7 round (CONTRACT-round-0.7.md R1, R2, R3), the spec side, tests first.

(a) every new vector is on disk as tools/gen_vectors_round_0_7.py builds it; the only existing vector files that
    changed since the classes-round draft (fa98b69) are the two K8 vectors R1 replaces;
(b) the reference tools (tools/canon.py, tools/formula.py) reproduce every new vector (these fail until they are
    written; some "invalid" vectors already pass for the wrong reason, `E_SCHEMA` on the member the old tools do not
    know, and must keep passing for the right one);
(c) the case hashes of the 7.3 vectors differ as R3 says; (d) SPEC.md states the rules (fails until the text lands).

Choices the contract leaves open, each the most conservative reading (listed in the report to the coordinator):

R1
* A withdrawal keeps `summary` (and `valid`, `issued`, ...): `withdrawn` takes the place of `type` and `value` only.
  `withdrawn` beside `type` (without `value`) is E_SCHEMA as well.
* `withdrawn`: non-NFC or control characters E_CANON_STRING, over 1024 bytes E_CANON_LIMIT (the codes a summary gets);
  empty, null and non-string E_SCHEMA (coordinator decision 3).
* The `not_covered` envelope with a withdrawal carries `receipt`, `reason` and a required `trust`, checked against the
  receipt as for ok; `trust` stays forbidden without a receipt (coordinator decision 1). `reason` is
  required with the receipt (absent: E_ENVELOPE) and `fault` beside the receipt is E_ENVELOPE.
* `reason` without a receipt (the label case) is valid; the client cannot tell the label case from another, so only the
  empty reason is refused.
* A withdrawn cell read alone is E_FORMULA_NOT_COVERED (15.11, coordinator decision 2). at(slice, d) of a withdrawn
  member stays E_FORMULA_ABSENT: it is a lookup on a slice, not a single-cell read.
* The `call` kind cannot express not_covered, so a withdrawn label has an envelope vector only; the two K8 call vectors
  (a lookup cell holding "") now expect E_KEY_NORMALISATION.
* A slice page's member that is a withdrawal (an ok envelope, or a not_covered with the receipt) is E_ENVELOPE.
* The formula-eval vectors give no `fuel_used`.

R2: no vector (the bindings answer has no vector kind).

R3
* A slice override with `members` echoes as {"slice", "members": [{"cell", "value"}]}, sorted by cell id, `members`
  present when empty; a request description cannot hold `members` with `add` or `remove` (a malformed description, the
  caller's error), so the E_SLICE_MEMBER answers for that have a description without overrides.
* In a test's `inputs` the form is {<slice call>: {"members": {<cell call>: <typed scalar>}}}, and a cell may be
  {"withdrawn": "<reason>"}; the case hash is the JCS of the test with `inputs` as given.
"""

import json
import pathlib
import re
import subprocess
import sys
import unittest

from helpers import ROOT, canon

sys.path.insert(0, str(ROOT / "tools"))
import gen_vectors_round_0_7 as G  # noqa: E402  (builds the vectors in memory)

SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
FLAT = re.sub(r"\s+", " ", SPEC)
NEW = {v["id"]: v for v in G.VECTORS}
ALL = {v["id"]: v for v in canon.load_vectors()}
BASE = "fa98b69"  # the classes-round draft: where the 0.7 round starts
REPLACED = {"vectors/invalid/call-class-lookup-withdrawn.json", "vectors/invalid/call-class-lookup-withdrawn-cased.json"}


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def run(vec):
    try:
        return canon.check_vector({k: x for k, x in vec.items() if k != "_file"})
    except Exception as e:  # a form the reference does not know yet raises
        return [f"{type(e).__name__}: {e}"]


class VectorFiles(unittest.TestCase):
    def test_every_new_vector_is_on_disk_unchanged(self):
        self.assertEqual(len(NEW), 74)
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertIn(id_, ALL)
                self.assertEqual({k: x for k, x in ALL[id_].items() if k != "_file"}, vec)
                self.assertTrue(vec["description"].startswith("spec-0.7.0: "))
                self.assertEqual(vec["valid"], not id_.startswith("invalid/"))

    @unittest.skipUnless(subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", BASE + "^{commit}"],
                                        capture_output=True).returncode == 0, "the base commit is not in this clone")
    def test_only_the_two_k8_vectors_changed(self):
        names = git("ls-tree", "-r", "--name-only", BASE, "--", "vectors").decode().split("\n")
        changed = set()
        for n in (x for x in names if x.endswith(".json")):
            self.assertTrue((ROOT / n).exists(), f"{n} was removed or moved")
            if (ROOT / n).read_bytes() != git("show", f"{BASE}:{n}"):
                changed.add(n)
        self.assertEqual(changed, REPLACED)

    def test_the_k8_pair_now_expects_the_key_error(self):
        for n in REPLACED:
            self.assertEqual(json.loads((ROOT / n).read_text())["error"], "E_KEY_NORMALISATION")


class ReferenceTools(unittest.TestCase):
    """(b): fail until tools/canon.py and tools/formula.py implement the round."""

    def test_every_new_vector(self):
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertEqual(run(vec), [])

    def test_the_replaced_k8_vectors(self):
        for n in REPLACED:
            with self.subTest(n):
                self.assertEqual(run(json.loads((ROOT / n).read_text())), [])


class CaseHashes(unittest.TestCase):
    def test_cases_differ(self):
        ids = {s: v["sha256"][:16] for s, v in ((i[len("jcs/test-case-id-"):], x) for i, x in NEW.items()
                                                 if i.startswith("jcs/test-case-id-"))}
        self.assertEqual(len(ids), 8)
        self.assertEqual(len(set(ids.values())), len(ids), ids)
        for slug, case in ids.items():
            self.assertIn(case, NEW[f"jcs/test-case-id-{slug}"]["description"])


class Spec(unittest.TestCase):
    """(d): the text says it (fails until the spec lands)."""

    def test_withdrawal(self):
        for word in ("`withdrawn`", "the null version"):
            self.assertIn(word, FLAT)
        self.assertNotIn("a withdrawn label is the lookup cell's value `\"\"`", FLAT)

    def test_members(self):
        self.assertIn('"members"', FLAT)
        self.assertIn("E_SLICE_MEMBER", FLAT)


if __name__ == "__main__":
    unittest.main()
