# SPDX-License-Identifier: Apache-2.0
"""Brief test 11: spec-0.4.0 changes no hash of any receipt whose inputs are single cells, nor of
any descriptor without order or extent.

The spec-0.3.0 files are read from git at the spec-0.3.0 tag's commit (3bac3d4), so this test
needs git and that commit (a full clone).

- Every spec-0.3.0 vector file and example exists at the same path and is byte-identical, and the
  new reference tool reproduces its expected result.
- The receipt hash of every receipt in every spec-0.3.0 vector is unchanged.
- Differential: the spec-0.3.0 canon.py (with its own units.md) runs beside the new one on fuzzed
  receipts with single-cell inputs and fuzzed descriptors without order and extent: canonical
  bytes, hashes and results are equal. With a slice entry, or order or extent, the old tool
  rejects what the new one accepts, and only those objects' hashes are new.

DATUMESH_MIGRATION_N sets the number of fuzzed objects (default 100000)."""

import importlib.util
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import ROOT, canon
from test_migration_0_3_0 import receipts_in

OLD_COMMIT = "3bac3d4"  # tagged spec-0.3.0
N = int(os.environ.get("DATUMESH_MIGRATION_N", "100000"))
SEED = int(os.environ.get("DATUMESH_MIGRATION_SEED", "20261024"))


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def old_files():
    names = git("ls-tree", "-r", "--name-only", OLD_COMMIT, "--", "vectors", "examples").decode().split("\n")
    return {name: git("show", f"{OLD_COMMIT}:{name}") for name in names if name.endswith(".json")}


def old_canon():
    """canon.py of spec-0.3.0, with the units.md and Unicode data of that revision."""
    tmp = tempfile.mkdtemp(prefix="canon-0.3.0-")
    os.makedirs(os.path.join(tmp, "tools"))
    for path in ("tools/canon.py", "tools/unicode-15.1-assigned.txt", "units.md"):
        with open(os.path.join(tmp, path), "wb") as f:
            f.write(git("show", f"{OLD_COMMIT}:{path}"))
    spec = importlib.util.spec_from_file_location("canon_0_3_0", os.path.join(tmp, "tools", "canon.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, tmp


def outcome(tool, fn, *args):
    try:
        return ("ok", fn(tool)(*args))
    except tool.DatumeshError as e:
        return ("error", e.code)


TYPES = ("number", "string", "date", "instant", "boolean", "blob")
UNITS = ("EUR", "1", "degC", "percent", "count", {"arg": "s"}, {"of": {"arg": "s"}, "per": "EUR"})


def random_descriptor(rng):
    args = {}
    for i in range(rng.randrange(0, 5)):
        t = rng.choice(TYPES)
        decl = {"type": t, "valid": t in ("date", "instant") and rng.random() < 0.5}
        if t == "number":
            decl["unit"] = rng.choice(UNITS)
        args[rng.choice(["a", "b", "c", "x", "date", "t1"]) + str(i)] = decl
    args["s"] = {"type": "string", "valid": False}
    r = rng.choice(TYPES)
    returns = {"type": "number", "unit": rng.choice(UNITS)} if r == "number" else r
    return {"code": {"body": rng.choice(["", "x\n", "a + b\n"]), "lang": rng.choice(["stored", "expr", "formula"])},
            "inputs": sorted(rng.sample(["rates.example.org/fx_rate", "a.example.org/f", "b.example.org/g"],
                                        rng.randrange(0, 3))),
            "signature": {"args": args, "returns": returns}}


@unittest.skipUnless(shutil.which("git"), "git is needed to read the spec-0.3.0 files")
class Migration040(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            git("cat-file", "-e", f"{OLD_COMMIT}^{{commit}}")
        except subprocess.CalledProcessError:
            raise AssertionError(f"commit {OLD_COMMIT} (spec-0.3.0) is not in this clone; fetch the full history")
        cls.old = old_files()
        cls.old_canon, cls.tmp = old_canon()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_counts(self):
        self.assertEqual(sum(p.startswith("vectors/") for p in self.old), 365)

    def test_every_file_is_byte_identical_and_still_passes(self):
        for path, data in self.old.items():
            with self.subTest(path):
                new = ROOT / path
                self.assertTrue(new.exists(), "a spec-0.3.0 file was removed or moved")
                self.assertEqual(new.read_bytes(), data)
                if path.startswith("vectors/"):
                    self.assertEqual(canon.check_vector(json.loads(data)), [])

    def test_no_receipt_hash_changed(self):
        compared = 0
        for path, data in self.old.items():
            if not path.startswith("vectors/"):
                continue
            vec = json.loads(data)
            for where, r in receipts_in(vec):
                self.assertEqual(canon.receipt_hash(r), self.old_canon.receipt_hash(r), f"{path} {where}")
                compared += 1
        self.assertGreaterEqual(compared, 88)

    def test_differential_receipts_with_single_cell_inputs(self):
        rng = random.Random(SEED)
        old = self.old_canon
        seed = bytes(range(32))
        _, public = canon.keypair(seed)
        kid = canon.key_id(public)
        doc = {"host": "calc.example.net", "keys": [{"alg": "ed25519", "id": kid, "public": public.hex(),
                                                     "valid_from": "2020-01-01T00:00:00.000000Z"}], "proto": "datumesh/1"}
        keyenv = {"calc.example.net": {"https": {"status": 200, "body": json.dumps(doc)}}}
        for i in range(N):
            inputs = sorted({canon.sha256_hex(f"{i}.{k}".encode()) for k in range(rng.randrange(0, 6))})
            t = rng.choice(["number", "string", "boolean", "date"])
            value = {"number": rng.choice(["1", "-2.5", "100.25"]), "string": rng.choice(["", "x", "Zürich"]),
                     "boolean": rng.random() < 0.5, "date": "2026-03-01"}[t]
            r = {"asof": "2026-03-02T00:00:00.000000Z",
                 "cell": {"args": {"d": {"type": "date", "value": "2026-03-01"}}, "fn": "f", "fn_hash": "a" * 64,
                          "ns": "calc.example.net"},
                 "computed_by": f"calc.example.net#{kid}", "inputs": inputs, "issued": "2026-03-02T00:00:00.000000Z",
                 "licence": "CC0-1.0", "proto": "datumesh/1", "publisher": "calc.example.net", "summary": "s",
                 "tx": "2026-03-01T00:00:00.000000Z", "type": t, "valid": {"d": {"type": "date", "value": "2026-03-01"}},
                 "value": value}
            if rng.random() < 0.3:  # sometimes non-canonical, to compare failures too
                r[rng.choice(["tx", "summary", "licence"])] = rng.choice(["2026-03-01", "", "bad licence"])
            signed = canon.sign_receipt(r, seed)
            data = json.dumps(signed).encode()
            with self.subTest(i=i):
                self.assertEqual(canon.receipt_payload(signed), old.receipt_payload(signed))
                self.assertEqual(outcome(canon, lambda m: m.verify_receipt, data, keyenv),
                                 outcome(old, lambda m: m.verify_receipt, data, keyenv))
            if i % 10 == 0:  # with a slice entry: only the new tool accepts it, and the hash is new
                entry = f"slice:{canon.sha256_hex(str(i).encode())}:{canon.sha256_hex(b'[]')}"
                with_slice = canon.sign_receipt(dict(r, inputs=sorted(inputs + [entry], key=canon._utf16_key)), seed)
                d2 = json.dumps(with_slice).encode()
                if outcome(canon, lambda m: m.verify_receipt, data, keyenv)[0] == "ok":
                    self.assertEqual(outcome(canon, lambda m: m.verify_receipt, d2, keyenv)[0], "ok")
                    self.assertEqual(outcome(old, lambda m: m.verify_receipt, d2, keyenv), ("error", "E_CANON_HEX"))
                    self.assertNotEqual(canon.receipt_hash(with_slice), canon.receipt_hash(signed))

    def test_differential_descriptors(self):
        rng = random.Random(SEED + 1)
        old = self.old_canon
        for i in range(N // 2):
            d = random_descriptor(rng)
            with self.subTest(i=i):
                a, b = outcome(canon, lambda m: m.check_function, d), outcome(old, lambda m: m.check_function, d)
                self.assertEqual(a, b)
                self.assertEqual(canon.function_hash(d), old.function_hash(d))
            if a[0] == "ok" and i % 5 == 0:  # order or extent: new hashes, which the old tool rejects
                d2 = json.loads(json.dumps(d))
                if rng.random() < 0.5:
                    d2["signature"]["order"] = sorted(d2["signature"]["args"])
                else:
                    d2["signature"]["args"]["s"]["extent"] = ["EUR", "USD"]
                self.assertEqual(outcome(canon, lambda m: m.check_function, d2)[0], "ok")
                self.assertEqual(outcome(old, lambda m: m.check_function, d2), ("error", "E_SCHEMA"))
                self.assertNotEqual(canon.function_hash(d2), canon.function_hash(d))


if __name__ == "__main__":
    unittest.main()
