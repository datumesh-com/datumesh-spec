# SPDX-License-Identifier: Apache-2.0
"""Slice-as-lineage (SPEC 15.13, 10.1) and the descriptor additions order and extent (SPEC 7),
as a verifier sees them: what the Python and JavaScript verifiers 0.4.0 must do."""

import json
import unittest

from helpers import ROOT, canon  # noqa: F401
import formula  # noqa: E402
import gen_formula as G  # noqa: E402

VECTORS = {v["id"]: v for v in canon.load_vectors()}

REQUIRED = """
receipt/slice-weighted-mean receipt/slice-empty receipt/slice-range receipt/slice-version receipt/slice-signed-only
receipt/slice-mixed-inputs receipt/slice-superseded receipt/slice-superseded-member receipt/slice-computed-members
invalid/receipt-slice-entry-uppercase invalid/receipt-slice-entry-short invalid/receipt-slice-entry-prefix
invalid/receipt-slice-entries-unsorted invalid/receipt-slice-manifest-unavailable invalid/receipt-slice-manifest-mismatch
invalid/receipt-slice-manifest-unsorted invalid/receipt-slice-manifest-schema invalid/receipt-slice-undeclared
invalid/receipt-slice-member-unavailable invalid/receipt-slice-member-invalid invalid/receipt-slice-member-outside
invalid/receipt-slice-member-duplicate-cell invalid/receipt-slice-member-later-asof invalid/receipt-slice-tx
invalid/receipt-slice-value-mismatch invalid/receipt-slice-version-outside
slice/unbounded slice/range slice/version slice/manifest slice/manifest-empty
invalid/slice-no-open-argument invalid/slice-range-boolean invalid/slice-version-of-slice
invalid/slice-manifest-member-hex invalid/slice-manifest-duplicate
function/order function/extent-values function/extent-range function/formula-descriptor
invalid/function-order-missing-argument invalid/function-order-duplicate invalid/function-order-unknown
invalid/function-order-not-array invalid/function-extent-unsorted invalid/function-extent-lexical
invalid/function-extent-boolean invalid/function-extent-range-reversed invalid/function-extent-range-decimal
invalid/function-extent-range-string invalid/function-extent-shape
envelope/not-covered-fault invalid/envelope-not-covered-fault-unknown invalid/envelope-ok-with-fault
""".split()


class Vectors(unittest.TestCase):
    def test_required_vectors_exist(self):
        self.assertEqual([i for i in REQUIRED if i not in VECTORS], [])

    def test_counts(self):
        slice_receipts = [v for v in VECTORS.values() if v["kind"] == "receipt" and "slice" in v["id"]]
        self.assertGreaterEqual(len(slice_receipts), 30)
        self.assertGreaterEqual(sum(v["kind"] == "slice" for v in VECTORS.values()), 12)

    def test_slice_vectors_pass(self):
        for vec in VECTORS.values():
            if "slice" in vec["id"] or vec["id"].startswith(("function/order", "function/extent", "invalid/function-order",
                                                              "invalid/function-extent")) or "fault" in vec["id"]:
                with self.subTest(vec["id"]):
                    self.assertEqual(canon.check_vector(vec), [])

    def test_superseded_is_success_at_signed(self):
        for name in ("receipt/slice-superseded", "receipt/slice-superseded-member"):
            vec = VECTORS[name]
            self.assertEqual((vec["valid"], vec["level"], vec["code"]), (True, "signed", "E_INPUT_SUPERSEDED"))
            self.assertIn("lineage", vec["recompute"])


class EntryForm(unittest.TestCase):
    H = "a" * 64

    def test_entry_form(self):
        good = f"slice:{'0' * 64}:{'f' * 64}"
        canon.check_input_entry(good, "$")
        canon.check_input_entry(self.H, "$")
        for bad in (f"slice:{'0' * 63}:{'f' * 64}", f"slice:{'0' * 64}:{'F' * 64}", f"Slice:{'0' * 64}:{'f' * 64}",
                    f"slice:{'0' * 64}{'f' * 64}", f"slice:{'0' * 64}:{'f' * 64}:", "slice:", "s" * 64):
            with self.subTest(bad):
                with self.assertRaises(canon.DatumeshError) as e:
                    canon.check_input_entry(bad, "$")
                self.assertEqual(e.exception.code, "E_CANON_HEX")

    def test_slice_entries_sort_after_receipt_hashes(self):
        entries = sorted([f"slice:{'0' * 64}:{'0' * 64}", "f" * 64, "0" * 64], key=canon._utf16_key)
        self.assertEqual(entries[-1][:6], "slice:")
        canon.check_set(entries, "$")

    def test_members_hash_is_over_the_sorted_array(self):
        members = sorted(["b" * 64, "a" * 64])
        self.assertEqual(canon.members_hash(members), canon.sha256_hex(json.dumps(members, separators=(",", ":")).encode()))
        self.assertEqual(canon.members_hash([]), canon.sha256_hex(b"[]"))

    def test_unbounded_slice_id_is_the_cell_id_of_4_4(self):
        """An unbounded slice object is the cell-with-markers object SPEC 4.4 already allows."""
        vec = VECTORS["cell/slice"]
        obj = json.loads(vec["input"])
        self.assertEqual(canon.slice_id(obj), vec["sha256"])


class Envelope(unittest.TestCase):
    def test_fault_member(self):
        for code in canon.FORMULA_FAULTS:
            body = json.dumps({"fault": code, "outcome": "not_covered"}).encode()
            self.assertEqual(canon.check_envelope(404, body, {}, {"cell_id": "0" * 64}), {"outcome": "not_covered"})
        for bad in ({"fault": "E_FORMULA_BUDGET", "outcome": "not_covered"},  # not a fault: error, E_EVAL_UNAVAILABLE
                    {"fault": "E_VALUE_MISMATCH", "outcome": "not_covered"},
                    {"fault": "E_FORMULA_DIV_ZERO", "outcome": "unlicensed"}):
            with self.subTest(bad):
                with self.assertRaises(canon.DatumeshError) as e:
                    canon.check_envelope(404 if bad["outcome"] == "not_covered" else 403, json.dumps(bad).encode(), {},
                                         {"cell_id": "0" * 64})
                self.assertEqual(e.exception.code, "E_ENVELOPE")


class Descriptors(unittest.TestCase):
    def test_order_and_extent_are_optional_and_hashed(self):
        base = {"code": {"body": "", "lang": "stored"}, "inputs": [],
                "signature": {"args": {"a": {"type": "string", "valid": False}, "b": {"type": "date", "valid": True}},
                              "returns": "boolean"}}
        h0 = canon.function_hash(canon.check_function(base))
        with_order = json.loads(json.dumps(base))
        with_order["signature"]["order"] = ["b", "a"]
        h1 = canon.function_hash(canon.check_function(with_order))
        other = json.loads(json.dumps(with_order))
        other["signature"]["order"] = ["a", "b"]
        h2 = canon.function_hash(canon.check_function(other))
        self.assertEqual(len({h0, h1, h2}), 3)  # order is hashed, and absent is a third value
        with_extent = json.loads(json.dumps(base))
        with_extent["signature"]["args"]["a"]["extent"] = ["EUR", "GBP", "USD"]
        self.assertNotEqual(canon.function_hash(canon.check_function(with_extent)), h0)

    def test_check_order(self):
        """Within a signature: args (each declaration: type, unit, valid, extent), then order, then returns."""
        desc = {"code": {"body": "", "lang": "stored"}, "inputs": [],
                "signature": {"args": {"a": {"extent": ["b", "a"], "type": "string", "valid": False}},
                              "order": ["x"], "returns": "nope"}}
        with self.assertRaises(canon.DatumeshError) as e:
            canon.check_function(desc)
        self.assertEqual(e.exception.code, "E_CANON_SET")  # the extent, before order and returns
        desc["signature"]["args"]["a"]["extent"] = ["a", "b"]
        with self.assertRaises(canon.DatumeshError) as e:
            canon.check_function(desc)
        self.assertEqual((e.exception.code, e.exception.path), ("E_CANON_SET", "$.signature.order"))
        desc["signature"]["order"] = ["a"]
        with self.assertRaises(canon.DatumeshError) as e:
            canon.check_function(desc)
        self.assertEqual(e.exception.code, "E_CANON_TYPE")


if __name__ == "__main__":
    unittest.main()
