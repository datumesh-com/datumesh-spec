# SPDX-License-Identifier: Apache-2.0
"""The spreadsheet integration design (integrations/spreadsheets) stays testable:
every case names a requirement that exists, error codes are declared, and
canonical expectations are valid under the protocol's own rules."""

import json
import re
import unittest

from helpers import ROOT, canon

DIR = ROOT / "integrations" / "spreadsheets"
SPEC = (DIR / "SPEC.md").read_text(encoding="utf-8")
CASES = json.loads((DIR / "cases.json").read_text(encoding="utf-8"))["cases"]
SHEET_CODES = set(re.findall(r"^\| `(E_SHEET_[A-Z_]+)` \|", SPEC, re.M))


class SpreadsheetCases(unittest.TestCase):
    def test_unique_ids_and_known_requirements(self):
        ids = [c["id"] for c in CASES]
        self.assertEqual(len(ids), len(set(ids)))
        for case in CASES:
            self.assertIn(f"**{case['req']}**", SPEC, case["id"])
            self.assertIn(case["host"], ("excel", "sheets", "both"))
            self.assertIn(case["type"], canon.TYPES)

    def test_error_codes_are_declared(self):
        for case in CASES:
            code = case["expect"].get("error")
            if code:
                self.assertTrue(code in SHEET_CODES or code in canon.ERROR_CODES, case["id"])

    def test_expected_arguments_are_canonical(self):
        for case in CASES:
            if "arg" in case["expect"]:
                with self.subTest(case["id"]):
                    value = case["expect"]["arg"]
                    if case["type"] == "boolean":
                        value = {"true": True, "false": False}[value]
                    canon.check_lexical(case["type"], value, "$")


if __name__ == "__main__":
    unittest.main()
