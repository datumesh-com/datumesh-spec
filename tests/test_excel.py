# SPDX-License-Identifier: Apache-2.0
"""Brief test 10: every supported or partially supported Excel function in SPEC 15.14's table has
a vector showing equivalence on a sample input. The vectors are derived from Microsoft's
documentation (each cites its page) on inputs where Excel's binary doubles give the exact decimal
result; no real Excel was run."""

import re
import unittest

from helpers import ROOT, canon

VECTORS = [v for v in canon.load_vectors() if v["kind"] == "excel"]
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")


def table_rows():
    section = SPEC[SPEC.index("### 15.14 Excel compatibility"):SPEC.index("### 15.15")]
    rows = []
    for line in section.splitlines():
        m = re.match(r"^\| `([A-Z0-9.]+(?:, [A-Z0-9.]+)*)` \| (supported|partial|not supported) \|", line)
        if m:
            rows.append(([n.strip() for n in m.group(1).split(",")], m.group(2), line))
    return rows


class Excel(unittest.TestCase):
    def test_vectors_pass_and_equal_excel(self):
        self.assertGreaterEqual(len(VECTORS), 45)
        for vec in VECTORS:
            with self.subTest(vec["id"]):
                self.assertEqual(canon.check_vector(vec), [])
                self.assertEqual(vec["value"], vec["excel_result"])
                self.assertIs(vec["documentation_derived"], True)
                self.assertTrue(vec["doc"].startswith("https://support.microsoft.com/en-us/"))
                self.assertIn(vec["status"], ("supported", "partial"))

    def test_every_supported_or_partial_function_has_a_vector(self):
        ids = {v["id"] for v in VECTORS}
        rows = table_rows()
        self.assertGreaterEqual(len(rows), 60)
        for names, status, line in rows:
            if status == "not supported":
                continue
            for name in names:
                with self.subTest(name):
                    self.assertIn("excel/" + name.lower().replace(".", "-"), ids)

    def test_table_names_the_functions_the_contract_lists(self):
        listed = {n for names, _, _ in table_rows() for n in names}
        for name in ("SUM AVERAGE COUNT MIN MAX MEDIAN STDEV.S STDEV.P IF IFS AND OR NOT ROUND ROUNDUP ROUNDDOWN ABS "
                     "SUMPRODUCT SUMIF SUMIFS AVERAGEIF AVERAGEIFS COUNTIF COUNTIFS VLOOKUP HLOOKUP XLOOKUP INDEX MATCH "
                     "EDATE EOMONTH NETWORKDAYS WORKDAY YEARFRAC DATE TEXT LEN LEFT RIGHT MID CONCAT CONCATENATE FIND "
                     "SEARCH UPPER LOWER TRIM IFERROR NOW TODAY RAND INDIRECT OFFSET SQRT EXP LN LOG LOG10 POWER SIN COS "
                     "TAN ATAN2 PI").split():
            self.assertIn(name, listed)

    def test_statuses_agree_with_the_table(self):
        status = {n: s for names, s, _ in table_rows() for n in names}
        for vec in VECTORS:
            name = vec["id"].split("/")[1].split("-basis")[0].replace("-approximate", "").replace("-", ".").upper()
            with self.subTest(vec["id"]):
                self.assertEqual(vec["status"], status[name])


if __name__ == "__main__":
    unittest.main()
