# SPDX-License-Identifier: Apache-2.0
"""Test 6: the holding page answers 200 over HTTPS at datumesh.com and www.

Set DATUMESH_SKIP_SITE=1 to skip when offline."""

import os
import unittest
import urllib.request

SENTENCE = (
    "Datumesh is an open protocol for addressable, verifiable data cells: "
    "a name, a resolver, a signed answer, and a lineage you can follow."
)
REPO = "https://github.com/datumesh-com/datumesh-spec"


@unittest.skipIf(os.environ.get("DATUMESH_SKIP_SITE"), "DATUMESH_SKIP_SITE is set")
class HoldingPage(unittest.TestCase):
    def test_apex_and_www(self):
        for url in ("https://datumesh.com/", "https://www.datumesh.com/"):
            with self.subTest(url):
                request = urllib.request.Request(url, headers={"User-Agent": "datumesh-spec-test"})
                with urllib.request.urlopen(request, timeout=20) as response:
                    self.assertEqual(response.status, 200)
                    self.assertTrue(response.geturl().startswith("https://"))
                    body = response.read().decode("utf-8")
                self.assertIn(SENTENCE, body)
                self.assertIn(f'href="{REPO}"', body)


if __name__ == "__main__":
    unittest.main()
