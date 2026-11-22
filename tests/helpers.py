# SPDX-License-Identifier: Apache-2.0
"""Make tools/canon.py importable from the tests."""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import canon  # noqa: E402,F401


# spec-0.7.0 (coordinator decision on 10.1 step 7.5): the one old vector whose result changed is rewritten in place
# (a tx later than the latest input's was E_TIME_ORDER, and is valid now); its new form keeps the id and the error.
ROUND_0_7_CHANGED = {"vectors/invalid/receipt-computed-tx.json"}
ROUND_0_7_CHANGED_IDS = {"invalid/receipt-computed-tx"}
