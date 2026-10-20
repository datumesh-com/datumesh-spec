# SPDX-License-Identifier: Apache-2.0
"""Make tools/canon.py importable from the tests."""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import canon  # noqa: E402,F401
