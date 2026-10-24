# SPDX-License-Identifier: Apache-2.0
"""The reference tool as a third runner: vector JSON lines in, outputs out."""
import json
import sys

sys.path.insert(0, sys.argv[1] + "/tools")
import canon  # noqa: E402

for line in sys.stdin:
    vec = json.loads(line)
    got = canon.run_vector(vec)
    got.pop("detail", None)
    got.pop("ast", None)  # compared by its hash
    print(json.dumps({"id": vec["id"], "error": got.pop("error", None), **got}, ensure_ascii=True))
