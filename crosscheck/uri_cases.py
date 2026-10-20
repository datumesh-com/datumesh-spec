# SPDX-License-Identifier: Apache-2.0
"""Mutate the spec's valid URI vectors into N cases (JSON lines, vector format)."""
import json
import pathlib
import random
import sys

spec, n, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rng = random.Random(seed)
base = [json.loads(p.read_text()) for p in sorted(pathlib.Path(spec, "vectors/uri").glob("*.json"))]
CHARS = list("@:/?#&=%*+ ._~-") + ["%20", "%2A", "%C3%BC", "%c3", "%41", "u@", ":443", "asof=", "dm_x=1", "Ü", "A", "0"]


def mutate(uri):
    op = rng.choice(["insert", "delete", "replace", "userinfo", "port", "swap", "dup", "noeq"])
    head, _, rest = uri.partition("cell://")
    s = rest
    if op == "userinfo":
        s = "user@" + s
    elif op == "port":
        host, slash, tail = s.partition("/")
        s = host + rng.choice([":443", ":", ":x"]) + slash + tail
    elif op in ("swap", "dup", "noeq") and "?" in s:
        path, _, q = s.partition("?")
        params = q.split("&")
        if op == "swap" and len(params) > 1:
            i = rng.randrange(len(params) - 1); params[i], params[i + 1] = params[i + 1], params[i]
        elif op == "dup":
            i = rng.randrange(len(params)); params.insert(i, params[i])
        elif op == "noeq":
            i = rng.randrange(len(params)); params[i] = params[i].split("=")[0]
        s = path + "?" + "&".join(params)
    elif s:
        i = rng.randrange(len(s) + 1)
        if op == "insert":
            s = s[:i] + rng.choice(CHARS) + s[i:]
        elif op == "delete" and i < len(s):
            s = s[:i] + s[i + 1:]
        elif op == "replace" and i < len(s):
            s = s[:i] + rng.choice(CHARS) + s[i + 1:]
    return "cell://" + s


for i in range(n):
    v = rng.choice(base)
    uri = v["input"] if rng.random() < 0.1 else mutate(v["input"])
    print(json.dumps({"id": f"uri/{i:04d}", "kind": "uri", "description": "mutated", "valid": True,
                      "input": uri, "signature": v["signature"]}, ensure_ascii=True))
