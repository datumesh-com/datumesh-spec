# SPDX-License-Identifier: Apache-2.0
"""Generate formula cases (JSON lines, vector format; spec-0.4.0) for an independent
implementation of the dialect (the Rust datumesh-formula crate) against the reference:

- N grammar cases (kind formula): random sources over the grammar environment, well-formed or
  mutated (a token dropped, doubled or swapped), compared on ast_sha256, body, inputs, returns,
  asof_dependent and the error code;
- N evaluation cases (kind formula-eval): random well-typed bodies over the fuzz world, compared on
  value, lineage, tx, receipt_asof, fuel_used, receipt_hash and the error code;
- N // 10 decimal cases per operation (kind decimal), compared on every result to the last digit.

    python generate_formula.py SPEC_REPO N SEED > formula.jsonl
"""

import json
import random
import sys

SPEC, N, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path[:0] = [f"{SPEC}/tools", f"{SPEC}/tests"]
import formula as F  # noqa: E402
import gen_formula as G  # noqa: E402

rng = random.Random(SEED)


def grammar_source():
    if rng.random() < 0.6:
        name, source, *_ = rng.choice(G.VALID)
    else:
        name, source, *_ = rng.choice(G.INVALID)
    if rng.random() < 0.5:
        tokens = source.split(" ")
        k = rng.randrange(len(tokens))
        op = rng.randrange(3)
        if op == 0 and len(tokens) > 1:
            del tokens[k]
        elif op == 1:
            tokens.insert(k, tokens[k])
        else:
            j = rng.randrange(len(tokens))
            tokens[k], tokens[j] = tokens[j], tokens[k]
        source = " ".join(tokens)
    return source


def main():
    for i in range(N):
        source = grammar_source()
        returns = rng.choice(["EUR", "1", "boolean", "string", "date", "degC", "count", G.RATE_UNIT])
        env = G.env_for(source, G.std_sig(returns))
        print(json.dumps({"id": f"formula/{i}", "kind": "formula", "description": "generated", "valid": True,
                          "input": source, "env": env}, ensure_ascii=True))
    spec = G.world_fuzz()
    env = {"functions": {n: f["descriptor"] for n, f in spec["functions"].items()}}
    for i in range(N):
        source, returns = G.random_expression(rng)
        try:
            d = F.define("fuzz.example.net/f", G.fuzz_signature(returns), source, env)
        except F.FormulaError:
            continue
        world = {"functions": dict(spec["functions"], **{"fuzz.example.net/f": {"bound": G.BOUND, "descriptor": d}}),
                 "receipts": spec["receipts"]}
        print(json.dumps({"id": f"formula-eval/{i}", "kind": "formula-eval", "description": source, "valid": True,
                          "world": world, "cell": {"args": G.FUZZ_ARGS, "fn": "fuzz.example.net/f"}, "asof": G.LATER},
                         ensure_ascii=True))
    for op in G.DECIMAL_OPS:
        cases = G.decimal_cases(op, rng, max(N // 10, 10))
        print(json.dumps({"id": f"decimal/{op}", "kind": "decimal", "description": "generated", "valid": True, "op": op,
                          "cases": cases}, ensure_ascii=True))


main()
