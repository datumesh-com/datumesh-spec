<p align="center"><img src="assets/datumesh-logo.svg" alt="Datumesh" width="180"></p>

# datumesh-spec

Datumesh is an open protocol for addressable, verifiable data cells: a name, a resolver, a signed answer, and a lineage you can follow.

This repository is the protocol's specification ([SPEC.md](SPEC.md), revision `spec-0.3.0`, with [units.md](units.md)), its JSON Schemas ([schemas/](schemas/)), its test vectors ([vectors/](vectors/)), and a reference canonicaliser used to generate and check them ([tools/canon.py](tools/canon.py)). The canonicaliser is a test tool, not a library.

## In ten lines

```text
cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD&asof=2024-03-16T09:00:00.000000Z

{"signature": {"args": {"base": …, "date": …, "quote": …},                                    # examples/fx_rate.function.json
               "returns": {"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}}}, "code": …, "inputs": []}
{"cell": {"ns": "rates.example.org", "fn": "fx_rate", "fn_hash": "7b58ecb8…", "args": {"base": …, "date": …, "quote": …}},
 "type": "number", "value": "1.0892", "asof": "2024-03-16T09:00:00.000000Z", "computed_by": "rates.example.org#d712b32a2cc5cb7c",
 "summary": "1 EUR was worth 1.0892 USD at the 15 March 2024 reference rate.", "sig": "ddf61d49…", …}   # examples/receipt.json

$ python3 tools/canon.py verify examples/receipt.json examples/keyenv.json
OK 19a5fe3a744c5792f747fb4c286ce396ab44b95922de4f07937502fe595b6f81 signed by rates.example.org#d712b32a2cc5cb7c
$ python3 tools/canon.py unit examples/fx_rate.function.json examples/receipt.json
USD/EUR
```

The URI names one cell: a function, rooted in a domain its publisher controls, applied to typed arguments, as of a transaction time. The function's descriptor fixes its signature, including the unit of the number it returns, and `fn_hash` is SHA-256 of that descriptor. The receipt is the cell's signed answer. Its hash is SHA-256 over the RFC 8785 canonical JSON of everything except `sig`, and `sig` is Ed25519 over the same bytes. Verification finds the key `computed_by` names at `https://rates.example.org/.well-known/datumesh.json` (here supplied offline by `keyenv.json`) and checks the signature. The receipt carries no unit: `USD/EUR` comes from the descriptor its `fn_hash` pins, filled in with the cell's arguments.

A mesh serves receipts inside a response envelope that says whether the answer is current, stale or superseded ([SPEC.md 5.5](SPEC.md#55-response-envelope)). Units are listed in [units.md](units.md).

## Integrations (design)

[integrations/spreadsheets](integrations/spreadsheets/SPEC.md) specifies a future Excel add-in and Google Sheets add-on, with conversion test cases written ahead of the code. It is non-normative and not built.

## Running the tests

The tools need Python 3.13 or later (for Unicode 15.1) and PyNaCl. Schema tests need `jsonschema`.

```sh
pip install pynacl jsonschema
python3 tools/canon.py check                 # every vector
cd tests && python3 -m unittest -v           # all tests; DATUMESH_FUZZ_N=100000 by default
```

With Docker only:

```sh
docker run --rm -v "$PWD":/w -w /w python:3.13-slim sh -c \
  'apt-get -qq update && apt-get -qq install -y git >/dev/null && git config --global --add safe.directory /w &&
   pip -q install pynacl==1.5.0 jsonschema==4.23.0 && python tools/canon.py check && cd tests && python -m unittest -v'
```

`tests/test_migration_0_3_0.py` reads the `spec-0.2.1` files from git, so it needs `git` and the full history (it is skipped without `git`).

Independent cross-check of every canonical form, hash and signature with the `canonicalize` npm package and Node's crypto:

```sh
docker run --rm -v "$PWD":/w -w /w/tests/oracle node:22-slim sh -c 'npm install --silent && node oracle.mjs'
```

`python3 tools/gen_vectors.py` regenerates `vectors/` and `examples/` byte for byte.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
