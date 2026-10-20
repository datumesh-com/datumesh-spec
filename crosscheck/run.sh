#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Cross-language check: run the Python and JavaScript verifier libraries and the
# reference tool over the spec's own vectors, random receipts (with blob content),
# random unit and envelope cases, and mutated URIs, and require identical bytes,
# hashes, signatures, levels, units, envelope outcomes and error codes.
#
#   crosscheck/run.sh [N] [SEED]          (needs Docker and git; default 1000 cases, seed 7)
#   PY_REF=<commit> JS_REF=<commit> crosscheck/run.sh
#   PY_REPO=<path or URL> JS_REPO=<path or URL> crosscheck/run.sh   (e.g. local clones)
set -eu
N=${1:-1000}
SEED=${2:-7}
SPEC=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git clone -q "${PY_REPO:-https://github.com/datumesh-com/datumesh-verify-py}" "$WORK/py"
git clone -q "${JS_REPO:-https://github.com/datumesh-com/datumesh-verify-js}" "$WORK/js"
git -C "$WORK/py" checkout -q "${PY_REF:-main}"
git -C "$WORK/js" checkout -q "${JS_REF:-main}"
cp "$SPEC"/crosscheck/*.py "$WORK/"

PYIMG="python:3.13-slim"
run_py() { docker run --rm -v "$SPEC":/spec -v "$WORK":/w -w /w "$PYIMG" sh -c "pip -q install pynacl==1.5.0 2>/dev/null; $1"; }

run_py "python generate.py /spec $N $SEED > cases.jsonl && python uri_cases.py /spec $N $SEED > uri-cases.jsonl \
  && python generate_02.py /spec $N $SEED > cases-02.jsonl \
  && python -c 'import json,pathlib,sys; [print(json.dumps(json.loads(p.read_text()))) for p in sorted(pathlib.Path(sys.argv[1]).rglob(\"*.json\"))]' /spec/vectors > vectors.jsonl"
SETS="vectors cases cases-02 uri-cases"
run_py "for f in $SETS; do python canon_runner.py /spec < \$f.jsonl > \$f.ref.jsonl; done"
docker run --rm -v "$WORK":/w -w /w python:3.10-slim sh -c \
  "pip -q install pynacl==1.5.0 2>/dev/null; for f in $SETS; do PYTHONPATH=py/src python py/tools/run_vectors.py < \$f.jsonl > \$f.py.jsonl; done"
docker run --rm -v "$WORK":/w -w /w/js node:18-slim sh -c \
  "npm ci --silent >/dev/null 2>&1 && npm run build --silent >/dev/null 2>&1 && for f in $SETS; do node tools/run-vectors.mjs < ../\$f.jsonl > ../\$f.js.jsonl; DATUMESH_BUILD=cjs node tools/run-vectors.mjs < ../\$f.jsonl > ../\$f.cjs.jsonl; done"

for f in vectors cases cases-02; do
  echo "== $f"
  run_py "python compare.py python=$f.py.jsonl javascript=$f.js.jsonl javascript-cjs=$f.cjs.jsonl reference=$f.ref.jsonl"
done
run_py "python fields_compare.py uri-cases.jsonl python=uri-cases.py.jsonl javascript=uri-cases.js.jsonl javascript-cjs=uri-cases.cjs.jsonl" | tee "$WORK/uri.txt"
grep -q '; 0 mismatching' "$WORK/uri.txt"
run_py "python fields_compare.py uri-cases.jsonl python=uri-cases.py.jsonl reference=uri-cases.ref.jsonl" | tee "$WORK/uri-ref.txt"
grep -q '; 0 mismatching' "$WORK/uri-ref.txt"
