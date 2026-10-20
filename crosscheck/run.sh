#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Cross-language check: run the Python and JavaScript verifier libraries and the
# reference tool over the same random receipts and mutated URIs, and require
# identical bytes, hashes, signatures, levels and error codes.
#
#   crosscheck/run.sh [N] [SEED]          (needs Docker and git; default 1000 cases, seed 7)
#   PY_REF=<commit> JS_REF=<commit> crosscheck/run.sh
set -eu
N=${1:-1000}
SEED=${2:-7}
SPEC=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git clone -q https://github.com/datumesh-com/datumesh-verify-py "$WORK/py"
git clone -q https://github.com/datumesh-com/datumesh-verify-js "$WORK/js"
git -C "$WORK/py" checkout -q "${PY_REF:-main}"
git -C "$WORK/js" checkout -q "${JS_REF:-main}"
cp "$SPEC"/crosscheck/*.py "$WORK/"

PYIMG="python:3.13-slim"
run_py() { docker run --rm -v "$SPEC":/spec -v "$WORK":/w -w /w "$PYIMG" sh -c "pip -q install pynacl==1.5.0 2>/dev/null; $1"; }

run_py "python generate.py /spec $N $SEED > cases.jsonl && python uri_cases.py /spec $N $SEED > uri-cases.jsonl"
run_py "for f in cases uri-cases; do python canon_runner.py /spec < \$f.jsonl > \$f.ref.jsonl; done"
docker run --rm -v "$WORK":/w -w /w python:3.10-slim sh -c \
  'pip -q install pynacl==1.5.0 2>/dev/null; for f in cases uri-cases; do PYTHONPATH=py/src python py/tools/run_vectors.py < $f.jsonl > $f.py.jsonl; done'
docker run --rm -v "$WORK":/w -w /w/js node:18-slim sh -c \
  'npm ci --silent >/dev/null 2>&1 && npm run build --silent >/dev/null 2>&1 && for f in cases uri-cases; do node tools/run-vectors.mjs < ../$f.jsonl > ../$f.js.jsonl; DATUMESH_BUILD=cjs node tools/run-vectors.mjs < ../$f.jsonl > ../$f.cjs.jsonl; done'

run_py "python compare.py python=cases.py.jsonl javascript=cases.js.jsonl javascript-cjs=cases.cjs.jsonl reference=cases.ref.jsonl"
run_py "python fields_compare.py uri-cases.jsonl python=uri-cases.py.jsonl javascript=uri-cases.js.jsonl javascript-cjs=uri-cases.cjs.jsonl" | tee "$WORK/uri.txt"
grep -q '; 0 mismatching' "$WORK/uri.txt"
echo "Reference tool on URIs (known spec defects 5.1/5.4; informational):"
run_py "python fields_compare.py uri-cases.jsonl python=uri-cases.py.jsonl reference=uri-cases.ref.jsonl" || true
