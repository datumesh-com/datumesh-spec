#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Cross-language check: run the Python, JavaScript and Rust implementations and the
# reference tool over five sets: the spec's own vectors, random receipts (with blob
# content), random unit and envelope cases, adversarial envelope requests, and mutated
# URIs. All four must agree on bytes, hashes, signatures, levels, units, envelope
# outcomes and error codes.
#
#   crosscheck/run.sh [N] [SEED]          (needs Docker and git; default 1000 cases, seed 7)
#   PY_REF=<commit> JS_REF=<commit> crosscheck/run.sh
#   PY_REPO=<path or URL> JS_REPO=<path or URL> RS_REPO=<path or URL> crosscheck/run.sh   (e.g. local clones)
#   RS_REF=<commit> selects the Rust commit
#   LIBS=0.3 checks libraries of spec-0.3.0: the vector set is then the spec-0.3.0 vectors only, and
#   the slice-lineage set (spec-0.4.0) is run by the reference tool alone. LIBS=0.4 (the default)
#   runs every set through every library.
#   FORMULA_RUNNER="<command reading vector lines on stdin>" adds an implementation of the formula
#   dialect (the Rust datumesh-formula crate) to the formula set; without it the reference runs
#   that set twice, which checks its determinism.
set -eu
LIBS=${LIBS:-0.4}
N=${1:-1000}
SEED=${2:-7}
SPEC=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git clone -q "${PY_REPO:-https://github.com/datumesh-com/datumesh-verify-py}" "$WORK/py"
git clone -q "${JS_REPO:-https://github.com/datumesh-com/datumesh-verify-js}" "$WORK/js"
git -C "$WORK/py" checkout -q "${PY_REF:-main}"
git -C "$WORK/js" checkout -q "${JS_REF:-main}"
git clone -q "${RS_REPO:-https://github.com/datumesh-com/datumesh-core}" "$WORK/rs"
git -C "$WORK/rs" checkout -q "${RS_REF:-main}"
cp "$SPEC"/crosscheck/*.py "$WORK/"

PYIMG="python:3.13-slim"
run_py() { docker run --rm -e LIBS="$LIBS" -v "$SPEC":/spec -v "$WORK":/w -w /w "$PYIMG" sh -c "pip -q install pynacl==1.5.0 2>/dev/null; $1"; }

run_py "python generate.py /spec $N $SEED > cases.jsonl && python uri_cases.py /spec $N $SEED > uri-cases.jsonl \
  && python generate_02.py /spec $N $SEED > cases-02.jsonl \
  && python generate_envelopes.py /spec $N $SEED > envelopes.jsonl \
  && python generate_slices.py /spec $N $SEED > slices.jsonl \
  && python generate_formula.py /spec $N $SEED > formula.jsonl \
  && python -c 'import json,pathlib,sys; [print(json.dumps(json.loads(p.read_text()))) for p in sorted(pathlib.Path(sys.argv[1]).rglob(\"*.json\"))]' /spec/vectors > vectors.jsonl"
if [ "$LIBS" = "0.3" ]; then  # only the spec-0.3.0 vectors, which those libraries implement
  git -C "$SPEC" ls-tree -r --name-only 3bac3d4 -- vectors | sed 's#^vectors/##; s#\.json$##' > "$WORK/ids-0.3.0.txt"
  run_py "python -c 'import json,sys; ids=set(open(\"ids-0.3.0.txt\").read().split()); [print(l, end=\"\") for l in open(\"vectors.jsonl\") if json.loads(l)[\"id\"] in ids]' > v.jsonl && mv v.jsonl vectors.jsonl"
  SETS="vectors cases cases-02 envelopes uri-cases"
else
  SETS="vectors cases cases-02 envelopes uri-cases slices"
fi
run_py "python canon_runner.py /spec < slices.jsonl > slices.ref.jsonl && python canon_runner.py /spec < formula.jsonl > formula.ref.jsonl \
  && python canon_runner.py /spec < formula.jsonl > formula.ref2.jsonl"
run_py "for f in $SETS; do python canon_runner.py /spec < \$f.jsonl > \$f.ref.jsonl; done"
docker run --rm -v "$WORK":/w -w /w python:3.10-slim sh -c \
  "pip -q install pynacl==1.5.0 2>/dev/null; for f in $SETS; do PYTHONPATH=py/src python py/tools/run_vectors.py < \$f.jsonl > \$f.py.jsonl; done"
docker run --rm -v "$WORK":/w -w /w/js node:18-slim sh -c \
  "npm ci --silent >/dev/null 2>&1 && npm run build --silent >/dev/null 2>&1 && for f in $SETS; do node tools/run-vectors.mjs < ../\$f.jsonl > ../\$f.js.jsonl; DATUMESH_BUILD=cjs node tools/run-vectors.mjs < ../\$f.jsonl > ../\$f.cjs.jsonl; done"

docker run --rm -v "$WORK":/w -w /w/rs rust:1.99 sh -c \
  "cargo build -q --release -p datumesh-cli 2>/dev/null && for f in $SETS; do target/release/datumesh-cli run-vectors < ../\$f.jsonl > ../\$f.rs.jsonl; done"

COMPARED="vectors cases cases-02 envelopes"
[ "$LIBS" = "0.3" ] || COMPARED="$COMPARED slices"
for f in $COMPARED; do
  echo "== $f"
  run_py "python compare.py python=$f.py.jsonl javascript=$f.js.jsonl javascript-cjs=$f.cjs.jsonl rust=$f.rs.jsonl reference=$f.ref.jsonl"
done
echo "== uri-cases"
run_py "python fields_compare.py uri-cases.jsonl python=uri-cases.py.jsonl javascript=uri-cases.js.jsonl javascript-cjs=uri-cases.cjs.jsonl rust=uri-cases.rs.jsonl" | tee "$WORK/uri.txt"
grep -q '; 0 mismatching' "$WORK/uri.txt"
run_py "python fields_compare.py uri-cases.jsonl python=uri-cases.py.jsonl reference=uri-cases.ref.jsonl" | tee "$WORK/uri-ref.txt"
grep -q '; 0 mismatching' "$WORK/uri-ref.txt"
echo "== formula"
if [ -n "${FORMULA_RUNNER:-}" ]; then
  sh -c "$FORMULA_RUNNER" < "$WORK/formula.jsonl" > "$WORK/formula.impl.jsonl"
  run_py "python compare.py reference=formula.ref.jsonl implementation=formula.impl.jsonl"
else
  run_py "python compare.py reference=formula.ref.jsonl reference-again=formula.ref2.jsonl"
fi
