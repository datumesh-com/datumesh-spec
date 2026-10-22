# Cross-language check

`run.sh` runs the Python (`datumesh`), JavaScript (`@datumesh/verify`) and Rust (`datumesh-core`) implementations and the reference tool over the same inputs: every vector in `vectors/`; randomly generated receipts (about half corrupted, reaching every verification step, with blob content for step 7.7), followed by computed receipts with a `recompute` object whose stored inputs have `asof`s earlier than, equal to or later than the receipt's, and whose evaluation value matches, differs or is absent (`E_EVAL_UNAVAILABLE`, since `spec-0.3.0`); random function descriptors with units, their unit resolution, and random response envelopes (`generate_02.py`); adversarial envelope requests aimed at stale/ok confusion (the receipt's `asof` earlier, equal or later than requested, with and without a requested `asof`, and `age_seconds` present or absent under both outcomes) and receipts for another cell (`generate_envelopes.py`); and mutated cell URIs. The implementations must agree on every byte, hash, signature, level, code reported with success (`E_EVAL_UNAVAILABLE`), unit, envelope outcome and error code. The reference tool is compared too, on every set; since `spec-0.2.0` it agrees on URIs as well.

```sh
crosscheck/run.sh 1000 7     # needs Docker and git
```
