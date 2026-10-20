# Cross-language check

`run.sh` runs the Python (`datumesh`), JavaScript (`@datumesh/verify`) and Rust (`datumesh-core`) implementations and the reference tool over the same inputs: every vector in `vectors/`; randomly generated receipts (about half corrupted, reaching every verification step, with blob content for step 7.7); random function descriptors with units, their unit resolution, and random response envelopes (`generate_02.py`); adversarial envelope requests aimed at stale/ok confusion and receipts for another cell (`generate_envelopes.py`); and mutated cell URIs. The implementations must agree on every byte, hash, signature, level, unit, envelope outcome and error code. The reference tool is compared too, on every set; since `spec-0.2.0` it agrees on URIs as well.

```sh
crosscheck/run.sh 1000 7     # needs Docker and git
```
