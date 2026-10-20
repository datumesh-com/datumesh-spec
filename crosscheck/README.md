# Cross-language check

`run.sh` runs the Python (`datumesh`) and JavaScript (`@datumesh/verify`) verifier libraries and the reference tool over the same randomly generated receipts (about half corrupted, reaching every verification step) and mutated cell URIs. The libraries must agree on every byte, hash, signature, level and error code. The reference tool is compared too; on URIs it is informational, because of known defects in `tools/canon.py` (userinfo/port and check order, SPEC 5.1/5.4).

```sh
crosscheck/run.sh 1000 7     # needs Docker and git
```
