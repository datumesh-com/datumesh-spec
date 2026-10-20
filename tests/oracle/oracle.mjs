// SPDX-License-Identifier: Apache-2.0
// Recompute every vector's canonical bytes, hash and signature with code that
// shares nothing with tools/canon.py: the canonicalize package and Node crypto.
import canonicalize from "canonicalize";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../../vectors/", import.meta.url).pathname;
const files = (dir) => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  return statSync(p).isDirectory() ? files(p) : [p];
});
const sha256 = (s) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
const ed25519 = (hex) => createPublicKey({
  key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]),
  format: "der", type: "spki",
});

let checked = 0, sigs = 0, failed = 0;
for (const file of files(root)) {
  const v = JSON.parse(readFileSync(file, "utf8"));
  if (!v.valid || v.canonical === undefined) continue;
  let value = v.kind === "uri" ? v.object : JSON.parse(v.input);
  if (v.kind === "receipt") { const { sig, ...rest } = value; value = rest; }
  const canonical = canonicalize(value);
  const ok = canonical === v.canonical && sha256(canonical) === v.sha256;
  if (!ok) { failed++; console.log(`FAIL ${v.id}\n  ours:   ${v.canonical}\n  oracle: ${canonical}`); }
  if (v.kind === "receipt") {
    const good = verify(null, Buffer.from(canonical, "utf8"), ed25519(v.keypair.public), Buffer.from(v.sig, "hex"));
    if (!good) { failed++; console.log(`FAIL signature ${v.id}`); }
    sigs++;
  }
  checked++;
}
// RFC 8785 appendix B through the engine's own Number serialisation.
const samples = readFileSync(new URL("../test_jcs.py", import.meta.url), "utf8")
  .matchAll(/\("([0-9a-f]{16})", "([^"]+)"\)/g);
let numbers = 0;
for (const [, bits, expected] of samples) {
  const x = Buffer.from(bits, "hex").readDoubleBE(0);
  if (canonicalize(x) !== expected) { failed++; console.log(`FAIL number ${bits}: ${canonicalize(x)} != ${expected}`); }
  numbers++;
}
console.log(`${checked} canonical forms, ${sigs} signatures, ${numbers} appendix B numbers checked; ${failed} failures`);
process.exit(failed ? 1 : 0);
