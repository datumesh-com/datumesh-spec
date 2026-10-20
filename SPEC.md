# Datumesh protocol, version 1

Status: draft, revision `spec-0.1.1`. Identifier in data: `datumesh/1`. Changes are listed in section 14.

Datumesh is an open protocol for addressable, verifiable data cells: a name, a resolver, a signed answer, and a lineage you can follow. This document defines how a cell is named (the cell URI), how it is written as canonical bytes, what a signed answer (a receipt) contains, how keys are published, and how a verifier checks a receipt. Storage formats, wire protocols, resolvers and the engine are out of scope.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174.

Everything hashed or signed under these rules is hashed or signed forever. The rules are therefore strict: **where an input could be read two ways, it is rejected, not normalised.** A verifier never guesses.

The executable form of this document is `tools/canon.py`; the vectors under `vectors/` are normative examples. If the prose and the vectors disagree, that is a bug in this document to be reported, not a choice for implementers.

## Contents

1. Terms
2. Names
3. Scalar types and lexical forms
4. JSON forms: typed scalars, arguments, references, cells, limits
5. Cell URIs
6. Canonical encoding and hashing
7. Function descriptors and function identity
8. Receipts
9. Keys
10. Verification
11. Test vectors
12. Security considerations
13. Decisions and rationale
14. Changes
- Appendix A: collected ABNF

## 1. Terms

- **Namespace**: a DNS name the publisher controls, optionally followed by path segments: `rates.example.org`, `example.org/central_bank/stats`.
- **Function**: a name within a namespace, together with a descriptor (section 7) that fixes its signature and code. Its fully qualified name is `<namespace>/<function>`, Go-module style, e.g. `ecb.europa.eu/fx_rate`.
- **Function hash**: SHA-256 of the canonical descriptor. A name resolves to a current function hash; cells and receipts pin the hash.
- **Cell**: a function applied to a complete tuple of typed scalar arguments. A cell has at most one value at any transaction time.
- **Slice**: a function applied to a tuple in which one or more arguments are left open. A slice denotes a set of cells. It can be named and canonicalised but never has a receipt.
- **Valid time**: the time a value is about (a rate *for* 15 March). It is carried by ordinary arguments that the function declares as valid-time arguments.
- **Transaction time**: the time the system knew a value. Every call has an `asof` transaction time (default: now). Every receipt carries `asof` (as of when it answers), `tx` (when the value it gives was recorded) and `issued` (when it was signed).
- **Receipt**: a signed statement of one cell's value as of one transaction time, with its lineage.
- **Mesh**: any HTTPS host that resolves cells and serves receipts.
- **Alias**: a short local name such as `ecb/fx_rate`. Aliases are a resolver convenience. They never appear in anything hashed, signed, or written as a cell URI.

## 2. Names

### 2.1 DNS names

A DNS name is written in lowercase ASCII:

- two or more labels separated by `.`; no trailing dot;
- each label is 1-63 characters from `a-z`, `0-9` and `-`, not starting or ending with `-`;
- at most 253 characters in total;
- the last label is not all digits, so IPv4 addresses are excluded.

Internationalised domain names appear only as A-labels (`xn--bcher-kva.example`). Uppercase letters and U-labels are rejected with `E_CANON_NAME`, not folded. The A-label's Punycode is not validated further; it is treated as an opaque LDH string, as DNS treats it.

### 2.2 Names of functions, path segments, arguments and code languages

A name is lowercase snake_case:

```
name = lower *( lower / DIGIT ) *( "_" 1*( lower / DIGIT ) )
```

So `fx_rate`, `base`, `a01` and `v2_final` are names. `FxRate`, `_x`, `x_`, `a__b` and `1st` are not. A name is at most 64 characters (`E_CANON_LIMIT`).

### 2.3 Namespaces and fully qualified function names

```
namespace     = dns-name *( "/" name )
function-name = namespace "/" name        ; at most 512 characters
```

The last segment of a fully qualified function name is the function. Everything before it is the namespace. In `example.org/central_bank/stats/fx_rate`, the namespace is `example.org/central_bank/stats` and the function is `fx_rate`. The DNS name at the start of a namespace is its **host**. The host publishes the keys for every namespace under it (section 9).

### 2.4 Argument names

Argument names are names (2.2). `asof`, and every name starting with `dm_`, are reserved for the protocol and rejected as argument names (`E_CANON_ARG_NAME`).

## 3. Scalar types and lexical forms

There are exactly five types. A value has one lexical form per type. Any other spelling is rejected with the code shown.

| Type | JSON | Lexical form | Example | Error |
|---|---|---|---|---|
| `number` | string | `-?(0\|[1-9][0-9]*)(\.[0-9]*[1-9])?`, not `-0` | `"1.0892"` | `E_CANON_NUMBER` |
| `string` | string | NFC, Unicode 15.1 assigned, no controls | `"Zürich"` | `E_CANON_STRING` |
| `boolean` | `true` / `false` | — | `true` | `E_CANON_TYPE` |
| `date` | string | `YYYY-MM-DD` | `"2024-03-15"` | `E_CANON_DATE` |
| `instant` | string | `YYYY-MM-DDTHH:MM:SS.ffffffZ` | `"2024-03-15T16:00:00.000000Z"` | `E_CANON_INSTANT` |

A value whose JSON type does not match its declared type fails with `E_CANON_TYPE`, e.g. the string `"true"` for a boolean. A type name outside the five also fails with `E_CANON_TYPE`.

### 3.1 Numbers

A number is an exact decimal, written as a JSON string:

```
number = [ "-" ] ( "0" / nonzero *DIGIT ) [ "." *DIGIT nonzero ]
nonzero = %x31-39
```

- ASCII digits only. No `+`, no exponent, no leading zeros, no leading or trailing `.`, no trailing fractional zeros, no whitespace.
- Zero is `0`. `-0` is rejected.
- At most 128 characters, sign and point included (`E_CANON_LIMIT`).
- NaN and infinities have no form.

Two numbers are equal exactly when their lexical forms are equal. A number carries no precision or unit: `1.5` and `1.50` are the same value, and only `1.5` is accepted. A publisher who means "1.50 with two significant decimals" says so in the function's documentation or returns a string.

*Rationale.* JSON numbers are IEEE 754 doubles in every JCS implementation. They cannot hold `0.1` exactly, they lose integers above 2^53, and their canonical text form (ECMAScript `Number.toString`) is a subtle algorithm that implementations get wrong. Decimal strings with one spelling avoid all three problems. Rejecting `1.50`, rather than stripping it to `1.5`, keeps a verifier from having to decide whether the trailing zero meant something. The 128-character limit covers every physical constant and financial quantity written out in full, which also covers the cases an exponent would otherwise be needed for.

### 3.2 Dates

`YYYY-MM-DD` in the proleptic Gregorian calendar, years `0001` to `9999`, a real calendar day (`2023-02-29` is rejected). Two-digit month and day are mandatory.

### 3.3 Instants

`YYYY-MM-DDTHH:MM:SS.ffffffZ`. That is UTC, with uppercase `T` and `Z`, exactly six fractional digits, hours `00`-`23`, minutes and seconds `00`-`59`, and a date as in 3.2.

- **No offsets.** `+01:00` and `-00:00` are rejected; only `Z` appears anywhere in hashed data.
- **Leap seconds are rejected.** `23:59:60` fails with `E_CANON_INSTANT`.
- **Microsecond precision, always written.** `.000000` is mandatory.

*Rationale.* Microseconds are the precision of PostgreSQL `timestamptz`, Python `datetime` and most databases a publisher will record `tx` in, so a stored transaction time maps to an instant exactly, with no rounding. Milliseconds would round those values. Nanoseconds would claim a precision few systems have and would overflow 64-bit integer timestamps in year 2262. Fixed width means instants compare correctly as strings, which the verification procedure relies on. Leap seconds are rejected because POSIX time cannot represent them, systems that smear them disagree about what `23:59:60` is, and UTC will stop inserting them by 2035.

### 3.4 Time zones

When a function needs a time zone, it declares an ordinary `string` argument and takes an IANA time zone name (`"Europe/Amsterdam"`). Offsets and local times never appear in hashed data. Datumesh does not validate zone names, because the IANA database changes.

### 3.5 Strings

A string value is checked in this order:

1. **Characters.** Every code point is assigned in Unicode 15.1 (General_Category is not `Cn`). It is not a surrogate. It is not a control character (U+0000-U+001F, U+007F-U+009F). Failure: `E_CANON_STRING`.
2. **Normalisation.** The string is in Normalization Form C. A non-NFC string is rejected, not normalised. Failure: `E_CANON_STRING`.
3. **Length.** At most 1024 bytes when encoded as UTF-8. Failure: `E_CANON_LIMIT`.

The empty string is a valid value. Format characters (ZWJ, bidi controls) and private-use characters are allowed.

*Rationale.* NFC means visually identical text has one encoding. A string that is NFC under one Unicode version can stop being NFC under a later one, if it contains code points that were unassigned before. Pinning the set of allowed code points to Unicode 15.1 makes validity permanent: by Unicode's normalisation stability policy, every later Unicode version gives the same NFC answer for such strings. `tools/unicode-15.1-assigned.txt` lists the assigned ranges. Control characters are rejected because they render ambiguously and some systems strip them.

### 3.6 Null

There is no null value. `null` is rejected wherever a value is expected (`E_SCHEMA`). An absent value is expressed by a cell having no receipt, never by a receipt for "nothing".

## 4. JSON forms

### 4.1 Typed scalar

```json
{"type": "number", "value": "1.0892"}
```

A JSON object with exactly the members `type` and `value`. `value` is a JSON string, except for booleans, where it is `true` or `false`.

### 4.2 Argument map

A JSON object from argument names to typed scalars. A typed scalar may be replaced by the **slice marker**, the JSON string `"*"`, meaning the argument is open. The order of members is irrelevant on input, and JCS fixes it for hashing. Duplicate names are duplicate JSON members (`E_PARSE_DUPLICATE_KEY`).

### 4.3 Cell reference

What a cell URI denotes, before the function name has been resolved to a hash:

```json
{"args": {...}, "asof": "2024-03-16T09:00:00.000000Z", "fn": "fx_rate", "ns": "rates.example.org"}
```

`asof` is optional (absent: now). Slice markers are allowed.

### 4.4 Cell

A cell reference with `asof` removed and `fn_hash` added after resolution:

```json
{
  "args": {
    "base":  {"type": "string", "value": "EUR"},
    "date":  {"type": "date",   "value": "2024-03-15"},
    "quote": {"type": "string", "value": "USD"}
  },
  "fn": "fx_rate",
  "fn_hash": "<64 lowercase hex digits>",
  "ns": "rates.example.org"
}
```

The **cell id** is SHA-256 of the cell's canonical bytes. A cell object may contain slice markers; it then denotes a slice, and its id may be used as a cache key. A receipt's cell MUST NOT contain slice markers (`E_SLICE`).

A cell binds every argument its function declares, and no others. Arguments are never optional: an open argument is written as a slice explicitly.

### 4.5 Limits

| Limit | Value | Applies to |
|---|---|---|
| `name` | 64 | characters in a function name, path segment, argument name or code language |
| `function_name` | 512 | characters in `<namespace>/<function>` |
| `args` | 32 | arguments per function or cell |
| `number` | 128 | characters in a number |
| `string` | 1024 | UTF-8 bytes in a string value |
| `summary` | 1024 | UTF-8 bytes in a receipt summary |
| `body` | 1048576 | UTF-8 bytes in a function body |
| `inputs` | 4096 | entries in a receipt's or descriptor's `inputs` |
| `licence_spdx` | 64 | characters in an SPDX licence identifier |
| `licence_url` | 512 | characters in a licence URL |
| `keys` | 64 | keys in one key publication |

Exceeding a limit fails with `E_CANON_LIMIT`. DNS's own limits (63-character labels, 253-character names) are part of the DNS grammar and fail with `E_CANON_NAME`.

## 5. Cell URIs

### 5.1 Grammar

```
cell-uri   = "cell://" namespace "/" name [ "?" query ]
query      = params [ "&" asof-param ] / asof-param
params     = param *( "&" param )
param      = arg-name "=" arg-value
asof-param = "asof=" instant
arg-value  = "*" / *( literal / pct-encoded )
literal    = ALPHA / DIGIT / "-" / "." / "_" / "~" / ":"
pct-encoded = "%" UPHEX UPHEX
UPHEX      = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
```

`namespace`, `name` and `instant` are as in sections 2 and 3. A cell URI has no fragment, no userinfo, no port and no empty query. Failures of this outer grammar are `E_PARSE_URI`. Invalid names inside it are `E_CANON_NAME`.

Example:

```
cell://ecb.europa.eu/fx_rate?base=EUR&date=2024-03-15&quote=USD&asof=2024-03-16T09:00:00.000000Z
```

### 5.2 One URI per reference

The URI is canonical: every cell reference has exactly one URI, and every accepted URI maps back to it.

- **Ordering.** Arguments appear in ascending order of name (byte order; names are ASCII), each exactly once. `asof`, if present, is last and is not part of that ordering. Out of order: `E_CANON_ARG_ORDER`. Repeated: `E_CANON_ARG_DUPLICATE`.
- **Completeness.** Every argument the function declares appears. A missing argument is `E_ARG_MISSING`; an undeclared one is `E_ARG_UNKNOWN`.
- **Percent-encoding.** A value is the UTF-8 encoding of its lexical form. Bytes that are `literal` characters appear as themselves; every other byte appears as `%` plus two uppercase hex digits. Lowercase hex, encoding a literal character (`%41`), an unencoded non-literal character (raw `ü`, `+`, space), or bytes that are not UTF-8 all fail with `E_CANON_PERCENT`. `+` is never a space. Space is `%20`.
- **Values.** Numbers, dates and instants appear in their lexical forms (instants keep their literal `:`). Strings are encoded as above, and the empty string is `name=`. Booleans are `true` or `false`; anything else is `E_CANON_TYPE`. Decoded values follow section 3, so `Zu%CC%88rich` (NFD) fails with `E_CANON_STRING`.
- **Slices.** A bare `*` is the slice marker. The string `"*"` is encoded `%2A`, so the two cannot be confused.

The URI does not carry types. To turn a URI into a cell reference, a resolver looks up the function by name. The descriptor's signature then gives each argument's type, which the resolver needs anyway. Because a slice is always written explicitly, the URI of a full cell and the URI of a slice never differ only by an omission. This keeps omission free to mean an error.

### 5.3 HTTPS mapping

On a mesh host `<mesh>`, the cell URI `cell://<rest>` is served at:

```
https://<mesh>/cell/<rest>
```

`<rest>` is copied byte for byte, query included. The mapping is reversible by stripping the prefix.

### 5.4 URI to reference and back

`parse(uri, signature)` checks, in order:

1. the outer grammar;
2. the namespace and function names;
3. parameter names left to right (grammar, reserved names, duplicates, order);
4. the argument count;
5. arguments against the signature (unknown arguments, then missing ones);
6. each value left to right (percent-encoding, then its lexical form);
7. `asof`.

The first failure is reported. The result is a cell reference (4.3) whose typed scalars carry the declared types. `format(reference)` writes the unique URI. For every accepted URI, `format(parse(uri)) = uri`.

## 6. Canonical encoding and hashing

### 6.1 Parsing JSON

Any JSON that is hashed, signed or verified is parsed strictly, as I-JSON (RFC 7493):

- the text is UTF-8 with no byte order mark;
- no member name appears twice in one object (`E_PARSE_DUPLICATE_KEY`). Names are compared after unescaping, so `"a"` and `"a"` are duplicates;
- no string contains a lone surrogate, whether written raw or escaped;
- `NaN`, `Infinity` and numbers outside the IEEE 754 double range are rejected.

All other failures are `E_PARSE_JSON`.

### 6.2 Canonical bytes

The canonical bytes of a JSON value are its RFC 8785 JSON Canonicalization Scheme (JCS) serialisation, in UTF-8. Datumesh objects contain no JSON numbers: numbers are decimal strings (3.1). JCS number formatting therefore never affects a Datumesh hash. It is implemented anyway, and tested against RFC 8785 Appendix B, so the serialiser is a complete JCS.

### 6.3 Hashes

A hash is SHA-256 over canonical bytes, written as 64 lowercase hex digits (`E_CANON_HEX` otherwise). Datumesh defines these hashes:

| Hash | Over |
|---|---|
| function hash | the function descriptor (section 7) |
| cell id | the cell object (4.4) |
| receipt hash | the receipt without its `sig` member (8.3) |

## 7. Function descriptors and function identity

A function descriptor has exactly three members: the function's signature, its code and its declared inputs.

```json
{
  "code": {"body": "amount * rates.example.org/fx_rate(base: base, date: date, quote: quote)\n", "lang": "expr"},
  "inputs": ["rates.example.org/fx_rate"],
  "signature": {
    "args": {
      "amount": {"type": "number", "valid": false},
      "base":   {"type": "string", "valid": false},
      "date":   {"type": "date",   "valid": true},
      "quote":  {"type": "string", "valid": false}
    },
    "returns": "number"
  }
}
```

- `signature.args` maps each argument name to its type. `valid: true` marks a valid-time argument, which must be a `date`, `instant` or `string` (`E_CANON_TYPE`). A period such as `2024-Q1` is a `string` valid-time argument whose format the function documents. At most 32 arguments.
- `signature.returns` is the value type.
- `code.lang` is a name identifying the language of `code.body`. `stored` means the function is a table of recorded values; by convention its body is empty and it declares no inputs. Other languages are defined by later steps. Until then, a body is an opaque text that the evaluator for `lang` interprets.
- `code.body` follows the string rules (3.5), except that TAB and LF are allowed, and its limit is 1 MiB. Line endings are LF.
- `inputs` is the set of fully qualified function names whose cells this function may read. It is an array in ascending order with no duplicates (`E_CANON_SET`). Aliases are not names (`E_CANON_NAME`).

The **function hash** is SHA-256 of the descriptor's canonical bytes. The name is deliberately not part of it: the same code published under two names has one hash. A function name resolves, through the publisher, to its current function hash. Cells and receipts pin the hash, so a receipt always identifies the exact code that produced it.

## 8. Receipts

### 8.1 Members

A receipt is a JSON object with exactly these members (`E_SCHEMA` for any missing or extra member):

| Member | Type | Meaning |
|---|---|---|
| `proto` | string | Always `"datumesh/1"`. |
| `cell` | cell (4.4) | The cell answered. No slice markers. |
| `type` | type name | The value's type. |
| `value` | string or boolean | The value, in the lexical form of `type`. |
| `valid` | argument map | The valid-time arguments of `cell.args`, echoed: same names, same typed scalars. `{}` if the function has none. |
| `asof` | instant | The transaction time this receipt answers as of. |
| `tx` | instant | The transaction time at which `value` was recorded. |
| `issued` | instant | When this receipt was signed. |
| `publisher` | namespace | The namespace that owns the function. Equals `cell.ns`. |
| `computed_by` | key reference | `<host>#<key id>` of the key that signed this receipt. |
| `inputs` | array of receipt hashes | Receipts of the input cells read to compute `value`, ascending, no duplicates. Empty for stored cells. |
| `licence` | string | An SPDX licence identifier (`CC-BY-4.0`) or an `https://` URL. |
| `summary` | string | One human sentence saying what the value is. Non-empty. String rules apply. |
| `sig` | 128 lowercase hex digits | Ed25519 signature (8.3). |

Example (`vectors/receipt/stored-number.json`):

```json
{
  "asof": "2024-03-16T09:00:00.000000Z",
  "cell": {"args": {"base": {"type": "string", "value": "EUR"}, "date": {"type": "date", "value": "2024-03-15"}, "quote": {"type": "string", "value": "USD"}},
           "fn": "fx_rate", "fn_hash": "…", "ns": "rates.example.org"},
  "computed_by": "rates.example.org#d712b32a2cc5cb7c",
  "inputs": [],
  "issued": "2024-03-16T09:00:00.000000Z",
  "licence": "CC-BY-4.0",
  "proto": "datumesh/1",
  "publisher": "rates.example.org",
  "sig": "…",
  "summary": "1 EUR was worth 1.0892 USD at the 15 March 2024 reference rate.",
  "tx": "2024-03-15T16:00:00.000000Z",
  "type": "number",
  "valid": {"date": {"type": "date", "value": "2024-03-15"}},
  "value": "1.0892"
}
```

### 8.2 Time

- `tx <= asof <= issued` always holds (`E_TIME_ORDER`).
- For a computed cell, `tx` is the latest `tx` among its input receipts, i.e. the moment the computed value became knowable. All input receipts share the receipt's `asof`. This makes recomputation deterministic: the same cell as of the same `asof` gives the same value and the same `tx`.
- `issued` exists because `asof` can be in the past. A receipt answering "as of 2020", signed today, must be checked against the key valid today, not the key valid in 2020.

### 8.3 Receipt hash and signature

Let `payload` be the canonical bytes (6.2) of the receipt with the `sig` member removed. Then:

- the **receipt hash** is `SHA-256(payload)`, in lowercase hex;
- `sig` is the 64-byte Ed25519 signature (RFC 8032, pure Ed25519, no context, no prehash) of `payload`, in lowercase hex, made with the private key named by `computed_by`.

The signed bytes are exactly the hashed bytes. A receipt hash therefore identifies the signed content, and the signature is not part of the hash, so a receipt can be re-signed with a rotated key without changing its hash.

### 8.4 Lineage

`inputs` lists receipt hashes. Each input receipt must be a cell of a function named in the descriptor's `inputs` (`E_INPUT_UNDECLARED`). Following `inputs` recursively gives the full lineage of a value down to stored cells.

## 9. Keys

### 9.1 Key id

A key is an Ed25519 public key: 32 bytes, written as 64 lowercase hex digits. Its **key id** is the first 16 hex digits of SHA-256 over the 32 raw bytes. A key reference is `<host>#<key id>`, e.g. `rates.example.org#d712b32a2cc5cb7c`. The host is a DNS name (2.1), and keys for every namespace under a host are published by that host.

### 9.2 HTTPS key document

`https://<host>/.well-known/datumesh.json`:

```json
{
  "host": "rates.example.org",
  "keys": [
    {"alg": "ed25519", "id": "d712b32a2cc5cb7c", "public": "843baeb2…", "valid_from": "2020-01-01T00:00:00.000000Z", "valid_to": "2024-06-01T00:00:00.000000Z"},
    {"alg": "ed25519", "id": "d9a2df65559c4444", "public": "3ecf7b3f…", "valid_from": "2024-06-01T00:00:00.000000Z"}
  ],
  "proto": "datumesh/1"
}
```

- `host` equals the host it was fetched from.
- `keys` holds 1 to 64 entries. `id` MUST equal the key id of `public`, and no key may appear twice.
- `valid_to` is optional (absent: open-ended). When present it is later than `valid_from`.
- No redirects are followed.

A document that breaks any of these rules is rejected whole (`E_KEY_DOC`).

### 9.3 Resolution

The HTTPS document of 9.2 is the only way keys are published. A verifier resolves the keys of a host with one `GET https://<host>/.well-known/datumesh.json`:

- **200** with a document satisfying 9.2: those are the host's keys.
- **200** with a document that does not satisfy 9.2: `E_KEY_DOC`.
- **Anything else** is `E_KEY_UNAVAILABLE`. That includes 404 and every other status, any redirect, and any network, DNS-resolution, TLS or timeout failure. There is no fallback.

A host that serves no document publishes no keys, and its receipts cannot be verified.

*Rationale.* HTTPS is authenticated by the Web PKI, so one authenticated path is simpler and stronger than two paths with a precedence rule. A 404 is not treated differently from an outage, because a verifier cannot tell a host that never published keys from one whose document is temporarily missing, and either way it has no keys to check against.

### 9.4 Retrieval is separate from verification

Resolution needs the network; verification (section 10) does not. A verifier library SHOULD take keys as an input to verification rather than fetch them itself, and SHOULD offer fetching as a separate, explicit operation that reports `E_KEY_UNAVAILABLE` or `E_KEY_DOC` as above.

### 9.5 Rotation

A host publishes all keys still needed to verify receipts it has issued, each with its window. A key is usable for a receipt when `valid_from <= issued` and, if `valid_to` is present, `issued < valid_to` (`E_KEY_NOT_VALID`). To rotate a key, add the new key with a `valid_from`, then set the old key's `valid_to` to that time. To revoke a compromised key, set its `valid_to` to the time of compromise. Receipts issued after that time stop verifying, and earlier ones still verify.

## 10. Verification

### 10.1 Procedure

A verifier runs these steps in order and stops at the first failure, reporting its code. Within a step, members are examined in canonical (JCS) order, depth first, so the reported error is deterministic.

1. **Parse** the bytes as strict JSON (6.1).
2. **Structure.** Check the receipt has exactly the members of 8.1 with the right JSON types, `proto` is `datumesh/1`, `cell` has exactly `args`, `fn`, `fn_hash`, `ns`, and every argument is a typed scalar or the slice marker. Failure: `E_SCHEMA`.
3. **Canonical form.** Check every member against its lexical rules: names, hex, instants, typed scalars, licence, the summary, `inputs` ascending and unique, and limits. `value` is checked against `type`.
4. **Consistency.**
   - No slice markers in `cell.args` or `valid` (`E_SLICE`).
   - `publisher` equals `cell.ns` (`E_PUBLISHER_MISMATCH`).
   - Every member of `valid` equals the same-named member of `cell.args` and is a date, instant or string (`E_VALID_MISMATCH`).
   - `tx <= asof <= issued` (`E_TIME_ORDER`).
5. **Key.** Resolve the keys of the host in `computed_by` (9.3) and find the key with the given id (`E_KEY_UNKNOWN`). Check that `issued` is in its window (`E_KEY_NOT_VALID`).
6. **Signature.** Verify `sig` over `payload` (8.3) with that key (`E_SIGNATURE`). Use RFC 8032 verification with the cofactorless equation, rejecting `S >= L`, non-canonical encodings of `R` and `A`, and small-order `A` and `R` (as libsodium does). A receipt that passes steps 1-6 is **signature-valid**.
7. **Recomputation** (optional; makes the receipt **fully verified**):
   1. Obtain the descriptor for `cell.fn_hash` (`E_FN_UNAVAILABLE`). It must hash to `cell.fn_hash` (`E_FN_HASH_MISMATCH`) and be canonical (sections 6-7).
   2. `cell.args` names exactly the declared arguments (`E_ARG_UNKNOWN`, then `E_ARG_MISSING`), each with its declared type (`E_ARG_TYPE`).
   3. `valid` holds exactly the declared valid-time arguments (`E_VALID_MISMATCH`).
   4. `type` equals `signature.returns` (`E_RETURN_TYPE`).
   5. For each hash in `inputs`, in order:
      - obtain the input receipt (`E_INPUT_UNAVAILABLE`), which must hash to the listed hash;
      - verify it through step 6 (`E_INPUT_INVALID`);
      - check it is a cell of a declared input function (`E_INPUT_UNDECLARED`);
      - check it has the same `asof` (`E_TIME_ORDER`).

      If there are inputs, `tx` must equal the latest input `tx` (`E_TIME_ORDER`).
   6. Evaluate the function (for `stored`: look the value up as of `asof`). The result's `type` and `value` must equal the receipt's lexically (`E_VALUE_MISMATCH`).

Signature-valid means the holder of key `computed_by` stated this value. Whether to trust that party is policy, outside this specification.

### 10.2 Error codes

The four failure classes a verifier distinguishes are: bad canonical form (parse, schema and canon codes), unknown or unusable key (key codes), bad signature, and value mismatch on recomputation (the remaining codes).

| Code | Step | Meaning |
|---|---|---|
| `E_PARSE_JSON` | 1 | Not strict JSON: invalid UTF-8, BOM, lone surrogate, NaN/Infinity, syntax error. |
| `E_PARSE_DUPLICATE_KEY` | 1 | A member name repeated in one object. |
| `E_PARSE_URI` | URI | Not `cell://<path>[?<query>]`, has a fragment, empty query, or a parameter without `=`. |
| `E_SCHEMA` | 2 | Missing or extra member, wrong JSON type, wrong `proto`, null. |
| `E_CANON_NAME` | 3 | Invalid DNS name, namespace, function name, code language or key reference. |
| `E_CANON_ARG_NAME` | 3 | Invalid or reserved argument name. |
| `E_CANON_ARG_DUPLICATE` | URI | An argument or `asof` repeated in a URI. |
| `E_CANON_ARG_ORDER` | URI | URI arguments not in ascending order, or `asof` not last. |
| `E_CANON_PERCENT` | URI | Non-canonical percent-encoding or non-UTF-8 bytes. |
| `E_CANON_TYPE` | 3 | Unknown type name, value of the wrong JSON type, or a non-date/instant/string valid-time declaration. |
| `E_CANON_NUMBER` | 3 | Number not in canonical decimal form. |
| `E_CANON_DATE` | 3 | Date not `YYYY-MM-DD` or not a calendar day. |
| `E_CANON_INSTANT` | 3 | Instant not `YYYY-MM-DDTHH:MM:SS.ffffffZ`, not a real time, or a leap second. |
| `E_CANON_STRING` | 3 | Control, unassigned or surrogate code point, not NFC, or empty summary. |
| `E_CANON_HEX` | 3 | Hash, key id or signature not lowercase hex of the right length. |
| `E_CANON_LICENCE` | 3 | Licence neither an SPDX identifier nor an `https://` URL. |
| `E_CANON_SET` | 3 | `inputs` not strictly ascending. |
| `E_CANON_LIMIT` | 3 | A limit from 4.5 exceeded. |
| `E_SLICE` | 4 | A slice marker in a receipt. |
| `E_PUBLISHER_MISMATCH` | 4 | `publisher` differs from `cell.ns`. |
| `E_VALID_MISMATCH` | 4, 7 | `valid` does not echo exactly the valid-time arguments. |
| `E_TIME_ORDER` | 4, 7 | `tx <= asof <= issued` fails, inputs have another `asof`, or computed `tx` is not the latest input `tx`. |
| `E_ARG_UNKNOWN` | URI, 7 | An argument the function does not declare. |
| `E_ARG_MISSING` | URI, 7 | A declared argument not bound (slices are written `*`). |
| `E_KEY_UNAVAILABLE` | 5 | The key document could not be retrieved: any non-200 status (404 included), redirect, or network, DNS-resolution, TLS or timeout failure. |
| `E_KEY_DOC` | 5 | The key document is malformed or breaks a rule of 9.2. |
| `E_KEY_UNKNOWN` | 5 | The host's key document has no key with that id. |
| `E_KEY_NOT_VALID` | 5 | `issued` is outside the key's validity window. |
| `E_SIGNATURE` | 6 | The Ed25519 signature does not verify. |
| `E_FN_UNAVAILABLE` | 7 | No descriptor found for `fn_hash`. |
| `E_FN_HASH_MISMATCH` | 7 | The descriptor does not hash to `fn_hash`. |
| `E_ARG_TYPE` | 7 | An argument's type differs from its declaration. |
| `E_RETURN_TYPE` | 7 | `type` differs from the declared return type. |
| `E_INPUT_UNAVAILABLE` | 7 | An input receipt cannot be found, or the one found has another hash. |
| `E_INPUT_INVALID` | 7 | An input receipt is not signature-valid. |
| `E_INPUT_UNDECLARED` | 7 | An input receipt is a cell of a function not in the descriptor's `inputs`. |
| `E_VALUE_MISMATCH` | 7 | Recomputation gives a different type or value. |

"URI" marks codes raised while parsing a cell URI (5.4). Canonicalising a scalar, cell, reference or descriptor on its own uses the same codes as steps 1-3.

## 11. Test vectors

`vectors/<group>/<name>.json`, one vector per file, described by `schemas/vector.schema.json`. Every vector has `id` (its path without `.json`), `kind`, `description` and `valid`. An invalid vector has `error`: the exact code the reference tool reports.

| Kind | Input | Outputs when valid |
|---|---|---|
| `jcs` | `input`: JSON text | `canonical`, `sha256` |
| `scalar`, `cell`, `ref`, `function` | `input`: JSON text (or `input_hex`: raw bytes) | `canonical`, `sha256` |
| `uri` | `input`: URI, `signature`: function signature | `object` (cell reference), `canonical`, `sha256`, `https` (on mesh `mesh.example`) |
| `keyid` | `input`: public key hex | `key_id` |
| `keys` | `host`, `env`: what the HTTPS request returned | `key_ids` |
| `receipt` | `input`: receipt JSON text; `keypair` (`seed`, `public`, `key_id`); `keys`: an `env` per host; optional `recompute` | `canonical` (the signed payload), `sha256` (receipt hash), `sig`, `level` (`signed` or `recomputed`) |

`canonical` is the canonical byte string as UTF-8 text. Inputs are deliberately not canonical: member order is reversed, and there is whitespace and escaping. A valid receipt vector's expected verification result is success at `level`; an invalid one's is `error`. Keypairs come from fixed seeds and Ed25519 is deterministic, so `tools/gen_vectors.py` reproduces every file byte for byte.

The `env` for a host is `{"https": {"status": 200, "body": "<text>"}}` for a retrieved document, or `{"https": {"status": <other status>}}` or `{"https": {"status": "error"}}` for a failed retrieval. A host absent from `keys` behaves as `{"https": {"status": "error"}}`.

The vectors use reserved example domains (`example.org`, `example.net`, `.example`) for everything signed.

## 12. Security considerations

- **Ambiguity is the attack surface.** Two encodings of one object would give one receipt two hashes, or let a signature cover something other than what is shown. Every rule above exists to make the canonical form unique. Implementations MUST reject, never repair.
- **Duplicate JSON members** are the classic signature-confusion bug: one parser takes the first, another the last. They are rejected at parse time.
- **Trust.** A valid signature means only that the key holder said it. A verifier chooses whom to trust (typically the publisher for stored cells, or anyone for recomputed cells, since recomputation does not depend on trust).
- **Key retrieval** is as trustworthy as the Web PKI. Verifiers MUST validate the TLS certificate and MUST NOT follow redirects.
- **Revocation** is by shortening `valid_to`. There is no other revocation list.
- **Text in summaries and strings** may contain bidi controls and confusable characters. Display it as data.

## 13. Decisions and rationale

Every choice this specification makes where its brief left room, with the main alternative considered.

| # | Choice | Alternative not taken | Why |
|---|---|---|---|
| D1 | Numbers are decimal strings with one spelling; non-canonical spellings rejected | Normalise `1.50` to `1.5`; allow exponents | Rejecting means no verifier ever decides what a trailing zero meant; 128 characters cover all realistic magnitudes without exponents. |
| D2 | Instants have microsecond precision | Milliseconds | Matches database `tx` precision exactly; fixed width keeps string comparison chronological. |
| D3 | Leap seconds rejected | Accept `:60` | POSIX time cannot represent them; smearing makes them ambiguous. |
| D4 | Strings NFC-checked (not normalised), code points pinned to Unicode 15.1 | NFC under "the verifier's Unicode version" | Only a pinned repertoire makes NFC validity permanent across Unicode versions. |
| D5 | No null anywhere | Null as "unknown" | Absence is no receipt; null would add a sixth type in disguise. |
| D6 | Typed values in JSON (`{"type","value"}`), types not in URIs | Untyped JSON values with types from the signature; type sigils in URIs | Hashes commit to types so a verifier can check canonical form offline; URIs stay readable and get types from the signature the resolver fetches anyway. |
| D7 | Slices written explicitly as `*` (JSON `"*"`) | Slice by omitting the argument | Omission stays an error, so typos and future optional arguments cannot silently become slices. |
| D8 | `asof` last in URIs, not sorted with arguments | Sort `asof` with the arguments | It is protocol-level, not an argument, and the brief's grammar puts it last. |
| D9 | `asof` and the `dm_` prefix reserved as argument names | Reserve only `asof` | Leaves room for protocol parameters without breaking existing cells. |
| D10 | Lowercase-only names, A-label IDNs; rejected not folded | Case-fold | Folding is normalisation; DNS is case-insensitive but hashes are not. |
| D11 | Receipt has `proto` and `issued` beyond the brief's list | Exactly the listed members | `proto` lets a future version coexist; `issued` is needed for key rotation when `asof` is historical. |
| D12 | `computed_by` is `<host>#<key id>` | Bare key id | A bare key id cannot be looked up without a global registry. |
| D13 | Receipt hash and signature over the same bytes (receipt minus `sig`) | Sign the hash | One canonical payload; re-signing keeps the hash. |
| D14 | `inputs` are sets: sorted, unique; same for descriptor inputs | Ordered lists | Lineage is a set; order would be a second spelling. |
| D15 | Keys only from the HTTPS key document; every retrieval failure, 404 included, is `E_KEY_UNAVAILABLE` | DNS TXT as a fallback (removed in `spec-0.1.1`) | One Web-PKI-authenticated path; nothing to downgrade to. |
| D16 | Keys published per DNS host, covering its path namespaces | Per-namespace key files | `/.well-known` exists only at an origin's root (RFC 8615). |
| D17 | Computed `tx` = latest input `tx`; inputs share `asof` | `tx` = evaluation time | Makes recomputation deterministic and checkable. |
| D18 | "Declared inputs" in the function hash = names of functions it may read | Declared arguments | Arguments are already in the signature; dependencies are what the brief's third component can add. |
| D19 | Descriptor `code` is `{lang, body}`; `stored` for stored functions | Hash of external source | Self-contained hash input; languages defined later. |
| D20 | Licence: one SPDX identifier or `https://` URL, not an SPDX expression | Full SPDX expressions | Brief says identifier; expressions add a grammar to canonicalise. |
| D21 | Signed test data uses example domains, not real publishers | Use `ecb.europa.eu` | Vectors must not look like statements by real organisations. |
| D22 | Verification uses libsodium-strict Ed25519 | ZIP-215 permissive rules | Honest signatures verify either way; strict rules reject malleable edge cases. |

## Appendix A: collected ABNF

```
; RFC 5234 core rules: ALPHA, DIGIT. lower = %x61-7A.
cell-uri      = "cell://" namespace "/" name [ "?" query ]
query         = params [ "&" asof-param ] / asof-param
params        = param *( "&" param )
param         = name "=" arg-value
asof-param    = "asof=" instant
arg-value     = "*" / *( literal / pct-encoded )
literal       = ALPHA / DIGIT / "-" / "." / "_" / "~" / ":"
pct-encoded   = "%" UPHEX UPHEX
UPHEX         = DIGIT / %x41-46

namespace     = dns-name *( "/" name )
function-name = namespace "/" name
dns-name      = label 1*( "." label )            ; <= 253 chars, last label not all digits
label         = ( lower / DIGIT ) [ *61( lower / DIGIT / "-" ) ( lower / DIGIT ) ]
name          = lower *( lower / DIGIT ) *( "_" 1*( lower / DIGIT ) )   ; <= 64 chars
key-ref       = dns-name "#" 16HEXLOW

number        = [ "-" ] ( "0" / %x31-39 *DIGIT ) [ "." *DIGIT %x31-39 ]   ; not "-0", <= 128 chars
date          = 4DIGIT "-" 2DIGIT "-" 2DIGIT                               ; a real day, 0001..9999
instant       = date "T" 2DIGIT ":" 2DIGIT ":" 2DIGIT "." 6DIGIT "Z"     ; seconds 00-59
HEXLOW        = DIGIT / %x61-66

```

## 14. Changes

### spec-0.1.1

- **Removed DNS TXT key publication.** Section 9.3 used to define `_datumesh.<host>` TXT records with a precedence rule. The HTTPS document is now the only key source; any retrieval failure, including 404, is `E_KEY_UNAVAILABLE` (9.3). `E_KEY_UNKNOWN` now means only that the document lacks the key id. The vectors for DNS were removed and the `env` format lost its `dns` member.
- **Added 9.4:** retrieving keys is separate from verifying.
- **Open question for the engine:** the limit of 4096 `inputs` per receipt (4.5) stands for now. A computed cell over a long slice may need more inputs than that, or an intermediate aggregation cell; the engine step decides.

The receipt format, canonical encoding and all hashes are unchanged: every receipt valid under `spec-0.1` that names a key published over HTTPS is valid under `spec-0.1.1`, with the same hash.

