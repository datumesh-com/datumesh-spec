# Datumesh protocol, version 1

Status: draft, revision `spec-0.2.0`. Identifier in data: `datumesh/1`. Changes are listed in section 14.

Datumesh is an open protocol for addressable, verifiable data cells: a name, a resolver, a signed answer, and a lineage you can follow. This document defines how a cell is named (the cell URI), how it is written as canonical bytes, what a signed answer (a receipt) contains, what a mesh returns around it (the response envelope), how keys are published, and how a verifier checks a receipt. The units a function may declare are listed in `units.md`, which is part of this specification. Storage formats, wire protocols, resolvers and the engine are out of scope.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174.

Everything hashed or signed under these rules is hashed or signed forever. The rules are therefore strict: **where an input could be read two ways, it is rejected, not normalised.** A verifier never guesses.

The executable form of this document is `tools/canon.py`; the vectors under `vectors/` are normative examples. If the prose and the vectors disagree, that is a bug in this document to be reported, not a choice for implementers.

## Contents

1. Terms
2. Names
3. Scalar types and lexical forms
4. JSON forms: typed scalars, arguments, references, cells, limits
5. Cell URIs and response envelopes
6. Canonical encoding and hashing
7. Function descriptors, function identity and units
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
- **Unit**: what a number means, such as `EUR` or `degC`. A function declares the unit of every number argument and number return (7.1). Values and receipts never carry units.
- **Blob**: a scalar whose value names content by its hash, byte length and media type (3.7). The content itself travels out of band.
- **Envelope**: the JSON body a mesh returns around a receipt (5.5). It is the mesh's statement, unsigned; the receipt inside is the signer's.
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

There are exactly six types. A value has one lexical form per type. Any other spelling is rejected with the code shown.

| Type | JSON | Lexical form | Example | Error |
|---|---|---|---|---|
| `number` | string | `-?(0\|[1-9][0-9]*)(\.[0-9]*[1-9])?`, not `-0` | `"1.0892"` | `E_CANON_NUMBER` |
| `string` | string | NFC, Unicode 15.1 assigned, no controls | `"Zürich"` | `E_CANON_STRING` |
| `boolean` | `true` / `false` | — | `true` | `E_CANON_TYPE` |
| `date` | string | `YYYY-MM-DD` | `"2024-03-15"` | `E_CANON_DATE` |
| `instant` | string | `YYYY-MM-DDTHH:MM:SS.ffffffZ` | `"2024-03-15T16:00:00.000000Z"` | `E_CANON_INSTANT` |
| `blob` | string | `<sha256>:<length>:<media type>` | `"9dc3…330a:17:text/plain"` | `E_CANON_BLOB` |

A value whose JSON type does not match its declared type fails with `E_CANON_TYPE`, e.g. the string `"true"` for a boolean. A type name outside the six also fails with `E_CANON_TYPE`.

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

Two numbers are equal exactly when their lexical forms are equal. A number value carries no precision and no unit: `1.5` and `1.50` are the same value, and only `1.5` is accepted. A publisher who means "1.50 with two significant decimals" says so in the function's documentation or returns a string. The unit of a number is declared once, by the function (7.1).

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

### 3.7 Blobs

A blob names a sequence of bytes, its **content**, without containing it:

```
blob            = sha256 ":" length ":" media-type
sha256          = 64HEXLOW                         ; SHA-256 of the content
length          = "0" / %x31-39 *DIGIT             ; bytes of content, at most 9007199254740991
media-type      = restricted-name "/" restricted-name   ; at most 128 characters
restricted-name = ( lower / DIGIT ) *( lower / DIGIT / "!" / "#" / "$" / "&" / "-" / "^" / "_" / "." / "+" )
```

- The hash is lowercase hex. The length is a canonical non-negative integer, at most 2^53 - 1.
- The media type is an RFC 6838 `type/subtype`, lowercase, with no parameters and no whitespace. `text/csv;charset=utf-8` and `text/CSV` are rejected. Content of a `text/*` blob SHOULD be UTF-8.
- Every failure is `E_CANON_BLOB`, including a media type longer than 128 characters.

Only the blob string is hashed and signed. The content is retrieved out of band, by its hash; how is outside this revision. Content that does not hash to `sha256`, or does not have exactly `length` bytes, is not the blob's content (`E_BLOB_MISMATCH`, 10.1 step 7.7). A blob has no unit and cannot be a valid-time argument (section 7). The string type and its 1024-byte limit are unchanged: text longer than that is published as a blob.

*Rationale.* A blob is a scalar whose value is a content hash, so the type system stays "scalars only" and a receipt stays small whatever the content's size. The length lets a client refuse or bound a download before hashing it. The media type tells a client how to read the content. It is not checked against the content, because no verifier can do that reliably.

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

## 5. Cell URIs and response envelopes

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

`namespace`, `name` and `instant` are as in sections 2 and 3. A cell URI has no fragment, no userinfo, no port and no empty query. The authority is the text between `cell://` and the first `/` (or `?`, or the end); an `@` or `:` in it is `E_PARSE_URI`, so `cell://user@rates.example.org/…` and `cell://rates.example.org:443/…` are rejected, not corrected. Failures of this outer grammar are `E_PARSE_URI`. Invalid names inside it are `E_CANON_NAME`.

Example:

```
cell://ecb.europa.eu/fx_rate?base=EUR&date=2024-03-15&quote=USD&asof=2024-03-16T09:00:00.000000Z
```

### 5.2 One URI per reference

The URI is canonical: every cell reference has exactly one URI, and every accepted URI maps back to it.

- **Ordering.** Arguments appear in ascending order of name (byte order; names are ASCII), each exactly once. `asof`, if present, is last and is not part of that ordering. Out of order: `E_CANON_ARG_ORDER`. Repeated: `E_CANON_ARG_DUPLICATE`.
- **Completeness.** Every argument the function declares appears. A missing argument is `E_ARG_MISSING`; an undeclared one is `E_ARG_UNKNOWN`.
- **Percent-encoding.** A value is the UTF-8 encoding of its lexical form. Bytes that are `literal` characters appear as themselves; every other byte appears as `%` plus two uppercase hex digits. Lowercase hex, encoding a literal character (`%41`), an unencoded non-literal character (raw `ü`, `+`, space), or bytes that are not UTF-8 all fail with `E_CANON_PERCENT`. `+` is never a space. Space is `%20`.
- **Values.** Numbers, dates and instants appear in their lexical forms (instants keep their literal `:`). Strings and blobs are encoded as above, so a blob's `:` stays literal and its `/` and `+` become `%2F` and `%2B`. The empty string is `name=`. Booleans are `true` or `false`; anything else is `E_CANON_TYPE`. Decoded values follow section 3, so `Zu%CC%88rich` (NFD) fails with `E_CANON_STRING`.
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

1. the outer grammar, entirely before any name: the URI starts with `cell://`, contains no `#`, has no userinfo or port, and, if it contains `?`, the text after it is non-empty and each `&`-separated parameter contains `=` (`E_PARSE_URI`);
2. the namespace and function names;
3. parameter names left to right (grammar, reserved names, duplicates, order);
4. the argument count;
5. arguments against the signature (unknown arguments, then missing ones);
6. each value left to right (percent-encoding, then its lexical form);
7. `asof`.

The first failure is reported. `signature` is taken as given: it comes from a descriptor already checked under section 7, and `parse` does not check it again. The result is a cell reference (4.3) whose typed scalars carry the declared types. `format(reference)` writes the unique URI. For every accepted URI, `format(parse(uri)) = uri`.

### 5.5 Response envelope

A mesh answers `GET https://<mesh>/cell/<rest>` (5.3) with an HTTP status and a JSON body, the **envelope**, served as `application/json`.

**An envelope is the mesh's statement and a receipt is the signer's. Only the receipt is verifiable.** The envelope is not hashed and not signed, and nothing in it changes what a receipt means. Everything a mesh says about a receipt (that it is stale, superseded or recomputed) is therefore said here, outside it, and receipts never change to carry such news. A client parses the envelope with the strict rules of 6.1.

The envelope is an object whose `outcome` decides which other members it has. A member not listed for the outcome is not allowed.

| `outcome` | HTTP status | Required members | Optional members | Meaning |
|---|---|---|---|---|
| `ok` | 200 | `receipt`, `trust` | `superseded_by`, `reason` | The receipt answers the cell as of the requested `asof`. |
| `stale` | 200 | `receipt`, `trust`, `age_seconds` | `superseded_by`, `reason` | The mesh could not get a current answer and serves the last receipt it knows. |
| `not_covered` | 404 | none | none | The mesh has no receipt for this cell: it does not serve the function, or the cell has no value. |
| `unlicensed` | 403 | none | none | The requester may not receive this cell. |
| `payment_required` | 402 | `quote` | none | The cell is available for the quoted price. |
| `rate_limited` | 429 | `retry_after_seconds` | none | Too many requests. The mesh SHOULD also send the `Retry-After` header with the same value. |
| `bad_request` | 400 | `error` | none | The request is malformed: the cell URI does not parse. |
| `error` | 500-599 | `error` | none | The mesh failed to produce an answer. |

Members:

- `outcome`: one of the eight strings above.
- `receipt`: a receipt object (section 8), embedded as JSON. For `stale`, it is the last receipt the mesh knows for the cell.
- `trust`: what the mesh asserts about how the receipt was produced:
  - `primary`: the host of `computed_by` equals the host of `cell.ns` (2.3), and `inputs` is empty. The publisher answered from its own records.
  - `verified`: not primary, and the mesh recomputed the receipt (10.1 step 7) and it matched.
  - `unverified`: neither.

  A mesh MUST say `primary` exactly when the first condition holds. A client checks this against the receipt. It cannot check `verified`, which remains the mesh's claim.
- `age_seconds`: a non-negative integer. The number of seconds since the mesh last confirmed that the receipt was the current answer.
- `superseded_by`: the receipt hash (8.3) of a newer receipt for the same cell at a later `tx`. It is not the receipt's own hash. A client fetches that receipt like any other.
- `reason`: a non-empty string saying why the receipt was superseded, typically a correction. It follows the string rules (3.5) with the `summary` limit, and is only present with `superseded_by`.
- `quote`: an object with exactly `amount`, a number in the form of 3.1 (128 characters at most) greater than zero; `currency`, any currency code listed in `units.md`, withdrawn codes included; and `authorise`, where the requester can pay, an `https://` URL by the licence URL rule (`https://` followed by printable ASCII, at most 512 characters).
- `retry_after_seconds`: a non-negative integer.
- `error`: what failed. For `bad_request`, one of the codes `parse` can raise (5.4): `E_PARSE_URI`, `E_CANON_NAME`, `E_CANON_ARG_NAME`, `E_CANON_ARG_DUPLICATE`, `E_CANON_ARG_ORDER`, `E_CANON_PERCENT`, `E_CANON_TYPE`, `E_CANON_NUMBER`, `E_CANON_DATE`, `E_CANON_INSTANT`, `E_CANON_STRING`, `E_CANON_BLOB`, `E_CANON_LIMIT`, `E_ARG_UNKNOWN`, `E_ARG_MISSING`. For `error`, any code in 10.2 except `E_ENVELOPE`, which is a client's code, e.g. `E_INPUT_UNAVAILABLE`.

**Integer members.** `age_seconds` and `retry_after_seconds` are JSON numbers written `0` or `[1-9][0-9]*`: no fraction, no exponent, no sign, and at most 2^53 - 1. So `30.0`, `3e1` and `-0` are `E_ENVELOPE`. They are the only JSON numbers in this specification, which is possible because envelopes are never hashed.

A client checks an envelope in this order and reports the first failure:

1. Parse the body as strict JSON (6.1).
2. Check the members against the table and the rules above (`E_ENVELOPE`). Here `receipt` need only be an object. Every failure of a member's rule is `E_ENVELOPE`, including the rules `reason`, `quote` and `superseded_by` borrow from other sections.
3. Check that the HTTP status matches `outcome` (`E_ENVELOPE`).
4. If there is a receipt, verify it through step 6 of 10.1, with that procedure's codes.
5. **The receipt answers the request** (`E_ENVELOPE`). Its cell id (4.4) MUST equal the id of the cell requested. That is, the cell the request's URI denotes, resolved to the `fn_hash` the client used. If the request carried `asof`:
   - for `ok`, the receipt's `asof` MUST equal it;
   - for `stale`, the receipt's `asof` MUST be at or before it. How much earlier is what `age_seconds` describes.

   If the request carried no `asof`, the receipt's `asof` is the mesh's "now", and the client accepts it.
6. Check `trust` against the receipt, as above, and that `superseded_by` differs from the receipt's hash (`E_ENVELOPE`).

Step 5 needs the request, which the envelope does not contain. A client MUST perform it; a library takes the requested cell id and `asof` as inputs. A malformed request description is the caller's error, not `E_ENVELOPE`. For outcomes without a receipt there is nothing to bind. Without it, a mesh could answer with a valid receipt for a different cell.

An envelope that passes says only that this mesh made a well-formed statement, about the requested cell, citing a receipt that its signer signed.

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

## 7. Function descriptors, function identity and units

A function descriptor has exactly three members: the function's signature, its code and its declared inputs.

```json
{
  "code": {"body": "amount * rates.example.org/fx_rate(base: base, date: date, quote: quote)\n", "lang": "expr"},
  "inputs": ["rates.example.org/fx_rate"],
  "signature": {
    "args": {
      "amount": {"type": "number", "unit": {"arg": "base"}, "valid": false},
      "base":   {"type": "string", "valid": false},
      "date":   {"type": "date",   "valid": true},
      "quote":  {"type": "string", "valid": false}
    },
    "returns": {"type": "number", "unit": {"arg": "quote"}}
  }
}
```

- `signature.args` maps each argument name to its declaration: `{"type", "valid"}`, or `{"type", "unit", "valid"}` when the type is `number`. `valid: true` marks a valid-time argument, which must be a `date`, `instant` or `string` (`E_CANON_TYPE`). A period such as `2024-Q1` is a `string` valid-time argument whose format the function documents. At most 32 arguments.
- `signature.returns` is the value type: a type name, or `{"type": "number", "unit": …}` when the type is `number`.
- Units are required on numbers and allowed nowhere else. Each of these fails with `E_CANON_UNIT`: a `number` argument without `unit`; `unit` on any other argument; `returns` written as the bare name `"number"`; a `returns` object whose type is not `number`, or that has no `unit`; and a unit that is not valid by 7.1. A declaration or `returns` object with a missing `type` or any other member is `E_SCHEMA`.
- **Check order.** A descriptor's structure (`E_SCHEMA`), unit shapes included, is checked over the whole descriptor before any canonical-form rule. Then `code`, `inputs`, each argument in JCS order of names, and `returns`. Within an argument declaration: `type` (`E_CANON_TYPE`), then `unit`, then `valid`. For `returns`: the type name (`E_CANON_TYPE`), then that an object's type is `number` and that a bare name is not `number`, then the presence of `unit`, then the unit itself (all `E_CANON_UNIT`).
- `code.lang` is a name identifying the language of `code.body`. `stored` means the function is a table of recorded values; by convention its body is empty and it declares no inputs. Other languages are defined by later steps. Until then, a body is an opaque text that the evaluator for `lang` interprets.
- `code.body` follows the string rules (3.5), except that TAB and LF are allowed, and its limit is 1 MiB. Line endings are LF.
- `inputs` is the set of fully qualified function names whose cells this function may read. It is an array in ascending order with no duplicates (`E_CANON_SET`). Aliases are not names (`E_CANON_NAME`).

The **function hash** is SHA-256 of the descriptor's canonical bytes. The name is deliberately not part of it: the same code published under two names has one hash. A function name resolves, through the publisher, to its current function hash. Cells and receipts pin the hash, so a receipt always identifies the exact code that produced it, and the units of its numbers.

### 7.1 Units

A unit says what a number means. It is declared in the signature, never in a receipt: the function hash commits to it, and every receipt inherits it through `cell.fn_hash`. `units.md` lists the units and is normative. In a signature, a unit is one of:

- **a literal**: a string listed in `units.md`, or an index unit (`units.md` 2.4), such as `"EUR"`, `"degC"`, `"percent"`, `"1"` or `"index:2015=100"`;
- **an argument reference** `{"arg": "<name>"}`: the value of the named argument, which must be an argument of the same signature of type `string`;
- **a rate** `{"of": X, "per": Y}`: units of X per one unit of Y, where X and Y are each a currency code from `units.md` or an argument reference.

`fx_rate(base, date, quote)` therefore returns `{"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}}`. Its cell for base `EUR` and quote `USD` has the unit `USD/EUR`, US dollars per euro.

- A unit string is compared byte for byte and never parsed. `degC` and `°C` differ, and `USD/EUR` written as a string is not a unit, because a rate has only the object form. A literal not in `units.md` is `E_CANON_UNIT`.
- For an argument reference, the descriptor check is only that the argument exists and is a `string` (`E_CANON_UNIT`). Its value comes from the cell.
- Any other JSON shape for a unit is `E_SCHEMA`.
- The list grows only through revisions of this specification. A code removed from ISO 4217 stays listed, because receipts that use it stay valid.

**Resolution** is a client convenience; verification (10.1) never resolves units. The unit of one cell's value is found by substituting the cell's argument values into the return unit. A rate is written `<of>/<per>`. A substituted value must itself be a listed unit, and on a side of a rate a currency code (`E_CANON_UNIT`). A slice marker cannot be substituted (`E_SLICE`). A function that does not return a number has no unit. The resolved string is for display and comparison; it is not hashed and cannot be written in a signature. `units.md` section 3 gives the full rules, including the check order: the cell, then the descriptor's hash (`E_FN_HASH_MISMATCH`), then the descriptor, then substitution, where a referenced argument that is unbound is `E_ARG_MISSING`, a slice `E_SLICE`, and of another type `E_ARG_TYPE`.

A verifier never checks a value against its unit, and never converts between units.

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

A receipt carries no unit. The unit of a `number` value is its function's declared return unit, resolved against `cell.args` (7.1); a client gets the descriptor through `cell.fn_hash`. A `blob` value names its content (3.7), which travels separately. Facts that may change after signing, such as staleness, supersession and the mesh's trust label, are never added to a receipt: they belong to the response envelope (5.5).

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
3. **Canonical form.** Check every member against its lexical rules: names, hex, instants, typed scalars (blobs included), licence, the summary, `inputs` ascending and unique, and limits. `value` is checked against `type`.
4. **Consistency.**
   - No slice markers in `cell.args` or `valid` (`E_SLICE`).
   - `publisher` equals `cell.ns` (`E_PUBLISHER_MISMATCH`).
   - Every member of `valid` equals the same-named member of `cell.args` and is a date, instant or string (`E_VALID_MISMATCH`).
   - `tx <= asof <= issued` (`E_TIME_ORDER`).
5. **Key.** Resolve the keys of the host in `computed_by` (9.3) and find the key with the given id (`E_KEY_UNKNOWN`). Check that `issued` is in its window (`E_KEY_NOT_VALID`).
6. **Signature.** Verify `sig` over `payload` (8.3) with that key (`E_SIGNATURE`). Use RFC 8032 verification with the cofactorless equation, rejecting `S >= L`, non-canonical encodings of `R` and `A`, and small-order `A` and `R` (as libsodium does). A receipt that passes steps 1-6 is **signature-valid**.
7. **Recomputation** (optional; makes the receipt **fully verified**):
   1. Obtain the descriptor for `cell.fn_hash` (`E_FN_UNAVAILABLE`). It must hash to `cell.fn_hash` (`E_FN_HASH_MISMATCH`) and be canonical (sections 6-7, units included).
   2. `cell.args` names exactly the declared arguments (`E_ARG_UNKNOWN`, then `E_ARG_MISSING`), each with its declared type (`E_ARG_TYPE`).
   3. `valid` holds exactly the declared valid-time arguments (`E_VALID_MISMATCH`).
   4. `type` equals the declared return type: `signature.returns`, or its `type` member when it is an object (`E_RETURN_TYPE`).
   5. For each hash in `inputs`, in order:
      - obtain the receipt offered for it (`E_INPUT_UNAVAILABLE` if none);
      - verify it through step 6 (`E_INPUT_INVALID`);
      - check that it hashes to the listed hash (`E_INPUT_UNAVAILABLE`);
      - check it is a cell of a declared input function (`E_INPUT_UNDECLARED`);
      - check it has the same `asof` (`E_TIME_ORDER`).

      If there are inputs, `tx` must equal the latest input `tx` (`E_TIME_ORDER`).
   6. Evaluate the function (for `stored`: look the value up as of `asof`). The result's `type` and `value` must equal the receipt's lexically (`E_VALUE_MISMATCH`).
   7. **Blob content.** If content is supplied: `type` must be `blob` (`E_SCHEMA` otherwise), and the content must have exactly `length` bytes and a SHA-256 equal to the blob's hash (`E_BLOB_MISMATCH`). This sub-step needs no descriptor and no inputs. It runs last: after 7.6 when recomputing, otherwise directly after step 6. Content of blob arguments is checked the same way by whoever retrieves it.

   A receipt that passes 7.1-7.6 is at level `recomputed`; otherwise it stays `signed`. Step 7.7 does not change the level: passing it is reported separately, as `blob_checked`.

Signature-valid means the holder of key `computed_by` stated this value. Whether to trust that party is policy, outside this specification.

### 10.2 Error codes

The four failure classes a verifier distinguishes are: bad canonical form (parse, schema and canon codes), unknown or unusable key (key codes), bad signature, and value mismatch on recomputation (the remaining codes).

| Code | Step | Meaning |
|---|---|---|
| `E_PARSE_JSON` | 1 | Not strict JSON: invalid UTF-8, BOM, lone surrogate, NaN/Infinity, syntax error. |
| `E_PARSE_DUPLICATE_KEY` | 1 | A member name repeated in one object. |
| `E_PARSE_URI` | URI | Not `cell://<path>[?<query>]`, has a fragment, userinfo or a port, an empty query, or a parameter without `=`. |
| `E_SCHEMA` | 2, 7 | Missing or extra member, wrong JSON type, wrong `proto`, null; content supplied for a value that is not a blob (7.7). |
| `E_CANON_NAME` | 3 | Invalid DNS name, namespace, function name, code language or key reference. |
| `E_CANON_ARG_NAME` | 3 | Invalid or reserved argument name. |
| `E_CANON_ARG_DUPLICATE` | URI | An argument or `asof` repeated in a URI. |
| `E_CANON_ARG_ORDER` | URI | URI arguments not in ascending order, or `asof` not last. |
| `E_CANON_PERCENT` | URI | Non-canonical percent-encoding or non-UTF-8 bytes. |
| `E_CANON_TYPE` | 3 | Unknown type name, value of the wrong JSON type, or a non-date/instant/string valid-time declaration. |
| `E_CANON_NUMBER` | 3 | Number not in canonical decimal form. |
| `E_CANON_UNIT` | 3 | A number declaration without a unit, a unit on anything else, `returns` in the wrong form, a unit not in `units.md`, or a unit reference to no string argument; when resolving a unit, a value that is not a unit. |
| `E_CANON_DATE` | 3 | Date not `YYYY-MM-DD` or not a calendar day. |
| `E_CANON_INSTANT` | 3 | Instant not `YYYY-MM-DDTHH:MM:SS.ffffffZ`, not a real time, or a leap second. |
| `E_CANON_STRING` | 3 | Control, unassigned or surrogate code point, not NFC, or empty summary. |
| `E_CANON_BLOB` | 3 | Blob not `<sha256>:<length>:<media type>` as in 3.7. |
| `E_CANON_HEX` | 3 | Hash, key id or signature not lowercase hex of the right length. |
| `E_CANON_LICENCE` | 3 | Licence neither an SPDX identifier nor an `https://` URL. |
| `E_CANON_SET` | 3 | `inputs` not strictly ascending. |
| `E_CANON_LIMIT` | 3 | A limit from 4.5 exceeded. |
| `E_SLICE` | 4, unit | A slice marker in a receipt, or in an argument a unit refers to. |
| `E_PUBLISHER_MISMATCH` | 4 | `publisher` differs from `cell.ns`. |
| `E_VALID_MISMATCH` | 4, 7 | `valid` does not echo exactly the valid-time arguments. |
| `E_TIME_ORDER` | 4, 7 | `tx <= asof <= issued` fails, inputs have another `asof`, or computed `tx` is not the latest input `tx`. |
| `E_ARG_UNKNOWN` | URI, 7 | An argument the function does not declare. |
| `E_ARG_MISSING` | URI, 7, unit | A declared argument not bound (slices are written `*`). |
| `E_KEY_UNAVAILABLE` | 5 | The key document could not be retrieved: any non-200 status (404 included), redirect, or network, DNS-resolution, TLS or timeout failure. |
| `E_KEY_DOC` | 5 | The key document is malformed or breaks a rule of 9.2. |
| `E_KEY_UNKNOWN` | 5 | The host's key document has no key with that id. |
| `E_KEY_NOT_VALID` | 5 | `issued` is outside the key's validity window. |
| `E_SIGNATURE` | 6 | The Ed25519 signature does not verify. |
| `E_FN_UNAVAILABLE` | 7 | No descriptor found for `fn_hash`. |
| `E_FN_HASH_MISMATCH` | 7, unit | The descriptor does not hash to `fn_hash`. |
| `E_ARG_TYPE` | 7, unit | An argument's type differs from its declaration. |
| `E_RETURN_TYPE` | 7 | `type` differs from the declared return type. |
| `E_INPUT_UNAVAILABLE` | 7 | An input receipt cannot be found, or the one found has another hash. |
| `E_INPUT_INVALID` | 7 | An input receipt is not signature-valid. |
| `E_INPUT_UNDECLARED` | 7 | An input receipt is a cell of a function not in the descriptor's `inputs`. |
| `E_VALUE_MISMATCH` | 7 | Recomputation gives a different type or value. |
| `E_BLOB_MISMATCH` | 7 | Blob content has another length or hash than the blob states. |
| `E_ENVELOPE` | envelope | A response envelope breaks a rule of 5.5, its HTTP status does not match its outcome, or its receipt does not answer the request. |

"URI" marks codes raised while parsing a cell URI (5.4), "envelope" codes raised while checking a response envelope (5.5), and "unit" codes raised while resolving a unit (7.1). Canonicalising a scalar, cell, reference or descriptor on its own uses the same codes as steps 1-3.

## 11. Test vectors

`vectors/<group>/<name>.json`, one vector per file, described by `schemas/vector.schema.json`. Every vector has `id` (its path without `.json`), `kind`, `description` and `valid`. An invalid vector has `error`: the exact code the reference tool reports.

| Kind | Input | Outputs when valid |
|---|---|---|
| `jcs` | `input`: JSON text | `canonical`, `sha256` |
| `scalar`, `cell`, `ref`, `function` | `input`: JSON text (or `input_hex`: raw bytes) | `canonical`, `sha256` |
| `uri` | `input`: URI, `signature`: function signature | `object` (cell reference), `canonical`, `sha256`, `https` (on mesh `mesh.example`) |
| `keyid` | `input`: public key hex | `key_id` |
| `keys` | `host`, `env`: what the HTTPS request returned | `key_ids` |
| `receipt` | `input`: receipt JSON text; `keypair` (`seed`, `public`, `key_id`); `keys`: an `env` per host; optional `recompute`; optional `blob_hex`: content for step 7.7 | `canonical` (the signed payload), `sha256` (receipt hash), `sig`, `level` (`signed` or `recomputed`); `blob_checked` (true) when `blob_hex` is given |
| `unit` | `input`: JSON text of an object with exactly `cell` and `descriptor` (any other shape is `E_SCHEMA`) | `unit`: the resolved unit of the cell's value (7.1), or null when the function does not return a number |
| `envelope` | `input`: the response body; `status`: the HTTP status; `keys`: an `env` per host; `request`: `{"cell_id", "asof"?}` for step 5 | `outcome`, and when there is a receipt, `trust` and `receipt_hash` |

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
- **Blob content** is untrusted until step 7.7 passes. Check the length before downloading or hashing more than that many bytes. Do not let the media type override what a client would otherwise do with the bytes: it is the publisher's claim.
- **Envelopes are unsigned.** TLS authenticates the mesh, not what it says. `stale`, `superseded_by`, `verified` and every non-`ok` outcome are the mesh's claims, and a mesh can lie about them or omit them. A client that needs a newer value asks with a later `asof`, or asks another mesh.

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
| D23 | `returns` stays a bare type name except for `number`, which is `{"type": "number", "unit": …}`; argument declarations gain `unit` only for numbers | `returns` always an object | Always an object would change the hash of every descriptor, including those with no number, and of every receipt pinning them, for no gain. As it is, a descriptor with no number member is byte-identical to `spec-0.1.1`, and each meaning still has one spelling. |
| D24 | The unit is part of the signature, inherited by receipts through `fn_hash` | A `unit` member in each receipt | A unit is a property of the function, not of one answer. Putting it in the hash of the function makes it impossible for two receipts of one function to disagree, and leaves the receipt format unchanged. |
| D25 | A closed list of unit strings (`units.md`), compared byte for byte | UCUM, a grammar of unit expressions with its own canonical form | UCUM can express everything, but needs a parser and canonicaliser of its own, and gives `kWh` several spellings. A short list cannot disagree with itself; additions come with spec revisions. |
| D26 | Units may reference a string argument (`{"arg"}`), and rates are `{"of", "per"}` objects | Fixed units only, which means one function per currency pair; or rate strings like `USD/EUR` | A generic `fx_rate(base, quote)` or `convert(amount, base, quote)` has units that depend on its arguments. A reference keeps them one function each. A single object form for rates avoids a second spelling and any parsing. |
| D27 | Blob is a scalar `<sha256>:<length>:<media type>` | A blob object type; a URL; a multihash | It keeps "scalars only" and fits wherever a string fits: URIs, arguments, values. The content is addressed by hash, so any host can serve it. |
| D28 | Staleness, supersession and trust live in an unsigned response envelope | New receipt members | Receipts already signed stay byte-identical and verifiable. These facts change after signing and are the mesh's claims, not the signer's. |
| D29 | `trust: primary` is defined from the receipt (signer's host = namespace's host, no inputs), and a mesh must use it exactly then | Let the mesh choose its label freely | A client can check the one label that is checkable. |
| D30 | One code, `E_ENVELOPE`, for every envelope rule | A code per envelope rule | An envelope is not hashed or signed, so a client needs to know only that the mesh's statement is malformed. Receipt failures inside it keep their own codes. |
| D31 | A client binds an envelope's receipt to its request: the same cell id, and, when an `asof` was asked for, the same `asof` for `ok`, or one at or before it for `stale` | Trust the mesh to answer the question asked; or require an equal `asof` for `stale` too | Without the binding, a mesh can answer any request with any valid receipt. It needs nothing in the receipt or the envelope, only what the client already knows. A stale receipt is the last one known, so its `asof` is earlier by construction; the client learns how much earlier from `age_seconds`. |
| D32 | Malformed requests are `bad_request` (HTTP 400) carrying a URI parse code; `error` (5xx) is for the mesh's own failures | One `error` outcome for both | A client should not retry its own mistake, and should know which part of the URI to fix. |

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

blob          = 64HEXLOW ":" ( "0" / %x31-39 *DIGIT ) ":" media-type     ; length <= 2^53 - 1
media-type    = restricted-name "/" restricted-name                       ; <= 128 chars
restricted-name = ( lower / DIGIT ) *( lower / DIGIT / "!" / "#" / "$" / "&" / "-" / "^" / "_" / "." / "+" )

index-unit    = "index:" 4DIGIT [ "-" 2DIGIT [ "-" 2DIGIT ] ] "=" number   ; units.md 2.4, value > 0, <= 64 chars

```

## 14. Changes

### spec-0.2.0

Three additions, released together so that there is one migration.

- **Units (7.1, `units.md`).** Number arguments and number returns declare a unit: a listed literal, a reference to a string argument, or a rate `{"of", "per"}`. `returns` stays a bare type name for every other type (D23). New code `E_CANON_UNIT`.
- **Blobs (3.7).** A sixth type, `blob`: `<sha256>:<length>:<media type>`. Verification step 7.7 checks content when it is available. New codes `E_CANON_BLOB` and `E_BLOB_MISMATCH`.
- **Response envelope (5.5).** The JSON body a mesh returns: outcome (including `bad_request` for malformed requests), trust label, staleness, supersession, quotes, rate limits and errors, with HTTP status mappings. It is unsigned and outside the receipt. A client binds its receipt to the request: the same cell id, and when an `asof` was asked for, the same `asof` (`ok`) or one at or before it (`stale`) (D31). New code `E_ENVELOPE`, schema `schemas/envelope.schema.json`.
- **Open points from `spec-0.1.1` resolved.**
  - Userinfo and ports in a cell URI are `E_PARSE_URI` (5.1).
  - The outer grammar is checked before any name (5.4 step 1).
  - Step 7.5 now checks an input receipt's hash after verifying it, as the vector `invalid/receipt-input-invalid` always required.
  - The reference tool follows all three, and new vectors cover userinfo, ports and the check order.
- **Vectors.** New kinds `unit` and `envelope`, the receipt field `blob_hex` with the output `blob_checked`, and the envelope field `request`. 136 new vectors.

JCS, hashing, signing, keys and verification steps 1-6 are unchanged. The receipt format is unchanged: `proto` is still `datumesh/1`, and no member was added.

**What changed.** A descriptor with a number member now has a unit, so its bytes and function hash changed. Everything that embeds such a function hash changed with it: cell ids, receipt bytes, receipt hashes and signatures. A `spec-0.1.1` descriptor with a number member fails `E_CANON_UNIT` under this revision; no publisher had one. Changed hashes in the vectors (old, then new):

| Vector | Hash | spec-0.1.1 | spec-0.2.0 |
|---|---|---|---|
| `cell/fx-rate` | cell id | `9ebea149cfe52c62a8cd23287c2c25f8a704bc0c2fa59ab0c5c9dcd55313c6b3` | `f566f2838815a8649fe467b7a41876c5d2b4deca9afb974b8c50caafd4633ca5` |
| `cell/idn-a-label` | cell id | `618ae3e71a97a3ba5ccfe0d8aacc65545398f6d2086d15435df6eca912a31fd6` | `22ed67f6963758206ee4eef5f9765ecb0b2eb79164ff3eee537193fb781832ef` |
| `cell/max-arguments` | cell id | `d7b340cd7559a69839accef9bf8c0ce8e99e0f2606e4821ecdc6cb5fa2ee8f11` | `b0b646900957fc0d410446543ed76838bbb0eb8666a2a0d5aa54b94f17996533` |
| `cell/namespace-path` | cell id | `9b86987b0cddde785e0c563e0b35422de8049467c0780ae00e683efc1ee26e97` | `bd5c8fa308731672e7b946c825ebea3de33d762053c2466551478bb88ea5b7bf` |
| `cell/no-arguments` | cell id | `dcc38effea66f3e4f87d07280f7ded1bde1051f9dd416b013234d9a90f66a567` | `55f39026b5d68516244758d43a1ff8bee208dd23615ec9b5a1fe43c0c800493d` |
| `cell/slice` | cell id | `f22dfb6463b44a3d109178081f71c926a9e7e1d6b92613f395a9585d24d3fac8` | `6046e961e3573d42422565754037c2b4d1c4bfe744f3a3a323d69b62c71c10f8` |
| `function/computed-convert` | function hash | `794a960b7fa32ae7763a2308766864b52fa27920f48fb328b5c3413300eaf876` | `014fc97eb3a442ab28a96d89131ccfd11c9eec8187595578c212b392d0702c71` |
| `function/no-arguments` | function hash | `4184dc316637adb1837b3224ef0043f8766786321e2048b7f0a653a684483159` | `6548c6e298e8f66b98295303aaac8fcf45bed6fff3bdedcbda2ce8d49d6dedbb` |
| `function/stored-fx-rate` | function hash | `88445cddbf86a358e1318934bfc8160728a9a0ff2b05b50be6c0fee2eb3e5af4` | `7b58ecb8fd23b644c87951d0bd609790ff547cbb23fed27186c669ce2ce0aa80` |
| `receipt/computed-two-inputs` | receipt hash | `0dc78d69228376bcf5d33400af6830e60c1ab14d3b032c90e4ac5e3f5b19ac7e` | `8c2ae5c04d287b9571d2c05a8f51c5bb79a59d19c2dfcbd552f6e0528d6fb5b8` |
| `receipt/computed-with-lineage` | receipt hash | `46cce62c62419ba5486cc592d47affa453901e003e61327bedeec8dfd69bc859` | `9f4d8814808d783e83b0424f90439fbbedc5f73457828d0ed346b0f424a85527` |
| `receipt/date-value` | receipt hash | `9d195c19f362edcd1950e61711823df881ece975230da905b60825283d3ae3d4` | `d2566102ab6fec1b2acc11cb524e1d3de71f8ded3135837d00f503418c51b00f` |
| `receipt/historical-asof` | receipt hash | `b5540615da5ae5a1ffecb166526ebe4f6814199991658a3e78ef50bf16c9e44a` | `b3364bca98cb936f81f12d84b9134216abb3270538390f662c3b7d35ad2f23d1` |
| `receipt/rotated-key` | receipt hash | `d2d01a26527bb85b9c6587037ba26b56751e30fb5edab48f74771f3190dba013` | `e7347ac3732d56286d45aa99af3f6d7346a6bb18540fbe2396bf6c865e3ddd74` |
| `receipt/stored-number-second` | receipt hash | `8dd337dbddb7194551dc094b89f81e1c82ffd853273a4a4ce19cc86ee08bedd1` | `9b34fa55582d96c85949bc64673dd89aa9c19b5c104362bbb3cd37e61ec699ac` |
| `receipt/stored-number` | receipt hash | `501f744d910c585859a5be4f3b62385ed0d6803db53dbbf95dff5097a68bee0d` | `19a5fe3a744c5792f747fb4c286ce396ab44b95922de4f07937502fe595b6f81` |
| `receipt/string-value` | receipt hash | `5fa7375ae6db221588824f66fda176e28dbfaf5fa1230401c8d51b88e639be56` | `50cd62b0b12aab79f6ab14648f661bfa03231d61f50d1f0a178092306a55cd85` |

Every invalid vector built from these descriptors, cells and receipts changed its bytes, with the same expected error. URI vectors changed only their `signature` input, which gained units; their outputs are unchanged. Each changed vector says so in its description.

**What did not change.**

- Descriptors with no number member: `is_holiday` (`ed1f0ecb7166dd6d70ae263456e3af94147d4781f43035e534b9368e9561f84a`) and `last_trade` (`c9e0d9f0d0cb8b5be729b6e30a4e89fbfa2ff2e6b55f18632751b2f0f7acb923`).
- Their receipts: `receipt/boolean-namespace-path` (`0c3feb4c797f580d279287dbe11a41eed45cfd00c72c3e983dbd5e7ab69cacbf`) and `receipt/instant-no-valid-time` (`935b74a360c9b37f35094192834b86dc1b2bf74f33b43f30bd84c581545dd57e`), byte for byte, signatures included.
- All 26 scalar, 5 JCS, 10 URI and 1 reference hashes, every key id and every key document.

### spec-0.1.1

- **Removed DNS TXT key publication.** Section 9.3 used to define `_datumesh.<host>` TXT records with a precedence rule. The HTTPS document is now the only key source; any retrieval failure, including 404, is `E_KEY_UNAVAILABLE` (9.3). `E_KEY_UNKNOWN` now means only that the document lacks the key id. The vectors for DNS were removed and the `env` format lost its `dns` member.
- **Added 9.4:** retrieving keys is separate from verifying.
- **Open question for the engine:** the limit of 4096 `inputs` per receipt (4.5) stands for now. A computed cell over a long slice may need more inputs than that, or an intermediate aggregation cell; the engine step decides.

The receipt format, canonical encoding and all hashes are unchanged: every receipt valid under `spec-0.1` that names a key published over HTTPS is valid under `spec-0.1.1`, with the same hash.

