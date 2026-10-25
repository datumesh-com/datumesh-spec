# Datumesh protocol, version 1

Status: draft, revision `spec-0.4.0`. Identifier in data: `datumesh/1`. Changes are listed in section 14.

Datumesh is an open protocol for addressable, verifiable data cells: a name, a resolver, a signed answer, and a lineage you can follow. This document defines how a cell is named (the cell URI), how it is written as canonical bytes, what a signed answer (a receipt) contains, what a mesh returns around it (the response envelope), how keys are published, and how a verifier checks a receipt, including receipts whose lineage cites whole slices of cells. Section 15 defines the formula dialect, the default language of computed functions. The units a function may declare are listed in `units.md`, which is part of this specification. Storage formats, wire protocols, resolvers and the engine are out of scope.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174.

Everything hashed or signed under these rules is hashed or signed forever. The rules are therefore strict: **where an input could be read two ways, it is rejected, not normalised.** A verifier never guesses.

The executable form of this document is `tools/canon.py`, with `tools/formula.py` and `tools/fdecimal.py` for section 15; the vectors under `vectors/` are normative examples. If the prose and the vectors disagree, that is a bug in this document to be reported, not a choice for implementers.

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
15. The formula dialect
- Appendix A: collected ABNF

## 1. Terms

- **Namespace**: a DNS name the publisher controls, optionally followed by path segments: `rates.example.org`, `example.org/central_bank/stats`.
- **Function**: a name within a namespace, together with a descriptor (section 7) that fixes its signature and code. Its fully qualified name is `<namespace>/<function>`, Go-module style, e.g. `ecb.europa.eu/fx_rate`.
- **Function hash**: SHA-256 of the canonical descriptor. A name resolves to a current function hash; cells and receipts pin the hash.
- **Cell**: a function applied to a complete tuple of typed scalar arguments. A cell has at most one value at any transaction time.
- **Slice**: a function applied to a tuple in which one or more arguments are left open, or bounded by a range. A slice denotes a set of cells. It can be named and canonicalised but never has a receipt. A computed receipt can cite a slice it read as one input entry (15.13).
- **Slice entry**: the `inputs` entry `slice:<slice id>:<members hash>` for a slice read (8.1, 15.13). Its **manifest** lists the members' receipt hashes.
- **Valid time**: the time a value is about (a rate *for* 15 March). It is carried by ordinary arguments that the function declares as valid-time arguments.
- **Transaction time**: the time the system knew a value. Every call has an `asof` transaction time (default: now). Every receipt carries `asof` (as of when it answers), `tx` (when the value it gives was recorded) and `issued` (when it was signed).
- **Receipt**: a signed statement of one cell's value as of one transaction time, with its lineage.
- **Mesh**: any HTTPS host that resolves cells and serves receipts.
- **Unit**: what a number means, such as `EUR` or `degC`. A function declares the unit of every number argument and number return (7.1). Values and receipts never carry units.
- **Blob**: a scalar whose value names content by its hash, byte length and media type (3.7). The content itself travels out of band.
- **Envelope**: the JSON body a mesh returns around a receipt (5.5). It is the mesh's statement, unsigned; the receipt inside is the signer's.
- **Formula**: the default language of computed functions, `code.lang = "formula"` (section 15).
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

A typed scalar's `value` must be a JSON string or boolean (`E_SCHEMA` otherwise: a JSON number, null, array or object). A string for a `boolean`, or a boolean for any other type, is `E_CANON_TYPE`, e.g. the string `"true"` for a boolean. A type name outside the six also fails with `E_CANON_TYPE`.

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
- Any failure, an impossible calendar date included, is `E_CANON_INSTANT`.

*Rationale.* Microseconds are the precision of PostgreSQL `timestamptz`, Python `datetime` and most databases a publisher will record `tx` in, so a stored transaction time maps to an instant exactly, with no rounding. Milliseconds would round those values. Nanoseconds would claim a precision few systems have and would overflow 64-bit integer timestamps in year 2262. Fixed width means instants compare correctly as strings, which the verification procedure relies on. Leap seconds are rejected because POSIX time cannot represent them, systems that smear them disagree about what `23:59:60` is, and UTC will stop inserting them by 2035.

### 3.4 Time zones

When a function needs a time zone, it declares an ordinary `string` argument and takes an IANA time zone name (`"Europe/Amsterdam"`). Offsets and local times never appear in hashed data. Datumesh does not validate zone names, because the IANA database changes.

### 3.5 Strings

A string value is checked in this order:

1. **Characters.** Every code point is assigned in Unicode 15.1 (General_Category is not `Cn`). It is not a surrogate. It is not a control character (U+0000-U+001F, U+007F-U+009F). Failure: `E_CANON_STRING`.
2. **Normalisation.** The string is in Normalization Form C, decided with Unicode 15.1 normalisation data or later. A non-NFC string is rejected, not normalised. Failure: `E_CANON_STRING`. An implementation whose platform has older normalisation data must bring its own, because older data can accept strings that are not NFC under 15.1.
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
- The 128-character limit applies to the media type as a whole, not to each name: either name may be up to 126 characters, so `a/` followed by 126 characters is accepted and `a/` followed by 127 is not. RFC 6838 limits each name to 127 characters; a media type within 128 always satisfies that, so no separate per-name limit applies.

Only the blob string is hashed and signed. The content is retrieved out of band, by its hash; how is outside this revision. Content that does not hash to `sha256`, or does not have exactly `length` bytes, is not the blob's content (`E_BLOB_MISMATCH`, 10.1 step 7.7). A blob has no unit and cannot be a valid-time argument (section 7). The string type and its 1024-byte limit are unchanged: text longer than that is published as a blob.

*Rationale.* A blob is a scalar whose value is a content hash, so the type system stays "scalars only" and a receipt stays small whatever the content's size. The length lets a client refuse or bound a download before hashing it. The media type tells a client how to read the content. It is not checked against the content, because no verifier can do that reliably.

## 4. JSON forms

### 4.1 Typed scalar

```json
{"type": "number", "value": "1.0892"}
```

A JSON object with exactly the members `type` and `value`. `value` is a JSON string, except for booleans, where it is `true` or `false`.

### 4.2 Argument map

A JSON object from argument names to typed scalars. A typed scalar may be replaced by the **slice marker**, the JSON string `"*"`, meaning the argument is open. In a slice object only (4.4), it may also be replaced by a **range object** `{"hi": <lexical>, "lo": <lexical>, "type": <date, instant, number or string>}`: the argument bounded, both ends inclusive. The order of members is irrelevant on input, and JCS fixes it for hashing. Duplicate names are duplicate JSON members (`E_PARSE_DUPLICATE_KEY`).

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

A **slice object** is a cell object with at least one argument written as the slice marker or as a range object (`E_SLICE` otherwise), or a **version slice** `{"cell": <cell without markers>, "from": <instant>, "to": <instant>}`: the cell's versions with `tx` in `[from, to]`. Its **slice id** is SHA-256 of its canonical bytes; for an unbounded slice it is the cell id above. Slice objects appear in manifests (15.13), never in a receipt's `cell`; they have no cell URI in this revision.

**Which shape.** An object whose members are exactly `cell`, `from` and `to` is a version slice; any other slice object is read as a cell object (so `{"cell", "from"}` is `E_SCHEMA`, for its missing `args`). In a slice object's arguments, `"*"` is the slice marker, an object whose members are exactly `hi`, `lo` and `type` is a range object, and any other value is read as a typed scalar (so `{"type", "value", "lo"}` and `{"hi", "lo", "step", "type"}` are `E_SCHEMA`). Every member of a range object is a string (`E_SCHEMA`).

**Check order.** Structure first, over the whole object (`E_SCHEMA`), then canonical form:
- *A cell-shaped slice object* is checked like a cell (4.4, 4.5): the argument count, then each argument in JCS order of names (its name, then its value), then `fn`, `fn_hash`, `ns` and the 512-character function name. Within a range object, `type` comes first (a type name, and one of `date`, `instant`, `number`, `string`: booleans and blobs have no ranges, `E_CANON_TYPE`), then `hi`, then `lo`, each in that type's lexical form. Last, a slice object with no open or ranged argument is `E_SLICE`.
- *A version slice*: its `cell` is checked whole, as a cell (its own name limit included), then for slice markers (`E_SLICE`), then `from` and `to` (`E_CANON_INSTANT`).

**Empty is not an error.** A range with `lo` after `hi` is empty, and so is a version slice with `from` after `to`. Neither end has to be a value any cell holds.

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
| `extent` | 4096 | values in an argument's extent (7) |
| `members` | 1048576 | member receipt hashes in a slice manifest (15.13) |

Exceeding a limit fails with `E_CANON_LIMIT`, except `keys`: a key document with more than 64 keys is rejected whole, with `E_KEY_DOC` (9.2). DNS's own limits (63-character labels, 253-character names) are part of the DNS grammar and fail with `E_CANON_NAME`.

Order of checks:
- **Values and names.** A value or name is checked against its lexical form first and its length limit second. An argument name is then checked for reserved names.
- **Containers.** For an argument map, the count is checked before its members, and members are checked in JCS order of names. For an `inputs` array, its entries are checked first, then that they are strictly ascending (`E_CANON_SET`), then the count (`E_CANON_LIMIT`).
- **Function names.** The 512-character `function_name` limit applies to `ns + "/" + fn` also when they are carried separately. It is checked after both parts are valid; in cells and references, after all their own members.

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

`namespace`, `name` and `instant` are as in sections 2 and 3. The outer grammar is `"cell://" path [ "?" query ]`. The path is split at its last `/` into namespace and function, and both are checked as names: no `/`, an empty segment or an empty function name is `E_CANON_NAME`. A parameter is split at its first `=`: a value runs to the next `&` and may contain `=`, which then fails percent-encoding (`a=b=c` is `E_CANON_PERCENT`). A cell URI has no fragment, no userinfo, no port and no empty query. The authority is the text between `cell://` and the first `/` (or `?`, or the end); an `@` or `:` in it is `E_PARSE_URI`, so `cell://user@rates.example.org/…` and `cell://rates.example.org:443/…` are rejected, not corrected. Failures of this outer grammar are `E_PARSE_URI`. Invalid names inside it are `E_CANON_NAME`.

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

`<rest>` is copied byte for byte, query included. The mapping is reversible by stripping the prefix. `<mesh>` is a DNS name (2.1), served on the default HTTPS port: no port, no IP address, no userinfo.

### 5.4 URI to reference and back

`parse(uri, signature)` checks, in order:

1. the outer grammar, entirely before any name: the URI starts with `cell://`, contains no `#`, has no userinfo or port, and, if it contains `?`, the text after it is non-empty and each `&`-separated parameter contains `=` (`E_PARSE_URI`);
2. the namespace and function names;
3. parameter names. If the last parameter is named `asof`, it is the asof parameter. Each other parameter, left to right, is checked completely before the next:
   1. if its name is `asof`: `E_CANON_ARG_DUPLICATE` when there is an asof parameter, otherwise `E_CANON_ARG_ORDER`;
   2. its name (`E_CANON_ARG_NAME`, or `E_CANON_LIMIT` when longer than 64), then reserved names (`dm_…`: `E_CANON_ARG_NAME`);
   3. equal to the previous parameter's name: `E_CANON_ARG_DUPLICATE`;
   4. sorting before it: `E_CANON_ARG_ORDER`.

   So a repetition that is not adjacent is reported as an ordering error;
4. the argument count;
5. the signature, then the arguments against it. The signature must be an object with an `args` object whose members are objects with a string `type`; otherwise `E_SCHEMA`, checked in JCS order of names. Then unknown arguments (`E_ARG_UNKNOWN`), then missing ones (`E_ARG_MISSING`);
6. each value left to right (percent-encoding, then its lexical form). A type name outside the six is `E_CANON_TYPE` when a value of that argument is read; a slice reads none;
7. `asof`, percent-decoded like a value (`E_CANON_PERCENT`; a bare `*` is not a slice there and fails percent-encoding), then checked as an instant (`E_CANON_INSTANT`).

The first failure is reported. `signature` is taken as given: it comes from a descriptor already checked under section 7, and `parse` does not check it again beyond what step 5 needs to read it. The result is a cell reference (4.3) whose typed scalars carry the declared types. `format(reference)` writes the unique URI. For every accepted URI, `format(parse(uri)) = uri`.

### 5.5 Response envelope

A mesh answers `GET https://<mesh>/cell/<rest>` (5.3) with an HTTP status and a JSON body, the **envelope**, served as `application/json`.

**An envelope is the mesh's statement and a receipt is the signer's. Only the receipt is verifiable.** The envelope is not hashed and not signed, and nothing in it changes what a receipt means. Everything a mesh says about a receipt (that it is stale, superseded or recomputed) is therefore said here, outside it, and receipts never change to carry such news. A client parses the envelope with the strict rules of 6.1.

The envelope is an object whose `outcome` decides which other members it has. A member not listed for the outcome is not allowed.

| `outcome` | HTTP status | Required members | Optional members | Meaning |
|---|---|---|---|---|
| `ok` | 200 | `receipt`, `trust` | `superseded_by`, `reason` | The receipt is for the requested cell, its `asof` is at or before the requested `asof`, and the mesh asserts that it is the cell's latest version known as of the requested `asof`. |
| `stale` | 200 | `receipt`, `trust`, `age_seconds` | `superseded_by`, `reason` | As `ok`, except that the mesh cannot assert that the receipt is current: it could not get a current answer and serves the last receipt it knows. |
| `not_covered` | 404 | none | `fault` | The mesh has no receipt for this cell: it does not serve the function, or the cell has no value. With `fault`, the cell is a computed cell whose evaluation faulted (15.12): it has no value, deterministically, and this is not missing data. |
| `unlicensed` | 403 | none | none | The requester may not receive this cell. |
| `payment_required` | 402 | `quote` | none | The cell is available for the quoted price. |
| `rate_limited` | 429 | `retry_after_seconds` | none | Too many requests. The mesh SHOULD also send the `Retry-After` header with the same value. |
| `bad_request` | 400 | `error` | none | The request is malformed: the cell URI does not parse. |
| `error` | 500-599 | `error` | none | The mesh failed to produce an answer. |

Members:

- `outcome`: one of the eight strings above.
- `receipt`: a receipt object (section 8), embedded as JSON. For `ok`, it is the cell's latest version as of the requested `asof`, which may have been signed at an earlier `asof`. For `stale`, it is the last receipt the mesh knows for the cell.
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
- `fault`: one of the formula evaluation faults `E_FORMULA_DIV_ZERO`, `E_FORMULA_DOMAIN`, `E_FORMULA_RANGE`, `E_FORMULA_EMPTY`, `E_FORMULA_ABSENT`, `E_FORMULA_FUTURE` (15.11). Running out of fuel, a cycle and too deep an evaluation are not faults: they are the mesh's failures, an `error` with `E_EVAL_UNAVAILABLE`.
- `error`: what failed. For `bad_request`, one of the codes `parse` can raise (5.4): `E_PARSE_URI`, `E_CANON_NAME`, `E_CANON_ARG_NAME`, `E_CANON_ARG_DUPLICATE`, `E_CANON_ARG_ORDER`, `E_CANON_PERCENT`, `E_CANON_TYPE`, `E_CANON_NUMBER`, `E_CANON_DATE`, `E_CANON_INSTANT`, `E_CANON_STRING`, `E_CANON_BLOB`, `E_CANON_LIMIT`, `E_ARG_UNKNOWN`, `E_ARG_MISSING`. For `error`, any code in 10.2 except `E_ENVELOPE` (a client's code), for example `E_INPUT_UNAVAILABLE`, or `E_EVAL_UNAVAILABLE` when the mesh could not evaluate the cell's function.

**Integer members.** `age_seconds` and `retry_after_seconds` are JSON numbers written `0` or `[1-9][0-9]*`: no fraction, no exponent, no sign, and at most 2^53 - 1. So `30.0`, `3e1` and `-0` are `E_ENVELOPE`. They are the only JSON numbers in this specification, which is possible because envelopes are never hashed.

A client checks an envelope in this order and reports the first failure:

1. Parse the body as strict JSON (6.1).
2. Check the members against the table and the rules above (`E_ENVELOPE`). Here `receipt` need only be an object. Every failure of a member's rule is `E_ENVELOPE`, including the rules `reason`, `quote` and `superseded_by` borrow from other sections.
3. Check that the HTTP status matches `outcome` (`E_ENVELOPE`).
4. If there is a receipt, verify it through step 6 of 10.1, with that procedure's codes.
5. **The receipt answers the request** (`E_ENVELOPE`). Its cell id (4.4) MUST equal the id of the cell requested. That is, the cell the request's URI denotes, resolved to the `fn_hash` the client used. If the request carried `asof`, the receipt's `asof` MUST be at or before it, for `ok` and `stale` alike. If the request carried no `asof`, it asked for the mesh's "now", and the client accepts any receipt `asof`.
6. Check `trust` against the receipt, as above, and that `superseded_by` differs from the receipt's hash (`E_ENVELOPE`).

A receipt states a cell's value as of its own `asof`, and that value stands until the cell's next version. So one receipt answers every `asof` from its own up to the next version's, and a mesh serves it as `ok` for all of them without anything being re-signed. The two outcomes that carry a receipt differ only in what the mesh asserts about it:

- `ok`: the receipt is the cell's latest version known as of the requested `asof` (as of now, when none was requested);
- `stale`: the mesh cannot assert that. It serves the last receipt it knows, and `age_seconds` says how long ago it last confirmed it as current.

On the wire, the two are always told apart: by `outcome`, and by `age_seconds`, which `stale` requires and `ok` forbids.

A receipt of an **asof-dependent** function (one whose body reads `asof()`, 15.12) states a value as of its own `asof` only: its value may change with the asof alone. A mesh MUST NOT serve such a receipt as `ok` for a requested `asof` other than its own; it evaluates again, or answers `stale`. A client cannot check this without the descriptor, so step 5 is unchanged. A client checks the same binding for both (step 5): the cell, and an `asof` at or before the one requested. It cannot check either assertion. Whether an `ok` receipt is in fact the latest version, and how old a `stale` one is, are the mesh's claims (12); a client that doubts them asks another mesh.

Step 5 needs the request, which the envelope does not contain. A client MUST perform it; a library takes the requested cell id and `asof` as inputs. A malformed request description, meaning a `cell_id` that is not 64 lowercase hex digits or an `asof` that is not an instant, is the caller's error. It is not an `E_*` code: libraries report it the way their language reports a misused function. For outcomes without a receipt there is nothing to bind. Without it, a mesh could answer with a valid receipt for a different cell.

An envelope that passes says only that this mesh made a well-formed statement, about the requested cell, citing a receipt that its signer signed.

## 6. Canonical encoding and hashing

### 6.1 Parsing JSON

Any JSON that is hashed, signed or verified is parsed strictly, as I-JSON (RFC 7493):

- the text is UTF-8 with no byte order mark;
- no member name appears twice in one object (`E_PARSE_DUPLICATE_KEY`). Names are compared after unescaping, so `"a"` and `"a"` are duplicates;
- no string contains a lone surrogate, whether written raw or escaped;
- `NaN`, `Infinity` and numbers outside the IEEE 754 double range are rejected.

- nesting is at most 64 levels: a text with more than 64 `[` and `{` open at once, counted outside strings, is `E_PARSE_JSON`. An implementation that also accepts already-parsed values applies the same limit to them: at most 64 nested arrays and objects.

All other failures are `E_PARSE_JSON`. Failures are reported in this order:
1. byte order mark;
2. invalid UTF-8;
3. nesting deeper than 64, whatever else is wrong with the text;
4. the first, in text order, of a syntax error, `NaN` or `Infinity`, a number that overflows a double, or a duplicate member. A duplicate is detected when its object closes. Underflow is not an error;
5. a lone surrogate.

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
- `signature.order` (optional, since `spec-0.4.0`) is an array listing every argument name exactly once: the order in which positional arguments of a formula read bind (15.5), and in 1.3b the order of a class's key tuple. A list that misses an argument, repeats one or holds any string that is not a declared argument (whatever its form: `"Date"` and `""` too) is `E_CANON_SET`; anything but an array of strings is `E_SCHEMA`. A function with no arguments may have `"order": []`. Formula descriptors always carry it (`E_FORMULA_ORDER`); that, and the other formula rules of 15.6 (`E_FORMULA_NOT_CANONICAL`, `E_FORMULA_INPUTS`), are checked by `define` and by formula evaluators, not by a verifier (10.1 step 7.1).
- An argument declaration may have `extent` (optional, since `spec-0.4.0`): the cells a slice over a computed function enumerates (15.13). It is an array of lexical values of the argument's type, checked value by value in its lexical form (that type's code), then strictly ascending in the type's order (numbers numerically, dates and instants chronologically, strings by code point, not by UTF-16 code unit; `E_CANON_SET`), then at most 4096 (`E_CANON_LIMIT`); it may be empty. Or, for `date` and `number` arguments, a range `{"hi", "lo"}`: `hi`, then `lo`, each in the type's lexical form (for a number, 3.1's form and then its 128-character limit) and, for a number, an integer (`E_CANON_NUMBER`); then `lo <= hi` (`E_CANON_SET`). Any extent of a boolean or blob, and a range on a string or instant argument, is `E_CANON_TYPE`, before its values; any other shape is `E_SCHEMA`.
- **Both are optional, and absent they change nothing**: a descriptor without them is byte-identical to its `spec-0.3.0` form, with the same hash. A verifier library of `spec-0.3.0` rejects a descriptor that has either (`E_SCHEMA`); verifiers of `spec-0.4.0` MUST accept them.
- Units are required on numbers and allowed nowhere else. Each of these fails with `E_CANON_UNIT`: a `number` argument without `unit`; `unit` on any other argument; `returns` written as the bare name `"number"`; a `returns` object whose type is not `number`, or that has no `unit`; and a unit that is not valid by 7.1. A declaration or `returns` object with a missing `type` or any other member is `E_SCHEMA`.
- **Check order.** A descriptor's structure (`E_SCHEMA`), unit, `order` and `extent` shapes included, is checked over the whole descriptor before any canonical-form rule. Then `code`, `inputs`, each argument in JCS order of names, `order`, and `returns`. Within an argument declaration: `type` (`E_CANON_TYPE`), then `unit`, then `valid`, then `extent` (its values in order, then their order, then their count). For `returns`: the type name (`E_CANON_TYPE`), then that an object's type is `number` and that a bare name is not `number`, then the presence of `unit`, then the unit itself (all `E_CANON_UNIT`).
- `code.lang` is a name identifying the language of `code.body`. `stored` means the function is a table of recorded values; by convention its body is empty and it declares no inputs. This convention is not enforced. `formula` is defined in section 15: its body is the printed canonical AST and its `inputs` are derived from it. Other languages are defined by later steps; until then, a body is an opaque text that the evaluator for `lang` interprets.
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
| `inputs` | array of input entries | What was read to compute `value`: a receipt hash for each input cell, and since `spec-0.4.0` a slice entry `slice:<slice id>:<members hash>` for each slice (15.13); ascending, no duplicates. Empty for stored cells. |
| `licence` | string | An SPDX licence identifier (`CC-BY-4.0`) or an `https://` URL, by the grammar below. |
| `summary` | string | One human sentence saying what the value is. Non-empty. String rules apply. |
| `sig` | 128 lowercase hex digits | Ed25519 signature (8.3). |

The licence grammar:

```
licence   = spdx-id / https-url
spdx-id   = ( ALPHA / DIGIT ) *( ALPHA / DIGIT / "." / "+" / "-" )   ; at most 64 characters
https-url = "https://" 1*%x21-7E                                   ; at most 512 characters
```

A string starting `https://` is a URL, anything else an SPDX identifier. The identifier is not checked against the SPDX list, and the URL is not checked further. Grammar is checked first (`E_CANON_LICENCE`), then length (`E_CANON_LIMIT`).

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
- For a computed cell, every input receipt (slice members included) has an `asof` at or before the receipt's `asof` (`E_TIME_ORDER`), and, when there is at least one input receipt, `tx` is the latest `tx` among them, i.e. the moment the computed value became knowable. A receipt whose only inputs are empty slices, or that read nothing, has no input receipt and no `tx` constraint. Input receipts need not share an `asof`: a stored receipt is signed by its publisher at its own `asof`, and nobody else can re-sign it, so inputs published at different times keep different `asof`s.
- By signing, `computed_by` asserts that each input receipt was the latest version of its cell as of the receipt's `asof`, except an input read at an explicit transaction time `T` (`asof(c, T)`, 15.13), which it asserts answered as of `T`; and that each slice entry's members were exactly the slice's members as of the receipt's `asof`. That a stored slice is complete is the signer's statement, like currency: a verifier checks that every listed member belongs to the slice, not that none is missing. Recomputation (10.1 step 7) checks that the value follows deterministically from exactly those inputs, which `inputs` pins by hash. It does not check that they were current: that is the signer's statement, like the value itself.
- **Choosing `asof`** (D33). Two rules, one for each kind of issuer:
  1. A publisher of a stored receipt SHOULD set `asof = tx`.
  2. An issuer of a computed receipt SHOULD set `asof` to the latest of: the `asof`s of its input receipts, slice members included; the start of every name binding it relied on (the function names read, transitively, its own name included when it reads itself; the requested cell's own name excluded, since its receipt pins the hash); every `T` of an `asof(c, T)` read and every `to` of a `versions` read. Where an input was kept across a change of its own inputs (early cutoff), its `asof` counts from where its value is known again. For an asof-dependent function (15.12) it SHOULD instead be the evaluation asof. When every input follows rule 1 and no binding or explicit time is later, this equals the latest input `tx`, so `asof = tx`. A function that reads nothing and is not asof-dependent has `tx = asof = 0001-01-01T00:00:00.000000Z`.

  Rule 2 always satisfies the rule on input `asof`s above, and it is determined by the inputs alone, so each version of a computed cell has exactly one canonical receipt: immutable, cacheable, and served as `ok` for every later requested `asof` until the next version (5.5). That holds even when an input's `asof` is later than its `tx`, as in `receipt/stored-number`. Both rules are SHOULD only: verification does not check them.
- `issued` exists because `asof` can be in the past. A receipt answering "as of 2020", signed today, must be checked against the key valid today, not the key valid in 2020.

### 8.3 Receipt hash and signature

Let `payload` be the canonical bytes (6.2) of the receipt with the `sig` member removed. Then:

- the **receipt hash** is `SHA-256(payload)`, in lowercase hex;
- `sig` is the 64-byte Ed25519 signature (RFC 8032, pure Ed25519, no context, no prehash) of `payload`, in lowercase hex, made with the private key named by `computed_by`.

The signed bytes are exactly the hashed bytes. A receipt hash therefore identifies the signed content, and the signature is not part of the hash, so a receipt can be re-signed with a rotated key without changing its hash.

### 8.4 Lineage

`inputs` lists receipt hashes and slice entries. Each input receipt must be a cell of a function named in the descriptor's `inputs` (`E_INPUT_UNDECLARED`); so must each slice's function, and each member of a slice must belong to it (`E_SLICE_MEMBER`). Following `inputs` recursively, through manifests, gives the full lineage of a value down to stored cells. A slice entry is one entry for the 4,096 limit whatever its member count.

## 9. Keys

### 9.1 Key id

A key is an Ed25519 public key: 32 bytes, written as 64 lowercase hex digits. Its **key id** is the first 16 hex digits of SHA-256 over the 32 raw bytes. A key reference is `<host>#<key id>`, e.g. `rates.example.org#d712b32a2cc5cb7c`. The host is a DNS name (2.1), and keys for every namespace under a host are published by that host. A reference without `#`, or with an invalid host, is `E_CANON_NAME`; the text after the first `#` must be 16 lowercase hex digits (`E_CANON_HEX`).

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

- The document has exactly `host`, `keys` and `proto` (`"datumesh/1"`). Each key has exactly `alg` (`"ed25519"`), `id`, `public`, `valid_from` and optionally `valid_to`, all strings.
- `host` equals the host it was fetched from.
- `keys` holds 1 to 64 entries. `id` MUST equal the key id of `public`, and no two keys share an `id` (and so no two share a `public`). A `public` that is not a valid curve point is not a document error: signatures made with it fail in step 6.
- `valid_to` is optional (absent: open-ended). When present it is later than `valid_from`.
- No redirects are followed.

A document that breaks any of these rules is rejected whole (`E_KEY_DOC`).

### 9.3 Resolution

The HTTPS document of 9.2 is the only way keys are published. A verifier resolves the keys of a host with one `GET https://<host>/.well-known/datumesh.json`:

- **200** with a document satisfying 9.2: those are the host's keys.
- **200** with a document that does not satisfy 9.2, or with no document: `E_KEY_DOC`.
- **Anything else** is `E_KEY_UNAVAILABLE`. That includes 404 and every other status, any redirect, and any network, DNS-resolution, TLS or timeout failure. There is no fallback.

The status is the integer HTTP status code of the response. A library that takes a response as input instead of fetching it (9.4) treats any status other than the integer 200 as "anything else": a non-integer status, such as the string `"200"`, or no status at all, is `E_KEY_UNAVAILABLE`.

A host that serves no document publishes no keys, and its receipts cannot be verified.

Keys are resolved only for hosts that are DNS names (2.1). A client does not fetch for any other host; it has no keys (`E_KEY_UNAVAILABLE`). A response offered for such a host cannot satisfy 9.2, whose `host` must be a DNS name, so interpreting it gives `E_KEY_DOC`.

A client SHOULD bound retrieval, for example to 10 seconds and 256 KiB. A retrieval it abandons is `E_KEY_UNAVAILABLE`, like any other failure.

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
3. **Canonical form.** Check every member against its lexical rules: names, hex, instants, typed scalars (blobs included), licence, the summary, `inputs` ascending and unique, and limits. Each `inputs` entry is 64 lowercase hex digits or a slice entry: `slice:`, 64 lowercase hex digits, `:`, 64 lowercase hex digits (135 characters); anything else is `E_CANON_HEX`. `value` is checked against `type`.
4. **Consistency.** These checks run in the order listed, not in JCS order:
   - No slice markers in `cell.args` or `valid` (`E_SLICE`).
   - `publisher` equals `cell.ns` (`E_PUBLISHER_MISMATCH`).
   - Every member of `valid` equals the same-named member of `cell.args` and is a date, instant or string (`E_VALID_MISMATCH`).
   - `tx <= asof <= issued` (`E_TIME_ORDER`).
5. **Key.** Resolve the keys of the host in `computed_by` (9.3) and find the key with the given id (`E_KEY_UNKNOWN`). Check that `issued` is in its window (`E_KEY_NOT_VALID`).
6. **Signature.** Verify `sig` over `payload` (8.3) with that key (`E_SIGNATURE`). Let `R` be the first 32 bytes of `sig`, `S` the last 32 as a little-endian integer, `A` the public key, and `k` = SHA-512(`R` ‖ `A` ‖ `payload`) as a little-endian integer, reduced mod `L`. Reject if:
   - `S >= L`, the group order;
   - the encoding of `A` or of `R` is not canonical: its `y` is at or above p = 2^255 − 19, or `x = 0` with the sign bit set;
   - `A` or `R` does not decode to a curve point;
   - `A` or `R` has small order (its order divides 8).

   Otherwise, accept exactly when the canonical encoding of [S]B − [k]A equals the bytes of `R` (the cofactorless equation). Compute − [k]A as the negation of the point [k]A, or as [k](−A). Do not compute it as [L − k]A: for a mixed-order `A`, [L]A is not the identity, so that gives a different point. A key with a small-order component that is not itself small order (mixed order) is not rejected. These are the rules of libsodium's `crypto_sign_verify_detached`. The `receipt/ed25519-*` and `invalid/receipt-ed25519-*` vectors test each rule with signatures a permissive (cofactored) verifier accepts. A receipt that passes steps 1-6 is **signature-valid**.
7. **Recomputation** (optional; makes the receipt **fully verified**):
   1. Obtain the descriptor for `cell.fn_hash` (`E_FN_UNAVAILABLE` when none is obtained). First check that it hashes to `cell.fn_hash` (`E_FN_HASH_MISMATCH`), before anything else about it. Then check that it is canonical (sections 6-7, units, `order` and `extent` included), reporting a failure with the code canonicalising it on its own would give. For `lang = "formula"` this does not include the formula rules of 15.6 (`order` present, the body the print of its AST, `inputs` derived): those are `define`'s and a formula evaluator's, and the formula codes are not verification codes.

      What is obtained is a JSON value, and its hash is SHA-256 of that value's canonical bytes. A verifier that obtains the descriptor as bytes parses them strictly first (6.1), reporting a parse failure with its code. An implementation whose interface also takes text in place of a parsed value says which it takes; text is then the obtained bytes. Only obtaining nothing is unavailability: a JSON `null`, or any other value that is not the descriptor, is a descriptor offered, and fails the hash check (`E_FN_HASH_MISMATCH`), as there is no null value (3.6).
   2. `cell.args` names exactly the declared arguments, each with its declared type: first any undeclared argument (`E_ARG_UNKNOWN`), then any unbound declared argument (`E_ARG_MISSING`), then any type mismatch (`E_ARG_TYPE`), each in JCS order of names.
   3. `valid` holds exactly the declared valid-time arguments (`E_VALID_MISMATCH`).
   4. `type` equals the declared return type: `signature.returns`, or its `type` member when it is an object (`E_RETURN_TYPE`).
   5. For each hash in `inputs`, in order:
      - obtain the receipt offered for it (`E_INPUT_UNAVAILABLE` if none);
      - verify it through step 6 (`E_INPUT_INVALID`);
      - check that it hashes to the listed hash (`E_INPUT_UNAVAILABLE`);
      - check it is a cell of a declared input function (`E_INPUT_UNDECLARED`);
      - check its `asof` is at or before the receipt's `asof` (`E_TIME_ORDER`).

      For each slice entry, in its place in `inputs` (since `spec-0.4.0`):
      - obtain the manifest offered for the entry (`E_INPUT_UNAVAILABLE` if none); parse it strictly; check its structure, `{"members", "slice"}` with the slice object's structure included (`E_SCHEMA`); then its canonical form: each member 64 lowercase hex digits (`E_CANON_HEX`), then ascending and unique (`E_CANON_SET`), then at most 1,048,576 (`E_CANON_LIMIT`), then the slice object (4.4);
      - check that the slice object hashes to the entry's slice id and the members array to its members hash (`E_INPUT_UNAVAILABLE`, as for a receipt with another hash);
      - check that the slice's function (`ns/fn`, or the version slice's cell's) is a declared input function (`E_INPUT_UNDECLARED`);
      - for each member hash, in order: obtain the receipt (`E_INPUT_UNAVAILABLE`); verify it through step 6 (`E_INPUT_INVALID`); check its hash (`E_INPUT_UNAVAILABLE`); check that its cell belongs to the slice: the same `ns`, `fn` and `fn_hash`, the same argument names, bound arguments equal (the same typed scalar), ranged arguments of the range's type and within it, `lo <= v <= hi` in that type's order (numbers numerically, so `9.5` and `10` are within `[9..10.5]`; dates and instants chronologically; strings by code point), and any value, of any type, for an open argument; for a version slice, the same cell with a `tx` in `[from, to]`; then, for a membership slice, that no member before it in the manifest is the same cell (`E_SLICE_MEMBER`, so of two such members the second is reported, before its `asof`); then check its `asof` is at or before the receipt's (`E_TIME_ORDER`). A version slice may list several versions of its one cell.

      If there is at least one input receipt, slice members included, `tx` must equal the latest of their `tx`s (`E_TIME_ORDER`).
   6. Evaluate the function (for `stored`: look the value up as of `asof`). The result's `type` and `value` must equal the receipt's lexically (`E_VALUE_MISMATCH`).

      **A superseded input** (since `spec-0.4.0`). When the value differs and the evaluation's lineage is available (the `inputs` entries the evaluation read, with the receipts of those `inputs` does not list), the verifier checks whether an entry `e` of the receipt's `inputs` was replaced. The lineage is a set: its order does not matter. `e` is replaced when the lineage does not list `e` and lists an entry `n` that `inputs` does not list, such that:
      - for a receipt hash `e`: a receipt is offered for `n`, it is signature-valid through step 6, it hashes to `n`, it has the same cell id (4.4) as `e`'s receipt, and its `tx` is strictly later than that receipt's `tx`. Its `tx` is not compared with the receipt's `tx` or `asof`, and nothing else about it is checked (not its `asof`, not its function);
      - for a slice entry `e`: `n` is a string that begins `slice:` followed by `e`'s slice id and `:`. The slice id alone decides: no manifest is read, and the rest of `n` is not checked.

      An item of the lineage that is not a string replaces nothing, and lineage items are not otherwise validated. If some `e` is replaced, the result is success at level `signed` with `E_INPUT_SUPERSEDED` reported (at path `$.inputs`): typically a backdated correction or a late member changed what the evaluation reads, so the receipt is historical, not wrong. Otherwise, and when no lineage is available, it is `E_VALUE_MISMATCH`. Step 7.7 runs after it as after `E_EVAL_UNAVAILABLE`.

      If the verifier cannot evaluate the function (it has no runtime for the descriptor's `lang`, an evaluation budget is exceeded, or its evaluator cannot obtain the inputs it needs), recomputation stops here with `E_EVAL_UNAVAILABLE`. A verifier that does not attempt step 7 reports no code. This is not a verification failure, and it is distinct from `E_FN_UNAVAILABLE` (no descriptor, 7.1) and `E_VALUE_MISMATCH` (evaluated, and different). The result is success at level `signed`, with the code reported alongside it (at path `$.value`, where an implementation reports paths): the receipt is still signature-valid, and the caller learns that recomputation did not happen and why. It is reported only after 7.1-7.5 have passed; a failure there is reported instead.
   7. **Blob content.** If content is supplied: `type` must be `blob` (`E_SCHEMA` otherwise), and the content must have exactly `length` bytes and a SHA-256 equal to the blob's hash (`E_BLOB_MISMATCH`). This sub-step needs no descriptor and no inputs. It runs last: after 7.6 when recomputing, otherwise directly after step 6. It also runs after 7.6 ended with `E_EVAL_UNAVAILABLE`: if it passes, the code is still reported; if it fails, its failure replaces the code as an ordinary failure. Content of blob arguments is checked the same way by whoever retrieves it.

   A receipt that passes 7.1-7.6 is at level `recomputed`; otherwise it stays `signed`.

   **What verifier libraries of `spec-0.4.0` must do.** At level `signed`: accept slice entries in step 3 (their form, their place in the ascending order, one entry each for the limit), and nothing else changes, so every result of `spec-0.3.0` stands. In descriptors (7.1): accept `signature.order` and argument `extent`, with their canonical-form checks. At level `recomputed`: the manifest and member checks of step 7.5, the `tx` rule over input receipts and members, and `E_INPUT_SUPERSEDED` in 7.6 when a lineage is offered. A resolver supplies descriptors, receipts by hash (members included), manifests by entry and the evaluation (with its lineage, when it has one). A verifier needs no formula evaluator to do any of this: evaluation comes from the resolver, as for every language. The unit list of `units.md` gains `min`, `h`, `d`, `km` and `deg`. Step 7.7 does not change the level: passing it is reported separately, as `blob_checked`.

Signature-valid means the holder of key `computed_by` stated this value. Whether to trust that party is policy, outside this specification.

### 10.2 Error codes

The four failure classes a verifier distinguishes are: bad canonical form (parse, schema and canon codes), unknown or unusable key (key codes), bad signature, and value mismatch on recomputation (the remaining codes). Two codes, `E_EVAL_UNAVAILABLE` and `E_INPUT_SUPERSEDED`, are not failures: they are reported with success at level `signed` (10.1 step 7.6). The formula codes of section 15.11 are not verification codes.

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
| `E_CANON_HEX` | 3 | Hash, key id, signature or slice entry not lowercase hex of the right length. |
| `E_CANON_LICENCE` | 3 | Licence neither an SPDX identifier nor an `https://` URL. |
| `E_CANON_SET` | 3 | `inputs`, an extent or manifest members not strictly ascending; `order` not every argument exactly once. |
| `E_CANON_LIMIT` | 3 | A limit from 4.5 exceeded. |
| `E_SLICE` | 4, unit | A slice marker in a receipt, or in an argument a unit refers to; a slice object without an open or ranged argument. |
| `E_PUBLISHER_MISMATCH` | 4 | `publisher` differs from `cell.ns`. |
| `E_VALID_MISMATCH` | 4, 7 | `valid` does not echo exactly the valid-time arguments. |
| `E_TIME_ORDER` | 4, 7 | `tx <= asof <= issued` fails, an input receipt's `asof` is after the receipt's, or computed `tx` is not the latest input `tx`. |
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
| `E_INPUT_UNDECLARED` | 7 | An input receipt, or a slice, is of a function not in the descriptor's `inputs`. |
| `E_SLICE_MEMBER` | 7 | A member receipt does not belong to its slice, or two members of a membership slice are one cell. |
| `E_VALUE_MISMATCH` | 7 | Recomputation gives a different type or value. |
| `E_EVAL_UNAVAILABLE` | 7 | The verifier could not evaluate the function (7.6). Not a failure: reported with success at level `signed`. |
| `E_INPUT_SUPERSEDED` | 7 | Recomputation read a later version of an input cell, or other members of an input slice (7.6): the receipt is historical, not wrong. Not a failure: reported with success at level `signed`. |
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
| `receipt` | `input`: receipt JSON text; `keypair` (`seed`, `public`, `key_id`); `keys`: an `env` per host; optional `recompute`; optional `blob_hex`: content for step 7.7 | `canonical` (the signed payload), `sha256` (receipt hash), `sig`, `level` (`signed` or `recomputed`); `blob_checked` (true) when `blob_hex` is given; `code` (`E_EVAL_UNAVAILABLE`) when `recompute` has no `value` |
| `unit` | `input`: JSON text of an object with exactly `cell` and `descriptor` (any other shape is `E_SCHEMA`) | `unit`: the resolved unit of the cell's value (7.1), or null when the function does not return a number |
| `envelope` | `input`: the response body; `status`: the HTTP status; `keys`: an `env` per host; `request`: `{"cell_id", "asof"?}` for step 5 | `outcome`, and when there is a receipt, `trust` and `receipt_hash` |
| `slice` | `input`: JSON text of a slice object (4.4) or a manifest (15.13). It is a manifest exactly when it is an object with a `members` member; anything else is checked as a slice object (so `{"slice": …}` alone is `E_SCHEMA`, as a slice object without `args`) | `canonical`, `sha256`, `slice_id`; for a manifest also `members_hash` and `entry` |
| `formula` | `input`: a formula source; `env`: `{"name", "signature", "functions": {name: descriptor}, "aliases": {alias: name}}` | `ast` (the canonical AST's JCS text), `ast_sha256`, `body`, `inputs` (the derived set), `returns` (type and unit), `asof_dependent`; an invalid vector has `error`, and `token` for `E_FORMULA_FORBIDDEN` |
| `formula-eval` | `world`: `{"functions": {name: {"descriptor", "bound"}}, "receipts": [stored receipts], "max_depth"?}`; `cell`: `{"fn", "args"}`; `asof`; `fuel`? | `value`, `lineage` (the receipt's `inputs`), `tx`, `receipt_asof`, `fuel_used`, `receipt_hash`; an invalid vector has the evaluation code as `error` |
| `excel` | `excel` (the Excel formula), `doc` (the Microsoft page it follows), `documentation_derived` (true), `status`, `sample`, `excel_result`, `formula`, `signature`, `world`, `cell`, `asof` | as `formula-eval`, and `body`; `value` equals `excel_result` |
| `decimal` | `op`; `cases`: an array of argument arrays (canonical numbers; for `power` and `round` an integer second argument) | `results`: each case's canonical result or fault code, to the last digit; for `sqrt`, `exp`, `ln` and `pow` also `mpdecimal` (Python decimal's correctly rounded result, or null on a fault) and `hard_cases` (how many differ from the algorithm) |

`canonical` is the canonical byte string as UTF-8 text. It may contain U+2028 and U+2029, which some JSON-lines tools treat as line breaks. `key_ids` are in document order. Receipt vectors built by hand (the Ed25519 strictness vectors) have no `keypair`, because their keys have no seed.

**Computed receipts of `formula-eval` and `excel` vectors.** `receipt_hash` is the hash of the receipt the reference evaluator signs for the cell, built with these conventions: `computed_by` `mesh.example.net#cd42547c321bfc08` (the key of seed SHA-256 of `datumesh formula test key: mesh.example.net`, valid from `2020-01-01T00:00:00.000000Z`); `issued` the later of the receipt's `asof` and `2020-01-01T00:00:00.000000Z`; `licence` `CC0-1.0`; `summary` `Computed by the Datumesh formula reference evaluator.`; `publisher` the cell's namespace; `valid` the cell's valid-time arguments; `cell` the requested cell with the function hash of its descriptor; `type` and `value` the result; `inputs` the vector's `lineage`; `tx` and `asof` the vector's `tx` and `receipt_asof`. The stored receipts of a vector's `world` are signed by the key of each host's seed, SHA-256 of `datumesh formula test key: <host>`. An `excel` vector's function is the descriptor `{"code": {"body": <body>, "lang": "formula"}, "inputs": <the derived inputs>, "signature": <signature>}`. A `formula` vector's `returns.unit` is the checker's unit text: atoms in ascending order, with `^exponent` when it is not 1 (`arg:base^-1 arg:quote`), `1` for none, and `a bare number` for a body whose unit is a bare literal's.

A `recompute` object stands in for what step 7 obtains. It has these members:
- `descriptor`: the descriptor offered for `cell.fn_hash`, as a JSON value; when absent, the descriptor is unavailable (`E_FN_UNAVAILABLE`). It is never text to parse: a JSON string here is a string value offered as the descriptor, even when it holds a descriptor's text, and like `null` it does not hash to `fn_hash` (`E_FN_HASH_MISMATCH`, 10.1 step 7.1). Only an absent member means unavailable;
- `inputs`: a map from receipt hash to the input receipt's JSON text (slice members included); a hash with no entry is unavailable. Entries are always JSON strings; an entry that is not a string is a malformed vector;
- `manifests` (since `spec-0.4.0`): a map from slice entry to the manifest's JSON text; an entry with none is unavailable;
- `lineage` (since `spec-0.4.0`): the `inputs` entries the evaluation read, for 7.6's supersession check; absent, no check is made. Vectors hold only entries; 7.6 says what a verifier does with anything else;
- `value`: the typed scalar that evaluating the function gave, compared in 7.6. When absent, evaluation is unavailable: once 7.1-7.5 pass, the result is success at level `signed` with `E_EVAL_UNAVAILABLE` reported, and such a valid vector has `level: "signed"` and `code: "E_EVAL_UNAVAILABLE"`.

In an `env`, `status` is an integer HTTP status written without fraction or exponent, or the string `"error"`. Only the integer 200 is a retrieved document: any other value, including the string `"200"`, and an `https` object without `status`, is a failed retrieval (`E_KEY_UNAVAILABLE`, 9.3), as the vectors `invalid/keys-status-string` and `invalid/keys-status-missing` show.

A failed verification reports only its code. Whether a library also returns the receipt hash when it could compute one is the library's choice, and vectors do not record it. Inputs are deliberately not canonical: member order is reversed, and there is whitespace and escaping. A valid receipt vector's expected verification result is success at `level`, with `code` when given (`E_EVAL_UNAVAILABLE`, or `E_INPUT_SUPERSEDED` when `recompute` has a `value` and a `lineage`; a library reports no code otherwise); an invalid one's is `error`. A runner whose interface reads a string as JSON text passes a vector's `descriptor` as its JSON serialisation. `code` is the only output that names a code on success, and it is never `error`'s. Keypairs come from fixed seeds and Ed25519 is deterministic, so `tools/gen_vectors.py` reproduces every file byte for byte.

The `env` for a host is `{"https": {"status": 200, "body": "<text>"}}` for a retrieved document, or `{"https": {"status": <other status>}}` or `{"https": {"status": "error"}}` for a failed retrieval. A host absent from `keys` behaves as `{"https": {"status": "error"}}`.

The JSON Schemas under `schemas/` describe the shapes; where a schema keyword (`uniqueItems`, `maxItems`, a pattern) would reject an input that this document assigns another code, this document governs. In a cross-check, a runner that does not implement a kind of vector (a verifier library, for the kinds `formula`, `formula-eval`, `excel` and `decimal`) prints `{"id": …, "error": null, "skipped": "<kind>"}` for it, and is not compared on it (`crosscheck/README.md`).

The vectors use reserved example domains (`example.org`, `example.net`, `.example`) for everything signed. `tools/gen_vectors.py` (with `tools/gen_formula.py` for the kinds of `spec-0.4.0`) reproduces every file byte for byte.

## 12. Security considerations

- **Ambiguity is the attack surface.** Two encodings of one object would give one receipt two hashes, or let a signature cover something other than what is shown. Every rule above exists to make the canonical form unique. Implementations MUST reject, never repair.
- **Duplicate JSON members** are the classic signature-confusion bug: one parser takes the first, another the last. They are rejected at parse time.
- **Trust.** A valid signature means only that the key holder said it. A verifier chooses whom to trust (typically the publisher for stored cells, or anyone for recomputed cells, since recomputation does not depend on trust).
- **Key retrieval** is as trustworthy as the Web PKI. Verifiers MUST validate the TLS certificate and MUST NOT follow redirects.
- **Revocation** is by shortening `valid_to`. There is no other revocation list.
- **Text in summaries and strings** may contain bidi controls and confusable characters. Display it as data.
- **Blob content** is untrusted until step 7.7 passes. Check the length before downloading or hashing more than that many bytes. Do not let the media type override what a client would otherwise do with the bytes: it is the publisher's claim.
- **Envelopes are unsigned.** TLS authenticates the mesh, not what it says. `stale`, `superseded_by`, `verified`, every non-`ok` outcome, and the currency that `ok` asserts are the mesh's claims, and a mesh can lie about them or omit them. In particular, a mesh can serve an outdated receipt as `ok`: the client checks only that its `asof` is at or before the requested one. A client that needs a newer value asks with a later `asof`, or asks another mesh.

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
| D17 | Computed `tx` = latest input `tx`; every input receipt's `asof` is at or before the receipt's `asof`; by signing, `computed_by` asserts each input was its cell's latest version as of the receipt's `asof` (revised in `spec-0.3.0`) | Until `spec-0.2.1`: every input receipt shares the receipt's `asof`. Also `tx` = evaluation time | A stored input is signed by its publisher at its own `asof` and cannot be re-signed by anyone else, so a computed cell with two stored inputs published at different times could never satisfy the old rule. Recomputation stays deterministic and checkable given the inputs, which `inputs` pins by hash; their currency is the signer's assertion, which no verifier could check under the old rule either. `tx` = latest input `tx` is kept: it is when the value became knowable. |
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
| D31 | A client binds an envelope's receipt to its request: the same cell id, and, when an `asof` was asked for, a receipt `asof` at or before it, for `ok` and `stale` alike. `ok` asserts the receipt is the cell's latest version known as of the requested `asof`; `stale` does not, and carries `age_seconds` (revised in `spec-0.3.0`) | Until `spec-0.2.1`: an equal `asof` for `ok`, at or before for `stale`. Also: trust the mesh to answer the question asked | Without the binding, a mesh can answer any request with any valid receipt. It needs nothing in the receipt or the envelope, only what the client already knows. An equal `asof` forced a newly signed receipt for every distinct `asof` requested, so no receipt was reusable, and a publisher's own receipt could never be `ok` for an explicit `asof`. A receipt's value stands until the next version, so one receipt answers every later `asof` up to it. What `ok` adds over `stale` is the mesh's assertion of currency, which a client could not check under the old rule either (it could check only the equal `asof`, which says nothing about later versions). |
| D32 | Malformed requests are `bad_request` (HTTP 400) carrying a URI parse code; `error` (5xx) is for the mesh's own failures | One `error` outcome for both | A client should not retry its own mistake, and should know which part of the URI to fix. |
| D33 | A publisher of a stored receipt SHOULD set `asof = tx`. An issuer of a computed receipt SHOULD set `asof` to the latest of its input receipts' `asof`s, the start of every name binding it relied on, and every explicit transaction time it read; for an asof-dependent function, the evaluation asof (8.2; revised in `spec-0.4.0`) | Input `asof`s only (`spec-0.3.0`); let an input's `asof` exceed the receipt's | Each version of a computed cell has one canonical receipt, immutable and cacheable, that recomputes at its own `asof`: a binding that began later, or a time read explicitly, would otherwise make the receipt untrue as of its `asof`. The `spec-0.3.0` rule was incomplete, not wrong. Both rules are SHOULD only: verification does not check them. |
| D34 | A verifier that cannot evaluate a function reports `E_EVAL_UNAVAILABLE` with success at level `signed` (10.1 step 7.6) | Fail the receipt, with `E_FN_UNAVAILABLE` or `E_VALUE_MISMATCH`; or say nothing | Neither existing code says what happened: the descriptor was found, and nothing was compared. Failing would turn a signature-valid receipt invalid for a reason that is the verifier's, not the receipt's. Saying nothing would hide that recomputation did not happen. |
| D35 | A null descriptor, or one given as a value that is not the descriptor, is a descriptor offered and fails the hash check; only obtaining nothing is `E_FN_UNAVAILABLE` (10.1 step 7.1) | Treat `null` as absent | There is no null value (3.6): absence is expressed by absence. Reading `null` as "none" would give one input two meanings depending on the implementation. |
| D36 | `lang = "formula"`: a body is one expression; the grammar is a PEG with longest-match tokens | A general language; an LR grammar with precedence declarations | The brief; a PEG cannot be ambiguous, and the ordered choices only separate valid from invalid readings |
| D37 | Qualified names are one token beginning with a DNS name (so with a dot); aliases need `@` | Bare aliases resolved by scope | `x/f(y)` stays a division; meaning never depends on what is in scope |
| D38 | Built-ins and keywords case-insensitive, printed lowercase | Lowercase only | Excel users write `SUM`; the stored body is the printed form, so hashed data has one spelling |
| D39 | `-a^b`, `a^b^c` and comparison chains are rejected | Follow Excel (or mathematics) | The two traditions disagree; rejecting is the spec's rule for two readings |
| D40 | Bare ISO dates and canonical instants are literals | `date("…")` or a sigil | Matches the URI and the decision log; only a subtraction nobody writes without spaces is lost |
| D41 | Number literals must be canonical (3.1) | Accept `1.50`, `1e3` and normalise | One spelling in source and body |
| D42 | The function hash covers the printed canonical AST as `code.body`; a non-canonical body is rejected; the AST hash is a test artefact | Hash the AST JSON as the body | The body stays readable; one AST, one body, one hash |
| D44 | `inputs` is derived from the body and must equal the derived set | Declared by the author | The brief |
| D45 | Decimal: exact then round half-even to 34 digits per operation; every intermediate within the 128-character canonical form; no negative zero | decimal128's exponent range for intermediates | Fewer behaviours to reproduce; nothing outside the canonical form could be returned anyway |
| D46 | Integer exponents exact then rounded once; `sqrt`, `exp`, `ln`, non-integer `^`, `sin`, `cos`, `atan2` by named 40-digit algorithms with fixed term counts, then half-even to 34; the algorithm wins over correct rounding; `stdev` uses `SQRT-T40` | Integer exponents only and correctly rounded `sqrt` (the memo); correctly rounded results for everything | Correct rounding of transcendental functions has no bounded algorithm every evaluator can match; a fixed algorithm is deterministic and testable to the last digit |
| D47 | Units as atom-exponent maps over `units.md` symbols and argument references; listed composite symbols are atoms | A unit grammar (UCUM) | D25 stands; the algebra exists only at define time |
| D48 | Bare literals take their context's unit in `+ - <` and are dimensionless in `* /`, except against scaled ratios | Bare literals always `1` | `amount > 0` must work; `1 + r_percent` must not |
| D49 | `degC` is affine | An ordinary unit | `units.md` says it is a temperature, not a difference |
| D50 | Extent is an optional per-argument `extent` member; stored functions' extent is their recorded cells | A signature- or descriptor-level member; extents from another function | No existing hash changes; the descriptor keeps three members; function-defined extents wait for classes |
| D51 | An open or non-enumerable range argument over a non-stored function without an extent is refused at define time | Refuse at run time | The brief; stored histories are limited by fuel instead (decision log) |
| D52 | Members are ordered by key tuple, open arguments in name order | Source order | Independent of how the read was written |
| D53 | A slice entry is `slice:<slice id>:<members hash>`; the slice id is the id of the slice object (4.4 with range objects); the members hash is over the sorted member receipt hashes | No separators; an object entry; a Merkle root | Sorts after plain hashes, self-describing, one string; Merkle can come later as another prefix |
| D54 | Manifests `{members, slice}` fetched by entry | Members inline in the receipt | Keeps receipts small; that is the point |
| D55 | New code `E_SLICE_MEMBER` for a member outside its slice | Reuse `E_INPUT_UNDECLARED` | A different lie, which a reader should be able to tell apart |
| D56 | Lookups take the metric from the argument type, work along one dimension per group, and a bound narrows the recorded slice | A separate "group by"; read whole slices | Real-time aggregates at a cadence become one bounded slice per cell |
| D57 | No cell reads inside lambdas; slices join on equal open argument names | Per-member reads | Per-member reads would bring back the 4,096-entry problem |
| D58 | Evaluation faults give no value: `not_covered`, with the fault code in the envelope's optional `fault` member; `otherwise` catches only slice-proved absence | Excel-style error values; catch everything; an `error` envelope | There is no null; only slice absence is in the lineage; a fault is a property of the cell, not a failure of the mesh, but must not look like missing data |
| D59 | `asof()` is the evaluation asof; an asof-dependent receipt's `asof` is the evaluation asof, and it is not reused for other asofs | Forbid `asof()`; choose `asof` from inputs | The receipt must recompute at its own `asof` |
| D60 | `first_known`, `last_corrected`, `superseded` deferred to the standard library | Built-ins now | Expressible over `versions`; built-ins are hard to change |
| D61 | Calendars are slices; weekends a parameter | A built-in holiday table | Data is cells: lineage, versions, licences |
| D62 | `E_INPUT_SUPERSEDED` (7.6) is success at level `signed` with the code, raised when the resolver's lineage replaces an input by a later version of the same cell or slice | A failure; a bare `E_VALUE_MISMATCH` | The receipt is historical, not wrong (D34's reasoning) |
| D63 | Normative fuel table | Implementation-defined fuel | Two evaluators exhaust a budget at the same point; vectors can state fuel |
| D64 | Positional arguments bind by an optional, hashed `signature.order` listing every argument once; formula descriptors always carry it; positional before labelled; a positional read of a function without `order` is refused at define time; the canonical AST is labelled | Ascending name order; a required `order`, which would change every descriptor and receipt hash; positional arguments only for one-argument functions, or labels only | Authors and readers expect the declared order; optional means no existing hash changes; classes (1.3b) reuse it for key tuples |
| D65 | `haversine` on a 6371008.8 m sphere, to the millimetre; `ellipsoidal_distance` reserved | Ellipsoidal (Vincenty, Karney) now | The user's decision: one simple, fully specified metric first |
| D66 | Radians are dimensionless; `deg` is a listed unit; `sin`/`cos` accept both | A `rad` unit | SI treats the radian as dimensionless; `atan2(…) * r` then stays a length |
| D67 | Argument reduction uses 60-digit constants with an exact product | 40-digit constants throughout | A 40-digit pi loses up to six digits of `sin` near large multiples of pi; the reduction is one exact step |

## 14. Changes

### spec-0.4.0

The formula dialect and slice-as-lineage (step 1.3). **No hash of any receipt whose inputs are single cells changes, nor of any descriptor without `order` or `extent`**: receipts gain no member, `inputs` gains an entry form used only by receipts that read slices, descriptors gain two optional members, and `formula` is a new language. Every `spec-0.3.0` vector file and example is byte-identical, and every expected result is unchanged. `tests/test_migration_0_4_0.py` checks this against the `spec-0.3.0` files in git, recomputes every receipt hash with the `spec-0.3.0` and the new tool, and runs both tools side by side on fuzzed receipts with single-cell inputs and fuzzed descriptors without `order` or `extent`. `proto` is still `datumesh/1`.

- **The formula dialect (section 15).** `code.lang = "formula"`: grammar (15.2-15.4, Appendix A), resolution and the canonical AST (15.5), the printed body (15.6), built-ins (15.7), types (15.8), decimal arithmetic and the transcendental algorithms (15.9), units, angles and haversine (15.10), codes (15.11), evaluation, faults and fuel (15.12), slices (15.13), the Excel table (15.14) and the forms reserved for classes (15.15).
- **Slice-as-lineage (4.4, 8.1, 8.4, 10.1 steps 3 and 7.5, 15.13).** A slice read is one `inputs` entry `slice:<slice id>:<members hash>`; the manifest lists its members. New code `E_SLICE_MEMBER`.
- **Descriptors (7).** Optional `signature.order` (positional arguments bind by it) and argument `extent` (the cells of a slice over a computed function). Absent, a descriptor is unchanged; verifiers of `spec-0.3.0` reject a descriptor with either.
- **The three items from step 1.2b.**
  - 8.2's SHOULD for computed issuers now includes the start of every name binding relied on, explicit transaction times read, and the evaluation asof of asof-dependent functions (D33 revised).
  - `E_INPUT_SUPERSEDED` (10.1 step 7.6, 10.2, D62): a recomputation that read a later version of an input, or other members of a slice, is success at level `signed` with the code: the receipt is historical, not wrong.
  - The wording gaps: a descriptor given as text (7.1, the Python library's DEF-40 and the JavaScript library's note 36); no code when step 7 is not attempted (7.6, DEF-41); an `env` status written without fraction or exponent (11, JavaScript 37); `recompute.inputs` entries are always strings (11, RS-29); the `error` member's wording (5.5, RS-30).
- **Envelopes (5.5).** `not_covered` gains the optional member `fault`, a formula evaluation fault; no existing envelope's result changes. A mesh MUST NOT serve an asof-dependent receipt as `ok` for another asof.
- **Units (`units.md`).** `min`, `h`, `d`, `km` and `deg` added.
- **Limits (4.5).** `extent` (4096) and `members` (1048576).
- **Reference tools.** `tools/formula.py` (lexer, PEG parser, resolver, checker, printer, evaluator with lineage and fuel) and `tools/fdecimal.py` (integer decimal arithmetic and the 40-digit algorithms), standard library only; `tools/canon.py` gains slice entries, manifests, `order`, `extent`, `E_SLICE_MEMBER`, `E_INPUT_SUPERSEDED`, the envelope `fault` and the new vector kinds; `tools/gen_formula.py` generates the new vectors.
- **Schemas.** `slice.schema.json` and `manifest.schema.json`; receipt `inputs` entries, descriptor `order` and `extent`, the envelope `fault`, and the new vector kinds and members.
- **Settled after the verifier libraries' findings** (the Python library's DEF-42 to DEF-47, the JavaScript library's 38 to 45, the Rust core's RS-31 to RS-37), each as the reference tool already behaved; no vector's result and no hash changed:
  - 10.1 step 7.6, a superseded input, stated exactly: the replaced entry absent from the lineage, a replacement of the same cell id with a strictly later `tx` (not compared with the receipt's), signature-valid and hashing to its entry, a slice decided by its slice id alone, the lineage a set, its other items not validated, and an item that is not a string replacing nothing (the reference tool raised on one; it now ignores it);
  - 4.4: which shape a slice object, version slice and range object is; the check order inside them (a range's `type` first; `E_SLICE` last for a cell-shaped slice; a version slice's cell, then its markers, then `from` and `to`); a version slice with `from` after `to` is empty;
  - 10.1 step 7.5: the manifest's check order; membership in a range is in the type's order; an open argument admits any value; a duplicate cell is found at its second member, before its `asof`;
  - 7: an `order` entry that is not an argument is `E_CANON_SET` whatever its form; an empty extent and an empty `order` are allowed; the check order of extent values and range ends; the formula rules of 15.6 are not a verifier's (10.1 step 7.1);
  - 11: how a `slice` vector's input is classified; the prose governs where a schema keyword would give another code (the schemas' `uniqueItems`, `maxItems` and name patterns on `order`, `extent` and manifest members are removed); the `skipped` line of a runner in a cross-check;
  - the schemas' control characters are `\u` escapes again (the JavaScript library's entries 31 and 45), with a test.
- **Settled after the independent formula implementation's findings** (`datumesh-formula`, its SPEC-FINDINGS.md), each as the vectors and the reference already behaved; no vector's result changed: the computed-receipt conventions of `formula-eval` and `excel` vectors and an `excel` vector's descriptor (11); the fuel table made exact (`window`, free nodes, when a slice is charged; 15.12); how nesting and nodes are counted, lexing edge cases, tokens that cannot start an operand, lambda placement and key-set arguments (15.3); the error order of resolution (15.5); the built-ins' real parameter labels and the printed order of optional ones (15.7); `degC` and bare literals as applied (15.10); which operations round (`mod` does; `abs`, negation, `floor`, `ceiling` do not; 15.9.2); the 40-digit steps (15.9.3); step interpolation, the stored version answering, bindings as of `T` in `asof(c, T)` (15.13); `find` past the end; the descriptor check order (15.6). Four reference defects fixed, with tests: `if()` with four arguments, a non-integer where an integer is required, `fixed()` past 1024 bytes, and operator chains up to the node limit.
- **Vectors.** 613 new, 978 in all: 293 `formula` (172 valid, 121 invalid), 155 `formula-eval` (121, 34), 78 `excel`, 20 `decimal` (300 or more cases each), 18 `slice` (11, 7), 30 slice-lineage `receipt` (13, 17), 16 `function` with `order` and `extent` (4, 12), 3 `envelope` with `fault` (1, 2).

### spec-0.3.0

Time rules that work with real lineage. Two rules turned out unworkable with real data, and both become more permissive. It changes no hash: every receipt hash, cell id, function hash, canonical form and signature in the `spec-0.2.1` vectors is unchanged, and every `spec-0.2.1` vector file is byte-identical except the one whose expected result changed, which differs only in its result members and description. `tests/test_migration_0_3_0.py` checks this against the `spec-0.2.1` files in git, and recomputes the receipt hash of every receipt in every `spec-0.2.1` vector, inputs and envelope receipts included. `proto` is still `datumesh/1`.

- **D17 revised (8.2, 10.1 step 7.5, 10.2).** An input receipt's `asof` is at or before the receipt's `asof` (`E_TIME_ORDER`), instead of equal to it. Stored inputs are signed by their publishers at their own `asof` and cannot be re-signed, so a computed cell with two stored inputs published at different times could never satisfy the old rule. `tx` is still the latest input `tx`. By signing, `computed_by` asserts each input was its cell's latest version as of the receipt's `asof`; recomputation checks determinism given exactly those inputs, not their currency.
- **D31 revised (5.5).** For `ok`, the receipt's `asof` is at or before the requested `asof`, as for `stale`, instead of equal to it. An equal `asof` forced a newly signed receipt for every distinct `asof` requested, so no receipt was reusable. `ok` asserts the receipt is the cell's latest version known as of the requested `asof`; `stale` differs only in that the mesh cannot assert that, and carries `age_seconds`. On the wire the two are told apart by `outcome` and by `age_seconds`; neither assertion is checkable by a client.
- **Two SHOULDs (8.2, D33).** A stored receipt's publisher sets `asof = tx`; a computed receipt's issuer sets `asof` to the latest input `asof`. No vector's result depends on them.
- **`E_EVAL_UNAVAILABLE` (10.1 step 7.6, 10.2, 11, D34).** A verifier that cannot evaluate the function reports this code with success at level `signed`; the receipt stays signature-valid. Step 7.7 still runs, and its failure replaces the code. In the vectors, a `recompute` without `value` means evaluation is unavailable, and a valid receipt vector gains the output `code`. A valid receipt vector's expected result is success at `level`, with `code` when given. A mesh may carry the code in an `error` envelope.
- **Library questions settled.**
  - A non-integer HTTP status, or none, is a failed retrieval (`E_KEY_UNAVAILABLE`; 9.3, 11).
  - A descriptor is obtained as a JSON value; `null`, or a JSON string in a vector, is a descriptor offered and fails the hash check (`E_FN_HASH_MISMATCH`); only obtaining nothing is `E_FN_UNAVAILABLE` (10.1 step 7.1, 11, D35).
  - The 128-character media type limit is on the whole media type, with no per-name limit (3.7).
- **Reference tool.** `tools/canon.py` follows all of the above, reports `code` for receipt vectors, and no longer crashes on an `https` response without `status`.
- **Vectors.** 26 new, 365 in all.
  - Time rules: `receipt/computed-inputs-earlier-asof`, `receipt/computed-input-equal-asof`, `invalid/receipt-input-later-asof`; envelopes `envelope/ok-earlier-asof`, `envelope/ok-equal-asof`, `envelope/ok-no-requested-asof`, `envelope/served-ok` and `envelope/served-stale` (one receipt and request, both outcomes), `invalid/envelope-ok-later-asof`, `invalid/envelope-stale-later-than-request`, `invalid/envelope-stale-earlier-asof-without-age`, `invalid/envelope-ok-with-age`.
  - `E_EVAL_UNAVAILABLE`: `receipt/eval-unavailable-stored`, `receipt/eval-unavailable-computed`, `receipt/eval-unavailable-blob-checked`, `invalid/receipt-eval-unavailable-fn-unavailable`, `invalid/receipt-eval-unavailable-input-unavailable`, `invalid/receipt-eval-unavailable-input-later-asof`, `invalid/receipt-eval-unavailable-blob-mismatch`, `envelope/error-eval-unavailable`.
  - Settled questions: `invalid/keys-status-string`, `invalid/keys-status-missing`, `invalid/receipt-descriptor-null`, `invalid/receipt-descriptor-text`, `scalar/blob-media-type-long-subtype`, `invalid/scalar-blob-media-type-long-subtype`.

**Expected results that changed.** One, because the rules became more permissive:

| Vector | spec-0.2.1 | spec-0.3.0 | Why |
|---|---|---|---|
| `invalid/envelope-wrong-asof` | `E_ENVELOPE` | valid: `ok`, trust `primary`, receipt hash `19a5fe3a744c5792f747fb4c286ce396ab44b95922de4f07937502fe595b6f81` | Its receipt's `asof` is a day before the requested `asof`, which `ok` now accepts (D31). The file keeps its path under `invalid/`. |

No other vector's expected result changed. In particular, `receipt/computed-with-lineage` and the other computed vectors have inputs with an equal `asof`, which the revised D17 still accepts, and `invalid/envelope-stale-later-asof` stays `E_ENVELOPE`.

### spec-0.2.1

A text-only revision. It changes no hash: every `spec-0.2.0` vector file is byte-identical, which `tests/test_migration_0_2_1.py` checks. It writes down rules that the reference tool and both verifier libraries already followed, settles the gaps the libraries reported, and adds 20 vectors. Two outdated vector descriptions were corrected; nothing else in an existing vector changed.

- **Ed25519 strictness (10.1 step 6)** is now defined rule by rule, not by reference to libsodium. Six new vectors carry hand-built signatures that a permissive verifier accepts:
  - S not reduced;
  - a small-order key;
  - a small-order R;
  - a non-canonical R;
  - an R with x = 0 and the sign bit set;
  - a mixed-order key, which must be accepted.
- **Check orders:**
  - step 4's consistency checks run in the order listed;
  - URI parameter names (5.4 step 3);
  - container checks, and the length limit after the lexical form (4.5);
  - JSON parse errors (6.1);
  - step 7.1 checks the hash before canonical form;
  - step 7.2 checks unknown, then missing, then type.
- **JSON type codes (3):** a `value` that is not a string or boolean is `E_SCHEMA`; the wrong one of the two is `E_CANON_TYPE`.
- **New limit (6.1):** nesting deeper than 64 levels is `E_PARSE_JSON`, checked before anything else in the text. The two libraries previously broke at different depths, above 512.
- **`parse` (5.1, 5.4):**
  - an unreadable signature, meaning not an object, or a declaration that is not an object or has no type, is `E_SCHEMA`;
  - the outer URI grammar (path split, values containing `=`) is stated;
  - `asof` decoding is stated.
- **Grammar and member rules:**
  - the licence grammar (8.1);
  - key reference codes (9.1);
  - the key document's exact members, and that an invalid curve point is not a document error (9.2);
  - a 200 response without a document is `E_KEY_DOC` (9.3).
- **Smaller statements:**
  - instants report every failure as `E_CANON_INSTANT` (3.3);
  - NFC uses Unicode 15.1 data or later (3.5);
  - the `stored` convention is not enforced (7);
  - vector-format notes (11).
- **Reference tool fixes:** `tools/canon.py` no longer crashes on a 200 response without a body, or on deep nesting.

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

## 15. The formula dialect

`code.lang = "formula"` is the default language for computed functions: an Excel-compatible expression language over cells. It is not a general language. Its executable form is `tools/formula.py` (with `tools/fdecimal.py` for numbers); the vectors of kinds `formula`, `formula-eval`, `excel` and `decimal` are normative examples (section 11).

### 15.1 Purity and scope

A body is one expression. Its only values are the function's arguments, literals and cell reads. There is no I/O, no clock, no randomness, no mutable state, no loop, no accumulator and no cursor; iteration is only over slices, through aggregates, lookups and scans. `asof()` is the evaluation asof (15.12), a constant within an evaluation. A function may read itself with other arguments (recursion is only through cell reads, never inside a body); a cell that reappears on the evaluation stack is a cycle. A function returns a scalar; slices are values inside a body only.

**Inputs are derived, never declared.** A formula descriptor's `inputs` is exactly the set of fully qualified function names its body reads (15.5). A callee is always a lexical name, never a value, so the set is determined statically; a body that would need a dynamically constructed name fails at parse (`E_FORMULA_DYNAMIC_NAME`, `E_FORMULA_FORBIDDEN`).

### 15.2 Lexical rules

Tokens are recognised by **longest match**, trying these classes in order at each position. Whitespace between tokens is SP, HTAB or LF; CR and any other character outside a token are `E_FORMULA_SYNTAX`. Whitespace is never allowed inside a token. The whole body is lexed before it is parsed.

| # | Token | Form | Notes |
|---|---|---|---|
| L1 | instant | `date "T" 2DIGIT ":" 2DIGIT ":" 2DIGIT "." 6DIGIT "Z"` | Only the canonical form (3.3). Anything shaped `YYYY-MM-DDT…` that is not a canonical, real instant is `E_FORMULA_INSTANT`. |
| L2 | date | `4DIGIT "-" 2DIGIT "-" 2DIGIT` | Always a date, never a subtraction. Not a real day, or followed by a word character: `E_FORMULA_DATE`. |
| L3 | qualified name | `dns-name 1*( "/" name )` | A DNS name (2.1), so it contains a dot and its last label is not all digits; the last segment is the function (2.3). A run that looks like one but breaks 2.1-2.3 is `E_FORMULA_NAME`. |
| L4 | alias | `"@" name *( "/" name )` | A short name, replaced at define time by the resolver's alias map. |
| L5 | number | `( "0" / %x31-39 *DIGIT ) [ "." 1*DIGIT ]`, canonical (3.1) | Non-negative; a leading `-` is the unary operator. A non-canonical run (`1.50`, `01`, `1.`, `.5`, `1e5`, over 128 characters) is `E_FORMULA_NUMBER`. `1..2` is `1`, `..`, `2`. |
| L6 | unit suffix | after a number, optional SP or HTAB, the **longest unit literal of `units.md`** (index units included) not followed by a word character | `10 m/s` is ten metres per second; `10 m / s` divides ten metres by `s`. A following word that is a keyword is not a suffix. Any other word is `E_FORMULA_UNIT`, except digits directly followed by `D`, `M` or `Y` (`1M`, `10Y`), which are reserved for period keys (`E_FORMULA_RESERVED`, 15.15). The unit `1` is never a suffix. |
| L7 | string | `DQUOTE *( string-char / 2DQUOTE ) DQUOTE` | A doubled quote is a quote; there are no other escapes. The content follows 3.5 (assigned, NFC, no controls) and the 1024-byte limit: `E_FORMULA_STRING`. |
| L8 | word | `ALPHA *( ALPHA / DIGIT / "_" )` | Classified in 15.2.1. |
| L9 | punctuation | `..` `->` `<>` `<=` `>=` `(` `)` `[` `]` `,` `:` `*` `+` `-` `/` `^` `&` `=` `<` `>` `.` | `==` and `!=` are `E_FORMULA_SYNTAX` (write `=`, `<>`). A lone `.` is reserved for methods (15.15). |

#### 15.2.1 Words

Keywords and built-in names are **case-insensitive** and printed in lowercase; everything else is case-sensitive.

1. Keywords: `if then else let in and or not true false`.
2. Reserved: `this`, `super` (classes, 1.3b): `E_FORMULA_RESERVED` anywhere.
3. Forbidden function names, when followed by `(`: `now today rand randbetween randarray indirect offset info cell clock time random sleep fetch http eval`: `E_FORMULA_FORBIDDEN`, reporting the token as written. Without `(` such a word is an ordinary name.
4. A word followed by `(` is a built-in (15.7), `ellipsoidal_distance` (reserved: `E_FORMULA_UNSUPPORTED`), or `E_FORMULA_UNKNOWN_FUNCTION`. User functions are always written qualified or as an `@alias`.
5. A word not followed by `(` is a variable: an argument, a `let` name or a lambda parameter. It must be a name (2.2; `E_FORMULA_NAME`); a word with a capital letter is reserved for key literals (`E_FORMULA_RESERVED`, 15.15).

A formula function cannot have an argument named after a keyword or reserved word (`E_FORMULA_RESERVED`); `asof` cannot be an argument name at all (2.4). A label (`name:`) may be any name, so other functions' arguments called `in` or `if` can still be passed.

### 15.3 Grammar

The grammar is a PEG: alternatives are tried in order and the first that matches wins. It is given in ABNF notation in Appendix A; this section restates its structure.

- A body is an expression. `expr = or-expr / if-expr / let-expr`.
- `if c then a else b` and `let x = v in b` extend as far right as possible; `else` is mandatory. They appear only where a whole expression is expected: the body, a parenthesised expression, an argument, a branch, a `let` value or body, a lambda body. As an operand they need parentheses (`E_FORMULA_PLACEMENT`).
- Excel's `if(c, a, b)`, `and(a, b, …)` and `or(a, b, …)` are accepted as calls and resolve to the keyword forms. A body that starts `if (` is the function form exactly when the first parenthesised expression is followed by `,`.
- A read is a qualified name or alias followed by `(` and arguments; each argument is an expression, `*` (an open argument, when followed by `,` or `)`), or a range `[lo..hi]` with expression ends. A qualified name not followed by `(` is `E_FORMULA_SYNTAX`: there are no function values.
- A built-in call takes expressions; the second argument of `map` and `filter` is a lambda, `x -> e` or `(x, k1, …) -> e`. A lambda anywhere else, and `*` or a range outside a read, are `E_FORMULA_PLACEMENT`.
- Positional arguments come before labelled ones (`E_FORMULA_ARG_ORDER`); a label appears once (`E_FORMULA_ARG_DUPLICATE`).
- `(e)(x)`, `"a.org/f"(x)` and `f(x)(y)` are `E_FORMULA_DYNAMIC_NAME`; `).` and `x.y` are reserved for methods (`E_FORMULA_RESERVED`).
- **Limits** (`E_FORMULA_LIMIT`): a body over 1 MiB; nesting deeper than 256; more than 65,536 nodes. Nesting counts one level for every expression parsed (the body, each argument, each branch, a `let` value and body, a lambda body, each range end), one more for every parenthesis, and one for every `not`; a run of unary minus signs adds nothing. So 127 nested parentheses are accepted and 128 are not. Nodes are the canonical AST's objects (15.5), `open` and `range` markers included. An operator chain is not nesting: `a + a + … + a` is accepted up to the node limit.

Readings fixed by the vectors and the reference (an independent implementation found each):
- **Lexing.** A number's run covers digits and points up to a `..`, and a following exponent (`0.1.` and `1e5` are `E_FORMULA_NUMBER`; `1..2` is `1 .. 2`). An instant is exactly the 27 characters of 3.3 (`…Z.` is an instant, then a reserved `.`). A qualified name has non-empty labels (`a.b...org/f` is not one), and `x.org/` followed by something that is not a name is `E_FORMULA_NAME`. Period keys are digits only (`1.5M` is `E_FORMULA_UNIT`).
- **A token that cannot start an operand** reports what it is: `^` `E_FORMULA_AMBIGUOUS`; a comparison operator `E_FORMULA_CHAIN`; a lone `.` `E_FORMULA_RESERVED`; `->`, `*` and `[` `E_FORMULA_PLACEMENT`; `not(` as an operand `E_FORMULA_PLACEMENT`; `not x` as an operand, `true(`, `false(` and other keywords followed by `(` `E_FORMULA_SYNTAX`. `let` not followed by a name reports what an operand there would (`let = 1` is `E_FORMULA_CHAIN`).
- **Lambdas** are recognised in every built-in call argument (a name, or parenthesised names, before `->`), never in a read argument (where `->` is `E_FORMULA_PLACEMENT`). Their placement, the second argument of `map` or `filter` (positional, or labelled `fn:`), is checked at resolution, after the whole body has parsed. `if(` followed by a label is the keyword form.
- **Key-set arguments** (`E_FORMULA_UNSUPPORTED`): a read argument that is a `within(…)` call.

### 15.4 Precedence and ambiguity

From tightest to loosest:

| Level | Construct | Associativity |
|---|---|---|
| 1 | literals, reads, calls, `( )` (a unit suffix is part of its number) | — |
| 2 | `.` method (reserved, 15.15) | — |
| 3 | `^` | none: `a^b^c` is `E_FORMULA_AMBIGUOUS` |
| 4 | unary `-` | prefix; `-a^b` is `E_FORMULA_AMBIGUOUS`; no unary `+` |
| 5 | `*` `/` | left |
| 6 | `+` `-` | left |
| 7 | `&` | left |
| 8 | `=` `<>` `<` `<=` `>` `>=` | none: `a < b < c` is `E_FORMULA_CHAIN` |
| 9 | `not` | prefix |
| 10 | `and` | left |
| 11 | `or` | left |
| 12 | `if`, `let`, `->` | extend to the right |

The tree is binary at every level; with rounding (15.9), `+` and `*` are not associative, so its shape is part of the meaning. A unary minus is allowed in an exponent (`2^-1`).

Where two readings are plausible, the rule settles it or the input is rejected:

- **Division against `ns/fn`.** A qualified name begins with a DNS name, which contains a dot; a variable never does. `x/f(y)` with `x` an argument is a division. Short names need `@`.
- **Hyphenated hosts.** `a-b.org/f(x)` is the call of `a-b.org/f` (longest match); `a - b.org/f(x)`, with spaces, subtracts.
- **Units.** `10 m/s` against `10 m / s` (15.2 L6); `5 x` is `E_FORMULA_UNIT`, not a product.
- **Ranges.** `[1..2]`, `[1.5..2]`; `[1...2]` is `E_FORMULA_NUMBER`.
- **Powers.** Excel reads `-2^2` as 4 and `2^3^2` as 64, mathematics as -4 and 512: both rejected. Write `(-2)^2`, `-(2^2)`, `(2^3)^2` or `2^(3^2)`.
- **Dates.** `2024-10-15` is a date; `2024 - 10 - 15` subtracts.
- **Comparisons** do not chain; write `and`.

The printer (15.6) puts spaces round every binary operator, so no printed body contains a whitespace-sensitive form.

### 15.5 Resolution and the canonical AST

Resolution turns the parse tree into the **canonical AST**, a JSON value. It runs after parsing and before checking. `E_FORMULA_UNKNOWN_FUNCTION`, `E_FORMULA_FORBIDDEN`, `E_FORMULA_ARG_ORDER` and a duplicate label are parse errors, reported in text order after the whole body is lexed. Resolution then walks the tree in source order. For a read: the callee first (`E_FORMULA_ALIAS`, `E_FORMULA_UNRESOLVED`, `E_FORMULA_POSITIONAL`, too many positional arguments), then each argument in source order (its label's name, then its value), then duplicates, unknown labels and missing arguments. For a built-in: arguments bind one at a time (too many positional, an unknown label, a duplicate, then the value), then missing required ones; `and`, `or` and `asof` check their arity first. In checking (15.8), a `let` name and lambda parameters are checked before their value and body, and the left operand of `and` or `or` before the right one. The steps are:

- aliases become fully qualified names (`E_FORMULA_ALIAS`); a qualified name must have a binding at define time (`E_FORMULA_UNRESOLVED`), the function being defined included;
- keywords and built-in names become lowercase; `if(c, a, b)` becomes an `if` node and `and(a, b, c)` becomes `(a and b) and c`;
- **positional read arguments bind by the callee's `signature.order`** (7) and become labelled. A positional argument in a read of a function whose signature has no `order` is `E_FORMULA_POSITIONAL`; more positional arguments than `order` lists is `E_FORMULA_ARITY`; then labels are checked against the callee's arguments (`E_FORMULA_ARG_DUPLICATE`, `E_FORMULA_ARG_UNKNOWN`, then `E_FORMULA_ARG_MISSING` in JCS order of names);
- built-in arguments bind to their parameters (15.7): required parameters positional, optional ones labelled;
- nothing else changes: no constant folding, no reordering.

Nodes are objects discriminated by `node`: `num` (`value`, the canonical lexical form, and optionally `unit`), `str`, `bool`, `date`, `instant`, `var` (`name`), `op` (`op`: a binary operator, `neg` or `not`; `args`), `if` (`cond`, `then`, `else`), `let` (`name`, `value`, `body`), `read` (`fn`; `args`: an object from argument name to an expression, `{"node": "open"}` or `{"node": "range", "hi", "lo"}`), `call` (`fn`, `args`, `named`), `lambda` (`params`, `body`), `agg` (`name`: the aggregate of `scan` and `window`) and `key` (`name`: the dimension named by `along`). The AST contains no JSON numbers.

The **canonical AST hash** is SHA-256 of the AST's JCS bytes. It is in no protocol object; grammar vectors pin it.

### 15.6 The printer and `code.body`

A formula descriptor's `code.body` is the **printed canonical AST** followed by one LF: single spaces round every binary operator and `->`, keywords spaced, `name: value` labels in reads (ascending), built-ins with required arguments positional and optional ones labelled, a unit suffix after one space, strings with doubled quotes, and the fewest parentheses the precedence table allows plus those the rejected forms require. A formula descriptor whose body is not the print of its AST is not canonical (`E_FORMULA_NOT_CANONICAL`); one whose `inputs` differs from the derived set is `E_FORMULA_INPUTS`; one whose signature has no `order` is `E_FORMULA_ORDER`. They are checked in this order: the descriptor's canonical form (7), `E_FORMULA_ORDER`, the body's own codes (compiled against the descriptor's signature), `E_FORMULA_NOT_CANONICAL`, then `E_FORMULA_INPUTS`. So each formula has one body and one function hash.

For every canonical AST, parse(print(ast)) = ast, without an environment: a printed body has only full names and labelled reads.

### 15.7 Built-ins

The names in the table are the parameters' labels: every parameter, required or optional, may be given by label (`abs(x: a)`), positional ones first. Arguments in brackets are optional; the printer writes required ones positionally and optional ones labelled, in the order of this table (not ascending: `interpolate(…, method: "linear", bound: 1 h)` prints `method` before `bound`). An aggregate, `concat`, `and` and `or` take one slice or one or more positional scalars of one type, and no labels; `asof` takes none or two positional arguments.

| Built-in | Result |
|---|---|
| `sum(slice)` | Exact sum, rounded once; 0 on an empty slice. Not of `degC`. |
| `count(slice)` | Member count, unit `count`. |
| `mean(slice)` | Exact sum divided by the count, rounded once. |
| `min(slice)`, `max(slice)` | Least or greatest value (numbers, dates, instants, strings). |
| `first(slice)`, `last(slice)` | The first or last member in key order (15.13). |
| `median(slice)` | The middle value; for an even count, the two middle values' exact sum halved, rounded once. |
| `stdev(slice)`, `stdev_p(slice)` | Sample and population standard deviation (15.9.2); of `degC`, in `K`. |
| `at(slice, key, [along])` | The member at `key`. |
| `latest(slice, [bound], [along])` | The last member along the dimension; with a bound, none if older than `asof() - bound` (asof-dependent). |
| `last_before(slice, x, [bound], [along])` | The member with the greatest key at or before `x`. |
| `first_after(slice, x, [bound], [along])` | The member with the least key at or after `x`. |
| `nearest(slice, x, [bound], [along])` | The member nearest to `x`; on a tie, the earlier key. |
| `within(slice, x, bound, [along])` | The slice of members within `bound` of `x`. |
| `interpolate(slice, x, [method], [bound], [along])` | `"linear"` (default) or `"step"`; no extrapolation; `"spline"` is `E_FORMULA_UNSUPPORTED`. |
| `map(slice, fn)` | `fn` is a lambda `x -> e`: same keys, values `e`. Further lambda parameters name open arguments and bind to their key values. |
| `filter(slice, fn)` | `fn` is a lambda `x -> p`: the members for which `p` is true. |
| `scan(slice, aggregate, [along])` | The running aggregate along the dimension, per group. |
| `window(slice, n, aggregate, [along])` | The aggregate of the trailing `n` members; members with fewer than `n - 1` predecessors omitted. |
| `otherwise(x, fallback)` | `x`, or `fallback` when `x` is `E_FORMULA_EMPTY` or `E_FORMULA_ABSENT`. |
| `asof()` | The evaluation asof (asof-dependent). |
| `asof(cell, T)` | The value of the cell's version answering as of `T` (a transaction-time read). |
| `versions(cell, from, to)` | The slice of the cell's versions with `tx` in `[from, to]`, keyed by `tx`. |
| `abs(x)`, `floor(x)`, `ceiling(x)` | Exact. |
| `round(x, [digits])`, `round_up(x, [digits])`, `round_down(x, [digits])` | Excel's ROUND (half away from zero), ROUNDUP, ROUNDDOWN. |
| `mod(x, divisor)` | Excel's MOD: the sign of the divisor. |
| `sqrt(x)` | SQRT-T40 (15.9.3). |
| `exp(x)`, `ln(x)` | EXP-T48, LN-ATANH80; dimensionless. |
| `sin(x)`, `cos(x)` | TRIG-T24; `x` in radians (dimensionless) or `deg`. |
| `atan2(y, x)` | ATAN2-T32, in radians. Excel's ATAN2 takes `(x, y)`. |
| `pi()` | The 40-digit pi rounded to 34. |
| `haversine(lat1, lon1, lat2, lon2)` | HAVERSINE (15.10): metres, to the millimetre. |
| `convert(x, unit)` | Between units of one group by an exact factor (15.10). |
| `if(condition, then, else)`, `and(a, b, …)`, `or(a, b, …)` | Excel's forms of the keywords. |
| `date(year, month, day)` | A date; not a real day: `E_FORMULA_DOMAIN`. |
| `year(date)`, `month(date)`, `day(date)`, `weekday(date)` | `weekday` is ISO: Monday 1. |
| `end_of_month(date)` | The month's last day. |
| `add_days(date, n, [calendar], [weekend])` | Calendar days; with a calendar or weekend, business days (Excel's WORKDAY). |
| `add_months(date, n, [calendar], [roll], [weekend])` | Excel's EDATE; with a calendar or roll, rolled to a business day (`"following"`, `"modified_following"`, `"preceding"`). |
| `business_days(from, to, [calendar], [weekend])` | Excel's NETWORKDAYS: both ends inclusive, negative when reversed. |
| `year_fraction(from, to, convention)` | `"act/360"`, `"act/365f"`, `"act/act_isda"`, `"30/360"`, `"30e/360"`, `"30/360_us"`; the order of the dates does not matter. |
| `is_holiday(date, calendar)` | Whether the date is a member of the calendar slice. |
| `date_of(instant)`, `instant(date)` | The UTC date; midnight UTC. |
| `len(text)` | Code points. |
| `upper(text)`, `lower(text)` | Unicode 15.1 full case mappings, locale-free. |
| `trim(text)` | Excel's TRIM: U+0020 trimmed at both ends and collapsed inside. |
| `concat(a, b, …)` | Joined; the same as `&`. |
| `substr(text, start, length)` | Excel's MID: 1-based, in code points. |
| `find(needle, text, [start])` | 1-based position, case-sensitive; 0 when not found, and when `start` is past the end of the text; `start < 1` is `E_FORMULA_DOMAIN`. |
| `text(x)` | The canonical lexical form of any scalar. |
| `fixed(x, digits)` | Excel's FIXED without separators. |

A calendar is a slice with one open date argument; a date is a holiday when it is a member. `weekend` is `"sat-sun"` (default), `"fri-sat"`, `"sun"` or `"none"`. Enumeration arguments (`method`, `convention`, `roll`, `weekend`, the unit of `convert`, the aggregate of `scan` and `window`) are literals from their lists (`E_FORMULA_ENUM`). Every string result, `fixed`'s and `text`'s included, is normalised to NFC with Unicode 15.1 data (a computed value, not an input) and is at most 1024 bytes (`E_FORMULA_RANGE`). Where an integer is required (`digits`, `start`, `length`, `n`, the arguments of `date`, a number of days), a value that is not one is `E_FORMULA_DOMAIN`.

### 15.8 Types and checking

The types are the six scalars and **slices** `slice<T, keys>`: members, each a key tuple over the open arguments and a value of type `T`. A slice is never an argument, a branch of `if`, or a function's result (`E_FORMULA_SLICE_VALUE`). There are no implicit conversions (`E_FORMULA_TYPE`): `"a" & 1` is an error, `"a" & text(1)` is not. Blobs can be compared with `=` and `<>`, passed and returned.

**At define time** the checker walks the canonical AST depth first, left to right (a read's arguments in ascending label order), and reports the first failure: names in scope (`E_FORMULA_UNKNOWN_NAME`, `E_FORMULA_SHADOW`), built-in arity, argument types and units against the callee's signature, every node's type and unit (15.10), lambdas (`E_FORMULA_LAMBDA_PARAM`, and `E_FORMULA_LAMBDA_READ`: no cell reads inside a lambda; join instead), extents (15.13), joins (`E_FORMULA_JOIN`), lookups (`E_FORMULA_METRIC`, `E_FORMULA_ALONG`), transaction-time reads (`E_FORMULA_TX_ARG`), and finally the return type and unit against `signature.returns` (`E_FORMULA_RETURN_TYPE`, `E_FORMULA_RETURN_UNIT`).

**At evaluation** the remaining failures are faults (15.12), absences and the evaluator's own limits. A callee name rebound since define time is checked again, with the same codes.

### 15.9 Numbers

#### 15.9.1 The rule

Every operation computes its exact result, rounds it once to **34 significant digits, half-even**, then applies the **range rule**: the result in canonical form (3.1) has at most 128 characters, or the operation fails with `E_FORMULA_RANGE`. The rule applies to every intermediate, not only to the returned value. There is no exponent form, no infinity, no NaN and no negative zero (a zero result is `0`). No float appears anywhere.

The reference library for tests is Python's `decimal` in `Context(prec=34, rounding=ROUND_HALF_EVEN, Emin=-6143, Emax=6144, clamp=0)` with `InvalidOperation`, `DivisionByZero` and `Overflow` trapped, plus the range rule. Because every operand satisfies the range rule, no operation reaches those exponent limits.

#### 15.9.2 Operations

| Operation | Definition |
|---|---|
| `+` `-` `*` | Exact, rounded once. |
| `/` | The exact quotient rounded once; a zero divisor is `E_FORMULA_DIV_ZERO`. |
| comparison | Exact. |
| `x ^ n`, `n` an integer | `abs(n) <= 1024` (`E_FORMULA_DOMAIN`). The exact power rounded once; for `n < 0`, 1 divided by the exact power, rounded once; `x^0` is 1; `0` to a negative power is `E_FORMULA_DIV_ZERO`. |
| `x ^ y`, `y` not an integer | POW-EXPLN (15.9.3). |
| `sum`, `mean`, `median` | As in 15.7: exact sums, one rounding. |
| `stdev`, `stdev_p` | `m` = mean; `ss` = the exact sum of the exact squares `(x_i - m)^2`, rounded once; `v = ss / (n - 1)` (or `/ n`), rounded once; the result SQRT-T40 of `v`. `stdev` needs two members, `stdev_p` one (`E_FORMULA_EMPTY`). |
| `abs`, unary `-`, `floor`, `ceiling` | Exact: not rounded (a 39-digit argument keeps its 39 digits). |
| `round`, `round_up`, `round_down` | Exact, then the range rule. A huge positive `digits` leaves the value as it is; a huge negative one gives 0. |
| `mod` | The exact remainder `a - b * floor(a / b)`, rounded once to 34 digits like every arithmetic result. |

#### 15.9.3 Transcendental algorithms

`sqrt`, `exp`, `ln`, non-integer powers, `sin`, `cos`, `atan2` and `haversine` are defined by the named algorithms below. **Every step is at a working precision of 40 significant digits, half-even**; the 40-digit result is then rounded half-even to 34 and the range rule applied. The algorithm is normative: where its result differs from the correctly rounded value (a hard case near a rounding boundary), **the algorithm wins**. Python's `decimal` (mpdecimal) is the reference implementation for `sqrt`, `exp`, `ln` and powers; the vectors of kind `decimal` record its correctly rounded results beside the algorithm's and count the hard cases.

Constants, each the true value rounded half-even to the digits shown:

```
PI         = 3.141592653589793238462643383279502884197
HALF_PI    = 1.570796326794896619231321691639751442099
LN10       = 2.302585092994045684017991454684364207601
HALF_PI_60 = 1.57079632679489661923132169163975144209858469968755291048747
LN10_60    = 2.30258509299404568401799145468436420760110148862877297603333
RAD_PER_DEG = PI / 180, divided at 40 digits
```

The 60-digit constants are used only in argument reduction, where `x - n * C` is computed with the product exact and the difference rounded once to 40 digits.

- **SQRT-T40.** The exact square root truncated to 40 significant digits (an integer square root of the scaled coefficient), then half-even to 34. A negative argument is `E_FORMULA_DOMAIN`. Truncation makes a tie at digit 35 possible where the exact root is above it; half-even then keeps the even neighbour.
- **EXP-T48.** `abs(x) <= 300` (`E_FORMULA_RANGE` beyond). `n` = `x / LN10` rounded half-even to an integer; `r = x - n * LN10_60`; `S = sum of t_k` for `k = 0..47`, with `t_0 = 1` and `t_k = (t_(k-1) * r) / k`, each product and quotient rounded to 40, each addition rounded to 40; the result is `S * 10^n`.
- **LN-ATANH80.** `x > 0` (`E_FORMULA_DOMAIN`). `x = m * 10^k` with `1 <= m < 10`; when `m * m >= 10` (decided exactly), `m` is divided by 10 and `k` increased by 1. `z = (m - 1) / (m + 1)`; `ln m = 2 * sum of z^(2j+1) / (2j+1)` for `j = 0..79`, the powers by repeated multiplication with `z * z`; `ln x = ln m + k * LN10`.
- **POW-EXPLN.** For a non-integer `y`: `x > 0`: EXP-T48 of `y * LN-ATANH80(x)`, both at 40 digits before the final rounding; `x = 0` and `y > 0`: 0; `x = 0` and `y < 0`: `E_FORMULA_DIV_ZERO`; `x < 0`: `E_FORMULA_DOMAIN`.
- **TRIG-T24.** `abs(x) <= 1000000` radians (`E_FORMULA_DOMAIN`). `k` = `x / HALF_PI` rounded half-even to an integer; `r = x - k * HALF_PI_60`; `sin r = sum of (-1)^j r^(2j+1) / (2j+1)!` and `cos r = sum of (-1)^j r^(2j) / (2j)!` for `j = 0..23`, each term from the previous by `* r^2 / ((2j)(2j+1))` (or `/ ((2j-1)(2j))`); by `k mod 4`: `(sin x, cos x)` is `(sin r, cos r)`, `(cos r, -sin r)`, `(-sin r, -cos r)`, `(-cos r, sin r)`.
- **ATAN2-T32.** `atan2(0, 0)` is `E_FORMULA_DOMAIN`. `a = abs(y)`, `b = abs(x)`; `t = a / b`, or `b / a` when `a > b`; twice `t = t / (1 + SQRT40(1 + t * t))`, where SQRT40 is the 40-digit truncation of SQRT-T40; `A = 4 * sum of (-1)^j t^(2j+1) / (2j+1)` for `j = 0..31`; `HALF_PI - A` when `a > b`; then `PI` minus that when `x < 0`; negated when `y < 0`.

"Rounded half-even to an integer" (`n` in EXP-T48, `k` in TRIG-T24) applies to the 40-digit quotient. In LN-ATANH80, `m - 1` and `m + 1` are each at 40 digits before their quotient; in HAVERSINE, `dphi = (lat2 - lat1) * RAD_PER_DEG` and `dlambda` are each at 40 digits, and `R * 2` is formed before the product with the angle.

A term below a tenth of a unit in the 40th digit of the partial sum cannot change the sum, and every later term is smaller; an implementation may stop there, and the result is exactly that of the full term count.

The tests run 10,000 random cases per function against mpdecimal (`sqrt`, `exp`, `ln`, powers) and against 90-digit series (`sin`, `cos`, `atan2`); a difference larger than one unit in the 34th digit fails, and the number of hard cases is reported. A hard case is constructed for `sqrt` (`decimal/sqrt` holds it).

### 15.10 Units, angles and distance

The checker gives every number a unit: a map from atoms to non-zero integer exponents. An atom is a literal unit of `units.md` (indivisible: `kWh`, `m/s` and `W/m2` are atoms) or `arg:<name>`, the value of a string argument of the function being defined. A declared unit maps in directly: a literal to its atom, `{"arg": "q"}` to `arg:q`, a rate `{"of": X, "per": Y}` to `X^1 Y^-1`. A read's unit is the callee's declared unit with its argument references replaced by the units of the expressions bound to them: a string literal that is a listed unit, a string argument of the caller, or a `let` name bound to one of those; anything else is `E_FORMULA_UNIT_UNKNOWN`. When the reference is to an open argument the slice's unit varies by member, and the slice can only be counted or filtered.

- `*` and `/` add and subtract exponents; `^` with an integer literal multiplies them, and a unit-bearing base with any other exponent is `E_FORMULA_EXPONENT`; `sqrt` halves even exponents.
- `+`, `-`, comparison, the branches of `if`, the variadic aggregates and `otherwise` need equal units (`E_FORMULA_UNIT_MISMATCH`). A read argument with a declared unit must receive it; the body's unit must equal the declared return unit (`E_FORMULA_RETURN_UNIT`).
- **Bare literals.** A number without a suffix is dimensionless in `*`, `/` and `^`, and takes its context's unit in `+`, `-`, comparison, `if`, `otherwise`, arguments and the return: `amount > 0`, `price + 10`. Against `percent`, `permille` or `bp` only `0` is accepted: `1 + r` with `r` in percent is an error (write `1 + r / 100 percent` or `convert(r, "1")`). A value declared in `1` is the identity in `*` and `/` but needs `1` on the other side of `+`.
- **Offset units.** In `+` and `-`: `degC - degC` is `K`; `degC ± K`, `degC ±` a bare literal, `K + degC` and a bare literal `+ degC` are `degC`; every other combination with `degC` is `E_FORMULA_UNIT_OFFSET` (so is `degC + EUR`). Comparisons of `degC` with `degC` or a bare literal are allowed; comparisons, `if`, `otherwise` and variadic aggregates mixing `degC` with another unit are `E_FORMULA_UNIT_MISMATCH`. Negation keeps `degC`. `degC + degC`, `*`, `/`, `^`, `mod`, `atan2` and `sqrt` of `degC`, and `sum` over `degC`, are `E_FORMULA_UNIT_OFFSET`; `mean`, `median`, `min`, `max`, `first`, `last`, lookups and interpolation are allowed. A weighted mean of temperatures goes through kelvin: `convert(sum(map(t(*), x -> convert(x, "K")) * w(*)) / sum(w(*)), "degC")`.
- **Time.** An instant plus or minus a number in `s`, `min`, `h` or `d` (a bare literal: `s`) is an instant, in whole microseconds (`E_FORMULA_DOMAIN`); an instant minus an instant is in `s`. A date plus or minus an integer number of `d` (a bare literal: `d`) is a date; a date minus a date is in `d`. Results outside 0001-9999 are `E_FORMULA_RANGE`.
- **Angles.** Radians are dimensionless (`1`), as in SI; `deg` is listed. `sin` and `cos` take `1` or `deg`; `atan2(y, x)` takes two numbers of one unit and returns radians; `pi()` is `1`.
- **Other built-ins with bare numbers.** In `convert` a bare number is `1` (`convert(100, "deg")` is accepted, `convert(5, "m")` is a mismatch); `add_days` counts a bare number or `d` (a number in `1` is a mismatch); `add_months`, `round`'s `digits` and the arguments of `date` take dimensionless numbers; `count` of scalars does not unify their units.
- **`convert(x, "u")`** converts within a group by an exact factor: `1`, `percent`, `permille`, `bp`; `mm`, `cm`, `m`, `km`; `s`, `min`, `h`, `d`; and `degC` to `K` (+273.15) and back; `deg` and `1` by `RAD_PER_DEG` (at 40 digits, then 34). Nothing else converts.
- **HAVERSINE.** `haversine(lat1, lon1, lat2, lon2)` takes decimal degrees (`deg`, or bare) with `abs(lat) <= 90` and `abs(lon) <= 360` (`E_FORMULA_DOMAIN`) and returns metres on a sphere of radius R = 6371008.8 m: `phi = lat * RAD_PER_DEG`; `h = sin(dphi / 2)^2 + cos(phi1) * cos(phi2) * sin(dlambda / 2)^2` (clamped to [0, 1]); `d = R * 2 * atan2(SQRT40(h), SQRT40(1 - h))`, every step at 40 digits with the 40-digit forms of TRIG-T24 and ATAN2-T32; the result rounded half-even to millimetres (three decimals). `ellipsoidal_distance` is reserved for a later revision (`E_FORMULA_UNSUPPORTED`). The `point` metric of 1.3b dispatches to `haversine`; already now a slice keyed by latitude and longitude can be filtered by distance: `filter(f(lat: *, lon: *), (v, lat, lon) -> haversine(lat, lon, 51.5, -0.12) <= 20000 m)`.

A verifier never checks a value against its unit (7.1); all of this is checked at define time.

### 15.11 Error codes

Define-time codes are reported by `define` and the reference checker; evaluation codes by an evaluator. None is a verification code (10.2): no receipt is signed for a failed evaluation.

| Code | Rule |
|---|---|
| `E_FORMULA_SYNTAX` | Not a sentence of the grammar; a stray or unknown character. |
| `E_FORMULA_NUMBER` | A number literal not in canonical form. |
| `E_FORMULA_STRING` | A string literal unterminated, not NFC, with a control or unassigned character, or over 1024 bytes. |
| `E_FORMULA_DATE` | A date-shaped token that is not a real day. |
| `E_FORMULA_INSTANT` | An instant-shaped token not in canonical form or not a real time. |
| `E_FORMULA_UNIT` | A unit suffix, or the unit of `convert`, that is not a listed unit. |
| `E_FORMULA_NAME` | A qualified name, alias, variable or label that breaks 2.1-2.3. |
| `E_FORMULA_RESERVED` | `this`, `super`, a keyword as a name, a word with a capital, a period key, `.` after an expression. |
| `E_FORMULA_FORBIDDEN` | A forbidden function name called; the token is reported. |
| `E_FORMULA_DYNAMIC_NAME` | A call whose callee is not a name. |
| `E_FORMULA_AMBIGUOUS` | `-a^b` or `a^b^c` without parentheses. |
| `E_FORMULA_CHAIN` | Two comparisons chained. |
| `E_FORMULA_PLACEMENT` | `if`, `let` or `not` as an operand; `*` or a range outside a read; a lambda outside `map` and `filter`. |
| `E_FORMULA_LIMIT` | A body over 1 MiB, nesting deeper than 256, more than 65,536 nodes. |
| `E_FORMULA_UNKNOWN_FUNCTION` | A bare call that is not a built-in. |
| `E_FORMULA_ALIAS` | An alias not in the alias map. |
| `E_FORMULA_UNRESOLVED` | A function name with no binding. |
| `E_FORMULA_UNKNOWN_NAME` | A variable not in scope. |
| `E_FORMULA_SHADOW` | A `let` name or lambda parameter equal to a name in scope, or two equal lambda parameters. |
| `E_FORMULA_ARITY` | A built-in with the wrong number of arguments; more positional read arguments than `order` lists. |
| `E_FORMULA_ARG_UNKNOWN` | A label the callee does not declare. |
| `E_FORMULA_ARG_MISSING` | A callee argument not bound. |
| `E_FORMULA_ARG_DUPLICATE` | An argument bound twice. |
| `E_FORMULA_ARG_ORDER` | A positional argument after a labelled one. |
| `E_FORMULA_POSITIONAL` | A positional argument in a read of a function without `order`. |
| `E_FORMULA_ORDER` | A formula descriptor without `order`. |
| `E_FORMULA_TYPE` | A type mismatch. |
| `E_FORMULA_SLICE_VALUE` | A slice where a scalar is required. |
| `E_FORMULA_UNIT_MISMATCH` | Units that must agree do not. |
| `E_FORMULA_UNIT_OFFSET` | An offset unit where only differences make sense. |
| `E_FORMULA_UNIT_UNKNOWN` | A unit that cannot be determined statically. |
| `E_FORMULA_EXPONENT` | A unit-bearing base with a non-literal exponent; a unit exponent; `sqrt` of an odd power. |
| `E_FORMULA_RETURN_TYPE` | The body's type differs from `signature.returns`. |
| `E_FORMULA_RETURN_UNIT` | The body's unit differs from the declared return unit. |
| `E_FORMULA_UNBOUNDED` | An open or non-enumerable argument over a function without an extent, or a slice of more than 1,048,576 cells (15.13). |
| `E_FORMULA_SLICE_BOUND` | A range over a boolean or blob argument. |
| `E_FORMULA_METRIC` | A metric lookup on a dimension without a metric; a bound in the wrong unit. |
| `E_FORMULA_ALONG` | A lookup or scan whose dimension cannot be chosen. |
| `E_FORMULA_JOIN` | An operator over two slices with different key names or types. |
| `E_FORMULA_LAMBDA_PARAM` | A lambda parameter after the first that is not an open argument. |
| `E_FORMULA_LAMBDA_READ` | A cell read inside a lambda. |
| `E_FORMULA_ENUM` | An enumeration argument not a literal from its list. |
| `E_FORMULA_TX_ARG` | The first argument of `asof(cell, T)` or `versions` is not a single-cell read. |
| `E_FORMULA_UNSUPPORTED` | Parsed but not in this revision: key-set arguments, the `point` metric, `ellipsoidal_distance`, `spline`. |
| `E_FORMULA_INPUTS` | A descriptor's `inputs` differs from the derived set. |
| `E_FORMULA_NOT_CANONICAL` | A descriptor's body is not the print of its AST. |
| `E_FORMULA_DIV_ZERO` | Fault: division or `mod` by zero; zero to a negative power. |
| `E_FORMULA_DOMAIN` | Fault: an argument outside an operation's domain. |
| `E_FORMULA_RANGE` | Fault: a result outside the canonical forms. |
| `E_FORMULA_EMPTY` | Fault: an aggregate that needs members over an empty slice (catchable). |
| `E_FORMULA_ABSENT` | Fault: a lookup with no qualifying member; a computed slice with a member without value (catchable). |
| `E_FORMULA_FUTURE` | Fault: `asof(c, T)` or `versions(c, f, T)` with `T` after the evaluation asof. |
| `E_FORMULA_NOT_COVERED` | A single-cell read with no value as of the asof: the cell has none either. |
| `E_FORMULA_BUDGET` | Fuel exhausted. |
| `E_FORMULA_CYCLE` | A cell reappears on the evaluation stack. |
| `E_FORMULA_DEPTH` | Evaluation deeper than the evaluator's limit. |

### 15.12 Evaluation

**Order.** Evaluation is strict and left to right, except: `if` evaluates only the chosen branch, `and` and `or` short-circuit, `otherwise` evaluates its fallback only on absence, and `let` always evaluates its value first. The lineage is exactly the reads performed, so this order is part of the semantics; the first fault in it is reported.

**Faults and absence.** A fault gives the cell no value. A mesh answers `not_covered` with the fault in the envelope's `fault` member (5.5), so that it is not mistaken for missing data. `E_FORMULA_NOT_COVERED` is plain `not_covered`. `E_FORMULA_BUDGET`, `E_FORMULA_CYCLE` and `E_FORMULA_DEPTH` are the mesh's failures: an `error` envelope with `E_EVAL_UNAVAILABLE`. `otherwise` catches only `E_FORMULA_EMPTY` and `E_FORMULA_ABSENT`, absences that the slice lineage proves; a single-cell read with no value cannot be caught (a receipt cannot list an absence), but `otherwise(at(f(*), k), 0)` can.

**`asof()`.** A body that contains `asof()`, or `latest` with a bound, is **asof-dependent**; the checker derives this statically. Its computed receipt's `asof` SHOULD be the evaluation asof (the request's `asof`, or the clock reading of the request), so that it recomputes there. Such receipts are one per requested asof, not one per version: the engine must not reuse one for another asof, and a mesh MUST NOT serve one as `ok` for a requested `asof` other than its own (5.5). Prefer a valid-time argument at a declared cadence to `asof()`.

**Fuel.** Fuel is normative, so that every evaluator exhausts a budget at the same point:

| Work | Fuel |
|---|---|
| each AST node evaluated | 1 |
| a single-cell read | 1, besides its node (the read inside `asof(c, T)` is not a node: only its arguments are) |
| a slice read | 1 + members, charged after the members are obtained (so a computed member's fault is reported first) |
| an aggregate over a slice of n members | n (`median`: n × the bit length of n); over scalars, only its nodes |
| a lookup over n members | n |
| `scan` over n | n |
| `window` with width w over a group of n members | (n - w + 1) × w: w for every member with w - 1 predecessors |
| `x ^ n`, `n` an integer | abs(n) |
| a non-integer power | 130 |
| `sqrt`, `exp`, `ln`, `sin`, `cos`, `atan2`, `haversine` | 10, 50, 80, 50, 50, 60, 400 |
| `upper`, `lower`, `trim`, `concat` | 1 + bytes of the result / 64, rounded down |
| a business day | 1 for every day examined while stepping or rolling (a modified following that falls into the next month counts the days of both directions) |

Free: enumeration literals (`method`, `convention`, `roll`, `weekend`, the unit of `convert`, the aggregate of `scan` and `window`, `along`) and lambda nodes, which are not evaluated nodes (a lambda's body costs per member); the read inside `versions`, whose arguments are nodes. A name's binding is relied on (8.2 rule 2) as soon as a read of it is attempted, even when the read then fails: `otherwise(sum(f(*)), 0)` over a slice with a faulting member has the binding start of `f` among its `asof` candidates.

Fuel is per request and covers the computed inputs it evaluates. Refused at define time: open arguments over functions without an extent, ranges that cannot be enumerated or that enumerate more than 1,048,576 cells, and the size limits of 15.3.

### 15.13 Slices and slice-as-lineage

**Writing a slice.** A read with at least one argument `*` or `[lo..hi]` is a slice. Range ends are expressions of the argument's type, inclusive; `lo > hi` in a written range is `E_FORMULA_DOMAIN`.

**Membership as of the evaluation asof A.** For a stored function, the cells of the function name, with the function hash it resolves to as of A, whose arguments match (bound arguments equal, ranges containing) and which have a version answering as of A; each member's value is that version's. For any other language, the cells of the declared extent (7) within the pattern; every one must have a value as of A, or the read is `E_FORMULA_ABSENT` as a whole.

**Extents.** An open argument over a function whose `lang` is not `stored`, without an `extent` for that argument, is `E_FORMULA_UNBOUNDED` at define time; a range over such an argument is allowed for `date` and integer-valued `number` arguments (enumerated daily, or by 1) and is otherwise `E_FORMULA_UNBOUNDED`; a range over a boolean or blob is `E_FORMULA_SLICE_BOUND`. A stored function's extent is its recorded cells: an unbounded slice over a long stored history is accepted and limited by fuel.

**Order.** Members are ordered by key tuple: the open arguments in ascending name order, each compared in its type's order (numbers numerically, dates and instants chronologically, strings by code point, `false` before `true`). `first`, `last`, scans and lookups use it.

**Empty slices.** `sum` is 0 and `count` 0; other aggregates are `E_FORMULA_EMPTY` and lookups `E_FORMULA_ABSENT`.

**Lookups** work along one dimension: the only open argument; otherwise the only open valid-time argument; otherwise the one named by `along` (`E_FORMULA_ALONG`). The other open arguments are group keys: a lookup over a k-dimensional slice gives a (k-1)-dimensional slice of the groups where it found a member, or a scalar when k = 1. The metric comes from the dimension's type: instants a duration (bound in `s`, `min`, `h` or `d`), dates days (`d`), numbers the absolute difference in their unit; strings, booleans and blobs have none (`E_FORMULA_METRIC`). **A bound narrows the read**, and the narrowed slice is what lineage records: `last_before(f(*), x, b)` reads `f([x - b..x])`; `first_after` `[x..x + b]`; `nearest`, `within` and `interpolate` `[x - b..x + b]`; `latest(s, b)` `[asof() - b..9999-12-31T23:59:59.999999Z]`; ends rounded inward to the key's precision and clamped to the type's range. Step interpolation is `last_before` within the bound: it needs no member after `x`. Linear interpolation is `v0 + ((v1 - v0) * (x - x0)) / (x1 - x0)` as dialect operations (instants in seconds, dates in days), from the members at or before and after `x`, both within the bound; an exact key gives its value.

**Joins.** `+ - * /` between two slices with the same open argument names and key types is an inner join on keys; between a slice and a scalar, the scalar applies to every member.

**Answering.** The version of a stored cell answering as of a time A is the receipt of that cell (with the function hash its name resolves to as of A) with the latest `tx` among those whose `tx` and `asof` are at or before A.

**Transaction-time reads.** `asof(c, T)` reads the version of `c` answering as of `T` (T after A: `E_FORMULA_FUTURE`); it is an ordinary single-cell input whose `asof` is at or before `T`, and `c`'s function name resolves as of `T` (a `T` before its binding began is `E_FORMULA_UNRESOLVED`). `versions(c, from, to)` is a version slice of the stored cell `c`. In both, the times are evaluated, and `E_FORMULA_FUTURE` reported, before the cell's arguments.

**Lineage.** A slice read is one `inputs` entry (8.1): `slice:<slice id>:<members hash>`, where the slice id is SHA-256 of the slice object's canonical bytes (4.4: a cell object with `*` or range objects, or a version slice `{"cell", "from", "to"}`) and the members hash is SHA-256 of the canonical bytes of the JSON array of the member receipt hashes, ascending (for an empty slice, of `[]`). The same slice read twice is one entry. Its **manifest**, `{"members": [...], "slice": {...}}`, is fetched by the entry; a mesh SHOULD serve it at `https://<mesh>/slice/<slice id>/<members hash>` as `application/json`; members are fetched as receipts by hash.

### 15.14 Excel compatibility

Excel's ranges are slices and Excel's positions are keys: a criteria column becomes an argument of the function that holds the values. Every supported or partial row has a vector (`excel/<function>`) showing equivalence on a sample input. The vectors are **documentation-derived**: each cites the Microsoft documentation page it follows (`doc`), uses inputs on which Excel's binary doubles give the exact decimal result, and compares irrational results after `ROUND`; no Excel was run. The FIND vector cites Microsoft's FIND/SEARCH troubleshooting page, because the FIND article linked from Microsoft's function index redirected to a retired page when checked on 2026-10-24.

| Excel | Status | Formula | Differences or reason |
|---|---|---|---|
| `SUM` | supported | `sum(s)`, `sum(a, b, …)` | Exact decimal, not double. |
| `AVERAGE` | supported | `mean(s)` | |
| `COUNT` | supported | `count(s)` | Members are typed: no "numbers only". |
| `COUNTA` | supported | `count(s)` | |
| `MIN` | supported | `min(s)` | An empty slice has no minimum, not 0. |
| `MAX` | supported | `max(s)` | As MIN. |
| `MEDIAN` | supported | `median(s)` | |
| `STDEV.S` | supported | `stdev(s)` | The fixed sequence of 15.9.2. |
| `STDEV.P` | supported | `stdev_p(s)` | |
| `IF` | supported | `if c then a else b`, `if(c, a, b)` | |
| `IFS` | partial | `if c1 then v1 else if c2 then v2 else …` | Needs a final `else`; Excel's `#N/A` has no equivalent. |
| `AND` | supported | `a and b`, `and(a, b, …)` | Booleans only. |
| `OR` | supported | `a or b`, `or(a, b, …)` | |
| `NOT` | supported | `not a` | |
| `ROUND` | supported | `round(x, digits)` | Half away from zero, as Excel. |
| `ROUNDUP` | supported | `round_up(x, digits)` | |
| `ROUNDDOWN` | supported | `round_down(x, digits)` | |
| `INT` | supported | `floor(x)` | |
| `FLOOR.MATH` | supported | `floor(x)` | One argument. |
| `CEILING.MATH` | supported | `ceiling(x)` | One argument. |
| `MOD` | supported | `mod(a, b)` | |
| `ABS` | supported | `abs(x)` | |
| `POWER` | supported | `x ^ y` | Non-integer exponents by POW-EXPLN. |
| `SQRT` | supported | `sqrt(x)` | SQRT-T40. |
| `EXP` | supported | `exp(x)` | 34 digits, not 15. |
| `LN` | supported | `ln(x)` | |
| `LOG` | partial | `ln(x) / ln(base)` | Two roundings: compare after `round`. |
| `LOG10` | partial | `ln(x) / ln(10)` | As LOG. |
| `SIN` | supported | `sin(x)` | Radians, or `deg`. |
| `COS` | supported | `cos(x)` | |
| `TAN` | partial | `sin(x) / cos(x)` | |
| `ATAN2` | supported | `atan2(y, x)` | **Excel's argument order is ATAN2(x, y).** |
| `ASIN` | partial | `atan2(x, sqrt(1 - x ^ 2))` | |
| `ACOS` | partial | `atan2(sqrt(1 - x ^ 2), x)` | |
| `ATAN` | partial | `atan2(x, 1)` | |
| `PI` | supported | `pi()` | 34 digits. |
| `DEGREES` | partial | `convert(x, "deg")` | Radians are dimensionless. |
| `RADIANS` | partial | `convert(x deg, "1")` | |
| `SUMPRODUCT` | supported | `sum(a(*) * b(*))` | Joined on keys, not positions. |
| `SUMIF` | partial | `sum(f(row: *, item: "bolt", region: *))`, or `sum(filter(s, x -> x > 5))` | Criteria become keys or predicates; wildcard criteria are not supported. |
| `SUMIFS` | partial | `sum(f(row: *, item: "nut", region: "north"))` | As SUMIF. |
| `AVERAGEIF` | partial | `mean(…)` | As SUMIF. |
| `AVERAGEIFS` | partial | `mean(…)` | As SUMIF. |
| `COUNTIF` | partial | `count(filter(s, v -> v > 25))` | As SUMIF. |
| `COUNTIFS` | partial | `count(f(…: "nut", …: "north"))` | As SUMIF. |
| `VLOOKUP` | partial | exact: `at(s, k)`; approximate (TRUE): `last_before(s, k)` | By key, not column index: the looked-up function is the column. |
| `HLOOKUP` | partial | `at(s, k)` | As VLOOKUP. |
| `XLOOKUP` | partial | `at`; match mode -1 `last_before`, 1 `first_after`; `if_not_found`: `otherwise(at(s, k), d)` | Wildcard and binary-search modes not supported. |
| `INDEX` | partial | `at(s, k)` with `MATCH` | Positions have no meaning in a slice. |
| `MATCH` | partial | `at(s, k)` inside INDEX | MATCH alone (a position) is not supported. |
| `EDATE` | supported | `add_months(d, n)` | |
| `EOMONTH` | supported | `end_of_month(add_months(d, n))` | |
| `NETWORKDAYS` | supported | `business_days(a, b, calendar: …)` | Holidays are a calendar slice; a weekend parameter. |
| `WORKDAY` | supported | `add_days(d, n, calendar: …)` | As NETWORKDAYS. |
| `YEARFRAC` | partial | `year_fraction(a, b, "30/360_us" / "act/360" / "act/365f" / "30e/360")` for bases 0, 2, 3, 4 | Basis 1 (Excel's actual/actual) is not supported; `"act/act_isda"` is near it and differs. |
| `DATE` | supported | `date(y, m, d)` | No overflow of months or days: `E_FORMULA_DOMAIN`. |
| `YEAR` | supported | `year(d)` | |
| `MONTH` | supported | `month(d)` | |
| `DAY` | supported | `day(d)` | |
| `WEEKDAY` | supported | `mod(weekday(d), 7) + 1` | `weekday` is ISO (Monday 1). |
| `LEN` | supported | `len(s)` | Code points, not UTF-16 units. |
| `LEFT` | supported | `substr(s, 1, n)` | |
| `RIGHT` | supported | `substr(s, len(s) - n + 1, n)` | |
| `MID` | supported | `substr(s, i, n)` | |
| `CONCAT` | supported | `concat(a, b, …)` | The result is NFC. |
| `CONCATENATE` | supported | `a & b & …` | |
| `FIND` | supported | `find(needle, s, [start])` | 0 when not found, not `#VALUE!`. |
| `SEARCH` | partial | `find(lower(needle), lower(s))` | No wildcards. |
| `UPPER` | supported | `upper(s)` | Unicode case mapping. |
| `LOWER` | supported | `lower(s)` | |
| `TRIM` | supported | `trim(s)` | |
| `FIXED` | supported | `fixed(x, n)` | With `no_commas` TRUE. |
| `IFERROR` | partial | `otherwise(x, y)` for slice absence; arithmetic: `if b = 0 then y else a / b` | Arithmetic faults are not catchable (15.12). |
| `IFNA` | partial | `otherwise(x, y)` | |
| `TEXT` | not supported | `text(x)`, `fixed(x, n)` | Format strings are locale-dependent. |
| `VALUE` | not supported | none | Locale-dependent parsing. |
| `NOW` | not supported | `asof()` or a valid-time argument | Purity: no clock. |
| `TODAY` | not supported | `date_of(asof())` or a valid-time argument | Purity: no clock. |
| `RAND` | not supported | none: publish random values as stored cells | Purity: no randomness. |
| `RANDBETWEEN` | not supported | none | As RAND. |
| `INDIRECT` | not supported | none | Inputs must be static. |
| `OFFSET` | not supported | a bounded slice with a static shape | Dynamic ranges cannot be derived statically. |

What Excel users will miss first: `IFERROR` over arithmetic, `TEXT` format strings, wildcard criteria, positions (`INDEX` by row number, `MATCH`, `OFFSET`), `NOW()`, and that results have 34 digits where Excel shows 15.

### 15.15 Reserved for classes (1.3b)

Three forms are reserved so that 1.3b can add meaning without changing any 0.4.0 body:

1. **Method chaining.** `postfix = primary *( "." name "(" [ args ] ")" )`: `rates.example.org/fx_pair(base: "EUR", quote: "USD").forward(tenor: "1M")`. `).` is `E_FORMULA_RESERVED` now. A method call will resolve to a read of the method's function with the object's keys as its first arguments (by `signature.order`), so its canonical AST, and hash, equal those of the plain read.
2. **Key literals.** A word with a capital letter not followed by `(` (`EUR`) and digits followed by `D`, `M` or `Y` (`1M`, `10Y`) are reserved for class keys; in 1.3b they are strings checked by the class's key normalisation and printed quoted, so `fx_pair(EUR, USD)` and `fx_pair("EUR", "USD")` will have one AST. `1W` stays one watt; a one-week tenor is `7D`.
3. **Class-typed keys.** When a callee's parameter is declared with a class type (1.3b), a call in that position will be the object's key, not a read and not an input. The distinction is made at resolution from the callee's signature, with an AST node kind `key`; 0.4.0 signatures cannot declare class types, so every 0.4.0 body keeps meaning a read.

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

input-entry   = 64HEXLOW / slice-entry                                    ; 8.1
slice-entry   = "slice:" 64HEXLOW ":" 64HEXLOW                            ; slice id, members hash (15.13)
```

The formula dialect (section 15). A PEG: alternatives are tried in order; tokens by longest match
(15.2), whitespace (SP, HTAB, LF) between any two tokens.

```
formula-body   = expr
expr           = or-expr / if-expr / let-expr
if-expr        = "if" expr "then" expr "else" expr
let-expr       = "let" name "=" expr "in" expr
or-expr        = and-expr *( "or" and-expr )
and-expr       = not-expr *( "and" not-expr )
not-expr       = "not" not-expr / cmp-expr
cmp-expr       = cat-expr [ cmp-op cat-expr ]                    ; no chains
cmp-op         = "=" / "<>" / "<" / "<=" / ">" / ">="
cat-expr       = add-expr *( "&" add-expr )
add-expr       = mul-expr *( ( "+" / "-" ) mul-expr )
mul-expr       = unary *( ( "*" / "/" ) unary )
unary          = 1*"-" postfix / power                           ; "-" never takes a power
power          = postfix [ "^" *"-" postfix ]                    ; no chains
postfix        = primary                                         ; "." is reserved (15.15)
primary        = formula-literal / read / call / variable / "(" expr ")"
formula-literal = number-literal [ unit-suffix ] / string / date / instant / "true" / "false"
read           = ( qualified-name / alias ) "(" [ read-arg *( "," read-arg ) ] ")"
read-arg       = [ arg-label ] ( "*" / range / expr )                ; "*" followed by "," or ")"
range          = "[" expr ".." expr "]"
call           = builtin "(" [ call-arg *( "," call-arg ) ] ")"  ; and "if", "and", "or" (15.3)
call-arg       = [ arg-label ] ( lambda / expr )
lambda         = name "->" expr / "(" name *( "," name ) ")" "->" expr
arg-label      = name ":"
variable       = name
qualified-name = dns-name 1*( "/" name )                         ; longest match (15.2 L3)
alias          = "@" name *( "/" name )
unit-suffix    = *( SP / HTAB ) unit-literal                     ; the longest listed unit (15.2 L6)
number-literal = ( "0" / %x31-39 *DIGIT ) [ "." *DIGIT %x31-39 ]  ; canonical, non-negative
string         = DQUOTE *( string-char / 2DQUOTE ) DQUOTE      ; string-char: 3.5, not DQUOTE
builtin        = <a word naming a built-in of 15.7, any case>
unit-literal   = <a unit of units.md other than "1", or an index unit>
```
