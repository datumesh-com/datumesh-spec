#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate vectors/ deterministically.

Every vector is run through tools/canon.py while it is generated. A valid
vector takes its canonical bytes, hash and signature from canon.py; an
invalid vector states its expected error code here, by hand, and generation
stops if canon.py disagrees. Keys come from fixed seeds, and Ed25519 is
deterministic, so re-running this script reproduces vectors/ byte for byte.

    python3 tools/gen_vectors.py
"""

import hashlib
import json
import pathlib
import shutil
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import canon  # noqa: E402

ROOT = canon.ROOT
OUT = ROOT / "vectors"
VECTORS = []
OUTPUT_FIELDS = ("object", "canonical", "sha256", "https", "key_id", "key_ids", "sig", "level", "blob_checked",
                 "code", "unit", "outcome", "trust", "receipt_hash",
                 # spec-0.4.0 (SPEC 11): slices, the formula dialect, decimal cases
                 "slice_id", "members_hash", "entry", "ast", "ast_sha256", "body", "inputs", "returns", "asof_dependent",
                 "value", "lineage", "tx", "receipt_asof", "fuel_used", "results",
                 # spec-0.4.1: mesh documents
                 "bindings", "endpoints")


# Vectors from spec-0.1.1 whose bytes changed in spec-0.2.0, and why. tests/test_migration.py
# checks this list against the spec-0.1.1 vectors in both directions.
CHANGED_0_2_0 = {
    "function": "the descriptor now declares units (SPEC 7.1), so its bytes and function hash changed",
    "cell": "fn_hash is the hash of a descriptor that now declares units",
    "uri": "the signature input now declares units; the outputs are unchanged",
    "receipt": "the cell's fn_hash changed because its descriptor now declares units, so the receipt bytes, "
               "hash and signature changed",
}
CHANGED_IDS = """
cell/fx-rate cell/idn-a-label cell/max-arguments cell/namespace-path cell/no-arguments cell/slice
function/computed-convert function/no-arguments function/stored-fx-rate
invalid/cell-arg-camel-case invalid/cell-arg-double-underscore invalid/cell-arg-name-too-long
invalid/cell-arg-reserved-asof invalid/cell-arg-reserved-prefix invalid/cell-duplicate-argument
invalid/cell-fn-hash-uppercase invalid/cell-function-camel-case invalid/cell-numeric-tld
invalid/cell-single-label-namespace invalid/cell-too-many-arguments invalid/cell-trailing-dot
invalid/cell-unicode-namespace invalid/cell-untyped-argument invalid/cell-uppercase-namespace
invalid/function-body-cr invalid/function-inputs-alias invalid/function-inputs-unsorted invalid/function-valid-number
invalid/receipt-arg-missing invalid/receipt-arg-type invalid/receipt-arg-unknown invalid/receipt-computed-by-bare-key-id
invalid/receipt-computed-tx invalid/receipt-duplicate-member invalid/receipt-empty-summary invalid/receipt-extra-member
invalid/receipt-fn-hash-mismatch invalid/receipt-fn-unavailable invalid/receipt-input-invalid
invalid/receipt-input-unavailable invalid/receipt-input-undeclared invalid/receipt-inputs-unsorted
invalid/receipt-key-expired invalid/receipt-key-not-yet-valid invalid/receipt-key-unavailable invalid/receipt-licence
invalid/receipt-missing-member invalid/receipt-publisher-mismatch invalid/receipt-return-type
invalid/receipt-sig-uppercase invalid/receipt-slice invalid/receipt-tampered-value invalid/receipt-tx-after-asof
invalid/receipt-unknown-key invalid/receipt-valid-mismatch invalid/receipt-value-form invalid/receipt-value-mismatch
invalid/receipt-value-type-mismatch invalid/receipt-wrong-proto invalid/receipt-wrong-signer
invalid/uri-alias invalid/uri-asof-milliseconds invalid/uri-asof-not-last invalid/uri-asof-twice invalid/uri-bad-utf8
invalid/uri-boolean-form invalid/uri-duplicate invalid/uri-empty-query invalid/uri-fragment invalid/uri-lowercase-hex
invalid/uri-missing-argument invalid/uri-needless-encoding invalid/uri-nfd-string invalid/uri-number-form
invalid/uri-parameter-without-value invalid/uri-plus-for-space invalid/uri-raw-unicode invalid/uri-unknown-argument
invalid/uri-unsorted invalid/uri-uppercase-host invalid/uri-wrong-scheme
receipt/computed-two-inputs receipt/computed-with-lineage receipt/date-value receipt/historical-asof
receipt/rotated-key receipt/stored-number receipt/stored-number-second receipt/string-value
uri/all-types uri/empty-string uri/fx-rate uri/fx-rate-asof uri/literal-star uri/no-arguments
uri/no-arguments-asof uri/reserved-characters uri/slice uri/unicode-string
""".split()


def add(id_, kind, description, input=None, error=None, input_hex=None, **extra):
    if id_ in CHANGED_IDS:
        description += f" Changed in spec-0.2.0: {CHANGED_0_2_0[kind]}."
    vec = {"id": id_, "kind": kind, "description": description, "valid": error is None}
    if input_hex is not None:
        vec["input_hex"] = input_hex
    elif input is not None:
        vec["input"] = input
    vec.update(extra)
    got = canon.run_vector(vec)
    if error is not None:
        if got.get("error") != error:
            raise SystemExit(f"{id_}: expected {error}, canon.py says {got.get('detail', 'valid')}")
        vec["error"] = error
    else:
        if "error" in got:
            raise SystemExit(f"{id_}: expected valid, canon.py says {got['detail']}")
        for field in OUTPUT_FIELDS:
            if field in got:
                vec[field] = got[field]
    VECTORS.append(vec)


def messy(obj):
    """Reverse member order at every level, so inputs are not already canonical."""
    if isinstance(obj, dict):
        return {k: messy(obj[k]) for k in reversed(list(obj))}
    if isinstance(obj, list):
        return [messy(x) for x in obj]
    return obj


def text(obj):
    return json.dumps(messy(obj), indent=2, ensure_ascii=False)


def S(v):
    return {"type": "string", "value": v}


def N(v):
    return {"type": "number", "value": v}


def D(v):
    return {"type": "date", "value": v}


def I(v):
    return {"type": "instant", "value": v}


def B(v):
    return {"type": "boolean", "value": v}


# ---------------------------------------------------------------------------
# JCS (RFC 8785)

add("jcs/rfc8785-main-example", "jcs",
    "RFC 8785 section 3.2.2: number formatting, string escaping and member order.",
    '{\n  "numbers": [333333333.33333329, 1E30, 4.50,\n              2e-3, 0.000000000000000000000000001],\n'
    '  "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",\n  "literals": [null, true, false]\n}')
add("jcs/rfc8785-sorting", "jcs",
    "RFC 8785 section 3.2.3: members sorted by UTF-16 code units, so U+1F600 sorts before U+FB33.",
    '{"\\u20ac": "Euro Sign", "\\r": "Carriage Return", "\\ufb33": "Hebrew Letter Dalet With Dagesh",'
    ' "1": "One", "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control",'
    ' "\\u00f6": "Latin Small Letter O With Diaeresis"}')
add("jcs/rfc8785-numbers", "jcs",
    "RFC 8785 appendix B samples, including negative zero serialised as 0.",
    "[0, -0.0, 5e-324, -5e-324, 1.7976931348623157e308, 9007199254740992, 295147905179352830000,"
    " 9.999999999999997e22, 1e23, 1.0000000000000001e23, 999999999999999700000, 1e21,"
    " 9.999999999999997e-7, 0.000001, 333333333.3333332, 333333333.33333325, -0.0000033333333333333333,"
    " 1424953923781206.2]")
add("jcs/nested-whitespace", "jcs",
    "Insignificant whitespace is removed and nested members are sorted.",
    ' {\n\t"z" : [ {"b":1, "a":2} ],\r\n "a" : { } } ')
add("jcs/escapes", "jcs",
    "Only quote, backslash and C0 controls are escaped; DEL, U+2028 and non-ASCII stay literal.",
    '["\\u0000\\u001f\\b\\f\\n\\r\\t", "\\u007f\\u2028\\u00e9", "\\"\\\\\\/"]')

# ---------------------------------------------------------------------------
# Typed scalars

for name, scalar, why in [
    ("number-integer", N("42"), "An integer."),
    ("number-negative", N("-17.25"), "A negative decimal."),
    ("number-zero", N("0"), "Zero has exactly one form."),
    ("number-small", N("0.000001"), "Small magnitudes are written out; there is no exponent form."),
    ("number-large", N("123456789012345678901234567890123456789012"),
     "Integers beyond 2^53 are exact because numbers are decimal strings, not JSON numbers."),
    ("number-max-length", N("-" + "9" * 63 + "." + "9" * 62 + "1"), "A 128-character number, the maximum."),
    ("string-ascii", S("EUR"), "A plain ASCII string."),
    ("string-empty", S(""), "The empty string is a value."),
    ("string-nfc", S("Zürich"), "Precomposed ü (U+00FC) is NFC."),
    ("string-emoji-zwj", S("👩‍💻"), "An emoji ZWJ sequence; U+200D is allowed."),
    ("string-scripts", S("東京 · مرحبا · Ελλάδα"), "CJK, Arabic and Greek in one NFC string."),
    ("string-quotes", S('He said "hi" \\ ok'), "Quotes and backslashes are escaped by JCS."),
    ("string-iana-zone", S("America/Argentina/Buenos_Aires"), "A time zone is an IANA name in a string argument."),
    ("string-max-bytes", S("é" * 512), "512 two-byte characters: 1024 UTF-8 bytes, the maximum."),
    ("string-astral-max", S("😀" * 256), "256 four-byte characters: 1024 UTF-8 bytes, the maximum."),
    ("boolean-true", B(True), "A boolean is a JSON true."),
    ("boolean-false", B(False), "A boolean is a JSON false."),
    ("date-ordinary", D("2024-03-15"), "A calendar date."),
    ("date-leap-day", D("2024-02-29"), "29 February in a leap year."),
    ("date-min", D("0001-01-01"), "The earliest date."),
    ("date-max", D("9999-12-31"), "The latest date."),
    ("instant-epoch", I("1970-01-01T00:00:00.000000Z"), "The Unix epoch."),
    ("instant-microseconds", I("2024-03-15T16:00:00.123456Z"), "Microsecond precision."),
    ("instant-before-leap-second", I("2016-12-31T23:59:59.999999Z"), "The last microsecond before a leap second."),
    ("instant-max", I("9999-12-31T23:59:59.999999Z"), "The latest instant."),
]:
    add(f"scalar/{name}", "scalar", why, text(scalar))

add("scalar/escaped-input", "scalar",
    "JSON escapes in the input are decoded; the canonical form is literal UTF-8.",
    '{"value":"Z\\u00fcrich","type":"string"}')

for name, raw, error, why in [
    ("number-trailing-zero", text(N("1.50")), "E_CANON_NUMBER", "Trailing fractional zeros are rejected, not stripped."),
    ("number-leading-zero", text(N("007")), "E_CANON_NUMBER", "Leading zeros are rejected."),
    ("number-negative-zero", text(N("-0")), "E_CANON_NUMBER", "Negative zero is rejected; zero is \"0\"."),
    ("number-exponent", text(N("1e5")), "E_CANON_NUMBER", "Exponent notation is rejected."),
    ("number-plus-sign", text(N("+1")), "E_CANON_NUMBER", "A leading plus sign is rejected."),
    ("number-bare-point", text(N(".5")), "E_CANON_NUMBER", "A fraction needs a leading 0."),
    ("number-trailing-point", text(N("5.")), "E_CANON_NUMBER", "A trailing decimal point is rejected."),
    ("number-nan", text(N("NaN")), "E_CANON_NUMBER", "NaN is not a number value."),
    ("number-arabic-digits", text(N("٤٢")), "E_CANON_NUMBER", "Only ASCII digits."),
    ("number-json-number", '{"type":"number","value":1.5}', "E_SCHEMA", "Numbers are decimal strings, never JSON numbers."),
    ("number-too-long", text(N("1" * 129)), "E_CANON_LIMIT", "129 characters exceeds the limit."),
    ("string-nfd", text(S("Zürich")), "E_CANON_STRING", "Decomposed u + U+0308 is not NFC; it is rejected, not normalised."),
    ("string-bell", text(S("a\u0007b")), "E_CANON_STRING", "C0 control characters are rejected."),
    ("string-newline", text(S("a\nb")), "E_CANON_STRING", "Newline is a control character."),
    ("string-c1-control", text(S("a\u0085b")), "E_CANON_STRING", "C1 control characters are rejected."),
    ("string-unassigned", text(S("a͸")), "E_CANON_STRING", "U+0378 is unassigned."),
    ("string-noncharacter", text(S("￿")), "E_CANON_STRING", "U+FFFF is a noncharacter."),
    ("string-unicode-16", text(S("Ᲊ")), "E_CANON_STRING", "U+1C89 was assigned in Unicode 16.0, after the pinned 15.1."),
    ("string-lone-surrogate", '{"type":"string","value":"\\ud800"}', "E_PARSE_JSON", "A lone surrogate is not a Unicode string."),
    ("string-too-long", text(S("é" * 512 + "a")), "E_CANON_LIMIT", "1025 UTF-8 bytes exceeds the limit."),
    ("boolean-as-string", text(S("x") | {"type": "boolean", "value": "true"}), "E_CANON_TYPE", "A boolean is JSON true, not the string \"true\"."),
    ("date-not-leap-year", text(D("2023-02-29")), "E_CANON_DATE", "2023 is not a leap year."),
    ("date-month-13", text(D("2024-13-01")), "E_CANON_DATE", "There is no month 13."),
    ("date-year-zero", text(D("0000-01-01")), "E_CANON_DATE", "Year 0000 is outside the range."),
    ("date-unpadded", text(D("2024-3-15")), "E_CANON_DATE", "Months and days have two digits."),
    ("instant-leap-second", text(I("2016-12-31T23:59:60.000000Z")), "E_CANON_INSTANT", "Leap seconds are rejected."),
    ("instant-milliseconds", text(I("2024-03-15T16:00:00.123Z")), "E_CANON_INSTANT", "Exactly six fractional digits."),
    ("instant-no-fraction", text(I("2024-03-15T16:00:00Z")), "E_CANON_INSTANT", "The fraction is mandatory."),
    ("instant-offset", text(I("2024-03-15T17:00:00.000000+01:00")), "E_CANON_INSTANT", "Only UTC, written Z."),
    ("instant-lowercase", text(I("2024-03-15t16:00:00.000000z")), "E_CANON_INSTANT", "T and Z are uppercase."),
    ("type-unknown", text({"type": "decimal", "value": "1"}), "E_CANON_TYPE", "There are exactly six types."),
    ("extra-member", text(S("EUR") | {"unit": "x"}), "E_SCHEMA", "A typed scalar has exactly type and value."),
    ("null-value", '{"type":"string","value":null}', "E_SCHEMA", "null is not a value."),
    ("duplicate-member", '{"type":"string","type":"number","value":"1"}', "E_PARSE_DUPLICATE_KEY", "Duplicate JSON members are rejected, not resolved."),
    ("not-json", '{"type":"string","value":"EUR"', "E_PARSE_JSON", "Truncated JSON."),
]:
    add(f"invalid/scalar-{name}", "scalar", why, raw, error)

add("invalid/scalar-bad-utf8", "scalar", "The input bytes are not UTF-8.",
    error="E_PARSE_JSON", input_hex=('{"type":"string","value":"'.encode() + b"\xc3\x28" + b'"}').hex())

# ---------------------------------------------------------------------------
# Function descriptors

FX = {
    "code": {"body": "", "lang": "stored"},
    "inputs": [],
    "signature": {
        "args": {
            "base": {"type": "string", "valid": False},
            "date": {"type": "date", "valid": True},
            "quote": {"type": "string", "valid": False},
        },
        "returns": {"type": "number", "unit": {"of": {"arg": "quote"}, "per": {"arg": "base"}}},
    },
}
CONVERT = {
    "code": {
        "body": "amount * rates.example.org/fx_rate(base: base, date: date, quote: quote)\n",
        "lang": "expr",
    },
    "inputs": ["rates.example.org/fx_rate"],
    "signature": {
        "args": {
            "amount": {"type": "number", "unit": {"arg": "base"}, "valid": False},
            "base": {"type": "string", "valid": False},
            "date": {"type": "date", "valid": True},
            "quote": {"type": "string", "valid": False},
        },
        "returns": {"type": "number", "unit": {"arg": "quote"}},
    },
}
HOLIDAY = {
    "code": {"body": "", "lang": "stored"},
    "inputs": [],
    "signature": {
        "args": {
            "calendar": {"type": "string", "valid": False},
            "date": {"type": "date", "valid": True},
        },
        "returns": "boolean",
    },
}
LAST_TRADE = {
    "code": {"body": "", "lang": "stored"},
    "inputs": [],
    "signature": {
        "args": {"symbol": {"type": "string", "valid": False}},
        "returns": "instant",
    },
}
PI = {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": {"args": {}, "returns": {"type": "number", "unit": "1"}}}
FX_HASH, CONVERT_HASH = canon.function_hash(FX), canon.function_hash(CONVERT)

add("function/stored-fx-rate", "function",
    "A stored function: no code, no inputs. Its hash is the fn_hash in fx_rate cells.", text(FX))
add("function/computed-convert", "function",
    "A computed function that declares one input function.", text(CONVERT))
add("function/no-arguments", "function", "A function of no arguments.", text(PI))
add("invalid/function-inputs-unsorted", "function", "Declared inputs are a set: sorted, no duplicates.",
    text(CONVERT | {"inputs": ["z.example/b", "a.example/a"]}), "E_CANON_SET")
add("invalid/function-inputs-alias", "function", "Declared inputs are fully qualified; a short alias is not a name.",
    text(CONVERT | {"inputs": ["ecb/fx_rate"]}), "E_CANON_NAME")
add("invalid/function-body-cr", "function", "Function bodies use LF line endings; CR is a control character.",
    text(CONVERT | {"code": {"body": "a\r\nb", "lang": "expr"}}), "E_CANON_STRING")
add("invalid/function-valid-number", "function", "A valid-time argument must be a date, instant or string.",
    text({**FX, "signature": {"args": {"n": {"type": "number", "unit": "1", "valid": True}},
                               "returns": {"type": "number", "unit": "1"}}}), "E_CANON_TYPE")

# ---------------------------------------------------------------------------
# Cells (resolved: with fn_hash)

FX_ARGS = {"base": S("EUR"), "date": D("2024-03-15"), "quote": S("USD")}
FX_CELL = {"args": FX_ARGS, "fn": "fx_rate", "fn_hash": FX_HASH, "ns": "rates.example.org"}

add("cell/fx-rate", "cell", "A cell: namespace, function, function hash and typed arguments.", text(FX_CELL))
add("cell/namespace-path", "cell", "A namespace may carry path segments after the DNS name.",
    text(FX_CELL | {"ns": "example.org/central_bank/stats"}))
add("cell/idn-a-label", "cell", "Internationalised domain names appear as A-labels.",
    text(FX_CELL | {"ns": "xn--bcher-kva.example"}))
add("cell/no-arguments", "cell", "A cell of a function with no arguments.",
    text({"args": {}, "fn": "pi", "fn_hash": canon.function_hash(PI), "ns": "math.example"}))
add("cell/slice", "cell", "A slice: an argument bound to \"*\". Canonicalisable, never a receipt.",
    text(FX_CELL | {"args": FX_ARGS | {"date": "*"}}))
add("cell/max-arguments", "cell", "32 arguments, the maximum.",
    text(FX_CELL | {"args": {f"a{i:02d}": N(str(i)) for i in range(32)}}))

for name, cell, error, why in [
    ("uppercase-namespace", FX_CELL | {"ns": "Rates.Example.org"}, "E_CANON_NAME", "Namespaces are lowercase; they are rejected, not folded."),
    ("single-label-namespace", FX_CELL | {"ns": "ecb"}, "E_CANON_NAME", "A short alias like ecb never appears in hashed data."),
    ("unicode-namespace", FX_CELL | {"ns": "bücher.example"}, "E_CANON_NAME", "U-labels are rejected; use the A-label."),
    ("trailing-dot", FX_CELL | {"ns": "rates.example.org."}, "E_CANON_NAME", "No trailing dot."),
    ("numeric-tld", FX_CELL | {"ns": "192.168.0.1"}, "E_CANON_NAME", "IP addresses are not namespaces."),
    ("function-camel-case", FX_CELL | {"fn": "fxRate"}, "E_CANON_NAME", "Function names are lowercase snake_case."),
    ("arg-camel-case", FX_CELL | {"args": {"baseCurrency": S("EUR")}}, "E_CANON_ARG_NAME", "Argument names are lowercase snake_case."),
    ("arg-double-underscore", FX_CELL | {"args": {"base__ccy": S("EUR")}}, "E_CANON_ARG_NAME", "snake_case has single underscores between words."),
    ("arg-reserved-asof", FX_CELL | {"args": FX_ARGS | {"asof": I("2024-03-15T00:00:00.000000Z")}}, "E_CANON_ARG_NAME", "asof is protocol-level, never an argument."),
    ("arg-reserved-prefix", FX_CELL | {"args": FX_ARGS | {"dm_version": S("1")}}, "E_CANON_ARG_NAME", "Names starting dm_ are reserved."),
    ("arg-name-too-long", FX_CELL | {"args": {"a" * 65: S("x")}}, "E_CANON_LIMIT", "Argument names are at most 64 characters."),
    ("too-many-arguments", FX_CELL | {"args": {f"a{i:02d}": N(str(i)) for i in range(33)}}, "E_CANON_LIMIT", "33 arguments exceeds the limit."),
    ("fn-hash-uppercase", FX_CELL | {"fn_hash": FX_HASH.upper()}, "E_CANON_HEX", "Hashes are lowercase hex."),
    ("untyped-argument", FX_CELL | {"args": FX_ARGS | {"base": "EUR"}}, "E_SCHEMA", "Arguments are typed scalars."),
    ("missing-fn-hash", {k: v for k, v in FX_CELL.items() if k != "fn_hash"}, "E_SCHEMA", "A resolved cell pins its function hash."),
]:
    add(f"invalid/cell-{name}", "cell", why, text(cell), error)

add("invalid/cell-duplicate-argument", "cell", "A duplicated argument is a duplicate JSON member.",
    '{"args":{"base":{"type":"string","value":"EUR"},"base":{"type":"string","value":"GBP"}},'
    f'"fn":"fx_rate","fn_hash":"{FX_HASH}","ns":"rates.example.org"}}', "E_PARSE_DUPLICATE_KEY")

# ---------------------------------------------------------------------------
# Cell URIs

SIG = FX["signature"]
ALL_TYPES = {
    "args": {
        "active": {"type": "boolean", "valid": False},
        "at": {"type": "instant", "valid": True},
        "label": {"type": "string", "valid": False},
        "ratio": {"type": "number", "unit": "1", "valid": False},
    },
    "returns": "string",
}

for name, uri, sig, why in [
    ("fx-rate", "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD",
     SIG, "Arguments sorted by name; asof omitted means now."),
    ("fx-rate-asof", "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD&asof=2024-03-16T09:00:00.000000Z",
     SIG, "asof is the last parameter and is not sorted with the arguments."),
    ("slice", "cell://rates.example.org/fx_rate?base=EUR&date=*&quote=USD",
     SIG, "A bare * is a slice over that argument."),
    ("literal-star", "cell://rates.example.org/fx_rate?base=%2A&date=2024-03-15&quote=USD",
     SIG, "The string \"*\" is percent-encoded, so it cannot be mistaken for a slice."),
    ("empty-string", "cell://rates.example.org/fx_rate?base=&date=2024-03-15&quote=USD",
     SIG, "An empty value is the empty string."),
    ("unicode-string", "cell://rates.example.org/fx_rate?base=Z%C3%BCrich%20Hbf&date=2024-03-15&quote=%E2%82%AC",
     SIG, "Non-literal characters are UTF-8, percent-encoded with uppercase hex."),
    ("reserved-characters", "cell://rates.example.org/fx_rate?base=a%26b%3Dc%2Bd%2Fe%3Ff%25&date=2024-03-15&quote=USD",
     SIG, "& = + / ? and % are always percent-encoded."),
    ("all-types", "cell://example.org/sensors/reading?active=true&at=2024-03-15T16:00:00.000000Z&label=north-gate_2&ratio=-0.25",
     ALL_TYPES, "Booleans, instants (colons are literal), strings and numbers; a namespace path segment."),
    ("no-arguments", "cell://math.example/pi", PI["signature"], "A function of no arguments has no query."),
    ("no-arguments-asof", "cell://math.example/pi?asof=2024-01-01T00:00:00.000000Z", PI["signature"],
     "asof alone."),
]:
    add(f"uri/{name}", "uri", why, uri, signature=sig)

for name, uri, sig, error, why in [
    ("unsorted", "cell://rates.example.org/fx_rate?quote=USD&base=EUR&date=2024-03-15", SIG, "E_CANON_ARG_ORDER", "Arguments must be sorted; the URI is canonical."),
    ("duplicate", "cell://rates.example.org/fx_rate?base=EUR&base=GBP&date=2024-03-15&quote=USD", SIG, "E_CANON_ARG_DUPLICATE", "An argument appears once."),
    ("asof-not-last", "cell://rates.example.org/fx_rate?asof=2024-03-16T09:00:00.000000Z&base=EUR&date=2024-03-15&quote=USD", SIG, "E_CANON_ARG_ORDER", "asof comes last."),
    ("asof-twice", "cell://math.example/pi?asof=2024-01-01T00:00:00.000000Z&asof=2024-01-01T00:00:00.000000Z", PI["signature"], "E_CANON_ARG_DUPLICATE", "asof appears at most once."),
    ("missing-argument", "cell://rates.example.org/fx_rate?base=EUR&quote=USD", SIG, "E_ARG_MISSING", "A slice is written date=*; omission is an error."),
    ("unknown-argument", "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD&zone=UTC", SIG, "E_ARG_UNKNOWN", "Undeclared arguments are rejected."),
    ("lowercase-hex", "cell://rates.example.org/fx_rate?base=Z%c3%bcrich&date=2024-03-15&quote=USD", SIG, "E_CANON_PERCENT", "Percent-encoding uses uppercase hex."),
    ("needless-encoding", "cell://rates.example.org/fx_rate?base=%45UR&date=2024-03-15&quote=USD", SIG, "E_CANON_PERCENT", "Literal characters must not be percent-encoded."),
    ("plus-for-space", "cell://rates.example.org/fx_rate?base=New+York&date=2024-03-15&quote=USD", SIG, "E_CANON_PERCENT", "+ is not a space; a space is %20."),
    ("raw-unicode", "cell://rates.example.org/fx_rate?base=Zürich&date=2024-03-15&quote=USD", SIG, "E_CANON_PERCENT", "Non-ASCII must be percent-encoded."),
    ("bad-utf8", "cell://rates.example.org/fx_rate?base=%FF&date=2024-03-15&quote=USD", SIG, "E_CANON_PERCENT", "Percent-encoded bytes must be UTF-8."),
    ("nfd-string", "cell://rates.example.org/fx_rate?base=Zu%CC%88rich&date=2024-03-15&quote=USD", SIG, "E_CANON_STRING", "Decoded strings follow the string rules, including NFC."),
    ("number-form", "cell://example.org/sensors/reading?active=true&at=2024-03-15T16:00:00.000000Z&label=x&ratio=-0.250", ALL_TYPES, "E_CANON_NUMBER", "Numbers in URIs follow the number rules."),
    ("boolean-form", "cell://example.org/sensors/reading?active=TRUE&at=2024-03-15T16:00:00.000000Z&label=x&ratio=1", ALL_TYPES, "E_CANON_TYPE", "Booleans are true or false."),
    ("asof-milliseconds", "cell://math.example/pi?asof=2024-01-01T00:00:00.000Z", PI["signature"], "E_CANON_INSTANT", "asof has microsecond precision."),
    ("uppercase-host", "cell://Rates.Example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD", SIG, "E_CANON_NAME", "Hosts are lowercase."),
    ("alias", "cell://ecb/fx_rate?base=EUR&date=2024-03-15&quote=USD", SIG, "E_CANON_NAME", "Aliases are resolved before a URI is formed."),
    ("fragment", "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD#x", SIG, "E_PARSE_URI", "Cell URIs have no fragment."),
    ("empty-query", "cell://math.example/pi?", PI["signature"], "E_PARSE_URI", "A ? needs at least one parameter."),
    ("wrong-scheme", "https://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD", SIG, "E_PARSE_URI", "The scheme is cell."),
    ("parameter-without-value", "cell://rates.example.org/fx_rate?base&date=2024-03-15&quote=USD", SIG, "E_PARSE_URI", "Every parameter has =."),
    ("userinfo", "cell://user@rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD", SIG, "E_PARSE_URI", "A cell URI has no userinfo."),
    ("port", "cell://rates.example.org:443/fx_rate?base=EUR&date=2024-03-15&quote=USD", SIG, "E_PARSE_URI", "A cell URI has no port."),
    ("empty-port", "cell://rates.example.org:/fx_rate?base=EUR&date=2024-03-15&quote=USD", SIG, "E_PARSE_URI", "Not even an empty one."),
    ("port-not-numeric", "cell://rates.example.org:x/fx_rate?base=EUR&date=2024-03-15&quote=USD", SIG, "E_PARSE_URI", "Any : in the authority."),
    ("grammar-before-names", "cell://Rates.example.org/fx_rate?base", SIG, "E_PARSE_URI",
     "The outer grammar is checked before any name: the parameter without = is reported, not the uppercase host."),
]:
    add(f"invalid/uri-{name}", "uri", why, uri, error, signature=sig)

# ---------------------------------------------------------------------------
# Cell references (the JSON form a URI denotes)

add("ref/fx-rate-asof", "ref", "The JSON form of a cell URI: no fn_hash yet, asof optional.",
    text({"args": FX_ARGS, "asof": "2024-03-16T09:00:00.000000Z", "fn": "fx_rate", "ns": "rates.example.org"}))
add("invalid/ref-asof-offset", "ref", "asof is a UTC instant.",
    text({"args": FX_ARGS, "asof": "2024-03-16T10:00:00.000000+01:00", "fn": "fx_rate", "ns": "rates.example.org"}),
    "E_CANON_INSTANT")

# ---------------------------------------------------------------------------
# Keys


def seed(name):
    return hashlib.sha256(b"datumesh test vector key: " + name.encode()).digest()


def keypair_fields(name):
    _, public = canon.keypair(seed(name))
    return {"seed": seed(name).hex(), "public": public.hex(), "key_id": canon.key_id(public)}


def key_entry(name, valid_from, valid_to=None):
    kp = keypair_fields(name)
    entry = {"alg": "ed25519", "id": kp["key_id"], "public": kp["public"], "valid_from": valid_from}
    if valid_to:
        entry["valid_to"] = valid_to
    return entry


def https_env(host, *entries):
    doc = {"host": host, "keys": list(entries), "proto": canon.PROTO}
    return {"https": {"status": 200, "body": json.dumps(doc, indent=2)}}


T0 = "2020-01-01T00:00:00.000000Z"
ROTATE = "2024-06-01T00:00:00.000000Z"

for name in ("rates-2020", "calc-2020"):
    kp = keypair_fields(name)
    add(f"keyid/{name}", "keyid",
        "Key id: the first 16 hex digits of SHA-256 over the raw 32-byte Ed25519 public key.", kp["public"])

add("keys/https-document", "keys", "Keys come from https://<host>/.well-known/datumesh.json when it exists.",
    host="rates.example.org",
    env=https_env("rates.example.org", key_entry("rates-2020", T0, ROTATE), key_entry("rates-2024", ROTATE)))
add("invalid/keys-server-error", "keys", "Any status other than 200 is a retrieval failure; there is no fallback.",
    host="rates.example.org", env={"https": {"status": 503}}, error="E_KEY_UNAVAILABLE")
add("invalid/keys-not-found", "keys", "A 404 is a retrieval failure like any other: the host publishes no keys.",
    host="rates.example.org", env={"https": {"status": 404}}, error="E_KEY_UNAVAILABLE")
add("invalid/keys-redirect", "keys", "Redirects are not followed.",
    host="rates.example.org", env={"https": {"status": 301}}, error="E_KEY_UNAVAILABLE")
add("invalid/keys-network-error", "keys", "A network, DNS-resolution, TLS or timeout failure.",
    host="rates.example.org", env={"https": {"status": "error"}}, error="E_KEY_UNAVAILABLE")
add("invalid/keys-not-json", "keys", "A 200 response whose body is not a key document.",
    host="rates.example.org", env={"https": {"status": 200, "body": "<html>Not here</html>"}}, error="E_KEY_DOC")
add("invalid/keys-valid-to-before-from", "keys", "valid_to must be later than valid_from.",
    host="rates.example.org", env=https_env("rates.example.org", key_entry("rates-2020", ROTATE, T0)), error="E_KEY_DOC")
add("invalid/keys-duplicate-key", "keys", "The same key may not appear twice.",
    host="rates.example.org", env=https_env("rates.example.org", key_entry("rates-2020", T0), key_entry("rates-2020", ROTATE)), error="E_KEY_DOC")
bad_doc = json.loads(https_env("rates.example.org", key_entry("rates-2020", T0))["https"]["body"])
bad_doc["keys"][0]["id"] = "0000000000000000"
add("invalid/keys-wrong-id", "keys", "A key document whose id is not derived from its public key is rejected whole.",
    host="rates.example.org", env={"https": {"status": 200, "body": json.dumps(bad_doc)}}, error="E_KEY_DOC")
add("invalid/keys-host-mismatch", "keys", "A key document names the host it was fetched from.",
    host="rates.example.org", env=https_env("other.example.org", key_entry("rates-2020", T0)), error="E_KEY_DOC")
# ---------------------------------------------------------------------------
# Receipts

RATES = "rates.example.org"
CALC = "calc.example.net"
RATES_ENV = https_env(RATES, key_entry("rates-2020", T0, ROTATE), key_entry("rates-2024", ROTATE))
CALC_ENV = https_env(CALC, key_entry("calc-2020", T0))
KEYENV = {RATES: RATES_ENV, CALC: CALC_ENV}
ASOF = "2024-03-16T09:00:00.000000Z"


def receipt(cell, type_, value, summary, key, asof=ASOF, tx="2024-03-15T16:00:00.000000Z",
            issued=None, inputs=(), licence="CC-BY-4.0", valid=None, publisher=None):
    host = key.split("-")[0] + (".example.org" if key.startswith("rates") else ".example.net")
    if valid is None:
        valid = {k: v for k, v in cell["args"].items() if k in ("date", "at")}
    return {
        "asof": asof,
        "cell": cell,
        "computed_by": f"{host}#{keypair_fields(key)['key_id']}",
        "inputs": list(inputs),
        "issued": issued or asof,
        "licence": licence,
        "proto": canon.PROTO,
        "publisher": publisher or cell["ns"],
        "summary": summary,
        "tx": tx,
        "type": type_,
        "valid": valid,
        "value": value,
    }


def signed(unsigned, key):
    return canon.sign_receipt(unsigned, seed(key))


def add_receipt(id_, description, r, key, error=None, keys=KEYENV, recompute=None, raw=None, blob_hex=None):
    extra = {"keypair": keypair_fields(key), "keys": keys}
    if recompute is not None:
        extra["recompute"] = recompute
    if blob_hex is not None:
        extra["blob_hex"] = blob_hex
    add(id_, "receipt", description, raw if raw is not None else text(r), error, **extra)


R_FX = signed(receipt(FX_CELL, "number", "1.0892",
                      "1 EUR was worth 1.0892 USD at the 15 March 2024 reference rate.", "rates-2020"), "rates-2020")
R_FX_GBP = signed(receipt(FX_CELL | {"args": FX_ARGS | {"quote": S("GBP")}}, "number", "0.8556",
                          "1 EUR was worth 0.8556 GBP at the 15 March 2024 reference rate.", "rates-2020"), "rates-2020")
H_FX, H_FX_GBP = canon.receipt_hash(R_FX), canon.receipt_hash(R_FX_GBP)

add_receipt("receipt/stored-number", "A stored cell, signed by its publisher; recomputation is a stored lookup.",
            R_FX, "rates-2020",
            recompute={"descriptor": FX, "inputs": {}, "value": N("1.0892")})
add_receipt("receipt/stored-number-second", "A second stored cell, used as an input below.", R_FX_GBP, "rates-2020")

convert_cell = {"args": {"amount": N("100"), "base": S("EUR"), "date": D("2024-03-15"), "quote": S("USD")},
                "fn": "convert", "fn_hash": CONVERT_HASH, "ns": CALC}
R_CONVERT = signed(receipt(convert_cell, "number", "108.92", "100 EUR converted to USD at the 15 March 2024 rate is 108.92.",
                           "calc-2020", inputs=[H_FX], issued="2024-03-16T09:00:01.250000Z"), "calc-2020")
add_receipt("receipt/computed-with-lineage", "A computed cell signed by another party, with its input receipt hash; "
            "full verification checks the input, its declared function, asof and tx.",
            R_CONVERT, "calc-2020",
            recompute={"descriptor": CONVERT, "inputs": {H_FX: text(R_FX)}, "value": N("108.92")})

two_inputs = signed(receipt(convert_cell | {"args": convert_cell["args"] | {"quote": S("GBP")}}, "number", "85.56",
                            "Two inputs, listed in ascending hash order.", "calc-2020",
                            inputs=sorted([H_FX, H_FX_GBP])), "calc-2020")
add_receipt("receipt/computed-two-inputs", "Input hashes are a set: ascending, no duplicates.", two_inputs, "calc-2020")

holiday_cell = {"args": {"calendar": S("TARGET2"), "date": D("2024-12-25")}, "fn": "is_holiday",
                "fn_hash": canon.function_hash(HOLIDAY), "ns": "calendars.example.org/eu"}
R_HOLIDAY = receipt(holiday_cell, "boolean", True, "25 December 2024 is a TARGET2 holiday.", "rates-2020",
                    publisher="calendars.example.org/eu", licence="https://calendars.example.org/licence")
R_HOLIDAY["computed_by"] = "calendars.example.org#" + keypair_fields("calendars-2020")["key_id"]
add_receipt("receipt/boolean-namespace-path", "A boolean value, a namespace with a path segment, and a licence URL. "
            "Keys for calendars.example.org/eu are published by the host calendars.example.org.",
            signed(R_HOLIDAY, "calendars-2020"), "calendars-2020",
            keys={"calendars.example.org": https_env("calendars.example.org", key_entry("calendars-2020", T0))})

trade_cell = {"args": {"symbol": S("XAMS:ASML")}, "fn": "last_trade", "fn_hash": canon.function_hash(LAST_TRADE),
              "ns": RATES}
add_receipt("receipt/instant-no-valid-time", "An instant value from a function with no valid-time arguments: valid is {}.",
            signed(receipt(trade_cell, "instant", "2024-03-15T16:29:59.874211Z", "The last trade in XAMS:ASML was at 16:29:59.874211 UTC.",
                           "rates-2020", valid={}), "rates-2020"), "rates-2020")
add_receipt("receipt/string-value", "A string value with non-ASCII text.",
            signed(receipt(FX_CELL, "string", "Euro → US-Dollar", "The pair name for the EUR/USD cell.", "rates-2020"),
                   "rates-2020"), "rates-2020")
add_receipt("receipt/date-value", "A date value.",
            signed(receipt(FX_CELL, "date", "2024-03-14", "The previous fixing date before 15 March 2024.", "rates-2020"),
                   "rates-2020"), "rates-2020")
R_ROTATED = signed(receipt(FX_CELL, "number", "1.0892", "Signed after rotation with the 2024 key.", "rates-2024",
                           asof="2024-07-01T00:00:00.000000Z"), "rates-2024")
add_receipt("receipt/rotated-key", "Issued after 1 June 2024, so signed with the second key in the key document.",
            R_ROTATED, "rates-2024")
add_receipt("receipt/historical-asof", "asof in the past, issued later with the current key: key validity is checked "
            "against issued, not asof.",
            signed(receipt(FX_CELL, "number", "1.0892", "The EUR/USD rate as known on 16 March 2024, served later.",
                           "rates-2024", issued="2024-09-01T00:00:00.000000Z"), "rates-2024"), "rates-2024")
def tampered(r, **changes):
    return dict(r, **changes)


for name, r, error, key, why, extra in [
    ("tampered-value", tampered(R_FX, value="1.0893"), "E_SIGNATURE", "rates-2020", "The value was changed after signing.", {}),
    ("wrong-signer", signed(receipt(FX_CELL, "number", "1.0892", "Claims key rates-2020, signed by rates-2024.", "rates-2020"), "rates-2024"),
     "E_SIGNATURE", "rates-2020", "computed_by names one key; the signature is from another.", {}),
    ("unknown-key", signed(receipt(FX_CELL, "number", "1.0892", "Signed by an unpublished key.", "rates-rogue") | {"computed_by": f"{RATES}#{keypair_fields('rates-rogue')['key_id']}"}, "rates-rogue"),
     "E_KEY_UNKNOWN", "rates-rogue", "The key id is not published by the host.", {}),
    ("key-expired", signed(receipt(FX_CELL, "number", "1.0892", "Issued after the key was retired.", "rates-2020", asof="2024-07-01T00:00:00.000000Z"), "rates-2020"),
     "E_KEY_NOT_VALID", "rates-2020", "issued is after the key's valid_to.", {}),
    ("key-not-yet-valid", signed(receipt(FX_CELL, "number", "1.0892", "Issued before the key was valid.", "rates-2024"), "rates-2024"),
     "E_KEY_NOT_VALID", "rates-2024", "issued is before the key's valid_from.", {}),
    ("key-unavailable", R_FX, "E_KEY_UNAVAILABLE", "rates-2020", "The key document could not be fetched.", {"keys": {RATES: {"https": {"status": "error"}}}}),
    ("slice", signed(receipt(FX_CELL | {"args": FX_ARGS | {"date": "*"}}, "number", "1.0892", "A slice cannot be a receipt.", "rates-2020", valid={}), "rates-2020"),
     "E_SLICE", "rates-2020", "Only individual cells have receipts.", {}),
    ("publisher-mismatch", signed(receipt(FX_CELL, "number", "1.0892", "Wrong publisher.", "rates-2020", publisher="other.example.org"), "rates-2020"),
     "E_PUBLISHER_MISMATCH", "rates-2020", "publisher must equal cell.ns.", {}),
    ("valid-mismatch", signed(receipt(FX_CELL, "number", "1.0892", "valid disagrees with the arguments.", "rates-2020", valid={"date": D("2024-03-14")}), "rates-2020"),
     "E_VALID_MISMATCH", "rates-2020", "valid echoes the valid-time arguments exactly.", {}),
    ("tx-after-asof", signed(receipt(FX_CELL, "number", "1.0892", "Recorded after it was served.", "rates-2020", tx="2024-03-17T00:00:00.000000Z"), "rates-2020"),
     "E_TIME_ORDER", "rates-2020", "tx <= asof <= issued.", {}),
    ("inputs-unsorted", signed(receipt(convert_cell, "number", "1", "Unsorted inputs.", "calc-2020", inputs=sorted([H_FX, H_FX_GBP], reverse=True)), "calc-2020"),
     "E_CANON_SET", "calc-2020", "Input hashes must be ascending.", {}),
    ("value-form", signed(receipt(FX_CELL, "number", "1.0890", "A non-canonical number.", "rates-2020"), "rates-2020"),
     "E_CANON_NUMBER", "rates-2020", "Values follow the same lexical rules as arguments.", {}),
    ("value-type-mismatch", signed(receipt(FX_CELL, "boolean", "true", "The string true is not a boolean.", "rates-2020"), "rates-2020"),
     "E_CANON_TYPE", "rates-2020", "A boolean value is JSON true or false.", {}),
    ("sig-uppercase", tampered(R_FX, sig=R_FX["sig"].upper()), "E_CANON_HEX", "rates-2020", "Signatures are lowercase hex.", {}),
    ("licence", signed(receipt(FX_CELL, "number", "1.0892", "A licence with a space.", "rates-2020", licence="CC BY 4.0"), "rates-2020"),
     "E_CANON_LICENCE", "rates-2020", "A licence is an SPDX identifier or an https URL.", {}),
    ("empty-summary", signed(receipt(FX_CELL, "number", "1.0892", "", "rates-2020"), "rates-2020"),
     "E_CANON_STRING", "rates-2020", "summary is one non-empty sentence.", {}),
    ("computed-by-bare-key-id", tampered(R_FX, computed_by=R_FX["computed_by"].split("#")[1]), "E_CANON_NAME", "rates-2020",
     "computed_by is <host>#<key id>, so a verifier knows where to look the key up.", {}),
    ("missing-member", {k: v for k, v in R_FX.items() if k != "summary"}, "E_SCHEMA", "rates-2020", "Every member is required.", {}),
    ("extra-member", R_FX | {"comment": "x"}, "E_SCHEMA", "rates-2020", "No other members are allowed; sig would not cover them unambiguously.", {}),
    ("wrong-proto", tampered(R_FX, proto="datumesh/2"), "E_SCHEMA", "rates-2020", "proto is datumesh/1.", {}),
    ("value-mismatch", R_FX, "E_VALUE_MISMATCH", "rates-2020", "Recomputation returns a different value.",
     {"recompute": {"descriptor": FX, "inputs": {}, "value": N("1.0893")}}),
    ("fn-hash-mismatch", R_FX, "E_FN_HASH_MISMATCH", "rates-2020", "The descriptor offered does not hash to cell.fn_hash.",
     {"recompute": {"descriptor": FX | {"inputs": ["rates.example.org/ecb_feed"]}, "inputs": {}, "value": N("1.0892")}}),
    ("fn-unavailable", R_FX, "E_FN_UNAVAILABLE", "rates-2020", "No descriptor can be found for cell.fn_hash.",
     {"recompute": {"inputs": {}, "value": N("1.0892")}}),
    ("input-unavailable", R_CONVERT, "E_INPUT_UNAVAILABLE", "calc-2020", "An input receipt cannot be found.",
     {"recompute": {"descriptor": CONVERT, "inputs": {}, "value": N("108.92")}}),
    ("input-invalid", R_CONVERT, "E_INPUT_INVALID", "calc-2020", "An input receipt does not verify.",
     {"recompute": {"descriptor": CONVERT, "inputs": {H_FX: text(tampered(R_FX, value="2"))}, "value": N("108.92")}}),
]:
    add_receipt(f"invalid/receipt-{name}", why, r, key, error, **extra)

undeclared = {**CONVERT, "inputs": ["rates.example.org/other"]}
r_undeclared = signed(receipt(convert_cell | {"fn_hash": canon.function_hash(undeclared)}, "number", "108.92",
                              "Uses an input its function does not declare.", "calc-2020", inputs=[H_FX]), "calc-2020")
add_receipt("invalid/receipt-input-undeclared", "Every input receipt must be a cell of a declared input function.",
            r_undeclared, "calc-2020", "E_INPUT_UNDECLARED",
            recompute={"descriptor": undeclared, "inputs": {H_FX: text(R_FX)}, "value": N("108.92")})
r_tx = signed(receipt(convert_cell, "number", "108.92", "tx is not the latest input tx.", "calc-2020", inputs=[H_FX],
                      tx="2024-03-16T08:00:00.000000Z"), "calc-2020")
add_receipt("invalid/receipt-computed-tx", "A computed cell's tx is the latest tx among its inputs.", r_tx, "calc-2020",
            "E_TIME_ORDER", recompute={"descriptor": CONVERT, "inputs": {H_FX: text(R_FX)}, "value": N("108.92")})
wrong_args = {**CONVERT, "signature": {**CONVERT["signature"], "args": {**CONVERT["signature"]["args"], "amount": {"type": "string", "valid": False}}}}
r_argtype = signed(receipt(convert_cell | {"fn_hash": canon.function_hash(wrong_args)}, "number", "108.92",
                           "amount is declared a string.", "calc-2020", inputs=[H_FX]), "calc-2020")
add_receipt("invalid/receipt-arg-type", "Argument types must match the declared signature.", r_argtype, "calc-2020",
            "E_ARG_TYPE", recompute={"descriptor": wrong_args, "inputs": {H_FX: text(R_FX)}, "value": N("108.92")})
extra_arg = {**CONVERT, "signature": {**CONVERT["signature"], "args": {**CONVERT["signature"]["args"], "rounding": {"type": "string", "valid": False}}}}
r_missing = signed(receipt(convert_cell | {"fn_hash": canon.function_hash(extra_arg)}, "number", "108.92",
                           "The function declares an argument the cell lacks.", "calc-2020", inputs=[H_FX]), "calc-2020")
add_receipt("invalid/receipt-arg-missing", "A cell binds every declared argument.", r_missing, "calc-2020",
            "E_ARG_MISSING", recompute={"descriptor": extra_arg, "inputs": {H_FX: text(R_FX)}, "value": N("108.92")})
fewer_args = {**FX, "signature": {"args": {k: v for k, v in FX["signature"]["args"].items() if k != "quote"},
                                  "returns": {"type": "number", "unit": {"of": "USD", "per": {"arg": "base"}}}}}
r_unknown = signed(receipt(FX_CELL | {"fn_hash": canon.function_hash(fewer_args)}, "number", "1.0892",
                           "The cell binds an argument the function does not declare.", "rates-2020"), "rates-2020")
add_receipt("invalid/receipt-arg-unknown", "A cell binds only declared arguments.", r_unknown, "rates-2020",
            "E_ARG_UNKNOWN", recompute={"descriptor": fewer_args, "inputs": {}, "value": N("1.0892")})
r_return = signed(receipt(FX_CELL, "string", "1.0892", "fx_rate returns a number, not a string.", "rates-2020"), "rates-2020")
add_receipt("invalid/receipt-return-type", "The value's type is the function's declared return type.", r_return,
            "rates-2020", "E_RETURN_TYPE", recompute={"descriptor": FX, "inputs": {}, "value": S("1.0892")})
add_receipt("invalid/receipt-duplicate-member", "Duplicate members make the signed content ambiguous.",
            None, "rates-2020", "E_PARSE_DUPLICATE_KEY",
            raw=json.dumps(R_FX, ensure_ascii=False)[:-1] + ', "value": "9.9"}')


# ---------------------------------------------------------------------------
# Rules written down in spec-0.2.1 (check orders, limits, readable signatures)

add("jcs/nesting-64", "jcs", "64 nested arrays, the deepest allowed (SPEC 6.1).", "[" * 64 + "]" * 64)
add("invalid/jcs-nesting-65", "jcs", "65 nested arrays: deeper than 64 is rejected.", "[" * 65 + "]" * 65, "E_PARSE_JSON")
add("invalid/jcs-nesting-before-duplicate", "jcs",
    "Depth is checked before anything else in the text: a duplicate member is not reported.",
    '{"a": 1, "a": 2, "b": ' + "[" * 64 + "]" * 64 + "}", "E_PARSE_JSON")
add("invalid/jcs-brackets-in-strings", "jcs", "Brackets inside strings do not count towards depth; the duplicate is reported.",
    '{"a": "' + "[" * 100 + '", "a": 2}', "E_PARSE_DUPLICATE_KEY")
add("invalid/keys-host-not-dns-name", "keys",
    "Keys are resolved only for DNS names: a document for an uppercase host cannot satisfy 9.2.",
    host="Rates.Example.org", env=https_env("Rates.Example.org", key_entry("rates-2020", T0)), error="E_KEY_DOC")
add("invalid/keys-ok-without-body", "keys", "A 200 response without a document is a document error.",
    host="rates.example.org", env={"https": {"status": 200}}, error="E_KEY_DOC")
for name, sig, why in [
    ("not-object", "fx_rate", "The signature passed to parse is not an object."),
    ("declaration-not-object", {"args": {"base": "string", "date": {"type": "date", "valid": True},
                                         "quote": {"type": "string", "valid": False}}, "returns": "boolean"},
     "An argument declaration is not an object."),
    ("declaration-without-type", {"args": {"base": {"valid": False}, "date": {"type": "date", "valid": True},
                                           "quote": {"type": "string", "valid": False}}, "returns": "boolean"},
     "An argument declaration has no type."),
]:
    add(f"invalid/uri-signature-{name}", "uri", why + " The signature is taken as given, but must be readable (SPEC 5.4).",
        "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD", "E_SCHEMA", signature=sig)
add("invalid/uri-repeat-not-adjacent", "uri", "A repetition that is not adjacent is reported as an ordering error.",
    "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&base=GBP&quote=USD", "E_CANON_ARG_ORDER", signature=SIG)
add("invalid/uri-asof-star", "uri", "asof is decoded like a value, but * is not a slice there.",
    "cell://math.example/pi?asof=*", "E_CANON_PERCENT", signature=PI["signature"])
add_receipt("invalid/receipt-check-order-valid-before-time",
            "Step 4 runs its checks in the order listed: the valid mismatch is reported before tx > asof.",
            signed(receipt(FX_CELL, "number", "1.0892", "Two consistency errors.", "rates-2020",
                           valid={"date": D("2024-03-14")}, tx="2024-03-17T00:00:00.000000Z"), "rates-2020"),
            "rates-2020", "E_VALID_MISMATCH")
add_receipt("invalid/receipt-licence-url-too-long", "A licence URL is checked for its grammar first, then its length (512).",
            signed(receipt(FX_CELL, "number", "1.0892", "A long licence URL.", "rates-2020",
                           licence="https://example.org/" + "l" * 493), "rates-2020"), "rates-2020", "E_CANON_LIMIT")
add_receipt("invalid/receipt-licence-url-space", "A licence URL is https:// followed by printable ASCII without spaces.",
            signed(receipt(FX_CELL, "number", "1.0892", "A licence URL with a space.", "rates-2020",
                           licence="https://example.org/a licence"), "rates-2020"), "rates-2020", "E_CANON_LICENCE")

# ---------------------------------------------------------------------------
# Ed25519 strictness (spec-0.2.1: SPEC 10.1 step 6). Each receipt is signed by hand; all but
# the mixed-order key satisfy the permissive (cofactored) equation and must still be rejected.

import ed25519_edge  # noqa: E402

EDGE = "edge.example.net"


def edge_receipt(build, summary):
    public, _ = build(b"")  # the key, to name it in computed_by
    unsigned = receipt(FX_CELL, "number", "1.0892", summary, "rates-2020")
    unsigned["computed_by"] = f"{EDGE}#{canon.key_id(public)}"
    public, sig = build(canon.jcs(unsigned))
    doc = {"host": EDGE, "keys": [{"alg": "ed25519", "id": canon.key_id(public), "public": public.hex(),
                                   "valid_from": T0}], "proto": canon.PROTO}
    keys = {EDGE: {"https": {"status": 200, "body": json.dumps(doc, indent=2)}}}
    return dict(unsigned, sig=sig.hex()), keys, public


def add_edge(id_, description, build, summary, error=None):
    r, keys, _ = edge_receipt(build, summary)
    add(id_, "receipt", description, text(r), error, keys=keys)  # no keypair: there is no seed


add_edge("receipt/ed25519-mixed-order-key",
         "The key has a small-order component but is not small order: a strict verifier accepts it "
         "(only small-order keys are rejected).",
         ed25519_edge.mixed_order_key, "Signed with a mixed-order key.")
for name, build, why in [
    ("s-not-reduced", ed25519_edge.s_not_reduced, "S is the honest S plus L: S >= L is rejected."),
    ("small-order-key", ed25519_edge.small_order_key, "The key is the identity point, of order 1: small-order keys are rejected."),
    ("small-order-r", ed25519_edge.small_order_r, "R is the identity point: a small-order R is rejected."),
    ("non-canonical-r", ed25519_edge.non_canonical_r, "R encodes y as p + 1: a y at or above p is rejected."),
    ("negative-zero-r", ed25519_edge.negative_zero_r, "R has x = 0 with the sign bit set: rejected."),
]:
    add_edge(f"invalid/receipt-ed25519-{name}",
             why + " A permissive (cofactored) verifier would accept this signature.", build,
             "A hand-built signature.", "E_SIGNATURE")

# ---------------------------------------------------------------------------
# Units (spec-0.2.0: SPEC 7.1, units.md)


def stored(args, returns):
    return {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": {"args": args, "returns": returns}}


def NUM(unit):
    return {"type": "number", "unit": unit}


SARG = {"type": "string", "valid": False}
DARG = {"type": "date", "valid": True}
ECB = stored({"date": DARG, "quote": SARG}, NUM({"of": {"arg": "quote"}, "per": "EUR"}))
TEMPERATURE = stored({"date": DARG, "station": SARG}, NUM("degC"))
AMOUNT_IN = stored({"amount": {"type": "number", "unit": {"arg": "currency"}, "valid": False}, "currency": SARG},
                   NUM({"arg": "currency"}))

for name, desc, why in [
    ("unit-currency", stored({"company": SARG, "date": DARG}, NUM("GBP")), "An amount of money: its unit is a currency code."),
    ("unit-rate-literal", stored({"date": DARG}, NUM({"of": "USD", "per": "EUR"})),
     "A rate between two fixed currencies: US dollars per one euro."),
    ("unit-rate-ecb", ECB, "A reference rate against the euro: units of the quote currency per one euro."),
    ("unit-argument-reference", AMOUNT_IN,
     "A number argument and the return take their unit from a string argument."),
    ("unit-temperature", TEMPERATURE, "An air temperature in degrees Celsius."),
    ("unit-percent", stored({"date": DARG}, NUM("percent")), "An inflation rate in percent."),
    ("unit-basis-points", stored({"date": DARG}, NUM("bp")), "A spread in basis points."),
    ("unit-dimensionless", stored({"date": DARG}, NUM("1")), "A ratio of like quantities is dimensionless: unit 1."),
    ("unit-count", stored({"date": DARG}, NUM("count")), "A number of companies incorporated."),
    ("unit-index", stored({"date": DARG}, NUM("index:2015=100")), "A price index equal to 100 in 2015."),
    ("unit-index-day", stored({"date": DARG}, NUM("index:1984-01-03=1000")), "An index based on one day."),
    ("unit-speed", stored({"date": DARG, "station": SARG}, NUM("m/s")), "m/s is one fixed symbol, not a quotient."),
    ("unit-energy", stored({"date": DARG}, NUM("kWh")), "Energy in kilowatt-hours."),
    ("unit-number-argument", stored({"date": DARG, "station": SARG,
                                     "threshold": {"type": "number", "unit": "degC", "valid": False}}, "boolean"),
     "A number argument declares its unit; the boolean return stays a bare type name."),
    ("unit-withdrawn-currency", stored({"date": DARG}, NUM({"of": "GRD", "per": "EUR"})),
     "Withdrawn currency codes used by historical rates remain units."),
    ("unit-seed-sources", stored({"date": DARG, "station": SARG}, NUM("hPa")) | {"signature": {
        "args": {"date": DARG, "precipitation": {"type": "number", "unit": "mm", "valid": False},
                 "radiation": {"type": "number", "unit": "W/m2", "valid": False},
                 "snow": {"type": "number", "unit": "cm", "valid": False},
                 "weight": {"type": "number", "unit": "permille", "valid": False},
                 "wind": {"type": "number", "unit": "km/h", "valid": False}},
        "returns": NUM("hPa")}},
     "The units added for the seed sources: hPa, mm, W/m2, cm, permille and km/h."),
]:
    add(f"function/{name}", "function", why, text(desc))

for name, desc, error, why in [
    ("unit-number-return-bare", stored({}, "number"), "E_CANON_UNIT", "A number return is an object with a unit, never the bare name."),
    ("unit-missing-on-return", stored({}, {"type": "number"}), "E_CANON_UNIT", "A number return declares its unit."),
    ("unit-missing-on-argument", stored({"amount": {"type": "number", "valid": False}}, "boolean"), "E_CANON_UNIT",
     "A number argument declares its unit."),
    ("unit-on-string-argument", stored({"name": {"type": "string", "unit": "1", "valid": False}}, "boolean"), "E_CANON_UNIT",
     "Only number arguments have a unit."),
    ("unit-object-for-boolean", stored({}, {"type": "boolean"}), "E_CANON_UNIT",
     "Only a number return is written as an object; a boolean return is the bare name."),
    ("unit-on-boolean-return", stored({}, {"type": "boolean", "unit": "1"}), "E_CANON_UNIT", "Booleans have no unit."),
    ("unit-unknown", stored({}, NUM("dollars")), "E_CANON_UNIT", "Only units listed in units.md are accepted."),
    ("unit-lowercase-currency", stored({}, NUM("usd")), "E_CANON_UNIT", "Units are compared byte for byte: usd is not USD."),
    ("unit-unassigned-currency", stored({}, NUM("ABC")), "E_CANON_UNIT", "ABC is not an ISO 4217 code."),
    ("unit-rate-as-string", stored({}, NUM("USD/EUR")), "E_CANON_UNIT", "A rate is written {\"of\", \"per\"}; the string USD/EUR is not a unit."),
    ("unit-symbol-variant", stored({}, NUM("°C")), "E_CANON_UNIT", "Units are not parsed: °C is not degC."),
    ("unit-index-zero-base", stored({}, NUM("index:2015=0")), "E_CANON_UNIT", "An index base value is greater than zero."),
    ("unit-index-bad-period", stored({}, NUM("index:2015-13=100")), "E_CANON_UNIT", "The base period is a real month."),
    ("unit-index-non-canonical", stored({}, NUM("index:2015=100.0")), "E_CANON_UNIT", "The base value is a canonical number."),
    ("unit-arg-missing", stored({"date": DARG}, NUM({"arg": "currency"})), "E_CANON_UNIT",
     "A unit reference names an argument of the signature."),
    ("unit-arg-not-string", stored({"currency": {"type": "date", "valid": False}}, NUM({"arg": "currency"})), "E_CANON_UNIT",
     "A unit reference names a string argument."),
    ("unit-rate-side-not-currency", stored({}, NUM({"of": "kg", "per": "EUR"})), "E_CANON_UNIT",
     "Each side of a rate is a currency code or an argument reference."),
    ("unit-json-number", stored({}, NUM(1)), "E_SCHEMA", "A unit is a string or an object, never a JSON number."),
    ("unit-rate-extra-member", stored({}, NUM({"of": "USD", "per": "EUR", "scale": "1"})), "E_SCHEMA",
     "A rate has exactly the members of and per."),
    ("unit-superscript", stored({}, NUM("W/m²")), "E_CANON_UNIT", "W/m2 is written in ASCII; W/m² is not a unit."),
    ("unit-index-year-zero", stored({}, NUM("index:0000=100")), "E_CANON_UNIT", "Index periods are years 0001 to 9999."),
    ("unit-arg-not-a-name", stored({"date": DARG}, NUM({"arg": "Bad"})), "E_CANON_UNIT",
     "A reference to anything that is not an argument of the signature, even a malformed name."),
]:
    add(f"invalid/function-{name}", "function", why, text(desc), error)


BAD_UNIT = stored({}, NUM("dollars"))
add("invalid/unit-descriptor-not-canonical", "unit",
    "A descriptor that hashes to fn_hash is still checked: its unit is not listed.",
    text({"cell": {"args": {}, "fn": "f", "fn_hash": canon.function_hash(BAD_UNIT), "ns": "units.example.org"},
          "descriptor": BAD_UNIT}), "E_CANON_UNIT")


def unit_input(desc, cell):
    return text({"cell": cell, "descriptor": desc})


def cell_of(desc, ns, fn, args):
    return {"args": args, "fn": fn, "fn_hash": canon.function_hash(desc), "ns": ns}


ECB_CELL = cell_of(ECB, "rates.example.org", "eur_rate", {"date": D("2024-03-15"), "quote": S("JPY")})
for name, desc, cell, why in [
    ("fx-rate", FX, FX_CELL, "fx_rate's unit is quote per base: USD/EUR for base EUR, quote USD."),
    ("fx-rate-gbp", FX, FX_CELL | {"args": FX_ARGS | {"quote": S("GBP")}}, "The same function in another cell: GBP/EUR."),
    ("rate-literal-per", ECB, ECB_CELL, "A literal side and an argument side: JPY/EUR."),
    ("argument-reference", CONVERT, convert_cell, "convert returns an amount in the quote currency: USD."),
    ("literal", TEMPERATURE, cell_of(TEMPERATURE, "weather.example.org", "temperature",
                                     {"date": D("2024-03-15"), "station": S("EHAM")}), "A literal unit resolves to itself."),
    ("no-unit", HOLIDAY, holiday_cell, "A boolean return has no unit: null."),
]:
    add(f"unit/{name}", "unit", why, unit_input(desc, cell))

for name, desc, cell, error, why in [
    ("not-currency", FX, FX_CELL | {"args": FX_ARGS | {"quote": S("usd")}}, "E_CANON_UNIT",
     "A rate side resolved from an argument must be a currency code."),
    ("not-a-unit", AMOUNT_IN, cell_of(AMOUNT_IN, "calc.example.net", "amount_in",
                                      {"amount": N("5"), "currency": S("dollars")}), "E_CANON_UNIT",
     "A referenced argument's value must itself be a listed unit."),
    ("slice", FX, FX_CELL | {"args": FX_ARGS | {"quote": "*"}}, "E_SLICE", "A slice over the unit's argument has no single unit."),
    ("fn-hash-mismatch", CONVERT, FX_CELL, "E_FN_HASH_MISMATCH", "The descriptor must be the cell's function."),
    ("arg-missing", FX, FX_CELL | {"args": {k: v for k, v in FX_ARGS.items() if k != "quote"}}, "E_ARG_MISSING",
     "The cell does not bind an argument the unit refers to."),
    ("arg-type", FX, FX_CELL | {"args": FX_ARGS | {"quote": D("2024-03-15")}}, "E_ARG_TYPE",
     "An argument the unit refers to is bound with another type than string."),
]:
    add(f"invalid/unit-{name}", "unit", why, unit_input(desc, cell), error)

# ---------------------------------------------------------------------------
# Blobs (spec-0.2.0: SPEC 3.7, 10.1 step 7.7)


def blob(content, media_type):
    return f"{hashlib.sha256(content).hexdigest()}:{len(content)}:{media_type}"


def BL(v):
    return {"type": "blob", "value": v}


CSV = b"date,rate\n2024-03-15,1.0892\n2024-03-14,1.0885\n"
HELLO = b"Hello, Datumesh!\n"
PNG = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000"
                    "1f15c4890000000d49444154789c63f8cfc0f01f0005000201a5f1d5e90000000049454e44ae426082")
LONG_TYPE = "application/" + "x" * 116  # 128 characters
for name, value, why in [
    ("blob-text", blob(HELLO, "text/plain"), "A blob: content hash, byte length and media type."),
    ("blob-empty", blob(b"", "application/octet-stream"), "Empty content: length 0 and the hash of no bytes."),
    ("blob-csv", blob(CSV, "text/csv"), "A CSV file."),
    ("blob-png", blob(PNG, "image/png"), "A 1x1 PNG image."),
    ("blob-vendor-tree", blob(HELLO, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
     "Vendor-tree media types with dots are allowed."),
    ("blob-suffix", blob(HELLO, "application/ld+json"), "Structured-syntax suffixes with + are allowed."),
    ("blob-max-length", "0" * 64 + ":9007199254740991:application/octet-stream", "The largest length, 2^53 - 1."),
    ("blob-max-media-type", blob(HELLO, LONG_TYPE), "A 128-character media type, the maximum."),
]:
    add(f"scalar/{name}", "scalar", why, text(BL(value)))

H = hashlib.sha256(HELLO).hexdigest()
for name, raw, error, why in [
    ("blob-uppercase-hex", text(BL(H.upper() + ":17:text/plain")), "E_CANON_BLOB", "The hash is lowercase hex."),
    ("blob-short-hash", text(BL(H[:63] + ":17:text/plain")), "E_CANON_BLOB", "The hash has 64 hex digits."),
    ("blob-length-leading-zero", text(BL(H + ":017:text/plain")), "E_CANON_BLOB", "The length is a canonical integer: no leading zeros."),
    ("blob-length-fraction", text(BL(H + ":17.0:text/plain")), "E_CANON_BLOB", "The length is a whole number of bytes."),
    ("blob-length-negative", text(BL(H + ":-17:text/plain")), "E_CANON_BLOB", "The length is not negative."),
    ("blob-length-too-large", text(BL(H + ":9007199254740992:text/plain")), "E_CANON_BLOB", "The length is at most 2^53 - 1."),
    ("blob-media-type-uppercase", text(BL(H + ":17:text/Plain")), "E_CANON_BLOB", "Media types are lowercase; rejected, not folded."),
    ("blob-media-type-parameter", text(BL(H + ":17:text/plain;charset=utf-8")), "E_CANON_BLOB", "Media type parameters are not allowed."),
    ("blob-media-type-no-subtype", text(BL(H + ":17:text")), "E_CANON_BLOB", "A media type is type/subtype."),
    ("blob-media-type-too-long", text(BL(H + ":17:" + LONG_TYPE + "x")), "E_CANON_BLOB", "129 characters exceeds the media type limit."),
    ("blob-missing-length", text(BL(H + ":text/plain")), "E_CANON_BLOB", "All three parts are required."),
    ("blob-json-object", '{"type":"blob","value":{"sha256":"' + H + '"}}', "E_SCHEMA", "A blob value is one string."),
]:
    add(f"invalid/scalar-{name}", "scalar", why, raw, error)

FILING = stored({"company": SARG, "date": DARG}, "blob")
add("function/blob-return", "function", "A function returning a blob; blobs have no unit, so the return is the bare name.", text(FILING))
add("invalid/function-blob-valid-time", "function", "A blob cannot be a valid-time argument.",
    text(stored({"file": {"type": "blob", "valid": True}}, "boolean")), "E_CANON_TYPE")
add("invalid/function-blob-unit", "function", "Only numbers have units.",
    text(stored({"file": {"type": "blob", "unit": "1", "valid": False}}, "boolean")), "E_CANON_UNIT")

DESCRIBE_SIG = {"args": {"file": {"type": "blob", "valid": False}}, "returns": "string"}
add("uri/blob-argument", "uri", "A blob argument: : is literal, / and + are percent-encoded.",
    f"cell://files.example.org/describe?file={H}:17:application%2Fld%2Bjson", signature=DESCRIBE_SIG)
add("invalid/uri-blob-form", "uri", "Blob arguments follow the blob rules.",
    f"cell://files.example.org/describe?file={H}:17:text%2FPlain", "E_CANON_BLOB", signature=DESCRIBE_SIG)

filing_cell = cell_of(FILING, RATES, "filing", {"company": S("01234567"), "date": D("2024-03-15")})
R_BLOB = signed(receipt(filing_cell, "blob", blob(CSV, "text/csv"), "The filing of company 01234567 on 15 March 2024.",
                        "rates-2020"), "rates-2020")
add_receipt("receipt/blob-value", "A blob value with its content: step 7.7 checks the content's length and hash.",
            R_BLOB, "rates-2020", blob_hex=CSV.hex())
add_receipt("receipt/blob-value-recomputed", "Recomputation and the content check together: level recomputed, content checked.",
            R_BLOB, "rates-2020", blob_hex=CSV.hex(),
            recompute={"descriptor": FILING, "inputs": {}, "value": BL(blob(CSV, "text/csv"))})
add_receipt("invalid/receipt-content-not-blob", "Content supplied for a value that is not a blob.", R_FX, "rates-2020",
            "E_SCHEMA", blob_hex=HELLO.hex())
add_receipt("invalid/receipt-blob-mismatch", "Content whose hash differs from the blob's.", R_BLOB, "rates-2020",
            "E_BLOB_MISMATCH", blob_hex=CSV.replace(b"1.0892", b"1.0893").hex())
add_receipt("invalid/receipt-blob-length-mismatch", "Content with one byte more than the blob's length.", R_BLOB,
            "rates-2020", "E_BLOB_MISMATCH", blob_hex=(CSV + b"\n").hex())

# ---------------------------------------------------------------------------
# Response envelopes (spec-0.2.0: SPEC 5.5)

CALENDARS = "calendars.example.org"
ALL_KEYS = KEYENV | {CALENDARS: https_env(CALENDARS, key_entry("calendars-2020", T0))}
R_HOLIDAY_SIGNED = signed(R_HOLIDAY, "calendars-2020")
R_MIRROR = signed(receipt(FX_CELL, "number", "1.0892", "The EUR/USD rate, re-signed by a mirror.", "calc-2020"), "calc-2020")
R_FX_CORRECTED = signed(receipt(FX_CELL, "number", "1.0893", "The corrected EUR/USD rate for 15 March 2024.", "rates-2020",
                                asof="2024-03-18T09:00:00.000000Z", tx="2024-03-18T08:00:00.000000Z"), "rates-2020")
H_CORRECTED = canon.receipt_hash(R_FX_CORRECTED)


def cell_id(cell):
    return canon.sha256_hex(canon.jcs(cell))


def add_envelope(id_, description, env, status, error=None, raw=None, request=None):
    """request defaults to the receipt's own cell (or fx_rate's) as of ASOF."""
    if request is None:
        cell = env["receipt"]["cell"] if env and isinstance(env.get("receipt"), dict) else FX_CELL
        request = {"asof": ASOF, "cell_id": cell_id(cell)}
    add(id_, "envelope", description, raw if raw is not None else text(env), error, status=status, keys=ALL_KEYS,
        request=request)


for name, env, status, why in [
    ("ok-primary", {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200,
     "A stored cell signed by its publisher's host: trust is primary."),
    ("ok-primary-namespace-path", {"outcome": "ok", "receipt": R_HOLIDAY_SIGNED, "trust": "primary"}, 200,
     "The host of calendars.example.org/eu is calendars.example.org, which signed: primary."),
    ("ok-verified", {"outcome": "ok", "receipt": R_CONVERT, "trust": "verified"}, 200,
     "A computed cell the mesh recomputed: verified, a claim the client cannot check."),
    ("ok-unverified", {"outcome": "ok", "receipt": R_CONVERT, "trust": "unverified"}, 200,
     "A computed cell the mesh did not recompute."),
    ("ok-mirror", {"outcome": "ok", "receipt": R_MIRROR, "trust": "unverified"}, 200,
     "A stored cell signed by another host is not primary."),
    ("ok-correction", {"outcome": "ok", "reason": "The 15 March 2024 rate was republished with a correction.",
                       "receipt": R_FX, "superseded_by": H_CORRECTED, "trust": "primary"}, 200,
     "A receipt superseded by a correction at a later tx, with the reason."),
    ("ok-superseded", {"outcome": "ok", "receipt": R_FX, "superseded_by": H_CORRECTED, "trust": "primary"}, 200,
     "superseded_by without a reason."),
    ("stale", {"age_seconds": 86400, "outcome": "stale", "receipt": R_FX, "trust": "primary"}, 200,
     "The mesh could not get a current answer and serves its last known receipt, a day old."),
    ("stale-verified", {"age_seconds": 0, "outcome": "stale", "receipt": R_CONVERT, "trust": "verified"}, 200,
     "A stale computed receipt the mesh had recomputed."),
    ("not-covered", {"outcome": "not_covered"}, 404, "The mesh has no receipt for this cell."),
    ("unlicensed", {"outcome": "unlicensed"}, 403, "The requester is not licensed for this cell."),
    ("payment-required", {"outcome": "payment_required", "quote": {
        "amount": "0.05", "authorise": "https://mesh.example/pay?q=7f3a", "currency": "EUR"}}, 402,
     "A quote: the amount is a decimal string, the currency a code from units.md."),
    ("rate-limited", {"outcome": "rate_limited", "retry_after_seconds": 30}, 429, "Too many requests: retry after 30 seconds."),
    ("error", {"error": "E_INPUT_UNAVAILABLE", "outcome": "error"}, 503, "The mesh could not compute the cell: an input was unavailable."),
    ("error-500", {"error": "E_FN_UNAVAILABLE", "outcome": "error"}, 500, "Any 5xx status carries outcome error."),
    ("bad-request", {"error": "E_PARSE_URI", "outcome": "bad_request"}, 400, "The requested URI is malformed."),
    ("bad-request-argument", {"error": "E_ARG_MISSING", "outcome": "bad_request"}, 400,
     "The URI omits an argument the function declares."),
]:
    add_envelope(f"envelope/{name}", why, env, status)
add_envelope("envelope/stale-earlier-asof", "A stale receipt is the last one known: its asof may be before the requested asof.",
             {"age_seconds": 172800, "outcome": "stale", "receipt": R_FX, "trust": "primary"}, 200,
             request={"asof": "2024-03-18T09:00:00.000000Z", "cell_id": cell_id(FX_CELL)})
add_envelope("invalid/envelope-stale-later-asof", "A stale receipt's asof cannot be after the requested asof.",
             {"age_seconds": 60, "outcome": "stale", "receipt": R_FX, "trust": "primary"}, 200, "E_ENVELOPE",
             request={"asof": "2024-03-15T09:00:00.000000Z", "cell_id": cell_id(FX_CELL)})
add_envelope("envelope/ok-asof-now", "A request without asof: the receipt's asof is the mesh's now, and any is accepted.",
             {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200, request={"cell_id": cell_id(FX_CELL)})

for name, env, status, error, why in [
    ("unknown-outcome", {"outcome": "maybe"}, 200, "E_ENVELOPE", "outcome is one of eight values."),
    ("ok-without-receipt", {"outcome": "ok", "trust": "primary"}, 200, "E_ENVELOPE", "ok carries a receipt."),
    ("ok-without-trust", {"outcome": "ok", "receipt": R_FX}, 200, "E_ENVELOPE", "ok carries trust."),
    ("not-covered-with-receipt", {"outcome": "not_covered", "receipt": R_FX}, 404, "E_ENVELOPE",
     "Only ok and stale carry a receipt."),
    ("status-mismatch", {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 404, "E_ENVELOPE",
     "The HTTP status matches the outcome."),
    ("error-client-status", {"error": "E_PARSE_URI", "outcome": "error"}, 400, "E_ENVELOPE", "error is a 5xx status."),
    ("trust-primary-computed", {"outcome": "ok", "receipt": R_CONVERT, "trust": "primary"}, 200, "E_ENVELOPE",
     "A receipt with inputs is not primary."),
    ("trust-primary-mirror", {"outcome": "ok", "receipt": R_MIRROR, "trust": "primary"}, 200, "E_ENVELOPE",
     "A receipt signed by another host than the namespace's is not primary."),
    ("trust-verified-for-primary", {"outcome": "ok", "receipt": R_FX, "trust": "verified"}, 200, "E_ENVELOPE",
     "A primary receipt is always labelled primary."),
    ("trust-unknown", {"outcome": "ok", "receipt": R_FX, "trust": "trusted"}, 200, "E_ENVELOPE", "trust is one of three values."),
    ("stale-without-age", {"outcome": "stale", "receipt": R_FX, "trust": "primary"}, 200, "E_ENVELOPE", "stale carries age_seconds."),
    ("age-negative", {"age_seconds": -1, "outcome": "stale", "receipt": R_FX, "trust": "primary"}, 200, "E_ENVELOPE",
     "age_seconds is a non-negative integer."),
    ("reason-without-superseded", {"outcome": "ok", "reason": "Corrected.", "receipt": R_FX, "trust": "primary"}, 200,
     "E_ENVELOPE", "reason accompanies superseded_by."),
    ("superseded-by-self", {"outcome": "ok", "receipt": R_FX, "superseded_by": H_FX, "trust": "primary"}, 200, "E_ENVELOPE",
     "A receipt cannot supersede itself."),
    ("quote-currency", {"outcome": "payment_required", "quote": {
        "amount": "0.05", "authorise": "https://mesh.example/pay", "currency": "EURO"}}, 402, "E_ENVELOPE",
     "The quote currency is a currency code."),
    ("quote-amount", {"outcome": "payment_required", "quote": {
        "amount": "0.50", "authorise": "https://mesh.example/pay", "currency": "EUR"}}, 402, "E_ENVELOPE",
     "The quote amount is a canonical decimal."),
    ("error-unknown-code", {"error": "E_TEAPOT", "outcome": "error"}, 500, "E_ENVELOPE", "error is a code from SPEC 10.2."),
    ("rate-limited-fraction", {"outcome": "rate_limited", "retry_after_seconds": 1.5}, 429, "E_ENVELOPE",
     "retry_after_seconds is a whole number of seconds."),
    ("tampered-receipt", {"outcome": "ok", "receipt": tampered(R_FX, value="1.0893"), "trust": "primary"}, 200,
     "E_SIGNATURE", "The receipt inside an envelope is verified on its own terms."),
]:
    add_envelope(f"invalid/envelope-{name}", why, env, status, error)

GBP_CELL = FX_CELL | {"args": FX_ARGS | {"quote": S("GBP")}}
for name, env, status, request, why in [
    ("wrong-cell", {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200, {"asof": ASOF, "cell_id": cell_id(GBP_CELL)},
     "A valid receipt for another cell than the one requested."),
    ("stale-wrong-cell", {"age_seconds": 60, "outcome": "stale", "receipt": R_FX, "trust": "primary"}, 200,
     {"cell_id": cell_id(GBP_CELL)}, "The binding applies to a stale receipt too."),
]:
    add_envelope(f"invalid/envelope-{name}", why, env, status, "E_ENVELOPE", request=request)
for name, env, status, why in [
    ("bad-request-status", {"error": "E_PARSE_URI", "outcome": "bad_request"}, 500, "bad_request is HTTP 400."),
    ("bad-request-code", {"error": "E_SIGNATURE", "outcome": "bad_request"}, 400,
     "bad_request carries a code that parsing a cell URI can raise."),
    ("error-envelope-code", {"error": "E_ENVELOPE", "outcome": "error"}, 500, "E_ENVELOPE is the client's code, not the mesh's."),
]:
    add_envelope(f"invalid/envelope-{name}", why, env, status, "E_ENVELOPE")
for name, raw, why in [
    ("seconds-decimal", '{"outcome": "rate_limited", "retry_after_seconds": 30.0}', "Integer members have no fraction: 30.0 is rejected."),
    ("seconds-exponent", '{"outcome": "rate_limited", "retry_after_seconds": 3e1}', "Integer members have no exponent."),
    ("seconds-negative-zero", '{"outcome": "rate_limited", "retry_after_seconds": -0}', "Integer members have no sign."),
    ("seconds-too-large", '{"outcome": "rate_limited", "retry_after_seconds": 9007199254740992}', "At most 2^53 - 1."),
]:
    add_envelope(f"invalid/envelope-{name}", why, None, 429, "E_ENVELOPE", raw=raw)

add_envelope("invalid/envelope-duplicate-member", "Envelopes are parsed strictly: no duplicate members.", None, 404,
             "E_PARSE_DUPLICATE_KEY", raw='{"outcome": "not_covered", "outcome": "ok"}')


# The one spec-0.2.1 vector whose expected result changed in spec-0.3.0 (tests/test_migration_0_3_0.py).
# It keeps its path, so the file under invalid/ is now a valid vector.
add_envelope("invalid/envelope-wrong-asof",
             "A receipt whose asof is a day earlier than the requested asof, served as ok. Changed in spec-0.3.0: "
             "valid. ok binds the receipt to an asof at or before the requested one, like stale (SPEC 5.5, D31); "
             "it was E_ENVELOPE when ok required an equal asof. The file keeps its spec-0.2.1 path.",
             {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200,
             request={"asof": "2024-03-17T09:00:00.000000Z", "cell_id": cell_id(FX_CELL)})

# ---------------------------------------------------------------------------
# Time rules that work with real lineage (spec-0.3.0: SPEC 8.2, 10.1 step 7.5, D17)

CROSS = {
    "code": {"body": "round(rates.example.org/fx_rate(base: \"EUR\", date: date, quote: quote)"
                     " / rates.example.org/fx_rate(base: \"EUR\", date: date, quote: base), 4)\n", "lang": "expr"},
    "inputs": ["rates.example.org/fx_rate"],
    "signature": {"args": {"base": SARG, "date": DARG, "quote": SARG},
                  "returns": NUM({"of": {"arg": "quote"}, "per": {"arg": "base"}})},
}
CROSS_CELL = cell_of(CROSS, CALC, "cross_rate", {"base": S("USD"), "date": D("2024-03-15"), "quote": S("GBP")})
GBP_TX = "2024-03-15T16:05:00.000000Z"
# A stored receipt that follows the SHOULD of 8.2: asof = tx. R_FX does not (its asof is later than its tx).
R_GBP_PUBLISHED = signed(receipt(GBP_CELL, "number", "0.8556",
                                 "1 EUR was worth 0.8556 GBP at the 15 March 2024 reference rate, published at 16:05 UTC.",
                                 "rates-2020", asof=GBP_TX, tx=GBP_TX), "rates-2020")
H_GBP_PUBLISHED = canon.receipt_hash(R_GBP_PUBLISHED)
CROSS_INPUTS = sorted([H_FX, H_GBP_PUBLISHED])
CROSS_RECOMPUTE = {"descriptor": CROSS, "inputs": {H_FX: text(R_FX), H_GBP_PUBLISHED: text(R_GBP_PUBLISHED)},
                   "value": N("0.7855")}


def cross_receipt(asof, issued, summary):
    return signed(receipt(CROSS_CELL, "number", "0.7855", summary, "calc-2020", asof=asof, tx=GBP_TX, issued=issued,
                          inputs=CROSS_INPUTS), "calc-2020")


add_receipt("receipt/computed-inputs-earlier-asof",
            "A computed cell with two stored inputs published at different times: their asofs (2024-03-15T16:05 and "
            "2024-03-16T09:00) differ, and both are before the receipt's asof (2024-03-16T12:00). Every input asof "
            "is at or before the receipt's (D17), and tx is the latest input tx.",
            cross_receipt("2024-03-16T12:00:00.000000Z", "2024-03-16T12:00:00.000000Z",
                          "1 USD was worth 0.7855 GBP at the 15 March 2024 reference rates, as of 12:00 UTC on 16 March."),
            "calc-2020", recompute=CROSS_RECOMPUTE)
add_receipt("receipt/computed-input-equal-asof",
            "The same inputs, with the receipt's asof equal to the later input's asof (2024-03-16T09:00), as the "
            "SHOULD of 8.2 recommends: the latest asof among the inputs.",
            cross_receipt("2024-03-16T09:00:00.000000Z", "2024-03-16T09:00:02.000000Z",
                          "1 USD was worth 0.7855 GBP at the 15 March 2024 reference rates."),
            "calc-2020", recompute=CROSS_RECOMPUTE)
R_CROSS_EARLY = cross_receipt("2024-03-16T08:00:00.000000Z", "2024-03-16T08:00:00.000000Z",
                              "Cites an input whose asof is an hour after its own.")
add_receipt("invalid/receipt-input-later-asof",
            "An input receipt's asof (2024-03-16T09:00) is after the receipt's asof (2024-03-16T08:00): the signer "
            "cites an input it could not have seen as of its own asof (10.1 step 7.5).",
            R_CROSS_EARLY, "calc-2020", "E_TIME_ORDER", recompute=CROSS_RECOMPUTE)

# Envelopes under the revised binding (SPEC 5.5 step 5, D31): ok and stale both bind to an asof at or
# before the requested one; they differ in what the mesh asserts, which the wire carries as outcome and
# age_seconds.
PAIR_REQUEST = {"asof": "2024-03-17T12:00:00.000000Z", "cell_id": cell_id(FX_CELL)}
add_envelope("envelope/ok-earlier-asof", "ok with a receipt whose asof is before the requested asof: one receipt "
             "answers every asof up to the cell's next version, and the mesh asserts it is still the latest.",
             {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200,
             request={"asof": "2024-03-20T00:00:00.000000Z", "cell_id": cell_id(FX_CELL)})
add_envelope("envelope/ok-equal-asof", "ok with a receipt whose asof equals the requested asof.",
             {"outcome": "ok", "receipt": R_CONVERT, "trust": "verified"}, 200,
             request={"asof": ASOF, "cell_id": cell_id(R_CONVERT["cell"])})
add_envelope("invalid/envelope-ok-later-asof", "ok with a receipt whose asof is a microsecond after the requested asof.",
             {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200, "E_ENVELOPE",
             request={"asof": "2024-03-16T08:59:59.999999Z", "cell_id": cell_id(FX_CELL)})
add_envelope("envelope/ok-no-requested-asof", "ok for a request without asof, which asks for now: any receipt asof is "
             "accepted.", {"outcome": "ok", "receipt": R_CONVERT, "trust": "unverified"}, 200,
             request={"cell_id": cell_id(R_CONVERT["cell"])})
add_envelope("envelope/served-ok", "The receipt and request of envelope/served-stale, served as ok: the mesh asserts "
             "that the receipt is the cell's latest version as of the requested asof.",
             {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200, request=PAIR_REQUEST)
add_envelope("envelope/served-stale", "The receipt and request of envelope/served-ok, served as stale: the mesh cannot "
             "assert that the receipt is current, and says when it last could in age_seconds.",
             {"age_seconds": 97200, "outcome": "stale", "receipt": R_FX, "trust": "primary"}, 200, request=PAIR_REQUEST)
add_envelope("invalid/envelope-stale-later-than-request", "stale with a receipt whose asof is an hour after the "
             "requested asof.", {"age_seconds": 0, "outcome": "stale", "receipt": R_CONVERT, "trust": "verified"}, 200,
             "E_ENVELOPE", request={"asof": "2024-03-16T08:00:00.000000Z", "cell_id": cell_id(R_CONVERT["cell"])})
add_envelope("invalid/envelope-stale-earlier-asof-without-age", "envelope/served-stale without age_seconds: stale "
             "requires it, and it is what tells stale from ok on the wire.",
             {"outcome": "stale", "receipt": R_FX, "trust": "primary"}, 200, "E_ENVELOPE", request=PAIR_REQUEST)
add_envelope("invalid/envelope-ok-with-age", "envelope/served-ok with age_seconds: ok does not carry it.",
             {"age_seconds": 0, "outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200, "E_ENVELOPE",
             request=PAIR_REQUEST)

# ---------------------------------------------------------------------------
# A verifier that cannot evaluate the function (spec-0.3.0: SPEC 10.1 step 7.6, E_EVAL_UNAVAILABLE).
# A recompute object without value: success at level signed, with the code reported.

add_receipt("receipt/eval-unavailable-stored", "Recomputation of a stored cell whose value cannot be looked up: 7.1-7.5 "
            "pass, 7.6 cannot run. Success at level signed, with E_EVAL_UNAVAILABLE reported.",
            R_FX, "rates-2020", recompute={"descriptor": FX, "inputs": {}})
add_receipt("receipt/eval-unavailable-computed", "A computed cell whose function the verifier cannot evaluate: the "
            "descriptor and the input receipt check out (7.1-7.5), the value is not compared. Level signed, "
            "E_EVAL_UNAVAILABLE reported.",
            R_CONVERT, "calc-2020", recompute={"descriptor": CONVERT, "inputs": {H_FX: text(R_FX)}})
add_receipt("invalid/receipt-eval-unavailable-fn-unavailable", "No descriptor and no evaluation: 7.1 fails first, so "
            "the result is E_FN_UNAVAILABLE, not E_EVAL_UNAVAILABLE.", R_FX, "rates-2020", "E_FN_UNAVAILABLE",
            recompute={"inputs": {}})
add_receipt("invalid/receipt-eval-unavailable-input-unavailable", "No evaluation, and an input receipt cannot be found: "
            "7.5 fails first.", R_CONVERT, "calc-2020", "E_INPUT_UNAVAILABLE",
            recompute={"descriptor": CONVERT, "inputs": {}})
add_receipt("invalid/receipt-eval-unavailable-input-later-asof", "No evaluation, and an input's asof is after the "
            "receipt's: 7.5 fails first.", R_CROSS_EARLY, "calc-2020", "E_TIME_ORDER",
            recompute={k: v for k, v in CROSS_RECOMPUTE.items() if k != "value"})
add_receipt("receipt/eval-unavailable-blob-checked", "No evaluation, then step 7.7 checks the blob content and "
            "passes: level signed, blob_checked, and E_EVAL_UNAVAILABLE still reported.",
            R_BLOB, "rates-2020", blob_hex=CSV.hex(), recompute={"descriptor": FILING, "inputs": {}})
add_receipt("invalid/receipt-eval-unavailable-blob-mismatch", "No evaluation, then step 7.7 fails: the blob mismatch "
            "replaces E_EVAL_UNAVAILABLE as an ordinary failure.",
            R_BLOB, "rates-2020", "E_BLOB_MISMATCH", blob_hex=CSV.replace(b"1.0892", b"1.0893").hex(),
            recompute={"descriptor": FILING, "inputs": {}})
add_envelope("envelope/error-eval-unavailable", "A mesh that could not evaluate the cell reports E_EVAL_UNAVAILABLE, "
             "a code in 10.2.", {"error": "E_EVAL_UNAVAILABLE", "outcome": "error"}, 503)

# ---------------------------------------------------------------------------
# Open library questions settled in spec-0.3.0 (DEF-16(b), DEF-17, JS note 32)

RATES_DOC = https_env(RATES, key_entry("rates-2020", T0))["https"]["body"]
add("invalid/keys-status-string", "keys", "Only the number 200 is a retrieved document: the string \"200\" is a "
    "failed retrieval like any other status (SPEC 9.3, 11).",
    host=RATES, env={"https": {"body": RATES_DOC, "status": "200"}}, error="E_KEY_UNAVAILABLE")
add("invalid/keys-status-missing", "keys", "A response without a status is a failed retrieval.",
    host=RATES, env={"https": {"body": RATES_DOC}}, error="E_KEY_UNAVAILABLE")
add_receipt("invalid/receipt-descriptor-null", "A null descriptor is a value offered for fn_hash, not an absent one: "
            "it does not hash to fn_hash (SPEC 10.1 step 7.1, 11).", R_FX, "rates-2020", "E_FN_HASH_MISMATCH",
            recompute={"descriptor": None, "inputs": {}, "value": N("1.0892")})
add_receipt("invalid/receipt-descriptor-text", "In a vector, the descriptor is a JSON value, never text to parse: a "
            "JSON string holding the descriptor's canonical text is a string, and does not hash to fn_hash.",
            R_FX, "rates-2020", "E_FN_HASH_MISMATCH",
            recompute={"descriptor": canon.jcs(FX).decode(), "inputs": {}, "value": N("1.0892")})
add("scalar/blob-media-type-long-subtype", "scalar", "The 128-character limit is on the whole media type: a subtype of "
    "126 characters is allowed, within RFC 6838's 127 per name (SPEC 3.7).", text(BL(f"{H}:17:a/" + "x" * 126)))
add("invalid/scalar-blob-media-type-long-subtype", "scalar", "A subtype of 127 characters makes the media type 129 "
    "characters long.", text(BL(f"{H}:17:a/" + "x" * 127)), "E_CANON_BLOB")


# ---------------------------------------------------------------------------
# spec-0.4.1, addition A: the pending outcome and job results (SPEC 5.5, D68).

JOB = "4f9c2a7e1b3d5f60817a9c2e4b6d8f01"  # 128 bits, as 32 lowercase hex digits
OTHER_JOB = "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a"
FX_ID = cell_id(FX_CELL)
FX_REQUEST = {"asof": ASOF, "cell_id": FX_ID}
JOB_REQUEST = {"asof": ASOF, "cell_id": FX_ID, "job": JOB}


def pending(**over):
    env = {"estimate_seconds": 5, "job": JOB, "outcome": "pending", "poll": f"https://mesh.example/jobs/{JOB}",
           "request": {"asof": ASOF, "cell_id": FX_ID}}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


add_envelope("envelope/pending", "The mesh accepted the request and is computing the cell: 202, the job, an estimate "
             "and the poll URL, with the original request echoed.", pending(), 202, request=FX_REQUEST)
add_envelope("envelope/pending-no-asof", "A pending answer to a request without asof echoes the cell id only.",
             pending(request={"cell_id": FX_ID}), 202, request={"cell_id": FX_ID})
add_envelope("envelope/pending-polled", "GET /jobs/<job> while the job is still running returns the pending envelope "
             "again; it is bound to the original request and to the job polled.", pending(estimate_seconds=2), 202,
             request=JOB_REQUEST)
add_envelope("envelope/job-result-ok", "GET /jobs/<job> once the job is done: the envelope the /cell call would have "
             "returned, checked against the original request (cell and asof), not the job URL.",
             {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200, request=JOB_REQUEST)
add_envelope("envelope/job-result-not-covered", "A job may complete with any outcome but pending's own: here the "
             "mesh found no receipt.", {"outcome": "not_covered"}, 404, request=JOB_REQUEST)
add_envelope("envelope/job-unknown", "An unknown or expired job id: bad_request with E_JOB_UNKNOWN, the request's "
             "fault, never a completed not_covered.", {"error": "E_JOB_UNKNOWN", "outcome": "bad_request"}, 400,
             request=JOB_REQUEST)
add_envelope("envelope/pending-poll-other-host", "poll on another host than the mesh asked passes the envelope check, "
             "which does not know that host: the client's HTTP layer refuses to send it.",
             pending(poll=f"https://other.example.net/jobs/{JOB}"), 202, request=FX_REQUEST)
for name, env, status, request, why in [
    ("pending-missing-poll", pending(poll=None), 202, FX_REQUEST, "pending requires poll."),
    ("pending-missing-job", pending(job=None, poll="https://mesh.example/jobs/"), 202, FX_REQUEST, "pending requires job."),
    ("pending-missing-estimate", pending(estimate_seconds=None), 202, FX_REQUEST, "pending requires estimate_seconds."),
    ("pending-missing-request", pending(request=None), 202, FX_REQUEST, "pending requires the original request."),
    ("pending-with-receipt", pending(receipt=R_FX), 202, FX_REQUEST, "pending carries no receipt."),
    ("pending-with-trust", pending(trust="primary"), 202, FX_REQUEST, "pending carries no trust."),
    ("pending-short-job", pending(job=JOB[:31], poll=f"https://mesh.example/jobs/{JOB[:31]}"), 202, FX_REQUEST,
     "A job id has at least 32 hex digits (128 bits)."),
    ("pending-uppercase-job", pending(job=JOB.upper(), poll=f"https://mesh.example/jobs/{JOB.upper()}"), 202,
     FX_REQUEST, "A job id is lowercase hex."),
    ("pending-http-poll", pending(poll=f"http://mesh.example/jobs/{JOB}"), 202, FX_REQUEST, "poll is an https URL."),
    ("pending-poll-other-job", pending(poll=f"https://mesh.example/jobs/{OTHER_JOB}"), 202, FX_REQUEST,
     "poll is the URL of this envelope's job: it ends /jobs/<job>."),
    ("pending-status", pending(), 200, FX_REQUEST, "pending is HTTP 202."),
    ("pending-request-extra", pending(request={"asof": ASOF, "cell_id": FX_ID, "trust": "primary"}), 202, FX_REQUEST,
     "The echoed request has cell_id and, if one was given, asof; nothing else."),
    ("pending-other-cell", pending(request={"asof": ASOF, "cell_id": cell_id(R_CONVERT["cell"])}), 202, FX_REQUEST,
     "The echoed request names another cell than the one asked for."),
    ("pending-asof-dropped", pending(request={"cell_id": FX_ID}), 202, FX_REQUEST,
     "The request carried an asof, which the echo drops."),
    ("pending-asof-added", pending(), 202, {"cell_id": FX_ID}, "The echo carries an asof the request did not."),
    ("pending-polled-other-job", pending(job=OTHER_JOB, poll=f"https://mesh.example/jobs/{OTHER_JOB}"), 202,
     JOB_REQUEST, "Polled /jobs/<job>, the mesh answered for another job."),
    ("job-result-other-cell", {"outcome": "ok", "receipt": R_CONVERT, "trust": "verified"}, 200, JOB_REQUEST,
     "The job's result is a receipt for another cell than the original request's: step 5 against the original "
     "request fails."),
    ("job-result-later-asof", {"outcome": "ok", "receipt": R_FX, "trust": "primary"}, 200,
     {"asof": "2024-03-15T09:00:00.000000Z", "cell_id": FX_ID, "job": JOB},
     "The job's result has an asof after the original request's: step 5 against the original request fails."),
    ("pending-poll-empty-host", pending(poll=f"https:///jobs/{JOB}"), 202, FX_REQUEST,
     "poll names a host: https://, a DNS name, then the path."),
    ("pending-poll-port", pending(poll=f"https://mesh.example:8443/jobs/{JOB}"), 202, FX_REQUEST,
     "poll's host is a DNS name, with no port (or userinfo)."),
    ("job-unknown-on-cell", {"error": "E_JOB_UNKNOWN", "outcome": "bad_request"}, 400, FX_REQUEST,
     "E_JOB_UNKNOWN answers a job URL only, not a /cell request."),
    ("error-job-unknown", {"error": "E_JOB_UNKNOWN", "outcome": "error"}, 500, JOB_REQUEST,
     "An unknown job is bad_request, not a mesh error."),
]:
    add_envelope(f"invalid/envelope-{name}", why, env, status, "E_ENVELOPE", request=request)

# ---------------------------------------------------------------------------
# spec-0.4.1, addition B: the mesh document /.well-known/datumesh-mesh.json (SPEC 9.6, D69).

MESH_HOST = "mesh.example.org"
MB = f"https://{MESH_HOST}"
MESH_ENDPOINTS = {"blob": f"{MB}/blob/{{sha256}}", "cell": f"{MB}/cell/{{cell}}", "cells": f"{MB}/cells",
                  "descriptor": f"{MB}/descriptor/{{hash}}", "explain": f"{MB}/explain/{{cell}}", "find": f"{MB}/find",
                  "jobs": f"{MB}/jobs/{{job}}", "manifest": f"{MB}/manifest/{{slice_id}}/{{members_hash}}",
                  "receipt": f"{MB}/receipt/{{hash}}", "slice": f"{MB}/slice/{{cell}}", "verify": f"{MB}/verify"}


def mesh_doc(endpoints=None, **over):
    doc = {"bindings": f"{MB}/bindings", "endpoints": dict(MESH_ENDPOINTS, **(endpoints or {})), "host": MESH_HOST,
           "proto": canon.PROTO}
    doc.update(over)
    return {k: v for k, v in doc.items() if v is not None}


def mesh_env(mesh=None, keys=None, mesh_status=200, key_status=200):
    keydoc = keys or {"host": MESH_HOST, "keys": [key_entry("calc-2020", T0)], "proto": canon.PROTO}
    e = {"keys": {"https": {"status": key_status}}, "mesh": {"https": {"status": mesh_status}}}
    if key_status == 200:
        e["keys"]["https"]["body"] = keydoc if isinstance(keydoc, str) else json.dumps(keydoc, indent=2)
    if mesh_status == 200:
        e["mesh"]["https"]["body"] = mesh if isinstance(mesh, str) else json.dumps(mesh or mesh_doc(), indent=2)
    return e


REQUIRED_ONLY = {k: v for k, v in MESH_ENDPOINTS.items() if k in canon.MESH_REQUIRED}
for name, e, error, why in [
    ("mesh/full", mesh_env(), None, "A mesh document naming every endpoint of 9.6; it agrees with the key document "
     "on host and proto."),
    ("mesh/required-only", mesh_env(mesh_doc() | {"endpoints": REQUIRED_ONLY}),
     None, "Only the required endpoints: cell, descriptor, jobs, manifest, receipt."),
    ("mesh/extension-members", mesh_env(mesh_doc({"x_graphql": f"{MB}/graphql"}, x_status="beta")), None,
     "Unknown members, at the top level and in endpoints, are ignored: they are not in the result."),
    ("invalid/mesh-host-mismatch", mesh_env(mesh_doc(host="other.example.org")), "E_MESH_DOC",
     "The mesh document names another host than the one fetched (and than the key document)."),
    ("invalid/mesh-proto-mismatch", mesh_env(mesh_doc(proto="datumesh/2")), "E_MESH_DOC",
     "The mesh document's proto differs from the key document's."),
    ("invalid/mesh-key-doc-proto-mismatch", mesh_env(keys={"host": MESH_HOST, "keys": [key_entry("calc-2020", T0)],
                                                           "proto": "datumesh/2"}), "E_MESH_DOC",
     "The key document's proto differs from the mesh document's: the identity check comes before the key "
     "document's own rules."),
    ("invalid/mesh-key-doc-other-host", mesh_env(keys={"host": "other.example.org", "keys": [key_entry("calc-2020", T0)],
                                                       "proto": canon.PROTO}), "E_MESH_DOC",
     "The key document names another host: the two documents do not describe the same mesh."),
    ("invalid/mesh-endpoint-other-host", mesh_env(mesh_doc({"cell": "https://other.example.org/cell/{cell}"})),
     "E_MESH_DOC", "An endpoint on another host: a mesh document speaks for its own host only."),
    ("invalid/mesh-bindings-other-host", mesh_env(mesh_doc(bindings="https://other.example.org/bindings")),
     "E_MESH_DOC", "The bindings URL on another host."),
    ("invalid/mesh-malformed", mesh_env("{\"host\": \"mesh.example.org\","), "E_MESH_DOC",
     "The mesh document is not strict JSON."),
    ("invalid/mesh-not-object", mesh_env("[]"), "E_MESH_DOC", "The mesh document is not a JSON object."),
    ("invalid/mesh-duplicate-member", mesh_env('{"host": "mesh.example.org", "host": "mesh.example.org"}'),
     "E_MESH_DOC", "The mesh document is parsed strictly: no duplicate members."),
    ("invalid/mesh-missing-endpoints", mesh_env({k: v for k, v in mesh_doc().items() if k != "endpoints"}), "E_MESH_DOC",
     "endpoints is required, an object."),
    ("invalid/mesh-missing-required-endpoint", mesh_env(mesh_doc() | {"endpoints": {
        k: v for k, v in MESH_ENDPOINTS.items() if k != "jobs"}}), "E_MESH_DOC",
     "jobs is required: a client given a pending envelope must be able to poll."),
    ("invalid/mesh-missing-placeholder", mesh_env(mesh_doc({"receipt": f"{MB}/receipt"})), "E_MESH_DOC",
     "The receipt template lacks its {hash} placeholder."),
    ("invalid/mesh-unknown-placeholder", mesh_env(mesh_doc({"cell": f"{MB}/cell/{{cell}}?v={{version}}"})),
     "E_MESH_DOC", "A known endpoint has exactly its own placeholders."),
    ("invalid/mesh-http-endpoint", mesh_env(mesh_doc({"cell": f"http://{MESH_HOST}/cell/{{cell}}"})), "E_MESH_DOC",
     "Endpoints are https URLs."),
    ("invalid/mesh-unavailable", mesh_env(mesh_status=404), "E_MESH_DOC",
     "No mesh document: the host cannot be resolved across meshes (its receipts still verify)."),
    ("invalid/mesh-key-doc-unavailable", mesh_env(key_status=404), "E_KEY_UNAVAILABLE",
     "No key document: the key document's own code, as in 9.3."),
    ("invalid/mesh-key-doc-malformed", mesh_env(keys="{not json"), "E_KEY_DOC",
     "A key document that is not strict JSON keeps its own code."),
    ("invalid/mesh-key-doc-not-object", mesh_env(keys="[]"), "E_KEY_DOC",
     "A key document that is JSON but not an object: step 4 has no key side to compare, and step 5 fails."),
    ("invalid/mesh-key-doc-no-proto", mesh_env(keys={"host": MESH_HOST, "keys": [key_entry("calc-2020", T0)]}),
     "E_KEY_DOC", "A key document without proto: step 4 compares only a string proto, and step 5 fails."),
    ("invalid/mesh-key-doc-no-body", {"keys": {"https": {"status": 200}}, "mesh": {"https": {"status": 404}}},
     "E_KEY_DOC", "A 200 key-document response without a body is E_KEY_DOC at step 1, before the mesh document "
     "is retrieved."),
    ("invalid/mesh-endpoint-lone-brace", mesh_env(mesh_doc({"cell": f"{MB}/cell/{{cell}}}}"})), "E_MESH_DOC",
     "Every brace of a template belongs to one of its placeholders: a lone } fails."),
    ("invalid/mesh-endpoint-empty-placeholder", mesh_env(mesh_doc({"find": f"{MB}/find/{{}}"})), "E_MESH_DOC",
     "{} is no placeholder of find, which has none."),
    ("invalid/mesh-endpoint-port", mesh_env(mesh_doc({"cell": f"https://{MESH_HOST}:443/cell/{{cell}}"})),
     "E_MESH_DOC", "A URL is on the host only when it begins https://<host>/: a port fails, even the default one."),
    ("invalid/mesh-endpoint-userinfo", mesh_env(mesh_doc({"cell": f"https://user@{MESH_HOST}/cell/{{cell}}"})),
     "E_MESH_DOC", "Userinfo before the host fails: the URL does not begin https://<host>/."),
    ("invalid/mesh-endpoint-no-path", mesh_env(mesh_doc({"cell": f"https://{MESH_HOST}?c={{cell}}"})), "E_MESH_DOC",
     "A query right after the host fails: the URL does not begin https://<host>/."),
    ("mesh/bindings-with-braces", mesh_env(mesh_doc(bindings=f"{MB}/bindings/{{x}}}}")), None,
     "bindings is a URL, not a template: its braces are not checked."),
    ("mesh/unknown-endpoint-unchecked", mesh_env(mesh_doc({"x_graphql": "not a URL {"})), None,
     "Unknown endpoints are not checked, and are dropped from the result."),
]:
    add(name, "mesh", why, error=error, host=MESH_HOST, env=e)

# spec-0.4.0: the formula dialect and slice-as-lineage (tools/gen_formula.py).
import gen_formula  # noqa: E402

gen_formula.add_all(add, text)


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    for vec in VECTORS:
        path = OUT / f"{vec['id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(vec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    examples = ROOT / "examples"
    examples.mkdir(exist_ok=True)
    for name, obj in [("fx_rate.function.json", FX), ("receipt.json", R_FX), ("keyenv.json", {RATES: RATES_ENV})]:
        (examples / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    valid = sum(v["valid"] for v in VECTORS)
    print(f"wrote {len(VECTORS)} vectors ({valid} valid, {len(VECTORS) - valid} invalid)")


if __name__ == "__main__":
    main()
