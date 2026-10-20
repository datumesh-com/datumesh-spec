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
OUTPUT_FIELDS = ("object", "canonical", "sha256", "https", "key_id", "key_ids", "sig", "level")


def add(id_, kind, description, input=None, error=None, input_hex=None, **extra):
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
    ("type-unknown", text({"type": "decimal", "value": "1"}), "E_CANON_TYPE", "There are exactly five types."),
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
        "returns": "number",
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
            "amount": {"type": "number", "valid": False},
            "base": {"type": "string", "valid": False},
            "date": {"type": "date", "valid": True},
            "quote": {"type": "string", "valid": False},
        },
        "returns": "number",
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
PI = {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": {"args": {}, "returns": "number"}}
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
    text({**FX, "signature": {"args": {"n": {"type": "number", "valid": True}}, "returns": "number"}}), "E_CANON_TYPE")

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
        "ratio": {"type": "number", "valid": False},
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
    return {"https": {"status": 200, "body": json.dumps(doc, indent=2)}, "dns": {"status": "nxdomain"}}


def txt(name, valid_from, valid_to=None):
    record = f"v=datumesh1; alg=ed25519; pub={keypair_fields(name)['public']}; from={valid_from}"
    return record + (f"; to={valid_to}" if valid_to else "")


def dns_env(*records, https_status=404):
    return {"https": {"status": https_status}, "dns": {"status": "ok", "records": list(records)}}


T0 = "2020-01-01T00:00:00.000000Z"
ROTATE = "2024-06-01T00:00:00.000000Z"

for name in ("rates-2020", "calc-2020"):
    kp = keypair_fields(name)
    add(f"keyid/{name}", "keyid",
        "Key id: the first 16 hex digits of SHA-256 over the raw 32-byte Ed25519 public key.", kp["public"])

add("keys/https-document", "keys", "Keys come from https://<host>/.well-known/datumesh.json when it exists.",
    host="rates.example.org",
    env=https_env("rates.example.org", key_entry("rates-2020", T0, ROTATE), key_entry("rates-2024", ROTATE)))
add("keys/dns-fallback", "keys", "With no HTTPS document (404), TXT records at _datumesh.<host> are used; other TXT records are ignored.",
    host="rates.example.org", env=dns_env("v=spf1 -all", txt("rates-2020", T0, ROTATE), txt("rates-2024", ROTATE)))
add("keys/https-wins", "keys", "When the HTTPS document exists, DNS is not consulted.",
    host="rates.example.org",
    env=https_env("rates.example.org", key_entry("rates-2024", ROTATE)) | {"dns": {"status": "ok", "records": [txt("rates-2020", T0)]}})
add("invalid/keys-https-error", "keys", "An HTTPS failure other than 404/410 does not fall back to DNS.",
    host="rates.example.org", env=dns_env(txt("rates-2020", T0), https_status=503), error="E_KEY_UNAVAILABLE")
add("invalid/keys-dns-error", "keys", "A DNS failure after a 404 is unavailable, not unknown.",
    host="rates.example.org", env={"https": {"status": 404}, "dns": {"status": "error"}}, error="E_KEY_UNAVAILABLE")
add("invalid/keys-none-published", "keys", "No document and no TXT records: the host publishes no keys.",
    host="rates.example.org", env={"https": {"status": 404}, "dns": {"status": "nxdomain"}}, error="E_KEY_UNKNOWN")
bad_doc = json.loads(https_env("rates.example.org", key_entry("rates-2020", T0))["https"]["body"])
bad_doc["keys"][0]["id"] = "0000000000000000"
add("invalid/keys-wrong-id", "keys", "A key document whose id is not derived from its public key is rejected whole.",
    host="rates.example.org", env={"https": {"status": 200, "body": json.dumps(bad_doc)}}, error="E_KEY_DOC")
add("invalid/keys-host-mismatch", "keys", "A key document names the host it was fetched from.",
    host="rates.example.org", env=https_env("other.example.org", key_entry("rates-2020", T0)), error="E_KEY_DOC")
add("invalid/keys-bad-txt", "keys", "A TXT record starting v=datumesh1 must match the grammar exactly.",
    host="rates.example.org", env=dns_env(f"v=datumesh1;alg=ed25519;pub={keypair_fields('rates-2020')['public']};from={T0}"),
    error="E_KEY_DOC")

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


def add_receipt(id_, description, r, key, error=None, keys=KEYENV, recompute=None, raw=None):
    extra = {"keypair": keypair_fields(key), "keys": keys}
    if recompute is not None:
        extra["recompute"] = recompute
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
            "Keys for calendars.example.org/eu are published by the host calendars.example.org, here via DNS.",
            signed(R_HOLIDAY, "calendars-2020"), "calendars-2020",
            keys={"calendars.example.org": dns_env(txt("calendars-2020", T0))})

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
add_receipt("receipt/dns-published-key", "The publisher has no HTTPS key document; its key is in DNS.",
            R_FX, "rates-2020", keys={RATES: dns_env(txt("rates-2020", T0, ROTATE))})


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
    ("key-https-authoritative", R_FX, "E_KEY_UNKNOWN", "rates-2020", "DNS lists the key but the HTTPS document, which wins, does not.",
     {"keys": {RATES: https_env(RATES, key_entry("rates-2024", ROTATE)) | {"dns": {"status": "ok", "records": [txt("rates-2020", T0)]}}}}),
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
fewer_args = {**FX, "signature": {**FX["signature"], "args": {k: v for k, v in FX["signature"]["args"].items() if k != "quote"}}}
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
