#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Datumesh reference canonicaliser and vector checker.

This is a test tool. It exists to generate and check the vectors in
../vectors and to make every rule in SPEC.md executable. It is written for
readability next to the spec, not for speed or for distribution.

    python3 tools/canon.py check                 check every vector in vectors/
    python3 tools/canon.py jcs FILE              print the JCS form of a JSON file
    python3 tools/canon.py uri URI DESCRIPTOR    print the canonical object of a cell URI
    python3 tools/canon.py verify RECEIPT KEYENV verify a receipt against a key environment
    python3 tools/canon.py unit DESCRIPTOR CELL  print the unit of a cell's value (CELL may be a receipt)

Requires Python >= 3.13 (Unicode >= 15.1) and PyNaCl.
"""

import bisect
import datetime
import hashlib
import json
import math
import pathlib
import re
import sys
import unicodedata

import nacl.exceptions
import nacl.signing

PROTO = "datumesh/1"
ROOT = pathlib.Path(__file__).resolve().parent.parent

if tuple(int(p) for p in unicodedata.unidata_version.split(".")) < (15, 1, 0):
    raise SystemExit(
        f"canon.py needs Unicode >= 15.1 (Python >= 3.13); this Python has {unicodedata.unidata_version}"
    )

# Section 10 of SPEC.md. The order here is the order of the table there.
ERROR_CODES = (
    "E_PARSE_JSON",
    "E_PARSE_DUPLICATE_KEY",
    "E_PARSE_URI",
    "E_SCHEMA",
    "E_CANON_NAME",
    "E_CANON_ARG_NAME",
    "E_CANON_ARG_DUPLICATE",
    "E_CANON_ARG_ORDER",
    "E_CANON_PERCENT",
    "E_CANON_TYPE",
    "E_CANON_NUMBER",
    "E_CANON_UNIT",
    "E_CANON_DATE",
    "E_CANON_INSTANT",
    "E_CANON_STRING",
    "E_CANON_BLOB",
    "E_CANON_HEX",
    "E_CANON_LICENCE",
    "E_CANON_SET",
    "E_CANON_LIMIT",
    "E_SLICE",
    "E_PUBLISHER_MISMATCH",
    "E_VALID_MISMATCH",
    "E_TIME_ORDER",
    "E_ARG_UNKNOWN",
    "E_ARG_MISSING",
    "E_KEY_UNAVAILABLE",
    "E_KEY_DOC",
    "E_KEY_UNKNOWN",
    "E_KEY_NOT_VALID",
    "E_SIGNATURE",
    "E_FN_UNAVAILABLE",
    "E_FN_HASH_MISMATCH",
    "E_ARG_TYPE",
    "E_RETURN_TYPE",
    "E_INPUT_UNAVAILABLE",
    "E_INPUT_INVALID",
    "E_INPUT_UNDECLARED",
    "E_SLICE_MEMBER",
    "E_VALUE_MISMATCH",
    "E_EVAL_UNAVAILABLE",
    "E_INPUT_SUPERSEDED",
    "E_BLOB_MISMATCH",
    "E_ENVELOPE",
    "E_JOB_UNKNOWN",
    "E_MESH_DOC",
)

# Section 4.5 of SPEC.md.
LIMITS = {
    "name": 64,  # function name, path segment, argument name, code language (characters)
    "function_name": 512,  # namespace + "/" + function (characters)
    "args": 32,  # arguments per cell
    "number": 128,  # characters in a number's lexical form
    "string": 1024,  # UTF-8 bytes in a string value
    "summary": 1024,  # UTF-8 bytes in a receipt summary
    "body": 1048576,  # UTF-8 bytes in a function body
    "inputs": 4096,  # entries in a receipt's or descriptor's inputs
    "licence_spdx": 64,  # characters
    "licence_url": 512,  # characters
    "keys": 64,  # keys in one key publication
    "extent": 4096,  # values in an argument's extent
    "members": 1048576,  # members in a slice manifest
}

TYPES = ("blob", "boolean", "date", "instant", "number", "string")
VALID_TIME_TYPES = ("date", "instant", "string")
SLICE = "*"
RESERVED_ARG_NAMES = ("asof",)
RESERVED_ARG_PREFIX = "dm_"


class DatumeshError(Exception):
    """A rule violation carrying one of ERROR_CODES."""

    def __init__(self, code, detail="", path="$"):
        assert code in ERROR_CODES, code
        self.code, self.detail, self.path = code, detail, path
        super().__init__(f"{code} at {path}: {detail}")


def fail(code, detail, path="$"):
    raise DatumeshError(code, detail, path)


# ---------------------------------------------------------------------------
# Strict JSON parsing (SPEC.md 6.1): UTF-8, no BOM, no duplicate members,
# no lone surrogates, no NaN/Infinity. Numbers parse as IEEE 754 doubles.

_SURROGATE = re.compile("[\ud800-\udfff]")


class JsonInteger(float):
    """A JSON number written without fraction or exponent; keeps its text (SPEC 5.5)."""

    def __new__(cls, text):
        obj = super().__new__(cls, text)
        obj.text = text
        return obj


def parse_json(data, keep_integer_text=False):
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            fail("E_PARSE_JSON", f"invalid UTF-8: {e.reason}")
    else:
        text = data
    if text.startswith("﻿"):
        fail("E_PARSE_JSON", "byte order mark")
    _check_depth(text)

    def object_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                fail("E_PARSE_DUPLICATE_KEY", f"duplicate member {key!r}")
            obj[key] = value
        return obj

    def number(literal):
        value = float(literal)
        if math.isinf(value):
            fail("E_PARSE_JSON", f"number out of IEEE 754 range: {literal}")
        return value

    def integer(literal):
        number(literal)  # range check
        return JsonInteger(literal)

    def constant(name):
        fail("E_PARSE_JSON", f"{name} is not JSON")

    try:
        value = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_float=number,
            parse_int=integer if keep_integer_text else number,
            parse_constant=constant,
        )
    except (ValueError, RecursionError) as e:
        fail("E_PARSE_JSON", str(e))
    _reject_surrogates(value)
    return value


MAX_DEPTH = 64


def _check_depth(text):
    """SPEC.md 6.1: at most 64 nested arrays and objects, counting [ and { outside strings.
    Checked before anything else in the text, so it is reported whatever else is wrong."""
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                fail("E_PARSE_JSON", f"nested deeper than {MAX_DEPTH} levels")
        elif ch in "]}":
            depth -= 1


def _reject_surrogates(value, path="$"):
    if isinstance(value, str):
        if _SURROGATE.search(value):
            fail("E_PARSE_JSON", "lone surrogate", path)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _reject_surrogates(item, f"{path}[{i}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            if _SURROGATE.search(key):
                fail("E_PARSE_JSON", "lone surrogate in member name", path)
            _reject_surrogates(item, f"{path}.{key}")


# ---------------------------------------------------------------------------
# RFC 8785 JSON Canonicalization Scheme. This is the only serialiser for
# anything hashed or signed in this repository.


def jcs(value):
    parts = []
    _jcs(value, parts)
    return "".join(parts).encode("utf-8")


def _jcs(value, out):
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, (int, float)):
        out.append(_jcs_number(float(value)))
    elif isinstance(value, str):
        out.append(_jcs_string(value))
    elif isinstance(value, list):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _jcs(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(value, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(_jcs_string(key))
            out.append(":")
            _jcs(value[key], out)
        out.append("}")
    else:
        raise TypeError(f"not a JSON value: {value!r}")


def _utf16_key(key):
    # RFC 8785 3.2.3: members sorted by their UTF-16 code units.
    return key.encode("utf-16-be")


_JCS_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _jcs_string(text):
    out = ['"']
    for ch in text:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c < 0x20:
            out.append(_JCS_ESCAPES.get(c) or "\\u%04x" % c)
        elif 0xD800 <= c <= 0xDFFF:
            fail("E_PARSE_JSON", "lone surrogate")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_number(x):
    # ECMAScript Number.prototype.toString, which RFC 8785 3.2.2.3 adopts.
    if math.isnan(x) or math.isinf(x):
        fail("E_PARSE_JSON", "NaN and Infinity have no JSON form")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    # repr() gives the shortest digits that round-trip, as ECMAScript requires.
    mantissa, _, exponent = repr(abs(x)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    scale = int(exponent or "0") - len(fraction)
    trimmed = digits.rstrip("0")
    scale += len(digits) - len(trimmed)
    digits = trimmed
    k = len(digits)
    n = k + scale  # value = 0.digits * 10^n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    exp = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return sign + digits + "e" + exp
    return sign + digits[0] + "." + digits[1:] + "e" + exp


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Unicode: strings may only contain code points assigned in Unicode 15.1.


def _load_assigned():
    starts, ends = [], []
    for line in (ROOT / "tools" / "unicode-15.1-assigned.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            a, b = line.split("..")
            starts.append(int(a, 16))
            ends.append(int(b, 16))
    return starts, ends


_ASSIGNED_STARTS, _ASSIGNED_ENDS = _load_assigned()


def assigned_in_15_1(c):
    i = bisect.bisect_right(_ASSIGNED_STARTS, c) - 1
    return i >= 0 and c <= _ASSIGNED_ENDS[i]


_PLAIN_ASCII = re.compile(r"[\x20-\x7e]*")


def check_text(text, path, limit, multiline=False):
    """String rules (SPEC.md 3.5): characters, then NFC, then length."""
    if not _PLAIN_ASCII.fullmatch(text):
        for ch in text:
            c = ord(ch)
            if c < 0x20 and not (multiline and ch in "\t\n"):
                fail("E_CANON_STRING", f"control character U+{c:04X}", path)
            if 0x7F <= c <= 0x9F:
                fail("E_CANON_STRING", f"control character U+{c:04X}", path)
            if 0xD800 <= c <= 0xDFFF:
                fail("E_CANON_STRING", f"surrogate U+{c:04X}", path)
            if not assigned_in_15_1(c):
                fail("E_CANON_STRING", f"U+{c:04X} is not assigned in Unicode 15.1", path)
        if not unicodedata.is_normalized("NFC", text):
            fail("E_CANON_STRING", "not in Normalization Form C", path)
    if len(text.encode("utf-8")) > LIMITS[limit]:
        fail("E_CANON_LIMIT", f"longer than {LIMITS[limit]} UTF-8 bytes", path)


# ---------------------------------------------------------------------------
# Lexical forms of scalar values (SPEC.md section 3).

_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
_DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_INSTANT = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{6}Z"
)


def check_number(text, path):
    if not _NUMBER.fullmatch(text) or text == "-0":
        fail("E_CANON_NUMBER", f"not a canonical decimal: {text!r}", path)
    if len(text) > LIMITS["number"]:
        fail("E_CANON_LIMIT", f"number longer than {LIMITS['number']} characters", path)


def _calendar_date(y, m, d):
    try:
        datetime.date(int(y), int(m), int(d))
        return True
    except ValueError:
        return False


def check_date(text, path):
    m = _DATE.fullmatch(text)
    if not m or not _calendar_date(*m.groups()):
        fail("E_CANON_DATE", f"not a YYYY-MM-DD calendar date: {text!r}", path)


def check_instant(text, path):
    m = _INSTANT.fullmatch(text)
    ok = (
        m is not None
        and _calendar_date(*m.groups()[:3])
        and int(m.group(4)) < 24
        and int(m.group(5)) < 60
        and int(m.group(6)) < 60
    )
    if not ok:
        fail("E_CANON_INSTANT", f"not YYYY-MM-DDTHH:MM:SS.ffffffZ: {text!r}", path)


MAX_SAFE_INTEGER = 2**53 - 1
_BLOB = re.compile(
    r"([0-9a-f]{64}):(0|[1-9][0-9]*):"
    r"([a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*)"
)


def check_blob(text, path):
    """A blob (SPEC.md 3.7): <sha256 hex>:<length>:<media type>."""
    m = _BLOB.fullmatch(text)
    if not m:
        fail("E_CANON_BLOB", f"not <sha256>:<length>:<type/subtype>: {text!r}", path)
    if len(m.group(2)) > 16 or int(m.group(2)) > MAX_SAFE_INTEGER:
        fail("E_CANON_BLOB", f"length above {MAX_SAFE_INTEGER}", path)
    if len(m.group(3)) > 128:
        fail("E_CANON_BLOB", "media type longer than 128 characters", path)


def check_blob_content(text, content, path="$.value"):
    """Step 7.7: content bytes match the blob's length and hash."""
    digest, length, _ = text.split(":", 2)
    if len(content) != int(length):
        fail("E_BLOB_MISMATCH", f"content is {len(content)} bytes, blob says {length}", path)
    if sha256_hex(content) != digest:
        fail("E_BLOB_MISMATCH", "content does not hash to the blob's sha256", path)


def check_lexical(type_, value, path):
    """Check value against type_, which must already be one of TYPES."""
    if type_ == "boolean":
        if not isinstance(value, bool):
            fail("E_CANON_TYPE", "boolean value must be JSON true or false", path)
        return
    if not isinstance(value, str):
        fail("E_CANON_TYPE", f"{type_} value must be a JSON string", path)
    if type_ == "number":
        check_number(value, path)
    elif type_ == "date":
        check_date(value, path)
    elif type_ == "instant":
        check_instant(value, path)
    elif type_ == "blob":
        check_blob(value, path)
    else:
        check_text(value, path, "string")


# ---------------------------------------------------------------------------
# Units (SPEC.md 7.1 and units.md). The list is read from units.md.


def _load_units():
    lists = {}
    text = (ROOT / "units.md").read_text(encoding="utf-8")
    for kind, body in re.findall(r"```units-([a-z]+)\n(.*?)```", text, re.S):
        lists.setdefault(kind, []).extend(body.split())
    return {kind: frozenset(items) for kind, items in lists.items()}


UNITS = _load_units()
CURRENCIES = UNITS["currency"]
_INDEX_UNIT = re.compile(
    r"index:([0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2}))?)?=((?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?)"
)


def is_unit_literal(text):
    if any(text in items for items in UNITS.values()):
        return True
    m = _INDEX_UNIT.fullmatch(text)
    if not m or len(text) > 64 or m.group(4) == "0":
        return False
    year, month, day, _ = m.groups()
    return _calendar_date(year, month or "01", day or "01")


def check_type_name(type_, path):
    if type_ not in TYPES:
        fail("E_CANON_TYPE", f"unknown type {type_!r}", path)


# ---------------------------------------------------------------------------
# Names (SPEC.md section 2).

_NAME = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_HEX = re.compile(r"[0-9a-f]*")


def check_name(text, path, code="E_CANON_NAME"):
    if not _NAME.fullmatch(text):
        fail(code, f"not a lowercase snake_case name: {text!r}", path)
    if len(text) > LIMITS["name"]:
        fail("E_CANON_LIMIT", f"name longer than {LIMITS['name']} characters", path)


def check_dns_name(text, path):
    labels = text.split(".")
    if len(labels) < 2:
        fail("E_CANON_NAME", f"DNS name needs at least two labels: {text!r}", path)
    if len(text) > 253:
        fail("E_CANON_NAME", "DNS name longer than 253 characters", path)
    for label in labels:
        if not _LABEL.fullmatch(label) or len(label) > 63:
            fail("E_CANON_NAME", f"bad DNS label {label!r}", path)
    if labels[-1].isdigit():
        fail("E_CANON_NAME", "top-level label is numeric", path)


def check_namespace(text, path):
    host, *segments = text.split("/")
    check_dns_name(host, path)
    for segment in segments:
        check_name(segment, path)


def check_function_name(text, path):
    """A fully qualified function name: namespace "/" function."""
    namespace, slash, function = text.rpartition("/")
    if not slash:
        fail("E_CANON_NAME", f"function name has no namespace: {text!r}", path)
    check_namespace(namespace, path)
    check_name(function, path)
    if len(text) > LIMITS["function_name"]:
        fail("E_CANON_LIMIT", "function name too long", path)


def check_arg_name(name, path):
    check_name(name, path, "E_CANON_ARG_NAME")
    if name in RESERVED_ARG_NAMES or name.startswith(RESERVED_ARG_PREFIX):
        fail("E_CANON_ARG_NAME", f"reserved argument name {name!r}", path)


def check_hex(text, length, path):
    if len(text) != length or not _HEX.fullmatch(text):
        fail("E_CANON_HEX", f"expected {length} lowercase hex digits", path)


_SPDX = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
_URL = re.compile(r"https://[!-~]+")


def check_licence(text, path):
    if text.startswith("https://"):
        if not _URL.fullmatch(text):
            fail("E_CANON_LICENCE", "licence URL has characters outside printable ASCII", path)
        if len(text) > LIMITS["licence_url"]:
            fail("E_CANON_LIMIT", "licence URL too long", path)
    else:
        if not _SPDX.fullmatch(text):
            fail("E_CANON_LICENCE", f"not an SPDX identifier or https URL: {text!r}", path)
        if len(text) > LIMITS["licence_spdx"]:
            fail("E_CANON_LIMIT", "licence identifier too long", path)


def check_key_ref(text, path):
    host, hash_, kid = text.partition("#")
    if not hash_:
        fail("E_CANON_NAME", "key reference must be <dns-name>#<key id>", path)
    check_dns_name(host, path)
    check_hex(kid, 16, path)


_SLICE_ENTRY = re.compile(r"slice:[0-9a-f]{64}:[0-9a-f]{64}")


def check_input_entry(entry, path):
    """An inputs entry (SPEC 8.1, 15.13): a receipt hash, or slice:<slice id>:<members hash>."""
    if entry.startswith("slice:"):
        if not _SLICE_ENTRY.fullmatch(entry):
            fail("E_CANON_HEX", "a slice entry is slice:<64 hex>:<64 hex>", path)
        return
    check_hex(entry, 64, path)


def check_set(items, path):
    """A JSON array used as a set: ascending code point order, no duplicates."""
    for a, b in zip(items, items[1:]):
        if not _utf16_key(a) < _utf16_key(b):
            fail("E_CANON_SET", "entries must be strictly ascending", path)


def keys_in_order(obj):
    return sorted(obj, key=_utf16_key)


# ---------------------------------------------------------------------------
# Structure checks. Everything here fails with E_SCHEMA and runs before any
# lexical check, so a document is either the right shape or rejected whole.


def _shape_object(obj, required, optional, path):
    if not isinstance(obj, dict):
        fail("E_SCHEMA", "expected an object", path)
    missing = [k for k in required if k not in obj]
    if missing:
        fail("E_SCHEMA", f"missing member {missing[0]!r}", path)
    extra = [k for k in obj if k not in required and k not in optional]
    if extra:
        fail("E_SCHEMA", f"unexpected member {extra[0]!r}", path)


def _shape_str(obj, key, path):
    if not isinstance(obj[key], str):
        fail("E_SCHEMA", f"{key} must be a string", f"{path}.{key}")


def shape_scalar(value, path):
    _shape_object(value, ("type", "value"), (), path)
    _shape_str(value, "type", path)
    if not isinstance(value["value"], (str, bool)):
        fail("E_SCHEMA", "value must be a string or a boolean", f"{path}.value")


def shape_args(args, path):
    if not isinstance(args, dict):
        fail("E_SCHEMA", "expected an object", path)
    for name, value in args.items():
        if value != SLICE:
            shape_scalar(value, f"{path}.{name}")


def shape_ref(ref, path="$"):
    _shape_object(ref, ("args", "fn", "ns"), ("asof",), path)
    shape_args(ref["args"], f"{path}.args")
    for key in ("fn", "ns", "asof"):
        if key in ref:
            _shape_str(ref, key, path)


def shape_cell(cell, path="$"):
    _shape_object(cell, ("args", "fn", "fn_hash", "ns"), (), path)
    shape_args(cell["args"], f"{path}.args")
    for key in ("fn", "fn_hash", "ns"):
        _shape_str(cell, key, path)


def shape_function(desc, path="$"):
    _shape_object(desc, ("code", "inputs", "signature"), (), path)
    _shape_object(desc["code"], ("body", "lang"), (), f"{path}.code")
    _shape_str(desc["code"], "body", f"{path}.code")
    _shape_str(desc["code"], "lang", f"{path}.code")
    if not isinstance(desc["inputs"], list) or not all(isinstance(i, str) for i in desc["inputs"]):
        fail("E_SCHEMA", "inputs must be an array of strings", f"{path}.inputs")
    shape_signature(desc["signature"], f"{path}.signature")


def shape_signature(sig, path):
    _shape_object(sig, ("args", "returns"), ("order",), path)
    if not isinstance(sig["args"], dict):
        fail("E_SCHEMA", "expected an object", f"{path}.args")
    for name, decl in sig["args"].items():
        p = f"{path}.args.{name}"
        _shape_object(decl, ("type", "valid"), ("extent", "unit"), p)
        _shape_str(decl, "type", p)
        if "unit" in decl:
            shape_unit(decl["unit"], f"{p}.unit")
        if not isinstance(decl["valid"], bool):
            fail("E_SCHEMA", "valid must be a boolean", f"{p}.valid")
        if "extent" in decl:
            ext = decl["extent"]
            if isinstance(ext, list):
                if not all(isinstance(v, str) for v in ext):
                    fail("E_SCHEMA", "an extent array holds lexical values as strings", f"{p}.extent")
            else:
                _shape_object(ext, ("hi", "lo"), (), f"{p}.extent")
                _shape_str(ext, "hi", f"{p}.extent")
                _shape_str(ext, "lo", f"{p}.extent")
    if "order" in sig:
        if not isinstance(sig["order"], list) or not all(isinstance(n, str) for n in sig["order"]):
            fail("E_SCHEMA", "order is an array of argument names", f"{path}.order")
    returns = sig["returns"]
    if isinstance(returns, dict):
        _shape_object(returns, ("type",), ("unit",), f"{path}.returns")
        _shape_str(returns, "type", f"{path}.returns")
        if "unit" in returns:
            shape_unit(returns["unit"], f"{path}.returns.unit")
    elif not isinstance(returns, str):
        fail("E_SCHEMA", "returns must be a type name or an object", f"{path}.returns")


def _is_arg_ref(unit):
    return isinstance(unit, dict) and set(unit) == {"arg"} and isinstance(unit["arg"], str)


def shape_unit(unit, path):
    """A literal, {"arg": name}, or {"of": side, "per": side} (units.md section 1)."""
    if isinstance(unit, str) or _is_arg_ref(unit):
        return
    if isinstance(unit, dict) and set(unit) == {"of", "per"}:
        for side in ("of", "per"):
            if not (isinstance(unit[side], str) or _is_arg_ref(unit[side])):
                fail("E_SCHEMA", "a rate side is a currency code or {\"arg\": name}", f"{path}.{side}")
        return
    fail("E_SCHEMA", "a unit is a string, {\"arg\": name} or {\"of\", \"per\"}", path)


RECEIPT_MEMBERS = (
    "asof", "cell", "computed_by", "inputs", "issued", "licence", "proto",
    "publisher", "sig", "summary", "tx", "type", "valid", "value",
)


def shape_receipt(r, path="$"):
    _shape_object(r, RECEIPT_MEMBERS, (), path)
    for key in ("asof", "computed_by", "issued", "licence", "proto", "publisher",
                "sig", "summary", "tx", "type"):
        _shape_str(r, key, path)
    if r["proto"] != PROTO:
        fail("E_SCHEMA", f"proto must be {PROTO!r}", f"{path}.proto")
    shape_cell(r["cell"], f"{path}.cell")
    if not isinstance(r["inputs"], list) or not all(isinstance(i, str) for i in r["inputs"]):
        fail("E_SCHEMA", "inputs must be an array of strings", f"{path}.inputs")
    shape_args(r["valid"], f"{path}.valid")
    if not isinstance(r["value"], (str, bool)):
        fail("E_SCHEMA", "value must be a string or a boolean", f"{path}.value")


# ---------------------------------------------------------------------------
# Lexical checks, walking members in canonical (JCS) order so the first error
# reported is well defined.


def check_scalar(value, path):
    check_type_name(value["type"], f"{path}.type")
    check_lexical(value["type"], value["value"], f"{path}.value")


def check_args(args, path):
    if len(args) > LIMITS["args"]:
        fail("E_CANON_LIMIT", f"more than {LIMITS['args']} arguments", path)
    for name in keys_in_order(args):
        check_arg_name(name, f"{path}.{name}")
        if args[name] != SLICE:
            check_scalar(args[name], f"{path}.{name}")


def check_ref(ref, path="$"):
    """A cell reference: what a cell URI denotes (SPEC.md 4.3)."""
    shape_ref(ref, path)
    check_args(ref["args"], f"{path}.args")
    if "asof" in ref:
        check_instant(ref["asof"], f"{path}.asof")
    check_name(ref["fn"], f"{path}.fn")
    check_namespace(ref["ns"], f"{path}.ns")
    check_function_name(ref["ns"] + "/" + ref["fn"], path)
    return ref


def check_cell(cell, path="$"):
    """A resolved cell: reference without asof, plus the function hash (SPEC.md 4.4)."""
    shape_cell(cell, path)
    check_args(cell["args"], f"{path}.args")
    check_name(cell["fn"], f"{path}.fn")
    check_hex(cell["fn_hash"], 64, f"{path}.fn_hash")
    check_namespace(cell["ns"], f"{path}.ns")
    check_function_name(cell["ns"] + "/" + cell["fn"], path)
    return cell


def check_function(desc, path="$"):
    """A function descriptor (SPEC.md section 7)."""
    shape_function(desc, path)
    check_text(desc["code"]["body"], f"{path}.code.body", "body", multiline=True)
    check_name(desc["code"]["lang"], f"{path}.code.lang")
    inputs = desc["inputs"]
    for i, name in enumerate(inputs):
        check_function_name(name, f"{path}.inputs[{i}]")
    check_set(inputs, f"{path}.inputs")
    if len(inputs) > LIMITS["inputs"]:
        fail("E_CANON_LIMIT", "too many inputs", f"{path}.inputs")
    args = desc["signature"]["args"]
    if len(args) > LIMITS["args"]:
        fail("E_CANON_LIMIT", f"more than {LIMITS['args']} arguments", f"{path}.signature.args")
    for name in keys_in_order(args):
        p = f"{path}.signature.args.{name}"
        decl = args[name]
        check_arg_name(name, p)
        check_type_name(decl["type"], f"{p}.type")
        if decl["type"] == "number":
            if "unit" not in decl:
                fail("E_CANON_UNIT", "a number argument declares its unit", p)
            check_unit(decl["unit"], args, f"{p}.unit")
        elif "unit" in decl:
            fail("E_CANON_UNIT", "only number arguments have a unit", f"{p}.unit")
        if decl["valid"] and decl["type"] not in VALID_TIME_TYPES:
            fail("E_CANON_TYPE", "a valid-time argument must be a date, instant or string", p)
        if "extent" in decl:
            check_extent(decl, f"{p}.extent")
    if "order" in desc["signature"]:
        order = desc["signature"]["order"]
        if len(order) != len(set(order)) or set(order) != set(args):
            fail("E_CANON_SET", "order lists every argument exactly once", f"{path}.signature.order")
    p = f"{path}.signature.returns"
    returns = desc["signature"]["returns"]
    if isinstance(returns, str):
        check_type_name(returns, p)
        if returns == "number":
            fail("E_CANON_UNIT", 'a number return is written {"type": "number", "unit": ...}', p)
    else:
        check_type_name(returns["type"], f"{p}.type")
        if returns["type"] != "number":
            fail("E_CANON_UNIT", "only a number return is written as an object", p)
        if "unit" not in returns:
            fail("E_CANON_UNIT", "a number return declares its unit", p)
        check_unit(returns["unit"], args, f"{p}.unit")
    return desc


def type_key(type_, lexical):
    """The order of a type's values (SPEC 15.13): numbers numerically, the others by code point."""
    if type_ == "number":
        whole, _, frac = lexical.lstrip("-").partition(".")
        from fractions import Fraction
        value = Fraction(int(whole + frac), 10 ** len(frac))
        return -value if lexical.startswith("-") else value
    return lexical


def check_extent(decl, path):
    """An argument's declared extent (SPEC 7): its values, or a date or integer range."""
    type_, ext = decl["type"], decl["extent"]
    if type_ in ("boolean", "blob"):
        fail("E_CANON_TYPE", f"a {type_} argument has no extent", path)
    if isinstance(ext, list):
        for i, v in enumerate(ext):
            check_lexical(type_, v, f"{path}[{i}]")
        for a, b in zip(ext, ext[1:]):
            if not type_key(type_, a) < type_key(type_, b):
                fail("E_CANON_SET", "extent values are strictly ascending in their type's order", path)
        if len(ext) > LIMITS["extent"]:
            fail("E_CANON_LIMIT", f"more than {LIMITS['extent']} extent values", path)
        return
    if type_ not in ("date", "number"):
        fail("E_CANON_TYPE", "an extent range is for date and number arguments", path)
    for end in ("hi", "lo"):
        check_lexical(type_, ext[end], f"{path}.{end}")
        if type_ == "number" and "." in ext[end]:
            fail("E_CANON_NUMBER", "an extent range over numbers has integer ends", f"{path}.{end}")
    if type_key(type_, ext["lo"]) > type_key(type_, ext["hi"]):
        fail("E_CANON_SET", "an extent range has lo <= hi", path)


def returns_type(desc):
    returns = desc["signature"]["returns"]
    return returns if isinstance(returns, str) else returns["type"]


def check_unit(unit, args, path):
    """A unit in a signature (units.md section 1); args is the signature's args."""
    if isinstance(unit, str):
        if not is_unit_literal(unit):
            fail("E_CANON_UNIT", f"not a unit listed in units.md: {unit!r}", path)
    elif "arg" in unit:
        _check_unit_arg(unit["arg"], args, path)
    else:
        for side in ("of", "per"):
            if isinstance(unit[side], str):
                if unit[side] not in CURRENCIES:
                    fail("E_CANON_UNIT", f"a rate side is a currency code: {unit[side]!r}", f"{path}.{side}")
            else:
                _check_unit_arg(unit[side]["arg"], args, f"{path}.{side}")


def _check_unit_arg(name, args, path):
    if name not in args or args[name]["type"] != "string":
        fail("E_CANON_UNIT", f"a unit names a string argument of the signature: {name!r}", path)


def resolved_unit(desc, cell):
    """The unit of a cell's value as a string (units.md section 3), or None."""
    check_cell(cell, "$.cell")
    if function_hash(desc) != cell["fn_hash"]:
        fail("E_FN_HASH_MISMATCH", "descriptor does not hash to cell.fn_hash", "$.descriptor")
    check_function(desc, "$.descriptor")  # structure, then canonical form
    returns = desc["signature"]["returns"]
    if isinstance(returns, str):
        return None
    unit, path = returns["unit"], "$.descriptor.signature.returns.unit"
    if isinstance(unit, str):
        return unit
    if "arg" in unit:
        value = _unit_arg_value(unit["arg"], cell, path)
        if not is_unit_literal(value):
            fail("E_CANON_UNIT", f"argument {unit['arg']} is not a unit: {value!r}", path)
        return value
    sides = []
    for side in ("of", "per"):
        value = unit[side] if isinstance(unit[side], str) else _unit_arg_value(unit[side]["arg"], cell, path)
        if value not in CURRENCIES:
            fail("E_CANON_UNIT", f"rate {side} is not a currency code: {value!r}", f"{path}.{side}")
        sides.append(value)
    return "/".join(sides)


def _unit_arg_value(name, cell, path):
    if name not in cell["args"]:
        fail("E_ARG_MISSING", f"the cell does not bind {name!r}", "$.cell.args")
    value = cell["args"][name]
    if value == SLICE:
        fail("E_SLICE", f"{name} is a slice; its unit is not one string", f"$.cell.args.{name}")
    if value["type"] != "string":
        fail("E_ARG_TYPE", f"{name} is declared string", f"$.cell.args.{name}")
    return value["value"]


def function_hash(desc):
    return sha256_hex(jcs(desc))


def check_receipt_form(r, path="$"):
    """Steps 2-4 of the verification procedure (SPEC.md 10.1)."""
    shape_receipt(r, path)
    # Step 3: lexical, in canonical member order.
    check_instant(r["asof"], f"{path}.asof")
    check_cell(r["cell"], f"{path}.cell")
    check_key_ref(r["computed_by"], f"{path}.computed_by")
    for i, h in enumerate(r["inputs"]):
        check_input_entry(h, f"{path}.inputs[{i}]")
    check_set(r["inputs"], f"{path}.inputs")
    if len(r["inputs"]) > LIMITS["inputs"]:
        fail("E_CANON_LIMIT", "too many inputs", f"{path}.inputs")
    check_instant(r["issued"], f"{path}.issued")
    check_licence(r["licence"], f"{path}.licence")
    check_namespace(r["publisher"], f"{path}.publisher")
    check_hex(r["sig"], 128, f"{path}.sig")
    if r["summary"] == "":
        fail("E_CANON_STRING", "summary must not be empty", f"{path}.summary")
    check_text(r["summary"], f"{path}.summary", "summary")
    check_instant(r["tx"], f"{path}.tx")
    check_type_name(r["type"], f"{path}.type")
    check_args(r["valid"], f"{path}.valid")
    check_lexical(r["type"], r["value"], f"{path}.value")
    # Step 4: consistency.
    args = r["cell"]["args"]
    for name in keys_in_order(args):
        if args[name] == SLICE:
            fail("E_SLICE", "a receipt is for one cell, not a slice", f"{path}.cell.args.{name}")
    for name in keys_in_order(r["valid"]):
        if r["valid"][name] == SLICE:
            fail("E_SLICE", "a receipt is for one cell, not a slice", f"{path}.valid.{name}")
    if r["publisher"] != r["cell"]["ns"]:
        fail("E_PUBLISHER_MISMATCH", "publisher must equal cell.ns", f"{path}.publisher")
    for name in keys_in_order(r["valid"]):
        if args.get(name) != r["valid"][name]:
            fail("E_VALID_MISMATCH", f"valid.{name} does not echo cell.args.{name}", f"{path}.valid")
        if r["valid"][name]["type"] not in VALID_TIME_TYPES:
            fail("E_VALID_MISMATCH", "valid-time arguments are dates, instants or strings", f"{path}.valid")
    # Fixed-width instants compare correctly as strings.
    if not r["tx"] <= r["asof"] <= r["issued"]:
        fail("E_TIME_ORDER", "requires tx <= asof <= issued", path)
    return r


# ---------------------------------------------------------------------------
# Slice objects and manifests (SPEC 15.13): slice-as-lineage.

RANGE_TYPES = ("date", "instant", "number", "string")


def _is_version_slice(obj):
    return isinstance(obj, dict) and set(obj) == {"cell", "from", "to"}


def shape_slice(obj, path="$"):
    if _is_version_slice(obj):
        shape_cell(obj["cell"], f"{path}.cell")
        _shape_str(obj, "from", path)
        _shape_str(obj, "to", path)
        return
    _shape_object(obj, ("args", "fn", "fn_hash", "ns"), (), path)
    if not isinstance(obj["args"], dict):
        fail("E_SCHEMA", "expected an object", f"{path}.args")
    for name, value in obj["args"].items():
        p = f"{path}.args.{name}"
        if value == SLICE:
            continue
        if isinstance(value, dict) and set(value) == {"hi", "lo", "type"}:
            for key in ("hi", "lo", "type"):
                _shape_str(value, key, p)
            continue
        shape_scalar(value, p)
    for key in ("fn", "fn_hash", "ns"):
        _shape_str(obj, key, path)


def check_slice(obj, path="$"):
    """A slice object: a cell with open (*) or ranged arguments, or a version slice."""
    shape_slice(obj, path)
    if _is_version_slice(obj):
        check_cell(obj["cell"], f"{path}.cell")
        for name in keys_in_order(obj["cell"]["args"]):
            if obj["cell"]["args"][name] == SLICE:
                fail("E_SLICE", "a version slice is of one cell", f"{path}.cell.args.{name}")
        check_instant(obj["from"], f"{path}.from")
        check_instant(obj["to"], f"{path}.to")
        return obj
    args = obj["args"]
    if len(args) > LIMITS["args"]:
        fail("E_CANON_LIMIT", f"more than {LIMITS['args']} arguments", f"{path}.args")
    open_args = 0
    for name in keys_in_order(args):
        p = f"{path}.args.{name}"
        check_arg_name(name, p)
        value = args[name]
        if value == SLICE:
            open_args += 1
        elif "lo" in value:
            open_args += 1
            check_type_name(value["type"], f"{p}.type")
            if value["type"] not in RANGE_TYPES:
                fail("E_CANON_TYPE", f"a {value['type']} argument has no range", f"{p}.type")
            check_lexical(value["type"], value["hi"], f"{p}.hi")
            check_lexical(value["type"], value["lo"], f"{p}.lo")
        else:
            check_scalar(value, p)
    check_name(obj["fn"], f"{path}.fn")
    check_hex(obj["fn_hash"], 64, f"{path}.fn_hash")
    check_namespace(obj["ns"], f"{path}.ns")
    check_function_name(obj["ns"] + "/" + obj["fn"], path)
    if not open_args:
        fail("E_SLICE", "a slice object has an open or ranged argument", f"{path}.args")
    return obj


def shape_manifest(m, path="$"):
    _shape_object(m, ("members", "slice"), (), path)
    if not isinstance(m["members"], list) or not all(isinstance(h, str) for h in m["members"]):
        fail("E_SCHEMA", "members is an array of receipt hashes", f"{path}.members")
    shape_slice(m["slice"], f"{path}.slice")


def check_manifest(m, path="$"):
    """A slice manifest {members, slice} (SPEC 15.13)."""
    shape_manifest(m, path)
    for i, h in enumerate(m["members"]):
        check_hex(h, 64, f"{path}.members[{i}]")
    check_set(m["members"], f"{path}.members")
    if len(m["members"]) > LIMITS["members"]:
        fail("E_CANON_LIMIT", f"more than {LIMITS['members']} members", f"{path}.members")
    check_slice(m["slice"], f"{path}.slice")
    return m


def slice_id(obj):
    return sha256_hex(jcs(obj))


def members_hash(members):
    return sha256_hex(jcs(list(members)))


def slice_entry(obj, members):
    return f"slice:{slice_id(obj)}:{members_hash(sorted(members, key=_utf16_key))}"


def slice_function(obj):
    cell = obj["cell"] if _is_version_slice(obj) else obj
    return cell["ns"] + "/" + cell["fn"]


def is_slice_member(obj, receipt):
    """Whether a receipt's cell belongs to a slice object (10.1 step 7.5); for a version slice,
    the same cell with tx in [from, to]."""
    cell = receipt["cell"]
    if _is_version_slice(obj):
        return cell == obj["cell"] and obj["from"] <= receipt["tx"] <= obj["to"]
    if (cell["ns"], cell["fn"], cell["fn_hash"]) != (obj["ns"], obj["fn"], obj["fn_hash"]):
        return False
    if set(cell["args"]) != set(obj["args"]):
        return False
    for name, pattern in obj["args"].items():
        value = cell["args"][name]
        if pattern == SLICE:
            continue
        if "lo" in pattern:
            if value["type"] != pattern["type"]:
                return False
            t = pattern["type"]
            if not type_key(t, pattern["lo"]) <= type_key(t, value["value"]) <= type_key(t, pattern["hi"]):
                return False
        elif value != pattern:
            return False
    return True


def receipt_payload(r):
    """The bytes that are hashed and signed: JCS of the receipt without sig."""
    return jcs({k: v for k, v in r.items() if k != "sig"})


def receipt_hash(r):
    return sha256_hex(receipt_payload(r))


# ---------------------------------------------------------------------------
# Cell URIs (SPEC.md section 5).

_URI = re.compile(r"cell://([^?#]*)(?:\?([^#]*))?")
_LITERAL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:")
_PCT = re.compile(r"[0-9A-F]{2}")


def percent_encode(text):
    return "".join(
        chr(b) if chr(b) in _LITERAL else "%%%02X" % b for b in text.encode("utf-8")
    )


def percent_decode(raw, path):
    out = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "%":
            pair = raw[i + 1 : i + 3]
            if not _PCT.fullmatch(pair):
                fail("E_CANON_PERCENT", "percent-encoding must be % and two uppercase hex digits", path)
            byte = int(pair, 16)
            if chr(byte) in _LITERAL:
                fail("E_CANON_PERCENT", f"{chr(byte)!r} must not be percent-encoded", path)
            out.append(byte)
            i += 3
        elif ch in _LITERAL:
            out.append(ord(ch))
            i += 1
        else:
            fail("E_CANON_PERCENT", f"{ch!r} must be percent-encoded", path)
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        fail("E_CANON_PERCENT", "percent-encoded bytes are not UTF-8", path)


def parse_uri(uri, signature):
    """Cell URI -> cell reference. Argument types come from the function signature."""
    m = _URI.fullmatch(uri)
    if not m:
        fail("E_PARSE_URI", "not cell://<namespace>/<function>[?<query>] without fragment")
    path, query = m.group(1), m.group(2)
    # Step 1, the outer grammar, entirely before any name is examined.
    authority = path.split("/", 1)[0]
    if "@" in authority or ":" in authority:
        fail("E_PARSE_URI", "a cell URI has no userinfo and no port")
    params = []
    if query is not None:
        if query == "":
            fail("E_PARSE_URI", "empty query")
        for part in query.split("&"):
            name, eq, raw = part.partition("=")
            if not eq:
                fail("E_PARSE_URI", f"parameter without '=': {part!r}")
            params.append((name, raw))
    namespace, slash, function = path.rpartition("/")
    if not slash:
        fail("E_CANON_NAME", "missing namespace", "uri.path")
    check_namespace(namespace, "uri.path")
    check_name(function, "uri.path")
    check_function_name(path, "uri.path")
    asof = None
    if params and params[-1][0] == "asof":
        asof = params.pop()[1]
    previous = None
    for name, raw in params:
        p = f"uri.query.{name}"
        if name == "asof":
            code = "E_CANON_ARG_DUPLICATE" if asof is not None else "E_CANON_ARG_ORDER"
            fail(code, "asof appears once, as the last parameter", p)
        check_arg_name(name, p)
        if previous is not None and name == previous:
            fail("E_CANON_ARG_DUPLICATE", f"argument {name!r} repeated", p)
        if previous is not None and name < previous:
            fail("E_CANON_ARG_ORDER", "arguments must be sorted by name", p)
        previous = name
    if len(params) > LIMITS["args"]:
        fail("E_CANON_LIMIT", f"more than {LIMITS['args']} arguments", "uri.query")
    declared = _signature_args(signature)
    for name, raw in params:
        if name not in declared:
            fail("E_ARG_UNKNOWN", f"function declares no argument {name!r}", f"uri.query.{name}")
    present = {name for name, raw in params}
    for name in keys_in_order(declared):
        if name not in present:
            fail("E_ARG_MISSING", f"argument {name!r} absent; use {name}=* for a slice", "uri.query")
    args = {}
    for name, raw in params:
        p = f"uri.query.{name}"
        type_ = declared[name]["type"]
        if raw == SLICE:
            args[name] = SLICE
            continue
        text = percent_decode(raw, p)
        if type_ == "boolean":
            if text not in ("true", "false"):
                fail("E_CANON_TYPE", "boolean must be true or false", p)
            value = text == "true"
        else:
            value = text
            check_lexical(type_, value, p)
        args[name] = {"type": type_, "value": value}
    ref = {"args": args, "fn": function, "ns": namespace}
    if asof is not None:
        ref["asof"] = percent_decode(asof, "uri.query.asof")
        check_instant(ref["asof"], "uri.query.asof")
    return ref


def _signature_args(signature):
    """Step 5 of SPEC.md 5.4: the signature is taken as given, but must be readable."""
    if not isinstance(signature, dict) or not isinstance(signature.get("args"), dict):
        fail("E_SCHEMA", "the signature has no args object", "signature")
    for name in keys_in_order(signature["args"]):
        decl = signature["args"][name]
        if not isinstance(decl, dict) or not isinstance(decl.get("type"), str):
            fail("E_SCHEMA", "an argument declaration is an object with a string type", f"signature.args.{name}")
    return signature["args"]


def format_uri(ref):
    """Cell reference -> its one canonical cell URI."""
    query = []
    for name in keys_in_order(ref["args"]):
        value = ref["args"][name]
        if value == SLICE:
            text = SLICE
        elif value["type"] == "boolean":
            text = "true" if value["value"] else "false"
        else:
            text = percent_encode(value["value"])
        query.append(f"{name}={text}")
    if "asof" in ref:
        query.append("asof=" + ref["asof"])
    uri = f"cell://{ref['ns']}/{ref['fn']}"
    return uri + ("?" + "&".join(query) if query else "")


def https_url(uri, mesh):
    """The HTTPS mapping of a canonical cell URI on a given mesh host."""
    assert uri.startswith("cell://")
    return f"https://{mesh}/cell/{uri[len('cell://'):]}"


# ---------------------------------------------------------------------------
# Keys (SPEC.md section 9). The HTTPS key document is the only key source.


def key_id(public):
    return sha256_hex(public)[:16]


def _key(public_hex, valid_from, valid_to, path):
    check_hex(public_hex, 64, path)
    check_instant(valid_from, path)
    if valid_to is not None:
        check_instant(valid_to, path)
        if not valid_from < valid_to:
            fail("E_KEY_DOC", "valid_to must be after valid_from", path)
    public = bytes.fromhex(public_hex)
    return {"id": key_id(public), "public": public, "valid_from": valid_from, "valid_to": valid_to}


def _as_error(code):
    """Report every failure inside fn as code."""
    def decorate(fn):
        def wrapped(*args):
            try:
                return fn(*args)
            except DatumeshError as e:
                if e.code == code:
                    raise
                fail(code, f"{e.code}: {e.detail}", e.path)
        return wrapped
    return decorate


@_as_error("E_KEY_DOC")
def parse_key_doc(text, host):
    """The document at https://<host>/.well-known/datumesh.json."""
    doc = parse_json(text)
    _shape_object(doc, ("host", "keys", "proto"), (), "$")
    if doc["proto"] != PROTO or doc["host"] != host:
        fail("E_KEY_DOC", "proto or host does not match", "$")
    check_dns_name(doc["host"], "$.host")  # keys exist only for DNS names (SPEC.md 9.3)
    if not isinstance(doc["keys"], list) or not 1 <= len(doc["keys"]) <= LIMITS["keys"]:
        fail("E_KEY_DOC", f"keys must be an array of 1 to {LIMITS['keys']} keys", "$.keys")
    keys = []
    for i, entry in enumerate(doc["keys"]):
        p = f"$.keys[{i}]"
        _shape_object(entry, ("alg", "id", "public", "valid_from"), ("valid_to",), p)
        for k in entry:
            _shape_str(entry, k, p)
        if entry["alg"] != "ed25519":
            fail("E_KEY_DOC", "alg must be ed25519", p)
        key = _key(entry["public"], entry["valid_from"], entry.get("valid_to"), p)
        if entry["id"] != key["id"]:
            fail("E_KEY_DOC", "id is not the key id of public", p)
        keys.append(key)
    return _no_duplicate_keys(keys)


def _no_duplicate_keys(keys):
    if len({k["id"] for k in keys}) != len(keys):
        fail("E_KEY_DOC", "the same key is published twice")
    return keys


def resolve_keys(host, env):
    """Key resolution (SPEC.md 9.3): the HTTPS document or nothing.

    env describes what the HTTPS request returned for this host:
      {"https": {"status": 200, "body": "..."} | {"status": <other>} | {"status": "error"}}
    """
    https = (env or {}).get("https") or {"status": "error"}
    status = https.get("status")
    # Only the number 200 is a retrieved document; any other status, including the string "200"
    # or none at all, is a failed retrieval (SPEC.md 9.3, 11).
    if isinstance(status, bool) or not isinstance(status, (int, float)) or status != 200:
        fail("E_KEY_UNAVAILABLE", f"https key document: {status!r}")
    if "body" not in https:
        fail("E_KEY_DOC", "a 200 response without a document")
    return parse_key_doc(https["body"], host)


# ---------------------------------------------------------------------------
# The mesh document (SPEC.md 9.6, spec-0.4.1): cross-mesh resolution, never verification.

MESH_ENDPOINTS = {  # endpoint -> its placeholders (each exactly once)
    "blob": ("sha256",), "cell": ("cell",), "cells": (), "descriptor": ("hash",), "explain": ("cell",), "find": (),
    "jobs": ("job",), "manifest": ("slice_id", "members_hash"), "receipt": ("hash",), "slice": ("cell",), "verify": (),
}
MESH_REQUIRED = ("cell", "descriptor", "jobs", "manifest", "receipt")
_PLACEHOLDER = re.compile(r"\{([a-z_0-9]*)\}")


def _retrieved(env, code, no_body):
    """A retrieval as in 9.3: only the number 200 is a document; a 200 without a body is no_body."""
    https = (env or {}).get("https") or {"status": "error"}
    status = https.get("status")
    if isinstance(status, bool) or not isinstance(status, (int, float)) or status != 200:
        fail(code, f"https document: {status!r}")
    if "body" not in https:
        fail(no_body, "a 200 response without a document")
    return https["body"]


def _mesh_url(value, host, path):
    if not isinstance(value, str) or not _URL.fullmatch(value) or len(value) > LIMITS["licence_url"]:
        fail("E_MESH_DOC", "an https URL of at most 512 characters", path)
    rest = value[len("https://"):]
    authority = rest.split("/", 1)[0]
    if authority != host or "/" not in rest:
        fail("E_MESH_DOC", f"a URL on this host ({host}), with a path", path)


def resolve_mesh(host, env):
    """Cross-mesh resolution of a host (SPEC.md 9.6): its key document and mesh document.

    env: {"keys": <https env of /.well-known/datumesh.json>, "mesh": <https env of
    /.well-known/datumesh-mesh.json>}. Returns {"bindings", "endpoints", "host", "proto"} with the
    known members only, or raises E_KEY_UNAVAILABLE, E_KEY_DOC or E_MESH_DOC."""
    key_text = _retrieved(env.get("keys"), "E_KEY_UNAVAILABLE", "E_KEY_DOC")  # 1. the key document (9.3)
    mesh_text = _retrieved(env.get("mesh"), "E_MESH_DOC", "E_MESH_DOC")  # 2. the mesh document
    try:  # 3. both strict JSON
        keydoc = parse_json(key_text.encode("utf-8") if isinstance(key_text, str) else key_text)
    except DatumeshError:
        fail("E_KEY_DOC", "the key document is not strict JSON")
    try:
        mesh = parse_json(mesh_text.encode("utf-8") if isinstance(mesh_text, str) else mesh_text)
    except DatumeshError:
        fail("E_MESH_DOC", "the mesh document is not strict JSON")
    if not isinstance(mesh, dict):
        fail("E_MESH_DOC", "the mesh document is an object")
    # 4. identity: both name this host and the same proto
    if isinstance(keydoc, dict) and isinstance(keydoc.get("host"), str) and keydoc["host"] != host:
        fail("E_MESH_DOC", "the key document names another host", "$.host")
    if mesh.get("host") != host:
        fail("E_MESH_DOC", "the mesh document names another host", "$.host")
    if mesh.get("proto") != PROTO or (isinstance(keydoc, dict) and keydoc.get("proto") != mesh.get("proto")):
        fail("E_MESH_DOC", "the mesh document and the key document disagree on proto", "$.proto")
    parse_key_doc(key_text, host)  # 5. the key document's own rules (9.2): E_KEY_DOC
    # 6. the mesh document's members; unknown members are ignored
    _mesh_url(mesh.get("bindings"), host, "$.bindings")
    endpoints = mesh.get("endpoints")
    if not isinstance(endpoints, dict):
        fail("E_MESH_DOC", "endpoints is an object", "$.endpoints")
    for name in MESH_REQUIRED:
        if name not in endpoints:
            fail("E_MESH_DOC", f"the endpoint {name} is required", f"$.endpoints.{name}")
    known = {}
    for name in sorted(endpoints):
        if name not in MESH_ENDPOINTS:
            continue
        value = endpoints[name]
        _mesh_url(value, host, f"$.endpoints.{name}")
        if sorted(_PLACEHOLDER.findall(value)) != sorted(MESH_ENDPOINTS[name]) or value.count("{") != len(MESH_ENDPOINTS[name]):
            fail("E_MESH_DOC", f"{name} has the placeholders {MESH_ENDPOINTS[name]}", f"$.endpoints.{name}")
        known[name] = value
    return {"bindings": mesh["bindings"], "endpoints": known, "host": host, "proto": PROTO}


# ---------------------------------------------------------------------------
# Signing and verification (SPEC.md sections 8 and 10).


def keypair(seed):
    signing = nacl.signing.SigningKey(seed)
    public = bytes(signing.verify_key)
    return signing, public


def sign_receipt(unsigned, seed):
    """Return the receipt with sig set. unsigned must not contain sig."""
    assert "sig" not in unsigned
    signing, _ = keypair(seed)
    sig = signing.sign(jcs(unsigned)).signature.hex()
    return dict(unsigned, sig=sig)


def verify_receipt(data, keyenv, recompute=None, blob=None):
    """Run the verification procedure. Returns a summary or raises DatumeshError.

    keyenv maps host -> resolve_keys env. recompute, if given, enables step 7:
      {"descriptor": {...} (absent: unavailable; any value given, null included, is offered),
       "inputs": {hash: receipt JSON text},
       "value": {"type": ..., "value": ...} (absent: the function cannot be evaluated)}
    blob, if given, is the content bytes of a blob value, checked in step 7.7.

    The result has "code": "E_EVAL_UNAVAILABLE" when 7.1-7.5 passed but there was no value to
    compare in 7.6: verification succeeds at level signed, with the code reported.
    """
    r = parse_json(data)  # step 1
    check_receipt_form(r)  # steps 2-4
    host, _, kid = r["computed_by"].partition("#")
    keys = resolve_keys(host, keyenv.get(host))  # step 5
    key = next((k for k in keys if k["id"] == kid), None)
    if key is None:
        fail("E_KEY_UNKNOWN", f"{host} publishes no key {kid}", "$.computed_by")
    if not (key["valid_from"] <= r["issued"] and (key["valid_to"] is None or r["issued"] < key["valid_to"])):
        fail("E_KEY_NOT_VALID", "issued is outside the key's validity window", "$.issued")
    try:  # step 6
        nacl.signing.VerifyKey(key["public"]).verify(receipt_payload(r), bytes.fromhex(r["sig"]))
    except (nacl.exceptions.BadSignatureError, ValueError):
        fail("E_SIGNATURE", "Ed25519 verification failed", "$.sig")
    result = {"hash": receipt_hash(r), "key": r["computed_by"], "level": "signed"}
    if recompute is not None:  # step 7
        outcome = _recompute(r, recompute, keyenv)
        if outcome == "superseded":  # step 7.6: an input was superseded; not a failure
            result["code"] = "E_INPUT_SUPERSEDED"
        elif outcome:
            result["level"] = "recomputed"
        else:  # step 7.6 could not run: not a failure
            result["code"] = "E_EVAL_UNAVAILABLE"
    if blob is not None:  # step 7.7
        if r["type"] != "blob":
            fail("E_SCHEMA", "content was supplied for a value that is not a blob", "$.type")
        check_blob_content(r["value"], blob)
        result["blob_checked"] = True
    return result


def _recompute(r, recompute, keyenv):
    cell = r["cell"]
    if "descriptor" not in recompute:
        fail("E_FN_UNAVAILABLE", f"no descriptor for {cell['fn_hash']}")
    desc = recompute["descriptor"]
    if function_hash(desc) != cell["fn_hash"]:
        fail("E_FN_HASH_MISMATCH", "descriptor does not hash to cell.fn_hash")
    check_function(desc, "descriptor")
    declared = desc["signature"]["args"]
    args = cell["args"]
    for name in keys_in_order(args):
        if name not in declared:
            fail("E_ARG_UNKNOWN", f"function declares no argument {name!r}", f"$.cell.args.{name}")
    for name in keys_in_order(declared):
        if name not in args:
            fail("E_ARG_MISSING", f"argument {name!r} absent", "$.cell.args")
    for name in keys_in_order(args):
        if args[name]["type"] != declared[name]["type"]:
            fail("E_ARG_TYPE", f"{name} is declared {declared[name]['type']}", f"$.cell.args.{name}")
    if set(r["valid"]) != {n for n, d in declared.items() if d["valid"]}:
        fail("E_VALID_MISMATCH", "valid must echo exactly the declared valid-time arguments", "$.valid")
    if r["type"] != returns_type(desc):
        fail("E_RETURN_TYPE", f"function returns {returns_type(desc)}", "$.type")
    supplied = recompute.get("inputs", {})
    input_tx = []
    for h in r["inputs"]:
        if h.startswith("slice:"):
            input_tx.extend(_check_slice_input(r, h, desc, recompute, keyenv))
            continue
        if h not in supplied:
            fail("E_INPUT_UNAVAILABLE", f"input receipt {h} not available", "$.inputs")
        try:
            verify_receipt(supplied[h], keyenv)
            ir = parse_json(supplied[h])
        except DatumeshError as e:
            fail("E_INPUT_INVALID", f"input {h}: {e}", "$.inputs")
        if receipt_hash(ir) != h:
            fail("E_INPUT_UNAVAILABLE", f"supplied receipt does not hash to {h}", "$.inputs")
        if ir["cell"]["ns"] + "/" + ir["cell"]["fn"] not in desc["inputs"]:
            fail("E_INPUT_UNDECLARED", f"input {h} is a cell of an undeclared function", "$.inputs")
        if not ir["asof"] <= r["asof"]:
            fail("E_TIME_ORDER", "an input receipt's asof is after the receipt's asof", "$.inputs")
        input_tx.append(ir["tx"])
    if input_tx and r["tx"] != max(input_tx):
        fail("E_TIME_ORDER", "a computed cell's tx is the latest tx of its inputs", "$.tx")
    if "value" not in recompute:  # step 7.6: the function cannot be evaluated
        return False
    if recompute["value"] != {"type": r["type"], "value": r["value"]}:
        if "lineage" in recompute and _superseded(r, recompute, keyenv):
            return "superseded"  # historical, not wrong (step 7.6, D62)
        fail("E_VALUE_MISMATCH", "recomputed value differs from the receipt", "$.value")
    return True


def _check_slice_input(r, entry, desc, recompute, keyenv):
    """Step 7.5 for a slice entry: the manifest, then every member. Returns the members' tx."""
    _, sid, mh = entry.split(":")
    manifests = recompute.get("manifests", {})
    if entry not in manifests:
        fail("E_INPUT_UNAVAILABLE", f"no manifest for {entry}", "$.inputs")
    text = manifests[entry]
    m = parse_json(text.encode("utf-8") if isinstance(text, str) else text)
    check_manifest(m, "$.manifest")
    if slice_id(m["slice"]) != sid or members_hash(m["members"]) != mh:
        fail("E_INPUT_UNAVAILABLE", "the manifest offered does not hash to the entry", "$.inputs")
    if slice_function(m["slice"]) not in desc["inputs"]:
        fail("E_INPUT_UNDECLARED", f"the slice {entry} is of an undeclared function", "$.inputs")
    supplied = recompute.get("inputs", {})
    version = _is_version_slice(m["slice"])
    seen, txs = set(), []
    for h in m["members"]:
        if h not in supplied:
            fail("E_INPUT_UNAVAILABLE", f"member receipt {h} not available", "$.inputs")
        try:
            verify_receipt(supplied[h], keyenv)
            ir = parse_json(supplied[h])
        except DatumeshError as e:
            fail("E_INPUT_INVALID", f"member {h}: {e}", "$.inputs")
        if receipt_hash(ir) != h:
            fail("E_INPUT_UNAVAILABLE", f"supplied receipt does not hash to {h}", "$.inputs")
        cid = sha256_hex(jcs(ir["cell"]))
        if not is_slice_member(m["slice"], ir) or (not version and cid in seen):
            fail("E_SLICE_MEMBER", f"member {h} does not belong to the slice once", "$.inputs")
        seen.add(cid)
        if not ir["asof"] <= r["asof"]:
            fail("E_TIME_ORDER", "a member receipt's asof is after the receipt's asof", "$.inputs")
        txs.append(ir["tx"])
    return txs


def _superseded(r, recompute, keyenv):
    """Whether the evaluation's lineage replaces an input by a later version of the same cell, or
    a slice entry by the same slice with other members (step 7.6)."""
    # The lineage is a set of strings; an item that is not a string replaces nothing (RS-37).
    lineage = {n for n in recompute["lineage"] if isinstance(n, str)}
    supplied = recompute.get("inputs", {})
    listed = set(r["inputs"])
    new = sorted(lineage - listed)  # the order of the lineage does not matter
    for e in r["inputs"]:
        if e in lineage:
            continue
        if e.startswith("slice:"):
            sid = e.split(":")[1]
            if any(n.startswith(f"slice:{sid}:") for n in new):
                return True
            continue
        old = parse_json(supplied[e].encode("utf-8") if isinstance(supplied[e], str) else supplied[e])
        for n in new:
            if n.startswith("slice:") or n not in supplied:
                continue
            try:
                verify_receipt(supplied[n], keyenv)
            except DatumeshError:
                continue
            nr = parse_json(supplied[n].encode("utf-8") if isinstance(supplied[n], str) else supplied[n])
            if receipt_hash(nr) == n and nr["cell"] == old["cell"] and nr["tx"] > old["tx"]:
                return True
    return False


# ---------------------------------------------------------------------------
# Response envelopes (SPEC.md 5.5). An envelope is the mesh's statement and is
# not signed; only the receipt inside it is verified.

ENVELOPE_MEMBERS = {  # outcome -> (required, optional)
    "ok": (("outcome", "receipt", "trust"), ("reason", "superseded_by")),
    "stale": (("age_seconds", "outcome", "receipt", "trust"), ("reason", "superseded_by")),
    "not_covered": (("outcome",), ("fault",)),
    "unlicensed": (("outcome",), ()),
    "payment_required": (("outcome", "quote"), ()),
    "rate_limited": (("outcome", "retry_after_seconds"), ()),
    "error": (("error", "outcome"), ()),
    "bad_request": (("error", "outcome"), ()),
    "pending": (("estimate_seconds", "job", "outcome", "poll", "request"), ()),
}
ENVELOPE_STATUS = {
    "ok": range(200, 201), "stale": range(200, 201), "not_covered": range(404, 405),
    "unlicensed": range(403, 404), "payment_required": range(402, 403),
    "rate_limited": range(429, 430), "error": range(500, 600), "bad_request": range(400, 401),
    "pending": range(202, 203),
}
# The codes parse(uri, signature) can raise (SPEC 5.4): what a bad_request may report.
URI_CODES = (
    "E_PARSE_URI", "E_CANON_NAME", "E_CANON_ARG_NAME", "E_CANON_ARG_DUPLICATE", "E_CANON_ARG_ORDER",
    "E_CANON_PERCENT", "E_CANON_TYPE", "E_CANON_NUMBER", "E_CANON_DATE", "E_CANON_INSTANT",
    "E_CANON_STRING", "E_CANON_BLOB", "E_CANON_LIMIT", "E_ARG_UNKNOWN", "E_ARG_MISSING",
)
_INTEGER = re.compile(r"0|[1-9][0-9]*")
TRUST = ("primary", "verified", "unverified")
_JOB = re.compile(r"[0-9a-f]{32,64}")


def _is_instant(text):
    try:
        check_instant(text, "$")
        return True
    except DatumeshError:
        return False
# The faults a not_covered envelope may carry (SPEC 5.5, 15.11): a computed cell with no value.
FORMULA_FAULTS = ("E_FORMULA_DIV_ZERO", "E_FORMULA_DOMAIN", "E_FORMULA_RANGE", "E_FORMULA_EMPTY",
                  "E_FORMULA_ABSENT", "E_FORMULA_FUTURE")


def _seconds(value):
    """An integer member: written 0|[1-9][0-9]*, at most 2^53 - 1."""
    return (isinstance(value, JsonInteger) and _INTEGER.fullmatch(value.text) is not None
            and int(value.text) <= MAX_SAFE_INTEGER)


@_as_error("E_ENVELOPE")
def _check_envelope_members(env):
    if not isinstance(env, dict) or not isinstance(env.get("outcome"), str):
        fail("E_ENVELOPE", "an envelope is an object with a string outcome")
    if env["outcome"] not in ENVELOPE_MEMBERS:
        fail("E_ENVELOPE", f"unknown outcome {env['outcome']!r}", "$.outcome")
    required, optional = ENVELOPE_MEMBERS[env["outcome"]]
    _shape_object(env, required, optional, "$")
    if "age_seconds" in env and not _seconds(env["age_seconds"]):
        fail("E_ENVELOPE", "age_seconds is a non-negative integer", "$.age_seconds")
    if "error" in env:
        # bad_request: a URI code, or E_JOB_UNKNOWN for a job URL (spec-0.4.1); error: any code
        # of 10.2 but the client's E_ENVELOPE and the request's E_JOB_UNKNOWN.
        allowed = URI_CODES + ("E_JOB_UNKNOWN",) if env["outcome"] == "bad_request" else tuple(
            c for c in ERROR_CODES if c not in ("E_ENVELOPE", "E_JOB_UNKNOWN"))
        if env["error"] not in allowed:
            fail("E_ENVELOPE", f"{env['error']!r} is not a code this outcome can carry", "$.error")
    if "quote" in env:
        quote = env["quote"]
        _shape_object(quote, ("amount", "authorise", "currency"), (), "$.quote")
        for key in ("amount", "authorise", "currency"):
            _shape_str(quote, key, "$.quote")
        check_number(quote["amount"], "$.quote.amount")
        if quote["amount"] == "0" or quote["amount"].startswith("-"):
            fail("E_ENVELOPE", "amount is greater than zero", "$.quote.amount")
        if not _URL.fullmatch(quote["authorise"]) or len(quote["authorise"]) > LIMITS["licence_url"]:
            fail("E_ENVELOPE", "authorise is an https URL", "$.quote.authorise")
        if quote["currency"] not in CURRENCIES:
            fail("E_ENVELOPE", "currency is a currency code from units.md", "$.quote.currency")
    if "reason" in env:
        _shape_str(env, "reason", "$")
        if env["reason"] == "":
            fail("E_ENVELOPE", "reason must not be empty", "$.reason")
        check_text(env["reason"], "$.reason", "summary")
        if "superseded_by" not in env:
            fail("E_ENVELOPE", "reason is given only with superseded_by", "$.reason")
    if "receipt" in env and not isinstance(env["receipt"], dict):
        fail("E_ENVELOPE", "receipt is a receipt object", "$.receipt")
    if "estimate_seconds" in env and not _seconds(env["estimate_seconds"]):
        fail("E_ENVELOPE", "estimate_seconds is a non-negative integer", "$.estimate_seconds")
    if "job" in env:
        if not isinstance(env["job"], str) or not _JOB.fullmatch(env["job"]):
            fail("E_ENVELOPE", "job is 32 to 64 lowercase hex digits", "$.job")
    if "poll" in env:
        poll = env["poll"]
        if not isinstance(poll, str) or not _URL.fullmatch(poll) or len(poll) > LIMITS["licence_url"] \
                or not poll.endswith("/jobs/" + str(env.get("job"))):
            fail("E_ENVELOPE", "poll is the https URL of the job: .../jobs/<job>", "$.poll")
    if "request" in env:
        req = env["request"]
        if not isinstance(req, dict) or "cell_id" not in req or set(req) - {"asof", "cell_id"}:
            fail("E_ENVELOPE", "request is {cell_id, asof?}", "$.request")
        if not isinstance(req["cell_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", req["cell_id"]):
            fail("E_ENVELOPE", "request.cell_id is a cell id", "$.request.cell_id")
        if "asof" in req and (not isinstance(req["asof"], str) or not _is_instant(req["asof"])):
            fail("E_ENVELOPE", "request.asof is an instant", "$.request.asof")
    if "retry_after_seconds" in env and not _seconds(env["retry_after_seconds"]):
        fail("E_ENVELOPE", "retry_after_seconds is a non-negative integer", "$.retry_after_seconds")
    if "superseded_by" in env:
        _shape_str(env, "superseded_by", "$")
        check_hex(env["superseded_by"], 64, "$.superseded_by")
    if "fault" in env and env["fault"] not in FORMULA_FAULTS:
        fail("E_ENVELOPE", "fault is a formula evaluation fault code (SPEC 15.11)", "$.fault")
    if "trust" in env and env["trust"] not in TRUST:
        fail("E_ENVELOPE", f"trust is one of {', '.join(TRUST)}", "$.trust")


def check_envelope(status, body, keyenv, request):
    """Check a mesh response (SPEC.md 5.5): HTTP status and JSON body, against the request:
    {"cell_id": <cell id asked for>, "asof": <instant, if the request carried one>}, and "job": <job id>
    when the response is to GET /jobs/<job> (spec-0.4.1): the job's envelope is bound to the original
    request, never to the job URL."""
    env = parse_json(body, keep_integer_text=True)
    _check_envelope_members(env)
    if status not in ENVELOPE_STATUS[env["outcome"]]:
        fail("E_ENVELOPE", f"status {status} does not match outcome {env['outcome']}", "$.outcome")
    result = {"outcome": env["outcome"]}
    if env.get("error") == "E_JOB_UNKNOWN" and "job" not in request:
        fail("E_ENVELOPE", "E_JOB_UNKNOWN answers a job URL only", "$.error")
    if env["outcome"] == "pending":
        # Step 5 for pending (spec-0.4.1): the echoed request is the one made, and a pending
        # envelope fetched from a job URL is that job's.
        echoed = env["request"]
        if echoed["cell_id"] != request["cell_id"] or echoed.get("asof") != request.get("asof"):
            fail("E_ENVELOPE", "the pending envelope echoes another request", "$.request")
        if "job" in request and env["job"] != request["job"]:
            fail("E_ENVELOPE", "the pending envelope is for another job than the one polled", "$.job")
    if "receipt" in env:
        r = env["receipt"]
        result["receipt_hash"] = verify_receipt(jcs(r), keyenv)["hash"]
        if sha256_hex(jcs(r["cell"])) != request["cell_id"]:
            fail("E_ENVELOPE", "the receipt is for another cell than the one requested", "$.receipt.cell")
        # ok and stale alike: a receipt answers every asof from its own up to the cell's next
        # version, so its asof is at or before the one requested (D31). What ok adds, that the
        # receipt is the latest version known as of the requested asof, is the mesh's claim.
        if "asof" in request and not r["asof"] <= request["asof"]:
            fail("E_ENVELOPE", "the receipt's asof is after the one requested", "$.receipt.asof")
        primary = r["computed_by"].split("#")[0] == r["cell"]["ns"].split("/")[0] and not r["inputs"]
        if primary != (env["trust"] == "primary"):
            fail("E_ENVELOPE", "trust is primary exactly when the publisher's host signed a stored answer", "$.trust")
        if env.get("superseded_by") == result["receipt_hash"]:
            fail("E_ENVELOPE", "a receipt cannot supersede itself", "$.superseded_by")
        result["trust"] = env["trust"]
    return result


# ---------------------------------------------------------------------------
# Vector checking (SPEC.md section 11).


def vector_input(vec):
    if "input_hex" in vec:
        return bytes.fromhex(vec["input_hex"])
    return vec["input"].encode("utf-8")


def run_vector(vec):
    """Run one vector. Returns a dict of computed outputs, or {"error": code}."""
    kind = vec["kind"]
    try:
        if kind == "jcs":
            canonical = jcs(parse_json(vector_input(vec)))
            return {"canonical": canonical.decode(), "sha256": sha256_hex(canonical)}
        if kind in ("scalar", "ref", "cell", "function"):
            obj = parse_json(vector_input(vec))
            if kind == "scalar":
                shape_scalar(obj, "$")
                check_scalar(obj, "$")
            else:
                {"ref": check_ref, "cell": check_cell, "function": check_function}[kind](obj)
            canonical = jcs(obj)
            return {"canonical": canonical.decode(), "sha256": sha256_hex(canonical)}
        if kind == "uri":
            ref = parse_uri(vec["input"], vec["signature"])
            check_ref(ref)
            canonical = jcs(ref)
            uri = format_uri(ref)
            return {
                "object": ref,
                "canonical": canonical.decode(),
                "sha256": sha256_hex(canonical),
                "uri": uri,
                "https": https_url(uri, "mesh.example"),
            }
        if kind == "keyid":
            return {"key_id": key_id(bytes.fromhex(vec["input"]))}
        if kind == "keys":
            keys = resolve_keys(vec["host"], vec["env"])
            return {"key_ids": [k["id"] for k in keys]}
        if kind == "unit":
            obj = parse_json(vector_input(vec))
            _shape_object(obj, ("cell", "descriptor"), (), "$")
            return {"unit": resolved_unit(obj["descriptor"], obj["cell"])}
        if kind == "envelope":
            return check_envelope(vec["status"], vector_input(vec), vec["keys"], vec["request"])
        if kind == "mesh":
            got = resolve_mesh(vec["host"], vec["env"])
            return {"bindings": got["bindings"], "endpoints": got["endpoints"]}
        if kind == "slice":
            obj = parse_json(vector_input(vec))
            if isinstance(obj, dict) and "members" in obj:
                check_manifest(obj)
                canonical = jcs(obj)
                return {"canonical": canonical.decode(), "sha256": sha256_hex(canonical),
                        "slice_id": slice_id(obj["slice"]), "members_hash": members_hash(obj["members"]),
                        "entry": slice_entry(obj["slice"], obj["members"])}
            check_slice(obj)
            canonical = jcs(obj)
            return {"canonical": canonical.decode(), "sha256": sha256_hex(canonical), "slice_id": slice_id(obj)}
        if kind == "decimal":
            import fdecimal  # the dialect's decimal arithmetic (SPEC 15.9)
            return {"results": [fdecimal.run_case(vec["op"], case) for case in vec["cases"]]}
        if kind in ("formula", "formula-eval", "excel"):
            import formula  # the dialect's reference implementation (SPEC 15)
            return formula.run_vector(vec)
        if kind == "receipt":
            blob = bytes.fromhex(vec["blob_hex"]) if "blob_hex" in vec else None
            result = verify_receipt(vector_input(vec), vec["keys"], vec.get("recompute"), blob)
            r = parse_json(vector_input(vec))
            payload = receipt_payload(r)
            out = {
                "canonical": payload.decode(),
                "sha256": sha256_hex(payload),
                "sig": r["sig"],
                "level": result["level"],
            }
            if blob is not None:
                out["blob_checked"] = result["blob_checked"]
            if "code" in result:
                out["code"] = result["code"]
            return out
        raise ValueError(f"unknown vector kind {kind!r}")
    except DatumeshError as e:
        return {"error": e.code, "detail": str(e)}


OUTPUT_FIELDS = ("canonical", "sha256", "object", "uri", "https", "key_id", "key_ids", "sig", "level",
                 "blob_checked", "code", "unit", "outcome", "trust", "receipt_hash",
                 "slice_id", "members_hash", "entry", "ast", "ast_sha256", "body", "inputs", "returns",
                 "asof_dependent", "value", "lineage", "tx", "receipt_asof", "fuel_used", "results",
                 "bindings", "endpoints")


def check_vector(vec):
    """Return a list of mismatches between a vector and the reference behaviour."""
    got = run_vector(vec)
    problems = []
    if vec["valid"]:
        if "error" in got:
            return [f"expected valid, got {got['detail']}"]
        for field in OUTPUT_FIELDS:
            if field in vec and vec[field] != got.get(field):
                problems.append(f"{field}: expected {vec[field]!r}, got {got.get(field)!r}")
        if vec["kind"] == "receipt" and "code" in got and "code" not in vec:
            problems.append(f"code: expected none, got {got['code']!r}")
        if vec["kind"] == "uri" and got["uri"] != vec["input"]:
            problems.append(f"URI does not round-trip: {got['uri']!r}")
        if vec["kind"] == "receipt" and "keypair" in vec:
            seed = bytes.fromhex(vec["keypair"]["seed"])
            _, public = keypair(seed)
            if public.hex() != vec["keypair"]["public"] or key_id(public) != vec["keypair"]["key_id"]:
                problems.append("keypair fields disagree with the seed")
    else:
        if got.get("error") != vec["error"]:
            problems.append(f"expected {vec['error']}, got {got.get('detail', 'success')}")
        elif "token" in vec and got.get("token") != vec["token"]:
            problems.append(f"token: expected {vec['token']!r}, got {got.get('token')!r}")
    return problems


def load_vectors():
    vectors = []
    for path in sorted((ROOT / "vectors").rglob("*.json")):
        vec = json.loads(path.read_text(encoding="utf-8"))
        vec["_file"] = str(path.relative_to(ROOT))
        vectors.append(vec)
    return vectors


def main(argv):
    if len(argv) >= 2 and argv[1] == "check":
        failed = 0
        vectors = load_vectors()
        for vec in vectors:
            problems = check_vector(vec)
            if problems:
                failed += 1
                print(f"FAIL {vec['_file']}")
                for p in problems:
                    print(f"     {p}")
        print(f"{len(vectors) - failed}/{len(vectors)} vectors pass")
        return 1 if failed else 0
    if len(argv) == 3 and argv[1] == "jcs":
        sys.stdout.buffer.write(jcs(parse_json(pathlib.Path(argv[2]).read_bytes())) + b"\n")
        return 0
    if len(argv) == 4 and argv[1] == "uri":
        desc = parse_json(pathlib.Path(argv[3]).read_bytes())
        ref = parse_uri(argv[2], desc["signature"])
        sys.stdout.buffer.write(jcs(ref) + b"\n")
        return 0
    if len(argv) == 4 and argv[1] == "verify":
        keyenv = parse_json(pathlib.Path(argv[3]).read_bytes())
        try:
            result = verify_receipt(pathlib.Path(argv[2]).read_bytes(), keyenv)
        except DatumeshError as e:
            print(e)
            return 1
        print(f"OK {result['hash']} signed by {result['key']}")
        return 0
    if len(argv) == 4 and argv[1] == "unit":
        desc = parse_json(pathlib.Path(argv[2]).read_bytes())
        cell = parse_json(pathlib.Path(argv[3]).read_bytes())
        try:
            shape_function(desc)
            print(resolved_unit(desc, cell.get("cell", cell)))
        except DatumeshError as e:
            print(e)
            return 1
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
