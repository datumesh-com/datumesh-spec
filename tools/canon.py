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
    "E_SLICE_AT_CELL",
    "E_NAME_UNBOUND",
    "E_FOREIGN_UNAVAILABLE",  # spec-0.4.3: an envelope and resolution code, never a verification result
    "E_UNROOTED_INPUT",  # spec-0.5.0: define's (2.5)
    "E_NAMESPACE_SUSPENDED",  # spec-0.5.0: a write refusal (9.9)
    # spec-0.5.0, classes (section 16): define-time codes of classes, and keys; never verification results
    "E_CLASS_MEMBER",
    "E_CLASS_PARENT",
    "E_CLASS_INHERIT",
    "E_CLASS_OVERRIDE",
    "E_CLASS_FINAL",
    "E_CLASS_METHOD",
    "E_CLASS_INTERFACE",
    "E_CLASS_OWNER",
    "E_KEY_NORMALISATION",
    "E_KEY_ENCODING",
    "E_SHORT_ID_AMBIGUOUS",  # spec-0.5.0: a mesh's answer about a request (16.8)
    "E_DESCRIBE",  # spec-0.5.0: a describe answer breaks 16.8 (a client's check)
    "E_WHATIF_UNSUPPORTED",  # spec-0.6.0: a whatif solve the mesh does not offer (5.9): bad_request
    "E_WHATIF_NO_SOLUTION",  # spec-0.6.0: a whatif solve with no value within its bounds and fuel (5.9): a fault
)
# spec-0.5.0: define and write codes, never verification results and never in a read envelope.
DEFINE_WRITE_CODES = ("E_UNROOTED_INPUT", "E_NAMESPACE_SUSPENDED", "E_CLASS_MEMBER", "E_CLASS_PARENT",
                      "E_CLASS_INHERIT", "E_CLASS_OVERRIDE", "E_CLASS_FINAL", "E_CLASS_METHOD", "E_CLASS_INTERFACE",
                      "E_CLASS_OWNER")

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
    "declarations": 64,  # function names in a key document's declarations (spec-0.4.3)
    "declaration_entries": 16,  # entries per declared function name (spec-0.4.3)
}

TYPES = ("blob", "boolean", "date", "instant", "number", "string")
VALID_TIME_TYPES = ("date", "instant", "string")
SLICE = "*"
RESERVED_ARG_NAMES = ("asof", "fn_hash")  # fn_hash since spec-0.4.2: the URI's pin (5.1)
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
        if "." in segment:
            check_dns_name(segment, path)
        else:
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
PUBLIC_PREFIX = "public:"  # spec-0.6.2 (8.1): public:<https URL>, the whole string at most 512 characters


def check_licence(text, path):
    if text.startswith(PUBLIC_PREFIX):
        if not _URL.fullmatch(text[len(PUBLIC_PREFIX):]):
            fail("E_CANON_LICENCE", f"public: is followed by an https URL of printable ASCII: {text!r}", path)
        if len(text) > LIMITS["licence_url"]:
            fail("E_CANON_LIMIT", "public: licence longer than 512 characters, the prefix included", path)
    elif text.startswith("https://"):
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
    _shape_object(ref, ("args", "fn", "ns"), ("asof", "fn_hash"), path)
    shape_args(ref["args"], f"{path}.args")
    for key in ("fn", "fn_hash", "ns", "asof"):
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


def _literal_default(decl, path):
    """A literal default (7, K13): a lexical value of the argument's type, a JSON string (a boolean's is "true" or
    "false"); not a value of the type is E_SCHEMA. A type that is not one of TYPES is checked by check_function."""
    value = decl["default"]
    if not isinstance(value, str):
        fail("E_SCHEMA", 'a literal default is a lexical value, a JSON string (or "asof")', f"{path}.default")
    if decl["type"] == "boolean":  # a lexical value: "true" or "false"
        if value not in ("true", "false"):
            fail("E_SCHEMA", f"{value!r} is not a boolean (7)", f"{path}.default")
        return
    if decl["type"] not in TYPES or decl["type"] == "blob":
        return
    try:
        check_lexical(decl["type"], value, path)
    except DatumeshError:
        fail("E_SCHEMA", f"{value!r} is not a valid {decl['type']} (7)", f"{path}.default")


def shape_signature(sig, path):
    _shape_object(sig, ("args", "returns"), ("order",), path)
    if not isinstance(sig["args"], dict):
        fail("E_SCHEMA", "expected an object", f"{path}.args")
    for name, decl in sig["args"].items():
        p = f"{path}.args.{name}"
        _shape_object(decl, ("type", "valid"), ("classes", "default", "extent", "key_normalisation", "unit"), p)
        _shape_str(decl, "type", p)
        # spec-0.5.0 (Q6 b): a rule of 16.4 other than none; absent means none, so "none" is not written
        if "key_normalisation" in decl and decl["key_normalisation"] not in KEY_NORMALISATIONS[1:]:
            fail("E_SCHEMA", "key_normalisation is a rule of 16.4 other than none (absent means none)",
                 f"{p}.key_normalisation")
        if "classes" in decl and (not isinstance(decl["classes"], list)
                                  or not all(isinstance(c, str) for c in decl["classes"])):
            fail("E_SCHEMA", "classes is an array of class names", f"{p}.classes")
        if "default" in decl and decl["default"] != "asof":  # K13 (since the classes round): a literal default
            _literal_default(decl, p)
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
        _shape_object(returns, ("type",), ("classes", "unit"), f"{path}.returns")
        _shape_str(returns, "type", f"{path}.returns")
        if "classes" in returns and (not isinstance(returns["classes"], list)
                                     or not all(isinstance(c, str) for c in returns["classes"])):
            fail("E_SCHEMA", "classes is an array of class names", f"{path}.returns.classes")
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
# spec-0.7.0 (R1, 8.1): a withdrawal is the null version; `withdrawn` takes the place of type and value.
WITHDRAWAL_MEMBERS = tuple(m for m in RECEIPT_MEMBERS if m not in ("type", "value")) + ("withdrawn",)


# spec-0.6.0 (C2, 8.1): a stored receipt may carry its source, a relayed value's provenance.
SOURCE_REQUIRED = ("name", "retrieved", "url")
SOURCE_OPTIONAL = ("sha256", "takeover")


def shape_source(src, path):
    """A receipt's source: exactly its members, each a string (E_SCHEMA); the rules are check_source's."""
    _shape_object(src, SOURCE_REQUIRED, SOURCE_OPTIONAL, path)
    for key in SOURCE_REQUIRED + SOURCE_OPTIONAL:
        if key in src:
            _shape_str(src, key, path)


def check_https_url(text, path):
    """An https URL by the licence URL rule (8.1): the grammar (E_CANON_LICENCE), then the length (E_CANON_LIMIT)."""
    if not isinstance(text, str) or not _URL.fullmatch(text):
        fail("E_CANON_LICENCE", "an https:// URL of printable ASCII", path)
    if len(text) > LIMITS["licence_url"]:
        fail("E_CANON_LIMIT", "a URL is at most 512 characters", path)


def check_source(src, host, path):
    """source (8.1, spec-0.6.0), its members in member order: name, retrieved, sha256, takeover, url. A
    publisher does not relay itself: name is not the host of cell.ns (E_SCHEMA)."""
    check_dns_name(src["name"], f"{path}.name")
    if src["name"] == host:
        fail("E_SCHEMA", "source.name is the publisher's own host: a publisher does not relay itself", f"{path}.name")
    check_instant(src["retrieved"], f"{path}.retrieved")
    if "sha256" in src:
        check_hex(src["sha256"], 64, f"{path}.sha256")
    if "takeover" in src:
        check_https_url(src["takeover"], f"{path}.takeover")
    check_https_url(src["url"], f"{path}.url")


def shape_receipt(r, path="$"):
    if isinstance(r, dict) and "withdrawn" in r:  # spec-0.7.0: a withdrawal, the null version
        _shape_object(r, WITHDRAWAL_MEMBERS, ("source",), path)
        if not isinstance(r["withdrawn"], str) or r["withdrawn"] == "":
            fail("E_SCHEMA", "withdrawn is a non-empty string: the reason", f"{path}.withdrawn")
        if isinstance(r.get("inputs"), list) and r["inputs"]:
            fail("E_SCHEMA", "a withdrawal is a stored cell's: inputs is empty", f"{path}.inputs")
    else:
        _shape_object(r, RECEIPT_MEMBERS, ("source",), path)
    for key in ("asof", "computed_by", "issued", "licence", "proto", "publisher",
                "sig", "summary", "tx") + (() if "withdrawn" in r else ("type",)):
        _shape_str(r, key, path)
    if r["proto"] != PROTO:
        fail("E_SCHEMA", f"proto must be {PROTO!r}", f"{path}.proto")
    shape_cell(r["cell"], f"{path}.cell")
    if not isinstance(r["inputs"], list) or not all(isinstance(i, str) for i in r["inputs"]):
        fail("E_SCHEMA", "inputs must be an array of strings", f"{path}.inputs")
    if "source" in r:  # spec-0.6.0: only a stored receipt, one with no inputs, has a source
        if r["inputs"]:
            fail("E_SCHEMA", "source is allowed only when inputs is empty (a stored receipt)", f"{path}.source")
        shape_source(r["source"], f"{path}.source")
    shape_args(r["valid"], f"{path}.valid")
    if "withdrawn" not in r and not isinstance(r["value"], (str, bool)):
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
    if "fn_hash" in ref:  # spec-0.4.2: a reference pinned to a function hash
        check_hex(ref["fn_hash"], 64, f"{path}.fn_hash")
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
        if "classes" in decl:  # spec-0.5.0 (16.5): the argument holds an object key of one of the classes
            if decl["type"] != "string":
                fail("E_CANON_TYPE", "only a string argument holds an object key", f"{p}.classes")
            _check_class_names(decl["classes"], f"{p}.classes")
        if decl.get("default") == "asof" and not (decl["valid"] and decl["type"] in ("date", "instant")):
            fail("E_CANON_TYPE", "the asof default is for a date or instant valid-time argument", f"{p}.default")
        if "key_normalisation" in decl and (decl["type"] != "string" or "classes" in decl):
            fail("E_CANON_TYPE", "key_normalisation is for a string argument without classes", f"{p}.key_normalisation")
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
    elif "classes" in returns:  # spec-0.5.0 (16.5): the function returns an object key
        check_type_name(returns["type"], f"{p}.type")
        if returns["type"] != "string":
            fail("E_CANON_TYPE", "an object key is returned as a string", p)
        if "unit" in returns:
            fail("E_CANON_UNIT", "an object key has no unit", p)
        _check_class_names(returns["classes"], f"{p}.classes")
    else:
        check_type_name(returns["type"], f"{p}.type")
        if returns["type"] != "number":
            fail("E_CANON_UNIT", "only a number return is written as an object", p)
        if "unit" not in returns:
            fail("E_CANON_UNIT", "a number return declares its unit", p)
        check_unit(returns["unit"], args, f"{p}.unit")
    return desc


def _check_class_names(names, path):
    if not names:
        fail("E_CANON_SET", "classes lists at least one class", path)
    for i, n in enumerate(names):
        check_function_name(n, f"{path}[{i}]")
    check_set(names, path)


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


def _rate_side_ok(side, value):
    """A rate's side (units.md 1, 3): of is a currency code; per is a currency code or shares (spec-0.6.2)."""
    return value in CURRENCIES or (side == "per" and value == "shares")


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
                if not _rate_side_ok(side, unit[side]):
                    fail("E_CANON_UNIT", f"a rate side is a currency code (per may be shares): {unit[side]!r}",
                         f"{path}.{side}")
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
        if is_unit_literal(value):
            return value
        return _resolved_rate_value(unit["arg"], value, path)
    sides = []
    for side in ("of", "per"):
        value = unit[side] if isinstance(unit[side], str) else _unit_arg_value(unit[side]["arg"], cell, path)
        if not _rate_side_ok(side, value):
            fail("E_CANON_UNIT", f"rate {side} is not allowed here: {value!r}", f"{path}.{side}")
        sides.append(value)
    return "/".join(sides)


def _resolved_rate_value(name, value, path):
    """spec-0.6.2 (units.md 3): a whole-unit argument may hold a rate's resolved form <of>/<per>. This is the one
    place a unit string is split, at its single slash, and only on resolution."""
    of, slash, per = value.partition("/")
    if not slash or "/" in per or not _rate_side_ok("of", of) or not _rate_side_ok("per", per):
        fail("E_CANON_UNIT", f"argument {name} is not a unit: {value!r}", path)
    return value


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
    if "source" in r:  # spec-0.6.0 (C2): in member order, after sig and before summary
        check_source(r["source"], r["cell"]["ns"].split("/")[0], f"{path}.source")
    if r["summary"] == "":
        fail("E_CANON_STRING", "summary must not be empty", f"{path}.summary")
    check_text(r["summary"], f"{path}.summary", "summary")
    check_instant(r["tx"], f"{path}.tx")
    if "withdrawn" in r:  # spec-0.7.0 (R1): the reason follows the string rules, with the summary limit
        check_text(r["withdrawn"], f"{path}.withdrawn", "summary")
    else:
        check_type_name(r["type"], f"{path}.type")
    check_args(r["valid"], f"{path}.valid")
    if "withdrawn" not in r:
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
    if "source" in r and not r["source"]["retrieved"] <= r["issued"]:  # spec-0.6.0 (8.2)
        fail("E_TIME_ORDER", "requires source.retrieved <= issued", f"{path}.source.retrieved")
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
    pin = None  # spec-0.4.2: fn_hash=, after the arguments and before asof
    if params and params[-1][0] == "fn_hash":
        pin = params.pop()[1]
    previous = None
    for name, raw in params:
        p = f"uri.query.{name}"
        if name == "asof":
            code = "E_CANON_ARG_DUPLICATE" if asof is not None else "E_CANON_ARG_ORDER"
            fail(code, "asof appears once, as the last parameter", p)
        if name == "fn_hash":
            code = "E_CANON_ARG_DUPLICATE" if pin is not None else "E_CANON_ARG_ORDER"
            fail(code, "fn_hash appears once, after the arguments and before asof", p)
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
    if pin is not None:
        check_hex(pin, 64, "uri.query.fn_hash")
        ref["fn_hash"] = pin
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
    if "fn_hash" in ref:
        query.append("fn_hash=" + ref["fn_hash"])
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


def parse_key_doc(text, host):
    """The keys of the document at https://<host>/.well-known/datumesh.json."""
    return parse_key_document(text, host)["keys"]


@_as_error("E_KEY_DOC")
def parse_key_document(text, host):
    """The document at https://<host>/.well-known/datumesh.json: {"host", "keys", "declarations"}.

    declarations (spec-0.4.3, SPEC.md 9.2) is optional; absent, the result's is {}."""
    doc = parse_json(text)
    _shape_object(doc, ("host", "keys", "proto"), ("declarations",), "$")
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
    declarations = _declarations(doc["declarations"], doc["host"]) if "declarations" in doc else {}
    return {"host": doc["host"], "keys": _no_duplicate_keys(keys), "declarations": declarations}


def _declarations(decl, host):
    """A key document's declarations (SPEC.md 9.2, spec-0.4.3); every failure is E_KEY_DOC."""
    p = "$.declarations"
    if not isinstance(decl, dict) or not 1 <= len(decl) <= LIMITS["declarations"]:
        fail("E_KEY_DOC", f"declarations must be an object of 1 to {LIMITS['declarations']} names", p)
    for name, entries in decl.items():
        q = f"{p}.{name}"
        check_function_name(name, q)
        if name.split("/")[0] != host:
            fail("E_KEY_DOC", f"a declared name is under the document's own host {host}", q)
        if not isinstance(entries, list) or not 1 <= len(entries) <= LIMITS["declaration_entries"]:
            fail("E_KEY_DOC", f"a declared name has 1 to {LIMITS['declaration_entries']} entries", q)
        for i, entry in enumerate(entries):
            e = f"{q}[{i}]"
            _shape_object(entry, ("licence", "valid_from"), ("valid_to",), e)
            for k in entry:
                _shape_str(entry, k, e)
            check_licence(entry["licence"], e)
            check_instant(entry["valid_from"], e)
            if "valid_to" in entry:
                check_instant(entry["valid_to"], e)
                if not entry["valid_from"] < entry["valid_to"]:
                    fail("E_KEY_DOC", "valid_to must be after valid_from", e)
    return decl


def _no_duplicate_keys(keys):
    if len({k["id"] for k in keys}) != len(keys):
        fail("E_KEY_DOC", "the same key is published twice")
    return keys


def resolve_keys(host, env):
    """Key resolution (SPEC.md 9.3): the HTTPS document or nothing.

    env describes what the HTTPS request returned for this host:
      {"https": {"status": 200, "body": "..."} | {"status": <other>} | {"status": "error"}}
    """
    return resolve_key_document(host, env)["keys"]


def resolve_key_document(host, env):
    """As resolve_keys, returning the whole document: {"host", "keys", "declarations"}."""
    https = (env or {}).get("https") or {"status": "error"}
    status = https.get("status")
    # Only the number 200 is a retrieved document; any other status, including the string "200"
    # or none at all, is a failed retrieval (SPEC.md 9.3, 11).
    if isinstance(status, bool) or not isinstance(status, (int, float)) or status != 200:
        fail("E_KEY_UNAVAILABLE", f"https key document: {status!r}")
    if "body" not in https:
        fail("E_KEY_DOC", "a 200 response without a document")
    return parse_key_document(https["body"], host)


# ---------------------------------------------------------------------------
# Unrooted namespaces, licence inheritance and entitlement (SPEC.md 2.5, 8.5, 10.3; spec-0.4.3).


def check_define(name, desc):
    """What a mesh's define checks of 7 and 2.5 (spec-0.5.0; the define vector kind): the full name,
    then the descriptor (section 7), then that a function under a rooted namespace reads no function
    under an unrooted one (E_UNROOTED_INPUT, at the first such input). Formula descriptors have the
    define-time rules of 15.6 too, which the formula kind tests."""
    check_function_name(name, "$.name")
    check_function(desc, "$")
    if not is_unrooted(name):
        for i, read in enumerate(desc["inputs"]):
            if is_unrooted(read):
                fail("E_UNROOTED_INPUT", f"a rooted function may not read the unrooted {read}", f"$.inputs[{i}]")
    canonical = jcs(desc)
    return {"canonical": canonical.decode(), "sha256": sha256_hex(canonical)}


def is_unrooted(namespace):
    """A namespace whose host is under .invalid (SPEC.md 2.5): it never resolves.

    Takes a namespace by 2.3 (so a host, or a full function name, which is a namespace followed by
    a name); anything else is E_CANON_NAME (spec-0.5.0: RS-45, JS 59)."""
    if not isinstance(namespace, str):
        fail("E_CANON_NAME", "a namespace is a string")
    check_namespace(namespace, "$")
    return namespace.split("/")[0].rsplit(".", 1)[-1] == "invalid"


# The listed open licences, least to most strict, in the order 8.5 lists them (spec-0.4.3). Every other licence,
# any https:// URL and any SPDX identifier not listed (compared byte for byte), is restricted: index 4 here.
LICENCE_TIERS = (("CC0-1.0", "PDDL-1.0"),
                 ("MIT", "Apache-2.0", "CC-BY-4.0", "OGL-UK-3.0"),
                 ("CC-BY-SA-4.0", "ODbL-1.0"))
RESTRICTED = 4


def licence_tier(licence):
    """The index of a listed licence in LICENCE_TIERS (1 to 3), RESTRICTED otherwise. public: licences are not
    listed; spec_tier() gives them their 8.5 tier (spec-0.6.2)."""
    for tier, ids in enumerate(LICENCE_TIERS, 1):
        if licence in ids:
            return tier
    return RESTRICTED


# The tiers of 8.5 (spec-0.6.2): 1 public domain, 2 public information (public:), 3 attribution, 4 share-alike,
# 5 restricted. The listed tiers 1 to 3 above are spec tiers 1, 3 and 4.
PUBLIC_TIER, SHARE_ALIKE_TIER, SPEC_RESTRICTED = 2, 4, 5
_SPEC_TIER_OF_INDEX = {1: 1, 2: 3, 3: SHARE_ALIKE_TIER}


def spec_tier(licence):
    if licence.startswith(PUBLIC_PREFIX):
        return PUBLIC_TIER
    index = licence_tier(licence)
    return SPEC_RESTRICTED if index == RESTRICTED else _SPEC_TIER_OF_INDEX[index]


def _open_at(entry, at):
    """A declaration entry's window, as a key's (9.5): valid_from <= at < valid_to."""
    return entry["valid_from"] <= at and ("valid_to" not in entry or at < entry["valid_to"])


def inherit_licence(licences, declarations, fn, issued, own):
    """The licence of a computed receipt (SPEC.md 8.5).

    licences: the licences of its input receipts, slice members included (a list; repeats allowed);
    declarations: the function's publisher's key document declarations (9.2); fn: the function's full
    name; issued: the receipt's issued; own: the mesh's own licence. Returns {"licence", "reason"}:
    licence None means the mesh may not compute the cell (an unlicensed answer, 5.5)."""
    # spec-0.5.0 (JS 56): the rule is defined for licences by 8.1, a function name and an instant.
    for i, licence in enumerate(licences):
        check_licence(licence, f"$.licences[{i}]")
    check_function_name(fn, "$.fn")
    check_instant(issued, "$.issued")
    check_licence(own, "$.mesh_licence")
    if not licences:
        return {"licence": own, "reason": "no_inputs"}
    restricted = sorted({x for x in licences if spec_tier(x) == SPEC_RESTRICTED})
    share_alike = {x for x in licences if spec_tier(x) == SHARE_ALIKE_TIER}
    if share_alike and (len(share_alike) > 1 or restricted):  # spec-0.4.3, the user's S2 b
        return {"licence": None, "reason": "share_alike_conflict"}
    if len(restricted) > 1:
        return {"licence": None, "reason": "restricted_conflict"}
    if restricted:
        entries = [e for e in declarations.get(fn, ()) if e["licence"] == restricted[0]]
        if not entries:
            return {"licence": None, "reason": "not_declared"}
        if not any(_open_at(e, issued) for e in entries):
            return {"licence": None, "reason": "declaration_not_open"}
        return {"licence": restricted[0], "reason": "declared"}
    top = max(spec_tier(x) for x in licences)
    if top == PUBLIC_TIER:  # several different public: licences: the one greatest in byte order (8.5 step 5)
        return {"licence": max((x for x in licences if spec_tier(x) == top), key=lambda x: x.encode()),
                "reason": "open"}
    listed = {1: LICENCE_TIERS[0], 3: LICENCE_TIERS[1], SHARE_ALIKE_TIER: LICENCE_TIERS[2]}[top]
    present = [x for x in listed if x in licences]
    return {"licence": present[-1], "reason": "open"}


def check_entitlement(receipt, licences, keydoc):
    """The entitlement check (SPEC.md 10.3): is a computed receipt's licence the one 8.5 gives?

    receipt: a receipt object; licences: its input receipts' licences, slice members included;
    keydoc: the key document of the publisher's host (the host of cell.ns), as parse_key_document
    returns it. Returns {"entitled", "reason"}. Not a verification step: no E_* code."""
    host = receipt["cell"]["ns"].split("/")[0]
    if not isinstance(keydoc, dict) or keydoc.get("host") != host:
        raise ValueError(f"the entitlement check takes the key document of the publisher's host {host}")
    if licences and not receipt["inputs"]:  # spec-0.5.0 (JS 58)
        raise ValueError("input licences given for a receipt that has no inputs")
    fn = receipt["cell"]["ns"] + "/" + receipt["cell"]["fn"]
    rule = inherit_licence(licences, keydoc.get("declarations", {}), fn, receipt["issued"], receipt["licence"])
    if rule["licence"] is None:
        return {"entitled": False, "reason": rule["reason"]}
    if rule["licence"] != receipt["licence"]:
        return {"entitled": False, "reason": "licence_mismatch"}
    return {"entitled": True, "reason": rule["reason"]}


def input_licences(receipt, receipts, manifests, keyenv=None):
    """The licences of a receipt's input receipts, slice members included, in inputs order (10.3).

    receipts: receipt hash -> receipt JSON text; manifests: slice entry -> manifest JSON text, as a
    recompute object's (11). Each input is obtained as 10.1 step 7.5 obtains it, with its codes
    (spec-0.5.0: RS-44, DEF-57, JS 57): a receipt not supplied, or of another hash,
    E_INPUT_UNAVAILABLE; one that is not signature-valid (verified when keyenv is given),
    E_INPUT_INVALID; a manifest not supplied, or of another slice or members, E_INPUT_UNAVAILABLE,
    and a malformed one its own code. Declared inputs, membership and times are verification's."""
    def get(h):
        if h not in receipts:
            fail("E_INPUT_UNAVAILABLE", f"input receipt {h} not available", "$.inputs")
        try:
            if keyenv is not None:
                verify_receipt(receipts[h], keyenv)
            r = parse_json(receipts[h].encode("utf-8") if isinstance(receipts[h], str) else receipts[h])
            check_receipt_form(r)
        except DatumeshError as e:
            fail("E_INPUT_INVALID", f"input {h}: {e}", "$.inputs")
        if receipt_hash(r) != h:
            fail("E_INPUT_UNAVAILABLE", f"supplied receipt does not hash to {h}", "$.inputs")
        return r["licence"]
    out = []
    for entry in receipt["inputs"]:
        if not entry.startswith("slice:"):
            out.append(get(entry))
            continue
        if entry not in manifests:
            fail("E_INPUT_UNAVAILABLE", f"no manifest for {entry}", "$.inputs")
        text = manifests[entry]
        m = parse_json(text.encode("utf-8") if isinstance(text, str) else text)
        check_manifest(m)
        if slice_entry(m["slice"], m["members"]) != entry:
            fail("E_INPUT_UNAVAILABLE", f"the manifest given for {entry} is another slice's", "$.inputs")
        out.extend(get(h) for h in m["members"])
    return out


# ---------------------------------------------------------------------------
# Classes (SPEC.md section 16, spec-0.5.0): the class descriptor, define and flattening, key
# normalisation, object keys and ids.

KEY_NORMALISATIONS = ("none", "upper_ascii", "nfc_strict", "arabic_skeleton", "hebrew_consonantal",
                      "greek_unaccented", "label_fold")  # label_fold: since the classes round (K8), labels only
_HEBREW_KEPT = {0x05BE, 0x05C0, 0x05C3, 0x05C6}  # maqaf, paseq, sof pasuq, nun hafukha
_ARABIC_MARKS = [(0x0610, 0x061A), (0x064B, 0x065F), (0x0670, 0x0670), (0x06D6, 0x06DC), (0x06DF, 0x06E8),
                 (0x06EA, 0x06ED), (0x0640, 0x0640)]


# nfc_strict (16.4): the White_Space characters of Unicode 15.1 other than U+0020 and the controls
# (U+0009-U+000D, U+0085), which 3.5 already refuses.
_WHITE_SPACE = frozenset("\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
                         "\u2028\u2029\u202f\u205f\u3000")


# label_fold (16.4, K8): the folding of a label: Unicode default case folding, then NFC, each run of White_Space one
# U+0020, leading and trailing spaces removed. A request's label is folded by the mesh (16.7); a value is canonical
# when it equals its own folding.
_WHITE_RUN = re.compile("[\t\n\x0b\x0c\r \x85\xa0  -     　]+")


def fold_label(value):
    return _WHITE_RUN.sub(" ", unicodedata.normalize("NFC", value.casefold())).strip(" ")


def check_key_value(rule, value, path="$"):
    """A string key value is canonical under its key normalisation (16.4); never repaired. It is first a
    string value (3.5, with its codes), whatever the rule; every rule but none rejects the empty string."""
    def bad(why):
        fail("E_KEY_NORMALISATION", f"not canonical under {rule}: {why}", path)
    if rule not in KEY_NORMALISATIONS:
        fail("E_CLASS_MEMBER", f"unknown key normalisation {rule!r}", path)
    check_text(value, path, "string")
    if rule == "none":
        return
    if value == "":
        bad("empty")
    if rule == "upper_ascii":
        if any(not ("\x21" <= c <= "\x7e") or "a" <= c <= "z" for c in value):
            bad("printable ASCII without lowercase letters or spaces")
    elif rule == "nfc_strict":
        for c in value:
            if unicodedata.category(c) == "Cf" or c in _WHITE_SPACE:
                bad(f"U+{ord(c):04X}")
        if value != value.strip(" ") or "  " in value:
            bad("leading, trailing or repeated spaces")
    elif rule == "hebrew_consonantal":
        if any(0x0591 <= ord(c) <= 0x05C7 and ord(c) not in _HEBREW_KEPT for c in value):
            bad("Hebrew points or accents")
    elif rule == "greek_unaccented":
        if any(0x0300 <= ord(c) <= 0x036F for c in unicodedata.normalize("NFD", value)):
            bad("Greek accents or breathings")
    elif rule == "arabic_skeleton":
        if any(lo <= ord(c) <= hi for c in value for lo, hi in _ARABIC_MARKS):
            bad("Arabic marks or tatweel")
    elif rule == "label_fold":
        if fold_label(value) != value:
            bad("not its case folding, in NFC with single spaces and no leading or trailing space")


CLASS_REQUIRED = ("keys", "methods", "order", "steward")
CLASS_OPTIONAL = ("extent", "final", "implements", "inverse", "lookup", "maps", "open", "parent")
_ANY_URI = re.compile(r"[a-z][a-z0-9+.-]*:[!-~]+")


def shape_class(d, path="$"):
    _shape_object(d, CLASS_REQUIRED, CLASS_OPTIONAL, path)
    if not isinstance(d["keys"], dict):
        fail("E_SCHEMA", "keys is an object", f"{path}.keys")
    for name, decl in d["keys"].items():
        p = f"{path}.keys.{name}"
        if isinstance(decl, dict) and "class" in decl:
            _shape_object(decl, ("class",), (), p)
            _shape_str(decl, "class", p)
        else:
            _shape_object(decl, ("type",), ("key_normalisation", "unit"), p)
            _shape_str(decl, "type", p)
            if "key_normalisation" in decl:
                _shape_str(decl, "key_normalisation", p)
            if "unit" in decl:
                shape_unit(decl["unit"], f"{p}.unit")
    if not isinstance(d["order"], list) or not all(isinstance(n, str) for n in d["order"]):
        fail("E_SCHEMA", "order is an array of key names", f"{path}.order")
    if not isinstance(d["methods"], dict) or not all(isinstance(h, str) for h in d["methods"].values()):
        fail("E_SCHEMA", "methods maps names to function hashes", f"{path}.methods")
    _shape_object(d["steward"], ("namespace", "process"), (), f"{path}.steward")
    for k in ("namespace", "process"):
        _shape_str(d["steward"], k, f"{path}.steward")
    if "parent" in d:
        _shape_str(d, "parent", path)
    if "lookup" in d:  # spec-0.5.0 (Q10 a)
        _shape_str(d, "lookup", path)
    if "final" in d and d["final"] is not True:
        fail("E_SCHEMA", "final is true when present", f"{path}.final")
    for k in ("implements", "inverse", "maps", "open"):
        if k in d and (not isinstance(d[k], list) or not d[k] or not all(isinstance(x, str) for x in d[k])):
            fail("E_SCHEMA", f"{k} is a non-empty array of strings", f"{path}.{k}")
    if "extent" in d:
        _shape_object(d["extent"], (), ("exists", "keys"), f"{path}.extent")
        if not d["extent"]:
            fail("E_SCHEMA", "extent names exists, keys or both", f"{path}.extent")
        for k in d["extent"]:
            _shape_str(d["extent"], k, f"{path}.extent")


def check_class(d, path="$"):
    """A class descriptor on its own (16.1): structure, then each member's rules, in the order of 16.1."""
    shape_class(d, path)
    keys = d["keys"]
    if len(keys) > LIMITS["args"]:
        fail("E_CANON_LIMIT", f"more than {LIMITS['args']} keys", f"{path}.keys")
    pseudo = {n: {"type": (k.get("type") if "type" in k else "string")} for n, k in keys.items()}
    for name in keys_in_order(keys):
        p = f"{path}.keys.{name}"
        decl = keys[name]
        check_arg_name(name, p)
        if "class" in decl:
            check_function_name(decl["class"], f"{p}.class")
            continue
        check_type_name(decl["type"], f"{p}.type")
        if decl["type"] == "blob":
            fail("E_CANON_TYPE", "a key is not a blob", f"{p}.type")
        if decl["type"] == "number":
            if "unit" not in decl:
                fail("E_CANON_UNIT", "a number key declares its unit", p)
            check_unit(decl["unit"], pseudo, f"{p}.unit")
        elif "unit" in decl:
            fail("E_CANON_UNIT", "only number keys have a unit", f"{p}.unit")
        if decl["type"] == "string":
            if "key_normalisation" not in decl:
                fail("E_CLASS_MEMBER", "a string key declares its key_normalisation", p)
            if decl["key_normalisation"] not in KEY_NORMALISATIONS or decl["key_normalisation"] == "label_fold":
                # label_fold is the rule of a label (K8): a class key is never folded, so it is not a class key's rule
                fail("E_CLASS_MEMBER", f"unknown key normalisation {decl['key_normalisation']!r}", p)
        elif "key_normalisation" in decl:
            fail("E_CLASS_MEMBER", "only string keys have a key_normalisation", p)
    order = d["order"]
    if len(order) != len(set(order)) or set(order) != set(keys):
        fail("E_CANON_SET", "order lists every key exactly once", f"{path}.order")
    for name in keys_in_order(d["methods"]):
        check_name(name, f"{path}.methods.{name}")
        check_hex(d["methods"][name], 64, f"{path}.methods.{name}")
    check_namespace(d["steward"]["namespace"], f"{path}.steward.namespace")
    proc = d["steward"]["process"]
    if not _URL.fullmatch(proc) or len(proc) > LIMITS["licence_url"]:
        fail("E_CLASS_MEMBER", "the steward's process is an https URL", f"{path}.steward.process")
    if "parent" in d:
        check_hex(d["parent"], 64, f"{path}.parent")
    if "open" in d:
        check_set(d["open"], f"{path}.open")
        for m in d["open"]:
            if m not in d["methods"]:
                fail("E_CLASS_MEMBER", f"open names a method: {m!r}", f"{path}.open")
        if "final" not in d:
            fail("E_CLASS_MEMBER", "open is for a final class", f"{path}.open")
    if "maps" in d:
        check_set(d["maps"], f"{path}.maps")
        for u in d["maps"]:
            if not _ANY_URI.fullmatch(u) or len(u) > LIMITS["licence_url"]:
                fail("E_CLASS_MEMBER", f"maps holds URIs: {u!r}", f"{path}.maps")
    if "inverse" in d:
        check_set(d["inverse"], f"{path}.inverse")
        for a in d["inverse"]:
            check_name(a, f"{path}.inverse")
            if f"by_{a}" not in d["methods"]:
                fail("E_CLASS_MEMBER", f"inverse {a!r} needs the method by_{a}", f"{path}.inverse")
    if "lookup" in d and d["lookup"] not in d["methods"]:  # spec-0.5.0 (Q10 a): names a method of the class
        fail("E_CLASS_MEMBER", f"lookup names a method: {d['lookup']!r}", f"{path}.lookup")
    if "extent" in d:
        for k in sorted(d["extent"]):
            check_hex(d["extent"][k], 64, f"{path}.extent.{k}")
    if "implements" in d:
        check_set(d["implements"], f"{path}.implements")
        for h in d["implements"]:
            check_hex(h, 64, f"{path}.implements")
    return d


def class_hash(flat):
    """SHA-256 of the canonical bytes of the flattened class descriptor (16.2)."""
    return sha256_hex(jcs(flat))


def _key_matches(decl, arg, rule=False):
    """A method's leading argument declares the class key (16.2); with rule (define, since Q6 b),
    a string key's argument also carries exactly the key's normalisation, absent meaning none."""
    if "class" in decl:
        return arg["type"] == "string" and arg.get("classes") == [decl["class"]]
    if arg["type"] != decl["type"] or "classes" in arg:
        return False
    if rule and decl["type"] == "string" and arg.get("key_normalisation", "none") != decl["key_normalisation"]:
        return False
    return decl["type"] != "number" or arg.get("unit") == decl.get("unit")


def _leading_keys(fd, keys, order, path, what):
    sig = fd["signature"]
    if "order" not in sig or sig["order"][:len(order)] != order:
        fail("E_CLASS_METHOD", f"{what} takes the class keys {order} first, by signature.order", path)
    for k in order:
        if not _key_matches(keys[k], sig["args"][k], rule=True):
            fail("E_CLASS_METHOD", f"{what}: argument {k} does not declare the key {k} (its type, unit and "
                 "key_normalisation)", path)


def _without_keys(sig, order):
    args = {n: a for n, a in sig["args"].items() if n not in order}
    return {"args": args, "order": [n for n in sig.get("order", []) if n not in order], "returns": sig["returns"]}


def define_class(name, desc, env):
    """Define a class (16.2): check it, flatten it onto its parent, check its methods. Returns the
    flattened descriptor, whose hash is the class hash.

    env: {"functions": [descriptors], "classes": [flattened class descriptors], "definer": namespace?}."""
    check_function_name(name, "$.name")
    definer = env.get("definer")
    ns = name.rpartition("/")[0]
    if definer is not None and not (ns == definer or ns.startswith(definer + "/")):
        fail("E_CLASS_OWNER", f"{definer} cannot define a class under {ns}", "$.name")
    check_class(desc)
    functions = {function_hash(f): f for f in env.get("functions", [])}
    classes = {class_hash(c): c for c in env.get("classes", [])}
    flat = copy_json(desc)
    parent = None
    if "parent" in desc:
        if desc["parent"] not in classes:
            fail("E_CLASS_PARENT", "no class descriptor for the parent's hash", "$.parent")
        parent = classes[desc["parent"]]
        for k in keys_in_order(desc["keys"]):
            if k in parent["keys"]:
                fail("E_CLASS_INHERIT", f"the key {k} is inherited: never redeclared, removed or retyped",
                     f"$.keys.{k}")
        flat["keys"] = dict(parent["keys"], **desc["keys"])
        flat["order"] = parent["order"] + desc["order"]
        flat["methods"] = dict(parent["methods"], **desc["methods"])
        implements = set(parent.get("implements", [])) | set(desc.get("implements", []))
        if implements:
            flat["implements"] = sorted(implements, key=_utf16_key)
        for m in keys_in_order(desc["methods"]):
            if m not in parent["methods"] or parent["methods"][m] == desc["methods"][m]:
                continue
            if "final" in parent and m not in parent.get("open", []):
                fail("E_CLASS_FINAL", f"{m} of a final class is not open: add, do not override", f"$.methods.{m}")
            old, new = functions.get(parent["methods"][m]), functions.get(desc["methods"][m])
            if old is None or new is None:
                fail("E_CLASS_METHOD", f"no descriptor for the method {m}", f"$.methods.{m}")
            if old["signature"] != new["signature"]:
                fail("E_CLASS_OVERRIDE", f"an override of {m} keeps its signature, return type and unit",
                     f"$.methods.{m}")
    check_class(flat)
    keys, order = flat["keys"], flat["order"]
    for m in keys_in_order(flat["methods"]):
        p = f"$.methods.{m}"
        fd = functions.get(flat["methods"][m])
        if fd is None:
            fail("E_CLASS_METHOD", f"no descriptor for the method {m}", p)
        if m == flat.get("lookup"):  # spec-0.5.0 (Q10 a): label -> key of this class, exempt from keys first
            sig = fd["signature"]
            label = sig["args"].get("label")
            if sig.get("order") != ["label"] or set(sig["args"]) != {"label"} or label["type"] != "string" \
                    or label["valid"] or "classes" in label or sig["returns"] != {"type": "string", "classes": [name]}:
                fail("E_CLASS_MEMBER", f"the lookup method {m} takes exactly one string argument label and returns "
                     "a key of this class", p)
            continue
        if parent is not None and m in parent["methods"]:
            n = 0  # an inherited method takes the parent's keys it was defined with: a prefix of its order
            while n < len(parent["order"]) and parent["order"][n] in fd["signature"]["args"]:
                n += 1
            _leading_keys(fd, keys, parent["order"][:n], p, m)
        else:
            _leading_keys(fd, keys, order, p, m)
        ret = fd["signature"]["returns"]
        if m == "same_as" and not (isinstance(ret, dict) and "classes" in ret and name not in ret["classes"]):
            fail("E_CLASS_METHOD", "same_as returns a key of another class", p)
        if m.startswith("by_") and m[3:] in flat.get("inverse", []) \
                and not (isinstance(ret, dict) and ret.get("classes") == [name]):
            fail("E_CLASS_METHOD", f"{m} returns a key of this class", p)
    for k in sorted(flat.get("extent", {})):
        fd = functions.get(flat["extent"][k])
        if fd is None or fd["signature"].get("order") != order or set(fd["signature"]["args"]) != set(order) \
                or fd["signature"]["returns"] != "boolean":
            fail("E_CLASS_MEMBER", f"extent.{k} takes exactly the class keys and returns a boolean", f"$.extent.{k}")
    for h in flat.get("implements", []):
        iface = classes.get(h)
        if iface is None or iface["keys"]:
            fail("E_CLASS_INTERFACE", "implements names keyless classes (interfaces) the define knows",
                 "$.implements")
        for m in keys_in_order(iface["methods"]):
            want, have = functions.get(iface["methods"][m]), functions.get(flat["methods"].get(m, ""))
            if want is None or have is None or _without_keys(have["signature"], order) != _without_keys(
                    want["signature"], []):
                fail("E_CLASS_INTERFACE", f"the interface's method {m} is not implemented with its signature",
                     "$.implements")
    return flat


def copy_json(value):
    return json.loads(json.dumps(value))


_KEY_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
_KEY_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_KEY_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_KEY_CLASS = re.compile(r"[a-z0-9][a-z0-9.\-]*(?:/[a-z0-9_]+)+")


def _encode_value(v):
    if "class" in v:
        return encode_key(v["class"], v["keys"])
    t, x = v["type"], v["value"]
    if t == "string":
        return '"' + x.replace('"', '""') + '"'
    if t == "boolean":
        return "true" if x else "false"
    return x


def encode_key(class_name, keys):
    """An object key as one canonical string (16.5): the class name, then its keys labelled in
    ascending order of name, without spaces; a class-typed key nested in the same form."""
    return class_name + "(" + ",".join(f"{k}:{_encode_value(keys[k])}" for k in keys_in_order(keys)) + ")"


def encode_decoded(decoded):
    return encode_key(decoded["class"], decoded["keys"])


def decode_key(text):
    """The object a key encoding names: {"class", "keys"}, keys typed scalars or nested objects.
    Anything malformed or not canonical is E_KEY_ENCODING (16.5)."""
    def bad(why):
        fail("E_KEY_ENCODING", f"{why}: {text!r}")
    if not isinstance(text, str):
        bad("not a string")
    try:  # the encoding is one string value (3.5): no control, NFC, at most 1024 bytes as a whole
        check_text(text, "$", "string")
    except DatumeshError as e:
        bad(f"the encoding breaks 3.5 ({e.code})")
    pos = [0]

    def obj():
        m = _KEY_CLASS.match(text, pos[0])
        if not m or not text.startswith("(", m.end()):
            bad("a key is <class name>(...)")
        name = m.group()
        try:
            check_function_name(name, "$")
        except DatumeshError:
            bad("not a class name")
        pos[0] = m.end() + 1
        keys = {}
        if text.startswith(")", pos[0]):
            pos[0] += 1
            return {"class": name, "keys": keys}
        while True:
            m = re.compile(r"[a-z][a-z0-9_]*:").match(text, pos[0])
            if not m:
                bad("a key is <name>:<value>")
            label = m.group()[:-1]
            try:
                check_arg_name(label, "$")
            except DatumeshError:
                bad("not a key name")
            if label in keys:
                bad("a key named twice")
            pos[0] = m.end()
            keys[label] = value()
            if text.startswith(",", pos[0]):
                pos[0] += 1
                continue
            if text.startswith(")", pos[0]):
                pos[0] += 1
                return {"class": name, "keys": keys}
            bad("expected , or )")

    def ends(n):
        return n == len(text) or text[n] in ",)"

    def value():
        i = pos[0]
        if text.startswith('"', i):
            j, out = i + 1, []
            while True:
                if j >= len(text):
                    bad("an unterminated string")
                if text[j] == '"':
                    if text.startswith('""', j):
                        out.append('"')
                        j += 2
                        continue
                    break
                out.append(text[j])
                j += 1
            s = "".join(out)
            try:
                check_text(s, "$", "string")
            except DatumeshError:
                bad("a string key breaks 3.5")
            pos[0] = j + 1
            return {"type": "string", "value": s}
        for regex, type_ in ((_KEY_INSTANT, "instant"), (_KEY_DATE, "date"), (_KEY_NUMBER, "number")):
            m = regex.match(text, i)
            if m and ends(m.end()):
                try:
                    check_lexical(type_, m.group(), "$")
                except DatumeshError:
                    bad(f"not a {type_}")
                pos[0] = m.end()
                return {"type": type_, "value": m.group()}
        for word, b in (("true", True), ("false", False)):
            if text.startswith(word, i) and ends(i + len(word)):
                pos[0] = i + len(word)
                return {"type": "boolean", "value": b}
        return obj()

    decoded = obj()
    if pos[0] != len(text):
        bad("text after the key")
    if encode_decoded(decoded) != text:
        bad("not the canonical encoding")
    return decoded


def _object_call(class_name, keys):
    parts = []
    for k in keys_in_order(keys):
        v = keys[k]
        parts.append(f"{k}: {_call_literal(v['type'] if v['type'] != 'blob' else 'string', v['value'])}")
    return f"{class_name}({', '.join(parts)})"


def describe_class(name, desc, functions, descriptions=None):
    """The describe answer for a class (16.8)."""
    methods = {}
    keys = set(desc["keys"])
    for m in keys_in_order(desc["methods"]):
        fd = next((d for d in functions.values() if function_hash(d) == desc["methods"][m]), None)
        sig = fd["signature"]
        entry = {"args": {a: d for a, d in sig["args"].items() if a not in keys}, "fn": f"{name}/{m}",
                 "fn_hash": desc["methods"][m], "returns": sig["returns"]}
        if descriptions and m in descriptions:
            entry["description"] = descriptions[m]
        methods[m] = entry
    return {"class": name, "class_hash": class_hash(desc), "descriptor": desc, "kind": "class", "methods": methods}


def describe_object(name, desc, keys, same_as=None):
    """The describe answer for an object (16.8)."""
    obj = object_of(name, class_hash(desc), keys)
    oid = object_id(obj)
    out = {"call": _object_call(name, keys), "kind": "object", "methods": keys_in_order(desc["methods"]),
           "object": obj, "object_id": oid, "short_id": short_id(oid)}
    if same_as:
        out["same_as"] = list(same_as)
    return out


def _shape_text(value, path, limit="string"):
    """A string member valid by 3.5: E_SCHEMA when it is not a string."""
    if not isinstance(value, str):
        fail("E_SCHEMA", "expected a string", path)
    check_text(value, path, limit)


def _value_of_key(decl, value, path):
    """An object's key value against its class's key declaration (16.5, 16.8): its type, and for a
    string key its normalisation; a class-typed key the typed string scalar of a key of that class."""
    if "class" in decl:
        if value["type"] != "string" or decode_key(value["value"])["class"] != decl["class"]:
            fail("E_DESCRIBE", f"a key of {decl['class']}, as a typed string scalar", path)
        return
    if value["type"] != decl["type"]:
        fail("E_DESCRIBE", f"a {decl['type']} key", path)
    if decl["type"] == "string":
        check_key_value(decl["key_normalisation"], value["value"], path)


@_as_error("E_DESCRIBE")
def check_describe(doc, classes=None, functions=None):
    """A describe answer (16.8), parsed (step 1, the caller's, with 6.1's codes), checked in the order
    of 16.8: 2 shape, 3 internal consistency, 4 the held class, found by class_hash among `classes`
    (flattened descriptors, by name; the name is not compared), 5 against it, 6 against the held method
    functions (`functions`, descriptors), when given. Every failure is E_DESCRIBE."""
    # 2. Shape.
    if not isinstance(doc, dict) or doc.get("kind") not in ("class", "object", "function", "catalog"):
        fail("E_DESCRIBE", "a describe answer is of kind class, object, function or catalog")
    if doc["kind"] == "function":  # spec-0.6.0 (C7): a function answer, for {id} a function name (2.3)
        return _check_describe_function(doc, functions)
    if doc["kind"] == "catalog":  # C7 (since the classes round): the catalogue root, in one call
        return _check_describe_catalog(doc)
    if doc["kind"] == "class":
        _shape_object(doc, ("class", "class_hash", "descriptor", "kind", "methods"), ("facets", "publisher"), "$")
        _shape_text(doc["class"], "$.class")
        check_function_name(doc["class"], "$.class")
        _check_publisher(doc, doc["class"])
        if "facets" in doc:  # C2 (since the classes round)
            check_facets(doc["facets"], "$.facets")
        _shape_text(doc["class_hash"], "$.class_hash")
        check_hex(doc["class_hash"], 64, "$.class_hash")
        shape_class(doc["descriptor"], "$.descriptor")
        if not isinstance(doc["methods"], dict):
            fail("E_DESCRIBE", "methods is an object", "$.methods")
        for m in keys_in_order(doc["methods"]):
            e, p = doc["methods"][m], f"$.methods.{m}"
            _shape_object(e, ("args", "fn", "fn_hash", "returns"), ("description", "source", "tests"), p)
            _shape_text(e["fn"], f"{p}.fn")
            _shape_text(e["fn_hash"], f"{p}.fn_hash")
            if not isinstance(e["args"], dict):
                fail("E_DESCRIBE", "args is an object", f"{p}.args")
            if "description" in e:
                _shape_text(e["description"], f"{p}.description")
                if e["description"] == "":
                    fail("E_DESCRIBE", "a description is 1 to 1024 bytes", f"{p}.description")
            if "tests" in e:  # spec-0.6.0 (C7)
                _check_describe_tests(e["tests"], f"{p}.tests")
            if "source" in e:
                _check_describe_source(e["source"], f"{p}.source")
        # 3. Consistency.
        check_class(doc["descriptor"], "$.descriptor")
        if doc["class_hash"] != class_hash(doc["descriptor"]):
            fail("E_DESCRIBE", "class_hash is the descriptor's hash", "$.class_hash")
        methods = doc["methods"]
        if set(methods) != set(doc["descriptor"]["methods"]):
            fail("E_DESCRIBE", "methods lists exactly the descriptor's methods", "$.methods")
        for m in keys_in_order(methods):
            e = methods[m]
            # 16.3 (K5, since the classes round): an inherited method's function is its defining class's, D/m; the
            # defining class is not checked here (the parents are not held), only the method and the hash
            named = e["fn"] == f"{doc['class']}/{m}" or (e["fn"].endswith(f"/{m}") and "/" in e["fn"])
            if not named or e["fn_hash"] != doc["descriptor"]["methods"][m]:
                fail("E_DESCRIBE", f"method {m} is {doc['class']}/{m}, or its defining class's, with the descriptor's hash",
                     f"$.methods.{m}")
        # 4. The held class.
        held = {class_hash(d): d for d in (classes or {}).values()}.get(doc["class_hash"])
        if held is None:
            return doc
        # 5. Against it: the descriptor byte for byte after canonicalisation.
        if jcs(doc["descriptor"]) != jcs(held):
            fail("E_DESCRIBE", "descriptor is the held flattened descriptor", "$.descriptor")
        # 6. Against the held method functions, for each method whose descriptor is held.
        fns = {function_hash(f): f for f in (functions or [])}
        keys = set(held["keys"])
        for m in keys_in_order(methods):
            fd = fns.get(methods[m]["fn_hash"])
            if fd is None:
                continue
            sig = fd["signature"]
            if methods[m]["args"] != {a: d for a, d in sig["args"].items() if a not in keys} \
                    or methods[m]["returns"] != sig["returns"]:
                fail("E_DESCRIBE", f"method {m}: args and returns are its function's, after the keys",
                     f"$.methods.{m}")
        return doc
    _shape_object(doc, ("call", "kind", "methods", "object", "object_id", "short_id"),
                  ("extensions", "resolved", "same_as"), "$")
    obj = doc["object"]
    _shape_object(obj, ("class", "class_hash", "keys"), (), "$.object")
    _shape_text(obj["class"], "$.object.class")
    check_function_name(obj["class"], "$.object.class")
    _shape_text(obj["class_hash"], "$.object.class_hash")
    check_hex(obj["class_hash"], 64, "$.object.class_hash")
    shape_args(obj["keys"], "$.object.keys")
    if SLICE in obj["keys"].values():
        fail("E_DESCRIBE", "an object binds every key to a typed scalar", "$.object.keys")
    check_args(obj["keys"], "$.object.keys")
    _shape_text(doc["object_id"], "$.object_id")
    check_hex(doc["object_id"], 64, "$.object_id")
    _shape_text(doc["short_id"], "$.short_id")
    check_hex(doc["short_id"], 12, "$.short_id")
    _shape_text(doc["call"], "$.call", "body")
    if not isinstance(doc["methods"], list) or not all(isinstance(m, str) for m in doc["methods"]):
        fail("E_DESCRIBE", "methods is an array of method names", "$.methods")
    for m in doc["methods"]:
        check_name(m, "$.methods")
    check_set(doc["methods"], "$.methods")
    if "same_as" in doc:
        same = doc["same_as"]
        if not isinstance(same, list) or not same or not all(isinstance(k, str) for k in same):
            fail("E_DESCRIBE", "same_as is a non-empty array of object keys", "$.same_as")
        check_set(same, "$.same_as")
        for k in same:
            decode_key(k)
    # 3. Consistency.
    if doc["object_id"] != object_id(obj):
        fail("E_DESCRIBE", "object_id is the object's id", "$.object_id")
    if doc["short_id"] != short_id(doc["object_id"]):
        fail("E_DESCRIBE", "short_id is the first 12 hex digits of the object id", "$.short_id")
    if doc["call"] != _object_call(obj["class"], obj["keys"]):
        fail("E_DESCRIBE", "call is the object's canonical call", "$.call")
    if "extensions" in doc:  # K9 (since the classes round)
        _check_extensions(doc["extensions"], "$.extensions")
    if "resolved" in doc:  # K8 (since the classes round): the lookup that named the object (N[label])
        _check_resolved(doc["resolved"], doc, "$.resolved")
    # 4. The held class.
    held = {class_hash(d): d for d in (classes or {}).values()}.get(obj["class_hash"])
    if held is None:
        return doc
    # 5. Against it: key names, each value's type and normalisation, the methods.
    if set(obj["keys"]) != set(held["keys"]):
        fail("E_DESCRIBE", "the object's keys are its class's", "$.object.keys")
    for k in keys_in_order(obj["keys"]):
        _value_of_key(held["keys"][k], obj["keys"][k], f"$.object.keys.{k}")
    if doc["methods"] != keys_in_order(held["methods"]):
        fail("E_DESCRIBE", "the object's methods are its class's", "$.methods")
    return doc


def _check_describe_tests(tests, path):
    """tests (16.8, spec-0.6.0): the mesh's statement of the tests it holds for a function hash. Four integers
    (5.5's integer rule: written 0 or without a leading zero, no fraction or exponent), covered at most branches."""
    _shape_object(tests, ("branches", "count", "counterexamples", "covered"), (), path)
    for name in ("branches", "count", "counterexamples", "covered"):
        if not _seconds(tests[name]):
            fail("E_DESCRIBE", f"{name} is an integer", f"{path}.{name}")
    if int(tests["covered"].text) > int(tests["branches"].text):
        fail("E_DESCRIBE", "covered is at most branches", f"{path}.covered")


def _check_describe_source(source, path):
    """source of a relayed function (16.8, spec-0.6.0): the source's DNS name, the mesh's host and its takeover URL."""
    _shape_object(source, ("name", "relayed_by", "takeover"), (), path)
    for name in ("name", "relayed_by", "takeover"):
        _shape_text(source[name], f"{path}.{name}")
    check_dns_name(source["name"], f"{path}.name")
    check_dns_name(source["relayed_by"], f"{path}.relayed_by")
    check_https_url(source["takeover"], f"{path}.takeover")


def _check_publisher(doc, name):
    if "publisher" in doc:
        _shape_text(doc["publisher"], "$.publisher")
        check_dns_name(doc["publisher"], "$.publisher")
        if doc["publisher"] != name.split("/")[0]:
            fail("E_DESCRIBE", "publisher is the host of the name", "$.publisher")


def _check_describe_function(doc, functions):
    """A function answer (16.8, spec-0.6.0): its shape; the descriptor's args and returns when it is held, all of its
    arguments, as a method entry's are after its keys."""
    _shape_object(doc, ("args", "fn", "fn_hash", "kind", "returns"),
                  ("description", "facets", "publisher", "source", "tests"), "$")
    if "facets" in doc:  # C2 (since the classes round)
        check_facets(doc["facets"], "$.facets")
    _shape_text(doc["fn"], "$.fn")
    check_function_name(doc["fn"], "$.fn")
    _check_publisher(doc, doc["fn"])
    _shape_text(doc["fn_hash"], "$.fn_hash")
    check_hex(doc["fn_hash"], 64, "$.fn_hash")
    if not isinstance(doc["args"], dict) or not all(isinstance(a, dict) and isinstance(a.get("type"), str)
                                                    for a in doc["args"].values()):
        fail("E_DESCRIBE", "args is an object of argument declarations", "$.args")
    if "description" in doc:
        _shape_text(doc["description"], "$.description")
        if not 1 <= len(doc["description"].encode("utf-8")) <= LIMITS["string"]:
            fail("E_DESCRIBE", "a description is 1 to 1024 bytes", "$.description")
    if "tests" in doc:
        _check_describe_tests(doc["tests"], "$.tests")
    if "source" in doc:
        _check_describe_source(doc["source"], "$.source")
    held = {function_hash(f): f for f in (functions or [])}.get(doc["fn_hash"])
    if held is not None and (doc["args"] != held["signature"]["args"] or doc["returns"] != held["signature"]["returns"]):
        fail("E_DESCRIBE", "args and returns are the held descriptor's", "$")
    return doc


FACETS = ("domain", "frequency", "measure", "region", "thing")  # C2: the five facet keys (16.8)


def check_facets(facets, path="$"):
    """facets (16.8, C2, since the classes round): an object of at most the five facet keys, each a list of 1 to 8
    names (2.2) of at most 32 bytes, ascending and unique. Not empty."""
    if not isinstance(facets, dict) or not facets:
        fail("E_DESCRIBE", "facets is a non-empty object", path)
    for key in keys_in_order(facets):
        p = f"{path}.{key}"
        if key not in FACETS:
            fail("E_DESCRIBE", f"facet {key!r} is not one of {FACETS}", p)
        values = facets[key]
        if not isinstance(values, list) or not 1 <= len(values) <= 8:
            fail("E_DESCRIBE", "a facet is a list of 1 to 8 names", p)
        for v in values:
            if not isinstance(v, str):
                fail("E_DESCRIBE", "a facet value is a string", p)
            check_name(v, p)
            if len(v.encode("utf-8")) > 32:
                fail("E_DESCRIBE", "a facet value is at most 32 bytes", p)
        if values != sorted(values) or len(set(values)) != len(values):
            fail("E_DESCRIBE", "a facet's values are ascending and unique", p)


def _check_extensions(ext, path):
    """extensions (16.8, K9, since the classes round): the functions that extend the object's class, ascending by fn
    and unique; each names its function, its hash and its publisher (the host of fn, 2.3)."""
    if not isinstance(ext, list) or not ext:
        fail("E_DESCRIBE", "extensions is a non-empty array of extensions", path)
    for i, e in enumerate(ext):
        p = f"{path}[{i}]"
        _shape_object(e, ("fn", "fn_hash", "publisher"), (), p)
        _shape_text(e["fn"], f"{p}.fn")
        check_function_name(e["fn"], f"{p}.fn")
        _shape_text(e["fn_hash"], f"{p}.fn_hash")
        check_hex(e["fn_hash"], 64, f"{p}.fn_hash")
        _check_publisher(e, e["fn"])
    names = [e["fn"] for e in ext]
    if names != sorted(names) or len(set(names)) != len(names):
        fail("E_DESCRIBE", "extensions is ascending by fn, and unique", path)


def _check_resolved(r, doc, path):
    """resolved of an object answer (16.8, K8, since the classes round): the call of the object, and the one resolution,
    a lookup (N[label]) whose key encoding is the object's, with the instant the lookup was read as of."""
    _shape_object(r, ("call", "resolutions"), (), path)
    _shape_text(r["call"], f"{path}.call")
    if r["call"] != doc["call"]:
        fail("E_DESCRIBE", "resolved.call is the object's call", f"{path}.call")
    res = r["resolutions"]
    if not isinstance(res, list) or len(res) != 1:
        fail("E_DESCRIBE", "resolutions holds the lookup resolution only", f"{path}.resolutions")
    x, p = res[0], f"{path}.resolutions[0]"
    _shape_object(x, ("asof", "from", "kind", "to"), (), p)
    for k in ("from", "kind", "to"):
        _shape_text(x[k], f"{p}.{k}")
    if x["kind"] != "lookup":
        fail("E_DESCRIBE", "the resolution is a lookup", f"{p}.kind")
    if not isinstance(x["asof"], str) or not _is_instant(x["asof"]):
        fail("E_DESCRIBE", "asof is an instant", f"{p}.asof")
    d, obj = decode_key(x["to"]), doc["object"]
    same = d["class"] == obj["class"] and set(d["keys"]) == set(obj["keys"]) and all(
        encode_decoded(d["keys"][k]) == obj["keys"][k]["value"] if "class" in d["keys"][k]
        else d["keys"][k] == obj["keys"][k] for k in d["keys"])
    if not same:
        fail("E_DESCRIBE", "the lookup's to is the key encoding of the object", f"{p}.to")


@_as_error("E_DESCRIBE")
def _check_describe_catalog(doc):
    """describe of the catalogue root (16.8, C7, since the classes round): the host, the rule's url, and the domains
    by number of subjects (descending), then by name; each domain has its label, its counts and 1 to 5 top subjects,
    each a key encoding, a label and a full name."""
    _shape_object(doc, ("domains", "host", "kind", "rule"), (), "$")
    _shape_text(doc["host"], "$.host")
    check_dns_name(doc["host"], "$.host")
    if not isinstance(doc["rule"], str) or doc["rule"] != f"https://{doc['host']}/catalog/rule":
        fail("E_DESCRIBE", "rule is the https url of /catalog/rule on this host", "$.rule")
    if not isinstance(doc["domains"], list):
        fail("E_DESCRIBE", "domains is an array", "$.domains")
    last = None
    for i, d in enumerate(doc["domains"]):
        p = f"$.domains[{i}]"
        _shape_object(d, ("domain", "label", "names", "subjects", "top"), (), p)
        _shape_text(d["domain"], f"{p}.domain")
        check_name(d["domain"], f"{p}.domain")
        _shape_text(d["label"], f"{p}.label")
        for name in ("names", "subjects"):
            if not _seconds(d[name]):
                fail("E_DESCRIBE", f"{name} is a non-negative integer", f"{p}.{name}")
        if not isinstance(d["top"], list) or not 1 <= len(d["top"]) <= 5:
            fail("E_DESCRIBE", "top is a list of 1 to 5 subjects", f"{p}.top")
        for j, t in enumerate(d["top"]):
            tp = f"{p}.top[{j}]"
            _shape_object(t, ("label", "source", "subject"), (), tp)
            _shape_text(t["label"], f"{tp}.label")
            _shape_text(t["subject"], f"{tp}.subject")
            decode_key(t["subject"])
            _shape_text(t["source"], f"{tp}.source")
            check_function_name(t["source"], f"{tp}.source")
        key = (-int(d["subjects"].text), d["domain"])
        if last is not None and key <= last:
            fail("E_DESCRIBE", "domains by subjects, descending, then by name", p)
        last = key


@_as_error("E_DESCRIBE")
def check_find_result(doc):
    """A find result (9.6, C2, since the classes round): its members are the mesh's; publisher, source and facets are
    checked as the describe answers check them."""
    if not isinstance(doc, dict):
        fail("E_DESCRIBE", "a find result is an object", "$")
    if "facets" in doc:
        check_facets(doc["facets"], "$.facets")
    if "publisher" in doc:
        if not isinstance(doc.get("fn"), str):
            fail("E_DESCRIBE", "a publisher needs its fn", "$.publisher")
        _check_publisher(doc, doc["fn"])
    if "source" in doc:
        _check_describe_source(doc["source"], "$.source")
    return doc


def check_key_of_class(decoded, classes, path="$"):
    """spec-0.5.0 (H3, 16.5): a decoded key encoding against its class, when the class is known: its key
    names exactly the class's, each value of its key's type (a class-typed key decoded against its own
    class, when known), each string value canonical under its key's normalisation. E_CANON_TYPE for names
    or types, E_KEY_NORMALISATION for a value not canonical; nothing when the class is not known."""
    desc = classes.get(decoded["class"])
    if desc is None:
        return
    keys = decoded["keys"]
    if set(keys) != set(desc["keys"]):
        fail("E_CANON_TYPE", f"not the keys of {decoded['class']}", path)
    for k in keys_in_order(keys):
        decl, v = desc["keys"][k], keys[k]
        if "class" in decl:
            if v.get("class") != decl["class"]:
                fail("E_CANON_TYPE", f"the key {k} of {decoded['class']} is a key of {decl['class']}", path)
            check_key_of_class(v, classes, path)
        elif "class" in v or v["type"] != decl["type"]:
            fail("E_CANON_TYPE", f"the key {k} of {decoded['class']} is a {decl['type']}", path)
        elif decl["type"] == "string":
            check_key_value(decl["key_normalisation"], v["value"], path)


def object_of_key(text, chash):
    """The object (16.5) a key encoding names, given its class's hash: a class-typed key is the typed
    string scalar of its own encoding, so the object holds typed scalars only."""
    decoded = decode_key(text)
    check_hex(chash, 64, "$.class_hash")
    keys = {k: {"type": "string", "value": encode_decoded(v)} if "class" in v else v
            for k, v in decoded["keys"].items()}
    return object_of(decoded["class"], chash, keys)


def object_of(class_name, chash, keys):
    """The object (16.5): a class name, its class hash and its key tuple. Never stored."""
    return {"class": class_name, "class_hash": chash, "keys": keys}


def object_id(obj):
    return sha256_hex(jcs(obj))


def short_id(identifier):
    """The first 12 hex digits of a cell id or object id (16.8); of a full id only (E_CANON_HEX)."""
    if not isinstance(identifier, str):
        fail("E_CANON_HEX", "a short id is taken of a cell id or object id")
    check_hex(identifier, 64, "$")
    return identifier[:12]


# ---------------------------------------------------------------------------
# The mesh document (SPEC.md 9.6, spec-0.4.1): cross-mesh resolution, never verification.

MESH_ENDPOINTS = {  # endpoint -> its placeholders (each exactly once)
    "whatif": (),  # spec-0.6.0 (5.9), optional: a whatif request, no placeholders
    "blob": ("sha256",), "cell": ("cell",), "cells": (), "descriptor": ("hash",), "explain": ("cell",), "find": (),
    "jobs": ("job",), "manifest": ("slice_id", "members_hash"), "receipt": ("hash",), "slice": ("cell",), "verify": (),
    "versions": ("cell",),  # spec-0.4.2, optional
    "describe": ("id",),  # spec-0.5.0, optional (16.8)
}
MESH_REQUIRED = ("cell", "descriptor", "jobs", "manifest", "receipt")


def _retrieved(env, code, no_body):
    """A retrieval as in 9.3: only the number 200 is a document; a 200 without a body is no_body."""
    https = (env or {}).get("https") or {"status": "error"}
    status = https.get("status")
    if isinstance(status, bool) or not isinstance(status, (int, float)) or status != 200:
        fail(code, f"https document: {status!r}")
    if "body" not in https:
        fail(no_body, "a 200 response without a document")
    return https["body"]


# spec-0.5.0 (the user's decision B3 b): for an unrooted host, mesh-document URLs, poll and next may be
# http:// on a loopback address only, with an optional port; rooted hosts stay https-only.
_LOOPBACK_URL = re.compile(r"(http://(?:127\.0\.0\.1|\[::1\]|localhost)(?::([1-9][0-9]{0,4}))?)/[!-~]*")


def loopback_origin(value):
    """The origin http://<loopback>[:<port>] of a loopback URL (SPEC.md 9.6, spec-0.5.0), or None."""
    m = _LOOPBACK_URL.fullmatch(value) if isinstance(value, str) else None
    if not m or len(value) > LIMITS["licence_url"] or (m.group(2) and int(m.group(2)) > 65535):
        return None
    return m.group(1)


def _mesh_url(value, host, path):
    """A URL of host's mesh document; returns its origin. For an unrooted host, also a loopback one."""
    if is_unrooted(host):
        origin = loopback_origin(value)
        if origin:
            return origin
    if not isinstance(value, str) or not _URL.fullmatch(value) or len(value) > LIMITS["licence_url"]:
        fail("E_MESH_DOC", "an https URL of at most 512 characters (or, for an unrooted host, a loopback http URL)",
             path)
    if not value.startswith(f"https://{host}/"):
        fail("E_MESH_DOC", f"a URL on this host: it begins https://{host}/", path)
    return f"https://{host}"


def _one_origin(origins, origin, path):
    """Every URL of a mesh document has the first one's origin (spec-0.5.0)."""
    if origins and origin != origins[0]:
        fail("E_MESH_DOC", f"every URL of the document has one origin, {origins[0]}", path)
    origins.append(origin)


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
    # The key document's side is compared only for a member that is a string in an object; any
    # other shape is the key document's own failure, at step 5 (E_KEY_DOC).
    key_side = keydoc if isinstance(keydoc, dict) else {}
    if isinstance(key_side.get("host"), str) and key_side["host"] != host:
        fail("E_MESH_DOC", "the key document names another host", "$.host")
    if mesh.get("host") != host:
        fail("E_MESH_DOC", "the mesh document names another host", "$.host")
    if mesh.get("proto") != PROTO:
        fail("E_MESH_DOC", "the mesh document's proto is not datumesh/1", "$.proto")
    if isinstance(key_side.get("proto"), str) and key_side["proto"] != PROTO:
        fail("E_MESH_DOC", "the key document and the mesh document disagree on proto", "$.proto")
    parse_key_doc(key_text, host)  # 5. the key document's own rules (9.2): E_KEY_DOC
    # 6. the mesh document's members; unknown members are ignored
    origins = []
    _one_origin(origins, _mesh_url(mesh.get("bindings"), host, "$.bindings"), "$.bindings")
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
        _one_origin(origins, _mesh_url(value, host, f"$.endpoints.{name}"), f"$.endpoints.{name}")
        # Every { and } belongs to one of the endpoint's placeholders, each once (spec-0.4.1).
        rest = value
        for placeholder in MESH_ENDPOINTS[name]:
            if rest.count("{" + placeholder + "}") != 1:
                fail("E_MESH_DOC", f"{name} has {{{placeholder}}} exactly once", f"$.endpoints.{name}")
            rest = rest.replace("{" + placeholder + "}", "")
        if "{" in rest or "}" in rest:
            fail("E_MESH_DOC", f"{name} has no braces but its placeholders {MESH_ENDPOINTS[name]}", f"$.endpoints.{name}")
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
        if "withdrawn" in r or r["type"] != "blob":
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
    if "withdrawn" not in r and r["type"] != returns_type(desc):
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
    if input_tx and r["tx"] < max(input_tx):  # since spec-0.7.0 (D125): at or after, a withdrawal may raise it
        fail("E_TIME_ORDER", "a computed cell's tx is earlier than the latest tx of its inputs", "$.tx")
    if "withdrawn" in r:  # spec-0.7.0: a withdrawal states no value to compare
        return True
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
    "ok": (("outcome", "receipt", "trust"), ("fn_hash", "reason", "resolved", "shadows", "superseded_by")),
    "stale": (("age_seconds", "outcome", "receipt", "trust"), ("fn_hash", "reason", "resolved", "shadows",
                                                               "superseded_by")),
    "not_covered": (("outcome",), ("error", "fault", "fn_hash", "reason", "receipt", "resolved", "shadows", "trust")),
    "unlicensed": (("outcome",), ("fn_hash", "resolved", "shadows")),
    "payment_required": (("outcome", "quote"), ("fn_hash", "resolved", "shadows")),
    "rate_limited": (("outcome", "retry_after_seconds"), ("fn_hash",)),
    # detail: E_FOREIGN_UNAVAILABLE's (spec-0.4.3); resolved and shadows (spec-0.5.0, 16.7, 16.9)
    # cycle (spec-0.6.0, 5.5): the path of a cycle, with the fixes it admits, on E_EVAL_UNAVAILABLE only
    "error": (("error", "outcome"), ("cycle", "detail", "fn_hash", "resolved", "shadows")),
    "bad_request": (("error", "outcome"), ("fn_hash",)),
    "pending": (("estimate_seconds", "job", "outcome", "poll", "request"), ()),
    # spec-0.6.0 (5.9): the answer of a whatif request, a scenario: never signed, stored or served as a fact
    "scenario": (("outcome", "scenario"), ("fn_hash", "resolved")),
}
# spec-0.4.2: an ok envelope at the slice endpoint (5.6) carries a page of member envelopes.
SLICE_OK_MEMBERS = (("members", "outcome", "slice"), ("fn_hash", "next"))
ENVELOPE_STATUS = {
    "ok": range(200, 201), "stale": range(200, 201), "not_covered": range(404, 405),
    "unlicensed": range(403, 404), "payment_required": range(402, 403),
    "rate_limited": range(429, 430), "error": range(500, 600), "bad_request": range(400, 401),
    "pending": range(202, 203), "scenario": range(200, 201),  # scenario: spec-0.6.0
}
# The codes parse(uri, signature) can raise (SPEC 5.4): what a bad_request may report.
URI_CODES = (
    "E_PARSE_URI", "E_CANON_NAME", "E_CANON_ARG_NAME", "E_CANON_ARG_DUPLICATE", "E_CANON_ARG_ORDER",
    "E_CANON_PERCENT", "E_CANON_TYPE", "E_CANON_NUMBER", "E_CANON_DATE", "E_CANON_INSTANT",
    "E_CANON_STRING", "E_CANON_BLOB", "E_CANON_LIMIT", "E_ARG_UNKNOWN", "E_ARG_MISSING",
    "E_CANON_HEX",  # spec-0.4.2: a fn_hash= that is not 64 lowercase hex digits
)
# spec-0.6.0 (5.9): the faults a whatif answer may carry beyond the formula faults (E_WHATIF_NO_SOLUTION, with solve)
WHATIF_FAULT = "E_WHATIF_NO_SOLUTION"
# Codes a mesh reports about a request, never as an error (spec-0.4.1, spec-0.4.2).
RESOLUTION_KINDS = ("alias", "chain", "default", "lookup", "method")  # spec-0.5.0 (16.7); lookup (Q10 a) carries asof;
# chain (K10, since the classes round) carries asof too
# spec-0.4.3: what an E_FOREIGN_UNAVAILABLE envelope's detail says failed (5.5).
FOREIGN_DETAILS = ("offline", "network", "dns", "tls", "timeout", "refused")
# spec-0.5.0: E_SHORT_ID_AMBIGUOUS (16.8), and a call's key codes (5.8, 16.4, 16.5): bad_request, never error.
REQUEST_CODES = ("E_JOB_UNKNOWN", "E_SLICE_AT_CELL", "E_NAME_UNBOUND", "E_SHORT_ID_AMBIGUOUS", "E_KEY_NORMALISATION",
                 "E_KEY_ENCODING", "E_WHATIF_UNSUPPORTED", "E_WHATIF_NO_SOLUTION")  # spec-0.6.0: whatif's codes (5.5)
_INTEGER = re.compile(r"0|[1-9][0-9]*")
TRUST = ("primary", "verified", "unverified", "computed", "relayed")  # computed since spec-0.4.2, relayed spec-0.6.0
_JOB = re.compile(r"[0-9a-f]{32,64}")


def _is_instant(text):
    try:
        check_instant(text, "$")
        return True
    except DatumeshError:
        return False
# The faults a not_covered envelope may carry (SPEC 5.5, 15.11): a computed cell with no value.
FORMULA_FAULTS = ("E_FORMULA_DIV_ZERO", "E_FORMULA_DOMAIN", "E_FORMULA_RANGE", "E_FORMULA_EMPTY",
                  "E_FORMULA_ABSENT", "E_FORMULA_FUTURE",
                  "E_FORMULA_KEY", "E_FORMULA_DISPATCH_KEY")  # spec-0.5.0: Q6 b, answer 5


def _seconds(value):
    """An integer member: written 0|[1-9][0-9]*, at most 2^53 - 1."""
    return (isinstance(value, JsonInteger) and _INTEGER.fullmatch(value.text) is not None
            and int(value.text) <= MAX_SAFE_INTEGER)


def _mesh_url_host(value, path, what):
    """An https URL (at most 512 characters) whose host is a DNS name: https://<DNS name>/... ; returns
    the host. Since spec-0.5.0 also a loopback http URL, returned as ("loopback", origin): whether the
    request allows one (an unrooted mesh asked) is _check_own_url's."""
    if loopback_origin(value):
        return ("loopback", loopback_origin(value))
    if not isinstance(value, str) or not _URL.fullmatch(value) or len(value) > LIMITS["licence_url"]:
        fail("E_ENVELOPE", f"{what} is an https URL", path)
    host = value[len("https://"):].split("/", 1)[0]
    if "/" not in value[len("https://"):]:
        fail("E_ENVELOPE", f"{what} has a path", path)
    try:
        check_dns_name(host, path)
    except DatumeshError:
        fail("E_ENVELOPE", f"{what} names a DNS name as its host, with no port or userinfo", path)
    return host


# spec-0.6.0 (C6, 5.5): the fixes a cycle admits, in the order 5.5 lists them.
CYCLE_FIXES = ("asof", "lag", "step", "solver")


@_as_error("E_ENVELOPE")
def _check_cycle(env):
    """An error envelope's cycle (5.5, spec-0.6.0): exactly path and fixes, on E_EVAL_UNAVAILABLE only. The path
    is at least two calls, its first and last equal; the fixes are distinct and in the order of CYCLE_FIXES."""
    if env["outcome"] != "error" or env.get("error") != "E_EVAL_UNAVAILABLE":
        fail("E_ENVELOPE", "cycle is carried by an error envelope with E_EVAL_UNAVAILABLE", "$.cycle")
    cycle = env["cycle"]
    _shape_object(cycle, ("fixes", "path"), (), "$.cycle")
    path = cycle["path"]
    if not isinstance(path, list) or len(path) < 2 or not all(isinstance(c, str) and c for c in path) \
            or path[0] != path[-1]:
        fail("E_ENVELOPE", "cycle.path is at least two calls, and its first and last are equal", "$.cycle.path")
    fixes = cycle["fixes"]
    if not isinstance(fixes, list) or not fixes or not all(isinstance(f, str) and f in CYCLE_FIXES for f in fixes):
        fail("E_ENVELOPE", "cycle.fixes is a non-empty array of asof, lag, step and solver", "$.cycle.fixes")
    places = [CYCLE_FIXES.index(f) for f in fixes]
    if any(a >= b for a, b in zip(places, places[1:])):
        fail("E_ENVELOPE", "cycle.fixes are distinct and in the order asof, lag, step, solver", "$.cycle.fixes")


@_as_error("E_ENVELOPE")
def _check_envelope_members(env, members=None):
    if not isinstance(env, dict) or not isinstance(env.get("outcome"), str):
        fail("E_ENVELOPE", "an envelope is an object with a string outcome")
    if env["outcome"] not in ENVELOPE_MEMBERS:
        fail("E_ENVELOPE", f"unknown outcome {env['outcome']!r}", "$.outcome")
    required, optional = members or ENVELOPE_MEMBERS[env["outcome"]]
    _shape_object(env, required, optional, "$")
    if "age_seconds" in env and not _seconds(env["age_seconds"]):
        fail("E_ENVELOPE", "age_seconds is a non-negative integer", "$.age_seconds")
    if "error" in env:
        # bad_request: a URI code, E_SLICE_AT_CELL (spec-0.4.2), or E_JOB_UNKNOWN for a job URL
        # (spec-0.4.1); not_covered: E_NAME_UNBOUND (spec-0.4.2) or E_NAMESPACE_SUSPENDED (spec-0.5.0, a
        # refused cross-mesh import); error: any code of 10.2 but
        # the client's E_ENVELOPE and the request codes.
        if env["outcome"] == "bad_request":
            allowed = URI_CODES + ("E_JOB_UNKNOWN", "E_SLICE_AT_CELL", "E_SHORT_ID_AMBIGUOUS", "E_KEY_NORMALISATION",
                                  "E_KEY_ENCODING", "E_WHATIF_UNSUPPORTED", "E_SLICE_MEMBER")  # spec-0.6.0 (5.5, 5.9)
        elif env["outcome"] == "not_covered":
            allowed = ("E_NAME_UNBOUND", "E_NAMESPACE_SUSPENDED")  # the latter since spec-0.5.0 (9.9)
        else:
            allowed = tuple(c for c in ERROR_CODES if c not in ("E_ENVELOPE", "E_DESCRIBE")
                            and c not in REQUEST_CODES and c not in DEFINE_WRITE_CODES)
        if env["error"] not in allowed:
            fail("E_ENVELOPE", f"{env['error']!r} is not a code this outcome can carry", "$.error")
        if "fault" in env:
            fail("E_ENVELOPE", "not_covered carries fault or error, not both", "$.error")
    if "cycle" in env:  # spec-0.6.0 (C6)
        _check_cycle(env)
    if "resolved" in env:  # spec-0.5.0 (16.7): what a short call resolved
        r = env["resolved"]
        if not isinstance(r, dict) or set(r) - {"aliases_tx", "call", "resolutions"} or "call" not in r \
                or "resolutions" not in r or not isinstance(r["call"], str) or not r["call"] \
                or not isinstance(r["resolutions"], list):
            fail("E_ENVELOPE", "resolved is {call, resolutions, aliases_tx?}", "$.resolved")
        for x in r["resolutions"]:
            # a lookup resolution also has asof, the instant its lookup cell was read as of (Q10 a)
            timed = isinstance(x, dict) and x.get("kind") in ("lookup", "chain")
            members = {"from", "kind", "to"} | ({"asof"} if timed else set())
            if not isinstance(x, dict) or set(x) != members \
                    or not all(isinstance(x[k], str) for k in x) or x["kind"] not in RESOLUTION_KINDS \
                    or ("asof" in x and not _is_instant(x["asof"])):
                fail("E_ENVELOPE", "a resolution is {from, kind, to}, kind alias, chain, default, lookup or method; a "
                     "lookup's and a chain's also have asof, an instant", "$.resolved.resolutions")
        if "aliases_tx" in r and (not isinstance(r["aliases_tx"], str) or not _is_instant(r["aliases_tx"])):
            fail("E_ENVELOPE", "aliases_tx is an instant", "$.resolved.aliases_tx")
    if "shadows" in env:  # spec-0.5.0 (16.9)
        sh = env["shadows"]
        if not isinstance(sh, dict) or set(sh) != {"class", "reference"} or not isinstance(sh["class"], str) \
                or not isinstance(sh["reference"], str) or not re.fullmatch(r"[0-9a-f]{64}", sh["reference"]):
            fail("E_ENVELOPE", "shadows is {class, reference}", "$.shadows")
        check_function_name(sh["class"], "$.shadows.class")
    # spec-0.4.3: E_FOREIGN_UNAVAILABLE carries detail, which no other envelope has.
    if (env.get("error") == "E_FOREIGN_UNAVAILABLE") != ("detail" in env):
        fail("E_ENVELOPE", "detail is present exactly with E_FOREIGN_UNAVAILABLE", "$.detail")
    if "detail" in env and env["detail"] not in FOREIGN_DETAILS:
        fail("E_ENVELOPE", f"detail is one of {', '.join(FOREIGN_DETAILS)}", "$.detail")
    if "fn_hash" in env:
        if not isinstance(env["fn_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", env["fn_hash"]):
            fail("E_ENVELOPE", "fn_hash is 64 lowercase hex digits", "$.fn_hash")
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
        # spec-0.7.0: a not_covered reason is a withdrawal's (with its receipt) or the label case's (none)
        if "superseded_by" not in env and env["outcome"] != "not_covered":
            fail("E_ENVELOPE", "reason is given only with superseded_by", "$.reason")
    if env["outcome"] == "not_covered":  # spec-0.7.0 (R1): the withdrawal's answer, or none
        if "receipt" in env:
            if "reason" not in env or "trust" not in env or "error" in env or "fault" in env:
                fail("E_ENVELOPE", "a withdrawal in not_covered carries reason and trust, and no error or fault",
                     "$.receipt")
            if not isinstance(env["receipt"], dict) or "withdrawn" not in env["receipt"]:
                fail("E_ENVELOPE", "not_covered carries a withdrawal receipt, or none", "$.receipt")
        elif "trust" in env:
            fail("E_ENVELOPE", "trust is given with a receipt only", "$.trust")
    elif "trust" in env and env["outcome"] not in ("ok", "stale"):
        fail("E_ENVELOPE", "trust is given with a receipt only", "$.trust")
    if "receipt" in env and not isinstance(env["receipt"], dict):
        fail("E_ENVELOPE", "receipt is a receipt object", "$.receipt")
    if "estimate_seconds" in env and not _seconds(env["estimate_seconds"]):
        fail("E_ENVELOPE", "estimate_seconds is a non-negative integer", "$.estimate_seconds")
    if "job" in env:
        if not isinstance(env["job"], str) or not _JOB.fullmatch(env["job"]):
            fail("E_ENVELOPE", "job is 32 to 64 lowercase hex digits", "$.job")
    if "poll" in env:
        poll = env["poll"]
        if not isinstance(poll, str) or not (_URL.fullmatch(poll) or loopback_origin(poll)) \
                or len(poll) > LIMITS["licence_url"] or not poll.endswith("/jobs/" + str(env.get("job"))):
            fail("E_ENVELOPE", "poll is the https URL of the job: .../jobs/<job>", "$.poll")
        # spec-0.4.1 (DEF-51): https://, a DNS name (2.1), then the path. Whether it is the host
        # asked is checked against the request's mesh, when the caller gives it (spec-0.4.2).
        _mesh_url_host(poll, "$.poll", "poll")
    if "request" in env:
        req = env["request"]
        if not isinstance(req, dict) or "cell_id" not in req or set(req) - {"asof", "cell_id", "fn_hash"}:
            fail("E_ENVELOPE", "request is {cell_id, asof?, fn_hash?}", "$.request")
        if not isinstance(req["cell_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", req["cell_id"]):
            fail("E_ENVELOPE", "request.cell_id is a cell id", "$.request.cell_id")
        if "asof" in req and (not isinstance(req["asof"], str) or not _is_instant(req["asof"])):
            fail("E_ENVELOPE", "request.asof is an instant", "$.request.asof")
        if "fn_hash" in req and (not isinstance(req["fn_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", req["fn_hash"])):
            fail("E_ENVELOPE", "request.fn_hash is a function hash", "$.request.fn_hash")
    if "retry_after_seconds" in env and not _seconds(env["retry_after_seconds"]):
        fail("E_ENVELOPE", "retry_after_seconds is a non-negative integer", "$.retry_after_seconds")
    if "superseded_by" in env:
        _shape_str(env, "superseded_by", "$")
        check_hex(env["superseded_by"], 64, "$.superseded_by")
    if "fault" in env and env["fault"] not in FORMULA_FAULTS + (WHATIF_FAULT,):
        fail("E_ENVELOPE", "fault is a formula evaluation fault code (SPEC 15.11) or E_WHATIF_NO_SOLUTION", "$.fault")
    if "trust" in env and env["trust"] not in TRUST:
        fail("E_ENVELOPE", f"trust is one of {', '.join(TRUST)}", "$.trust")
    if "next" in env:
        _mesh_url_host(env["next"], "$.next", "next")
    if "members" in env and not isinstance(env["members"], list):
        fail("E_ENVELOPE", "members is an array of envelopes", "$.members")
    if "slice" in env and not isinstance(env["slice"], dict):
        fail("E_ENVELOPE", "slice is a slice object", "$.slice")


def _host(key_ref):
    return key_ref.split("#")[0]


def _check_receipt_answer(env, keyenv, request, cell_ok, path="$"):
    """Steps 4-6 for an envelope with a receipt: verify it, bind it, check trust."""
    r = env["receipt"]
    receipt_hash = verify_receipt(jcs(r), keyenv)["hash"]
    if not cell_ok(r):
        fail("E_ENVELOPE", "the receipt is for another cell than the one requested", f"{path}.receipt.cell")
    if ("withdrawn" in r) != (env["outcome"] == "not_covered"):  # spec-0.7.0: ok and stale state a value
        fail("E_ENVELOPE", "a withdrawal answers not_covered, and not_covered carries only a withdrawal",
             f"{path}.receipt")
    if "withdrawn" in r and env["reason"] != r["withdrawn"]:
        fail("E_ENVELOPE", "reason is the withdrawal's reason", f"{path}.reason")
    # ok and stale alike: a receipt answers every asof from its own up to the cell's next
    # version, so its asof is at or before the one requested (D31). What ok adds, that the
    # receipt is the latest version known as of the requested asof, is the mesh's claim.
    if "asof" in request and not r["asof"] <= request["asof"]:
        fail("E_ENVELOPE", "the receipt's asof is after the one requested", f"{path}.receipt.asof")
    # spec-0.6.0 (C2): primary is a stored answer with no source; relayed is the same signed by the
    # publisher's host with a source (a value taken from another party).
    publisher_signed = _host(r["computed_by"]) == r["cell"]["ns"].split("/")[0] and not r["inputs"]
    primary = publisher_signed and "source" not in r
    relayed = publisher_signed and "source" in r
    if primary != (env["trust"] == "primary"):
        fail("E_ENVELOPE", "trust is primary exactly when the publisher's host signed a stored answer with no source",
             f"{path}.trust")
    if relayed != (env["trust"] == "relayed"):
        fail("E_ENVELOPE", "trust is relayed exactly when the publisher's host signed a stored answer with a source",
             f"{path}.trust")
    # spec-0.4.2: computed is this mesh's own evaluation, signed by it; verified and unverified are
    # receipts another host signed. The envelope check can tell them apart only when the caller
    # names the mesh it asked. A relayed receipt is never computed, even when the mesh asked signed it.
    if not primary and not relayed and "mesh" in request:
        own = _host(r["computed_by"]) == request["mesh"]
        if own != (env["trust"] == "computed"):
            fail("E_ENVELOPE", "trust is computed exactly when the mesh asked signed the receipt", f"{path}.trust")
    if "fn_hash" in env and env["fn_hash"] != r["cell"]["fn_hash"]:
        fail("E_ENVELOPE", "fn_hash echoes another function than the receipt's", f"{path}.fn_hash")
    if env.get("superseded_by") == receipt_hash:
        fail("E_ENVELOPE", "a receipt cannot supersede itself", f"{path}.superseded_by")
    return {"outcome": env["outcome"], "receipt_hash": receipt_hash, "trust": env["trust"]}


def _check_pin_echo(env, request):
    """spec-0.4.2: an envelope answering a request pinned to a function hash echoes it."""
    pin = request.get("fn_hash")
    if "fn_hash" in env and pin is not None and env["fn_hash"] != pin:
        fail("E_ENVELOPE", "fn_hash echoes another function than the one pinned", "$.fn_hash")
    if pin is not None and "fn_hash" not in env and env["outcome"] not in ("rate_limited", "bad_request", "pending"):
        fail("E_ENVELOPE", "an envelope answering a pinned request echoes its fn_hash", "$.fn_hash")


def _key_tuple(slice_obj, cell_args, path):
    """The key of a slice member (15.13): its open and ranged arguments, ascending by name, each as
    (type, its place in the type's order). Other names (in a cursor) are ignored."""
    names = [n for n in keys_in_order(slice_obj["args"]) if not _is_scalar_arg(slice_obj["args"][n])]
    try:
        return tuple((cell_args[n]["type"], type_key(cell_args[n]["type"], cell_args[n]["value"])) for n in names)
    except (KeyError, TypeError, DatumeshError):
        fail("E_ENVELOPE", "a key is the slice's open arguments, as typed scalars", path)


def _key_after(key, previous, path):
    """Whether key comes after previous; keys of other types cannot be ordered (E_ENVELOPE)."""
    if [t for t, _ in key] != [t for t, _ in previous]:
        fail("E_ENVELOPE", "a key of another type than the cursor's or the previous member's", path)
    return tuple(k for _, k in key) > tuple(k for _, k in previous)


def _is_scalar_arg(value):
    return isinstance(value, dict) and "value" in value


_HEX64 = re.compile(r"[0-9a-f]{64}")


def check_request(request):
    """A request description (5.5, 5.6) is the caller's input: a malformed one is the caller's error,
    a ValueError, never an E_* code (spec-0.4.2)."""
    def bad(what):
        raise ValueError(f"malformed request description: {what} (SPEC 5.5)")

    if not isinstance(request, dict):
        bad("not an object")
    page = "slice_id" in request
    allowed = {"slice_id", "asof", "fn_hash", "mesh", "after"} if page else {
        "cell_id", "asof", "job", "fn_hash", "mesh", "overrides", "solve"}  # overrides, solve: spec-0.6.0 (5.9)
    if set(request) - allowed:
        bad(f"unknown members {sorted(set(request) - allowed)}")
    key = "slice_id" if page else "cell_id"
    for name in (key, "fn_hash"):
        if (name == key or name in request) and not (isinstance(request.get(name), str) and _HEX64.fullmatch(request[name])):
            bad(f"{name} is 64 lowercase hex digits")
    if "asof" in request and not (isinstance(request["asof"], str) and _is_instant(request["asof"])):
        bad("asof is an instant")
    if "job" in request and not (isinstance(request["job"], str) and _JOB.fullmatch(request["job"])):
        bad("job is 32 to 64 lowercase hex digits")
    if "mesh" in request:
        try:
            if not isinstance(request["mesh"], str):
                raise DatumeshError("E_CANON_NAME", "not a string")
            check_dns_name(request["mesh"], "request.mesh")
        except DatumeshError:
            bad("mesh is a DNS name")
    if "overrides" in request:  # spec-0.6.0 (5.9): the canonical override array of a whatif request
        overrides = request["overrides"]
        if not isinstance(overrides, list) or len(overrides) > 64:
            bad("overrides is an array of at most 64 overrides")
        if not overrides and "solve" not in request:
            bad("overrides is empty only when solve is given")
        ids = []
        for o in overrides:
            try:
                ids.append(_check_override(o))
            except DatumeshError as e:
                bad(f"an override is malformed ({e.code})")
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            bad("overrides are sorted by cell or slice id, each cell or slice once")
    if "solve" in request:
        if "overrides" not in request:
            bad("solve is given with overrides")
        if not (isinstance(request["solve"], str) and _HEX64.fullmatch(request["solve"])):
            bad("solve is the vary cell's id, 64 lowercase hex digits")
    if "after" in request:
        if not isinstance(request["after"], dict):
            bad("a cursor is an object")
        for name, value in request["after"].items():
            try:
                shape_scalar(value, f"request.after.{name}")
                check_scalar(value, f"request.after.{name}")
            except DatumeshError:
                bad(f"the cursor's {name} is not a typed scalar")


def cell_id(cell):
    """A cell's id (4.4): the hash of its canonical bytes."""
    return sha256_hex(jcs(cell))


def _check_override(o):
    """One override of a whatif request (5.9), checked as a value: a value override {cell, value} or a slice
    override {slice, add, remove}, with add and remove sorted by cell id. Returns the override's id: its cell's
    or its slice's. Raises DatumeshError."""
    if isinstance(o, dict) and set(o) == {"cell", "value"}:
        shape_cell(o["cell"], "$.cell")
        check_cell(o["cell"], "$.cell")
        shape_scalar(o["value"], "$.value")
        check_scalar(o["value"], "$.value")
        return cell_id(o["cell"])
    if isinstance(o, dict) and set(o) == {"members", "slice"}:  # spec-0.7.0 (R3, 5.9): the whole member set
        shape_slice(o["slice"], "$.slice")
        check_slice(o["slice"], "$.slice")
        if not isinstance(o["members"], list):
            fail("E_SCHEMA", "members is an array", "$.members")
        for member in o["members"]:
            _shape_object(member, ("cell", "value"), (), "$.members")
            shape_cell(member["cell"], "$.members.cell")
            check_cell(member["cell"], "$.members.cell")
            shape_scalar(member["value"], "$.members.value")
            check_scalar(member["value"], "$.members.value")
        ids = [cell_id(m["cell"]) for m in o["members"]]
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            fail("E_SCHEMA", "members is sorted by cell id, each cell once", "$.members")
        return slice_id(o["slice"])
    if isinstance(o, dict) and set(o) == {"add", "remove", "slice"}:
        shape_slice(o["slice"], "$.slice")
        check_slice(o["slice"], "$.slice")
        for name in ("add", "remove"):
            if not isinstance(o[name], list):
                fail("E_SCHEMA", f"{name} is an array", f"$.{name}")
        for member in o["add"]:
            _shape_object(member, ("cell", "value"), (), "$.add")
            shape_cell(member["cell"], "$.add.cell")
            check_cell(member["cell"], "$.add.cell")
            shape_scalar(member["value"], "$.add.value")
            check_scalar(member["value"], "$.add.value")
        for cell in o["remove"]:
            shape_cell(cell, "$.remove")
            check_cell(cell, "$.remove")
        for name, cells in (("add", [m["cell"] for m in o["add"]]), ("remove", o["remove"])):
            ids = [cell_id(c) for c in cells]
            if ids != sorted(ids) or len(set(ids)) != len(ids):
                fail("E_SCHEMA", f"{name} is sorted by cell id, each cell once", f"$.{name}")
        return slice_id(o["slice"])
    fail("E_SCHEMA", "an override is a value override {cell, value} or a slice override {slice, add, remove}")


def _check_own_url(value, request, path, what):
    """poll and next against the request (5.5 step 3a, 5.6): on the host asked when it is known; a
    loopback http URL only when the request names an unrooted mesh (spec-0.5.0)."""
    host = _mesh_url_host(value, path, what)
    if isinstance(host, tuple):
        if not ("mesh" in request and is_unrooted(request["mesh"])):
            fail("E_ENVELOPE", f"a loopback {what} answers only a request to an unrooted mesh", path)
    elif "mesh" in request and host != request["mesh"]:
        fail("E_ENVELOPE", f"{what} names another host than the mesh asked", path)


def _check_status(env, status):
    """5.5 step 3: the status matches the outcome; E_FOREIGN_UNAVAILABLE is 502 (spec-0.4.3)."""
    if status not in ENVELOPE_STATUS[env["outcome"]]:
        fail("E_ENVELOPE", f"status {status} does not match outcome {env['outcome']}", "$.outcome")
    if env.get("error") == "E_FOREIGN_UNAVAILABLE" and status != 502:
        fail("E_ENVELOPE", "E_FOREIGN_UNAVAILABLE is answered with 502", "$.outcome")


@_as_error("E_ENVELOPE")
def _check_scenario(env, request):
    """A scenario (5.9, spec-0.6.0): the answer to a whatif request, checked against it at step 5: its cell, its asof,
    its overrides byte for byte after canonical JSON, and solved exactly when the request had solve."""
    s = env["scenario"]
    _shape_object(s, ("asof", "cell", "overrides", "type", "value"), ("solved",), "$.scenario")
    shape_cell(s["cell"], "$.scenario.cell")
    check_cell(s["cell"], "$.scenario.cell")
    check_instant(s["asof"], "$.scenario.asof")
    _shape_str(s, "type", "$.scenario")
    check_type_name(s["type"], "$.scenario.type")
    if not isinstance(s["value"], (str, bool)):
        fail("E_ENVELOPE", "value is a string or a boolean", "$.scenario.value")
    check_lexical(s["type"], s["value"], "$.scenario.value")
    if cell_id(s["cell"]) != request["cell_id"]:
        fail("E_ENVELOPE", "scenario.cell is not the cell requested", "$.scenario.cell")
    if "asof" in request and s["asof"] != request["asof"]:
        fail("E_ENVELOPE", "scenario.asof is not the asof requested", "$.scenario.asof")
    if jcs(s["overrides"]) != jcs(request["overrides"]):
        fail("E_ENVELOPE", "scenario.overrides are not the request's overrides", "$.scenario.overrides")
    if ("solved" in s) != ("solve" in request):
        fail("E_ENVELOPE", "solved is present exactly when the request had solve", "$.scenario.solved")
    if "solved" in s:
        _shape_object(s["solved"], ("value", "vary"), (), "$.scenario.solved")
        shape_scalar(s["solved"]["value"], "$.scenario.solved.value")
        check_scalar(s["solved"]["value"], "$.scenario.solved.value")
        if s["solved"]["value"]["type"] != "number":
            fail("E_ENVELOPE", "solved.value is a number", "$.scenario.solved.value")
        shape_cell(s["solved"]["vary"], "$.scenario.solved.vary")
        check_cell(s["solved"]["vary"], "$.scenario.solved.vary")
        if cell_id(s["solved"]["vary"]) != request["solve"]:
            fail("E_ENVELOPE", "solved.vary is not the cell the request asked to vary", "$.scenario.solved.vary")
    return {"outcome": "scenario"}


def check_envelope_object(status, env, keyenv, request, _request_checked=False):
    """check_envelope on a parsed envelope (the items of a batch, 5.7, use it)."""
    if not _request_checked:
        check_request(request)
    if "slice_id" in request:
        return _check_slice_envelope(status, env, keyenv, request)
    _check_envelope_members(env)
    _check_status(env, status)
    result = {"outcome": env["outcome"]}
    if env.get("error") == "E_JOB_UNKNOWN" and "job" not in request:
        fail("E_ENVELOPE", "E_JOB_UNKNOWN answers a job URL only", "$.error")
    # spec-0.6.0 (5.9): a request with overrides is answered by a scenario or by a refusal, never by a fact
    whatif = "overrides" in request
    if whatif and env["outcome"] in ("ok", "stale", "pending"):
        fail("E_ENVELOPE", f"{env['outcome']} is not an answer to a whatif request", "$.outcome")
    if env["outcome"] == "scenario":
        if not whatif:
            fail("E_ENVELOPE", "a scenario answers a whatif request, with overrides", "$.outcome")
        _check_pin_echo(env, request)
        return _check_scenario(env, request)
    if env.get("fault") == WHATIF_FAULT and "solve" not in request:
        fail("E_ENVELOPE", "E_WHATIF_NO_SOLUTION answers a solve", "$.fault")
    # spec-0.6.0 (5.5): the whatif codes of a bad_request answer a whatif request, and only that one
    if env["outcome"] == "bad_request" and env.get("error") == "E_WHATIF_UNSUPPORTED" and "solve" not in request:
        fail("E_ENVELOPE", "E_WHATIF_UNSUPPORTED answers a solve", "$.error")
    _check_pin_echo(env, request)
    if env["outcome"] == "pending":
        # Step 5 for pending (spec-0.4.1): the echoed request is the one made, and a pending
        # envelope fetched from a job URL is that job's.
        echoed = env["request"]
        if echoed["cell_id"] != request["cell_id"] or echoed.get("asof") != request.get("asof") \
                or echoed.get("fn_hash") != request.get("fn_hash"):
            fail("E_ENVELOPE", "the pending envelope echoes another request", "$.request")
        if "job" in request and env["job"] != request["job"]:
            fail("E_ENVELOPE", "the pending envelope is for another job than the one polled", "$.job")
        _check_own_url(env["poll"], request, "$.poll", "poll")
    if "receipt" in env:
        result = _check_receipt_answer(
            env, keyenv, request, lambda r: sha256_hex(jcs(r["cell"])) == request["cell_id"])
    return result


@_as_error("E_ENVELOPE")
def _slice_members_shape(env):
    _check_envelope_members(env, SLICE_OK_MEMBERS)


def _check_slice_envelope(status, env, keyenv, request):
    """A response of the slice endpoint (5.6, spec-0.4.2), against the request
    {"slice_id", "asof"?, "fn_hash"?, "mesh"?, "after"?}."""
    if isinstance(env, dict) and env.get("outcome") == "ok":
        _slice_members_shape(env)
    else:
        _check_envelope_members(env)
        if env["outcome"] in ("ok", "stale", "pending"):
            fail("E_ENVELOPE", f"{env['outcome']} is not an answer of the slice endpoint", "$.outcome")
    _check_status(env, status)
    if env.get("error") == "E_JOB_UNKNOWN":
        fail("E_ENVELOPE", "E_JOB_UNKNOWN answers a job URL only", "$.error")
    _check_pin_echo(env, request)
    if env["outcome"] != "ok":
        return {"outcome": env["outcome"]}
    s = env["slice"]
    if sha256_hex(jcs(s)) != request["slice_id"] or "args" not in s:
        fail("E_ENVELOPE", "the page is of another slice than the one requested", "$.slice")
    if "fn_hash" in env and env["fn_hash"] != s.get("fn_hash"):
        fail("E_ENVELOPE", "fn_hash echoes another function than the slice's", "$.fn_hash")
    if "next" in env:
        _check_own_url(env["next"], request, "$.next", "next")
    previous = _key_tuple(s, request["after"], "request.after") if "after" in request else None
    results = []
    for i, member in enumerate(env["members"]):
        path = f"$.members[{i}]"
        _check_member_shape(member, path)
        got = _check_receipt_answer(member, keyenv, request, lambda r: is_slice_member(s, r), path)
        key = _key_tuple(s, member["receipt"]["cell"]["args"], path)
        if previous is not None and not _key_after(key, previous, path):
            fail("E_ENVELOPE", "members are in strictly ascending key order, after the cursor", path)
        previous = key
        results.append(got)
    return {"outcome": "ok", "results": results}


@_as_error("E_ENVELOPE")
def _check_member_shape(member, path):
    if not isinstance(member, dict) or member.get("outcome") not in ("ok", "stale"):
        fail("E_ENVELOPE", "a slice member is an ok or stale envelope", path)
    _check_envelope_members(member)


def check_envelope(status, body, keyenv, request):
    """Check a mesh response (SPEC.md 5.5): HTTP status and JSON body, against the request:
    {"cell_id": <cell id asked for>, "asof": <instant, if the request carried one>}, and "job": <job id>
    when the response is to GET /jobs/<job> (spec-0.4.1): the job's envelope is bound to the original
    request, never to the job URL. Since spec-0.4.2 also "fn_hash" (the request's pin) and "mesh"
    (the host asked); and for the slice endpoint (5.6) {"slice_id", "asof"?, "fn_hash"?, "mesh"?,
    "after"?} in place of cell_id and job."""
    env = parse_json(body, keep_integer_text=True)
    return check_envelope_object(status, env, keyenv, request)


# Whole-batch answers (5.7): the batch as a whole was refused.
BATCH_REFUSALS = ("unlicensed", "payment_required", "rate_limited", "bad_request", "error")


def check_batch(status, body, keyenv, requests):
    """A response of the batch endpoint (5.7, spec-0.4.2): 200 with a JSON array, one item per
    request in request order, each {"envelope", "status"}; or a refusal of the whole batch, one
    envelope with its own status. Each item is checked as check_envelope against its request; a
    failing item is reported in its place, and does not fail the others."""
    for request in requests:
        check_request(request)
    batch = parse_json(body, keep_integer_text=True)
    if status != 200:
        if not isinstance(batch, dict) or batch.get("outcome") not in BATCH_REFUSALS:
            fail("E_ENVELOPE", "a batch is refused whole only by a refusal outcome", "$.outcome")
        return {"outcome": check_envelope_object(status, batch, keyenv, {}, _request_checked=True)["outcome"]}
    if not isinstance(batch, list) or len(batch) != len(requests):
        fail("E_ENVELOPE", "a batch response is an array with one item per request", "$")
    for i, item in enumerate(batch):
        path = f"$[{i}]"
        if not isinstance(item, dict) or set(item) != {"envelope", "status"}:
            fail("E_ENVELOPE", "an item is {envelope, status}", path)
        st = item["status"]
        if not isinstance(st, JsonInteger) or not _INTEGER.fullmatch(st.text) or not 100 <= int(st.text) <= 599:
            fail("E_ENVELOPE", "an item's status is an HTTP status code, an integer", f"{path}.status")
    results = []
    for item, request in zip(batch, requests):
        try:
            got = check_envelope_object(int(item["status"].text), item["envelope"], keyenv, request)
            results.append({k: got[k] for k in ("outcome", "receipt_hash", "trust") if k in got})
        except DatumeshError as e:
            results.append({"error": e.code})
    return {"results": results}


# ---------------------------------------------------------------------------
# The call form (5.8, spec-0.4.2): a read of the formula dialect with literal arguments, as a
# request; it denotes the cell URI it is written as.

_CALL_LEXER_CODES = {"E_FORMULA_NUMBER": "E_CANON_NUMBER", "E_FORMULA_STRING": "E_CANON_STRING",
                     "E_FORMULA_DATE": "E_CANON_DATE", "E_FORMULA_INSTANT": "E_CANON_INSTANT"}


class CallFault(Exception):
    """A chained call's link holds a value that is not a key of the classes its method returns (K10, 16.6): the formula
    fault E_FORMULA_DISPATCH_KEY (15.12), which a request answers as not_covered with that fault. It is not one of the
    ERROR_CODES, so it has its own exception; the reference returns it as the call's error."""

    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


class NotCovered(Exception):
    """A link of a chained call (K10) whose cell has no value as of the call's asof: the mesh answers that cell's outcome,
    not_covered (5.5). A call vector cannot express it, so the reference raises it rather than give an error code."""


def parse_call(text, env):
    """A call (5.8) -> {"uri": its cell URI, "resolved": what the call resolved (5.5, 16.7)}.

    env: {"functions": {name: descriptor} (the names bound as of the request's asof), "aliases":
    {alias: name}, "descriptors": [descriptors the mesh has, for a pinned call]; since spec-0.5.0
    "classes": {class name: flattened class descriptor}, "aliases_tx": the instant of the alias
    snapshot, "now": the mesh's now, for a default or a lookup when the call has no asof, "lookups":
    {class name: {label: key encoding}}, the cells of each class's lookup method as of the call's
    asof (Q10 a; since the classes round, a folded label maps to "" when withdrawn, K8), "cells":
    {canonical call without asof: key encoding}, the cells of the methods that return a key, as of the
    call's asof (K10), "class_descriptors": [flattened class descriptors held by hash only, with no class name bound
    to them (K5): a parent an override is compared with, found by hash}.

    Since spec-0.5.0 (Q1) a request has no variables: every argument is read by the declared type of
    its position (_call_read), and an unquoted value is a single token of the dialect.

    Since the classes round: an inherited method reads the cell of the class that defines it (K5, 16.3); a
    chain N(k).m(a).n(b) calls each method on the key the one before returns (K10, 16.6); an argument may
    have a literal default (K13, 7); a label is folded (K8, 16.4)."""
    import formula
    if not isinstance(text, str):
        fail("E_PARSE_URI", "a call is text")
    q = _call_query_start(text)
    rest = text[q:]
    try:
        tokens = formula.tokenize(text[:q], request=True)  # spec-0.6.0: the request lexer (5.8, C3)
    except formula.FormulaError as e:
        fail(_CALL_LEXER_CODES.get(e.code, "E_PARSE_URI"), f"not a call: {e}")
    callee, args, methods, label = _call_tree(tokens)
    asof = None
    if rest:
        if not rest.startswith("?asof=") or "&" in rest:
            fail("E_PARSE_URI", "a call is a read, optionally followed by ?asof=<instant>")
        asof = rest[len("?asof="):]
    if asof is not None:
        check_instant(asof, "call.asof")
    resolutions = []
    fq = _call_name(callee, env, resolutions)
    functions = env.get("functions") or {}
    classes = env.get("classes") or {}
    pin = callee.pin
    if label is not None and (fq not in classes or pin is not None):
        fail("E_PARSE_URI", "a label [..] names an object of a class (16.7)")
    defaults = []
    if fq in classes and pin is None:  # spec-0.5.0: an object, then its method (16.3); K10: then its chain
        if not methods:
            fail("E_PARSE_URI", f"{fq} is a class: a call of it names a method")
        if label is not None:  # spec-0.5.0 (Q10 a): the object a label names, through the class's lookup
            keys = _call_lookup(fq, classes[fq], label, asof, env, resolutions)
        else:
            keys = _call_keys(fq, classes[fq], args, env)
        cname, cdesc, ckeys = fq, classes[fq], keys
        for mname, mtok, margs in methods[:-1]:
            mfq, descriptor, key_names = _call_method(cname, cdesc, mname, mtok, env)
            bound = {k: ("typed", ckeys[k]) for k in key_names}
            order = [n for n in descriptor["signature"].get("order", []) if n not in key_names]
            bound.update(_call_bind(mfq, descriptor, order, margs, set(key_names)))
            # K10: a link. Its cell is read as of the call's asof, and the key it holds is the next method's object.
            ref_args = _call_args(mfq, descriptor, bound, asof, env, defaults)
            ret = descriptor["signature"]["returns"]
            if not (isinstance(ret, dict) and "classes" in ret):
                fail("E_PARSE_URI", f"{mfq} returns no key, so no method can follow it in a chain (K10)")
            at = asof or env.get("now")
            if at is None:
                fail("E_ARG_MISSING", "a chained call is read as of the call's asof, or the mesh's now")
            written = _canonical_call(mfq, None, ref_args, None)
            cells = env.get("cells") or {}
            if written not in cells:
                raise NotCovered(f"{written} has no value as of {at}")
            value = cells[written]
            ckeys, cname = _chain_key(value, ret["classes"], classes, mfq)
            cdesc = classes[cname]
            resolutions.append({"asof": at, "from": mname, "kind": "chain", "to": value})
        # the last method: the cell the call reads
        mname, mtok, margs = methods[-1]
        mfq, descriptor, key_names = _call_method(cname, cdesc, mname, mtok, env)
        bound = {k: ("typed", ckeys[k]) for k in key_names}
        order = [n for n in descriptor["signature"].get("order", []) if n not in key_names]
        bound.update(_call_bind(mfq, descriptor, order, margs, set(key_names)))
        resolutions.append({"from": f"{cname}(...).{mname}", "kind": "method", "to": mfq})
        fq, pin = mfq, None
    else:
        if methods:
            fail("E_PARSE_URI", "a method is called on an object: a class read")
        if pin is not None:
            found = [d for d in list(env.get("descriptors") or []) + list(functions.values())
                     if function_hash(d) == pin]
            if not found:
                fail("E_FN_UNAVAILABLE", f"no descriptor with hash {pin}")
            descriptor = found[0]
        else:
            if fq not in functions:
                fail("E_NAME_UNBOUND", f"{fq} is not bound")
            descriptor = functions[fq]
        bound = _call_bind(fq, descriptor, descriptor["signature"].get("order"), args, set())
    ref_args = _call_args(fq, descriptor, bound, asof, env, defaults)
    resolutions.extend(defaults)
    ns, fn = fq.rsplit("/", 1)
    ref = {"args": ref_args, "fn": fn, "ns": ns}
    if pin is not None:
        ref["fn_hash"] = pin
    if asof is not None:
        ref["asof"] = asof
    out = {"uri": format_uri(ref)}
    if resolutions:
        resolved = {"call": _canonical_call(fq, pin, ref_args, asof), "resolutions": resolutions}
        if any(r["kind"] == "alias" for r in resolutions) and env.get("aliases_tx"):
            resolved["aliases_tx"] = env["aliases_tx"]
        out["resolved"] = resolved
    return out


def _flat_by_hash(classes, held, h):
    """The flattened class descriptor whose hash is h: a class name bound to it (classes), else one held by hash only
    (held: the env member class_descriptors, K5), or None."""
    for n in keys_in_order(classes):
        if class_hash(classes[n]) == h:
            return classes[n]
    for d in held:
        if class_hash(d) == h:
            return d
    return None


def method_definer(classes, desc, m, held=()):
    """The class name that defines the method m an object of desc reads (K5, 16.3), or None when desc writes m itself.

    An override is desc's own: deciding that needs only the parent's flattened descriptor, found by hash (in classes,
    or held by hash only in held). m is inherited when the parent carries m with the same function hash; the defining
    class is then the top of the run of ancestors that carry m with that hash, and its name is the class name bound to
    its hash (the first in ascending order, as 16.3's super). LookupError carries a hash that cannot be resolved: a
    parent whose descriptor is not held at all, or the defining class's hash, which no class name is bound to."""
    h = desc["methods"][m]
    cur, definer = desc, None
    while cur.get("parent") is not None:
        pdesc = _flat_by_hash(classes, held, cur["parent"])
        if pdesc is None:
            raise LookupError(cur["parent"])
        if pdesc["methods"].get(m) != h:
            break
        definer, cur = cur["parent"], pdesc
    if definer is None:
        return None
    name = next((n for n in keys_in_order(classes) if class_hash(classes[n]) == definer), None)
    if name is None:
        raise LookupError(definer)
    return name


def _method_fq(classes, fq, desc, m, held=()):
    """The function N/m a method of the object of class fq reads (16.3, K5): D/m when inherited, else fq/m."""
    try:
        definer = method_definer(classes, desc, m, held)
    except LookupError as e:
        fail("E_NAME_UNBOUND", f"no class name is bound to the parent hash {e} of {fq}: its method {m} is not known")
    return f"{fq if definer is None else definer}/{m}"


def _call_method(fq, desc, mname, mtok, env):
    """The function a method call of an object of class fq reads: its full name, its descriptor and the key names it
    takes first (16.3, K5)."""
    functions = env.get("functions") or {}
    if mtok.kind == "QNAME":  # an extension method (16.3): a function that takes the class keys first
        mfq = mtok.value
        if mfq not in functions:
            fail("E_NAME_UNBOUND", f"{mfq} is not bound")
        descriptor = functions[mfq]
        sig = descriptor["signature"]
        if sig.get("order", [])[:len(desc["order"])] != desc["order"] or not all(
                _key_matches(desc["keys"][k], sig["args"][k]) for k in desc["order"]):
            fail("E_ARG_UNKNOWN", f"{mfq} does not take the keys of {fq} first")
        return mfq, descriptor, list(desc["order"])
    if mname not in desc["methods"]:
        fail("E_NAME_UNBOUND", f"{fq} has no method {mname}")
    if mname == desc.get("lookup"):  # spec-0.5.0 (H7): as a method the class does not have
        fail("E_NAME_UNBOUND", f"{mname} is {fq}'s lookup: it takes a label, not an object")
    mfq = _method_fq(env.get("classes") or {}, fq, desc, mname, env.get("class_descriptors") or [])
    if mfq not in functions or function_hash(functions[mfq]) != desc["methods"][mname]:
        fail("E_NAME_UNBOUND", f"{mfq} is not bound to the method {mname} of {fq}")
    descriptor = functions[mfq]
    key_names = []
    for k in desc["order"]:
        if k not in descriptor["signature"]["args"]:
            break
        key_names.append(k)
    return mfq, descriptor, key_names


def _chain_key(value, declared, classes, mfq):
    """The key a chain's cell holds (K10): a key encoding of one of the declared classes, whose key names and types
    are the class's (16.6), else E_FORMULA_DISPATCH_KEY. Returns (its typed keys, its class name)."""
    try:
        decoded = decode_key(value)
    except DatumeshError as e:
        raise CallFault("E_FORMULA_DISPATCH_KEY", f"{mfq} holds {value!r}, not an object key (16.5): {e.detail}")
    c = decoded["class"]
    if c not in declared:
        raise CallFault("E_FORMULA_DISPATCH_KEY", f"{mfq} holds a key of {c}, where {declared} is declared (16.6)")
    if c not in classes:
        fail("E_NAME_UNBOUND", f"{c} is not a class of this mesh")
    decl = classes[c]["keys"]
    for k, v in decoded["keys"].items():
        if k not in decl or ("class" in v) != ("class" in decl[k]) or ("class" not in v and v["type"] != decl[k]["type"]):
            raise CallFault("E_FORMULA_DISPATCH_KEY", f"{mfq} holds a key of {c} whose keys are not its class's (16.6)")
    if set(decoded["keys"]) != set(decl):
        raise CallFault("E_FORMULA_DISPATCH_KEY", f"{mfq} holds a key of {c} whose keys are not its class's (16.6)")
    keys = {k: {"type": "string", "value": encode_decoded(v)} if "class" in v else v
            for k, v in decoded["keys"].items()}
    return keys, c


def _literal_value(type_, text):
    """A literal default's typed scalar (7, K13): its lexical value, read by its type."""
    if type_ == "boolean":
        return {"type": "boolean", "value": text == "true"}
    return {"type": type_, "value": text}


def _call_args(fq, descriptor, bound, asof, env, defaults):
    """The arguments of a call's cell (5.8, 16.7, 7): each unbound argument takes its default, the asof default or a
    literal one (K13), recorded in defaults; each bound one is read by its declared position. Returns the ref args."""
    declared = descriptor["signature"]["args"]
    for name in keys_in_order(declared):
        if name in bound:
            continue
        decl = declared[name]
        if decl.get("default") == "asof":  # spec-0.5.0 (16.7)
            at = asof or env.get("now")
            if at is None:
                fail("E_ARG_MISSING", f"{fq} needs {name}: its asof default needs an asof")
            value = at if decl["type"] == "instant" else at[:10]
            bound[name] = ("typed", {"type": decl["type"], "value": value})
            defaults.append({"from": name, "kind": "default", "to": value})
            continue
        if "default" in decl:  # K13 (since the classes round): a literal default (7)
            bound[name] = ("typed", _literal_value(decl["type"], decl["default"]))
            defaults.append({"from": name, "kind": "default", "to": decl["default"]})
            continue
        fail("E_ARG_MISSING", f"{fq} needs {name} (an open argument is written *)")
    ref_args = {}
    for name in keys_in_order(bound):
        p = f"call.{name}"
        kind, value = bound[name]
        if kind == "typed":
            ref_args[name] = value
            if value["type"] == "string" and declared[name].get("key_normalisation") \
                    and declared[name]["key_normalisation"] != "label_fold":  # Q6 b
                check_key_value(declared[name]["key_normalisation"], value["value"], p)
            continue
        ref_args[name] = _call_read(bound[name], declared[name], p, env)
    return ref_args


def _call_query_start(text):
    """Where ?asof= begins: after the last ) outside strings, or the end."""
    end, in_str, i = -1, False, 0
    while i < len(text):
        c = text[i]
        if c == '"':
            in_str = not in_str
        elif c == ")" and not in_str:
            end = i
        i += 1
    return end + 1 if end >= 0 else len(text)


def _call_name(tok, env, resolutions):
    aliases = env.get("aliases") or {}
    if tok.kind == "ALIAS":
        if tok.value not in aliases:
            fail("E_NAME_UNBOUND", f"@{tok.value} is not an alias of this mesh")
        resolutions.append({"from": "@" + tok.value, "kind": "alias", "to": aliases[tok.value]})
        return aliases[tok.value]
    if tok.kind == "WORD":  # spec-0.5.0: a bare name resolves through the alias map (16.7)
        if tok.text not in aliases:
            fail("E_NAME_UNBOUND", f"{tok.text} is not in the alias map")
        resolutions.append({"from": tok.text, "kind": "alias", "to": aliases[tok.text]})
        return aliases[tok.text]
    return tok.value


def _call_bind(fq, descriptor, order, args, taken):
    declared = descriptor["signature"]["args"]
    bound = {}
    for i, (label, value) in enumerate(args):
        if label is None:
            if order is None:
                fail("E_PARSE_URI", f"{fq} declares no order: label the arguments")
            if i >= len(order):
                fail("E_ARG_UNKNOWN", f"{fq} takes {len(order)} arguments")
            name = order[i]
        else:
            name = label
            if name not in declared:
                fail("E_ARG_UNKNOWN", f"{fq} has no argument {name!r}")
        if name in bound or name in taken:
            fail("E_CANON_ARG_DUPLICATE", f"{name} is given twice")
        bound[name] = value
    return bound


def _key_position(decl):
    """A class key declaration as the declaration of a request position (5.8)."""
    if "class" in decl:
        return {"type": "string", "classes": [decl["class"]]}
    return decl


def _call_read(raw, decl, path, env):
    """A request value read by the declared type of its position (5.8; spec-0.5.0, Q1): a quoted
    string is a string; an unquoted token is that string in a string position, that literal in a
    number, date, instant or boolean position; in a class-typed position the value is a key encoding
    (an object, or a quoted encoding). Returns the typed scalar, or "*"."""
    kind, value = raw
    if kind == "open":
        return SLICE
    type_ = decl["type"]
    if kind == "token" and value[0] == "digit-run" and type_ not in ("string", "blob") \
            and not decl.get("classes"):  # K11: where a digit run is no string, today's code for it
        fail(_digit_run_code(value[1]), f"{value[1]!r} is not a {type_} (5.8)", path)
    classes = decl.get("classes")
    if classes:
        if kind == "object":
            if value["class"] not in classes:
                fail("E_CANON_TYPE", f"an object of {value['class']} where {classes} is declared", path)
            text = encode_decoded(_call_object(value, env))
        elif kind == "quoted":
            check_lexical("string", value, path)  # the string first (3.5), then the encoding (16.5)
            decoded = decode_key(value)
            if decoded["class"] not in classes:
                fail("E_CANON_TYPE", f"a key of {decoded['class']} where {classes} is declared", path)
            check_key_of_class(decoded, env.get("classes") or {}, path)  # H3: as an object literal is
            text = value
        else:
            fail("E_CANON_TYPE", f"a key of {classes} is an object or a quoted key encoding", path)
        check_lexical("string", text, path)
        return {"type": "string", "value": text}
    if kind == "object":
        fail("E_CANON_TYPE", f"an object for a {type_} argument", path)
    if kind == "token" and value[0] == "digit-word" and type_ != "string":  # spec-0.6.0 (C3)
        fail("E_CANON_TYPE", f"the digit-led word {value[1]!r} for a {type_} argument", path)
    if type_ in ("string", "blob"):
        text = value if kind == "quoted" else value[1]
    elif kind == "token" and value[0] == type_ and type_ in ("number", "date", "instant"):
        text = value[1]
    elif kind == "token" and type_ == "boolean" and value in (("word", "true"), ("word", "false")):
        return {"type": "boolean", "value": value[1] == "true"}
    else:
        written = "a quoted string" if kind == "quoted" else f"the token {value[1]!r}"
        fail("E_CANON_TYPE", f"{written} for a {type_} argument", path)
    check_lexical(type_, text, path)
    if type_ == "string" and decl.get("key_normalisation") == "label_fold":  # K8: a label is folded, never refused
        return {"type": "string", "value": fold_label(text)}
    if type_ == "string" and decl.get("key_normalisation"):  # a key's rule, or a function's (Q6 b)
        check_key_value(decl["key_normalisation"], text, path)
    return {"type": type_, "value": text}


def _digit_run_code(text):
    """The code today's request lexer gives a digit run that is no string here (K11): the number lexer's, or E_PARSE_URI
    when the run is no single token (1-1)."""
    import formula
    try:
        formula.tokenize(text, request=True, runs=False)
    except formula.FormulaError as e:
        return _CALL_LEXER_CODES.get(e.code, "E_PARSE_URI")
    return "E_PARSE_URI"


def _call_keys(fq, desc, args, env):
    """An object's keys in a call (16.3): each key bound once and read by its type, a string key
    checked by its normalisation. Returns {key: typed scalar}."""
    keys = {}
    order = desc["order"]
    for i, (label, value) in enumerate(args):
        if label is None:
            if i >= len(order):
                fail("E_ARG_UNKNOWN", f"{fq} has {len(order)} keys")
            name = order[i]
        else:
            name = label
            if name not in desc["keys"]:
                fail("E_ARG_UNKNOWN", f"{fq} has no key {name!r}")
        if name in keys:
            fail("E_CANON_ARG_DUPLICATE", f"{name} is given twice")
        if value[0] == "open":
            fail("E_PARSE_URI", "an object binds every key")
        keys[name] = _call_read(value, _key_position(desc["keys"][name]), f"call.{name}", env)
    for name in keys_in_order(desc["keys"]):
        if name not in keys:
            fail("E_ARG_MISSING", f"{fq} needs its key {name}")
    return keys


def _call_object(raw, env):
    """An object literal of a call as a decoded object key (16.5)."""
    classes = env.get("classes") or {}
    if raw["class"] not in classes:
        fail("E_NAME_UNBOUND", f"{raw['class']} is not a class of this mesh")
    desc = classes[raw["class"]]
    keys = _call_keys(raw["class"], desc, raw["keys"], env)
    out = {k: decode_key(v["value"]) if "class" in desc["keys"][k] else v for k, v in keys.items()}
    return {"class": raw["class"], "keys": out}


def _call_lookup(fq, desc, label, asof, env, resolutions):
    """The keys of the object a label names (spec-0.5.0, Q10 a): the class's lookup method read at
    the label, as of the call's asof (the mesh's now when it has none). Returns {key: typed scalar}."""
    functions = env.get("functions") or {}
    m = desc.get("lookup")
    if m is None:
        fail("E_NAME_UNBOUND", f"{fq} has no lookup: a label names none of its objects")
    lfq = f"{fq}/{m}"
    if lfq not in functions or function_hash(functions[lfq]) != desc["methods"][m]:
        fail("E_NAME_UNBOUND", f"{lfq} is not bound to the lookup method of {fq}")
    decl = functions[lfq]["signature"]["args"]["label"]
    raw = _call_read(label, dict(decl, key_normalisation="none"), "call.label", env)["value"]  # 3.5 first
    text = fold_label(raw) if decl.get("key_normalisation") == "label_fold" else raw  # K8: folded before the lookup
    at = asof or env.get("now")
    if at is None:
        fail("E_ARG_MISSING", "a lookup is read as of the call's asof, or the mesh's now")
    table = (env.get("lookups") or {}).get(fq) or {}
    if text not in table:
        fail("E_NAME_UNBOUND", f"{fq}'s lookup has no value for the label {text!r} as of {at}")
    key = table[text]
    if key == "":  # spec-0.7.0 (R1): the lookup returns a key, never the empty string (a withdrawn label is a
        # withdrawn lookup cell, which a request through it answers not_covered; the call vectors refuse "")
        fail("E_KEY_NORMALISATION", f"the lookup of {text!r} returns the empty string, not a key of {fq}")
    decoded = decode_key(key)
    if decoded["class"] != fq or set(decoded["keys"]) != set(desc["keys"]):
        fail("E_KEY_ENCODING", f"the lookup's value is not a key of {fq}")
    resolutions.append({"asof": at, "from": raw, "kind": "lookup", "to": key})
    return {k: {"type": "string", "value": encode_decoded(v)} if "class" in v else v
            for k, v in decoded["keys"].items()}


def _call_literal(kind, value):
    if kind == "string":
        return '"' + value.replace('"', '""') + '"'
    if kind == "boolean":
        return "true" if value else "false"
    return value


def _canonical_call(fq, pin, ref_args, asof):
    """The full canonical call (16.7): the full name, every argument labelled in ascending order."""
    parts = []
    for name in keys_in_order(ref_args):
        a = ref_args[name]
        parts.append(f"{name}: *" if a == SLICE else f"{name}: {_call_literal(a['type'] if a['type'] != 'blob' else 'string', a['value'])}")
    head = fq + (f"@{pin}" if pin else "")
    return f"{head}({', '.join(parts)})" + (f"?asof={asof}" if asof else "")


def _call_tree(tokens):
    """The callee token, [(label or None, value)], an optional method (name, token, args) and an
    optional label of a call; E_PARSE_URI otherwise. A value is ("quoted", text), ("token", (lexical
    kind, text)) for an unquoted token (spec-0.5.0, Q1: number, date, instant, period or word),
    ("open", None) for "*", or ("object", {...})."""
    def bad(detail="not a call of literals"):
        fail("E_PARSE_URI", detail)

    pos = [0]

    def at(k=0):
        return tokens[min(pos[0] + k, len(tokens) - 1)]

    def punct(text, k=0):
        return at(k).kind == "PUNCT" and at(k).text == text

    def is_callee(k=0):
        t = at(k)
        return t.kind in ("QNAME", "ALIAS") or (t.kind == "WORD" and (punct("(", k + 1) or punct("[", k + 1))
                                                and t.text.lower() not in ("true", "false"))

    def arg_list():
        if not punct("("):
            bad("a call has its arguments in parentheses")
        pos[0] += 1
        args, labelled = [], False
        if punct(")"):
            pos[0] += 1
            return args
        while True:
            label = None
            if at().kind == "WORD" and punct(":", 1):
                label = at().text
                labelled = True
                pos[0] += 2
            elif labelled:
                bad("positional arguments come before labelled ones")
            args.append((label, value()))
            if punct(","):
                pos[0] += 1
                continue
            if punct(")"):
                pos[0] += 1
                return args
            bad("an unquoted value is one token: quote a string holding other characters")

    def value(objects=True):
        tok = at()
        if tok.kind == "STR":
            v = ("quoted", tok.value)
        elif tok.kind == "DATE":
            v = ("token", ("date", tok.value))
        elif tok.kind == "INSTANT":
            v = ("token", ("instant", tok.value))
        elif tok.kind == "NUM" and tok.unit is None:
            v = ("token", ("number", tok.value))
        elif tok.kind == "PUNCT" and tok.text == "-" and at(1).kind == "NUM" and at(1).unit is None:
            pos[0] += 1
            v = ("token", ("number", "-" + at().value))
        elif tok.kind == "PERIOD":
            v = ("token", ("period", tok.value))
        elif tok.kind == "DWORD":  # spec-0.6.0 (C3): a value only in a string position (_call_read)
            v = ("token", ("digit-word", tok.value))
        elif tok.kind == "DRUN":  # K11 (since the classes round): a run of digits and hyphens, a string where one is
            v = ("token", ("digit-run", tok.value))
        elif tok.kind == "WORD" and not punct("(", 1):  # a value, never an alias (Q1)
            v = ("token", ("word", tok.text))
        elif tok.kind == "PUNCT" and tok.text == "*" and objects:
            v = ("open", None)
        elif tok.kind == "QNAME" and punct("(", 1) and objects:  # an object literal in a class-typed position
            name = tok.value
            pos[0] += 1
            inner = arg_list()
            return ("object", {"class": name, "keys": inner, "raw": True})
        else:
            bad()
        pos[0] += 1
        return v

    if not is_callee():
        bad("a call begins with a function name, a class name, an @alias or a bare name")
    callee = at()
    pos[0] += 1
    label = None
    if punct("["):
        pos[0] += 1  # spec-0.5.0 (Q10 a): N[label], the object a label names (requests only)
        label = value(objects=False)
        if not punct("]"):
            bad("a label is one value in brackets: N[label]")
        pos[0] += 1
        args = None
    else:
        args = arg_list()
    methods = []  # K10: a chain N(k).m(a).n(b); each method after the first is called on the key the one before returns
    while at().kind == "DOT":
        pos[0] += 1
        t = at()
        if t.kind not in ("WORD", "QNAME") or not punct("(", 1):
            bad("a method is .name(...) or .<qualified name>(...)")
        pos[0] += 1
        methods.append((t.text if t.kind == "WORD" else t.value, t, arg_list()))
    if at().kind != "EOF":
        bad("nothing follows a call but ?asof=")
    if label is not None and not methods:
        bad("a label names an object: call one of its methods")
    return callee, args, methods, label


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
            doc = resolve_key_document(vec["host"], vec["env"])
            out = {"key_ids": [k["id"] for k in doc["keys"]]}
            if doc["declarations"]:  # spec-0.4.3
                out["declarations"] = doc["declarations"]
            return out
        if kind == "class":  # spec-0.5.0 (16.2)
            flat = define_class(vec["name"], parse_json(vector_input(vec)), vec.get("env", {}))
            return {"flattened": jcs(flat).decode(), "class_hash": class_hash(flat)}
        if kind == "normalisation":  # spec-0.5.0 (16.4)
            check_key_value(vec["rule"], vec["text"])
            return {}
        if kind == "describe":  # spec-0.5.0 (16.8); integers kept as written (spec-0.6.0: tests, 5.5)
            check_describe(parse_json(vector_input(vec), keep_integer_text=True), vec.get("classes"),
                           vec.get("functions"))
            return {}
        if kind == "find-result":  # since the classes round (C2, 9.6): one result of a find
            check_find_result(parse_json(vector_input(vec), keep_integer_text=True))
            return {}
        if kind == "key":  # spec-0.5.0 (16.5)
            out = {"decoded": decode_key(vec["input"])}
            if "class_hash" in vec:  # the object and its id (16.5), given the class hash
                obj = object_of_key(vec["input"], vec["class_hash"])
                out.update(object=obj, object_id=object_id(obj), class_hash=vec["class_hash"])
            return out
        if kind == "define":  # spec-0.5.0
            return check_define(vec["name"], parse_json(vector_input(vec)))
        if kind == "licence":  # spec-0.4.3: licence inheritance (8.5)
            return inherit_licence(vec["licences"], vec.get("declarations", {}), vec["fn"], vec["issued"],
                                   vec["mesh_licence"])
        if kind == "entitlement":  # spec-0.4.3: the entitlement check (10.3)
            # spec-0.5.0 (RS-44, DEF-57, JS 57): R through step 6 with its own codes, then L as step 7.5
            # obtains it, with its codes, then K.
            verify_receipt(vector_input(vec), vec["keys"])
            r = parse_json(vector_input(vec))
            licences = input_licences(r, vec.get("receipts", {}), vec.get("manifests", {}), vec["keys"])
            host = r["cell"]["ns"].split("/")[0]
            keydoc = resolve_key_document(host, vec["keys"].get(host))
            return check_entitlement(r, licences, keydoc)
        if kind == "unit":
            obj = parse_json(vector_input(vec))
            _shape_object(obj, ("cell", "descriptor"), (), "$")
            return {"unit": resolved_unit(obj["descriptor"], obj["cell"])}
        if kind == "envelope":
            return check_envelope(vec["status"], vector_input(vec), vec["keys"], vec["request"])
        if kind == "batch":
            return check_batch(vec["status"], vector_input(vec), vec["keys"], vec["requests"])
        if kind == "call":
            try:
                return parse_call(vec["input"], vec["env"])
            except CallFault as e:
                return {"error": e.code, "detail": e.detail}
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
                 "bindings", "endpoints",
                 "declarations", "licence", "reason", "entitled",  # spec-0.4.3
                 "decoded", "resolved", "flattened", "class_hash", "object_id")  # spec-0.5.0


def check_vector(vec):
    """Return a list of mismatches between a vector and the reference behaviour."""
    got = run_vector(vec)
    problems = []
    if vec["valid"]:
        if "error" in got:
            return [f"expected valid, got {got['detail']}"]
        for field in OUTPUT_FIELDS:
            if field == "declarations" and vec["kind"] == "licence":  # an input there (spec-0.4.3)
                continue
            if field in vec and vec[field] != got.get(field):
                problems.append(f"{field}: expected {vec[field]!r}, got {got.get(field)!r}")
        if vec["kind"] == "mesh":
            problems += [f"{f}: missing from a valid mesh vector" for f in ("bindings", "endpoints") if f not in vec]
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
