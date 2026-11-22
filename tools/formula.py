# SPDX-License-Identifier: Apache-2.0
"""Reference implementation of the formula dialect (SPEC.md section 15) and of slice-as-lineage.

A test tool like canon.py: it generates and checks the vectors, and is written to be read next to
the specification, not for speed. Standard library only; numbers use tools/fdecimal.py (integers),
never floats.

    compile(source, env)        lex, parse, resolve, check: a Compiled (canonical AST, body, inputs,
                                return type and unit, asof dependence)
    canonical_ast(source)       the canonical AST of a printed body, without an environment
    print_ast(ast)              the printed form (code.body without its final LF)
    define(name, signature, source, env)   a formula descriptor
    World(...).evaluate(...)    evaluation as of an asof, with lineage, fuel and computed receipts

An environment is {"name": <function being defined>, "signature": <its signature>,
"functions": {<fully qualified name>: <descriptor>}, "aliases": {<alias>: <fully qualified name>}}.
"""

import datetime
import hashlib
import json
import re
import sys
import threading
import unicodedata
from fractions import Fraction

import canon
import fdecimal
from fdecimal import ArithmeticFault, Dec

sys.setrecursionlimit(1_000_000)  # with deep(): the passes recurse once or twice per AST level

# ---------------------------------------------------------------------------
# Codes (SPEC 15.11). Define-time codes first, then evaluation codes.

DEFINE_CODES = (
    "E_FORMULA_SYNTAX", "E_FORMULA_NUMBER", "E_FORMULA_STRING", "E_FORMULA_DATE", "E_FORMULA_INSTANT",
    "E_FORMULA_UNIT", "E_FORMULA_NAME", "E_FORMULA_RESERVED", "E_FORMULA_FORBIDDEN", "E_FORMULA_DYNAMIC_NAME",
    "E_FORMULA_AMBIGUOUS", "E_FORMULA_CHAIN", "E_FORMULA_PLACEMENT", "E_FORMULA_LIMIT",
    "E_FORMULA_UNKNOWN_FUNCTION", "E_FORMULA_ALIAS", "E_FORMULA_UNRESOLVED", "E_FORMULA_UNKNOWN_NAME",
    "E_FORMULA_SHADOW", "E_FORMULA_ARITY", "E_FORMULA_ARG_UNKNOWN", "E_FORMULA_ARG_MISSING",
    "E_FORMULA_ARG_DUPLICATE", "E_FORMULA_ARG_ORDER", "E_FORMULA_POSITIONAL", "E_FORMULA_ORDER",
    "E_FORMULA_TYPE", "E_FORMULA_SLICE_VALUE", "E_FORMULA_UNIT_MISMATCH", "E_FORMULA_UNIT_OFFSET",
    "E_FORMULA_UNIT_UNKNOWN", "E_FORMULA_EXPONENT", "E_FORMULA_RETURN_TYPE", "E_FORMULA_RETURN_UNIT",
    "E_FORMULA_UNBOUNDED", "E_FORMULA_SLICE_BOUND", "E_FORMULA_METRIC", "E_FORMULA_ALONG", "E_FORMULA_JOIN",
    "E_FORMULA_LAMBDA_PARAM", "E_FORMULA_LAMBDA_READ", "E_FORMULA_ENUM", "E_FORMULA_TX_ARG",
    "E_FORMULA_UNSUPPORTED", "E_FORMULA_INPUTS", "E_FORMULA_NOT_CANONICAL",
    "E_FORMULA_METHOD", "E_FORMULA_DISPATCH", "E_FORMULA_KEY",  # spec-0.5.0: classes (16.3, 16.6)
)
# Faults: deterministic properties of a cell; the cell has no value (not_covered with fault).
FAULT_CODES = ("E_FORMULA_DIV_ZERO", "E_FORMULA_DOMAIN", "E_FORMULA_RANGE", "E_FORMULA_EMPTY",
               "E_FORMULA_ABSENT", "E_FORMULA_FUTURE",
               # spec-0.5.0: a computed key not canonical under its argument's rule (Q6 b), a value
               # outside the dispatch set (answer 5). E_FORMULA_KEY is also a define-time code.
               "E_FORMULA_KEY", "E_FORMULA_DISPATCH_KEY")
# Other evaluation outcomes: no value for missing data, and failures of the evaluation itself.
EVAL_CODES = FAULT_CODES + ("E_FORMULA_NOT_COVERED", "E_FORMULA_BUDGET", "E_FORMULA_CYCLE", "E_FORMULA_DEPTH",
                             "E_FORMULA_BLOB_UNAVAILABLE")  # spec-0.4.2: text_of without the content
CODES = tuple(dict.fromkeys(DEFINE_CODES + EVAL_CODES))  # E_FORMULA_KEY is both (spec-0.5.0)
CATCHABLE = ("E_FORMULA_EMPTY", "E_FORMULA_ABSENT")
# spec-0.5.0 (I3): a code of 10.2, not of 15.11, that the define of a method body can give: super in a
# subclass whose parent's hash no class name is bound to in the definer's environment (16.3).
CLASS_CODES = ("E_CLASS_PARENT",)
# spec-0.6.0 (C3): the request lexer's code for a run that is no token of a request (5.8), E_PARSE_URI.
REQUEST_CODES = ("E_PARSE_URI",)


def _no_value(e):
    """A fault or E_FORMULA_NOT_COVERED: the cell has no value, memoized as a property of the cell. A
    define-time code raised at evaluation (a rebound callee, 15.8) is the mesh's failure, even
    E_FORMULA_KEY, which since spec-0.5.0 is also a fault."""
    return e.code in FAULT_CODES + ("E_FORMULA_NOT_COVERED",) and not getattr(e, "define_time", False)


class FormulaError(Exception):
    def __init__(self, code, detail="", token=None):
        assert code in CODES or code in CLASS_CODES or code in REQUEST_CODES, code
        self.code, self.detail, self.token = code, detail, token
        super().__init__(f"{code}: {detail}")


def fail(code, detail="", token=None):
    raise FormulaError(code, detail, token)


_DEEP = threading.local()


def deep(fn):
    """Run fn on a thread with a 1 GiB stack, so that the recursive passes over the AST (resolve,
    print, check, evaluate) reach the 65,536-node limit of SPEC 15.3 without exhausting Python's
    stack. Nested calls run in place."""
    def run(*args, **kwargs):
        if getattr(_DEEP, "on", False):
            return fn(*args, **kwargs)
        result = {}

        def body():
            _DEEP.on = True
            try:
                result["value"] = fn(*args, **kwargs)
            except BaseException as e:  # re-raised on the caller's thread
                result["error"] = e
        old = threading.stack_size()
        threading.stack_size(1 << 30)
        try:
            t = threading.Thread(target=body)
            t.start()
        finally:
            threading.stack_size(old)
        t.join()
        if "error" in result:
            raise result["error"]
        return result["value"]
    run.__doc__ = fn.__doc__
    return run


# ---------------------------------------------------------------------------
# Words (SPEC 15.2.1)

KEYWORDS = ("if", "then", "else", "let", "in", "and", "or", "not", "true", "false")
RESERVED = ("this", "super")
FORBIDDEN = ("now", "today", "rand", "randbetween", "randarray", "indirect", "offset", "info", "cell",
             "clock", "time", "random", "sleep", "fetch", "http", "eval")
AGGREGATES = ("sum", "count", "mean", "min", "max", "first", "last", "median", "stdev", "stdev_p")
WEEKENDS = {"sat-sun": (5, 6), "fri-sat": (4, 5), "sun": (6,), "none": ()}
ROLLS = ("following", "modified_following", "preceding")
CONVENTIONS = ("act/360", "act/365f", "act/act_isda", "30/360", "30e/360", "30/360_us")
METHODS = ("linear", "step")

# name -> (required parameters, optional parameters, variadic)
BUILTINS = {a: ((), (), True) for a in AGGREGATES}
BUILTINS.update({
    "at": (("slice", "key"), ("along",), False),
    "latest": (("slice",), ("bound", "along"), False),
    "last_before": (("slice", "x"), ("bound", "along"), False),
    "first_after": (("slice", "x"), ("bound", "along"), False),
    "last_by": (("slice", "by"), (), False),  # spec-0.6.2 (15.7, 15.13)
    "first_by": (("slice", "by"), (), False),
    "nearest": (("slice", "x"), ("bound", "along"), False),
    "within": (("slice", "x", "bound"), ("along",), False),
    "interpolate": (("slice", "x"), ("method", "bound", "along"), False),
    "map": (("slice", "fn"), (), False),
    "filter": (("slice", "fn"), (), False),
    "scan": (("slice", "aggregate"), ("along",), False),
    "window": (("slice", "n", "aggregate"), ("along",), False),
    "otherwise": (("x", "fallback"), (), False),
    "asof": ((), ("cell", "at"), False),
    "versions": (("cell", "from", "to"), (), False),
    "abs": (("x",), (), False),
    "round": (("x",), ("digits",), False),
    "round_up": (("x",), ("digits",), False),
    "round_down": (("x",), ("digits",), False),
    "floor": (("x",), (), False),
    "ceiling": (("x",), (), False),
    "mod": (("x", "divisor"), (), False),
    "sqrt": (("x",), (), False),
    "exp": (("x",), (), False),
    "ln": (("x",), (), False),
    "sin": (("x",), (), False),
    "cos": (("x",), (), False),
    "atan2": (("y", "x"), (), False),
    "pi": ((), (), False),
    "haversine": (("lat1", "lon1", "lat2", "lon2"), (), False),
    "convert": (("x", "unit"), (), False),
    "if": (("condition", "then", "else"), (), False),
    "and": ((), (), True),
    "or": ((), (), True),
    "date": (("year", "month", "day"), (), False),
    "year": (("date",), (), False),
    "month": (("date",), (), False),
    "day": (("date",), (), False),
    "weekday": (("date",), (), False),
    "end_of_month": (("date",), (), False),
    "add_days": (("date", "n"), ("calendar", "weekend"), False),
    "add_months": (("date", "n"), ("calendar", "roll", "weekend"), False),
    "business_days": (("from", "to"), ("calendar", "weekend"), False),
    "year_fraction": (("from", "to", "convention"), (), False),
    "is_holiday": (("date", "calendar"), (), False),
    "date_of": (("instant",), (), False),
    "instant": (("date",), (), False),
    "len": (("text",), (), False),
    "upper": (("text",), (), False),
    "lower": (("text",), (), False),
    "trim": (("text",), (), False),
    "concat": ((), (), True),
    "substr": (("text", "start", "length"), (), False),
    "find": (("needle", "text"), ("start",), False),
    "text": (("x",), (), False),
    "fixed": (("x", "digits"), (), False),
    "text_of": (("blob",), (), False),  # spec-0.4.2
    "remove_chars": (("text", "chars"), (), False),  # spec-0.4.2
})

# Names reserved for later revisions: a call is E_FORMULA_UNSUPPORTED (SPEC 15.10, 15.7).
UNSUPPORTED_BUILTINS = ("ellipsoidal_distance",)
UNSUPPORTED_METHODS = ("spline",)
# Fuel of one call (SPEC 15.12): the transcendental algorithms run fixed term counts.
TRANSCENDENTAL_FUEL = {"sqrt": 10, "exp": 50, "ln": 80, "sin": 50, "cos": 50, "atan2": 60, "haversine": 400, "pow": 130}

LIMIT_DEPTH = 256
LIMIT_NODES = 65536
LIMIT_SOURCE = 1048576
LIMIT_ENUMERATION = 1048576
MIN_INSTANT = "0001-01-01T00:00:00.000000Z"
MAX_INSTANT = "9999-12-31T23:59:59.999999Z"

# ---------------------------------------------------------------------------
# Lexer (SPEC 15.2)


def _unit_literals():
    units = set()
    for items in canon.UNITS.values():
        units.update(items)
    units.discard("1")  # a bare literal already is dimensionless
    return sorted(units, key=lambda u: (-len(u), u))


UNIT_LITERALS = _unit_literals()


class Token:
    __slots__ = ("kind", "text", "pos", "value", "unit", "pin")

    def __init__(self, kind, text, pos, value=None, unit=None):
        self.kind, self.text, self.pos, self.value, self.unit = kind, text, pos, value, unit
        self.pin = None  # spec-0.4.2: name@<fn_hash>, a function pinned by hash

    def __repr__(self):
        return f"Token({self.kind}, {self.text!r})"


_INSTANT_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T")
_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_QUALIFIED = re.compile(_LABEL + r"(?:\." + _LABEL + r")+(?:/[a-z0-9_]+)+")
_QUALIFIED_HOST = re.compile(_LABEL + r"(?:\." + _LABEL + r")+")
_RUN = re.compile(r"[A-Za-z0-9_.-]*")
_HOSTISH = re.compile(r"[A-Za-z0-9_.\-]+")
_ALIAS = re.compile(r"@[A-Za-z0-9_/]*")
_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?")
_CANONICAL_NUMBER = re.compile(r"(0|[1-9][0-9]*)(\.[0-9]*[1-9])?")
_INDEX_UNIT = re.compile(r"index:[0-9]{4}(?:-[0-9]{2}){0,2}=(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
# spec-0.6.0 (C3, 5.8): a request's digit-led word is a run of digits, letters, digits or "_" that begins with a digit,
# when the number, date, instant and period lexers do not accept the whole run; a period is 1*DIGIT ("D"/"M"/"Y").
_DIGIT_RUN = re.compile(r"[0-9][A-Za-z0-9_]*")
_DIGIT_HYPHEN_RUN = re.compile(r"[0-9][0-9-]*")  # since the classes round (K11): a request's digit and hyphen run
_PERIOD_TOKEN = re.compile(r"[0-9]+[DMY]")
_NAME = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
PUNCT2 = ("..", "->", "<>", "<=", ">=")
PUNCT1 = "()[],:*+-/^&=<>"
SPACE = " \t\n"


def _word_char(c):
    return c.isascii() and (c.isalnum() or c == "_")


def is_name(text):
    return bool(_NAME.fullmatch(text)) and len(text) <= 64


_PIN = re.compile(r"@([0-9a-f]{64})")


def _pin(source, i, token):
    """spec-0.4.2: a function name directly followed by @ and 64 lowercase hex digits (its fn_hash)."""
    if i < len(source) and source[i] == "@":
        m = _PIN.match(source, i)
        if not m or (m.end() < len(source) and _word_char(source[m.end()])):
            fail("E_FORMULA_NAME", "a pin is @ and the 64 lowercase hex digits of a function hash")
        token.pin = m.group(1)
        return m.end()
    return i


def tokenize(source, request=False, runs=True):
    """The tokens of a body (15.2), or of a request's call (5.8) when request is true. The request lexer differs in
    two places (spec-0.6.0): a date followed by a letter, digit or "_" is E_PARSE_URI (the run is no token of the
    dialect, 5.8), and a digit-led word is a token DWORD. Since the classes round (K11) a run of digits and hyphens
    that no number lexer takes whole is a token DRUN, a string in a string position; runs=False gives the lexer
    without it (today's codes for the run in another position)."""
    if not isinstance(source, str):
        fail("E_FORMULA_SYNTAX", "a body is text")
    if len(source.encode("utf-8")) > LIMIT_SOURCE:
        fail("E_FORMULA_LIMIT", "a body is at most 1 MiB")
    tokens = []
    i, n = 0, len(source)
    while True:
        while i < n and source[i] in SPACE:
            i += 1
        if i >= n:
            tokens.append(Token("EOF", "", i))
            return tokens
        c = source[i]
        rest = source[i:]
        # L1 instants
        if _INSTANT_SHAPE.match(rest):
            m = _INSTANT.match(rest)
            if not m or (len(m.group()) < len(rest) and _word_char(rest[len(m.group())])):
                fail("E_FORMULA_INSTANT", "an instant is YYYY-MM-DDTHH:MM:SS.ffffffZ (SPEC 3.3)")
            try:
                canon.check_instant(m.group(), "$")
            except canon.DatumeshError:
                fail("E_FORMULA_INSTANT", f"not a real instant: {m.group()}")
            tokens.append(Token("INSTANT", m.group(), i, m.group()))
            i += len(m.group())
            continue
        # L2 dates
        m = _DATE.match(rest)
        if m:
            end = len(m.group())
            if end < len(rest) and _word_char(rest[end]):
                if request:
                    fail("E_PARSE_URI", f"{m.group()}{rest[end]} is no token of a request (5.8)")
                fail("E_FORMULA_DATE", "a date is YYYY-MM-DD")
            try:
                canon.check_date(m.group(), "$")
            except canon.DatumeshError:
                fail("E_FORMULA_DATE", f"not a real day: {m.group()}")
            tokens.append(Token("DATE", m.group(), i, m.group()))
            i += end
            continue
        # L3 qualified names (spec-0.6.1: a later segment may be a DNS name when a "/" follows it; the last is a name)
        if c.isascii() and c.isalnum():
            m = _QUALIFIED_HOST.match(rest)
            if m and not m.group().split(".")[-1].isdigit():
                j = m.end()
                text_end = None
                while j < len(rest) and rest[j] == "/":
                    r = _RUN.match(rest, j + 1)
                    run = r.group()
                    if not run:
                        break
                    k = j + 1 + len(run)
                    if k < len(rest) and rest[k] == "/":
                        j = k
                        text_end = j
                        continue
                    nm = re.match(r"[a-z0-9_]+", run)
                    if nm:
                        text_end = j + 1 + nm.end()
                    break
                if text_end is not None:
                    text = rest[:text_end]
                    if text_end < len(rest) and rest[text_end - 1] != "/" and _word_char(rest[text_end]):
                        fail("E_FORMULA_NAME", f"not a function name: {text}{rest[text_end]}")
                    try:
                        canon.check_function_name(text, "$")
                    except canon.DatumeshError as e:
                        fail("E_FORMULA_NAME", f"not a function name: {text} ({e.code})")
                    tokens.append(Token("QNAME", text, i, text))
                    i += len(text)
                    i = _pin(source, i, tokens[-1])
                    continue
            h = _HOSTISH.match(rest)
            if h and ".." in h.group():  # .. is a token (ranges), never inside a name
                h = None
            if h and "." in h.group() and len(h.group()) < len(rest) and rest[len(h.group())] == "/":
                host = h.group()
                last = host.split(".")[-1]
                if last and not last.isdigit():
                    fail("E_FORMULA_NAME", f"not a function name: {host}/…")
        # L4 aliases
        if c == "@":
            m = _ALIAS.match(rest)
            text = m.group()
            segments = text[1:].split("/")
            if not all(is_name(s) for s in segments):
                fail("E_FORMULA_NAME", f"not an alias: {text}")
            tokens.append(Token("ALIAS", text, i, text[1:]))
            i += len(text)
            i = _pin(source, i, tokens[-1])
            continue
        # L5 numbers, L6 unit suffixes
        if request and c.isdigit():  # spec-0.6.0 (C3): a digit-led word, unless it is a period
            run = _DIGIT_RUN.match(rest).group()
            if any(ch.isascii() and ch.isalpha() for ch in run) and not _PERIOD_TOKEN.fullmatch(run):
                tokens.append(Token("DWORD", run, i, run))
                i += len(run)
                continue
        if request and runs and c.isdigit():  # K11 (since the classes round): a digit run, unless a number
            m = _DIGIT_HYPHEN_RUN.match(rest)
            end_i = i + len(m.group())
            if (end_i >= n or source[end_i] in " \t\n,)]") and not _CANONICAL_NUMBER.fullmatch(m.group()) \
                    and not (i > 0 and source[i - 1] == "-"):  # a run after a minus is a number's, as before
                tokens.append(Token("DRUN", m.group(), i, m.group()))
                i = end_i
                continue
        if c.isdigit() or (c == "." and i + 1 < n and source[i + 1].isdigit()):
            if c == ".":
                fail("E_FORMULA_NUMBER", "a number has digits before its point")
            m = _NUMBER.match(rest)
            text = m.group()
            end = i + len(text)
            if end < n and source[end] == "." and not (end + 1 < n and source[end + 1] == "."):
                fail("E_FORMULA_NUMBER", f"not a canonical number: {text}.")
            if end < n and source[end] in "eE" and end + 1 < n and (source[end + 1].isdigit() or source[end + 1] in "+-"):
                fail("E_FORMULA_NUMBER", "numbers have no exponent")
            if not _CANONICAL_NUMBER.fullmatch(text) or len(text) > 128:
                fail("E_FORMULA_NUMBER", f"not a canonical number: {text} (SPEC 3.1)")
            unit = None
            if "." not in text and end < n and source[end] in "DMY" and (end + 1 >= n or not _word_char(source[end + 1])):
                # spec-0.5.0: a period key literal (16.3); outside a key position it stays reserved
                tokens.append(Token("PERIOD", source[i:end + 1], i, source[i:end + 1]))
                i = end + 1
                continue
            j = end
            while j < n and source[j] in " \t":
                j += 1
            if j < n and source[j].isascii() and source[j].isalpha():
                unit = _unit_at(source, j)
                if unit is None:
                    w = _WORD.match(source, j).group()
                    if w.lower() not in KEYWORDS:
                        fail("E_FORMULA_UNIT", f"not a listed unit: {w}")
                else:
                    end = j + len(unit)
            tokens.append(Token("NUM", source[i:end], i, text, unit))
            i = end
            continue
        # L7 strings
        if c == '"':
            j, out = i + 1, []
            while True:
                if j >= n:
                    fail("E_FORMULA_STRING", "unterminated string")
                if source[j] == '"':
                    if j + 1 < n and source[j + 1] == '"':
                        out.append('"')
                        j += 2
                        continue
                    break
                out.append(source[j])
                j += 1
            value = "".join(out)
            try:
                canon.check_text(value, "$", "string")
            except canon.DatumeshError as e:
                fail("E_FORMULA_STRING", f"string literal: {e.detail}")
            tokens.append(Token("STR", source[i:j + 1], i, value))
            i = j + 1
            continue
        # L8 words
        m = _WORD.match(rest)
        if m:
            tokens.append(Token("WORD", m.group(), i, m.group()))
            i += len(m.group())
            continue
        # L9 punctuation
        two = rest[:2]
        if two in ("==", "!="):
            fail("E_FORMULA_SYNTAX", f"{two} is not an operator: write = or <>")
        if two in PUNCT2:
            tokens.append(Token("PUNCT", two, i))
            i += 2
            continue
        if c == ".":
            tokens.append(Token("DOT", ".", i))
            i += 1
            continue
        if c in PUNCT1:
            tokens.append(Token("PUNCT", c, i))
            i += 1
            continue
        fail("E_FORMULA_SYNTAX", f"unexpected character {c!r} at {i}")


def _unit_at(source, j):
    m = _INDEX_UNIT.match(source, j)
    if m and canon.is_unit_literal(m.group()) and (m.end() >= len(source) or not _word_char(source[m.end()])):
        return m.group()
    for u in UNIT_LITERALS:
        if source.startswith(u, j):
            k = j + len(u)
            if k >= len(source) or not _word_char(source[k]):
                return u
    return None


# ---------------------------------------------------------------------------
# Parser (SPEC 15.3): a PEG, written as recursive descent. It builds the surface tree:
#   ("num", lexical, unit) ("str", v) ("bool", b) ("date", v) ("instant", v) ("var", word)
#   ("op", op, [args]) ("if", c, t, e) ("let", word, value, body)
#   ("read", fq or None, alias or None, [(label, arg)])   arg: expr, ("open",), ("range", lo, hi)
#   ("call", name, [(label, arg)])                         arg: expr or ("lambda", [words], body)

CMP = ("=", "<>", "<", "<=", ">", ">=")


class Parser:
    def __init__(self, tokens):
        self.t, self.i, self.depth = tokens, 0, 0

    def peek(self, k=0):
        return self.t[min(self.i + k, len(self.t) - 1)]

    def advance(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def is_p(self, text, k=0):
        tok = self.peek(k)
        return tok.kind == "PUNCT" and tok.text == text

    def is_kw(self, word, k=0):
        tok = self.peek(k)
        return tok.kind == "WORD" and tok.text.lower() == word

    def expect_p(self, text):
        if not self.is_p(text):
            self.unexpected(f"expected {text!r}")
        return self.advance()

    def expect_kw(self, word):
        if not self.is_kw(word):
            self.unexpected(f"expected {word!r}")
        return self.advance()

    def unexpected(self, detail):
        tok = self.peek()
        if tok.kind == "PUNCT" and tok.text == "^":
            fail("E_FORMULA_AMBIGUOUS", "write the parentheses: (-a)^b, -(a^b), (a^b)^c or a^(b^c)")
        if tok.kind == "PUNCT" and tok.text in CMP:
            fail("E_FORMULA_CHAIN", "comparisons do not chain: write and")
        if tok.kind == "PUNCT" and tok.text == "->":
            fail("E_FORMULA_PLACEMENT", "a lambda is only an argument of map or filter")
        if tok.kind == "DOT":
            fail("E_FORMULA_RESERVED", "'.' after an expression is reserved for methods (1.3b)")
        fail("E_FORMULA_SYNTAX", f"{detail}, found {tok.text or 'the end'!r} at {tok.pos}")

    def body(self):
        e = self.expr()
        if self.peek().kind != "EOF":
            self.unexpected("expected the end of the body")
        return e

    def expr(self):
        self.depth += 1
        if self.depth > LIMIT_DEPTH:
            fail("E_FORMULA_LIMIT", f"nesting deeper than {LIMIT_DEPTH}")
        try:
            if self.is_kw("if"):
                if self.is_p("(", 1) and self.function_form_if():
                    return self.or_expr()
                return self.if_expr()
            if self.is_kw("let"):
                return self.let_expr()
            return self.or_expr()
        finally:
            self.depth -= 1

    def function_form_if(self):
        """if ( e , ... is Excel's IF function; anything else is the keyword form."""
        save = self.i
        try:
            self.i += 2
            self.expr()
            return self.is_p(",")
        except FormulaError:
            return False
        finally:
            self.i = save

    def if_expr(self):
        self.expect_kw("if")
        c = self.expr()
        self.expect_kw("then")
        t = self.expr()
        self.expect_kw("else")
        return ("if", c, t, self.expr())

    def let_expr(self):
        self.expect_kw("let")
        tok = self.peek()
        if tok.kind != "WORD" or tok.text.lower() in KEYWORDS or tok.text.lower() in RESERVED:
            if tok.kind == "WORD":
                fail("E_FORMULA_RESERVED", f"{tok.text} cannot be a name")
            self.unexpected("expected a name")
        self.advance()
        self.expect_p("=")
        value = self.expr()
        self.expect_kw("in")
        return ("let", tok.text, value, self.expr())

    def or_expr(self):
        a = self.and_expr()
        while self.is_kw("or"):
            self.advance()
            a = ("op", "or", [a, self.and_expr()])
        return a

    def and_expr(self):
        a = self.not_expr()
        while self.is_kw("and"):
            self.advance()
            a = ("op", "and", [a, self.not_expr()])
        return a

    def not_expr(self):
        if self.is_kw("not"):
            self.advance()
            self.depth += 1
            if self.depth > LIMIT_DEPTH:
                fail("E_FORMULA_LIMIT", f"nesting deeper than {LIMIT_DEPTH}")
            try:
                return ("op", "not", [self.not_expr()])
            finally:
                self.depth -= 1
        return self.cmp_expr()

    def cmp_expr(self):
        a = self.cat_expr()
        tok = self.peek()
        if tok.kind == "PUNCT" and tok.text in CMP:
            self.advance()
            b = self.cat_expr()
            nxt = self.peek()
            if nxt.kind == "PUNCT" and nxt.text in CMP:
                fail("E_FORMULA_CHAIN", "comparisons do not chain: write and")
            return ("op", tok.text, [a, b])
        return a

    def cat_expr(self):
        a = self.add_expr()
        while self.is_p("&"):
            self.advance()
            a = ("op", "&", [a, self.add_expr()])
        return a

    def add_expr(self):
        a = self.mul_expr()
        while self.is_p("+") or self.is_p("-"):
            op = self.advance().text
            a = ("op", op, [a, self.mul_expr()])
        return a

    def mul_expr(self):
        a = self.unary()
        while self.is_p("*") or self.is_p("/"):
            op = self.advance().text
            a = ("op", op, [a, self.unary()])
        return a

    def unary(self):
        if self.is_p("-"):
            count = 0
            while self.is_p("-"):
                self.advance()
                count += 1
            x = self.postfix()
            if self.is_p("^"):
                fail("E_FORMULA_AMBIGUOUS", "-a^b: write (-a)^b or -(a^b)")
            for _ in range(count):
                x = ("op", "neg", [x])
            return x
        if self.is_p("+"):
            fail("E_FORMULA_SYNTAX", "there is no unary +")
        return self.power()

    def power(self):
        base = self.postfix()
        if self.is_p("^"):
            self.advance()
            count = 0
            while self.is_p("-"):
                self.advance()
                count += 1
            e = self.postfix()
            for _ in range(count):
                e = ("op", "neg", [e])
            if self.is_p("^"):
                fail("E_FORMULA_AMBIGUOUS", "a^b^c: write (a^b)^c or a^(b^c)")
            return ("op", "^", [base, e])
        return base

    def postfix(self):
        p = self.primary()
        while self.peek().kind == "DOT":  # spec-0.5.0: method calls (16.3)
            self.advance()
            tok = self.peek()
            if tok.kind == "WORD" and self.is_p("(", 1):
                self.advance()
                p = ("method", p, tok.text, False, self.read_args())
            elif tok.kind == "QNAME" and self.is_p("(", 1):
                if tok.pin is not None:
                    fail("E_FORMULA_PLACEMENT", "an extension method is not pinned")
                self.advance()
                p = ("method", p, tok.value, True, self.read_args())
            else:
                fail("E_FORMULA_SYNTAX", f"a method call is .name(...) or .<qualified name>(...), at {tok.pos}")
        if self.is_p("("):
            fail("E_FORMULA_DYNAMIC_NAME", "only a name can be called")
        return p

    def primary(self):
        tok = self.peek()
        k = tok.kind
        if k == "NUM":
            self.advance()
            return ("num", tok.value, tok.unit)
        if k == "STR":
            self.advance()
            return ("str", tok.value)
        if k == "DATE":
            self.advance()
            return ("date", tok.value)
        if k == "INSTANT":
            self.advance()
            return ("instant", tok.value)
        if k in ("QNAME", "ALIAS"):
            self.advance()
            if not self.is_p("("):
                fail("E_FORMULA_SYNTAX", f"{tok.text} must be called: there are no function values")
            args = self.read_args()
            read = ("read", tok.value if k == "QNAME" else None, tok.value if k == "ALIAS" else None, args)
            return read + (tok.pin,) if tok.pin is not None else read
        if k == "PUNCT" and tok.text == "(":
            self.advance()
            self.depth += 1
            if self.depth > LIMIT_DEPTH:
                fail("E_FORMULA_LIMIT", f"nesting deeper than {LIMIT_DEPTH}")
            try:
                e = self.expr()
            finally:
                self.depth -= 1
            self.expect_p(")")
            return e
        if k == "PUNCT" and tok.text in ("*", "["):
            fail("E_FORMULA_PLACEMENT", "* and ranges are arguments of a read only")
        if k == "PERIOD":  # spec-0.5.0: a period key literal (16.3)
            self.advance()
            return ("period", tok.value)
        if k == "WORD":
            w = tok.text.lower()
            if tok.text in RESERVED and self.peek(1).kind == "DOT":  # spec-0.5.0: this.m(), super.m()
                self.advance()
                return (tok.text,)
            if w in RESERVED:
                fail("E_FORMULA_RESERVED", f"{tok.text} is reserved")
            if self.is_p("(", 1):
                if w in FORBIDDEN:
                    fail("E_FORMULA_FORBIDDEN", f"{tok.text}() does not exist: formulas are pure", token=tok.text)
                if w == "if":
                    if self.function_form_if():
                        self.advance()
                        return ("call", "if", self.call_args())
                    fail("E_FORMULA_PLACEMENT", "if ... then ... else as an operand needs parentheses")
                if w in ("and", "or"):
                    self.advance()
                    return ("call", w, self.call_args())
                if w == "not":
                    fail("E_FORMULA_PLACEMENT", "not as an operand needs parentheses")
                if w in KEYWORDS:
                    self.unexpected("unexpected keyword")
                if w in UNSUPPORTED_BUILTINS:
                    fail("E_FORMULA_UNSUPPORTED", f"{tok.text}() is reserved for a later revision")
                if w in BUILTINS:
                    self.advance()
                    return ("call", w, self.call_args())
                fail("E_FORMULA_UNKNOWN_FUNCTION", f"{tok.text} is not a built-in; user functions are "
                     "written qualified or as @alias")
            if w in ("true", "false"):
                self.advance()
                return ("bool", w == "true")
            if w in ("if", "let"):
                fail("E_FORMULA_PLACEMENT", f"{w} as an operand needs parentheses")
            if w in KEYWORDS:
                self.unexpected("unexpected keyword")
            self.advance()
            return ("var", tok.text)
        self.unexpected("expected an expression")

    def label(self):
        if self.peek().kind == "WORD" and self.is_p(":", 1):
            word = self.advance().text
            self.advance()
            return word
        return None

    def lambda_ahead(self):
        """name -> or ( name {, name} ) ->"""
        if self.peek().kind == "WORD" and self.is_p("->", 1):
            return True
        if not self.is_p("("):
            return False
        k = 1
        while True:
            if self.peek(k).kind != "WORD":
                return False
            k += 1
            if self.is_p(")", k):
                return self.is_p("->", k + 1)
            if not self.is_p(",", k):
                return False
            k += 1

    def lambda_(self):
        params = []
        if self.is_p("("):
            self.advance()
            while True:
                params.append(self.advance().text)
                if self.is_p(")"):
                    self.advance()
                    break
                self.advance()
        else:
            params.append(self.advance().text)
        self.expect_p("->")
        return ("lambda", params, self.expr())

    def arg_list(self, read):
        self.expect_p("(")
        args, labelled = [], set()
        if self.is_p(")"):
            self.advance()
            return args
        while True:
            label = self.label()
            if label is None and labelled:
                fail("E_FORMULA_ARG_ORDER", "positional arguments come before labelled ones")
            if label is not None:
                if label in labelled:
                    fail("E_FORMULA_ARG_DUPLICATE", f"{label} is given twice")
                labelled.add(label)
            if read:
                if self.is_p("*") and (self.is_p(",", 1) or self.is_p(")", 1)):
                    self.advance()
                    arg = ("open",)
                elif self.is_p("["):
                    self.advance()
                    lo = self.expr()
                    self.expect_p("..")
                    hi = self.expr()
                    self.expect_p("]")
                    arg = ("range", lo, hi)
                elif self.lambda_ahead():
                    fail("E_FORMULA_PLACEMENT", "a lambda is only an argument of map or filter")
                else:
                    arg = self.expr()
            else:
                if self.is_p("*") and (self.is_p(",", 1) or self.is_p(")", 1)):
                    fail("E_FORMULA_PLACEMENT", "* is an argument of a read only")
                if self.is_p("["):
                    fail("E_FORMULA_PLACEMENT", "a range is an argument of a read only")
                arg = self.lambda_() if self.lambda_ahead() else self.expr()
            args.append((label, arg))
            if self.is_p(","):
                self.advance()
                continue
            self.expect_p(")")
            return args

    def read_args(self):
        return self.arg_list(True)

    def call_args(self):
        return self.arg_list(False)


def parse(source):
    """The surface tree of a body (SPEC 15.3)."""
    tokens = tokenize(source)
    p = Parser(tokens)
    tree = p.body()
    if _count_nodes(tree) > LIMIT_NODES:
        fail("E_FORMULA_LIMIT", f"more than {LIMIT_NODES} nodes")
    return tree


def _count_nodes(node):
    count, stack = 0, [node]
    while stack:
        x = stack.pop()
        if isinstance(x, tuple):
            count += 1
            stack.extend(x[1:])
        elif isinstance(x, list):
            stack.extend(x)
    return count


# ---------------------------------------------------------------------------
# Resolution (SPEC 15.5): the surface tree becomes the canonical AST. Aliases become full names,
# built-in names and keywords lowercase, positional read arguments labelled by the callee's
# signature.order, if(c, a, b) and and(a, b, ...) the keyword forms. Nothing else changes.
# Errors are reported in source order.


def _callee(env, fq):
    if env is None:
        return None
    if fq == env.get("name"):
        return {"code": {"body": "", "lang": "formula"}, "inputs": [], "signature": env["signature"]}
    return env.get("functions", {}).get(fq)


def _pinned(env, fn_hash):
    """The descriptor of a function hash, for a pinned read (super, 16.3)."""
    if env is None:
        return None
    if callable(env.get("by_hash")):
        return env["by_hash"](fn_hash)
    functions = env.get("functions", {})
    candidates = list(env.get("descriptors", [])) + (list(functions.values()) if isinstance(functions, dict) else [])
    for d in candidates:
        if canon.function_hash(d) == fn_hash:
            return d
    return None


def _classes(env):
    return (env or {}).get("classes") or {}


def _method_name(classes, cname, desc, m):
    """The function N/m a method m of an object of class cname reads (16.3, K5, since the classes round): D/m, where D is
    the class that defines an inherited m, else cname/m. An unbound parent hash is E_FORMULA_UNRESOLVED (a body)."""
    try:
        definer = canon.method_definer(classes, desc, m)
    except LookupError as e:
        fail("E_FORMULA_UNRESOLVED", f"no class name is bound to the parent hash {e} of {cname}: its method {m} is "
             "not known (16.3)")
    return f"{cname if definer is None else definer}/{m}"


def _dispatch_fq(classes, cname, m):
    """The function a dispatch over class cname calls for m (16.6, K5)."""
    desc = classes.get(cname)
    if desc is None:
        fail("E_FORMULA_UNRESOLVED", f"{cname} has no binding")
    return _method_name(classes, cname, desc, m)


def _class_of(env, fq):
    """The class descriptor a name is bound to, or None (16.1)."""
    return _classes(env).get(fq)


def resolve(tree, env):
    k = tree[0]
    if k == "num":
        node = {"node": "num", "value": tree[1]}
        if tree[2] is not None:
            node["unit"] = tree[2]
        return node
    if k in ("str", "date", "instant", "bool"):
        return {"node": k, "value": tree[1]}
    if k == "var":
        return {"node": "var", "name": _variable_name(tree[1])}
    if k == "op":
        return {"node": "op", "op": tree[1], "args": [resolve(a, env) for a in tree[2]]}
    if k == "if":
        return {"node": "if", "cond": resolve(tree[1], env), "then": resolve(tree[2], env), "else": resolve(tree[3], env)}
    if k == "let":
        name = _variable_name(tree[1])
        return {"node": "let", "name": name, "value": resolve(tree[2], env), "body": resolve(tree[3], env)}
    if k == "read":
        if tree[1] is not None and _class_of(env, tree[1]) is not None:
            fail("E_FORMULA_METHOD", f"{tree[1]} is a class: an object is not a value, call one of its methods")
        return _resolve_read(tree, env)
    if k == "call":
        return _resolve_call(tree[1], tree[2], env)
    if k == "method":  # spec-0.5.0 (16.3)
        return _resolve_method(tree, env)
    if k == "period":
        fail("E_FORMULA_RESERVED", f"{tree[1]} is a period key literal: an argument of a string key or parameter only")
    if k == "lambda":
        fail("E_FORMULA_PLACEMENT", "a lambda is only an argument of map or filter")
    raise AssertionError(tree)


def _variable_name(word):
    if word.lower() in RESERVED:
        fail("E_FORMULA_RESERVED", f"{word} is reserved")
    if any(c.isupper() for c in word):
        fail("E_FORMULA_RESERVED", f"{word}: words with capitals are reserved for key literals (1.3b)")
    if not is_name(word):
        fail("E_FORMULA_NAME", f"not a name (SPEC 2.2): {word}")
    return word


def _label_name(word):
    if not is_name(word):
        fail("E_FORMULA_NAME", f"not an argument name (SPEC 2.2): {word}")
    return word


def _resolve_read(tree, env):
    _, fq, alias, args = tree[:4]
    if len(tree) > 4:
        if not (env or {}).get("allow_pins"):
            fail("E_FORMULA_PLACEMENT", "a function pinned by hash (name@<fn_hash>) is a request form (SPEC 5.8), "
                 "not part of a body")
        return _resolve_pinned(fq, tree[4], args, env)
    if alias is not None:
        aliases = (env or {}).get("aliases", {})
        if alias not in aliases:
            fail("E_FORMULA_ALIAS", f"@{alias} is not in the alias map")
        fq = aliases[alias]
    callee = _callee(env, fq)
    if env is not None and callee is None:
        fail("E_FORMULA_UNRESOLVED", f"{fq} has no binding")
    bound = {}
    positional = [a for label, a in args if label is None]
    if positional:
        order = callee["signature"].get("order") if callee is not None else None
        if order is None:
            fail("E_FORMULA_POSITIONAL", f"{fq} declares no order: label its arguments")
        if len(positional) > len(order):
            fail("E_FORMULA_ARITY", f"{fq} takes {len(order)} arguments")
    for i, (label, arg) in enumerate(args):
        if label is None:
            name = callee["signature"]["order"][i]
        else:
            name = _label_name(label)
            if name in bound:
                fail("E_FORMULA_ARG_DUPLICATE", f"{name} is bound twice")
        if callee is not None and name not in callee["signature"]["args"]:
            fail("E_FORMULA_ARG_UNKNOWN", f"{fq} has no argument {name}")
        if arg[0] == "open":
            bound[name] = {"node": "open"}
        elif arg[0] == "range":
            bound[name] = {"node": "range", "lo": resolve(arg[1], env), "hi": resolve(arg[2], env)}
        else:
            bound[name] = _resolve_arg(arg, callee["signature"]["args"][name] if callee is not None else None, env)
    if callee is not None:
        _fill_defaults(fq, callee, bound)
    return {"node": "read", "fn": fq, "args": bound}


# -- classes (spec-0.5.0, SPEC 16.3, 16.6, 16.7)


def _is_key_literal(tree):
    """A key literal (16.3): a word with a capital letter that is not a keyword, or a period (1M)."""
    if tree[0] == "period":
        return True
    return tree[0] == "var" and any(c.isupper() for c in tree[1]) and tree[1].lower() not in KEYWORDS \
        and tree[1] not in RESERVED


def _resolve_arg(tree, decl, env, normalisation=None):
    """An argument bound to a declared parameter: key literals are strings there (16.3), and an object
    literal in a class-typed position is its key encoding (16.5)."""
    if decl is not None and _is_key_literal(tree):
        if decl["type"] != "string":
            fail("E_FORMULA_TYPE", f"the key literal {tree[1]} is a string; this argument is a {decl['type']}")
        node = {"node": "str", "value": tree[1]}
    elif decl is not None and decl.get("classes") and tree[0] == "read" and tree[1] is not None \
            and _class_of(env, tree[1]) is not None:
        if tree[1] not in decl["classes"]:
            fail("E_FORMULA_TYPE", f"an object of {tree[1]} where {decl['classes']} is declared")
        obj = _resolve_object(tree, env)
        node = {"node": "str", "value": _encode_object(obj)}
    else:
        node = resolve(tree, env)
    if decl is not None and decl.get("classes") and node["node"] == "str":
        try:
            decoded = canon.decode_key(node["value"])
        except canon.DatumeshError as e:
            fail("E_FORMULA_KEY", f"not an object key (16.5): {e.detail}")
        if decoded["class"] not in decl["classes"]:
            fail("E_FORMULA_TYPE", f"a key of {decoded['class']} where {decl['classes']} is declared")
        try:  # spec-0.5.0 (H3): decoded against its class, when known, exactly as an object literal is (16.5)
            canon.check_key_of_class(decoded, _classes(env))
        except canon.DatumeshError as e:
            fail("E_FORMULA_KEY" if e.code == "E_KEY_NORMALISATION" else "E_FORMULA_TYPE",
                 f"not a key of {decoded['class']} (16.5): {e.detail}")
    if normalisation is None and decl is not None:  # spec-0.5.0 (Q6 b): the argument's own rule
        normalisation = decl.get("key_normalisation")
    if normalisation is not None and node["node"] == "str":
        try:
            canon.check_key_value(normalisation, node["value"])
        except canon.DatumeshError as e:
            fail("E_FORMULA_KEY", f"a literal key (16.4): {e.detail}")
    return node


def _literal_node(decl):
    """A literal default (7, K13) as the node the literal written in the body is: the canonical AST holds it (16.7)."""
    t, v = decl["type"], decl["default"]
    if t == "string":
        return {"node": "str", "value": v}
    if t == "boolean":
        return {"node": "bool", "value": v == "true"}
    if t in ("date", "instant"):
        return {"node": t, "value": v}
    neg = v.startswith("-")
    node = {"node": "num", "value": v[1:] if neg else v}
    if isinstance(decl.get("unit"), str) and decl["unit"] != "1":
        node["unit"] = decl["unit"]
    return {"node": "op", "op": "neg", "args": [node]} if neg else node


def _fill_defaults(fq, callee, bound, skip=()):
    """Unbound arguments: the asof default (16.7, 7), a literal default (K13), then E_FORMULA_ARG_MISSING."""
    for name in canon.keys_in_order(callee["signature"]["args"]):
        if name in bound or name in skip:
            continue
        decl = callee["signature"]["args"][name]
        if decl.get("default") == "asof":
            asof = {"node": "call", "fn": "asof", "args": [], "named": {}}
            bound[name] = asof if decl["type"] == "instant" else {"node": "call", "fn": "date_of", "args": [asof],
                                                                  "named": {}}
            continue
        if "default" in decl:
            bound[name] = _literal_node(decl)
            continue
        fail("E_FORMULA_ARG_MISSING", f"{fq} needs {name} (an open argument is written *)")


def _encode_object(obj):
    """The key encoding of an object all of whose keys are literals (16.5)."""
    name, desc, keys = obj
    out = {}
    for k, node in keys.items():
        decl = desc["keys"][k]
        if node["node"] == "str" and "class" in decl:
            out[k] = canon.decode_key(node["value"])
        elif node["node"] in ("str", "date", "instant"):
            out[k] = {"type": decl.get("type", "string"), "value": node["value"]}
        elif node["node"] == "num" and "unit" not in node:
            out[k] = {"type": "number", "value": node["value"]}
        elif node["node"] == "bool":
            out[k] = {"type": "boolean", "value": node["value"]}
        elif node["node"] == "op" and node["op"] == "neg" and node["args"][0]["node"] == "num":
            out[k] = {"type": "number", "value": "-" + node["args"][0]["value"]}
        else:
            fail("E_FORMULA_PLACEMENT", f"an object in a class-typed key or argument has literal keys ({k})")
    return canon.encode_key(name, out)


def _key_decl(decl):
    """A class key declaration as a parameter declaration."""
    if "class" in decl:
        return {"type": "string", "classes": [decl["class"]], "valid": False}
    return dict(decl, valid=False)


def _resolve_object(tree, env):
    """A read of a class name: an object (16.3). Returns (class name, descriptor, {key: node})."""
    _, fq, alias, args = tree[:4]
    if alias is not None:
        aliases = (env or {}).get("aliases", {})
        if alias not in aliases:
            fail("E_FORMULA_ALIAS", f"@{alias} is not in the alias map")
        fq = aliases[alias]
    if len(tree) > 4:
        fail("E_FORMULA_PLACEMENT", "an object is not pinned in a body")
    desc = _class_of(env, fq)
    if desc is None:
        fail("E_FORMULA_UNRESOLVED", f"{fq} has no binding")
    order = desc["order"]
    keys = {}
    positional = [a for label, a in args if label is None]
    if len(positional) > len(order):
        fail("E_FORMULA_ARITY", f"{fq} has {len(order)} keys")
    for i, (label, arg) in enumerate(args):
        name = order[i] if label is None else _label_name(label)
        if name in keys:
            fail("E_FORMULA_ARG_DUPLICATE", f"{name} is bound twice")
        if name not in desc["keys"]:
            fail("E_FORMULA_ARG_UNKNOWN", f"{fq} has no key {name}")
        if arg[0] in ("open", "range"):
            fail("E_FORMULA_PLACEMENT", "an object binds every key: there are no slices of objects")
        decl = desc["keys"][name]
        keys[name] = _resolve_arg(arg, _key_decl(decl), env, decl.get("key_normalisation"))
    for name in canon.keys_in_order(desc["keys"]):
        if name not in keys:
            fail("E_FORMULA_ARG_MISSING", f"{fq} needs its key {name}")
    return (fq, desc, keys)


def _method_object(recv, env):
    """The receiver of a method call when it is an object known statically: an object read, this, or
    super. Returns (class name, descriptor, {key: node}, parent-pinned) or None."""
    if recv in (("this",), ("super",)):
        name = (env or {}).get("method_of")
        if name is None or _class_of(env, name) is None:
            fail("E_FORMULA_RESERVED", f"{recv[0]} is for the body of a method (16.3)")
        desc = _class_of(env, name)
        sig_args = env["signature"]["args"]
        keys = {k: {"node": "var", "name": k} for k in desc["order"] if k in sig_args}
        if recv == ("super",):
            parent = desc.get("parent")
            if parent is None:
                fail("E_FORMULA_METHOD", "super needs the parent class")
            # spec-0.5.0 (I3): P is the class name parent's hash is bound to in the definer's environment
            # (the first in ascending order should several be); parent stays a hash.
            named = _classes(env)
            pname = next((n for n in canon.keys_in_order(named) if canon.class_hash(named[n]) == parent), None)
            if pname is None:
                fail("E_CLASS_PARENT", f"no class name is bound to the parent's hash {parent} at define")
            return (pname, _class_of(env, pname), keys, True)
        return (name, desc, keys, False)
    if recv[0] == "read" and recv[1] is not None and _class_of(env, recv[1]) is not None:
        fq, desc, keys = _resolve_object(recv, env)
        return (fq, desc, keys, False)
    if recv[0] == "read" and recv[2] is not None:
        alias = recv[2]
        fq = (env or {}).get("aliases", {}).get(alias)
        if fq is not None and _class_of(env, fq) is not None:
            fq, desc, keys = _resolve_object(recv, env)
            return (fq, desc, keys, False)
    return None


def _bind_method_args(fq, callee, key_names, keys, args, env):
    sig = callee["signature"]
    order = sig.get("order", [])
    rest = [n for n in order if n not in key_names]
    bound = dict(keys)
    positional = [a for label, a in args if label is None]
    if len(positional) > len(rest):
        fail("E_FORMULA_ARITY", f"{fq} takes {len(rest)} arguments after its keys")
    for i, (label, arg) in enumerate(args):
        name = rest[i] if label is None else _label_name(label)
        if name in bound:
            fail("E_FORMULA_ARG_DUPLICATE", f"{name} is bound twice (a key comes from the object)")
        if name not in sig["args"]:
            fail("E_FORMULA_ARG_UNKNOWN", f"{fq} has no argument {name}")
        if arg[0] == "open":
            bound[name] = {"node": "open"}
        elif arg[0] == "range":
            bound[name] = {"node": "range", "lo": resolve(arg[1], env), "hi": resolve(arg[2], env)}
        else:
            bound[name] = _resolve_arg(arg, sig["args"][name], env)
    _fill_defaults(fq, callee, bound, skip=key_names)
    return bound


def _resolve_method(tree, env):
    """obj.m(args): a read of the method's function with the object's keys first (16.3); on an
    expression of declared classes, a dispatch (16.6)."""
    _, recv, m, qualified, args = tree
    obj = _method_object(recv, env)
    if obj is None:
        return _resolve_dispatch(tree, env)
    cname, desc, keys, pinned = obj
    if qualified:  # an extension method: a function whose first arguments are the class keys
        fq = m
        callee = _callee(env, fq)
        if callee is None:
            fail("E_FORMULA_UNRESOLVED", f"{fq} has no binding")
        if "order" not in callee["signature"] or callee["signature"]["order"][:len(desc["order"])] != desc["order"] \
                or not all(canon._key_matches(desc["keys"][k], callee["signature"]["args"][k]) for k in desc["order"]):
            fail("E_FORMULA_METHOD", f"{fq} does not take the keys of {cname} first: not an extension method")
        key_names = list(desc["order"])
    else:
        if m not in desc["methods"]:
            fail("E_FORMULA_METHOD", f"{cname} has no method {m}")
        if m == desc.get("lookup"):  # spec-0.5.0 (Q10 a): it takes a label, not an object's keys
            fail("E_FORMULA_METHOD", f"{m} is {cname}'s lookup: read it by its plain name, {cname}/{m}(label)")
        fq = _method_name(_classes(env), cname, desc, m)  # K5: the defining class's name, pinned or not (super too)
        if pinned:
            callee = _pinned(env, desc["methods"][m])
            if callee is None:
                fail("E_FORMULA_UNRESOLVED", f"no descriptor for {fq}@{desc['methods'][m]}")
        else:
            callee = _callee(env, fq)
            if callee is None:
                fail("E_FORMULA_UNRESOLVED", f"{fq} has no binding")
            if fq != (env or {}).get("name") and canon.function_hash(callee) != desc["methods"][m]:
                fail("E_FORMULA_METHOD", f"{fq} is not bound to the method {m} of {cname}")
        key_names = []
        for k in desc["order"]:
            if k not in callee["signature"]["args"]:
                break
            key_names.append(k)
    missing = [k for k in key_names if k not in keys]
    if missing:
        fail("E_FORMULA_METHOD", f"{fq} takes the key {missing[0]}, which this method's own arguments lack")
    bound = _bind_method_args(fq, callee, key_names, {k: keys[k] for k in key_names}, args, env)
    node = {"node": "read", "fn": fq, "args": bound}
    if pinned:
        if any(a["node"] in ("open", "range") for a in bound.values()):
            fail("E_FORMULA_PLACEMENT", "super reads a single cell")
        node["fn_hash"] = desc["methods"][m]
    return node


def _resolve_pinned(fq, fn_hash, args, env):
    """A pinned read in a body: the print of super (16.3), accepted where pins are allowed."""
    callee = _pinned(env, fn_hash)
    if callee is None:
        fail("E_FORMULA_UNRESOLVED", f"no descriptor for {fq}@{fn_hash}")
    order = callee["signature"].get("order", [])
    bound = {}
    for i, (label, arg) in enumerate(args):
        name = order[i] if label is None else _label_name(label)
        if name in bound or name not in callee["signature"]["args"] or arg[0] in ("open", "range"):
            fail("E_FORMULA_PLACEMENT", "a pinned read binds each argument once, to a single cell")
        bound[name] = _resolve_arg(arg, callee["signature"]["args"][name], env)
    _fill_defaults(fq, callee, bound)
    return {"node": "read", "fn": fq, "args": bound, "fn_hash": fn_hash}


def _static_classes(node, env):
    """The classes an expression's object key is of, when declared (16.6), or None."""
    if node["node"] == "var":
        decl = ((env or {}).get("signature") or {}).get("args", {}).get(node["name"])
        return decl.get("classes") if decl else None
    if node["node"] == "read":
        callee = _pinned(env, node["fn_hash"]) if "fn_hash" in node else _callee(env, node["fn"])
        ret = callee["signature"]["returns"] if callee else None
        return ret.get("classes") if isinstance(ret, dict) else None
    if node["node"] == "dispatch":
        callee = _callee(env, _dispatch_fq(_classes(env), node["classes"][0], node["method"]))
        ret = callee["signature"]["returns"] if callee else None
        return ret.get("classes") if isinstance(ret, dict) else None
    if node["node"] == "str":
        try:
            return [canon.decode_key(node["value"])["class"]]
        except canon.DatumeshError:
            return None
    return None


def _resolve_dispatch(tree, env):
    _, recv, m, qualified, args = tree
    on = resolve(recv, env)
    classes = _static_classes(on, env)
    if classes is None:
        fail("E_FORMULA_RESERVED", "'.' after an expression that is not an object (16.3)")
    if qualified:
        fail("E_FORMULA_METHOD", "an extension method is called on an object written out, not on a key value")
    shape, first = None, None
    for c in classes:
        desc = _class_of(env, c)
        if desc is None:
            fail("E_FORMULA_UNRESOLVED", f"{c} has no binding")
        if m not in desc["methods"] or m == desc.get("lookup"):
            fail("E_FORMULA_METHOD", f"{c} has no method {m} to dispatch to")
        fq = _method_name(_classes(env), c, desc, m)  # K5: D/m for an inherited method
        callee = _callee(env, fq)
        if callee is None:
            fail("E_FORMULA_UNRESOLVED", f"{fq} has no binding")
        if canon.function_hash(callee) != desc["methods"][m] and not (env or {}).get("evaluating"):
            # At evaluation (spec-0.5.0, H1) a <class>/m bound to another hash than the class's method
            # is E_FORMULA_DISPATCH at the dispatch's read (16.6), not this define-time code (15.8).
            fail("E_FORMULA_METHOD", f"{fq} is not bound to the method {m} of {c}")
        keys = [k for k in desc["order"] if k in callee["signature"]["args"]]
        this_shape = canon._without_keys(callee["signature"], keys)
        if shape is None:
            shape, first = this_shape, (fq, callee, keys)
        elif this_shape != shape:
            fail("E_FORMULA_DISPATCH", f"{m} has another signature in {c}: a dispatch needs one")
    fq, callee, keys = first
    bound = _bind_method_args(fq, callee, keys, {}, args, env)
    for k in keys:
        bound.pop(k, None)
    if any(a["node"] in ("open", "range") for a in bound.values()):
        fail("E_FORMULA_PLACEMENT", "a dispatched method reads a single cell")
    return {"node": "dispatch", "on": on, "method": m, "classes": list(classes), "args": bound}


def _resolve_call(name, args, env):
    required, optional, variadic = BUILTINS[name]
    if name == "if":
        return _resolve_if(args, env)
    if name in ("and", "or"):
        if any(label is not None for label, _ in args):
            fail("E_FORMULA_ARG_UNKNOWN", f"{name}() takes no labels")
        if len(args) < 2:
            fail("E_FORMULA_ARITY", f"{name}() takes two or more arguments")
        out = _arg(name, None, args[0][1], env)
        for _, a in args[1:]:
            out = {"node": "op", "op": name, "args": [out, _arg(name, None, a, env)]}
        return out
    if variadic:
        if any(label is not None for label, _ in args):
            fail("E_FORMULA_ARG_UNKNOWN", f"{name}() takes no labels")
        if not args:
            fail("E_FORMULA_ARITY", f"{name}() takes one or more arguments")
        return {"node": "call", "fn": name, "args": [_arg(name, None, a, env) for _, a in args], "named": {}}
    if name == "asof":
        if any(label is not None for label, _ in args):
            fail("E_FORMULA_ARG_UNKNOWN", "asof() takes no labels")
        if len(args) not in (0, 2):
            fail("E_FORMULA_ARITY", "asof() or asof(cell, T)")
        return {"node": "call", "fn": "asof", "args": [_arg(name, "cell", a, env) for _, a in args], "named": {}}
    params = required + optional
    bound = {}
    for i, (label, a) in enumerate(args):
        if label is None:
            if i >= len(params):
                fail("E_FORMULA_ARITY", f"{name}() takes at most {len(params)} arguments")
            param = params[i]
        else:
            param = label
            if param not in params:
                fail("E_FORMULA_ARG_UNKNOWN", f"{name}() has no parameter {label}")
            if param in bound:
                fail("E_FORMULA_ARG_DUPLICATE", f"{param} is given twice")
        bound[param] = _arg(name, param, a, env)
    for param in required:
        if param not in bound:
            fail("E_FORMULA_ARITY", f"{name}() needs {param}")
    return {"node": "call", "fn": name, "args": [bound[p] for p in required],
            "named": {p: bound[p] for p in optional if p in bound}}


def _resolve_if(args, env):
    params = ("condition", "then", "else")
    bound = {}
    for i, (label, a) in enumerate(args):
        if label is None and i >= 3:
            fail("E_FORMULA_ARITY", "if() takes three arguments")
        param = params[i] if label is None else label
        if param not in params:
            fail("E_FORMULA_ARG_UNKNOWN", f"if() has no parameter {label}")
        bound[param] = _arg("if", param, a, env)
    if len(bound) != 3:
        fail("E_FORMULA_ARITY", "if() takes three arguments")
    return {"node": "if", "cond": bound["condition"], "then": bound["then"], "else": bound["else"]}


def _arg(fn, param, a, env):
    if a[0] == "lambda":
        if not (fn in ("map", "filter") and param == "fn"):
            fail("E_FORMULA_PLACEMENT", "a lambda is only the second argument of map or filter")
        params = [_variable_name(p) for p in a[1]]
        if len(set(params)) != len(params):
            fail("E_FORMULA_SHADOW", "lambda parameters must differ")
        return {"node": "lambda", "params": params, "body": resolve(a[2], env)}
    if param == "aggregate":
        if a[0] != "var" or a[1].lower() not in AGGREGATES:
            fail("E_FORMULA_ENUM", f"the aggregate of {fn}() is one of {', '.join(AGGREGATES)}")
        return {"node": "agg", "name": a[1].lower()}
    if param == "along":
        if a[0] != "var":
            fail("E_FORMULA_ALONG", "along names an open argument of the slice")
        return {"node": "key", "name": _label_name(a[1])}
    return resolve(a, env)


@deep
def canonical_ast(source, env=None):
    """Parse and resolve. Without an environment, aliases and positional reads are refused."""
    return resolve(parse(source), env)


def ast_hash(ast):
    return canon.sha256_hex(canon.jcs(ast))


# ---------------------------------------------------------------------------
# The printer (SPEC 15.6). parse(print(ast)) = ast for every canonical AST.

PREC = {"or": 1, "and": 2, "not": 3, "=": 4, "<>": 4, "<": 4, "<=": 4, ">": 4, ">=": 4, "&": 5,
        "+": 6, "-": 6, "*": 7, "/": 7, "neg": 8, "^": 9}
PRIMARY = 10


def _level(node):
    k = node["node"]
    if k in ("if", "let", "lambda"):
        return 0
    if k == "op":
        return PREC[node["op"]]
    return PRIMARY


def print_ast(node):
    return _deep_print(node)


def _print(node):
    return _p(node, 0)


def _wrap(node, need):
    text = _p(node, need)
    return f"({text})" if _level(node) < need else text


def _p(node, need=0):
    k = node["node"]
    if k == "num":
        return node["value"] + (" " + node["unit"] if "unit" in node else "")
    if k == "str":
        return '"' + node["value"].replace('"', '""') + '"'
    if k == "bool":
        return "true" if node["value"] else "false"
    if k in ("date", "instant"):
        return node["value"]
    if k in ("var", "agg", "key"):
        return node["name"]
    if k == "open":
        return "*"
    if k == "op":
        op, args = node["op"], node["args"]
        if op == "neg":
            return "-" + _neg_operand(args[0])
        if op == "not":
            return "not " + _wrap(args[0], 3)
        if op == "^":
            e = args[1]
            exponent = "-" + _neg_operand(e["args"][0]) if e["node"] == "op" and e["op"] == "neg" else _wrap(e, PRIMARY)
            return f"{_wrap(args[0], PRIMARY)} ^ {exponent}"
        p = PREC[op]
        left_need = p + 1 if p == 4 else p
        return f"{_wrap(args[0], left_need)} {op} {_wrap(args[1], p + 1)}"
    if k == "if":
        return f"if {_p(node['cond'])} then {_p(node['then'])} else {_p(node['else'])}"
    if k == "let":
        return f"let {node['name']} = {_p(node['value'])} in {_p(node['body'])}"
    if k == "lambda":
        params = node["params"]
        head = params[0] if len(params) == 1 else "(" + ", ".join(params) + ")"
        return f"{head} -> {_p(node['body'])}"
    if k == "read":
        parts = []
        for name in canon.keys_in_order(node["args"]):
            a = node["args"][name]
            if a["node"] == "range":
                parts.append(f"{name}: [{_p(a['lo'])}..{_p(a['hi'])}]")
            else:
                parts.append(f"{name}: {_p(a)}")
        pin = f"@{node['fn_hash']}" if "fn_hash" in node else ""  # spec-0.5.0: the print of super
        return f"{node['fn']}{pin}({', '.join(parts)})"
    if k == "dispatch":  # spec-0.5.0 (16.6)
        parts = [f"{name}: {_p(node['args'][name])}" for name in canon.keys_in_order(node["args"])]
        return f"{_wrap(node['on'], PRIMARY)}.{node['method']}({', '.join(parts)})"
    if k == "call":
        name = node["fn"]
        parts = [_p(a) for a in node["args"]]
        if name in BUILTINS and not BUILTINS[name][2]:
            for param in BUILTINS[name][1]:
                if param in node["named"]:
                    parts.append(f"{param}: {_p(node['named'][param])}")
        return f"{name}({', '.join(parts)})"
    raise AssertionError(node)


def _neg_operand(node):
    if node["node"] == "op" and node["op"] == "neg":
        return "-" + _neg_operand(node["args"][0])
    return _wrap(node, PRIMARY)


# ---------------------------------------------------------------------------
# Types and units (SPEC 15.8, 15.10)

BARE = "BARE"  # a bare literal: takes its context's unit
VARIES = "VARIES"  # a slice element unit that depends on an open argument
ONE = ()
SCALED = (("percent", 1),), (("permille", 1),), (("bp", 1),)
DEGC = (("degC", 1),)
KELVIN = (("K", 1),)
DURATIONS = {"s": Fraction(1), "min": Fraction(60), "h": Fraction(3600), "d": Fraction(86400)}
CONVERT = {
    "ratio": {"1": Fraction(1), "percent": Fraction(1, 100), "permille": Fraction(1, 1000), "bp": Fraction(1, 10000)},
    "length": {"mm": Fraction(1, 1000), "cm": Fraction(1, 100), "m": Fraction(1), "km": Fraction(1000)},
    "time": dict(DURATIONS),
}


def U(*atoms):
    """A unit from atoms with exponent 1, e.g. U("EUR")."""
    return unit_norm({a: 1 for a in atoms})


def unit_norm(d):
    return tuple(sorted((a, e) for a, e in d.items() if e))


def unit_mul(u, v, sign=1):
    d = dict(u)
    for a, e in v:
        d[a] = d.get(a, 0) + sign * e
    return unit_norm(d)


def unit_text(u):
    if u in (BARE, VARIES, None):
        return {BARE: "a bare number", VARIES: "a unit that varies by member", None: "an unknown unit"}[u]
    if u == ONE:
        return "1"
    return " ".join(a if e == 1 else f"{a}^{e}" for a, e in u)


class Ty:
    __slots__ = ("kind", "unit", "elem", "keys", "source", "zero")

    def __init__(self, kind, unit=None, elem=None, keys=None, source=None, zero=False):
        self.kind, self.unit, self.elem, self.keys, self.source, self.zero = kind, unit, elem, keys, source, zero

    def is_slice(self):
        return self.kind == "slice"

    def __repr__(self):
        if self.kind == "slice":
            return f"slice<{self.elem}, {list(self.keys)}>"
        if self.kind == "number":
            return f"number[{unit_text(self.unit)}]"
        return self.kind


class Key:
    __slots__ = ("kind", "unit", "valid")

    def __init__(self, kind, unit, valid):
        self.kind, self.unit, self.valid = kind, unit, valid


def NUM(unit):
    return Ty("number", unit)


def decl_unit(unit, bind):
    """A declared unit (SPEC 7.1) as an internal unit; bind(arg) gives an argument's unit atom,
    VARIES or None."""
    if isinstance(unit, str):
        return ONE if unit == "1" else U(unit)
    if "arg" in unit:
        atom = bind(unit["arg"])
        return atom if atom in (VARIES, None) else U(atom)
    parts = []
    for side in ("of", "per"):
        s = unit[side]
        atom = s if isinstance(s, str) else bind(s["arg"])
        if atom in (VARIES, None):
            return atom
        parts.append(atom)
    return unit_mul(U(parts[0]), U(parts[1]), -1)


class Compiled:
    def __init__(self, ast, ty, inputs, asof_dependent, annotations):
        self.ast = ast
        self.ast_sha256 = ast_hash(ast)
        self.body = print_ast(ast) + "\n"
        self.inputs = sorted(inputs, key=canon._utf16_key)
        self.ty = ty
        self.asof_dependent = asof_dependent
        self.ann = annotations

    def returns(self):
        if self.ty.kind == "number":
            return {"type": "number", "unit": unit_text(self.ty.unit)}
        return {"type": self.ty.kind}


class Checker:
    def __init__(self, env):
        self.env = env
        self.sig = env["signature"]
        self.inputs = set()
        self.asof_dependent = False
        self.lambda_depth = 0
        self.ann = {}

    # -- scope entries: name -> (Ty, unit atom for string names or None)
    def own_scope(self):
        scope = {}
        args = self.sig["args"]
        for name in canon.keys_in_order(args):
            decl = args[name]
            if name in KEYWORDS or name in RESERVED:
                fail("E_FORMULA_RESERVED", f"an argument of a formula cannot be named {name}")
            if decl["type"] == "number":
                ty = NUM(decl_unit(decl["unit"], lambda a: "arg:" + a))
            else:
                ty = Ty(decl["type"])
            scope[name] = (ty, "arg:" + name if decl["type"] == "string" else None)
        return scope

    def check_body(self, ast):
        ty = self.check(ast, self.own_scope())
        returns = self.sig["returns"]
        rtype = returns if isinstance(returns, str) else returns["type"]
        if isinstance(returns, dict) and "classes" in returns:
            returns = rtype  # spec-0.5.0: an object key is a string
        if ty.is_slice():
            fail("E_FORMULA_SLICE_VALUE", "a function returns a scalar, not a slice")
        if ty.kind != rtype:
            fail("E_FORMULA_RETURN_TYPE", f"the body is {ty.kind}; the function returns {rtype}")
        if rtype == "number":
            want = decl_unit(returns["unit"], lambda a: "arg:" + a)
            if ty.unit == BARE:
                if want in SCALED and not ty.zero:
                    fail("E_FORMULA_RETURN_UNIT", f"a bare number cannot be {unit_text(want)}: write the unit")
            elif ty.unit != want:
                fail("E_FORMULA_RETURN_UNIT", f"the body is in {unit_text(ty.unit)}; the function returns {unit_text(want)}")
        return ty

    def check(self, node, scope):
        ty = self._check(node, scope)
        self.ann[id(node)] = ty
        return ty

    def scalar(self, node, scope, what="a scalar"):
        ty = self.check(node, scope)
        if ty.is_slice():
            fail("E_FORMULA_SLICE_VALUE", f"{what} is required here, not a slice")
        return ty

    def _check(self, node, scope):
        k = node["node"]
        if k == "num":
            if "unit" in node:
                return NUM(ONE if node["unit"] == "1" else U(node["unit"]))
            return Ty("number", BARE, zero=node["value"] == "0")
        if k in ("str", "date", "instant"):
            return Ty({"str": "string"}.get(k, k))
        if k == "bool":
            return Ty("boolean")
        if k == "var":
            if node["name"] not in scope:
                fail("E_FORMULA_UNKNOWN_NAME", f"{node['name']} is not an argument, let or lambda name")
            return scope[node["name"]][0]
        if k == "let":
            name = node["name"]
            if name in scope:
                fail("E_FORMULA_SHADOW", f"{name} is already a name here")
            vty = self.check(node["value"], scope)
            inner = dict(scope)
            inner[name] = (vty, self.unit_atom(node["value"], scope))
            return self.check(node["body"], inner)
        if k == "if":
            c = self.scalar(node["cond"], scope)
            if c.kind != "boolean":
                fail("E_FORMULA_TYPE", "an if condition is a boolean")
            t = self.scalar(node["then"], scope, "a scalar branch")
            e = self.scalar(node["else"], scope, "a scalar branch")
            return self.merge(t, e, "the branches of if")
        if k == "op":
            return self.check_op(node, scope)
        if k == "read":
            return self.check_read(node, scope)
        if k == "call":
            return self.check_call(node, scope)
        if k == "dispatch":  # spec-0.5.0 (16.6)
            return self.check_dispatch(node, scope)
        raise AssertionError(node)

    def check_dispatch(self, node, scope):
        if self.lambda_depth:
            fail("E_FORMULA_LAMBDA_READ", "no cell reads inside a lambda: join another slice instead")
        on = self.scalar(node["on"], scope, "an object key")
        if on.kind != "string":
            fail("E_FORMULA_TYPE", "a method is called on an object key, a string")
        first = None
        for c in node["classes"]:
            fq = _dispatch_fq(_classes(self.env), c, node["method"])  # K5
            callee = _callee(self.env, fq)
            if callee is None:
                fail("E_FORMULA_UNRESOLVED", f"{fq} has no binding")
            self.inputs.add(fq)
            first = first or callee
        sig = first["signature"]
        bind = self.bind_unit(node["args"], scope)
        for name in canon.keys_in_order(node["args"]):
            decl = sig["args"][name]
            t = self.scalar(node["args"][name], scope, "an argument")
            self.expect_arg(t, decl["type"], decl_unit(decl["unit"], bind) if decl["type"] == "number" else None,
                            f"{node['method']}({name})")
        returns = sig["returns"]
        if isinstance(returns, str) or "classes" in returns:
            return Ty(returns if isinstance(returns, str) else returns["type"])
        u = decl_unit(returns["unit"], bind)
        if u is None:
            fail("E_FORMULA_UNIT_UNKNOWN", f"the unit of {node['method']}'s value cannot be determined statically")
        return NUM(u)

    def unit_atom(self, node, scope):
        """The unit atom a string expression denotes statically, or None."""
        if node["node"] == "str":
            return node["value"] if canon.is_unit_literal(node["value"]) and node["value"] != "1" else None
        if node["node"] == "var" and node["name"] in scope:
            return scope[node["name"]][1]
        return None

    # -- units
    def adopt(self, bare, want, code="E_FORMULA_UNIT_MISMATCH"):
        if want in SCALED and not bare.zero:
            fail(code, f"a bare number cannot be {unit_text(want)}: write the unit (e.g. 1 {want[0][0]})")
        return want

    def same_unit(self, a, b, what, code="E_FORMULA_UNIT_MISMATCH"):
        """Units of two numbers that must agree; the unit they share."""
        for u in (a.unit, b.unit):
            if u in (VARIES, None):
                fail("E_FORMULA_UNIT_UNKNOWN", f"{what}: the unit varies by member")
        if a.unit == BARE and b.unit == BARE:
            return BARE
        if a.unit == BARE:
            return self.adopt(a, b.unit, code)
        if b.unit == BARE:
            return self.adopt(b, a.unit, code)
        if a.unit != b.unit:
            fail(code, f"{what}: {unit_text(a.unit)} and {unit_text(b.unit)}")
        return a.unit

    def merge(self, a, b, what):
        if a.kind != b.kind:
            fail("E_FORMULA_TYPE", f"{what}: {a.kind} and {b.kind}")
        if a.kind == "number":
            return Ty("number", self.same_unit(a, b, what), zero=a.zero and b.zero)
        return Ty(a.kind)

    def add_units(self, op, a, b):
        ua, ub = a.unit, b.unit
        for u in (ua, ub):
            if u in (VARIES, None):
                fail("E_FORMULA_UNIT_UNKNOWN", "the unit varies by member")
        if DEGC in (ua, ub):
            if ua == DEGC and ub == DEGC:
                if op == "+":
                    fail("E_FORMULA_UNIT_OFFSET", "degC + degC: add a difference (K) to a temperature")
                return KELVIN
            if ua == DEGC and ub in (KELVIN, BARE):
                return DEGC
            if ub == DEGC and ua in (KELVIN, BARE) and op == "+":
                return DEGC
            fail("E_FORMULA_UNIT_OFFSET" if ub == DEGC or ua == DEGC else "E_FORMULA_UNIT_MISMATCH",
                 f"{unit_text(ua)} {op} {unit_text(ub)}")
        return self.same_unit(a, b, f"{op}")

    def check_op(self, node, scope):
        op, args = node["op"], node["args"]
        if op in ("and", "or"):
            for a in args:
                if self.scalar(a, scope).kind != "boolean":
                    fail("E_FORMULA_TYPE", f"{op} takes booleans")
            return Ty("boolean")
        if op == "not":
            if self.scalar(args[0], scope).kind != "boolean":
                fail("E_FORMULA_TYPE", "not takes a boolean")
            return Ty("boolean")
        if op == "neg":
            t = self.check(args[0], scope)
            if t.is_slice():
                if t.elem.kind != "number":
                    fail("E_FORMULA_TYPE", "- takes numbers")
                return Ty("slice", elem=Ty("number", t.elem.unit), keys=t.keys)
            if t.kind != "number":
                fail("E_FORMULA_TYPE", "- takes a number")
            return Ty("number", t.unit, zero=t.zero)
        if op in CMP:
            a, b = self.scalar(args[0], scope, "a scalar operand"), self.scalar(args[1], scope, "a scalar operand")
            if a.kind != b.kind:
                fail("E_FORMULA_TYPE", f"comparing {a.kind} with {b.kind}")
            if op not in ("=", "<>") and a.kind in ("boolean", "blob"):
                fail("E_FORMULA_TYPE", f"{a.kind} values are not ordered")
            if a.kind == "number":
                if not (a.unit == DEGC and b.unit == DEGC):
                    self.same_unit(a, b, f"comparison {op}")
            return Ty("boolean")
        if op == "&":
            for a in args:
                if self.scalar(a, scope).kind != "string":
                    fail("E_FORMULA_TYPE", "& joins strings: use text(x) for other values")
            return Ty("string")
        a, b = self.check(args[0], scope), self.check(args[1], scope)
        if a.is_slice() or b.is_slice():
            return self.check_join(op, a, b)
        return self.arith(op, a, b, args[1])

    def arith(self, op, a, b, exponent_node=None):
        if op in ("+", "-"):
            kinds = (a.kind, b.kind)
            if kinds == ("number", "number"):
                return Ty("number", self.add_units(op, a, b), zero=a.zero and b.zero)
            if a.kind in ("date", "instant") and b.kind == a.kind and op == "-":
                return NUM(U("d") if a.kind == "date" else U("s"))
            if a.kind in ("date", "instant") and b.kind == "number":
                self.duration(a.kind, b)
                return Ty(a.kind)
            if b.kind in ("date", "instant") and a.kind == "number" and op == "+":
                self.duration(b.kind, a)
                return Ty(b.kind)
            fail("E_FORMULA_TYPE", f"{a.kind} {op} {b.kind}")
        if a.kind != "number" or b.kind != "number":
            fail("E_FORMULA_TYPE", f"{op} takes numbers")
        for u in (a.unit, b.unit):
            if u in (VARIES, None):
                fail("E_FORMULA_UNIT_UNKNOWN", "the unit varies by member")
        if op in ("*", "/"):
            if DEGC in (a.unit, b.unit):
                fail("E_FORMULA_UNIT_OFFSET", "degC is a temperature: multiply or divide a difference (K)")
            if a.unit == BARE and b.unit == BARE:
                return Ty("number", BARE)
            ua = ONE if a.unit == BARE else a.unit
            ub = ONE if b.unit == BARE else b.unit
            return NUM(unit_mul(ua, ub, 1 if op == "*" else -1))
        # ^
        if a.unit == DEGC:
            fail("E_FORMULA_UNIT_OFFSET", "degC is a temperature")
        if b.unit not in (BARE, ONE):
            fail("E_FORMULA_EXPONENT", "an exponent is dimensionless")
        if a.unit in (BARE, ONE):
            return Ty("number", a.unit)
        n = self._literal_int(exponent_node) if exponent_node is not None else None
        if n is None:
            fail("E_FORMULA_EXPONENT", "a number with a unit takes an integer literal exponent")
        return NUM(unit_norm({atom: e * n for atom, e in a.unit}))

    def _literal_int(self, node):
        sign = 1
        while node["node"] == "op" and node["op"] == "neg":
            sign, node = -sign, node["args"][0]
        if node["node"] == "num" and "unit" not in node and "." not in node["value"]:
            return sign * int(node["value"])
        return None

    def duration(self, kind, n):
        if kind == "date":
            if n.unit not in (BARE, U("d")):
                fail("E_FORMULA_UNIT_MISMATCH", f"a date moves by days (d), not {unit_text(n.unit)}")
        elif n.unit != BARE and not (len(n.unit) == 1 and n.unit[0][0] in DURATIONS and n.unit[0][1] == 1):
            fail("E_FORMULA_UNIT_MISMATCH", f"an instant moves by a duration (s, min, h, d), not {unit_text(n.unit)}")

    def check_join(self, op, a, b):
        if op == "^":
            fail("E_FORMULA_TYPE", "^ does not apply to slices")
        if a.is_slice() and b.is_slice():
            if list(a.keys) != list(b.keys) or any(a.keys[k].kind != b.keys[k].kind for k in a.keys):
                fail("E_FORMULA_JOIN", "slices join on equal open argument names and key types")
            keys = a.keys
            ea, eb = a.elem, b.elem
        elif a.is_slice():
            keys, ea, eb = a.keys, a.elem, b
        else:
            keys, ea, eb = b.keys, a, b.elem
        return Ty("slice", elem=self.arith(op, ea, eb), keys=keys)

    # -- reads
    def bind_unit(self, read_args, scope):
        def bind(arg):
            a = read_args.get(arg)
            if a is None:
                return None
            if a["node"] in ("open", "range"):
                return VARIES
            return self.unit_atom(a, scope)
        return bind

    def check_read(self, node, scope):
        if self.lambda_depth:
            fail("E_FORMULA_LAMBDA_READ", "no cell reads inside a lambda: join another slice instead")
        fq = node["fn"]
        callee = _pinned(self.env, node["fn_hash"]) if "fn_hash" in node else _callee(self.env, fq)
        if callee is None:
            fail("E_FORMULA_UNRESOLVED", f"{fq} has no binding")
        self.inputs.add(fq)
        sig = callee["signature"]
        stored = callee["code"]["lang"] == "stored"
        bind = self.bind_unit(node["args"], scope)
        keys = {}
        enumeration = 1
        literal_count = True
        for name in canon.keys_in_order(node["args"]):
            a = node["args"][name]
            decl = sig["args"][name]
            want_kind = decl["type"]
            want_unit = decl_unit(decl["unit"], bind) if want_kind == "number" else None
            if a["node"] == "open":
                if not stored and "extent" not in decl:
                    fail("E_FORMULA_UNBOUNDED", f"{fq} declares no extent for {name}: bound it or declare one")
                count = _extent_size(decl)
                enumeration = enumeration * count if count is not None else enumeration
            elif a["node"] == "range":
                if want_kind in ("boolean", "blob"):
                    fail("E_FORMULA_SLICE_BOUND", f"{want_kind} arguments have no order")
                for end in ("lo", "hi"):
                    t = self.scalar(a[end], scope, "a range bound")
                    self.ann[id(a[end])] = t
                    self.expect_arg(t, want_kind, want_unit, f"{fq}({name}: [..])")
                if not stored and "extent" not in decl and want_kind not in ("date", "number"):
                    fail("E_FORMULA_UNBOUNDED", f"a {want_kind} range over {fq} needs a declared extent")
                if not stored:
                    count = _range_size(a, decl)
                    if count is None:
                        literal_count = False
                    else:
                        enumeration *= count
            else:
                if a["node"] == "call" and a["fn"] == "within":
                    fail("E_FORMULA_UNSUPPORTED", "a key-set argument (a read over the keys of a slice) is 1.3b")
                t = self.scalar(a, scope, "an argument")
                self.expect_arg(t, want_kind, want_unit, f"{fq}({name})")
                continue
            key_unit = decl_unit(decl["unit"], bind) if want_kind == "number" else None
            keys[name] = Key(want_kind, key_unit, decl["valid"])
        if not stored and keys and literal_count and enumeration > LIMIT_ENUMERATION:
            fail("E_FORMULA_UNBOUNDED", f"the slice over {fq} has more than {LIMIT_ENUMERATION} cells")
        returns = sig["returns"]
        if isinstance(returns, str):
            elem = Ty(returns)
        elif "classes" in returns:  # spec-0.5.0: an object key, a string
            elem = Ty("string")
        else:
            u = decl_unit(returns["unit"], bind)
            if u is None:
                fail("E_FORMULA_UNIT_UNKNOWN", f"the unit of {fq}'s value cannot be determined statically")
            elem = NUM(u)
        if keys:
            return Ty("slice", elem=elem, keys=keys, source=node)
        return elem

    def expect_arg(self, t, kind, unit, what):
        if t.kind != kind:
            fail("E_FORMULA_TYPE", f"{what} is a {kind}, not a {t.kind}")
        if kind == "number":
            if unit is None:
                fail("E_FORMULA_UNIT_UNKNOWN", f"{what}: its unit cannot be determined statically")
            if t.unit == BARE:
                self.adopt(t, unit)
            elif t.unit != unit and unit != VARIES:
                fail("E_FORMULA_UNIT_MISMATCH", f"{what} is in {unit_text(unit)}, not {unit_text(t.unit)}")

    # -- built-ins
    def check_call(self, node, scope):
        name = node["fn"]
        args, named = node["args"], node["named"]
        return getattr(self, "b_" + name, None)(node, scope, args, named) if hasattr(self, "b_" + name) else self.generic(node, scope)

    def slice_arg(self, node, scope, what):
        t = self.check(node, scope)
        if not t.is_slice():
            fail("E_FORMULA_TYPE", f"{what} takes a slice")
        return t

    def along(self, call, s, named):
        if "along" in named:
            name = named["along"]["name"]
            if name not in s.keys:
                fail("E_FORMULA_ALONG", f"{name} is not an open argument of the slice")
            dim = name
        elif len(s.keys) == 1:
            dim = next(iter(s.keys))
        else:
            valid = [k for k, v in s.keys.items() if v.valid]
            if len(valid) != 1:
                fail("E_FORMULA_ALONG", "name the dimension: along: <argument>")
            dim = valid[0]
        self.ann[("along", id(call))] = dim
        return dim

    def lookup_result(self, s, dim):
        rest = {k: v for k, v in s.keys.items() if k != dim}
        return Ty("slice", elem=s.elem, keys=rest) if rest else s.elem

    def metric(self, key, fn):
        if key.kind not in ("number", "date", "instant"):
            fail("E_FORMULA_METRIC", f"{fn}() needs a metric: {key.kind} keys match exactly (use at)")
        if key.kind == "number" and key.unit in (None, VARIES):
            fail("E_FORMULA_UNIT_UNKNOWN", f"{fn}(): the key's unit cannot be determined statically")

    def bound(self, node, key, scope, fn):
        t = self.scalar(node, scope, "a bound")
        if t.kind != "number":
            fail("E_FORMULA_METRIC", f"the bound of {fn}() is a number")
        if key.kind == "instant":
            ok = t.unit == BARE or (len(t.unit) == 1 and t.unit[0][0] in DURATIONS and t.unit[0][1] == 1)
        elif key.kind == "date":
            ok = t.unit in (BARE, U("d"))
        else:
            ok = t.unit in (BARE, key.unit)
        if not ok:
            fail("E_FORMULA_METRIC", f"the bound of {fn}() is in the wrong unit: {unit_text(t.unit)}")

    def key_value(self, node, key, scope, fn):
        t = self.scalar(node, scope, "a key")
        if t.kind != key.kind:
            fail("E_FORMULA_TYPE", f"{fn}(): the key is a {key.kind}, not a {t.kind}")
        if key.kind == "number":
            if t.unit == BARE:
                self.adopt(t, key.unit)
            elif t.unit != key.unit:
                fail("E_FORMULA_UNIT_MISMATCH", f"{fn}(): the key is in {unit_text(key.unit)}")

    def b_at(self, node, scope, args, named):
        s = self.slice_arg(args[0], scope, "at()")
        dim = self.along(node, s, named)
        self.key_value(args[1], s.keys[dim], scope, "at")
        return self.lookup_result(s, dim)

    def b_latest(self, node, scope, args, named):
        s = self.slice_arg(args[0], scope, "latest()")
        dim = self.along(node, s, named)
        if "bound" in named:
            if s.keys[dim].kind != "instant":
                fail("E_FORMULA_METRIC", "latest() with a bound needs an instant dimension (it is relative to asof())")
            self.bound(named["bound"], s.keys[dim], scope, "latest")
            self.asof_dependent = True
        return self.lookup_result(s, dim)

    def _metric_lookup(self, node, scope, args, named, fn):
        s = self.slice_arg(args[0], scope, f"{fn}()")
        dim = self.along(node, s, named)
        key = s.keys[dim]
        self.metric(key, fn)
        self.key_value(args[1], key, scope, fn)
        if "bound" in named:
            self.bound(named["bound"], key, scope, fn)
        return s, dim, key

    def b_last_before(self, node, scope, args, named):
        s, dim, _ = self._metric_lookup(node, scope, args, named, "last_before")
        return self.lookup_result(s, dim)

    def b_first_after(self, node, scope, args, named):
        s, dim, _ = self._metric_lookup(node, scope, args, named, "first_after")
        return self.lookup_result(s, dim)

    def b_nearest(self, node, scope, args, named):
        s, dim, _ = self._metric_lookup(node, scope, args, named, "nearest")
        return self.lookup_result(s, dim)

    def _by_check(self, node, scope, args, name):
        """spec-0.6.2 (15.13): by's open arguments are open arguments of the slice of the same key type (the
        dimension, E_FORMULA_JOIN); its values must be orderable; the result drops the dimension."""
        s = self.slice_arg(args[0], scope, f"{name}()")
        b = self.slice_arg(args[1], scope, f"{name}()")
        for k in b.keys:
            if k not in s.keys or s.keys[k].kind != b.keys[k].kind:
                fail("E_FORMULA_JOIN", f"{name}(): by's open arguments are open arguments of the slice, of the same type")
        if b.elem.kind in ("boolean", "blob"):
            fail("E_FORMULA_TYPE", f"{name}() needs ordered values in by")
        if b.elem.kind == "number" and b.elem.unit in (VARIES, None):
            fail("E_FORMULA_UNIT_UNKNOWN", f"{name}(): the unit of by's values varies by member")
        rest = {k: v for k, v in s.keys.items() if k not in b.keys}
        return Ty("slice", elem=s.elem, keys=rest) if rest else s.elem

    def b_last_by(self, node, scope, args, named):
        return self._by_check(node, scope, args, "last_by")

    def b_first_by(self, node, scope, args, named):
        return self._by_check(node, scope, args, "first_by")

    def b_within(self, node, scope, args, named):
        s = self.slice_arg(args[0], scope, "within()")
        dim = self.along(node, s, named)
        key = s.keys[dim]
        self.metric(key, "within")
        self.key_value(args[1], key, scope, "within")
        self.bound(args[2], key, scope, "within")
        return Ty("slice", elem=s.elem, keys=s.keys)

    def b_interpolate(self, node, scope, args, named):
        s = self.slice_arg(args[0], scope, "interpolate()")
        dim = self.along(node, s, named)
        key = s.keys[dim]
        self.metric(key, "interpolate")
        self.key_value(args[1], key, scope, "interpolate")
        method = self.enum(named["method"], METHODS, "method") if "method" in named else "linear"
        if "bound" in named:
            self.bound(named["bound"], key, scope, "interpolate")
        if method == "linear":
            if s.elem.kind != "number":
                fail("E_FORMULA_TYPE", "linear interpolation needs number values")
            if s.elem.unit in (VARIES, None):
                fail("E_FORMULA_UNIT_UNKNOWN", "the unit varies by member")
        return self.lookup_result(s, dim)

    def enum(self, node, allowed, what):
        if node["node"] == "str" and what == "method" and node["value"] in UNSUPPORTED_METHODS:
            fail("E_FORMULA_UNSUPPORTED", f"{node['value']} interpolation is not in this revision")
        if node["node"] != "str" or node["value"] not in allowed:
            fail("E_FORMULA_ENUM", f"{what} is a string literal, one of {', '.join(allowed)}")
        self.ann[id(node)] = Ty("string")
        return node["value"]

    def b_map(self, node, scope, args, named, filter_=False):
        s = self.slice_arg(args[0], scope, "map()" if not filter_ else "filter()")
        lam = args[1]
        if lam["node"] != "lambda":
            fail("E_FORMULA_TYPE", "the second argument of map() and filter() is a lambda: x -> ...")
        inner = dict(scope)
        for i, p in enumerate(lam["params"]):
            if p in scope:
                fail("E_FORMULA_SHADOW", f"{p} is already a name here")
            if i == 0:
                inner[p] = (s.elem, None)
            else:
                if p not in s.keys:
                    fail("E_FORMULA_LAMBDA_PARAM", f"{p} is not an open argument of the slice")
                key = s.keys[p]
                inner[p] = (Ty(key.kind, key.unit if key.kind == "number" else None),
                            None)
        self.lambda_depth += 1
        try:
            body = self.scalar(lam["body"], inner, "a scalar result")
        finally:
            self.lambda_depth -= 1
        if filter_:
            if body.kind != "boolean":
                fail("E_FORMULA_TYPE", "the lambda of filter() returns a boolean")
            return Ty("slice", elem=s.elem, keys=s.keys)
        if body.kind == "number" and body.unit == BARE:
            body = NUM(ONE)
        return Ty("slice", elem=body, keys=s.keys)

    def b_filter(self, node, scope, args, named):
        return self.b_map(node, scope, args, named, filter_=True)

    def agg_result(self, name, elem):
        if name == "count":
            return NUM(U("count"))
        if name in ("first", "last"):
            if elem.kind == "number" and elem.unit in (VARIES, None):
                fail("E_FORMULA_UNIT_UNKNOWN", "the unit varies by member")
            return Ty(elem.kind, elem.unit)
        if name in ("min", "max"):
            if elem.kind in ("boolean", "blob"):
                fail("E_FORMULA_TYPE", f"{name}() needs ordered values")
            if elem.kind == "number" and elem.unit in (VARIES, None):
                fail("E_FORMULA_UNIT_UNKNOWN", "the unit varies by member")
            return Ty(elem.kind, elem.unit)
        if elem.kind != "number":
            fail("E_FORMULA_TYPE", f"{name}() needs numbers")
        if elem.unit in (VARIES, None):
            fail("E_FORMULA_UNIT_UNKNOWN", f"{name}(): the unit varies by member")
        if name == "sum" and elem.unit == DEGC:
            fail("E_FORMULA_UNIT_OFFSET", "a sum of temperatures has no meaning: use mean")
        if name in ("stdev", "stdev_p") and elem.unit == DEGC:
            return NUM(KELVIN)
        return Ty("number", elem.unit)

    def b_scan(self, node, scope, args, named):
        s = self.slice_arg(args[0], scope, "scan()")
        self.along(node, s, named)
        return Ty("slice", elem=self.agg_result(args[1]["name"], s.elem), keys=s.keys)

    def b_window(self, node, scope, args, named):
        s = self.slice_arg(args[0], scope, "window()")
        n = self.scalar(args[1], scope)
        if n.kind != "number" or n.unit not in (BARE, ONE, U("count")):
            fail("E_FORMULA_TYPE", "the width of window() is a count")
        self.along(node, s, named)
        return Ty("slice", elem=self.agg_result(args[2]["name"], s.elem), keys=s.keys)

    def generic(self, node, scope):
        name = node["fn"]
        if name in AGGREGATES:
            return self.aggregate(node, scope)
        raise AssertionError(name)

    def aggregate(self, node, scope):
        name, args = node["fn"], node["args"]
        tys = [self.check(a, scope) for a in args]
        if len(tys) == 1 and tys[0].is_slice():
            return self.agg_result(name, tys[0].elem)
        if any(t.is_slice() for t in tys):
            fail("E_FORMULA_TYPE", f"{name}() takes one slice or scalars")
        if name == "count":
            return NUM(U("count"))
        merged = tys[0]
        for t in tys[1:]:
            merged = self.merge(merged, t, f"{name}()")
        if name == "sum" and merged.unit == DEGC and len(tys) > 1:
            fail("E_FORMULA_UNIT_OFFSET", "a sum of temperatures has no meaning: use mean")
        result = self.agg_result(name, merged) if merged.unit != BARE or merged.kind != "number" else merged
        return result

    def b_otherwise(self, node, scope, args, named):
        a = self.scalar(args[0], scope)
        b = self.scalar(args[1], scope)
        return self.merge(a, b, "otherwise()")

    def b_asof(self, node, scope, args, named):
        if not args:
            self.asof_dependent = True
            return Ty("instant")
        self.single_read(args[0], "asof(cell, T)")
        t = self.check(args[0], scope)
        if self.scalar(args[1], scope).kind != "instant":
            fail("E_FORMULA_TYPE", "asof(cell, T): T is an instant")
        return t

    def single_read(self, node, what):
        if node["node"] != "read" or any(a["node"] in ("open", "range") for a in node["args"].values()):
            fail("E_FORMULA_TX_ARG", f"{what} takes one cell read")

    def b_versions(self, node, scope, args, named):
        self.single_read(args[0], "versions(cell, from, to)")
        t = self.check(args[0], scope)
        for a in args[1:]:
            if self.scalar(a, scope).kind != "instant":
                fail("E_FORMULA_TYPE", "versions(cell, from, to): from and to are instants")
        return Ty("slice", elem=t, keys={"tx": Key("instant", None, True)})

    def num_arg(self, node, scope, what, units=None):
        t = self.scalar(node, scope)
        if t.kind != "number":
            fail("E_FORMULA_TYPE", f"{what} is a number")
        if units is not None and t.unit not in units:
            fail("E_FORMULA_UNIT_MISMATCH", f"{what} is dimensionless")
        return t

    def b_abs(self, node, scope, args, named):
        t = self.num_arg(args[0], scope, "abs()")
        return Ty("number", t.unit)

    b_floor = b_ceiling = b_abs

    def b_round(self, node, scope, args, named):
        t = self.num_arg(args[0], scope, "the value")
        if "digits" in named:
            self.num_arg(named["digits"], scope, "digits", (BARE, ONE))
        return Ty("number", t.unit)

    b_round_up = b_round_down = b_round

    def b_mod(self, node, scope, args, named):
        a = self.num_arg(args[0], scope, "mod()")
        b = self.num_arg(args[1], scope, "mod()")
        if DEGC in (a.unit, b.unit):
            fail("E_FORMULA_UNIT_OFFSET", "degC is a temperature")
        return Ty("number", self.same_unit(a, b, "mod()"))

    def b_sqrt(self, node, scope, args, named):
        t = self.num_arg(args[0], scope, "sqrt()")
        if t.unit == BARE:
            return t
        if t.unit == DEGC:
            fail("E_FORMULA_UNIT_OFFSET", "degC is a temperature")
        if any(e % 2 for _, e in t.unit):
            fail("E_FORMULA_EXPONENT", f"sqrt() of {unit_text(t.unit)} has no unit")
        return NUM(unit_norm({a: e // 2 for a, e in t.unit}))

    def b_exp(self, node, scope, args, named):
        self.num_arg(args[0], scope, f"the argument of {node['fn']}()", (BARE, ONE))
        return NUM(ONE)

    b_ln = b_exp

    def b_sin(self, node, scope, args, named):
        self.num_arg(args[0], scope, f"the angle of {node['fn']}() (radians: dimensionless, or deg)",
                     (BARE, ONE, U("deg")))
        return NUM(ONE)

    b_cos = b_sin

    def b_atan2(self, node, scope, args, named):
        y = self.num_arg(args[0], scope, "y")
        x = self.num_arg(args[1], scope, "x")
        if DEGC in (y.unit, x.unit):
            fail("E_FORMULA_UNIT_OFFSET", "degC is a temperature")
        self.same_unit(y, x, "atan2()")
        return NUM(ONE)

    def b_pi(self, node, scope, args, named):
        return NUM(ONE)

    def b_haversine(self, node, scope, args, named):
        for a in args:
            self.num_arg(a, scope, "a latitude or longitude (deg)", (BARE, U("deg")))
        return NUM(U("m"))

    def b_convert(self, node, scope, args, named):
        t = self.num_arg(args[0], scope, "convert()")
        if args[1]["node"] != "str":
            fail("E_FORMULA_ENUM", "the unit of convert() is a string literal")
        self.ann[id(args[1])] = Ty("string")
        target = args[1]["value"]
        if not canon.is_unit_literal(target):
            fail("E_FORMULA_UNIT", f"not a listed unit: {target}")
        source = "1" if t.unit in (BARE, ONE) else (t.unit[0][0] if len(t.unit) == 1 and t.unit[0][1] == 1 else None)
        ok = source in ("degC", "K") and target in ("degC", "K") or (
            source in ("1", "deg") and target in ("1", "deg")) or any(
            source in group and target in group for group in CONVERT.values())
        if not ok:
            fail("E_FORMULA_UNIT_MISMATCH", f"convert() cannot convert {unit_text(t.unit)} to {target}")
        return NUM(ONE if target == "1" else U(target))

    def kind_arg(self, node, scope, kind, what):
        t = self.scalar(node, scope)
        if t.kind != kind:
            fail("E_FORMULA_TYPE", f"{what} is a {kind}")
        return t

    def b_date(self, node, scope, args, named):
        for a in args:
            self.num_arg(a, scope, "date()", (BARE, ONE))
        return Ty("date")

    def b_year(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "date", "the argument")
        return NUM(ONE)

    b_month = b_day = b_weekday = b_year

    def b_end_of_month(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "date", "the argument")
        return Ty("date")

    def calendar(self, node, scope):
        t = self.slice_arg(node, scope, "calendar")
        if len(t.keys) != 1 or next(iter(t.keys.values())).kind != "date":
            fail("E_FORMULA_TYPE", "a calendar is a slice with one open date argument")

    def business(self, named, scope):
        if "calendar" in named:
            self.calendar(named["calendar"], scope)
        if "weekend" in named:
            self.enum(named["weekend"], tuple(WEEKENDS), "weekend")
        if "roll" in named:
            self.enum(named["roll"], ROLLS, "roll")

    def b_add_days(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "date", "the date")
        n = self.num_arg(args[1], scope, "n")
        if n.unit not in (BARE, U("d")):
            fail("E_FORMULA_UNIT_MISMATCH", "add_days() moves by days (d)")
        self.business(named, scope)
        return Ty("date")

    def b_add_months(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "date", "the date")
        self.num_arg(args[1], scope, "n", (BARE, ONE))
        self.business(named, scope)
        return Ty("date")

    def b_business_days(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "date", "from")
        self.kind_arg(args[1], scope, "date", "to")
        self.business(named, scope)
        return NUM(U("d"))

    def b_year_fraction(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "date", "from")
        self.kind_arg(args[1], scope, "date", "to")
        self.enum(args[2], CONVENTIONS, "convention")
        return NUM(ONE)

    def b_is_holiday(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "date", "the date")
        self.calendar(args[1], scope)
        return Ty("boolean")

    def b_date_of(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "instant", "the argument")
        return Ty("date")

    def b_instant(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "date", "the argument")
        return Ty("instant")

    def b_len(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "string", "the text")
        return NUM(ONE)

    def b_upper(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "string", "the text")
        return Ty("string")

    b_lower = b_trim = b_upper

    def b_text_of(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "blob", "the blob")
        return Ty("string")

    def b_remove_chars(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "string", "the text")
        self.kind_arg(args[1], scope, "string", "the characters")
        return Ty("string")

    def b_concat(self, node, scope, args, named):
        for a in args:
            self.kind_arg(a, scope, "string", "concat()")
        return Ty("string")

    def b_substr(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "string", "the text")
        self.num_arg(args[1], scope, "start", (BARE, ONE))
        self.num_arg(args[2], scope, "length", (BARE, ONE))
        return Ty("string")

    def b_find(self, node, scope, args, named):
        self.kind_arg(args[0], scope, "string", "the needle")
        self.kind_arg(args[1], scope, "string", "the text")
        if "start" in named:
            self.num_arg(named["start"], scope, "start", (BARE, ONE))
        return NUM(ONE)

    def b_text(self, node, scope, args, named):
        self.scalar(args[0], scope)
        return Ty("string")

    def b_fixed(self, node, scope, args, named):
        self.num_arg(args[0], scope, "the value")
        self.num_arg(args[1], scope, "digits", (BARE, ONE))
        return Ty("string")


def _extent_size(decl):
    ext = decl.get("extent")
    if ext is None:
        return None
    if isinstance(ext, list):
        return len(ext)
    if decl["type"] == "date":
        return (datetime.date.fromisoformat(ext["hi"]) - datetime.date.fromisoformat(ext["lo"])).days + 1
    return int(Dec.parse(ext["hi"]).to_int() - Dec.parse(ext["lo"]).to_int()) + 1


def _range_size(a, decl):
    lo, hi = a["lo"], a["hi"]
    if decl.get("extent") is not None:
        return _extent_size(decl)
    if lo["node"] != hi["node"] or lo["node"] not in ("date", "num"):
        return None
    if lo["node"] == "date":
        return max(0, (datetime.date.fromisoformat(hi["value"]) - datetime.date.fromisoformat(lo["value"])).days + 1)
    lo_d, hi_d = Dec.parse(lo["value"]), Dec.parse(hi["value"])
    if not (lo_d.is_integer() and hi_d.is_integer()):
        return None
    return max(0, hi_d.to_int() - lo_d.to_int() + 1)


@deep
def compile(source, env):
    """Lex, parse, resolve and check a body against an environment (SPEC 15)."""
    ast = canonical_ast(source, env)
    checker = Checker(env)
    ty = checker.check_body(ast)
    return Compiled(ast, ty, checker.inputs, checker.asof_dependent, checker.ann)


def define(name, signature, source, env):
    """The formula descriptor for a function: body printed, inputs derived (SPEC 15.5)."""
    if "order" not in signature:
        fail("E_FORMULA_ORDER", "a formula's signature declares its argument order")
    env = dict(env, name=name, signature=signature)
    c = compile(source, env)
    return {"code": {"body": c.body, "lang": "formula"}, "inputs": c.inputs, "signature": signature}


def check_descriptor(descriptor, name, env):
    """A formula descriptor is canonical: order present, body printed from its AST, inputs derived."""
    canon.check_function(descriptor)
    if descriptor["code"]["lang"] != "formula":
        fail("E_FORMULA_SYNTAX", "not a formula descriptor")
    if "order" not in descriptor["signature"]:
        fail("E_FORMULA_ORDER", "a formula's signature declares its argument order")
    env = dict(env, name=name, signature=descriptor["signature"])
    body = descriptor["code"]["body"]
    c = compile(body, env)
    if c.body != body:
        fail("E_FORMULA_NOT_CANONICAL", "the body is not the printed form of its AST")
    if c.inputs != descriptor["inputs"]:
        fail("E_FORMULA_INPUTS", f"inputs must be {c.inputs}")
    return c


# ---------------------------------------------------------------------------
# Slice objects, manifests and entries (SPEC 15.13, 10.1)


def slice_object(fn_hash, fq, pattern):
    """pattern: {name: typed scalar | "*" | {"hi", "lo", "type"}}."""
    ns, _, fn = fq.rpartition("/")
    return {"args": pattern, "fn": fn, "fn_hash": fn_hash, "ns": ns}


def members_hash(members):
    return canon.sha256_hex(canon.jcs(sorted(members, key=canon._utf16_key)))


def slice_entry(obj, members):
    return f"slice:{canon.sha256_hex(canon.jcs(obj))}:{members_hash(members)}"


def manifest(obj, members):
    return {"members": sorted(members, key=canon._utf16_key), "slice": obj}


# ---------------------------------------------------------------------------
# Test keys and receipts. Every signed object in a vector uses example domains (D21).

ENGINE_HOST = "mesh.example.net"
KEY_FROM = "2020-01-01T00:00:00.000000Z"
COMPUTED_LICENCE = "CC0-1.0"
COMPUTED_SUMMARY = "Computed by the Datumesh formula reference evaluator."


def host_seed(host):
    return hashlib.sha256(b"datumesh formula test key: " + host.encode()).digest()


def host_key_id(host):
    _, public = canon.keypair(host_seed(host))
    return canon.key_id(public)


def key_env(hosts):
    """A key environment (SPEC 11) publishing one key per host, valid from 2020."""
    env = {}
    for host in sorted(set(hosts) | {ENGINE_HOST}):
        _, public = canon.keypair(host_seed(host))
        doc = {"host": host, "keys": [{"alg": "ed25519", "id": canon.key_id(public), "public": public.hex(),
                                        "valid_from": KEY_FROM}], "proto": canon.PROTO}
        env[host] = {"https": {"status": 200, "body": json.dumps(doc, indent=2)}}
    return env


def stored_receipt(descriptor, fq, args, value, tx, asof=None, summary=None, licence="CC-BY-4.0"):
    """A publisher's receipt for a stored cell (asof = tx by default, SPEC 8.2 rule 1)."""
    ns, _, fn = fq.rpartition("/")
    host = ns.split("/")[0]
    asof = asof or tx
    valid = {k: v for k, v in args.items() if descriptor["signature"]["args"][k]["valid"]}
    unsigned = {
        "asof": asof,
        "cell": {"args": args, "fn": fn, "fn_hash": canon.function_hash(descriptor), "ns": ns},
        "computed_by": f"{host}#{host_key_id(host)}",
        "inputs": [],
        "issued": max(asof, KEY_FROM),
        "licence": licence,
        "proto": canon.PROTO,
        "publisher": ns,
        "summary": summary or f"A recorded value of {fn}.",
        "tx": tx,
        "type": value["type"],
        "valid": valid,
        "value": value["value"],
    }
    return canon.sign_receipt(unsigned, host_seed(host))


# ---------------------------------------------------------------------------
# Values. Scalars are (type, value): numbers carry a Dec, the others their lexical form
# (booleans a bool). A slice is a Ref (not yet read: a read can still be narrowed) or a Mat
# (members, ordered by key tuple).


class Ref:
    __slots__ = ("node", "fq", "pattern", "ty")

    def __init__(self, node, fq, pattern, ty):
        self.node, self.fq, self.pattern, self.ty = node, fq, pattern, ty


class Mat:
    __slots__ = ("keys", "kinds", "members", "elem")

    def __init__(self, keys, kinds, members, elem):
        self.keys, self.kinds, self.members, self.elem = keys, kinds, members, elem


def sort_key(kind, v):
    if kind == "number":
        return v.fraction()
    return v


def typed(value):
    kind, v = value
    if kind == "number":
        return {"type": "number", "value": str(v)}
    return {"type": kind, "value": v}


def untyped(scalar):
    kind, v = scalar["type"], scalar["value"]
    return (kind, Dec.parse(v)) if kind == "number" else (kind, v)


def _tuple_key(kinds, key):
    return tuple(sort_key(k, v) for k, v in zip(kinds, key))


def _date(text):
    return datetime.date.fromisoformat(text)


def _micros(instant):
    d = datetime.datetime.strptime(instant, "%Y-%m-%dT%H:%M:%S.%fZ")
    return (d - datetime.datetime(1, 1, 1)) // datetime.timedelta(microseconds=1)


def _instant_of(micros):
    if not (0 <= micros <= _micros(MAX_INSTANT)):
        raise ArithmeticFault("E_FORMULA_RANGE", "the instant is outside 0001-9999")
    d = datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds=micros)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond:06d}Z"


def _date_of_ordinal(n):
    if not (1 <= n <= datetime.date(9999, 12, 31).toordinal()):
        raise ArithmeticFault("E_FORMULA_RANGE", "the date is outside 0001-9999")
    return datetime.date.fromordinal(n).isoformat()


def _int_of(d, what):
    if not d.is_integer():
        raise FormulaError("E_FORMULA_DOMAIN", f"{what} is an integer")
    return d.to_int()


def _unit_factor(unit, kind):
    """Microseconds (instants) or days (dates) per unit of a duration; 1 for numbers."""
    if kind == "instant":
        atom = "s" if unit == BARE else unit[0][0]
        return DURATIONS[atom] * 1000000
    if kind == "date":
        return Fraction(1)
    return Fraction(1)


def _dim_value(kind, v):
    """A key as an exact number on its metric: microseconds, days, or the number."""
    if kind == "instant":
        return Fraction(_micros(v))
    if kind == "date":
        return Fraction(_date(v).toordinal())
    return v.fraction()


def _from_dim(kind, f, up):
    """The key value at an exact metric position, rounded inward (up for a lower end)."""
    n = -((-f.numerator) // f.denominator) if up else f.numerator // f.denominator
    if kind == "instant":
        return _instant_of(max(0, min(n, _micros(MAX_INSTANT))))
    if kind == "date":
        return _date_of_ordinal(max(1, min(n, datetime.date(9999, 12, 31).toordinal())))
    d = fdecimal.round_fraction(f)
    if d.fraction() != f:  # an exact end that needs more than 34 digits
        raise ArithmeticFault("E_FORMULA_RANGE", "the bounded range's end needs more than 34 digits")
    return d


# ---------------------------------------------------------------------------
# The world a reference evaluation runs in: function bindings and stored receipts.


class Answer:
    __slots__ = ("receipt", "hash", "value", "tx", "asof", "text")

    def __init__(self, receipt):
        self.receipt = receipt
        self.hash = canon.receipt_hash(receipt)
        self.value = untyped({"type": receipt["type"], "value": receipt["value"]})
        self.tx, self.asof = receipt["tx"], receipt["asof"]
        self.text = json.dumps(receipt, ensure_ascii=False)


def _bindings_of(entry):
    """A world's functions entry: one binding {"descriptor", "bound"} or a list of them."""
    items = entry if isinstance(entry, list) else [entry]
    return sorted(items, key=lambda b: b["bound"])


class _BoundAt:
    """The descriptors of the names bound as of an asof: a view, not a copy. It records which
    binding of each name it gave (the typing a compilation used), and may override one name."""

    def __init__(self, world, asof, override=None):
        self.world, self.asof, self.override = world, asof, override or {}
        self.used = {}

    def get(self, name, default=None):
        if name in self.override:
            d = self.override[name]
        else:
            b = self.world.binding_or_none(name, self.asof)
            if b is None:
                return default
            d = b[0]
        self.used[name] = canon.function_hash(d)
        return d


class World:
    """functions: {fully qualified name: {"descriptor": d, "bound": instant}};
    receipts: stored receipts (signed). Evaluation is memoised per (cell, asof)."""

    def __init__(self, functions, receipts=(), fuel=10_000_000, max_depth=2000, blobs=None, classes=None):
        self.blobs = dict(blobs or {})  # spec-0.4.2: sha256 -> content, what the resolver can give
        self.classes = {n: _bindings_of(c) for n, c in (classes or {}).items()}  # spec-0.5.0
        self.functions = functions  # a binding, or a list of bindings of one name (spec-0.4.1 tests)
        self._bindings = {name: [(b["bound"], b["descriptor"], canon.function_hash(b["descriptor"]))
                                 for b in _bindings_of(f)] for name, f in functions.items()}
        self.by_hash = {}
        for r in receipts:
            self.add_receipt(r)
        self.fuel_limit, self.max_depth = fuel, max_depth
        self.memo, self.compiled, self.stack, self.compatible = {}, {}, [], {}
        self.receipts = {}  # hash -> text, of every receipt answered (for resolvers)
        self.manifests = {}  # entry -> manifest text
        self.fuel_left = fuel
        self.evaluations = 0

    def bind(self, fq, descriptor, bound):
        """Bind a name (a test convenience: one binding per name)."""
        if not getattr(self, "_own_functions", False):  # copy the shared spec once, not per binding
            self.functions, self._own_functions = dict(self.functions), True
        self.functions[fq] = {"descriptor": descriptor, "bound": bound}
        self._bindings[fq] = [(bound, descriptor, canon.function_hash(descriptor))]

    def add_receipt(self, r):
        cell = r["cell"]
        cid = canon.sha256_hex(canon.jcs(cell))
        self.by_hash.setdefault(cell["fn_hash"], {}).setdefault(cid, []).append(r)
        self.memo = {}

    def charge(self, n):
        self.fuel_left -= n
        if self.fuel_left < 0:
            fail("E_FORMULA_BUDGET", "fuel exhausted")

    def binding_or_none(self, fq, asof):
        """(descriptor, hash, start) of the binding of fq answering as of asof: the latest begun."""
        found = None
        for bound, d, h in self._bindings.get(fq, ()):
            if bound <= asof:
                found = (d, h, bound)
        return found

    def binding(self, fq, asof):
        b = self.binding_or_none(fq, asof)
        if b is None:
            fail("E_FORMULA_UNRESOLVED", f"{fq} has no binding as of {asof}")
        return b

    def env_at(self, fq, asof, descriptor, override=None):
        return {"name": fq, "signature": descriptor["signature"],
                "functions": _BoundAt(self, asof, override), "aliases": {},
                "classes": self.classes_at(asof), "by_hash": self.descriptor_by_hash, "allow_pins": True,
                "evaluating": True}

    def classes_at(self, asof):
        """spec-0.5.0: the class descriptors bound as of asof."""
        out = {}
        for name, bindings in self.classes.items():
            begun = [b for b in bindings if b["bound"] <= asof]
            if begun:
                out[name] = begun[-1]["descriptor"]
        return out

    def descriptor_by_hash(self, fn_hash):
        """spec-0.5.0: a descriptor by its hash, for a pinned read (the print of super)."""
        for bindings in self._bindings.values():
            for bound, d, h in bindings:
                if h == fn_hash:
                    return d
        return None

    def answer_pinned(self, fq, fn_hash, args, asof):
        """A pinned read: the cell of the function with that hash, under the name read (16.3)."""
        d = self.descriptor_by_hash(fn_hash)
        if d is None:
            fail("E_FORMULA_UNRESOLVED", f"no descriptor for {fq}@{fn_hash}")
        saved = self._bindings.get(fq)
        self._bindings[fq] = [(MIN_INSTANT, d, fn_hash)]
        try:
            return self.answer(fq, args, asof)
        finally:
            if saved is None:
                del self._bindings[fq]
            else:
                self._bindings[fq] = saved

    def compiled_for(self, fq, descriptor, fn_hash, start, asof):
        """The body typed for an evaluation as of asof (SPEC 15.8): against the callees bound as of
        asof; when that fails, against those bound when the function's binding began (its define
        time), so that a callee rebound since makes only a read of it fail (checked at the read)."""
        ck = (fn_hash, asof)
        if ck not in self.compiled:
            body = descriptor["code"]["body"]
            env = self.env_at(fq, asof, descriptor)
            try:
                c = compile(body, env)
            except FormulaError as first:
                env = self.env_at(fq, start, descriptor)
                try:
                    c = compile(body, env)
                except FormulaError:
                    first.define_time = True  # a define-time code at evaluation: the mesh's failure
                    raise first from None
            c.typing = dict(env["functions"].used)
            c.typing_asof = env["functions"].asof
            c.self_fq, c.descriptor = fq, descriptor
            self.compiled[ck] = c
        return self.compiled[ck]

    def check_read(self, compiled, callee, binding):
        """A read of callee sees binding (descriptor, hash, start): the body must also check with
        it (SPEC 15.8, spec-0.4.1); otherwise the read raises the define-time code."""
        if callee == compiled.self_fq or compiled.typing.get(callee) == binding[1]:
            return
        key = (id(compiled), callee, binding[1])
        if key not in self.compatible:
            env = self.env_at(compiled.self_fq, compiled.typing_asof, compiled.descriptor, {callee: binding[0]})
            try:
                compile(compiled.descriptor["code"]["body"], env)
                self.compatible[key] = None
            except FormulaError as e:
                self.compatible[key] = e
        if self.compatible[key] is not None:
            e = self.compatible[key]
            err = FormulaError(e.code, f"{callee} as bound at this read: {e.detail}")
            err.define_time = True  # never a fault, though E_FORMULA_KEY is also one (spec-0.5.0)
            raise err

    def stored_answer(self, fn_hash, cid, asof):
        versions = [r for r in self.by_hash.get(fn_hash, {}).get(cid, []) if r["tx"] <= asof and r["asof"] <= asof]
        if not versions:
            return None
        return Answer(max(versions, key=lambda r: (r["tx"], r["asof"])))

    @deep
    def get(self, fq, args, asof, fuel=None):
        """The answer for a cell as of asof: a request, with its own fuel."""
        self.fuel_left = self.fuel_limit if fuel is None else fuel
        start = self.fuel_left
        answer = self.answer(fq, args, asof)
        self.fuel_used = start - self.fuel_left
        return answer

    def answer(self, fq, args, asof):
        descriptor, fn_hash, start = self.binding(fq, asof)
        ns, _, fn = fq.rpartition("/")
        cell = {"args": args, "fn": fn, "fn_hash": fn_hash, "ns": ns}
        cid = canon.sha256_hex(canon.jcs(cell))
        lang = descriptor["code"]["lang"]
        if lang == "stored":
            a = self.stored_answer(fn_hash, cid, asof)
            if a is None:
                fail("E_FORMULA_NOT_COVERED", f"{fq} has no value as of {asof}")
            self.receipts[a.hash] = a.text
            return a
        if lang != "formula":
            fail("E_FORMULA_UNSUPPORTED", f"no runtime for lang {lang}")
        key = (cid, asof)
        if key in self.memo:
            result = self.memo[key]
            if isinstance(result, FormulaError):
                raise result
            return result
        if cid in self.stack:
            fail("E_FORMULA_CYCLE", f"{fq} reads itself with the same arguments")
        if len(self.stack) >= self.max_depth:
            fail("E_FORMULA_DEPTH", "evaluation deeper than the limit")
        self.stack.append(cid)
        try:
            compiled = self.compiled_for(fq, descriptor, fn_hash, start, asof)
            ctx = Context(self, asof, compiled)
            scope = {name: untyped(v) for name, v in args.items()}
            try:
                value = ctx.eval(compiled.ast, scope)
            except FormulaError as e:
                # A fault holds from the faulted evaluation's latest input asof and binding start
                # (8.2 rule 2, spec-0.4.1): a reader that catches it counts that among its candidates.
                if _no_value(e) and getattr(e, "known", None) is None:
                    e.known = ctx.known()
                raise
            if isinstance(value, (Ref, Mat)):
                fail("E_FORMULA_SLICE_VALUE", "a function returns a scalar")
            receipt = ctx.receipt(cell, descriptor, value)
            self.evaluations += 1
        except FormulaError as e:
            if _no_value(e):
                self.memo[key] = e
            raise
        finally:
            self.stack.pop()
        a = Answer(receipt)
        self.receipts[a.hash] = a.text
        self.memo[key] = a
        return a


# ---------------------------------------------------------------------------
# Evaluation (SPEC 15.12, 15.13)


def check_keys(descriptor, args):
    """spec-0.5.0 (Q6 b): a read's string arguments are canonical under their declared
    key_normalisation; a computed one that is not faults with E_FORMULA_KEY (a property of the cell)."""
    if descriptor is None:
        return
    decls = descriptor["signature"]["args"]
    for name in canon.keys_in_order(args):
        a, rule = args[name], decls.get(name, {}).get("key_normalisation")
        if rule and isinstance(a, dict) and a.get("type") == "string":
            try:
                canon.check_key_value(rule, a["value"])
            except canon.DatumeshError as e:
                fail("E_FORMULA_KEY", f"the argument {name}: {e.detail}")


def _keys_of(desc, keys):
    """The decoded keys bind exactly the class's keys, each of its declared type (16.5)."""
    if set(keys) != set(desc["keys"]):
        return False
    for k, decl in desc["keys"].items():
        v = keys[k]
        if "class" in decl:
            if v.get("class") != decl["class"]:
                return False
        elif v.get("type") != decl["type"]:
            return False
    return True


class Context:
    """One evaluation of one computed cell: its reads, lineage and times."""

    def __init__(self, world, asof, compiled):
        self.world, self.A, self.c = world, asof, compiled
        self.entries = set()
        self.times = []  # (tx, asof) of every input receipt, slice members included
        self.names = set()  # (function name, binding start) of every name read
        self.tx_reads = []  # T of asof(c, T), to of versions(c, from, to)
        self.fault_known = []  # where faults this evaluation's reads returned hold from

    def ty(self, node):
        return self.c.ann[id(node)]

    # -- the computed receipt
    def receipt(self, cell, descriptor, value):
        txs = [t for t, _ in self.times]
        tx = max(txs) if txs else MIN_INSTANT
        if self.c.asof_dependent:
            asof = self.A
        else:
            known = self.known()
            asof = known if known is not None else MIN_INSTANT
            asof = max(asof, tx)
        sig = descriptor["signature"]["args"]
        unsigned = {
            "asof": asof,
            "cell": cell,
            "computed_by": f"{ENGINE_HOST}#{host_key_id(ENGINE_HOST)}",
            "inputs": sorted(self.entries, key=canon._utf16_key),
            "issued": max(asof, KEY_FROM),
            "licence": COMPUTED_LICENCE,
            "proto": canon.PROTO,
            "publisher": cell["ns"],
            "summary": COMPUTED_SUMMARY,
            "tx": tx,
            "type": value[0],
            "valid": {k: v for k, v in cell["args"].items() if sig[k]["valid"]},
            "value": str(value[1]) if value[0] == "number" else value[1],
        }
        return canon.sign_receipt(unsigned, host_seed(ENGINE_HOST))

    def known(self):
        """The latest of the asof candidates of 8.2 rule 2 so far, or None."""
        candidates = [a for _, a in self.times] + [start for _, start in self.names] + self.tx_reads + self.fault_known
        return max(candidates) if candidates else None

    def rely(self, fq, at):
        """Resolve fq as of at, check the read against that binding, and rely on it."""
        b = self.world.binding(fq, at)
        self.names.add((fq, b[2]))
        self.world.check_read(self.c, fq, b)
        return b

    def faulted(self, e):
        known = getattr(e, "known", None)
        if known is not None:
            self.fault_known.append(known)

    def record(self, answer, fq):
        self.entries.add(answer.hash)
        self.times.append((answer.tx, answer.asof))

    # -- evaluation
    def eval(self, node, scope):
        self.world.charge(1)
        k = node["node"]
        if k == "num":
            return ("number", Dec.parse(node["value"]))
        if k == "str":
            return ("string", node["value"])
        if k == "bool":
            return ("boolean", node["value"])
        if k in ("date", "instant"):
            return (k, node["value"])
        if k == "var":
            return scope[node["name"]]
        if k == "let":
            inner = dict(scope)
            inner[node["name"]] = self.eval(node["value"], scope)
            return self.eval(node["body"], inner)
        if k == "if":
            c = self.eval(node["cond"], scope)
            return self.eval(node["then"] if c[1] else node["else"], scope)
        if k == "op":
            return self.eval_op(node, scope)
        if k == "read":
            return self.eval_read(node, scope)
        if k == "call":
            return getattr(self, "f_" + node["fn"])(node, scope)
        if k == "dispatch":  # spec-0.5.0 (16.6)
            return self.eval_dispatch(node, scope)
        raise AssertionError(node)

    def eval_dispatch(self, node, scope):
        # spec-0.5.0 (answer 5): a value that is not the key of an object of a class in the set is a
        # fault, E_FORMULA_DISPATCH_KEY; a class's method not the bound one stays the mesh's failure.
        key = self.eval(node["on"], scope)[1]
        try:
            decoded = canon.decode_key(key)
        except canon.DatumeshError as e:
            fail("E_FORMULA_DISPATCH_KEY", f"the value is not an object key (16.5): {e.detail}")
        c = decoded["class"]
        if c not in node["classes"]:
            fail("E_FORMULA_DISPATCH_KEY", f"{c} is not among the classes {node['classes']} the function dispatches to")
        desc = self.world.classes_at(self.A).get(c)
        if desc is None:  # spec-0.5.0 (H1): not bound as of the read, 15.8's general rule; the mesh's failure
            fail("E_FORMULA_UNRESOLVED", f"{c} has no binding as of {self.A}")
        if not _keys_of(desc, decoded["keys"]):
            fail("E_FORMULA_DISPATCH_KEY", f"the value is not the key of an object of {c}: its keys differ")
        # A key of the class not canonical under its rules is still its key (H2): the method's
        # argument rule faults with E_FORMULA_KEY at the read (check_keys).
        fq = _dispatch_fq(self.world.classes_at(self.A), c, node["method"])  # K5: D/m, as the define reads it
        binding = self.world.binding(fq, self.A)  # E_FORMULA_UNRESOLVED when not bound (H1)
        if desc["methods"].get(node["method"]) != binding[1]:
            # H1: a binding changed since define; the mesh's failure, in place of 15.8's E_FORMULA_METHOD
            fail("E_FORMULA_DISPATCH", f"{fq} is not bound to the method {node['method']} of {c}")
        sig = binding[0]["signature"]["args"]
        args = {}
        for k in desc["order"]:
            if k not in sig:
                break
            v = decoded["keys"][k]
            args[k] = {"type": "string", "value": canon.encode_decoded(v)} if "class" in v else v
        for name, a in sorted(node["args"].items()):
            args[name] = typed(self.eval(a, scope))
        return self.read_cell(fq, args)

    def scalar(self, node, scope):
        return self.eval(node, scope)

    def mat(self, value):
        return self.read_slice(value) if isinstance(value, Ref) else value

    def eval_op(self, node, scope):
        op, args = node["op"], node["args"]
        try:
            if op == "and":
                return ("boolean", self.eval(args[0], scope)[1] and self.eval(args[1], scope)[1])
            if op == "or":
                return ("boolean", self.eval(args[0], scope)[1] or self.eval(args[1], scope)[1])
            if op == "not":
                return ("boolean", not self.eval(args[0], scope)[1])
            if op == "neg":
                v = self.eval(args[0], scope)
                if isinstance(v, (Ref, Mat)):
                    m = self.mat(v)
                    return Mat(m.keys, m.kinds, [(key, ("number", fdecimal.neg(x[1]))) for key, x in m.members], m.elem)
                return ("number", fdecimal.neg(v[1]))
            a = self.eval(args[0], scope)
            b = self.eval(args[1], scope)
            if op in CMP:
                return ("boolean", compare(op, a, b))
            if op == "&":
                return ("string", text_result(a[1] + b[1]))
            ta, tb = self.ty(args[0]), self.ty(args[1])
            if op == "^" and not isinstance(b, (Ref, Mat)):
                n = b[1]
                self.world.charge(min(abs(n.to_int()), 1025) if n.is_integer() else TRANSCENDENTAL_FUEL["pow"])
            if isinstance(a, (Ref, Mat)) or isinstance(b, (Ref, Mat)):
                return self.join(op, a, b, ta, tb)
            return arith(op, a, b, ta, tb)
        except ArithmeticFault as e:
            raise FormulaError(e.code, e.detail) from None

    def join(self, op, a, b, ta, tb):
        if isinstance(a, (Ref, Mat)) and isinstance(b, (Ref, Mat)):
            ma, mb = self.mat(a), self.mat(b)
            other = dict(mb.members)
            members = [(key, arith(op, va, other[key], ta.elem, tb.elem)) for key, va in ma.members if key in other]
            return Mat(ma.keys, ma.kinds, members, ma.elem)
        if isinstance(a, (Ref, Mat)):
            m = self.mat(a)
            return Mat(m.keys, m.kinds, [(key, arith(op, v, b, ta.elem, tb)) for key, v in m.members], m.elem)
        m = self.mat(b)
        return Mat(m.keys, m.kinds, [(key, arith(op, a, v, ta, tb.elem)) for key, v in m.members], m.elem)

    # -- reads
    def eval_read(self, node, scope):
        ty = self.ty(node)
        fq = node["fn"]
        if not ty.is_slice():
            args = {name: typed(self.eval(a, scope)) for name, a in sorted(node["args"].items())}
            if "fn_hash" in node:  # spec-0.5.0: a pinned read, the print of super
                self.world.charge(1)
                check_keys(self.world.descriptor_by_hash(node["fn_hash"]), args)
                answer = self.world.answer_pinned(fq, node["fn_hash"], args, self.A)
                self.record(answer, fq)
                return answer.value
            return self.read_cell(fq, args)
        pattern = {}
        for name in canon.keys_in_order(node["args"]):
            a = node["args"][name]
            if a["node"] == "open":
                pattern[name] = ("open",)
            elif a["node"] == "range":
                lo, hi = self.eval(a["lo"], scope), self.eval(a["hi"], scope)
                if compare(">", lo, hi):
                    fail("E_FORMULA_DOMAIN", f"the range of {name} has lo > hi")
                pattern[name] = ("range", lo, hi)
            else:
                pattern[name] = ("val", self.eval(a, scope))
        return Ref(node, fq, pattern, ty)

    def read_cell(self, fq, args, at=None):
        self.world.charge(1)
        b = self.rely(fq, at or self.A)
        check_keys(b[0], args)
        try:
            answer = self.world.answer(fq, args, at or self.A)
        except FormulaError as e:
            self.faulted(e)
            raise
        self.record(answer, fq)
        return answer.value

    def read_slice(self, ref, narrow=None):
        world = self.world
        descriptor, fn_hash, _ = self.rely(ref.fq, self.A)
        pattern = dict(ref.pattern)
        if narrow is not None:
            dim, lo, hi = narrow
            cur = pattern[dim]
            if cur[0] == "range":
                lo = lo if compare(">", lo, cur[1]) else cur[1]
                hi = hi if compare("<", hi, cur[2]) else cur[2]
            pattern[dim] = ("range", lo, hi)
        obj_args = {}
        for name, p in pattern.items():
            if p[0] == "open":
                obj_args[name] = "*"
            elif p[0] == "range":
                obj_args[name] = {"hi": typed(p[2])["value"], "lo": typed(p[1])["value"], "type": p[1][0]}
            else:
                obj_args[name] = typed(p[1])
        check_keys(descriptor, {n: a for n, a in obj_args.items() if isinstance(a, dict) and "value" in a})
        obj = slice_object(fn_hash, ref.fq, obj_args)
        keys = [n for n in canon.keys_in_order(pattern) if pattern[n][0] != "val"]
        kinds = [descriptor["signature"]["args"][n]["type"] for n in keys]
        members = []
        if descriptor["code"]["lang"] == "stored":
            ns, _, fn = ref.fq.rpartition("/")
            for cid, versions in world.by_hash.get(fn_hash, {}).items():
                cell = versions[0]["cell"]
                if (cell["ns"], cell["fn"]) != (ns, fn):  # one descriptor can serve two names
                    continue
                cell_args = cell["args"]
                if not _matches(cell_args, pattern):
                    continue
                a = world.stored_answer(fn_hash, cid, self.A)
                if a is None:
                    continue
                world.receipts[a.hash] = a.text
                members.append((tuple(untyped(cell_args[n])[1] for n in keys), a))
        else:
            for combo in self.enumerate(descriptor, pattern, keys, kinds):
                args = {}
                for n, p in pattern.items():
                    args[n] = typed(p[1]) if p[0] == "val" else None
                for n, v in zip(keys, combo):
                    args[n] = typed((kinds[keys.index(n)], v))
                try:
                    a = world.answer(ref.fq, args, self.A)
                except FormulaError as e:
                    if _no_value(e):
                        self.faulted(e)
                        absent = FormulaError("E_FORMULA_ABSENT", f"a member of the slice over {ref.fq} has no value")
                        absent.known = getattr(e, "known", None)
                        raise absent from None
                    raise
                members.append((tuple(combo), a))
        members.sort(key=lambda m: _tuple_key(kinds, m[0]))
        world.charge(1 + len(members))
        hashes = [a.hash for _, a in members]
        entry = slice_entry(obj, hashes)
        self.entries.add(entry)
        for _, a in members:
            self.times.append((a.tx, a.asof))
        world.manifests[entry] = json.dumps(manifest(obj, hashes), ensure_ascii=False)
        return Mat(keys, kinds, [(key, a.value) for key, a in members], ref.ty.elem)

    def enumerate(self, descriptor, pattern, keys, kinds):
        domains = []
        for n, kind in zip(keys, kinds):
            decl = descriptor["signature"]["args"][n]
            p = pattern[n]
            ext = decl.get("extent")
            if isinstance(ext, list):
                values = [untyped({"type": kind, "value": v})[1] for v in ext]
            elif ext is not None or p[0] == "range":
                lo = ext["lo"] if ext is not None else typed(p[1])["value"]
                hi = ext["hi"] if ext is not None else typed(p[2])["value"]
                values = _enumerate(kind, lo, hi)
            else:
                fail("E_FORMULA_UNBOUNDED", f"no extent for {n}")
            if p[0] == "range":
                values = [v for v in values if not compare("<", (kind, v), p[1]) and not compare(">", (kind, v), p[2])]
            domains.append(values)
        total = 1
        for d in domains:
            total *= len(d)
        if total > LIMIT_ENUMERATION:
            fail("E_FORMULA_UNBOUNDED", "the slice has more than 1,048,576 cells")
        combos = [()]
        for d in domains:
            combos = [c + (v,) for c in combos for v in d]
        return combos

    # -- built-ins (evaluated)
    def args_of(self, node, scope):
        return [self.eval(a, scope) for a in node["args"]]

    def lookup_slice(self, node, scope, window=None):
        """The slice argument of a lookup, read narrowed by window(dim, kind) -> (lo, hi) or None."""
        value = self.eval(node["args"][0], scope)
        dim = self.c.ann[("along", id(node))]
        if isinstance(value, Ref) and window is not None:
            kind = value.ty.keys[dim].kind
            w = window(kind)
            if w is not None:
                return self.read_slice(value, (dim, (kind, w[0]), (kind, w[1]))), dim
        return self.mat(value), dim

    def bound_of(self, node, scope, kind):
        """A bound as an exact distance on the metric of kind."""
        b = self.eval(node, scope)
        unit = self.ty(node).unit
        if b[1].sign() < 0:
            fail("E_FORMULA_DOMAIN", "a bound is not negative")
        return b[1].fraction() * _unit_factor(unit, kind)

    def groups(self, m, dim):
        i = m.keys.index(dim)
        kind = m.kinds[i]
        groups = {}
        for key, v in m.members:
            rest = key[:i] + key[i + 1:]
            groups.setdefault(rest, []).append((key[i], v))
        for rest in groups:
            groups[rest].sort(key=lambda kv: sort_key(kind, kv[0]))
        rest_keys = m.keys[:i] + m.keys[i + 1:]
        rest_kinds = m.kinds[:i] + m.kinds[i + 1:]
        return kind, groups, rest_keys, rest_kinds

    def per_group(self, m, dim, pick, elem):
        kind, groups, rest_keys, rest_kinds = self.groups(m, dim)
        self.world.charge(len(m.members))
        if not rest_keys:
            found = pick(kind, groups.get((), []))
            if found is None:
                fail("E_FORMULA_ABSENT", "no member qualifies")
            return found
        members = []
        for rest in sorted(groups, key=lambda r: _tuple_key(rest_kinds, r)):
            found = pick(kind, groups[rest])
            if found is not None:
                members.append((rest, found))
        return Mat(rest_keys, rest_kinds, members, elem)

    def f_at(self, node, scope):
        m, dim = self.lookup_slice(node, scope)
        key = self.eval(node["args"][1], scope)

        def pick(kind, items):
            for k, v in items:
                if compare("=", (kind, k), key):
                    return v
            return None
        return self.per_group(m, dim, pick, m.elem)

    def f_latest(self, node, scope):
        bound = None
        if "bound" in node["named"]:
            bound = self.bound_of(node["named"]["bound"], scope, "instant")

        def window(kind):
            if bound is None:
                return None
            return (_from_dim(kind, _dim_value(kind, self.A) - bound, True), MAX_INSTANT)
        m, dim = self.lookup_slice(node, scope, window)

        def pick(kind, items):
            if not items:
                return None
            k, v = items[-1]
            if bound is not None and _dim_value(kind, k) < _dim_value("instant", self.A) - bound:
                return None
            return v
        return self.per_group(m, dim, pick, m.elem)

    def _metric(self, node, scope, below, above):
        x = self.eval(node["args"][1], scope)
        bound = None
        if "bound" in node["named"]:
            bound_node = node["named"]["bound"]
        elif node["fn"] == "within":
            bound_node = node["args"][2]
        else:
            bound_node = None
        dim_kind = {}

        def window(kind):
            nonlocal bound
            dim_kind["k"] = kind
            if bound_node is None:
                return None
            bound = self.bound_of(bound_node, scope, kind)
            xv = _dim_value(kind, x[1])
            lo = _from_dim(kind, xv - bound, True) if below else x[1]
            hi = _from_dim(kind, xv + bound, False) if above else x[1]
            return (lo, hi)
        m, dim = self.lookup_slice(node, scope, window)
        kind = m.kinds[m.keys.index(dim)]
        if bound_node is not None and bound is None:
            bound = self.bound_of(bound_node, scope, kind)
        return m, dim, x, bound

    def f_last_before(self, node, scope):
        m, dim, x, bound = self._metric(node, scope, True, False)

        def pick(kind, items):
            xv = _dim_value(kind, x[1])
            best = None
            for k, v in items:
                kv = _dim_value(kind, k)
                if kv <= xv and (bound is None or xv - kv <= bound):
                    best = v
            return best
        return self.per_group(m, dim, pick, m.elem)

    def f_first_after(self, node, scope):
        m, dim, x, bound = self._metric(node, scope, False, True)

        def pick(kind, items):
            xv = _dim_value(kind, x[1])
            for k, v in items:
                kv = _dim_value(kind, k)
                if kv >= xv and (bound is None or kv - xv <= bound):
                    return v
            return None
        return self.per_group(m, dim, pick, m.elem)

    def _by(self, node, scope, last):
        """spec-0.6.2 (15.13): each member of the slice joined to the member of by with the same values for by's
        open arguments (an inner join); per group of the other open arguments the candidate whose by value is
        greatest (last_by) or least (first_by), a tie to the later or earlier member in key order. No charge
        beyond the two reads (15.12): the reads charge themselves."""
        s = self.mat(self.eval(node["args"][0], scope))
        b = self.mat(self.eval(node["args"][1], scope))
        bkind = self.ty(node["args"][1]).elem.kind
        by_value = {_tuple_key(b.kinds, key): v for key, v in b.members}
        pos = [s.keys.index(k) for k in b.keys]
        rest_idx = [i for i, k in enumerate(s.keys) if k not in b.keys]
        chosen = {}
        for key, value in s.members:  # key order
            bv = by_value.get(_tuple_key(b.kinds, tuple(key[i] for i in pos)))
            if bv is None:
                continue
            rank = sort_key(bkind, bv[1])
            rest = tuple(key[i] for i in rest_idx)
            cur = chosen.get(rest)
            if cur is None or (rank >= cur[0] if last else rank < cur[0]):
                chosen[rest] = (rank, value)
        rest_keys = [s.keys[i] for i in rest_idx]
        rest_kinds = [s.kinds[i] for i in rest_idx]
        if not rest_keys:
            if () not in chosen:
                fail("E_FORMULA_ABSENT", "no member of the slice has a candidate in by")
            return chosen[()][1]
        members = [(rest, found) for rest, (_, found) in
                   sorted(chosen.items(), key=lambda kv: _tuple_key(rest_kinds, kv[0]))]
        return Mat(rest_keys, rest_kinds, members, s.elem)

    def f_last_by(self, node, scope):
        return self._by(node, scope, True)

    def f_first_by(self, node, scope):
        return self._by(node, scope, False)

    def f_nearest(self, node, scope):
        m, dim, x, bound = self._metric(node, scope, True, True)

        def pick(kind, items):
            xv = _dim_value(kind, x[1])
            best, best_d = None, None
            for k, v in items:
                d = abs(_dim_value(kind, k) - xv)
                if bound is not None and d > bound:
                    continue
                if best_d is None or d < best_d:  # a tie keeps the earlier key
                    best, best_d = v, d
            return best
        return self.per_group(m, dim, pick, m.elem)

    def f_within(self, node, scope):
        m, dim, x, bound = self._metric(node, scope, True, True)
        i = m.keys.index(dim)
        kind = m.kinds[i]
        xv = _dim_value(kind, x[1])
        self.world.charge(len(m.members))
        return Mat(m.keys, m.kinds, [(key, v) for key, v in m.members if abs(_dim_value(kind, key[i]) - xv) <= bound],
                   m.elem)

    def f_interpolate(self, node, scope):
        m, dim, x, bound = self._metric(node, scope, True, True)
        method = node["named"]["method"]["value"] if "method" in node["named"] else "linear"

        def pick(kind, items):
            xv = _dim_value(kind, x[1])
            before = [(k, v) for k, v in items if _dim_value(kind, k) <= xv and (bound is None or xv - _dim_value(kind, k) <= bound)]
            if method == "step":
                return before[-1][1] if before else None
            for k, v in items:
                if _dim_value(kind, k) == xv:
                    return v
            after = [(k, v) for k, v in items if _dim_value(kind, k) > xv and (bound is None or _dim_value(kind, k) - xv <= bound)]
            if not before or not after:
                return None
            (k0, v0), (k1, v1) = before[-1], after[0]
            try:
                span = _metric_number(kind, k0, x[1])
                width = _metric_number(kind, k0, k1)
                diff = fdecimal.sub(v1[1], v0[1])
                return ("number", fdecimal.add(v0[1], fdecimal.div(fdecimal.mul(diff, span), width)))
            except ArithmeticFault as e:
                raise FormulaError(e.code, e.detail) from None
        return self.per_group(m, dim, pick, m.elem)

    def f_map(self, node, scope, filter_=False):
        m = self.mat(self.eval(node["args"][0], scope))
        lam = node["args"][1]
        out = []
        for key, v in m.members:
            inner = dict(scope)
            inner[lam["params"][0]] = v
            for p in lam["params"][1:]:
                i = m.keys.index(p)
                inner[p] = (m.kinds[i], key[i])
            r = self.eval(lam["body"], inner)
            if filter_:
                if r[1]:
                    out.append((key, v))
            else:
                out.append((key, r))
        return Mat(m.keys, m.kinds, out, m.elem if filter_ else self.ty(node).elem)

    def f_filter(self, node, scope):
        return self.f_map(node, scope, filter_=True)

    def f_scan(self, node, scope, width=None):
        m = self.mat(self.eval(node["args"][0], scope))
        dim = self.c.ann[("along", id(node))]
        name = node["args"][-1]["name"]
        n = None
        if node["fn"] == "window":
            n = _int_of(self.eval(node["args"][1], scope)[1], "the width")
            if n < 1:
                fail("E_FORMULA_DOMAIN", "the width of window() is at least 1")
        i = m.keys.index(dim)
        kind, groups, _, _ = self.groups(m, dim)
        out = []
        for rest, items in groups.items():
            for j, (k, _) in enumerate(items):
                if n is not None and j < n - 1:
                    continue
                part = items[(j - n + 1) if n is not None else 0:j + 1]
                self.world.charge(len(part) if n is not None else 1)  # window: n per member; scan: 1 (SPEC 15.12)
                key = rest[:i] + (k,) + rest[i:]
                out.append((key, aggregate(name, [v for _, v in part])))
        out.sort(key=lambda kv: _tuple_key(m.kinds, kv[0]))
        return Mat(m.keys, m.kinds, out, self.ty(node).elem)

    def f_window(self, node, scope):
        return self.f_scan(node, scope)

    def f_otherwise(self, node, scope):
        try:
            return self.eval(node["args"][0], scope)
        except FormulaError as e:
            if e.code in CATCHABLE:
                return self.eval(node["args"][1], scope)
            raise

    def f_asof(self, node, scope):
        if not node["args"]:
            return ("instant", self.A)
        read, t_node = node["args"]
        t = self.eval(t_node, scope)[1]
        if t > self.A:
            fail("E_FORMULA_FUTURE", "asof(cell, T) with T after the evaluation asof")
        args = {name: typed(self.eval(a, scope)) for name, a in sorted(read["args"].items())}
        self.tx_reads.append(t)
        return self.read_cell(read["fn"], args, at=t)

    def f_versions(self, node, scope):
        read, f_node, t_node = node["args"]
        f, t = self.eval(f_node, scope)[1], self.eval(t_node, scope)[1]
        if t > self.A:
            fail("E_FORMULA_FUTURE", "versions(cell, from, to) with to after the evaluation asof")
        self.tx_reads.append(t)
        args = {name: typed(self.eval(a, scope)) for name, a in sorted(read["args"].items())}
        fq = read["fn"]
        descriptor, fn_hash, _ = self.rely(fq, self.A)
        if descriptor["code"]["lang"] != "stored":
            fail("E_FORMULA_UNSUPPORTED", "versions() of a computed cell")
        ns, _, fn = fq.rpartition("/")
        cell = {"args": args, "fn": fn, "fn_hash": fn_hash, "ns": ns}
        cid = canon.sha256_hex(canon.jcs(cell))
        versions = [Answer(r) for r in self.world.by_hash.get(fn_hash, {}).get(cid, [])
                    if f <= r["tx"] <= t and r["asof"] <= self.A]
        versions.sort(key=lambda a: a.tx)
        obj = {"cell": cell, "from": f, "to": t}
        hashes = [a.hash for a in versions]
        self.world.charge(1 + len(versions))
        entry = slice_entry(obj, hashes)
        self.entries.add(entry)
        for a in versions:
            self.times.append((a.tx, a.asof))
            self.world.receipts[a.hash] = a.text
        self.world.manifests[entry] = json.dumps(manifest(obj, hashes), ensure_ascii=False)
        return Mat(["tx"], ["instant"], [((a.tx,), a.value) for a in versions], self.ty(node).elem)

    def f_aggregate(self, node, scope):
        name = node["fn"]
        values = self.args_of(node, scope)
        if len(values) == 1 and isinstance(values[0], (Ref, Mat)):
            m = self.mat(values[0])
            values = [v for _, v in m.members]
            n = len(values)
            self.world.charge(n * (max(1, n.bit_length()) if name == "median" else 1))
        return aggregate(name, values)

    f_sum = f_count = f_mean = f_min = f_max = f_first = f_last = f_median = f_stdev = f_stdev_p = f_aggregate

    def _num(self, node, scope):
        return self.eval(node, scope)[1]

    def f_abs(self, node, scope):
        return ("number", fdecimal.abs_(self._num(node["args"][0], scope)))

    def f_floor(self, node, scope):
        return ("number", fdecimal.floor(self._num(node["args"][0], scope)))

    def f_ceiling(self, node, scope):
        return ("number", fdecimal.ceiling(self._num(node["args"][0], scope)))

    def _round(self, node, scope, fn):
        x = self._num(node["args"][0], scope)
        n = _int_of(self._num(node["named"]["digits"], scope), "digits") if "digits" in node["named"] else 0
        return ("number", _fault(fn, x, n))

    def f_round(self, node, scope):
        return self._round(node, scope, fdecimal.round_away)

    def f_round_up(self, node, scope):
        return self._round(node, scope, fdecimal.round_up)

    def f_round_down(self, node, scope):
        return self._round(node, scope, fdecimal.round_down)

    def f_mod(self, node, scope):
        return ("number", _fault(fdecimal.mod, self._num(node["args"][0], scope), self._num(node["args"][1], scope)))

    def f_sqrt(self, node, scope):
        self.world.charge(TRANSCENDENTAL_FUEL["sqrt"])
        return ("number", _fault(fdecimal.sqrt, self._num(node["args"][0], scope)))

    def f_exp(self, node, scope):
        self.world.charge(TRANSCENDENTAL_FUEL["exp"])
        return ("number", _fault(fdecimal.exp, self._num(node["args"][0], scope)))

    def f_ln(self, node, scope):
        self.world.charge(TRANSCENDENTAL_FUEL["ln"])
        return ("number", _fault(fdecimal.ln, self._num(node["args"][0], scope)))

    def _angle(self, node, scope):
        x = self._num(node, scope)
        return fdecimal.deg_to_rad40(x) if self.ty(node).unit == U("deg") else x

    def f_sin(self, node, scope):
        self.world.charge(TRANSCENDENTAL_FUEL["sin"])
        return ("number", _fault(lambda a: fdecimal.final(fdecimal.sin40(a)), self._angle(node["args"][0], scope)))

    def f_cos(self, node, scope):
        self.world.charge(TRANSCENDENTAL_FUEL["cos"])
        return ("number", _fault(lambda a: fdecimal.final(fdecimal.cos40(a)), self._angle(node["args"][0], scope)))

    def f_atan2(self, node, scope):
        self.world.charge(TRANSCENDENTAL_FUEL["atan2"])
        y, x = self._num(node["args"][0], scope), self._num(node["args"][1], scope)
        return ("number", _fault(fdecimal.atan2, y, x))

    def f_pi(self, node, scope):
        return ("number", fdecimal.final(fdecimal.PI))

    def f_haversine(self, node, scope):
        self.world.charge(TRANSCENDENTAL_FUEL["haversine"])
        return ("number", _fault(fdecimal.haversine, *(self._num(a, scope) for a in node["args"])))

    def f_convert(self, node, scope):
        x = self._num(node["args"][0], scope)
        unit = self.ty(node["args"][0]).unit
        source = "1" if unit in (BARE, ONE) else unit[0][0]
        target = node["args"][1]["value"]
        if source == target:
            return ("number", x)
        if source == "degC" and target == "K":
            return ("number", _fault(fdecimal.add, x, Dec.parse("273.15")))
        if source == "K" and target == "degC":
            return ("number", _fault(fdecimal.sub, x, Dec.parse("273.15")))
        if source == "deg" and target == "1":  # degrees to radians, as the trigonometric functions do
            return ("number", _fault(fdecimal.final, fdecimal.deg_to_rad40(x)))
        if source == "1" and target == "deg":
            return ("number", _fault(fdecimal.final, fdecimal.wdiv(x, fdecimal.RAD_PER_DEG)))
        for group in CONVERT.values():
            if source in group and target in group:
                return ("number", _fault(fdecimal.round_fraction, x.fraction() * group[source] / group[target]))
        raise AssertionError((source, target))

    def f_date(self, node, scope):
        y, m, d = (_int_of(v[1], "date()") for v in self.args_of(node, scope))
        try:
            return ("date", datetime.date(y, m, d).isoformat())
        except (ValueError, OverflowError):
            fail("E_FORMULA_DOMAIN", f"date({y}, {m}, {d}) is not a day")

    def _d(self, node, scope):
        return _date(self.eval(node, scope)[1])

    def f_year(self, node, scope):
        return ("number", Dec.of_int(self._d(node["args"][0], scope).year))

    def f_month(self, node, scope):
        return ("number", Dec.of_int(self._d(node["args"][0], scope).month))

    def f_day(self, node, scope):
        return ("number", Dec.of_int(self._d(node["args"][0], scope).day))

    def f_weekday(self, node, scope):
        return ("number", Dec.of_int(self._d(node["args"][0], scope).isoweekday()))

    def f_end_of_month(self, node, scope):
        return ("date", _end_of_month(self._d(node["args"][0], scope)).isoformat())

    def holidays(self, node, scope):
        if node is None:
            return frozenset()
        m = self.mat(self.eval(node, scope))
        return frozenset(key[0] for key, _ in m.members)

    def business(self, node, scope):
        named = node["named"]
        on = "calendar" in named or "weekend" in named or "roll" in named
        weekend = WEEKENDS[named["weekend"]["value"]] if "weekend" in named else WEEKENDS["sat-sun"]
        return on, self.holidays(named.get("calendar"), scope), weekend

    def f_add_days(self, node, scope):
        d = self._d(node["args"][0], scope)
        n = _int_of(self._num(node["args"][1], scope), "n")
        on, holidays, weekend = self.business(node, scope)
        if not on:
            return ("date", _fault(_date_of_ordinal, d.toordinal() + n))
        step = 1 if n >= 0 else -1
        ordinal, left = d.toordinal(), abs(n)
        while left:
            ordinal += step
            self.world.charge(1)
            day = _fault(_date_of_ordinal, ordinal)
            if _business_day(day, holidays, weekend):
                left -= 1
        return ("date", _date_of_ordinal(ordinal))

    def f_add_months(self, node, scope):
        d = self._d(node["args"][0], scope)
        n = _int_of(self._num(node["args"][1], scope), "n")
        months = d.year * 12 + d.month - 1 + n
        y, m = divmod(months, 12)
        if not 1 <= y <= 9999:
            fail("E_FORMULA_RANGE", "the date is outside 0001-9999")
        last = _end_of_month(datetime.date(y, m + 1, 1)).day
        out = datetime.date(y, m + 1, min(d.day, last))
        on, holidays, weekend = self.business(node, scope)
        if on:
            roll = node["named"]["roll"]["value"] if "roll" in node["named"] else "following"
            out = _roll(out, roll, holidays, weekend, self.world)
        return ("date", out.isoformat())

    def f_business_days(self, node, scope):
        a, b = self._d(node["args"][0], scope), self._d(node["args"][1], scope)
        _, holidays, weekend = self.business(node, scope)
        sign = 1
        if a > b:
            a, b, sign = b, a, -1
        count = 0
        for o in range(a.toordinal(), b.toordinal() + 1):
            self.world.charge(1)
            if _business_day(datetime.date.fromordinal(o).isoformat(), holidays, weekend):
                count += 1
        return ("number", Dec.of_int(sign * count))

    def f_year_fraction(self, node, scope):
        a, b = self._d(node["args"][0], scope), self._d(node["args"][1], scope)
        return ("number", _fault(fdecimal.round_fraction, year_fraction(a, b, node["args"][2]["value"])))

    def f_is_holiday(self, node, scope):
        d = self.eval(node["args"][0], scope)[1]
        return ("boolean", d in self.holidays(node["args"][1], scope))

    def f_date_of(self, node, scope):
        return ("date", self.eval(node["args"][0], scope)[1][:10])

    def f_instant(self, node, scope):
        return ("instant", self.eval(node["args"][0], scope)[1] + "T00:00:00.000000Z")

    def _s(self, node, scope):
        return self.eval(node, scope)[1]

    def _charge_text(self, text):
        self.world.charge(1 + len(text.encode("utf-8")) // 64)

    def f_len(self, node, scope):
        return ("number", Dec.of_int(len(self._s(node["args"][0], scope))))

    def f_upper(self, node, scope):
        s = text_result(self._s(node["args"][0], scope).upper())
        self._charge_text(s)
        return ("string", s)

    def f_lower(self, node, scope):
        s = text_result(self._s(node["args"][0], scope).lower())
        self._charge_text(s)
        return ("string", s)

    def f_trim(self, node, scope):
        s = re.sub(" +", " ", self._s(node["args"][0], scope).strip(" "))
        self._charge_text(s)
        return ("string", text_result(s))

    def f_concat(self, node, scope):
        s = text_result("".join(v[1] for v in self.args_of(node, scope)))
        self._charge_text(s)
        return ("string", s)

    def f_substr(self, node, scope):
        s = self._s(node["args"][0], scope)
        start = _int_of(self._num(node["args"][1], scope), "start")
        length = _int_of(self._num(node["args"][2], scope), "length")
        if start < 1 or length < 0:
            fail("E_FORMULA_DOMAIN", "substr() needs start >= 1 and length >= 0")
        return ("string", text_result(s[start - 1:start - 1 + length]))

    def f_find(self, node, scope):
        needle = self._s(node["args"][0], scope)
        hay = self._s(node["args"][1], scope)
        start = _int_of(self._num(node["named"]["start"], scope), "start") if "start" in node["named"] else 1
        if start < 1:
            fail("E_FORMULA_DOMAIN", "find() needs start >= 1")
        if start > len(hay) + 1:
            return ("number", Dec.of_int(0))
        i = hay.find(needle, start - 1)
        return ("number", Dec.of_int(i + 1 if i >= 0 else 0))

    def f_text_of(self, node, scope):
        """spec-0.4.2: a text/plain blob's content as a string (15.7)."""
        sha, length, media = self._s(node["args"][0], scope).split(":", 2)
        if media != "text/plain":
            fail("E_FORMULA_DOMAIN", f"text_of() reads text/plain blobs, not {media}")
        content = self.world.blobs.get(sha)
        if content is None or len(content) != int(length) or hashlib.sha256(content).hexdigest() != sha:
            fail("E_FORMULA_BLOB_UNAVAILABLE", f"the content of blob {sha} is not available")
        self.world.charge(1 + len(content) // 64)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            fail("E_FORMULA_DOMAIN", "the blob's content is not UTF-8")
        s = text_result(text)
        try:
            canon.check_text(s, "$", "string")
        except canon.DatumeshError:
            fail("E_FORMULA_DOMAIN", "the blob's content is not a string (SPEC 3.5): a control or unassigned character")
        return ("string", s)

    def f_remove_chars(self, node, scope):
        """spec-0.4.2: every code point of chars removed from the text, then NFC (15.7)."""
        s = self._s(node["args"][0], scope)
        chars = set(self._s(node["args"][1], scope))
        out = text_result("".join(c for c in s if c not in chars))
        self._charge_text(out)
        return ("string", out)

    def f_text(self, node, scope):
        v = self.eval(node["args"][0], scope)
        if v[0] == "boolean":
            return ("string", "true" if v[1] else "false")
        return ("string", str(v[1]))

    def f_fixed(self, node, scope):
        x = self._num(node["args"][0], scope)
        n = _int_of(self._num(node["args"][1], scope), "digits")
        r = _fault(fdecimal.round_away, x, n)
        text = str(r)
        if n > 0:
            whole, _, frac = text.partition(".")
            text = whole + "." + frac.ljust(n, "0")
        return ("string", text_result(text))


def _fault(fn, *args):
    try:
        return fn(*args)
    except ArithmeticFault as e:
        raise FormulaError(e.code, e.detail) from None


def _matches(cell_args, pattern):
    for name, p in pattern.items():
        v = untyped(cell_args[name])
        if p[0] == "val":
            if typed(v) != typed(p[1]):
                return False
        elif p[0] == "range":
            if v[0] != p[1][0] or compare("<", v, p[1]) or compare(">", v, p[2]):
                return False
    return True


def _enumerate(kind, lo, hi):
    if kind == "date":
        a, b = _date(lo).toordinal(), _date(hi).toordinal()
        return [datetime.date.fromordinal(o).isoformat() for o in range(a, b + 1)]
    lo_d, hi_d = Dec.parse(lo), Dec.parse(hi)
    if not (lo_d.is_integer() and hi_d.is_integer()):
        fail("E_FORMULA_DOMAIN", "a range over a computed number argument has integer ends")
    return [Dec.of_int(i) for i in range(lo_d.to_int(), hi_d.to_int() + 1)]


def _metric_number(kind, a, b):
    """b - a on the metric, as a dialect number: seconds, days, or the number."""
    if kind == "instant":
        return round_micros(_micros(b) - _micros(a))
    if kind == "date":
        return Dec.of_int(_date(b).toordinal() - _date(a).toordinal())
    return fdecimal.sub(b, a)


def round_micros(us):
    return fdecimal.round_fraction(Fraction(us, 1000000))


def compare(op, a, b):
    kind = a[0]
    if kind == "number":
        c = fdecimal.cmp(a[1], b[1])
    else:
        x, y = a[1], b[1]
        c = (x > y) - (x < y)
    return {"=": c == 0, "<>": c != 0, "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[op]


def text_result(s):
    s = unicodedata.normalize("NFC", s)
    if len(s.encode("utf-8")) > 1024:
        raise FormulaError("E_FORMULA_RANGE", "a string is at most 1024 bytes")
    return s


def arith(op, a, b, ta, tb):
    """+ - * / ^ on scalars, with the operand types for dates, instants and durations."""
    try:
        ka, kb = a[0], b[0]
        if op in ("+", "-"):
            if ka == "number" and kb == "number":
                return ("number", (fdecimal.add if op == "+" else fdecimal.sub)(a[1], b[1]))
            if ka == kb == "date":
                return ("number", Dec.of_int(_date(a[1]).toordinal() - _date(b[1]).toordinal()))
            if ka == kb == "instant":
                return ("number", round_micros(_micros(a[1]) - _micros(b[1])))
            if ka in ("date", "instant"):
                point, n, unit, sign = a, b, tb.unit, (1 if op == "+" else -1)
            else:
                point, n, unit, sign = b, a, ta.unit, 1
            if point[0] == "date":
                days = _int_of(n[1], "a number of days")
                return ("date", _date_of_ordinal(_date(point[1]).toordinal() + sign * days))
            us = n[1].fraction() * _unit_factor(unit, "instant")
            if us.denominator != 1:
                raise ArithmeticFault("E_FORMULA_DOMAIN", "an instant moves by whole microseconds")
            return ("instant", _instant_of(_micros(point[1]) + sign * int(us)))
        if op == "*":
            return ("number", fdecimal.mul(a[1], b[1]))
        if op == "/":
            return ("number", fdecimal.div(a[1], b[1]))
        if op == "^":  # an integer exponent is exact; any other is POW-EXPLN (SPEC 15.9.3)
            return ("number", fdecimal.power(a[1], b[1]))
    except ArithmeticFault as e:
        raise FormulaError(e.code, e.detail) from None
    raise AssertionError(op)


def aggregate(name, values):
    try:
        n = len(values)
        if name == "count":
            return ("number", Dec.of_int(n))
        if name == "sum":
            return ("number", fdecimal.sum_exact([v[1] for v in values]))
        if not values:
            raise FormulaError("E_FORMULA_EMPTY", f"{name}() of no members")
        if name == "first":
            return values[0]
        if name == "last":
            return values[-1]
        if name in ("min", "max"):
            best = values[0]
            for v in values[1:]:
                if compare("<" if name == "min" else ">", v, best):
                    best = v
            return best
        nums = [v[1] for v in values]
        if name == "mean":
            return ("number", fdecimal.mean(nums))
        if name == "median":
            return ("number", fdecimal.median(nums))
        if name == "stdev":
            return ("number", fdecimal.stdev(nums))
        if name == "stdev_p":
            return ("number", fdecimal.stdev(nums, population=True))
    except ArithmeticFault as e:
        raise FormulaError(e.code, e.detail) from None
    raise AssertionError(name)


def _end_of_month(d):
    nxt = datetime.date(d.year + (d.month == 12), d.month % 12 + 1, 1) if d.year < 9999 or d.month < 12 else None
    return (nxt - datetime.timedelta(days=1)) if nxt else datetime.date(9999, 12, 31)


def _business_day(day, holidays, weekend):
    return _date(day).weekday() not in weekend and day not in holidays


def _roll(d, roll, holidays, weekend, world):
    def ok(x):
        return _business_day(x.isoformat(), holidays, weekend)
    if roll in ("following", "modified_following"):
        x = d
        while not ok(x):
            world.charge(1)
            x += datetime.timedelta(days=1)
        if roll == "following" or x.month == d.month:
            return x
    x = d
    while not ok(x):
        world.charge(1)
        x -= datetime.timedelta(days=1)
    return x


def _is_leap(y):
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def _last_of_feb(d):
    return d.month == 2 and d.day == (29 if _is_leap(d.year) else 28)


def year_fraction(a, b, convention):
    """The exact year fraction between two dates (SPEC 15.7). Like Excel's YEARFRAC, the order
    of the dates does not matter."""
    if a > b:
        a, b = b, a
    days = b.toordinal() - a.toordinal()
    if convention == "act/360":
        return Fraction(days, 360)
    if convention == "act/365f":
        return Fraction(days, 365)
    if convention == "act/act_isda":
        if a.year == b.year:
            return Fraction(days, 366 if _is_leap(a.year) else 365)
        total = Fraction(datetime.date(a.year + 1, 1, 1).toordinal() - a.toordinal(), 366 if _is_leap(a.year) else 365)
        total += b.year - a.year - 1
        total += Fraction(b.toordinal() - datetime.date(b.year, 1, 1).toordinal(), 366 if _is_leap(b.year) else 365)
        return total
    d1, d2 = a.day, b.day
    if convention == "30/360":  # ISDA bond basis
        d1 = min(d1, 30)
        if d2 == 31 and d1 == 30:
            d2 = 30
    elif convention == "30e/360":
        d1, d2 = min(d1, 30), min(d2, 30)
    elif convention == "30/360_us":  # NASD, as Excel's basis 0
        if _last_of_feb(a) and _last_of_feb(b):
            d2 = 30
        if _last_of_feb(a):
            d1 = 30
        if d2 == 31 and d1 >= 30:
            d2 = 30
        if d1 == 31:
            d1 = 30
    else:
        raise AssertionError(convention)
    return Fraction(360 * (b.year - a.year) + 30 * (b.month - a.month) + (d2 - d1), 360)


# ---------------------------------------------------------------------------
# Vectors (SPEC 11): kinds formula, formula-eval and excel.

assert FAULT_CODES == canon.FORMULA_FAULTS


def world_of(spec, fuel=10_000_000):
    """A World from a vector's world: {"functions": {name: {"descriptor", "bound"}}, "receipts": [...],
    optionally "max_depth"}."""
    blobs = {h: bytes.fromhex(x) for h, x in spec.get("blobs", {}).items()}  # spec-0.4.2
    return World(spec["functions"], spec.get("receipts", []), fuel=fuel, max_depth=spec.get("max_depth", 2000),
                 blobs=blobs, classes=spec.get("classes"))


def evaluate_vector(vec, world):
    asof = vec["asof"]
    answer = world.get(vec["cell"]["fn"], vec["cell"]["args"], asof, fuel=vec.get("fuel"))
    r = answer.receipt
    return {"value": {"type": r["type"], "value": r["value"]}, "lineage": r["inputs"], "tx": r["tx"],
            "receipt_asof": r["asof"], "fuel_used": world.fuel_used, "receipt_hash": answer.hash}


def excel_world(vec):
    world = dict(vec["world"])
    functions = dict(world["functions"])
    env = {"functions": {n: f["descriptor"] for n, f in functions.items()}}
    descriptor = define(vec["cell"]["fn"], vec["signature"], vec["formula"], env)
    functions[vec["cell"]["fn"]] = {"descriptor": descriptor, "bound": KEY_FROM}
    world["functions"] = functions
    return world_of(world, vec.get("fuel", 10_000_000)), descriptor


def run_vector(vec):
    try:
        kind = vec["kind"]
        if kind == "formula":
            c = compile(vec["input"], vec["env"])
            return {"ast": canon.jcs(c.ast).decode(), "ast_sha256": c.ast_sha256, "body": c.body,
                    "inputs": c.inputs, "returns": c.returns(), "asof_dependent": c.asof_dependent}
        if kind == "formula-eval":
            return evaluate_vector(vec, world_of(vec["world"]))
        if kind == "excel":
            world, descriptor = excel_world(vec)
            out = evaluate_vector(vec, world)
            out["body"] = descriptor["code"]["body"]
            return out
        raise ValueError(kind)
    except FormulaError as e:
        out = {"error": e.code, "detail": str(e)}
        if e.token is not None:
            out["token"] = e.token
        return out


_deep_print = deep(_print)
