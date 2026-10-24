# SPDX-License-Identifier: Apache-2.0
"""Decimal arithmetic of the formula dialect (SPEC.md 15.4), with integers only.

Every operation computes its exact result, rounds it once to 34 significant digits with
round-half-even, and then applies the range rule: the result, written in the canonical number
form of SPEC 3.1, has at most 128 characters, or the operation fails with E_FORMULA_RANGE.
There is no negative zero, no exponent form, no infinity and no float anywhere.

A value is a coefficient (a Python int, sign included) and an exponent: value = c * 10**e, kept
normalised (no trailing zeros in c; zero is 0 * 10**0). This is the algorithm a port in another
language follows: 34 digits fit in an unsigned 128-bit integer, and products and quotients need
a wider intermediate. tests/test_decimal.py checks it against Python's decimal module.
"""

import re
from fractions import Fraction
from math import isqrt

PRECISION = 34
MAX_CHARS = 128
MAX_EXPONENT = 1024  # abs(n) in x ^ n

_CANONICAL = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?")


class ArithmeticFault(Exception):
    """An evaluation fault: E_FORMULA_DIV_ZERO, E_FORMULA_DOMAIN, E_FORMULA_RANGE or E_FORMULA_EMPTY."""

    def __init__(self, code, detail=""):
        self.code, self.detail = code, detail
        super().__init__(f"{code}: {detail}")


def _ndigits(n):
    return len(str(n)) if n else 1


class Dec:
    __slots__ = ("c", "e")

    def __init__(self, c, e):
        if c == 0:
            e = 0
        else:
            while c % 10 == 0:
                c //= 10
                e += 1
        self.c, self.e = c, e

    @staticmethod
    def parse(text):
        """A canonical number (SPEC 3.1); anything else is ValueError."""
        if not isinstance(text, str) or not _CANONICAL.fullmatch(text) or text == "-0" or len(text) > MAX_CHARS:
            raise ValueError(f"not a canonical number: {text!r}")
        sign = -1 if text.startswith("-") else 1
        digits = text.lstrip("-")
        whole, _, frac = digits.partition(".")
        return Dec(sign * int(whole + frac), -len(frac))

    @staticmethod
    def of_int(n):
        return Dec(n, 0)

    def __str__(self):
        c, e = self.c, self.e
        if c == 0:
            return "0"
        sign = "-" if c < 0 else ""
        digits = str(abs(c))
        if e >= 0:
            return sign + digits + "0" * e
        point = len(digits) + e
        if point > 0:
            return sign + digits[:point] + "." + digits[point:]
        return sign + "0." + "0" * (-point) + digits

    def __repr__(self):
        return f"Dec({self})"

    def __eq__(self, other):
        return isinstance(other, Dec) and self.c == other.c and self.e == other.e

    def __hash__(self):
        return hash((self.c, self.e))

    def fraction(self):
        return Fraction(self.c) * Fraction(10) ** self.e

    def is_integer(self):
        return self.e >= 0

    def to_int(self):
        assert self.e >= 0
        return self.c * 10 ** self.e

    def is_zero(self):
        return self.c == 0

    def sign(self):
        return (self.c > 0) - (self.c < 0)


def _check_range(d):
    if len(str(d)) > MAX_CHARS:
        raise ArithmeticFault("E_FORMULA_RANGE", "the result does not fit the canonical number form")
    return d


def round_exact(c, e):
    """Round the exact value c * 10**e to 34 significant digits, half-even; then the range rule."""
    if c == 0:
        return Dec(0, 0)
    sign = -1 if c < 0 else 1
    a = abs(c)
    n = _ndigits(a)
    if n > PRECISION:
        drop = n - PRECISION
        q, r = divmod(a, 10 ** drop)
        half = 5 * 10 ** (drop - 1)
        if r > half or (r == half and q % 2 == 1):
            q += 1
        a, e = q, e + drop
    return _check_range(Dec(sign * a, e))


def round_fraction(x):
    """Round an exact rational to 34 significant digits, half-even; then the range rule."""
    if x == 0:
        return Dec(0, 0)
    sign = -1 if x < 0 else 1
    num, den = abs(x.numerator), x.denominator
    # Find k with 10**33 <= num * 10**k / den < 10**34.
    k = PRECISION - 1 - (_ndigits(num) - _ndigits(den))
    while True:
        scaled_num = num * 10 ** k if k >= 0 else num
        scaled_den = den if k >= 0 else den * 10 ** (-k)
        q, r = divmod(scaled_num, scaled_den)
        if q < 10 ** (PRECISION - 1):
            k += 1
        elif q >= 10 ** PRECISION:
            k -= 1
        else:
            break
    twice = 2 * r
    if twice > scaled_den or (twice == scaled_den and q % 2 == 1):
        q += 1
    return _check_range(Dec(sign * q, -k))


def _align(a, b):
    e = min(a.e, b.e)
    return a.c * 10 ** (a.e - e), b.c * 10 ** (b.e - e), e


def add(a, b):
    x, y, e = _align(a, b)
    return round_exact(x + y, e)


def sub(a, b):
    x, y, e = _align(a, b)
    return round_exact(x - y, e)


def mul(a, b):
    return round_exact(a.c * b.c, a.e + b.e)


def div(a, b):
    if b.c == 0:
        raise ArithmeticFault("E_FORMULA_DIV_ZERO", "division by zero")
    return round_fraction(a.fraction() / b.fraction())


def neg(a):
    return Dec(-a.c, a.e)


def abs_(a):
    return Dec(abs(a.c), a.e)


def cmp(a, b):
    x, y, _ = _align(a, b)
    return (x > y) - (x < y)


def sqrt(a):
    """The correctly rounded square root (round-half-even)."""
    if a.c < 0:
        raise ArithmeticFault("E_FORMULA_DOMAIN", "square root of a negative number")
    if a.c == 0:
        return Dec(0, 0)
    c, e = a.c, a.e
    if e % 2:  # make the exponent even
        c, e = c * 10, e - 1
    # Scale by 10**(2p) so that the integer root has at least PRECISION + 2 digits.
    p = max(0, PRECISION + 2 - (_ndigits(c) + 1) // 2)
    n = c * 10 ** (2 * p)
    t = isqrt(n)  # sqrt(n) = t + f, 0 <= f < 1
    exact = t * t == n
    digits = _ndigits(t)
    drop = digits - PRECISION
    unit = 10 ** drop
    q, r = divmod(t, unit)
    half = unit // 2
    # unit >= 100 here, so r + f compares with half exactly as r does, except at r == half.
    if r > half or (r == half and (not exact or q % 2 == 1)):
        q += 1
    return _check_range(Dec(q, drop + (e - 2 * p) // 2))


def power(a, n):
    """a ^ n for an integer n with abs(n) <= 1024: the exact power rounded once; for n < 0,
    1 divided by the exact power, correctly rounded."""
    if not isinstance(n, int):
        raise ArithmeticFault("E_FORMULA_DOMAIN", "exponents are integers")
    if abs(n) > MAX_EXPONENT:
        raise ArithmeticFault("E_FORMULA_DOMAIN", f"abs(exponent) is at most {MAX_EXPONENT}")
    if n == 0:
        return Dec(1, 0)
    if a.c == 0:
        if n < 0:
            raise ArithmeticFault("E_FORMULA_DIV_ZERO", "zero to a negative power")
        return Dec(0, 0)
    # Magnitude estimate before computing: the adjusted exponent of a is within [adj, adj + 1).
    adjusted = _ndigits(abs(a.c)) - 1 + a.e
    if adjusted * abs(n) > MAX_CHARS + 4 or (adjusted + 1) * abs(n) < -(MAX_CHARS + 4):
        raise ArithmeticFault("E_FORMULA_RANGE", "the result does not fit the canonical number form")
    c, e = a.c ** abs(n), a.e * abs(n)
    if n > 0:
        return round_exact(c, e)
    return round_fraction(1 / (Fraction(c) * Fraction(10) ** e))


def sum_exact(xs):
    """The exact sum, rounded once (order-independent)."""
    if not xs:
        return Dec(0, 0)
    e = min(x.e for x in xs)
    return round_exact(sum(x.c * 10 ** (x.e - e) for x in xs), e)


def _exact_sum_fraction(xs):
    e = min(x.e for x in xs)
    return Fraction(sum(x.c * 10 ** (x.e - e) for x in xs)) * Fraction(10) ** e


def mean(xs):
    if not xs:
        raise ArithmeticFault("E_FORMULA_EMPTY", "mean of no members")
    return round_fraction(_exact_sum_fraction(xs) / len(xs))


def median(xs):
    if not xs:
        raise ArithmeticFault("E_FORMULA_EMPTY", "median of no members")
    values = sorted(xs, key=lambda d: d.fraction())
    n = len(values)
    if n % 2:
        return values[n // 2]
    return round_fraction((values[n // 2 - 1].fraction() + values[n // 2].fraction()) / 2)


def stdev(xs, population=False):
    """m = mean; ss = exact sum of (x - m)^2, rounded once; v = ss / (n - 1) (or n), rounded once;
    the correctly rounded square root of v."""
    n = len(xs)
    if n < (1 if population else 2):
        raise ArithmeticFault("E_FORMULA_EMPTY", "stdev needs two members (stdev_p one)")
    m = mean(xs)
    squares = []
    for x in xs:
        x_, m_, e = _align(x, m)
        d = x_ - m_
        squares.append(Dec(d * d, 2 * e))
    # The squares are exact; their exact sum is rounded once.
    e = min(s.e for s in squares)
    ss = round_exact(sum(s.c * 10 ** (s.e - e) for s in squares), e)
    v = round_fraction(ss.fraction() / (n if population else n - 1))
    return sqrt(v)


def floor(a):
    return Dec(a.c // 10 ** -a.e, 0) if a.e < 0 else a


def ceiling(a):
    return Dec(-((-a.c) // 10 ** -a.e), 0) if a.e < 0 else a


def _quantize(a, n, mode):
    """Round a to n decimals (n may be negative) by mode: away, up (away from zero), down."""
    if a.e >= -n:
        return a
    unit = 10 ** (-n - a.e)
    sign = -1 if a.c < 0 else 1
    q, r = divmod(abs(a.c), unit)
    if mode == "away":
        if 2 * r >= unit:
            q += 1
    elif mode == "up":
        if r:
            q += 1
    return _check_range(Dec(sign * q, -n))


def round_away(a, n):
    """Excel ROUND: half away from zero at n decimals."""
    return _quantize(a, n, "away")


def round_up(a, n):
    return _quantize(a, n, "up")


def round_down(a, n):
    return _quantize(a, n, "down")


def mod(a, b):
    """Excel MOD: a - b * floor(a / b), with the quotient exact; the result has b's sign."""
    if b.c == 0:
        raise ArithmeticFault("E_FORMULA_DIV_ZERO", "mod by zero")
    q = a.fraction() / b.fraction()
    fl = q.numerator // q.denominator
    x, y, e = _align(a, b)
    return round_exact(x - y * fl, e)


ZERO = Dec(0, 0)
ONE = Dec(1, 0)
