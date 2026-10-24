# SPDX-License-Identifier: Apache-2.0
"""Decimal arithmetic of the formula dialect (SPEC.md 15.9), with integers only.

Every arithmetic operation computes its exact result, rounds it once to 34 significant digits
with round-half-even, and then applies the range rule: the result, written in the canonical
number form of SPEC 3.1, has at most 128 characters, or the operation fails with E_FORMULA_RANGE.

The transcendental functions (sqrt, exp, ln, non-integer powers, sin, cos, atan2, haversine) are
defined by the named algorithms below (SPEC 15.9.3): every step at a working precision of 40
significant digits, half-even, with fixed term counts and stated constants; the 40-digit result
is then rounded half-even to 34 digits and the range rule applied. The algorithm is normative:
where it differs from a correctly rounded result (a hard case near a rounding boundary), the
algorithm wins.
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


def round_exact(c, e, prec=PRECISION, check=True):
    """Round the exact value c * 10**e to prec significant digits, half-even; then the range rule."""
    if c == 0:
        return Dec(0, 0)
    sign = -1 if c < 0 else 1
    a = abs(c)
    n = _ndigits(a)
    if n > prec:
        drop = n - prec
        q, r = divmod(a, 10 ** drop)
        half = 5 * 10 ** (drop - 1)
        if r > half or (r == half and q % 2 == 1):
            q += 1
        a, e = q, e + drop
    d = Dec(sign * a, e)
    return _check_range(d) if check else d


def round_fraction(x, prec=PRECISION, check=True):
    """Round an exact rational to prec significant digits, half-even; then (by default) the range rule."""
    if x == 0:
        return Dec(0, 0)
    sign = -1 if x < 0 else 1
    num, den = abs(x.numerator), x.denominator
    # Find k with 10**(prec-1) <= num * 10**k / den < 10**prec.
    k = prec - 1 - (_ndigits(num) - _ndigits(den))
    while True:
        scaled_num = num * 10 ** k if k >= 0 else num
        scaled_den = den if k >= 0 else den * 10 ** (-k)
        q, r = divmod(scaled_num, scaled_den)
        if q < 10 ** (prec - 1):
            k += 1
        elif q >= 10 ** prec:
            k -= 1
        else:
            break
    twice = 2 * r
    if twice > scaled_den or (twice == scaled_den and q % 2 == 1):
        q += 1
    d = Dec(sign * q, -k)
    return _check_range(d) if check else d


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
    """SQRT-T40 (SPEC 15.9.3): the exact square root truncated to 40 significant digits, then
    rounded half-even to 34. Not always the correctly rounded root: when digits 35-40 of the
    truncation are 500000 the tie goes to the even neighbour (a hard case)."""
    return final(sqrt40(a))


def sqrt40(a):
    if a.c < 0:
        raise ArithmeticFault("E_FORMULA_DOMAIN", "square root of a negative number")
    if a.c == 0:
        return Dec(0, 0)
    c, e = a.c, a.e
    if e % 2:  # make the exponent even
        c, e = c * 10, e - 1
    p = max(0, WORK + 1 - (_ndigits(c) + 1) // 2)
    t = isqrt(c * 10 ** (2 * p))  # floor of the exact root, at least WORK digits
    drop = _ndigits(t) - WORK
    return Dec(t // 10 ** drop, drop + (e - 2 * p) // 2)


def power(a, n):
    """a ^ n for an integer n with abs(n) <= 1024: the exact power rounded once; for n < 0,
    1 divided by the exact power, correctly rounded. A non-integer Dec exponent is POW-EXPLN."""
    if isinstance(n, Dec):
        if n.is_integer():
            n = n.to_int()
        else:
            return pow_frac(a, n)
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


# ---------------------------------------------------------------------------
# Transcendental functions (SPEC 15.9.3). Working precision 40, half-even, at every step; the
# named algorithms fix the argument reduction, the term counts and the constants.

WORK = 40
# Constants, each the true value rounded half-even to 40 significant digits.
PI = Dec.parse("3.141592653589793238462643383279502884197")
HALF_PI = Dec.parse("1.570796326794896619231321691639751442099")
LN10 = Dec.parse("2.302585092994045684017991454684364207601")
# For argument reduction only: 60 significant digits, the product n * C exact, then x - n * C
# rounded once to 40 digits. A 40-digit constant would lose digits for large n.
HALF_PI_60 = Dec.parse("1.57079632679489661923132169163975144209858469968755291048747")
LN10_60 = Dec.parse("2.30258509299404568401799145468436420760110148862877297603333")
EARTH_RADIUS = Dec.parse("6371008.8")  # metres, the mean radius (IUGG)
EXP_TERMS, LN_TERMS, TRIG_TERMS, ATAN_TERMS = 48, 80, 24, 32
TRIG_LIMIT = Dec.parse("1000000")  # abs(x) in radians for sin and cos
EXP_LIMIT = Dec.parse("300")


def _w(c, e):
    return round_exact(c, e, WORK, check=False)


def wadd(a, b):
    x, y, e = _align(a, b)
    return _w(x + y, e)


def wsub(a, b):
    x, y, e = _align(a, b)
    return _w(x - y, e)


def wmul(a, b):
    return _w(a.c * b.c, a.e + b.e)


def wdiv(a, b):
    return round_fraction(a.fraction() / b.fraction(), WORK, check=False)


def final(d):
    """A 40-digit working result as a dialect number: half-even to 34, then the range rule."""
    return round_exact(d.c, d.e)


def _reduce(x, n, c60):
    """x - n * c60, exact, rounded once to 40 digits."""
    prod = Dec(n * c60.c, c60.e)
    a, b, e = _align(x, prod)
    return _w(a - b, e)


def _negligible(term, total):
    """A term below a tenth of a unit in the 40th digit of the partial sum cannot change it, even
    next to a power of ten where a negative term moves to the decade below: adding it and rounding
    half-even gives the partial sum back, and every later term is smaller still. The fixed term
    counts stand; skipping such terms is an optimisation with exactly the same result."""
    if term.c == 0:
        return True
    if total.c == 0:
        return False
    adj = lambda d: _ndigits(abs(d.c)) - 1 + d.e  # noqa: E731
    return adj(term) <= adj(total) - WORK - 2


def round_integer(a):
    """a rounded half-even to an integer (an int)."""
    q = a.fraction()
    fl = q.numerator // q.denominator
    rest = q - fl
    if rest > Fraction(1, 2) or (rest == Fraction(1, 2) and fl % 2):
        fl += 1
    return fl


RAD_PER_DEG = wdiv(PI, Dec(180, 0))


def exp40(x):
    """EXP-T48: n = x / LN10 rounded half-even to an integer; r = x - n * LN10_60 (abs(r) <= 1.152);
    S = sum of r^k / k! for k = 0..47, each term t_k = t_(k-1) * r / k; the result is S * 10^n."""
    if x.c == 0:
        return Dec(1, 0)
    if cmp(abs_(x), EXP_LIMIT) > 0:
        raise ArithmeticFault("E_FORMULA_RANGE", "exp() of a number this large does not fit the canonical form")
    n = round_integer(wdiv(x, LN10))
    r = _reduce(x, n, LN10_60)
    s, t = Dec(1, 0), Dec(1, 0)
    for k in range(1, EXP_TERMS):
        t = wdiv(wmul(t, r), Dec(k, 0))
        if k > 2 and _negligible(t, s):
            break
        s = wadd(s, t)
    return Dec(s.c, s.e + n)


def exp(x):
    return final(exp40(x))


def ln40(x):
    """LN-ATANH80: x = m * 10^k with m in [10^-0.5, 10^0.5) (m * m < 10 decided exactly);
    z = (m - 1) / (m + 1); ln m = 2 * sum of z^(2j+1) / (2j+1) for j = 0..79; ln x = ln m + k * LN10."""
    if x.c <= 0:
        raise ArithmeticFault("E_FORMULA_DOMAIN", "ln() of a number that is not positive")
    k = _ndigits(abs(x.c)) - 1 + x.e
    m = Dec(x.c, x.e - k)  # in [1, 10)
    if cmp(Dec(m.c * m.c, 2 * m.e), Dec(10, 0)) >= 0:
        m, k = Dec(m.c, m.e - 1), k + 1
    one = Dec(1, 0)
    z = wdiv(wsub(m, one), wadd(m, one))
    z2 = wmul(z, z)
    s, p = Dec(0, 0), z
    for j in range(LN_TERMS):
        term = wdiv(p, Dec(2 * j + 1, 0))
        if j and _negligible(term, s):
            break
        s = wadd(s, term)
        p = wmul(p, z2)
    ln_m = wmul(s, Dec(2, 0))
    if k == 0:
        return ln_m
    return wadd(ln_m, wmul(Dec(k, 0), LN10))


def ln(x):
    return final(ln40(x))


def pow_frac(x, y):
    """POW-EXPLN: x ^ y for a non-integer y is exp40(y * ln40(x)), rounded to 34; x > 0, or x = 0
    with y > 0 (the result 0)."""
    if x.c < 0:
        raise ArithmeticFault("E_FORMULA_DOMAIN", "a negative number to a non-integer power")
    if x.c == 0:
        if y.c < 0:
            raise ArithmeticFault("E_FORMULA_DIV_ZERO", "zero to a negative power")
        return Dec(0, 0)
    return final(exp40(wmul(y, ln40(x))))


def _sin_cos_reduced(x):
    """TRIG-T24: k = x / HALF_PI rounded half-even; r = x - k * HALF_PI_60; sin r and cos r by
    their Taylor series, 24 terms each; (sin x, cos x) from k mod 4."""
    if cmp(abs_(x), TRIG_LIMIT) > 0:
        raise ArithmeticFault("E_FORMULA_DOMAIN", "sin() and cos() take abs(x) <= 1000000 radians")
    k = round_integer(wdiv(x, HALF_PI))
    r = _reduce(x, k, HALF_PI_60)
    r2 = wmul(r, r)
    s, t = r, r
    for j in range(1, TRIG_TERMS):
        t = neg(wdiv(wmul(t, r2), Dec((2 * j) * (2 * j + 1), 0)))
        if _negligible(t, s):
            break
        s = wadd(s, t)
    c, t = Dec(1, 0), Dec(1, 0)
    for j in range(1, TRIG_TERMS):
        t = neg(wdiv(wmul(t, r2), Dec((2 * j - 1) * (2 * j), 0)))
        if _negligible(t, c):
            break
        c = wadd(c, t)
    q = k % 4
    return [(s, c), (c, neg(s)), (neg(s), neg(c)), (neg(c), s)][q]


def sin40(x):
    return _sin_cos_reduced(x)[0]


def cos40(x):
    return _sin_cos_reduced(x)[1]


def sin(x):
    return final(sin40(x))


def cos(x):
    return final(cos40(x))


def atan2_40(y, x):
    """ATAN2-T32: a = abs(y), b = abs(x); t = min/max of them; twice t = t / (1 + sqrt40(1 + t*t));
    atan t = 4 * sum of (-1)^j t^(2j+1) / (2j+1) for j = 0..31; HALF_PI minus it when a > b; PI
    minus that when x < 0; negated when y < 0."""
    if x.c == 0 and y.c == 0:
        raise ArithmeticFault("E_FORMULA_DOMAIN", "atan2(0, 0) has no angle")
    a, b = abs_(y), abs_(x)
    swap = cmp(a, b) > 0
    t = wdiv(b, a) if swap else wdiv(a, b)
    one = Dec(1, 0)
    for _ in range(2):
        t = wdiv(t, wadd(one, sqrt40(wadd(one, wmul(t, t)))))
    t2 = wmul(t, t)
    s, p = t, t
    for j in range(1, ATAN_TERMS):
        p = wmul(p, t2)
        term = wdiv(p, Dec(2 * j + 1, 0))
        if _negligible(term, s):
            break
        s = wsub(s, term) if j % 2 else wadd(s, term)
    angle = wmul(s, Dec(4, 0))
    if swap:
        angle = wsub(HALF_PI, angle)
    if x.c < 0:
        angle = wsub(PI, angle)
    if y.c < 0:
        angle = neg(angle)
    return angle


def atan2(y, x):
    return final(atan2_40(y, x))


def round_half_even(a, n):
    """a rounded half-even to n decimals."""
    if a.e >= -n:
        return a
    unit = 10 ** (-n - a.e)
    sign = -1 if a.c < 0 else 1
    q, r = divmod(abs(a.c), unit)
    if 2 * r > unit or (2 * r == unit and q % 2):
        q += 1
    return _check_range(Dec(sign * q, -n))


def haversine(lat1, lon1, lat2, lon2):
    """HAVERSINE (SPEC 15.10): the great-circle distance in metres on a sphere of radius
    6371008.8 m between two points in decimal degrees, rounded half-even to millimetres:
    h = sin40(dphi/2)^2 + cos40(phi1) * cos40(phi2) * sin40(dlambda/2)^2 (clamped to [0, 1]);
    distance = R * 2 * atan2_40(sqrt40(h), sqrt40(1 - h))."""
    for lat in (lat1, lat2):
        if cmp(abs_(lat), Dec(90, 0)) > 0:
            raise ArithmeticFault("E_FORMULA_DOMAIN", "a latitude is within [-90, 90] degrees")
    for lon in (lon1, lon2):
        if cmp(abs_(lon), Dec(360, 0)) > 0:
            raise ArithmeticFault("E_FORMULA_DOMAIN", "a longitude is within [-360, 360] degrees")
    two, one = Dec(2, 0), Dec(1, 0)
    phi1, phi2 = wmul(lat1, RAD_PER_DEG), wmul(lat2, RAD_PER_DEG)
    dphi = wmul(wsub(lat2, lat1), RAD_PER_DEG)
    dlam = wmul(wsub(lon2, lon1), RAD_PER_DEG)
    s1 = sin40(wdiv(dphi, two))
    s2 = sin40(wdiv(dlam, two))
    h = wadd(wmul(s1, s1), wmul(wmul(cos40(phi1), cos40(phi2)), wmul(s2, s2)))
    if cmp(h, one) > 0:
        h = one
    if h.c < 0:
        h = Dec(0, 0)
    c = wmul(two, atan2_40(sqrt40(h), sqrt40(wsub(one, h)))) if h.c else Dec(0, 0)
    return round_half_even(wmul(EARTH_RADIUS, c), 3)


def deg_to_rad40(x):
    return wmul(x, RAD_PER_DEG)


# ---------------------------------------------------------------------------
# Decimal vectors (SPEC 11, kind decimal): one operation over many cases.

def run_case(op, args):
    """The canonical result of one case, or its fault code."""
    try:
        if op == "power":
            return str(power(Dec.parse(args[0]), int(args[1])))
        if op == "round":
            return str(round_away(Dec.parse(args[0]), int(args[1])))
        xs = [Dec.parse(a) for a in args]
        fn = {"add": add, "sub": sub, "mul": mul, "div": div, "sqrt": sqrt, "exp": exp, "ln": ln, "pow": pow_frac,
              "sin": sin, "cos": cos, "atan2": atan2, "haversine": haversine, "mod": mod}.get(op)
        if fn is not None:
            return str(fn(*xs))
        if op == "stdev_p":
            return str(stdev(xs, population=True))
        return str({"sum": sum_exact, "mean": mean, "median": median, "stdev": stdev}[op](xs))
    except ArithmeticFault as e:
        return e.code
