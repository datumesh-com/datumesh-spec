# SPDX-License-Identifier: Apache-2.0
"""Brief test 2 (decimal half): the formula dialect's decimal arithmetic (SPEC 15.9) matches a
reference decimal library on random cases, and the transcendental algorithms (SPEC 15.9.3) are
compared with mpdecimal (Python's decimal) or a high-precision series, with every divergence
counted: the 40-digit algorithm is normative, and a divergence is a hard case, never more than
one unit in the 34th digit.

tools/fdecimal.py implements the rule with Python integers only: exact result, rounded once to 34
significant digits half-even, then the range rule (the canonical form is at most 128 characters).
This test compares it with Python's decimal module in the context the specification names, on
DATUMESH_DECIMAL_N random cases per operation (default 10000).
"""

import decimal
import os
import random
import unittest

from helpers import ROOT  # noqa: F401  (puts tools/ on the path)
import fdecimal  # noqa: E402

N = int(os.environ.get("DATUMESH_DECIMAL_N", "10000"))
SEED = int(os.environ.get("DATUMESH_DECIMAL_SEED", "20261024"))

CTX = decimal.Context(prec=34, rounding=decimal.ROUND_HALF_EVEN, Emin=-6143, Emax=6144, clamp=0,
                      traps=[decimal.InvalidOperation, decimal.DivisionByZero, decimal.Overflow])
HIGH = decimal.Context(prec=90, rounding=decimal.ROUND_HALF_EVEN, Emin=-999999, Emax=999999)
DOWN40 = decimal.Context(prec=40, rounding=decimal.ROUND_DOWN, Emin=-999999, Emax=999999)
EXACT = decimal.Context(prec=100000, rounding=decimal.ROUND_HALF_EVEN, Emin=-999999, Emax=999999,
                        traps=[decimal.InvalidOperation, decimal.DivisionByZero, decimal.Overflow])


def canonical(d):
    """The canonical number form (SPEC 3.1) of a finite Decimal."""
    if d == 0:
        return "0"
    text = format(d, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def reference(d):
    """What the specification says the result is: d (already rounded), or E_FORMULA_RANGE."""
    text = canonical(d)
    return "E_FORMULA_RANGE" if len(text) > 128 else text


def ours(fn, *args):
    try:
        return str(fn(*args))
    except fdecimal.ArithmeticFault as e:
        return e.code


def random_number(rng, digits=None, spread=40):
    """A canonical number with up to 34 significant digits, sometimes long, sometimes tiny."""
    digits = digits or rng.choice([1, 1, 2, 3, 5, 8, 17, 33, 34, 34, 34])
    coefficient = rng.randrange(10 ** (digits - 1), 10 ** digits)
    if rng.random() < 0.1:  # ties and carries: coefficients ending in 5, or all nines
        coefficient = coefficient // 10 * 10 + 5 if rng.random() < 0.5 else 10 ** digits - 1
    exponent = rng.randrange(-spread, spread)
    if rng.random() < 0.03:
        exponent = rng.choice([-126 - digits + 1 + 1, 127 - digits, -100, 90])
    d = decimal.Decimal((rng.random() < 0.4, tuple(int(c) for c in str(coefficient)), exponent))
    text = canonical(d)
    if len(text) > 128:
        return random_number(rng, digits, spread)
    return text


class Arithmetic(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(SEED)

    def operands(self, n, digits=None, spread=40):
        return [tuple(random_number(self.rng, digits, spread) for _ in range(n)) for _ in range(N)]

    def compare(self, name, ours_fn, ref_fn, cases):
        for args in cases:
            expected = ref_fn(*[decimal.Decimal(a) for a in args])
            got = ours(ours_fn, *[fdecimal.Dec.parse(a) for a in args])
            self.assertEqual(got, expected, f"{name}{args}")

    def test_add(self):
        self.compare("add", fdecimal.add, lambda a, b: reference(CTX.add(a, b)), self.operands(2))

    def test_add_far_apart(self):
        """Operands far apart in magnitude: the exact sum needs many more than 34 digits."""
        self.compare("add", fdecimal.add, lambda a, b: reference(CTX.add(a, b)), self.operands(2, spread=90))

    def test_subtract(self):
        self.compare("sub", fdecimal.sub, lambda a, b: reference(CTX.subtract(a, b)), self.operands(2))

    def test_multiply(self):
        self.compare("mul", fdecimal.mul, lambda a, b: reference(CTX.multiply(a, b)), self.operands(2, spread=70))

    def test_divide(self):
        def ref(a, b):
            if b == 0:
                return "E_FORMULA_DIV_ZERO"
            return reference(CTX.divide(a, b))
        cases = self.operands(2, spread=70)
        cases += [(a, "0") for a, _ in cases[:20]]
        self.compare("div", fdecimal.div, ref, cases)

    def test_sqrt(self):
        """SQRT-T40: the exact root truncated to 40 digits, then half-even to 34."""
        def ref(a):
            if a < 0:
                return "E_FORMULA_DOMAIN"
            root = HIGH.sqrt(a)
            return reference(CTX.plus(DOWN40.plus(root)))
        cases = self.operands(1, spread=120)
        cases += [(str(k * k),) for k in range(1, 50)] + [("0",), ("2",), ("0.0001",)]
        self.compare("sqrt", fdecimal.sqrt, ref, cases)

    def test_integer_power(self):
        def ref(a, n):
            if a == 0 and n < 0:
                return "E_FORMULA_DIV_ZERO"
            if n == 0:
                return "1"
            exact = EXACT.power(a, abs(n))  # exact: prec is far larger than any result here
            if n > 0:
                return reference(CTX.plus(exact))
            return reference(CTX.divide(decimal.Decimal(1), exact))
        cases = []
        for _ in range(N):
            a = random_number(self.rng, self.rng.choice([1, 2, 3, 6, 12, 34]), 6)
            n = self.rng.choice([0, 1, 2, 3, 5, 7, 10, 17, 33, -1, -2, -3, -7])
            cases.append((a, n))
        for a, n in cases:
            expected = ref(decimal.Decimal(a), n)
            self.assertEqual(ours(fdecimal.power, fdecimal.Dec.parse(a), n), expected, f"power({a}, {n})")

    def test_compare(self):
        for a, b in self.operands(2):
            expected = (decimal.Decimal(a) > decimal.Decimal(b)) - (decimal.Decimal(a) < decimal.Decimal(b))
            self.assertEqual(fdecimal.cmp(fdecimal.Dec.parse(a), fdecimal.Dec.parse(b)), expected)


class Aggregates(unittest.TestCase):
    """sum and mean round once; stdev is a fixed sequence of correctly rounded steps (SPEC 15.4)."""

    def setUp(self):
        self.rng = random.Random(SEED + 1)

    def samples(self):
        for _ in range(max(N // 10, 50)):
            count = self.rng.choice([1, 2, 3, 4, 7, 20, 101])
            yield [random_number(self.rng, self.rng.choice([1, 4, 12, 34]), 8) for _ in range(count)]

    def test_sum_rounds_once(self):
        for xs in self.samples():
            exact = decimal.Decimal(0)
            for x in xs:
                exact = EXACT.add(exact, decimal.Decimal(x))
            self.assertEqual(ours(fdecimal.sum_exact, [fdecimal.Dec.parse(x) for x in xs]), reference(CTX.plus(exact)))

    def test_mean_rounds_once(self):
        for xs in self.samples():
            exact = decimal.Decimal(0)
            for x in xs:
                exact = EXACT.add(exact, decimal.Decimal(x))
            expected = reference(CTX.divide(exact, decimal.Decimal(len(xs))))
            self.assertEqual(ours(fdecimal.mean, [fdecimal.Dec.parse(x) for x in xs]), expected)

    def test_median(self):
        for xs in self.samples():
            values = sorted(decimal.Decimal(x) for x in xs)
            n = len(values)
            if n % 2:
                expected = reference(values[n // 2])
            else:
                expected = reference(CTX.divide(EXACT.add(values[n // 2 - 1], values[n // 2]), decimal.Decimal(2)))
            self.assertEqual(ours(fdecimal.median, [fdecimal.Dec.parse(x) for x in xs]), expected)

    def test_stdev(self):
        for xs in self.samples():
            for population in (False, True):
                n = len(xs)
                if n < (1 if population else 2):
                    self.assertEqual(ours(fdecimal.stdev, [fdecimal.Dec.parse(x) for x in xs], population),
                                     "E_FORMULA_EMPTY")
                    continue
                exact = decimal.Decimal(0)
                for x in xs:
                    exact = EXACT.add(exact, decimal.Decimal(x))
                m = CTX.divide(exact, decimal.Decimal(n))
                ss = decimal.Decimal(0)
                for x in xs:
                    d = EXACT.subtract(decimal.Decimal(x), m)
                    ss = EXACT.add(ss, EXACT.multiply(d, d))
                ss = CTX.plus(ss)
                v = CTX.divide(ss, decimal.Decimal(n if population else n - 1))
                # The range rule applies to every step, not only to the result.
                steps = [reference(m), reference(ss), reference(v)]
                expected = "E_FORMULA_RANGE" if "E_FORMULA_RANGE" in steps else reference(CTX.sqrt(v))
                self.assertEqual(ours(fdecimal.stdev, [fdecimal.Dec.parse(x) for x in xs], population), expected,
                                 f"stdev({xs}, population={population})")


DIVERGENCES = {}


def _series_sin_cos(x, cos=False):
    """A 90-digit reference: Taylor series after reduction by a 90-digit pi."""
    pi = HIGH_PI
    k = (x / (pi / 2)).to_integral_value(rounding=decimal.ROUND_HALF_EVEN)
    r = x - k * (pi / 2)
    s = t = r if not cos else decimal.Decimal(1)
    for j in range(1, 80):
        t = -t * r * r / (((2 * j) * (2 * j + 1)) if not cos else ((2 * j - 1) * (2 * j)))
        s += t
    return s, int(k) % 4


def _atan_series(t):
    s = term = t
    for j in range(1, 400):
        term = term * t * t
        s += (-1) ** j * term / (2 * j + 1)
    return s


decimal.getcontext().prec = 90
HIGH_PI = 16 * (lambda x: _atan_series(x))(decimal.Decimal(1) / 5) - 4 * _atan_series(decimal.Decimal(1) / 239)


def high_sin(x):
    s, q = _series_sin_cos(x)
    c, _ = _series_sin_cos(x, cos=True)
    return [s, c, -s, -c][q]


def high_cos(x):
    s, q = _series_sin_cos(x)
    c, _ = _series_sin_cos(x, cos=True)
    return [c, -s, -c, s][q]


def high_atan2(y, x):
    a, b = abs(y), abs(x)
    swap = a > b
    t = b / a if swap else a / b
    for _ in range(3):
        t = t / (1 + (1 + t * t).sqrt())
    angle = 8 * _atan_series(t)
    if swap:
        angle = HIGH_PI / 2 - angle
    if x < 0:
        angle = HIGH_PI - angle
    return -angle if y < 0 else angle


class Transcendental(unittest.TestCase):
    """The algorithms against correctly rounded references. A divergence is a hard case: the
    reference and the algorithm differ by exactly one unit in the 34th digit. They are counted
    (tests/test_decimal.py prints the counts) and must stay rare."""

    def setUp(self):
        self.rng = random.Random(SEED + 2)

    def check(self, name, fn, ref, cases):
        diverged = 0
        for args in cases:
            ours_ = ours(fn, *[fdecimal.Dec.parse(a) for a in args])
            theirs = ref(*[decimal.Decimal(a) for a in args])
            if ours_ != theirs:
                self.assertNotIn("E_", ours_ + theirs, f"{name}{args}: {ours_} vs {theirs}")
                ulp = decimal.Decimal(1).scaleb(decimal.Decimal(theirs).adjusted() - 33)
                self.assertLessEqual(abs(decimal.Decimal(ours_) - decimal.Decimal(theirs)), ulp, f"{name}{args}")
                diverged += 1
        DIVERGENCES[name] = (diverged, len(cases))
        self.assertLessEqual(diverged, max(2, len(cases) // 1000), name)

    def numbers(self, lo, hi, places=20):
        out = []
        for _ in range(N):
            d = decimal.Decimal(self.rng.uniform(lo, hi)).quantize(decimal.Decimal(1).scaleb(-self.rng.randrange(0, places)))
            out.append((canonical(d),))
        return out

    def test_exp(self):
        self.check("exp", fdecimal.exp, lambda a: reference(CTX.exp(a)), self.numbers(-290, 290) + [("0",), ("1",), ("-1",)])

    def test_ln(self):
        cases = [(random_number(self.rng, spread=60).lstrip("-") or "1",) for _ in range(N)]
        cases = [c for c in cases if c[0] != "0"] + [("1",), ("10",), ("0.1",), ("2",)]
        self.check("ln", fdecimal.ln, lambda a: reference(CTX.ln(a)), cases)

    def test_power_non_integer(self):
        def ref(a, b):
            exact = EXACT.multiply(b, HIGH.ln(a))
            return reference(CTX.plus(HIGH.exp(exact)))
        cases = []
        for _ in range(N):
            a = canonical(decimal.Decimal(self.rng.uniform(0.01, 1000)).quantize(decimal.Decimal("1e-8")))
            b = canonical(decimal.Decimal(self.rng.uniform(-20, 20)).quantize(decimal.Decimal("1e-6")))
            if "." in b and a != "0":
                cases.append((a, b))
        self.check("pow", fdecimal.pow_frac, ref, cases)

    def test_sin_cos(self):
        cases = self.numbers(-1000, 1000, 15)
        self.check("sin", fdecimal.sin, lambda a: reference(CTX.plus(high_sin(a))), cases)
        self.check("cos", fdecimal.cos, lambda a: reference(CTX.plus(high_cos(a))), cases)

    def test_atan2(self):
        cases = [(a[0], b[0]) for a, b in zip(self.numbers(-100, 100, 12), self.numbers(-100, 100, 12))]
        cases += [("1", "0"), ("-1", "0"), ("0", "-1"), ("0", "1"), ("1", "1"), ("-1", "-1")]
        self.check("atan2", fdecimal.atan2, lambda y, x: reference(CTX.plus(high_atan2(y, x))), cases)

    def test_sqrt_divergences(self):
        cases = [(random_number(self.rng, spread=60).lstrip("-") or "1",) for _ in range(N)]
        self.check("sqrt-vs-correctly-rounded", fdecimal.sqrt, lambda a: reference(CTX.sqrt(a)), cases)

    def test_constructed_hard_case_the_algorithm_wins(self):
        """A root whose digits 35-41 are 5000001: correctly rounded it goes up; truncated to 40
        digits it is a tie, and half-even keeps the even 34-digit neighbour."""
        r = decimal.Decimal(10 ** 33 + 2) + decimal.Decimal("0.5000001")
        x = EXACT.multiply(r, r)
        text = canonical(x)
        self.assertLessEqual(len(text), 128)
        self.assertEqual(reference(CTX.sqrt(x)), str(10 ** 33 + 3))  # correctly rounded
        self.assertEqual(str(fdecimal.sqrt(fdecimal.Dec.parse(text))), str(10 ** 33 + 2))  # the algorithm

    def test_haversine(self):
        P = fdecimal.Dec.parse
        self.assertEqual(str(fdecimal.haversine(P("51.5074"), P("-0.1278"), P("48.8566"), P("2.3522"))), "343556.535")
        self.assertEqual(str(fdecimal.haversine(P("0"), P("0"), P("0"), P("180"))), "20015114.442")
        self.assertEqual(str(fdecimal.haversine(P("10"), P("20"), P("10"), P("20"))), "0")
        with self.assertRaises(fdecimal.ArithmeticFault):
            fdecimal.haversine(P("91"), P("0"), P("0"), P("0"))

    @classmethod
    def tearDownClass(cls):
        print("\nhard cases (divergences from the correctly rounded reference): " +
              ", ".join(f"{k} {d}/{n}" for k, (d, n) in sorted(DIVERGENCES.items())), file=__import__("sys").stderr)


class Rules(unittest.TestCase):
    def test_canonical_form(self):
        for text in ("0", "1", "-1", "1.5", "0.000001", "123456789012345678901234567890.1234"):
            self.assertEqual(str(fdecimal.Dec.parse(text)), text)
        for bad in ("-0", "1.50", "01", "1.", ".5", "1e5", "+1", ""):
            with self.assertRaises(ValueError):
                fdecimal.Dec.parse(bad)

    def test_no_negative_zero(self):
        zero = fdecimal.mul(fdecimal.Dec.parse("-1"), fdecimal.Dec.parse("0"))
        self.assertEqual(str(zero), "0")
        self.assertEqual(str(fdecimal.sub(fdecimal.Dec.parse("1.5"), fdecimal.Dec.parse("1.5"))), "0")

    def test_half_even(self):
        # 35 significant digits ending in 5: ties go to the even neighbour.
        a = fdecimal.Dec.parse("1234567890123456789012345678901234")
        self.assertEqual(str(fdecimal.add(a, fdecimal.Dec.parse("0.5"))), "1234567890123456789012345678901234")
        b = fdecimal.Dec.parse("1234567890123456789012345678901233")
        self.assertEqual(str(fdecimal.add(b, fdecimal.Dec.parse("0.5"))), "1234567890123456789012345678901234")

    def test_range_rule_applies_to_intermediates(self):
        big = fdecimal.Dec.parse("1" + "0" * 100)
        with self.assertRaises(fdecimal.ArithmeticFault) as e:
            fdecimal.mul(big, big)
        self.assertEqual(e.exception.code, "E_FORMULA_RANGE")
        tiny = fdecimal.Dec.parse("0." + "0" * 99 + "1")
        with self.assertRaises(fdecimal.ArithmeticFault):
            fdecimal.mul(tiny, tiny)

    def test_power_limits(self):
        two = fdecimal.Dec.parse("2")
        self.assertEqual(str(fdecimal.power(two, 100)), "1267650600228229401496703205376")
        self.assertEqual(str(fdecimal.power(two, -1)), "0.5")
        with self.assertRaises(fdecimal.ArithmeticFault) as e:
            fdecimal.power(two, 1025)
        self.assertEqual(e.exception.code, "E_FORMULA_DOMAIN")
        with self.assertRaises(fdecimal.ArithmeticFault) as e:
            fdecimal.power(two, 1000)
        self.assertEqual(e.exception.code, "E_FORMULA_RANGE")

    def test_excel_rounding_functions(self):
        P = fdecimal.Dec.parse
        self.assertEqual(str(fdecimal.round_away(P("2.5"), 0)), "3")
        self.assertEqual(str(fdecimal.round_away(P("-2.5"), 0)), "-3")
        self.assertEqual(str(fdecimal.round_away(P("1234.5678"), -2)), "1200")
        self.assertEqual(str(fdecimal.round_up(P("3.2"), 0)), "4")
        self.assertEqual(str(fdecimal.round_down(P("-3.7"), 0)), "-3")
        self.assertEqual(str(fdecimal.floor(P("-3.5"))), "-4")
        self.assertEqual(str(fdecimal.ceiling(P("-3.5"))), "-3")
        self.assertEqual(str(fdecimal.mod(P("-3"), P("2"))), "1")
        self.assertEqual(str(fdecimal.mod(P("3"), P("-2"))), "-1")
        self.assertEqual(str(fdecimal.mod(P("5.5"), P("2"))), "1.5")


if __name__ == "__main__":
    unittest.main()
