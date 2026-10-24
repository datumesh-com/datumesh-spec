# SPDX-License-Identifier: Apache-2.0
"""Brief test 2 (decimal half): the formula dialect's decimal arithmetic (SPEC 15.4) matches a
reference decimal library on random cases.

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
        def ref(a):
            if a < 0:
                return "E_FORMULA_DOMAIN"
            return reference(CTX.sqrt(a))
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
