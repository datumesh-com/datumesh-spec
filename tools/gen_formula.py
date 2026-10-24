# SPDX-License-Identifier: Apache-2.0
"""The spec-0.4.0 vectors (SPEC 15): grammar, evaluation, slices, slice-lineage receipts,
descriptors with order and extent, envelopes with a fault, decimal cases and Excel equivalence;
and the scenario worlds the tests use (brief tests 6-9).

tools/gen_vectors.py calls add_all(add) with its own add(), which runs every vector through
canon.py (and so formula.py) and records the outputs. Valid vectors state their expected inputs
by hand here, and generation stops if the parser disagrees (brief test 3).
"""

import json
import random

import canon
import fdecimal
import formula as F
from fdecimal import Dec

BOUND = "2026-01-01T00:00:00.000000Z"  # every function's binding start
LATER = "2026-06-01T00:00:00.000000Z"  # the usual evaluation asof
CORRECTED = "2026-06-15T09:00:00.000000Z"  # when corrections are recorded
AFTER_CORRECTION = "2026-07-01T00:00:00.000000Z"
BEFORE_LATE_SAMPLE = "2026-03-01T11:00:00.000000Z"


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


def arg(type_, unit=None, valid=False, extent=None):
    decl = {"type": type_, "valid": valid}
    if unit is not None:
        decl["unit"] = unit
    if extent is not None:
        decl["extent"] = extent
    return decl


def ret(r):
    if r in ("boolean", "string", "date", "instant", "blob"):
        return r
    return {"type": "number", "unit": r}


def stored(args, order, returns):
    sig = {"args": args, "returns": ret(returns)}
    if order is not None:
        sig["order"] = order
    return {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": sig}


def computed_stub(args, order, returns):
    """A computed function as a callee in a grammar environment: only its signature and language
    matter to the checker."""
    d = stored(args, order, returns)
    d["code"] = {"body": "1\n", "lang": "formula"}
    return d


STR = arg("string")
RATE_UNIT = {"of": {"arg": "quote"}, "per": {"arg": "base"}}

# ---------------------------------------------------------------------------
# The grammar environment (SPEC 15, vectors of kind formula)

FUNCTIONS = {
    "rates.example.org/fx_rate": stored({"base": STR, "date": arg("date", valid=True), "quote": STR},
                                        ["base", "quote", "date"], RATE_UNIT),
    "rates.example.org/fx_rate_legacy": stored({"base": STR, "date": arg("date", valid=True), "quote": STR}, None,
                                               RATE_UNIT),
    "rates.example.org/rate": stored({"currency": STR, "tenor": STR}, ["currency", "tenor"], "1"),
    "rates.example.org/rate_pct": stored({"currency": STR, "tenor": STR}, ["currency", "tenor"], "percent"),
    "weather.example.org/temp": stored({"station": STR, "t": arg("instant", valid=True)}, ["station", "t"], "degC"),
    "weather.example.org/weight": stored({"station": STR}, ["station"], "1"),
    "weather.example.org/forecast": stored({"issued": arg("instant", valid=True), "t": arg("instant", valid=True)},
                                           ["issued", "t"], "degC"),
    "data.example.org/daily": stored({"date": arg("date", valid=True)}, ["date"], "EUR"),
    "data.example.org/price": stored({"item": STR}, ["item"], "EUR"),
    "data.example.org/qty": stored({"item": STR}, ["item"], "1"),
    "data.example.org/name": stored({"company": STR}, ["company"], "string"),
    "data.example.org/incorporated": stored({"company": STR}, ["company"], "date"),
    "data.example.org/active": stored({"company": STR}, ["company"], "boolean"),
    "data.example.org/by_flag": stored({"active": arg("boolean")}, ["active"], "count"),
    "data.example.org/sized": stored({"size": arg("number", "m")}, ["size"], "count"),
    "data.example.org/zone": stored({"in": STR}, ["in"], "string"),
    "data.example.org/doc": stored({"company": STR}, ["company"], "blob"),
    "calendars.example.org/holiday": stored({"calendar": STR, "date": arg("date", valid=True)}, ["calendar", "date"],
                                            "string"),
    "geo.example.org/elev": stored({"lat": arg("number", "deg"), "lon": arg("number", "deg")}, ["lat", "lon"], "m"),
    "a-b.org/f": stored({"x": arg("number", "1")}, ["x"], "EUR"),
    "b.org/f": stored({"x": arg("number", "1")}, ["x"], "EUR"),
    "curve.example.net/df": computed_stub({"tenor": arg("number", "1", extent={"hi": "10", "lo": "1"})}, ["tenor"], "1"),
    "curve.example.net/big": computed_stub({"n": arg("number", "1")}, ["n"], "1"),
    "calc.example.net/noext": computed_stub({"x": arg("number", "1")}, ["x"], "1"),
    "calc.example.net/noext_s": computed_stub({"name": STR}, ["name"], "1"),
}
ALIASES = {"fx": "rates.example.org/fx_rate", "ecb/fx_rate": "rates.example.org/fx_rate",
           "rate": "rates.example.org/rate", "temp": "weather.example.org/temp"}
DEFINED = "calc.example.net/f"
STD_ARGS = {
    "a": arg("number", "EUR"), "b": arg("number", "EUR"), "c": arg("number", "USD"), "n": arg("number", "1"),
    "k": arg("number", "1"), "x": arg("number", "1"), "r": arg("number", "percent"), "t1": arg("number", "degC"),
    "t2": arg("number", "degC"), "amount": arg("number", {"arg": "base"}), "count": arg("number", "count"),
    "plat": arg("number", "deg"), "plon": arg("number", "deg"), "dist": arg("number", "m"), "secs": arg("number", "s"),
    "s": STR, "name": STR, "base": STR, "quote": STR, "station": STR, "tenor": STR, "item": STR,
    "stations": STR, "p": STR,
    "d": arg("date", valid=True), "d2": arg("date", valid=True), "t": arg("instant", valid=True), "flag": arg("boolean"),
}


def std_sig(returns, args=None):
    args = args or STD_ARGS
    return {"args": args, "order": sorted(args), "returns": ret(returns)}


def env_for(source, sig, name=DEFINED):
    """The environment a grammar vector carries: the functions and aliases its source names."""
    functions = {fq: d for fq, d in FUNCTIONS.items() if fq in source}
    aliases = {a: fq for a, fq in ALIASES.items() if "@" + a + "(" in source}
    for fq in aliases.values():
        functions[fq] = FUNCTIONS[fq]
    return {"aliases": aliases, "functions": functions, "name": name, "signature": sig}


# ---------------------------------------------------------------------------
# Keys

HOSTS = ("rates.example.org", "weather.example.org", "data.example.org", "calendars.example.org", "geo.example.org",
         "math.example.net", "curve.example.net", "shop.example.net", "calc.example.net", "sheet.example.org",
         "fz.example.org")
KEYS = F.key_env(HOSTS)


def keypair(host):
    seed = F.host_seed(host)
    _, public = canon.keypair(seed)
    return {"seed": seed.hex(), "public": public.hex(), "key_id": canon.key_id(public)}


def define(name, args, order, source, returns, functions):
    sig = {"args": args, "order": order, "returns": ret(returns)}
    return F.define(name, sig, source, {"functions": functions})


def spec_of(functions, receipts=()):
    return {"functions": {n: {"bound": BOUND, "descriptor": d} for n, d in sorted(functions.items())},
            "receipts": list(receipts)}


# ---------------------------------------------------------------------------
# Scenario worlds (brief tests 6-9)

FIB = "math.example.net/fib"
RATIO = "math.example.net/ratio"


def world_fib():
    num = arg("number", "1")
    fib = define(FIB, {"n": num}, ["n"], "if n < 2 then n else math.example.net/fib(n - 1) + math.example.net/fib(n - 2)",
                 "1", {})
    ratio = define(RATIO, {"x": num, "y": num}, ["x", "y"], "x / y", "1", {})
    return spec_of({FIB: fib, RATIO: ratio})


PAR = "curve.example.net/par_rate"
DF = "curve.example.net/df"
PAR_RATES = {n: str(fdecimal.add(Dec.parse("0.01"), fdecimal.mul(Dec.parse("0.0025"), Dec(n, 0)))) for n in range(1, 11)}


def world_curve():
    par = stored({"tenor": arg("number", "1")}, ["tenor"], "1")
    tenor = arg("number", "1", extent={"hi": "10", "lo": "1"})
    body = ("if tenor = 1 then 1 / (1 + curve.example.net/par_rate(tenor)) else "
            "(1 - curve.example.net/par_rate(tenor) * sum(curve.example.net/df(tenor: [1..tenor - 1]))) / "
            "(1 + curve.example.net/par_rate(tenor))")
    df = define(DF, {"tenor": tenor}, ["tenor"], body, "1", {PAR: par})
    receipts = [F.stored_receipt(par, PAR, {"tenor": N(str(n))}, N(PAR_RATES[n]), "2026-02-01T08:00:00.000000Z")
                for n in range(1, 11)]
    return spec_of({PAR: par, DF: df}, receipts)


def expected_df(n):
    """Bootstrapped discount factors computed directly with fdecimal, in the body's order."""
    one, dfs = Dec(1, 0), []
    for k in range(1, n + 1):
        r = Dec.parse(PAR_RATES[k])
        if k == 1:
            dfs.append(fdecimal.div(one, fdecimal.add(one, r)))
        else:
            dfs.append(fdecimal.div(fdecimal.sub(one, fdecimal.mul(r, fdecimal.sum_exact(dfs))), fdecimal.add(one, r)))
    return str(dfs[-1])


TEMP_DAILY = "weather.example.org/temp_daily"
WEIGHT = "weather.example.org/weight"
WMEAN = "calc.example.net/weighted_mean"


def _temp_daily():
    return stored({"date": arg("date", valid=True), "station": STR}, ["station", "date"], "degC")


def world_weighted(n=1000):
    temp, weight = _temp_daily(), FUNCTIONS[WEIGHT]
    body = ('convert(sum(map(weather.example.org/temp_daily(*, date), x -> convert(x, "K")) * '
            'weather.example.org/weight(*)) / sum(weather.example.org/weight(*)), "degC")')
    wm = define(WMEAN, {"date": arg("date", valid=True)}, ["date"], body, "degC", {TEMP_DAILY: temp, WEIGHT: weight})
    receipts = []
    for i in range(n):
        st = f"s{i:04d}"
        receipts.append(F.stored_receipt(temp, TEMP_DAILY, {"date": D("2026-03-01"), "station": S(st)},
                                         N(f"{8 + i % 9}.{i % 4 * 25}".rstrip("0").rstrip(".")),
                                         "2026-03-01T18:00:00.000000Z"))
        receipts.append(F.stored_receipt(weight, WEIGHT, {"station": S(st)}, N(str(1 + i % 3)),
                                         "2026-02-01T00:00:00.000000Z"))
    return spec_of({TEMP_DAILY: temp, WEIGHT: weight, WMEAN: wm}, receipts)


def weighted_correction():
    return F.stored_receipt(_temp_daily(), TEMP_DAILY, {"date": D("2026-03-01"), "station": S("s0003")}, N("25"),
                            CORRECTED)


TEMP = "weather.example.org/temp"
TEMP_AT = "calc.example.net/temp_at"
LATEST = "calc.example.net/latest_temp"
MEAN_TEMP = "calc.example.net/mean_temp"
FRESH = "calc.example.net/fresh_temp"
SAMPLES = [  # station, valid time, value, tx (when it arrived)
    ("kew", "2026-03-01T10:00:00.000000Z", "11.5", "2026-03-01T10:00:05.000000Z"),
    ("kew", "2026-03-01T10:07:00.000000Z", "11.7", "2026-03-01T10:07:05.000000Z"),
    ("ely", "2026-03-01T09:58:30.000000Z", "9.25", "2026-03-01T09:58:41.000000Z"),
    ("ely", "2026-03-01T10:12:00.000000Z", "9.5", "2026-03-01T10:12:09.000000Z"),
    ("kew", "2026-03-01T10:09:00.000000Z", "11.9", "2026-03-01T12:00:00.000000Z"),  # a late sample
]
WEATHER_CASES = [  # station, t, expected at LATER (None: no reading within the bound)
    ("kew", "2026-03-01T10:05:00.000000Z", "11.5"), ("kew", "2026-03-01T10:08:00.000000Z", "11.7"),
    ("kew", "2026-03-01T10:09:30.000000Z", "11.9"), ("kew", "2026-03-01T10:20:00.000000Z", None),
    ("ely", "2026-03-01T10:05:00.000000Z", "9.25"), ("ely", "2026-03-01T10:11:00.000000Z", None),
    ("ely", "2026-03-01T10:12:00.000000Z", "9.5"), ("kew", "2026-03-01T09:59:00.000000Z", None),
]


def weather_receipts():
    temp = FUNCTIONS[TEMP]
    return [F.stored_receipt(temp, TEMP, {"station": S(st), "t": I(t)}, N(v), tx) for st, t, v, tx in SAMPLES]


def weather_functions():
    temp = FUNCTIONS[TEMP]
    fns = {TEMP: temp}
    station, t = STR, arg("instant", valid=True)
    fns[TEMP_AT] = define(TEMP_AT, {"station": station, "t": t}, ["station", "t"],
                          "last_before(weather.example.org/temp(station, *), t, 10 min)", "degC", {TEMP: temp})
    fns[LATEST] = define(LATEST, {"station": station}, ["station"], "latest(weather.example.org/temp(station, *))",
                         "degC", {TEMP: temp})
    fns[MEAN_TEMP] = define(MEAN_TEMP, {"t": t}, ["t"], "mean(last_before(weather.example.org/temp(*, *), t, 10 min))",
                            "degC", {TEMP: temp})
    fns[FRESH] = define(FRESH, {"station": station}, ["station"], "latest(weather.example.org/temp(station, *), 15 min)",
                        "degC", {TEMP: temp})
    return fns


def world_weather():
    return spec_of(weather_functions(), weather_receipts())


DAILY = "data.example.org/daily"
RUNNING = "calc.example.net/running"


def day(i):
    import datetime
    return (datetime.date(2016, 1, 1) + datetime.timedelta(days=i)).isoformat()


def _daily_value(i):
    return (i % 10) + 1


def world_running(days=3650):
    daily = FUNCTIONS[DAILY]
    running = define(RUNNING, {"date": arg("date", valid=True)}, ["date"],
                     "sum(data.example.org/daily(date: [2016-01-01..date]))", "EUR", {DAILY: daily})
    receipts = [F.stored_receipt(daily, DAILY, {"date": D(day(i))}, N(str(_daily_value(i))), day(i) + "T18:00:00.000000Z")
                for i in range(days)]
    return spec_of({DAILY: daily, RUNNING: running}, receipts)


def running_expected(i):
    return sum(_daily_value(j) for j in range(i + 1))


def running_correction(i):
    return F.stored_receipt(FUNCTIONS[DAILY], DAILY, {"date": D(day(i))}, N(str(_daily_value(i) + 100)), CORRECTED)


PRICE = "shop.example.net/price"
TAX = "shop.example.net/tax"
TOTAL = "shop.example.net/total"


def world_supersede():
    price = stored({"item": STR}, ["item"], "EUR")
    tax = stored({"item": STR}, ["item"], "EUR")
    total = define(TOTAL, {"item": STR}, ["item"], "shop.example.net/price(item) + shop.example.net/tax(item)", "EUR",
                   {PRICE: price, TAX: tax})
    receipts = [F.stored_receipt(price, PRICE, {"item": S("bolt")}, N("100"), "2026-03-01T09:00:00.000000Z"),
                F.stored_receipt(tax, TAX, {"item": S("bolt")}, N("20"), "2026-03-02T09:00:00.000000Z")]
    return spec_of({PRICE: price, TAX: tax, TOTAL: total}, receipts)


def backdated_correction():
    """A correction of the price recorded with a tx before the total's tx (2026-03-02)."""
    price = stored({"item": STR}, ["item"], "EUR")
    return F.stored_receipt(price, PRICE, {"item": S("bolt")}, N("101"), "2026-03-01T12:00:00.000000Z")


# ---------------------------------------------------------------------------
# The fuzz world and well-typed random expressions (brief test 2)

FZ_P, FZ_Q, FZ_SERIES, FZ_TAG = "fz.example.org/p", "fz.example.org/q", "fz.example.org/series", "fz.example.org/tag"
FUZZ_ARGS = {"a": N("2.5"), "b": N("-1.25"), "d": D("2026-03-05"), "n": N("3"), "s": S("i1")}


def fuzz_signature(returns):
    args = {"a": arg("number", "EUR"), "b": arg("number", "EUR"), "d": arg("date", valid=True),
            "n": arg("number", "1"), "s": STR}
    return {"args": args, "order": ["a", "b", "n", "s", "d"], "returns": ret(returns)}


def world_fuzz():
    p = stored({"item": STR}, ["item"], "EUR")
    q = stored({"item": STR}, ["item"], "1")
    series = stored({"t": arg("date", valid=True)}, ["t"], "EUR")
    tag = stored({"item": STR}, ["item"], "string")
    receipts = []
    for i in range(5):
        receipts.append(F.stored_receipt(p, FZ_P, {"item": S(f"i{i}")}, N(f"{i + 1}.5"), "2026-02-01T00:00:00.000000Z"))
        receipts.append(F.stored_receipt(q, FZ_Q, {"item": S(f"i{i}")}, N(str(i)), "2026-02-01T00:00:00.000000Z"))
        receipts.append(F.stored_receipt(tag, FZ_TAG, {"item": S(f"i{i}")}, S(f"Tag {i}é"), "2026-02-01T00:00:00.000000Z"))
    for j in range(10):
        receipts.append(F.stored_receipt(series, FZ_SERIES, {"t": D(f"2026-03-{j + 1:02d}")}, N(str(10 + j * j % 7)),
                                         "2026-03-11T00:00:00.000000Z"))
    return spec_of({FZ_P: p, FZ_Q: q, FZ_SERIES: series, FZ_TAG: tag}, receipts)


class _Expr:
    def __init__(self, rng):
        self.rng, self.lets = rng, 0

    def pick(self, *options):
        return self.rng.choice(options)

    def lit(self):
        r = self.rng
        return r.choice(["0", "1", "2", "3", "0.5", "1.25", "10", "100", "0.001", "7", str(r.randrange(1000))])

    def eur(self, d):
        if d <= 0:
            return self.pick("a", "b", f"{self.lit()} EUR", 'fz.example.org/p(item: s)', 'fz.example.org/p("i3")')
        k = self.rng.randrange(16)
        e, o = self.eur, self.one
        return [
            lambda: f"({e(d - 1)} + {e(d - 1)})", lambda: f"({e(d - 1)} - {e(d - 1)})",
            lambda: f"({e(d - 1)} * {o(d - 1)})", lambda: f"({e(d - 1)} / {o(d - 1)})", lambda: f"-{e(0)}",
            lambda: f"(if {self.bool(d - 1)} then {e(d - 1)} else {e(d - 1)})",
            lambda: "sum(fz.example.org/series(*))", lambda: "at(fz.example.org/series(*), d)",
            lambda: "last_before(fz.example.org/series(*), d, 3 d)", lambda: f"round({e(d - 1)}, 2)",
            lambda: f"abs({e(d - 1)})", lambda: self.let(lambda: e(d - 1), lambda v: f"({v} + {e(d - 1)})"),
            lambda: "mean(filter(fz.example.org/series(*), v -> v > 11 EUR))",
            lambda: f"max({e(d - 1)}, {e(d - 1)})", lambda: f"otherwise(at(fz.example.org/series(*), d + 30), {e(0)})",
            lambda: "sum(fz.example.org/p(*) * fz.example.org/q(*))",
        ][k]()

    def one(self, d):
        if d <= 0:
            return self.pick("n", self.lit(), "fz.example.org/q(item: s)")
        k = self.rng.randrange(13)
        e, o = self.eur, self.one
        return [
            lambda: f"({o(d - 1)} + {o(d - 1)})", lambda: f"({o(d - 1)} * {o(d - 1)})", lambda: f"({o(d - 1)} / {o(d - 1)})",
            lambda: f"({e(d - 1)} / {e(d - 1)})", lambda: f"sqrt(abs({o(d - 1)}))", lambda: f"exp({o(0)})",
            lambda: f"ln(abs({o(d - 1)}) + 1)", lambda: f"sin({o(d - 1)})", lambda: f"({o(0)} ^ 2)",
            lambda: f"({o(0)} ^ 0.5)", lambda: f"len({self.str(d - 1)})", lambda: f"atan2({o(d - 1)}, {o(0)})",
            lambda: f"mod({o(d - 1)}, {o(0)})",
        ][k]()

    def bool(self, d):
        if d <= 0:
            return self.pick("true", "false", "n > 1")
        k = self.rng.randrange(5)
        return [lambda: f"({self.eur(d - 1)} > {self.eur(d - 1)})", lambda: f"({self.one(d - 1)} = {self.one(d - 1)})",
                lambda: f"(not {self.bool(d - 1)})", lambda: f"({self.bool(d - 1)} and {self.bool(d - 1)})",
                lambda: f"({self.str(d - 1)} = {self.str(d - 1)})"][k]()

    def str(self, d):
        if d <= 0:
            return self.pick("s", '"x"', '"Zürich"', "fz.example.org/tag(s)")
        k = self.rng.randrange(4)
        return [lambda: f"({self.str(d - 1)} & {self.str(d - 1)})", lambda: f"upper({self.str(d - 1)})",
                lambda: f"text({self.one(d - 1)})", lambda: f"substr({self.str(d - 1)}, 1, 3)"][k]()

    def date(self, d):
        if d <= 0:
            return self.pick("d", "2026-03-01")
        k = self.rng.randrange(3)
        return [lambda: f"({self.date(d - 1)} + 3)", lambda: f"add_days({self.date(d - 1)}, 2, weekend: \"sat-sun\")",
                lambda: f"add_months({self.date(d - 1)}, 1)"][k]()

    def let(self, value, body):
        self.lets += 1
        name = f"v{self.lets}"
        return f"(let {name} = {value()} in {body(name)})"


def random_expression(rng):
    gen = _Expr(rng)
    depth = rng.randrange(1, 5)
    kind = rng.choice(["EUR", "EUR", "1", "boolean", "string", "date"])
    source = {"EUR": gen.eur, "1": gen.one, "boolean": gen.bool, "string": gen.str, "date": gen.date}[kind](depth)
    return source, kind


# ---------------------------------------------------------------------------
# Grammar vectors: (id, source, returns, inputs written by hand, description)

FX_ = "rates.example.org/fx_rate"
RT_ = "rates.example.org/rate"
TP_ = "weather.example.org/temp"
DL_ = "data.example.org/daily"
CAL_ = "calendars.example.org/holiday"

VALID = [
    ("literal-number", "42", "1", [], "A number literal."),
    ("literal-decimal", "1.5", "1", [], "A decimal literal in canonical form."),
    ("literal-zero-in-context", "0", "EUR", [], "A bare 0 takes the return's unit."),
    ("unit-suffix-currency", "100 EUR", "EUR", [], "A unit suffix: a listed unit after a number."),
    ("unit-suffix-percent", "0.05 percent", "percent", [], "0.05 percent is the number 0.05 in percent (units.md 2.3)."),
    ("unit-suffix-degc", "20 degC", "degC", [], "A temperature literal."),
    ("unit-suffix-rate", "10 m/s", "m/s", [], "m/s is one listed unit: the longest unit symbol is taken."),
    ("unit-division", "10 m / secs = dist / secs", "boolean", [],
     "With spaces, 10 m / secs divides metres by an argument; both sides are m s^-1."),
    ("unit-suffix-index", "100 index:2015=100", "index:2015=100", [], "An index unit suffix."),
    ("unit-suffix-no-space", "20km", "km", [], "A unit suffix needs no space."),
    ("string-literal", '"Zürich"', "string", [], "A string literal (NFC)."),
    ("string-quote", '"say ""hi"""', "string", [], "Excel's quoting: a doubled quote is a quote."),
    ("string-empty", '""', "string", [], "The empty string."),
    ("boolean", "true", "boolean", [], "A boolean literal."),
    ("boolean-uppercase", "TRUE", "boolean", [], "Keywords are case-insensitive and printed lowercase."),
    ("date-literal", "2024-03-15", "date", [], "A bare ISO date is a date literal, never a subtraction."),
    ("instant-literal", "2024-03-15T16:00:00.000000Z", "instant", [], "A canonical instant literal."),
    ("date-subtraction-spaced", "2024 - 10 - 15", "1", [], "With spaces, digits and minus signs are a subtraction."),
    ("add", "a + b", "EUR", [], "Addition of two EUR amounts."),
    ("subtract", "a - b", "EUR", [], "Subtraction."),
    ("multiply-bare", "a * 1.2", "EUR", [], "A bare literal is dimensionless in a product."),
    ("divide", "a / n", "EUR", [], "Division by a dimensionless argument."),
    ("precedence-mul-add", "a + b * 2", "EUR", [], "* binds tighter than +."),
    ("left-assoc", "a - b - a", "EUR", [], "Binary operators associate to the left."),
    ("right-parenthesised", "a - (b - a)", "EUR", [], "Parentheses keep a right-nested subtraction."),
    ("neg", "-a", "EUR", [], "Unary minus."),
    ("double-neg", "--a", "EUR", [], "Two unary minus signs."),
    ("neg-power-left", "(-2) ^ 2", "1", [], "(-2)^2: the written-out reading Excel uses."),
    ("neg-power-right", "-(2 ^ 2)", "1", [], "-(2^2): the written-out reading mathematics uses."),
    ("power-negative-exponent", "2^-1", "1", [], "A unary minus in the exponent is unambiguous."),
    ("power-chain-left", "(2 ^ 3) ^ 2", "1", [], "A chain of powers written out to the left."),
    ("power-chain-right", "2 ^ (3 ^ 2)", "1", [], "A chain of powers written out to the right."),
    ("power-unit-literal", "(dist ^ 2) / (dist * dist)", "1", [], "A unit to an integer literal power."),
    ("power-non-integer", "n ^ 0.5", "1", [], "A non-integer power of a dimensionless number (POW-EXPLN)."),
    ("bare-adopts-unit", "a + 10", "EUR", [], "A bare literal takes the unit of the other operand."),
    ("compare-zero", "a > 0", "boolean", [], "A comparison with a bare zero."),
    ("percent-plus-zero", "r + 0", "percent", [], "Against percent, a bare literal must be 0."),
    ("percent-explicit", "1 + r / 100 percent", "1", [], "A percentage made dimensionless explicitly."),
    ("degc-plus-literal", "t1 + 5", "degC", [], "A bare literal added to degC is a difference (K)."),
    ("degc-difference", "t1 - t2", "K", [], "The difference of two temperatures is in K."),
    ("degc-plus-kelvin", "t1 + (t1 - t2)", "degC", [], "A temperature plus a difference."),
    ("degc-mean", "mean(t1, t2)", "degC", [], "The mean of temperatures is an affine combination."),
    ("concat", "s & name", "string", [], "& joins strings."),
    ("concat-precedence", '"a" & "b" = "ab"', "boolean", [], "& binds tighter than comparison, as in Excel."),
    ("compare-equal", "a = b", "boolean", [], "= compares."),
    ("compare-not-equal", "a <> b", "boolean", [], "<> is inequality."),
    ("compare-less-equal", "a <= b", "boolean", [], "<="),
    ("compare-greater-equal", "a >= b", "boolean", [], ">="),
    ("comparison-and", "a < b and b < a + 1 EUR", "boolean", [], "Two comparisons joined with and."),
    ("not-precedence", "not a = b", "boolean", [], "not applies to the comparison."),
    ("not-not", "not not flag", "boolean", [], "not of not."),
    ("and-or-precedence", "flag or flag and not flag", "boolean", [], "and binds tighter than or."),
    ("and-function", "AND(flag, a > 0, flag)", "boolean", [], "Excel's AND(): left-nested and."),
    ("or-function", "or(flag, flag)", "boolean", [], "Excel's OR()."),
    ("if-keyword", "if a > b then a else b", "EUR", [], "The keyword form of if."),
    ("if-extent", "if flag then a else a + b", "EUR", [], "else extends as far right as possible."),
    ("if-function-form", "IF(a > b, a, b)", "EUR", [], "Excel's IF() is the same AST as the keyword form."),
    ("if-keyword-paren", "if (a > b) then a else b", "EUR", [], "A parenthesised condition keeps the keyword form."),
    ("if-operand-parenthesised", "1 EUR + (if flag then a else b)", "EUR", [], "if as an operand, parenthesised."),
    ("if-else-if", "if n > 1 then a else if n > 0 then b else 0", "EUR", [], "else if chains."),
    ("let", "let w = a * 2 in w + b", "EUR", [], "A let binding."),
    ("let-extent", "let y = n in y + 1", "1", [], "in extends as far right as possible."),
    ("let-equality", "let e = a = b in e", "boolean", [], "let e = a = b binds e to the comparison."),
    ("let-nested", "let u = a in let v = u + b in v * 2", "EUR", [], "Nested lets."),
    ("keyword-uppercase", "IF flag THEN a ELSE b", "EUR", [], "Keywords in capitals."),
    ("builtin-uppercase", "SUM(a, b)", "EUR", [], "Built-in names in capitals, printed lowercase."),
    ("variable-named-count", "count + 1", "count", [], "count is a built-in only when called."),
    ("label-keyword", "data.example.org/zone(in: s)", "string", ["data.example.org/zone"],
     "A label may be a keyword: other functions' argument names are not restricted."),
    ("read-labelled", "rates.example.org/fx_rate(base: base, date: d, quote: quote)", RATE_UNIT, [FX_],
     "A read with labelled arguments."),
    ("read-positional", "rates.example.org/fx_rate(base, quote, d)", RATE_UNIT, [FX_],
     "Positional arguments bind by signature.order (base, quote, date)."),
    ("read-mixed", "rates.example.org/fx_rate(base, quote, date: d)", RATE_UNIT, [FX_],
     "Positional arguments first, then labelled ones."),
    ("read-literal-units", 'rates.example.org/fx_rate("EUR", "USD", d)', {"of": "USD", "per": "EUR"}, [FX_],
     "Literal currency arguments give a literal rate unit."),
    ("qualified-division", "a / rates.example.org/rate(currency: quote, tenor: tenor)", "EUR", [RT_],
     "A qualified name starts with a DNS name, so x/f(y) with x an argument is a division."),
    ("qualified-call-divided", "rates.example.org/rate(quote, tenor) / 2", "1", [RT_], "A read divided by a number."),
    ("hyphenated-host", "a-b.org/f(x: 1)", "EUR", ["a-b.org/f"],
     "Longest match: a-b.org/f is one name (hosts may contain hyphens)."),
    ("hyphen-subtraction", "a - b.org/f(x: 1)", "EUR", ["b.org/f"], "With spaces it is a subtraction."),
    ("alias", "@fx(base, quote, d)", RATE_UNIT, [FX_], "An alias, resolved at define time; never in hashed data."),
    ("alias-path", "@ecb/fx_rate(base: base, date: d, quote: quote)", RATE_UNIT, [FX_], "An alias with a path."),
    ("alias-division", "a / @rate(quote, tenor)", "EUR", [RT_], "x / @f(y) divides by an aliased read."),
    ("self-reference", "if x < 2 then x else calc.example.net/f(x: x - 1) + calc.example.net/f(x: x - 2)", "1",
     ["calc.example.net/f"], "A function reads itself with other arguments (fib)."),
    ("nested-read", "rates.example.org/fx_rate(base, quote, data.example.org/incorporated(company: s))", RATE_UNIT,
     [FX_, "data.example.org/incorporated"], "A read whose argument is another read."),
    ("multiply-in-argument", "geo.example.org/elev(lat: 2 * plat, lon: plon)", "m", ["geo.example.org/elev"],
     "In an argument, * not followed by , or ) multiplies."),
    ("open-marker", "sum(data.example.org/daily(*))", "EUR", [DL_], "An open argument: a slice."),
    ("range-dates", "sum(data.example.org/daily([2024-01-01..2024-12-31]))", "EUR", [DL_], "A date range."),
    ("range-integers", "sum(curve.example.net/df([1..3]))", "1", ["curve.example.net/df"],
     "[1..2] is 1, .., 2: a fraction needs a digit after the point."),
    ("range-decimal", "count(data.example.org/sized(size: [1.5 m..2 m]))", "count", ["data.example.org/sized"],
     "[1.5..2] is 1.5, .., 2."),
    ("range-expression", "sum(data.example.org/daily(date: [d..d + 30]))", "EUR", [DL_], "Range ends are expressions."),
    ("slice-let", "let v = data.example.org/daily(*) in max(v) - min(v)", "EUR", [DL_], "A slice bound by let."),
    ("aggregate-sum", "sum(data.example.org/daily([2024-01-01..2024-01-31]))", "EUR", [DL_], "sum over a slice."),
    ("aggregate-count", "count(data.example.org/daily(*))", "count", [DL_], "count over a slice is in count."),
    ("aggregate-mean", "mean(data.example.org/daily(*))", "EUR", [DL_], "mean over a slice."),
    ("aggregate-min", "min(data.example.org/daily(*))", "EUR", [DL_], "min over a slice."),
    ("aggregate-max", "max(data.example.org/daily(*))", "EUR", [DL_], "max over a slice."),
    ("aggregate-first", "first(data.example.org/daily(*))", "EUR", [DL_], "first in key order."),
    ("aggregate-last", "last(data.example.org/daily(*))", "EUR", [DL_], "last in key order."),
    ("aggregate-median", "median(data.example.org/daily(*))", "EUR", [DL_], "median over a slice."),
    ("aggregate-stdev", "stdev(data.example.org/daily(*))", "EUR", [DL_], "Sample standard deviation."),
    ("aggregate-stdev-p", "stdev_p(data.example.org/daily(*))", "EUR", [DL_], "Population standard deviation."),
    ("aggregate-strings", "min(data.example.org/name(*))", "string", ["data.example.org/name"], "min of strings."),
    ("aggregate-dates", "first(data.example.org/incorporated(*))", "date", ["data.example.org/incorporated"],
     "first of a date-valued slice."),
    ("aggregate-stdev-degc", "stdev(weather.example.org/temp(station, *))", "K", [TP_],
     "The spread of temperatures is a difference: K."),
    ("lookup-at", "at(data.example.org/daily(*), d)", "EUR", [DL_], "at: the member at a key."),
    ("lookup-latest", "latest(weather.example.org/temp(station, *))", "degC", [TP_], "latest along valid time."),
    ("lookup-latest-bound", "latest(weather.example.org/temp(station, *), 1 h)", "degC", [TP_],
     "latest with a staleness bound: asof-dependent."),
    ("lookup-last-before", "last_before(weather.example.org/temp(station, *), t, 10 min)", "degC", [TP_],
     "last_before with a staleness bound."),
    ("lookup-first-after", "first_after(weather.example.org/temp(station, *), t, 10 min)", "degC", [TP_], "first_after."),
    ("lookup-nearest", "nearest(weather.example.org/temp(station, *), t)", "degC", [TP_], "nearest, no bound."),
    ("lookup-within", "mean(within(weather.example.org/temp(station, *), t, 30 min))", "degC", [TP_],
     "within gives a slice for an aggregate."),
    ("interpolate-linear", 'interpolate(weather.example.org/temp(station, *), t, "linear", bound: 1 h)', "degC", [TP_],
     "Linear interpolation with a bound."),
    ("interpolate-step", 'interpolate(weather.example.org/temp(station, *), t, method: "step")', "degC", [TP_],
     "Step interpolation."),
    ("interpolate-default", "interpolate(weather.example.org/temp(station, *), t)", "degC", [TP_],
     "The method defaults to linear."),
    ("lookup-grouped", "mean(last_before(weather.example.org/temp(*, *), t, 10 min))", "degC", [TP_],
     "A lookup along valid time per station, then the mean: a real-time aggregate at a cadence."),
    ("lookup-along", "latest(at(weather.example.org/temp(*, *), station, along: station))", "degC", [TP_],
     "along names the dimension."),
    ("lookup-date-bound", "last_before(data.example.org/daily(*), d, 7 d)", "EUR", [DL_], "A bound in days."),
    ("lookup-number-dimension", "nearest(data.example.org/sized(*), dist)", "count", ["data.example.org/sized"],
     "A number dimension: the metric is the absolute difference in its unit."),
    ("map", "sum(map(data.example.org/daily(*), v -> v * 2))", "EUR", [DL_], "map over a slice."),
    ("map-key", "sum(map(data.example.org/daily(*), (v, date) -> if weekday(date) > 5 then 0 EUR else v))", "EUR",
     [DL_], "A lambda key parameter."),
    ("filter", "count(filter(data.example.org/daily(*), v -> v > 100 EUR))", "count", [DL_], "filter."),
    ("scan", "last(scan(data.example.org/daily(*), sum))", "EUR", [DL_], "A running sum."),
    ("window", "max(window(data.example.org/daily(*), 7, mean))", "EUR", [DL_], "A moving average."),
    ("scan-uppercase-aggregate", "last(scan(data.example.org/daily(*), SUM))", "EUR", [DL_],
     "The aggregate word is case-insensitive."),
    ("join", "sum(data.example.org/price(*) * data.example.org/qty(*))", "EUR",
     ["data.example.org/price", "data.example.org/qty"], "Implicit join on the shared open argument item."),
    ("join-broadcast", "sum(data.example.org/price(*) * 2)", "EUR", ["data.example.org/price"], "A slice times a scalar."),
    ("otherwise", "otherwise(at(data.example.org/daily(*), d), 0)", "EUR", [DL_], "A fallback for absence."),
    ("asof-zero-arity", "asof()", "instant", [], "asof() is the evaluation asof: asof-dependent."),
    ("asof-uppercase", "ASOF()", "instant", [], "The brief's spelling."),
    ("asof-two-arguments", "asof(data.example.org/price(item: s), t)", "EUR", ["data.example.org/price"],
     "A transaction-time read."),
    ("versions-count", "count(versions(data.example.org/price(item: s), 2024-01-01T00:00:00.000000Z, asof()))", "count",
     ["data.example.org/price"], "A version slice."),
    ("abs", "abs(a)", "EUR", [], "abs."),
    ("round", "round(a)", "EUR", [], "round to an integer."),
    ("round-digits", "round(a, 2)", "EUR", [], "round to 2 decimals."),
    ("round-up-down", "round_up(a, 1) - round_down(a, 1)", "EUR", [], "round_up and round_down."),
    ("floor-ceiling", "floor(a) + ceiling(b)", "EUR", [], "floor and ceiling."),
    ("mod", "mod(a, b)", "EUR", [], "mod keeps the divisor's unit."),
    ("sqrt", "sqrt(n)", "1", [], "sqrt (SQRT-T40)."),
    ("sqrt-unit", "sqrt(dist * dist)", "m", [], "sqrt halves even unit exponents."),
    ("convert-percent", 'convert(r, "1")', "1", [], "A percentage as a ratio."),
    ("convert-degc", 'convert(t1, "K")', "K", [], "Celsius to kelvin."),
    ("convert-deg", 'convert(plat, "1")', "1", [], "Degrees to radians."),
    ("exp-ln", "exp(n) + ln(x)", "1", [], "exp and ln (EXP-T48, LN-ATANH80)."),
    ("trigonometry", "sin(plat) + cos(30 deg) + atan2(1, x) + pi()", "1", [], "sin, cos (degrees), atan2, pi."),
    ("haversine", "haversine(plat, plon, 48.8566, 2.3522)", "m", [], "Great-circle distance in metres."),
    ("date-function", "date(2024, 3, 15)", "date", [], "date()."),
    ("date-parts", "year(d) + month(d) + day(d) + weekday(d)", "1", [], "year, month, day, weekday."),
    ("end-of-month", "end_of_month(d)", "date", [], "end_of_month."),
    ("add-days", "add_days(d, 30)", "date", [], "Calendar days."),
    ("add-days-calendar", 'add_days(d, 5, calendar: calendars.example.org/holiday(calendar: "gb-eaw", date: *))', "date",
     [CAL_], "Business days over a calendar slice: the calendar is an input."),
    ("add-months", "add_months(d, 1)", "date", [], "Excel's EDATE."),
    ("add-months-roll", 'add_months(d, 1, calendar: calendars.example.org/holiday("gb-eaw", *), roll: "modified_following")',
     "date", [CAL_], "A roll convention."),
    ("business-days", 'business_days(d, d2, weekend: "fri-sat")', "d", [], "Business days between two dates."),
    ("year-fraction", 'year_fraction(d, d2, "act/365f")', "1", [], "A day-count convention."),
    ("is-holiday", 'is_holiday(d, calendars.example.org/holiday("gb-eaw", *))', "boolean", [CAL_], "is_holiday."),
    ("date-of", "date_of(t)", "date", [], "The UTC date of an instant."),
    ("instant-of-date", "instant(d)", "instant", [], "Midnight UTC."),
    ("date-plus", "d + 30", "date", [], "A bare literal added to a date is days."),
    ("date-difference", "d2 - d", "d", [], "Two dates differ by days."),
    ("instant-plus", "t + 10 min", "instant", [], "An instant plus a duration."),
    ("instant-difference", "t - instant(d)", "s", [], "Two instants differ by seconds."),
    ("text-len", "len(s)", "1", [], "len counts code points."),
    ("text-case", "upper(s) & lower(name)", "string", [], "upper and lower."),
    ("text-trim", "trim(s)", "string", [], "Excel's TRIM."),
    ("text-concat", 'concat(s, " ", name)', "string", [], "concat."),
    ("text-substr", "substr(s, 2, 3)", "string", [], "substr (Excel MID)."),
    ("text-find", 'find("m", s)', "1", [], "find."),
    ("text-find-start", 'find("m", s, start: 3)', "1", [], "find from a position."),
    ("text-of", "text(a)", "string", [], "The canonical lexical form."),
    ("text-fixed", "fixed(a, 2)", "string", [], "Excel's FIXED without separators."),
    ("blob-equality", "data.example.org/doc(s) = data.example.org/doc(name)", "boolean", ["data.example.org/doc"],
     "Blobs compare for equality."),
    ("boolean-read", "data.example.org/active(s) and flag", "boolean", ["data.example.org/active"], "A boolean read."),
    ("whitespace", "a\n  +\tb", "EUR", [], "SP, TAB and LF between tokens; the body prints on one line."),
    ("spatial-filter-now",
     "mean(filter(geo.example.org/elev(lat: *, lon: *), (v, lat, lon) -> haversine(lat, lon, plat, plon) <= 20000 m))",
     "m", ["geo.example.org/elev"],
     "What the point metric of 1.3b will do, already now: a slice keyed by latitude and longitude filtered by distance."),
    ("same-read-twice", "a / rates.example.org/fx_rate(base, quote, d) * rates.example.org/fx_rate(base, quote, d)", "EUR",
     [FX_], "The same read twice is one input."),
]

INVALID = [  # (id, source, returns, error, description[, signature args])
    ("trailing-operator", "a +", "EUR", "E_FORMULA_SYNTAX", "An operator needs an operand."),
    ("unclosed", "(a", "EUR", "E_FORMULA_SYNTAX", "An unclosed parenthesis."),
    ("juxtaposed-names", "a b", "EUR", "E_FORMULA_SYNTAX", "Two names side by side."),
    ("trailing-comma", "sum(a,)", "EUR", "E_FORMULA_SYNTAX", "A trailing comma."),
    ("double-equals", "a == b", "boolean", "E_FORMULA_SYNTAX", "== is not an operator: write =."),
    ("bang-equals", "a != b", "boolean", "E_FORMULA_SYNTAX", "!= is not an operator: write <>."),
    ("unary-plus", "+a", "EUR", "E_FORMULA_SYNTAX", "There is no unary +."),
    ("semicolon", "a; b", "EUR", "E_FORMULA_SYNTAX", "No statements."),
    ("hash", "#a", "EUR", "E_FORMULA_SYNTAX", "An unknown character."),
    ("qualified-not-called", "rates.example.org/rate", "1", "E_FORMULA_SYNTAX", "There are no function values."),
    ("number-trailing-zero", "1.50", "1", "E_FORMULA_NUMBER", "Numbers are canonical: 1.5."),
    ("number-leading-zero", "01", "1", "E_FORMULA_NUMBER", "No leading zeros."),
    ("number-trailing-point", "1.", "1", "E_FORMULA_NUMBER", "No trailing point."),
    ("number-leading-point", ".5", "1", "E_FORMULA_NUMBER", "No leading point."),
    ("number-exponent", "1e5", "1", "E_FORMULA_NUMBER", "No exponents."),
    ("range-three-dots", "sum(data.example.org/daily(date: [1...2]))", "EUR", "E_FORMULA_NUMBER", "[1...2] is 1, .., .2."),
    ("string-unterminated", '"abc', "string", "E_FORMULA_STRING", "An unterminated string."),
    ("string-control", '"a\u0001b"', "string", "E_FORMULA_STRING", "No control characters."),
    ("string-nfd", '"Zürich"', "string", "E_FORMULA_STRING", "Strings are NFC, rejected not normalised."),
    ("date-impossible", "2023-02-29", "date", "E_FORMULA_DATE", "Not a real day."),
    ("date-month", "2024-13-01", "date", "E_FORMULA_DATE", "Month 13."),
    ("instant-short", "2024-03-15T16:00Z", "instant", "E_FORMULA_INSTANT", "Only the canonical instant form."),
    ("instant-hour", "2024-03-15T24:00:00.000000Z", "instant", "E_FORMULA_INSTANT", "Hour 24."),
    ("juxtaposition", "5 x", "1", "E_FORMULA_UNIT", "A word after a number is a unit, and x is not one: no implicit multiplication."),
    ("unit-lowercase-currency", "100 eur", "EUR", "E_FORMULA_UNIT", "Units are compared byte for byte."),
    ("unit-unknown", "10 kmh", "km/h", "E_FORMULA_UNIT", "Not a listed unit."),
    ("name-uppercase-host", "Rates.Example.org/fx_rate(base: base, date: d, quote: quote)", RATE_UNIT, "E_FORMULA_NAME",
     "Function names are lowercase."),
    ("name-alias-uppercase", "@Fx(base, quote, d)", RATE_UNIT, "E_FORMULA_NAME", "Aliases are names."),
    ("name-double-underscore", "rates.example.org/fx__rate(base: base)", "1", "E_FORMULA_NAME", "Not a name (SPEC 2.2)."),
    ("this", "this", "EUR", "E_FORMULA_RESERVED", "this is reserved for classes (1.3b)."),
    ("super", "super + 1", "EUR", "E_FORMULA_RESERVED", "super is reserved."),
    ("key-literal", "EUR", "string", "E_FORMULA_RESERVED", "Words with capitals are reserved for key literals (1.3b)."),
    ("period-key", "1M", "1", "E_FORMULA_RESERVED", "1M is reserved for period keys (1.3b)."),
    ("method-chain", "data.example.org/name(s).upper()", "string", "E_FORMULA_RESERVED", "'.' after a call is reserved for methods."),
    ("keyword-argument", "1", "1", "E_FORMULA_RESERVED", "A formula's argument cannot be a keyword.",
     {"in": arg("number", "1")}),
    ("forbidden-now", "now()", "instant", "E_FORMULA_FORBIDDEN", "No clock.", None, "now"),
    ("forbidden-today", "TODAY()", "date", "E_FORMULA_FORBIDDEN", "No clock, in any case.", None, "TODAY"),
    ("forbidden-rand", "a * RAND()", "EUR", "E_FORMULA_FORBIDDEN", "No randomness.", None, "RAND"),
    ("forbidden-indirect", "indirect(s)", "1", "E_FORMULA_FORBIDDEN", "No dynamic references.", None, "indirect"),
    ("forbidden-offset", "Offset(a, 1, 1)", "EUR", "E_FORMULA_FORBIDDEN", "No dynamic ranges.", None, "Offset"),
    ("dynamic-name-concat", '("rates.example.org/" & "rate")(quote, tenor)', "1", "E_FORMULA_DYNAMIC_NAME",
     "A name built from strings cannot be called: inputs are static."),
    ("dynamic-name-paren", "(a)(1)", "EUR", "E_FORMULA_DYNAMIC_NAME", "Only a name can be called."),
    ("neg-power", "-2^2", "1", "E_FORMULA_AMBIGUOUS", "Excel reads 4, mathematics -4: rejected."),
    ("neg-power-variable", "-n ^ 2", "1", "E_FORMULA_AMBIGUOUS", "The same with a name."),
    ("power-chain", "2^3^2", "1", "E_FORMULA_AMBIGUOUS", "Excel reads 64, mathematics 512: rejected."),
    ("comparison-chain", "a < b < a", "boolean", "E_FORMULA_CHAIN", "Comparisons do not chain."),
    ("equality-chain", "a = b = a", "boolean", "E_FORMULA_CHAIN", "Nor do equalities."),
    ("if-operand", "1 EUR + if flag then a else b", "EUR", "E_FORMULA_PLACEMENT", "if as an operand needs parentheses."),
    ("let-operand", "a + let y = 1 in y", "EUR", "E_FORMULA_PLACEMENT", "let as an operand needs parentheses."),
    ("open-outside-read", "sum(*)", "EUR", "E_FORMULA_PLACEMENT", "* is an argument of a read only."),
    ("lambda-outside-map", "sum(v -> v)", "EUR", "E_FORMULA_PLACEMENT", "A lambda is only an argument of map or filter."),
    ("range-outside-read", "[1..2]", "1", "E_FORMULA_PLACEMENT", "A range is an argument of a read only."),
    ("not-operand", "1 + not(flag)", "1", "E_FORMULA_PLACEMENT", "not as an operand needs parentheses."),
    ("nesting-limit", "(" * 300 + "a" + ")" * 300, "EUR", "E_FORMULA_LIMIT", "Nesting deeper than 256."),
    ("unknown-function", "foo(a)", "EUR", "E_FORMULA_UNKNOWN_FUNCTION", "User functions are qualified or @alias."),
    ("unknown-excel-function", "VLOOKUP(a, b, 1)", "EUR", "E_FORMULA_UNKNOWN_FUNCTION", "Excel's VLOOKUP is at() here."),
    ("alias-unknown", "@nope(a)", "EUR", "E_FORMULA_ALIAS", "Not in the alias map."),
    ("unresolved", "x.example.org/missing(a: 1)", "1", "E_FORMULA_UNRESOLVED", "No binding."),
    ("unknown-name", "zz + 1", "1", "E_FORMULA_UNKNOWN_NAME", "Not in scope."),
    ("asof-as-name", "asof", "instant", "E_FORMULA_UNKNOWN_NAME", "asof is reserved as an argument name; asof() is a call."),
    ("shadow-let", "let a = 1 EUR in a", "EUR", "E_FORMULA_SHADOW", "A let name equal to an argument."),
    ("shadow-lambda", "sum(map(data.example.org/daily(*), (v, v) -> v))", "EUR", "E_FORMULA_SHADOW", "Lambda parameters differ."),
    ("shadow-nested-let", "let y = 1 in let y = 2 in y", "1", "E_FORMULA_SHADOW", "Nested lets do not shadow."),
    ("arity-round", "round()", "EUR", "E_FORMULA_ARITY", "round() needs a value."),
    ("arity-if", "if(flag, a)", "EUR", "E_FORMULA_ARITY", "if() takes three arguments."),
    ("arity-and", "and(flag)", "boolean", "E_FORMULA_ARITY", "and() takes two or more."),
    ("arity-positional", "rates.example.org/fx_rate(base, quote, d, s)", RATE_UNIT, "E_FORMULA_ARITY",
     "More positional arguments than order lists."),
    ("arity-asof", "asof(t)", "instant", "E_FORMULA_ARITY", "asof() or asof(cell, T)."),
    ("arg-unknown", "rates.example.org/fx_rate(base: base, date: d, quote: quote, extra: 1)", RATE_UNIT,
     "E_FORMULA_ARG_UNKNOWN", "A label the callee does not declare."),
    ("arg-unknown-builtin", "round(a, places: 2)", "EUR", "E_FORMULA_ARG_UNKNOWN", "round() has digits, not places."),
    ("arg-missing", "rates.example.org/fx_rate(base: base, date: d)", RATE_UNIT, "E_FORMULA_ARG_MISSING",
     "Every argument is bound; an open one is written *."),
    ("arg-duplicate", "rates.example.org/fx_rate(base, quote, d, base: base)", RATE_UNIT, "E_FORMULA_ARG_DUPLICATE",
     "base bound by position and by label."),
    ("arg-duplicate-label", "round(a, digits: 1, digits: 2)", "EUR", "E_FORMULA_ARG_DUPLICATE", "A label twice."),
    ("arg-order", "rates.example.org/fx_rate(base: base, quote, d)", RATE_UNIT, "E_FORMULA_ARG_ORDER",
     "Positional arguments come first."),
    ("positional-without-order", "rates.example.org/fx_rate_legacy(base, d, quote)", RATE_UNIT, "E_FORMULA_POSITIONAL",
     "The callee declares no order: label its arguments."),
    ("type-add-string", "a + s", "EUR", "E_FORMULA_TYPE", "A number plus a string."),
    ("type-if-condition", "if n then a else b", "EUR", "E_FORMULA_TYPE", "An if condition is a boolean."),
    ("type-concat-number", '"a" & 1', "string", "E_FORMULA_TYPE", "& joins strings; use text()."),
    ("type-boolean-order", "flag < flag", "boolean", "E_FORMULA_TYPE", "Booleans are not ordered."),
    ("type-len-number", "len(a)", "1", "E_FORMULA_TYPE", "len() takes a string."),
    ("slice-return", "data.example.org/daily(*)", "EUR", "E_FORMULA_SLICE_VALUE", "A function returns a scalar."),
    ("slice-join-return", "data.example.org/daily(*) + 1 EUR", "EUR", "E_FORMULA_SLICE_VALUE", "Still a slice."),
    ("slice-argument", "rates.example.org/rate(currency: quote, tenor: data.example.org/name(*))", "1",
     "E_FORMULA_SLICE_VALUE", "An argument is a scalar."),
    ("unit-mismatch-add", "a + c", "EUR", "E_FORMULA_UNIT_MISMATCH", "EUR + USD."),
    ("unit-mismatch-compare", "a > c", "boolean", "E_FORMULA_UNIT_MISMATCH", "Comparison needs one unit."),
    ("unit-mismatch-percent", "1 + r", "percent", "E_FORMULA_UNIT_MISMATCH", "1 + 5 percent is not 101 %: write the unit."),
    ("unit-mismatch-sin", "sin(dist)", "1", "E_FORMULA_UNIT_MISMATCH", "sin takes an angle."),
    ("unit-mismatch-convert", 'convert(a, "m")', "m", "E_FORMULA_UNIT_MISMATCH", "No conversion between groups."),
    ("unit-offset-add", "t1 + t2", "degC", "E_FORMULA_UNIT_OFFSET", "A sum of temperatures."),
    ("unit-offset-multiply", "t1 * 2", "degC", "E_FORMULA_UNIT_OFFSET", "degC is a temperature, not a quantity to scale."),
    ("unit-offset-sum", "sum(weather.example.org/temp(station, *))", "degC", "E_FORMULA_UNIT_OFFSET", "sum over degC."),
    ("unit-unknown-value", 'rates.example.org/fx_rate(base & "", quote, d)', RATE_UNIT, "E_FORMULA_UNIT_UNKNOWN",
     "The rate's unit depends on a computed string."),
    ("unit-varies", "sum(rates.example.org/fx_rate(base, *, d))", "1", "E_FORMULA_UNIT_UNKNOWN",
     "The unit varies with the open quote: such a slice can only be counted."),
    ("exponent-variable", "a ^ n", "EUR", "E_FORMULA_EXPONENT", "A unit to a non-literal power."),
    ("exponent-sqrt", "sqrt(dist)", "m", "E_FORMULA_EXPONENT", "sqrt of m has no unit."),
    ("exponent-unit", "2 ^ (1 EUR)", "1", "E_FORMULA_EXPONENT", "An exponent is dimensionless."),
    ("return-type", "flag", "EUR", "E_FORMULA_RETURN_TYPE", "The body is boolean."),
    ("return-type-number", "a", "boolean", "E_FORMULA_RETURN_TYPE", "The body is a number."),
    ("return-unit", "a", "USD", "E_FORMULA_RETURN_UNIT", "EUR returned as USD."),
    ("return-unit-percent", "5", "percent", "E_FORMULA_RETURN_UNIT", "A bare 5 is not 5 percent."),
    ("unbounded-computed", "sum(calc.example.net/noext(x: *))", "1", "E_FORMULA_UNBOUNDED",
     "A computed function without an extent cannot be opened."),
    ("unbounded-string-range", 'sum(calc.example.net/noext_s(name: ["a".."b"]))', "1", "E_FORMULA_UNBOUNDED",
     "A string range over a computed function needs an extent."),
    ("unbounded-too-large", "sum(curve.example.net/big(n: [1..2000000]))", "1", "E_FORMULA_UNBOUNDED",
     "More than 1,048,576 cells."),
    ("slice-bound-boolean", "sum(data.example.org/by_flag(active: [false..true]))", "count", "E_FORMULA_SLICE_BOUND",
     "Booleans have no order for a range."),
    ("metric-string", "nearest(data.example.org/name(*), s)", "string", "E_FORMULA_METRIC", "Strings match exactly (at)."),
    ("metric-bound-unit", "last_before(weather.example.org/temp(station, *), t, 3 EUR)", "degC", "E_FORMULA_METRIC",
     "A bound on instants is a duration."),
    ("metric-latest-date", "latest(data.example.org/daily(*), 1 d)", "EUR", "E_FORMULA_METRIC",
     "latest with a bound is relative to asof(): it needs instants."),
    ("along-ambiguous", "latest(weather.example.org/forecast(*, *))", "degC", "E_FORMULA_ALONG", "Two valid-time dimensions."),
    ("along-unknown", 'latest(at(weather.example.org/temp(*, *), "kew", along: nope))', "degC", "E_FORMULA_ALONG",
     "Not an open argument."),
    ("join-keys", "sum(data.example.org/price(*) * data.example.org/daily(*))", "EUR", "E_FORMULA_JOIN",
     "item and date: slices join on equal key names."),
    ("lambda-param", "sum(map(data.example.org/daily(*), (v, region) -> v))", "EUR", "E_FORMULA_LAMBDA_PARAM",
     "region is not an open argument of the slice."),
    ("lambda-read", "sum(map(data.example.org/daily(*), v -> v * rates.example.org/rate(quote, tenor)))", "EUR",
     "E_FORMULA_LAMBDA_READ", "No reads inside a lambda: join instead."),
    ("enum-method", 'interpolate(weather.example.org/temp(station, *), t, "cubic")', "degC", "E_FORMULA_ENUM",
     "linear or step."),
    ("enum-convention", 'year_fraction(d, d2, "act/365")', "1", "E_FORMULA_ENUM", "The convention list is closed."),
    ("enum-aggregate", "last(scan(data.example.org/daily(*), total))", "EUR", "E_FORMULA_ENUM", "Not an aggregate."),
    ("enum-weekend", 'add_days(d, 1, weekend: "sat")', "date", "E_FORMULA_ENUM", "sat-sun, fri-sat, sun or none."),
    ("tx-arg-slice", "asof(data.example.org/daily(*), t)", "EUR", "E_FORMULA_TX_ARG", "asof(cell, T) takes one cell."),
    ("tx-arg-not-read", "versions(a, t, t)", "EUR", "E_FORMULA_TX_ARG", "versions() takes one cell read."),
    ("spatial-example", "interpolate(latest(weather.example.org/temp(within(stations, p, 20km), *)), p)", "degC",
     "E_FORMULA_UNSUPPORTED",
     "The decision log's composed example parses and resolves; key-set arguments and the point metric are 1.3b."),
    ("ellipsoidal", "ellipsoidal_distance(plat, plon, 1, 2)", "m", "E_FORMULA_UNSUPPORTED", "Reserved for later."),
    ("spline", 'interpolate(weather.example.org/temp(station, *), t, "spline")', "degC", "E_FORMULA_UNSUPPORTED",
     "No spline interpolation in this revision."),
]


def formula_vectors(add):
    for item in VALID:
        name, source, returns, inputs, description = item
        sig = std_sig(returns, {"x": arg("number", "1")} if name == "self-reference" else None)
        env = env_for(source, sig)
        got = F.run_vector({"kind": "formula", "input": source, "env": env})
        if "error" in got:
            raise SystemExit(f"formula/{name}: {got['detail']}")
        if got["inputs"] != sorted(inputs):
            raise SystemExit(f"formula/{name}: inputs {got['inputs']} differ from the hand-written {inputs}")
        add(f"formula/{name}", "formula", description, source, env=env)
    for item in INVALID:
        name, source, returns, error, description = item[:5]
        args = item[5] if len(item) > 5 else None
        token = item[6] if len(item) > 6 else None
        sig = std_sig(returns, args)
        extra = {"token": token} if token else {}
        add(f"invalid/formula-{name}", "formula", description, source, error, env=env_for(source, sig), **extra)


# ---------------------------------------------------------------------------
# Evaluation vectors (kind formula-eval): one computed function calc.example.net/e per vector
# over a small world.

E = "calc.example.net/e"
NUM1, EURA, DATEA, INSTA, BOOLA = arg("number", "1"), arg("number", "EUR"), arg("date", valid=True), \
    arg("instant", valid=True), arg("boolean")
DAILY_VALUES = [10, 12, 9, 15, 11, 13, 14, 8, 16, 10]
HOLIDAYS = [("2026-04-03", "Good Friday"), ("2026-04-06", "Easter Monday"), ("2026-05-04", "Early May bank holiday"),
            ("2026-05-25", "Spring bank holiday"), ("2026-08-31", "Summer bank holiday"), ("2026-12-25", "Christmas Day"),
            ("2026-12-28", "Boxing Day (substitute)")]
BLOB = canon.sha256_hex(b"Acme Ltd articles") + ":17:text/plain"


def base_world():
    fns = {n: FUNCTIONS[n] for n in ("data.example.org/price", "data.example.org/qty", "data.example.org/name",
                                     "data.example.org/incorporated", DL_, TP_, CAL_, FX_, RT_, "data.example.org/doc",
                                     "data.example.org/active")}
    r = []

    def put(fq, args, value, tx):
        r.append(F.stored_receipt(fns[fq], fq, args, value, tx))
    for item, p, q in (("bolt", "2.5", "4"), ("nut", "0.25", "10"), ("washer", "0.1", "100")):
        put("data.example.org/price", {"item": S(item)}, N(p), "2026-02-01T09:00:00.000000Z")
        put("data.example.org/qty", {"item": S(item)}, N(q), "2026-02-01T09:00:00.000000Z")
    put("data.example.org/price", {"item": S("bolt")}, N("2.75"), "2026-04-01T09:00:00.000000Z")  # a second version
    for c, nm, inc in (("acme", "Acme Ltd", "1999-05-17"), ("globex", "Globex Corp", "2004-11-30")):
        put("data.example.org/name", {"company": S(c)}, S(nm), "2026-01-10T00:00:00.000000Z")
        put("data.example.org/incorporated", {"company": S(c)}, D(inc), "2026-01-10T00:00:00.000000Z")
    put("data.example.org/doc", {"company": S("acme")}, {"type": "blob", "value": BLOB}, "2026-01-10T00:00:00.000000Z")
    put("data.example.org/active", {"company": S("acme")}, B(True), "2026-01-10T00:00:00.000000Z")
    for i, v in enumerate(DAILY_VALUES):
        dd = f"2026-03-{i + 1:02d}"
        put(DL_, {"date": D(dd)}, N(str(v)), dd + "T18:00:00.000000Z")
    for dd, nm in HOLIDAYS:
        put(CAL_, {"calendar": S("gb-eaw"), "date": D(dd)}, S(nm), "2025-12-01T00:00:00.000000Z")
    put(FX_, {"base": S("EUR"), "date": D("2026-03-02"), "quote": S("USD")}, N("1.0812"), "2026-03-02T16:00:00.000000Z")
    put(FX_, {"base": S("EUR"), "date": D("2026-03-02"), "quote": S("GBP")}, N("0.8556"), "2026-03-02T16:00:00.000000Z")
    put(RT_, {"currency": S("EUR"), "tenor": S("1M")}, N("0.0185"), "2026-03-02T16:00:00.000000Z")
    put(RT_, {"currency": S("USD"), "tenor": S("1M")}, N("0.0425"), "2026-03-02T16:00:00.000000Z")
    r += weather_receipts()
    # Computed functions some vectors read.
    fns[FIB] = world_fib()["functions"][FIB]["descriptor"]
    fns["math.example.net/chain"] = define("math.example.net/chain", {"n": NUM1}, ["n"],
                                           "if n = 0 then 0 else math.example.net/chain(n - 1) + 1", "1", {})
    fns["math.example.net/loop"] = define("math.example.net/loop", {"n": NUM1}, ["n"], "math.example.net/loop(n) + 1",
                                          "1", {})
    fns["math.example.net/recip"] = define("math.example.net/recip", {"n": arg("number", "1", extent={"hi": "3", "lo": "0"})},
                                           ["n"], "1 / n", "1", {})
    curve = world_curve()
    fns[PAR], fns[DF] = curve["functions"][PAR]["descriptor"], curve["functions"][DF]["descriptor"]
    r += curve["receipts"]
    return fns, r


BASE_FUNCTIONS, BASE_RECEIPTS = None, None


def _base():
    global BASE_FUNCTIONS, BASE_RECEIPTS
    if BASE_FUNCTIONS is None:
        BASE_FUNCTIONS, BASE_RECEIPTS = base_world()
    return BASE_FUNCTIONS, BASE_RECEIPTS


def world_for(descriptor, extra_options=None):
    """The part of the base world a descriptor needs: its inputs, transitively, and their receipts."""
    fns, receipts = _base()
    need, todo = {E: descriptor}, list(descriptor["inputs"])
    while todo:
        n = todo.pop()
        if n not in need:
            need[n] = fns[n]
            todo.extend(fns[n]["inputs"])
    hashes = {canon.function_hash(d) for d in need.values()}
    spec = spec_of(need, [r for r in receipts if r["cell"]["fn_hash"] in hashes])
    spec.update(extra_options or {})
    return spec


L_ = LATER
T_KEW = "2026-03-01T10:05:00.000000Z"
EVAL = [  # (name, {arg: (decl, value)}, source, returns, expected value or error code, asof, options)
    ("add-exact", {"x": (NUM1, N("1.5")), "y": (NUM1, N("2.25"))}, "x + y", "1", "3.75"),
    ("add-carry", {"x": (NUM1, N("9" * 34)), "y": (NUM1, N("1"))}, "x + y", "1", "1" + "0" * 34),
    ("add-half-even-down", {"x": (NUM1, N("1234567890123456789012345678901234")), "y": (NUM1, N("0.5"))}, "x + y", "1",
     "1234567890123456789012345678901234"),
    ("add-half-even-up", {"x": (NUM1, N("1234567890123456789012345678901233")), "y": (NUM1, N("0.5"))}, "x + y", "1",
     "1234567890123456789012345678901234"),
    ("subtract-to-zero", {"x": (NUM1, N("1.5"))}, "x - x", "1", "0"),
    ("no-negative-zero", {"x": (NUM1, N("1.5"))}, "-(x * 0)", "1", "0"),
    ("multiply", {"x": (NUM1, N("1.1")), "y": (NUM1, N("1.1"))}, "x * y", "1", "1.21"),
    ("multiply-rounds", {"x": (NUM1, N("1234567890.123456789")), "y": (NUM1, N("9876543210.987654321"))}, "x * y", "1", None),
    ("divide-third", {"x": (NUM1, N("1")), "y": (NUM1, N("3"))}, "x / y", "1", "0.3333333333333333333333333333333333"),
    ("divide-two-thirds", {"x": (NUM1, N("2")), "y": (NUM1, N("3"))}, "x / y", "1", "0.6666666666666666666666666666666667"),
    ("divide-zero", {"x": (NUM1, N("1")), "y": (NUM1, N("0"))}, "x / y", "1", "E_FORMULA_DIV_ZERO"),
    ("range-power", {"x": (NUM1, N("10"))}, "x ^ 200", "1", "E_FORMULA_RANGE"),
    ("range-intermediate", {"x": (NUM1, N("1" + "0" * 100))}, "x * x * 0", "1", "E_FORMULA_RANGE"),
    ("power-integer", {"x": (NUM1, N("2"))}, "x ^ 10", "1", "1024"),
    ("power-negative", {"x": (NUM1, N("3"))}, "x ^ -2", "1", "0.1111111111111111111111111111111111"),
    ("power-zero-negative", {"x": (NUM1, N("0"))}, "x ^ -1", "1", "E_FORMULA_DIV_ZERO"),
    ("power-fraction", {"x": (NUM1, N("2"))}, "x ^ 0.5", "1", "1.414213562373095048801688724209698"),
    ("power-fraction-negative-base", {"x": (NUM1, N("-4"))}, "x ^ 0.5", "1", "E_FORMULA_DOMAIN"),
    ("power-exponent-limit", {"x": (NUM1, N("1"))}, "x ^ 1025", "1", "E_FORMULA_DOMAIN"),
    ("sqrt", {"x": (NUM1, N("2"))}, "sqrt(x)", "1", "1.414213562373095048801688724209698"),
    ("sqrt-negative", {"x": (NUM1, N("-1"))}, "sqrt(x)", "1", "E_FORMULA_DOMAIN"),
    ("exp", {"x": (NUM1, N("1"))}, "exp(x)", "1", "2.718281828459045235360287471352662"),
    ("exp-range", {"x": (NUM1, N("300.5"))}, "exp(x)", "1", "E_FORMULA_RANGE"),
    ("exp-negative", {"x": (NUM1, N("-20"))}, "exp(x)", "1", None),
    ("ln", {"x": (NUM1, N("10"))}, "ln(x)", "1", "2.302585092994045684017991454684364"),
    ("ln-zero", {"x": (NUM1, N("0"))}, "ln(x)", "1", "E_FORMULA_DOMAIN"),
    ("ln-tiny", {"x": (NUM1, N("0.000000000000000000000000000001"))}, "ln(x)", "1", None),
    ("sin", {"x": (NUM1, N("1"))}, "sin(x)", "1", "0.8414709848078965066525023216302990"[:36].rstrip("0")),
    ("cos", {"x": (NUM1, N("1"))}, "cos(x)", "1", "0.5403023058681397174009366074429766"),
    ("sin-degrees", {"x": (arg("number", "deg"), N("30"))}, "sin(x)", "1", None),
    ("sin-large", {"x": (NUM1, N("1000"))}, "sin(x)", "1", None),
    ("sin-domain", {"x": (NUM1, N("10000000"))}, "sin(x)", "1", "E_FORMULA_DOMAIN"),
    ("atan2", {"x": (NUM1, N("1")), "y": (NUM1, N("1"))}, "atan2(y, x)", "1", "0.7853981633974483096156608458198757"),
    ("atan2-quadrants", {"x": (NUM1, N("-1")), "y": (NUM1, N("-1"))}, "atan2(y, x)", "1", None),
    ("atan2-origin", {"x": (NUM1, N("0")), "y": (NUM1, N("0"))}, "atan2(y, x)", "1", "E_FORMULA_DOMAIN"),
    ("pi", {}, "pi()", "1", "3.141592653589793238462643383279503"),
    ("haversine", {"x": (arg("number", "deg"), N("51.5074"))}, "haversine(x, -0.1278, 48.8566, 2.3522)", "m", "343556.535"),
    ("haversine-domain", {"x": (arg("number", "deg"), N("91"))}, "haversine(x, 0, 0, 0)", "m", "E_FORMULA_DOMAIN"),
    ("round-half-away", {"x": (NUM1, N("2.5"))}, "round(x)", "1", "3"),
    ("round-half-away-negative", {"x": (NUM1, N("-2.5"))}, "round(x)", "1", "-3"),
    ("round-digits-exact", {"x": (NUM1, N("1.005"))}, "round(x, 2)", "1", "1.01"),
    ("round-negative-digits", {"x": (NUM1, N("1234.5678"))}, "round(x, -2)", "1", "1200"),
    ("round-up-down", {"x": (NUM1, N("-3.75"))}, "round_up(x, 1) * 10 + round_down(x, 1)", "1", "-41.7"),
    ("floor-ceiling", {"x": (NUM1, N("-3.5"))}, "floor(x) * 10 + ceiling(x)", "1", "-43"),
    ("mod-sign", {"x": (NUM1, N("-3")), "y": (NUM1, N("2"))}, "mod(x, y)", "1", "1"),
    ("mod-decimal", {"x": (NUM1, N("5.5")), "y": (NUM1, N("-2"))}, "mod(x, y)", "1", "-0.5"),
    ("mod-zero", {"x": (NUM1, N("1")), "y": (NUM1, N("0"))}, "mod(x, y)", "1", "E_FORMULA_DIV_ZERO"),
    ("abs", {"a": (EURA, N("-4.2"))}, "abs(a)", "EUR", "4.2"),
    ("convert-percent", {"r": (arg("number", "percent"), N("5"))}, 'convert(r, "1")', "1", "0.05"),
    ("convert-celsius", {"t": (arg("number", "degC"), N("20"))}, 'convert(t, "K")', "K", "293.15"),
    ("convert-degrees", {"x": (arg("number", "deg"), N("180"))}, 'convert(x, "1")', "1", "3.141592653589793238462643383279503"),
    ("convert-length", {"x": (arg("number", "km"), N("1.5"))}, 'convert(x, "m")', "m", "1500"),
    ("short-circuit-or", {"x": (NUM1, N("0"))}, "x = 0 or 1 / x > 0", "boolean", True),
    ("short-circuit-and", {"x": (NUM1, N("0"))}, "x <> 0 and 1 / x > 0", "boolean", False),
    ("if-unchosen-branch", {"x": (NUM1, N("0"))}, "if x = 0 then 0 else 1 / x", "1", "0"),
    ("let-eager", {"x": (NUM1, N("0"))}, "let q = 1 / x in if x = 0 then 0 else q", "1", "E_FORMULA_DIV_ZERO"),
    ("len-code-points", {"s": (STR, S("Zürich"))}, "len(s)", "1", "6"),
    ("upper", {"s": (STR, S("Zürich"))}, "upper(s)", "string", "ZÜRICH"),
    ("lower", {"s": (STR, S("ÄBC"))}, "lower(s)", "string", "äbc"),
    ("trim", {"s": (STR, S("  a   b  "))}, "trim(s)", "string", "a b"),
    ("concat-nfc", {"s": (STR, S("e"))}, 'len(s & "́")', "1", "1"),
    ("substr", {"s": (STR, S("Datumesh"))}, "substr(s, 3, 4)", "string", "tume"),
    ("substr-domain", {"s": (STR, S("Datumesh"))}, "substr(s, 0, 4)", "string", "E_FORMULA_DOMAIN"),
    ("find", {"s": (STR, S("Datumesh"))}, 'find("m", s)', "1", "5"),
    ("find-not-found", {"s": (STR, S("Datumesh"))}, 'find("x", s)', "1", "0"),
    ("find-start", {"s": (STR, S("mama"))}, 'find("m", s, start: 2)', "1", "3"),
    ("text-number", {"x": (NUM1, N("1.5"))}, "text(x)", "string", "1.5"),
    ("text-boolean", {}, "text(1 < 2)", "string", "true"),
    ("fixed", {"x": (NUM1, N("1234.567"))}, "fixed(x, 1)", "string", "1234.6"),
    ("fixed-pad", {"x": (NUM1, N("1.2"))}, "fixed(x, 3)", "string", "1.200"),
    ("string-range", {}, '"' + "a" * 600 + '" & "' + "b" * 600 + '"', "string", "E_FORMULA_RANGE"),
    ("date-leap", {}, "date(2024, 2, 29)", "date", "2024-02-29"),
    ("date-domain", {}, "date(2023, 2, 29)", "date", "E_FORMULA_DOMAIN"),
    ("date-parts", {"d": (DATEA, D("2024-03-15"))}, "year(d) * 10000 + month(d) * 100 + day(d) + weekday(d) / 10", "1",
     "20240315.5"),
    ("end-of-month", {"d": (DATEA, D("2024-02-10"))}, "end_of_month(d)", "date", "2024-02-29"),
    ("add-days", {"d": (DATEA, D("2026-04-01"))}, "add_days(d, 3)", "date", "2026-04-04"),
    ("add-days-calendar", {"d": (DATEA, D("2026-04-01"))},
     'add_days(d, 3, calendar: calendars.example.org/holiday("gb-eaw", *))', "date", "2026-04-08"),
    ("add-days-calendar-back", {"d": (DATEA, D("2026-04-08"))},
     'add_days(d, -3, calendar: calendars.example.org/holiday("gb-eaw", *))', "date", "2026-04-01"),
    ("add-days-range", {"d": (DATEA, D("9999-12-30"))}, "add_days(d, 5)", "date", "E_FORMULA_RANGE"),
    ("add-months-clamp", {"d": (DATEA, D("2024-01-31"))}, "add_months(d, 1)", "date", "2024-02-29"),
    ("add-months-modified-following", {"d": (DATEA, D("2026-04-30"))},
     'add_months(d, 1, calendar: calendars.example.org/holiday("gb-eaw", *), roll: "modified_following")', "date",
     "2026-05-29"),
    ("business-days", {"d": (DATEA, D("2026-04-01")), "d2": (DATEA, D("2026-04-10"))},
     'business_days(d, d2, calendar: calendars.example.org/holiday("gb-eaw", *))', "d", "6"),
    ("business-days-reversed", {"d": (DATEA, D("2026-04-01")), "d2": (DATEA, D("2026-04-10"))},
     'business_days(d2, d, calendar: calendars.example.org/holiday("gb-eaw", *))', "d", "-6"),
    ("business-days-fri-sat", {"d": (DATEA, D("2026-04-01")), "d2": (DATEA, D("2026-04-10"))},
     'business_days(d, d2, weekend: "fri-sat")', "d", "7"),
    ("year-fraction-act-360", {"d": (DATEA, D("2024-01-01")), "d2": (DATEA, D("2024-07-01"))},
     'year_fraction(d, d2, "act/360")', "1", "0.5055555555555555555555555555555556"),
    ("year-fraction-act-365f", {"d": (DATEA, D("2024-01-01")), "d2": (DATEA, D("2024-07-01"))},
     'year_fraction(d, d2, "act/365f")', "1", None),
    ("year-fraction-act-act-isda", {"d": (DATEA, D("2023-07-01")), "d2": (DATEA, D("2024-07-01"))},
     'year_fraction(d, d2, "act/act_isda")', "1", None),
    ("year-fraction-30-360", {"d": (DATEA, D("2024-01-31")), "d2": (DATEA, D("2024-03-31"))},
     'year_fraction(d, d2, "30/360")', "1", "0.1666666666666666666666666666666667"),
    ("year-fraction-30e-360", {"d": (DATEA, D("2024-01-31")), "d2": (DATEA, D("2024-02-29"))},
     'year_fraction(d, d2, "30e/360")', "1", "0.08055555555555555555555555555555556"),
    ("year-fraction-30-360-us", {"d": (DATEA, D("2024-02-29")), "d2": (DATEA, D("2024-03-31"))},
     'year_fraction(d, d2, "30/360_us")', "1", "0.08333333333333333333333333333333333"),
    ("instant-plus", {"t": (INSTA, I("2026-03-01T10:00:00.000000Z"))}, "t + 90 min", "instant",
     "2026-03-01T11:30:00.000000Z"),
    ("instant-difference", {"t": (INSTA, I("2026-03-01T10:00:00.250000Z"))}, "t - 2026-03-01T00:00:00.000000Z", "s",
     "36000.25"),
    ("instant-sub-microsecond", {"t": (INSTA, I("2026-03-01T10:00:00.000000Z"))}, "t + 0.0000001 s", "instant",
     "E_FORMULA_DOMAIN"),
    ("read-current", {"s": (STR, S("bolt"))}, "data.example.org/price(s)", "EUR", "2.75"),
    ("read-earlier-asof", {"s": (STR, S("bolt"))}, "data.example.org/price(s)", "EUR", "2.5",
     "2026-03-01T00:00:00.000000Z"),
    ("read-not-covered", {"s": (STR, S("screw"))}, "data.example.org/price(s)", "EUR", "E_FORMULA_NOT_COVERED"),
    ("asof-read", {"s": (STR, S("bolt"))}, "asof(data.example.org/price(s), 2026-03-15T00:00:00.000000Z)", "EUR", "2.5"),
    ("asof-future", {"s": (STR, S("bolt"))}, "asof(data.example.org/price(s), 2026-07-01T00:00:00.000000Z)", "EUR",
     "E_FORMULA_FUTURE"),
    ("versions-count", {"s": (STR, S("bolt"))},
     "count(versions(data.example.org/price(s), 2026-01-01T00:00:00.000000Z, asof()))", "count", "2"),
    ("versions-first", {"s": (STR, S("bolt"))},
     "first(versions(data.example.org/price(s), 2026-01-01T00:00:00.000000Z, 2026-05-01T00:00:00.000000Z))", "EUR", "2.5"),
    ("versions-future", {"s": (STR, S("bolt"))},
     "count(versions(data.example.org/price(s), 2026-01-01T00:00:00.000000Z, 2026-09-01T00:00:00.000000Z))", "count",
     "E_FORMULA_FUTURE"),
    ("slice-sum", {}, "sum(data.example.org/daily(*))", "EUR", "118"),
    ("slice-count", {}, "count(data.example.org/daily(*))", "count", "10"),
    ("slice-mean", {}, "mean(data.example.org/daily(*))", "EUR", "11.8"),
    ("slice-median-even", {}, "median(data.example.org/daily(*))", "EUR", "11.5"),
    ("slice-stdev", {}, "stdev(data.example.org/daily(*))", "EUR", None),
    ("slice-stdev-p", {}, "stdev_p(data.example.org/daily(*))", "EUR", None),
    ("slice-min-max", {}, "max(data.example.org/daily(*)) - min(data.example.org/daily(*))", "EUR", "8"),
    ("slice-first-last", {}, "first(data.example.org/daily(*)) + last(data.example.org/daily(*))", "EUR", "20"),
    ("slice-range", {}, "sum(data.example.org/daily([2026-03-03..2026-03-05]))", "EUR", "35"),
    ("slice-range-reversed", {}, "sum(data.example.org/daily([2026-03-05..2026-03-01]))", "EUR", "E_FORMULA_DOMAIN"),
    ("slice-empty-mean", {}, "mean(data.example.org/daily([2027-01-01..2027-01-31]))", "EUR", "E_FORMULA_EMPTY"),
    ("slice-empty-sum", {}, "sum(data.example.org/daily([2027-01-01..2027-01-31]))", "EUR", "0"),
    ("slice-empty-count", {}, "count(data.example.org/daily([2027-01-01..2027-01-31]))", "count", "0"),
    ("otherwise-empty", {}, "otherwise(mean(data.example.org/daily([2027-01-01..2027-01-31])), 0)", "EUR", "0"),
    ("otherwise-absent", {"d": (DATEA, D("2027-01-01"))}, "otherwise(at(data.example.org/daily(*), d), -1)", "EUR", "-1"),
    ("otherwise-not-covered", {"s": (STR, S("screw"))}, "otherwise(data.example.org/price(s), 0)", "EUR",
     "E_FORMULA_NOT_COVERED"),
    ("at-absent", {"d": (DATEA, D("2027-01-01"))}, "at(data.example.org/daily(*), d)", "EUR", "E_FORMULA_ABSENT"),
    ("at", {"d": (DATEA, D("2026-03-04"))}, "at(data.example.org/daily(*), d)", "EUR", "15"),
    ("join", {}, "sum(data.example.org/price(*) * data.example.org/qty(*))", "EUR", "23.5"),
    ("filter", {}, "count(filter(data.example.org/daily(*), v -> v > 12 EUR))", "count", "4"),
    ("map-key", {}, "sum(map(data.example.org/daily(*), (v, date) -> if weekday(date) > 5 then 0 EUR else v))", "EUR", "86"),
    ("scan", {}, "last(scan(data.example.org/daily(*), sum))", "EUR", "118"),
    ("window", {}, "max(window(data.example.org/daily(*), 3, mean))", "EUR", "13"),
    ("window-width", {}, "max(window(data.example.org/daily(*), 0, mean))", "EUR", "E_FORMULA_DOMAIN"),
    ("latest", {"s": (STR, S("kew"))}, "latest(weather.example.org/temp(s, *))", "degC", "11.9"),
    ("latest-before-late-sample", {"s": (STR, S("kew"))}, "latest(weather.example.org/temp(s, *))", "degC", "11.7",
     BEFORE_LATE_SAMPLE),
    ("last-before", {"s": (STR, S("kew")), "t": (INSTA, I(T_KEW))},
     "last_before(weather.example.org/temp(s, *), t, 10 min)", "degC", "11.5"),
    ("last-before-stale", {"s": (STR, S("kew")), "t": (INSTA, I("2026-03-01T10:20:00.000000Z"))},
     "last_before(weather.example.org/temp(s, *), t, 10 min)", "degC", "E_FORMULA_ABSENT"),
    ("first-after", {"s": (STR, S("kew")), "t": (INSTA, I("2026-03-01T10:01:00.000000Z"))},
     "first_after(weather.example.org/temp(s, *), t, 10 min)", "degC", "11.7"),
    ("nearest", {"s": (STR, S("kew")), "t": (INSTA, I("2026-03-01T10:04:00.000000Z"))},
     "nearest(weather.example.org/temp(s, *), t)", "degC", "11.7"),
    ("nearest-tie-earlier", {"s": (STR, S("kew")), "t": (INSTA, I("2026-03-01T10:03:30.000000Z"))},
     "nearest(weather.example.org/temp(s, *), t)", "degC", "11.5"),
    ("within", {"s": (STR, S("kew")), "t": (INSTA, I(T_KEW))},
     "mean(within(weather.example.org/temp(s, *), t, 5 min))", "degC", "11.7"),
    ("interpolate-linear", {"s": (STR, S("kew")), "t": (INSTA, I("2026-03-01T10:03:30.000000Z"))},
     "interpolate(weather.example.org/temp(s, *), t)", "degC", "11.6"),
    ("interpolate-step", {"s": (STR, S("kew")), "t": (INSTA, I("2026-03-01T10:03:30.000000Z"))},
     'interpolate(weather.example.org/temp(s, *), t, "step")', "degC", "11.5"),
    ("interpolate-exact", {"s": (STR, S("kew")), "t": (INSTA, I("2026-03-01T10:07:00.000000Z"))},
     "interpolate(weather.example.org/temp(s, *), t)", "degC", "11.7"),
    ("interpolate-beyond", {"s": (STR, S("kew")), "t": (INSTA, I("2026-03-01T11:00:00.000000Z"))},
     "interpolate(weather.example.org/temp(s, *), t)", "degC", "E_FORMULA_ABSENT"),
    ("grouped-mean", {"t": (INSTA, I("2026-03-01T10:08:00.000000Z"))},
     "mean(last_before(weather.example.org/temp(*, *), t, 10 min))", "degC", "10.475"),
    ("fresh-asof-dependent", {"s": (STR, S("kew"))}, "latest(weather.example.org/temp(s, *), 15 min)", "degC", "11.7",
     "2026-03-01T10:09:00.000000Z"),
    ("fresh-stale", {"s": (STR, S("kew"))}, "latest(weather.example.org/temp(s, *), 15 min)", "degC", "E_FORMULA_ABSENT",
     BEFORE_LATE_SAMPLE),
    ("asof-value", {}, "asof()", "instant", "2026-03-01T10:09:00.000000Z", "2026-03-01T10:09:00.000000Z"),
    ("is-holiday", {"d": (DATEA, D("2026-04-03"))}, 'is_holiday(d, calendars.example.org/holiday("gb-eaw", *))',
     "boolean", True),
    ("fx-forward", {"base": (STR, S("EUR")), "quote": (STR, S("USD")), "d": (DATEA, D("2026-03-02"))},
     'rates.example.org/fx_rate(base, quote, d) * (1 + rates.example.org/rate(quote, "1M")) / '
     '(1 + rates.example.org/rate(base, "1M"))', RATE_UNIT, None),
    ("fib-30", {"n": (NUM1, N("30"))}, "math.example.net/fib(n)", "1", "832040"),
    ("fib-90", {"n": (NUM1, N("90"))}, "math.example.net/fib(n)", "1", "2880067194370816120"),
    ("curve", {}, "curve.example.net/df(4)", "1", expected_df(4)),
    ("curve-slice", {}, "sum(curve.example.net/df([1..10]))", "1", None),
    ("member-fault-is-absence", {}, "sum(math.example.net/recip(*))", "1", "E_FORMULA_ABSENT"),
    ("member-fault-caught", {}, "otherwise(sum(math.example.net/recip(*)), 0)", "1", "0"),
    ("cycle", {}, "math.example.net/loop(1)", "1", "E_FORMULA_CYCLE"),
    ("depth", {}, "math.example.net/chain(60)", "1", "E_FORMULA_DEPTH", L_, {"max_depth": 20}),
    ("budget", {}, "sum(data.example.org/daily(*))", "EUR", "E_FORMULA_BUDGET", L_, {"fuel": 5}),
    ("blob-equality", {"s": (STR, S("acme"))}, "data.example.org/doc(s) = data.example.org/doc(s)", "boolean", True),
    ("boolean-read", {"s": (STR, S("acme"))}, "data.example.org/active(s) and true", "boolean", True),
    ("string-read", {"s": (STR, S("acme"))}, 'data.example.org/name(s) & " (" & text(year(data.example.org/incorporated(s))) & ")"',
     "string", "Acme Ltd (1999)"),
]


def eval_vectors(add):
    for item in EVAL:
        name, args, source, returns, expected = item[:5]
        asof = item[5] if len(item) > 5 else LATER
        options = item[6] if len(item) > 6 else {}
        names = list(args)
        fns, _ = _base()
        descriptor = define(E, {n: d for n, (d, _) in args.items()}, names, source, returns, fns)
        world_options = {k: v for k, v in options.items() if k == "max_depth"}
        world = world_for(descriptor, world_options)
        vec = {"kind": "formula-eval", "world": world, "cell": {"args": {n: v for n, (_, v) in args.items()}, "fn": E},
               "asof": asof}
        if "fuel" in options:
            vec["fuel"] = options["fuel"]
        got = F.run_vector(vec)
        error = expected if isinstance(expected, str) and expected.startswith("E_FORMULA_") else None
        if error is None and "error" in got:
            raise SystemExit(f"formula-eval/{name}: {got['detail']}")
        if error is None and expected is not None:
            want = expected if not isinstance(expected, bool) else expected
            if got["value"]["value"] != want:
                raise SystemExit(f"formula-eval/{name}: expected {want!r}, the reference gives {got['value']['value']!r}")
        description = f"{source}  (with {', '.join(f'{n} = {v['value']}' for n, (_, v) in args.items()) or 'no arguments'})"
        vid = f"formula-eval/{name}" if error is None else f"invalid/formula-eval-{name}"
        extra = {k: vec[k] for k in ("world", "cell", "asof") if k in vec}
        if "fuel" in vec:
            extra["fuel"] = vec["fuel"]
        add(vid, "formula-eval", description, None, error, **extra)


# ---------------------------------------------------------------------------
# Slice objects and manifests (kind slice)

def daily_hash():
    return canon.function_hash(FUNCTIONS[DL_])


def slice_vectors(add, text):
    h = daily_hash()
    temp_h = canon.function_hash(FUNCTIONS[TP_])
    unb = F.slice_object(h, DL_, {"date": "*"})
    rng = F.slice_object(h, DL_, {"date": {"hi": "2026-03-05", "lo": "2026-03-01", "type": "date"}})
    two = F.slice_object(temp_h, TP_, {"station": "*", "t": "*"})
    inst = F.slice_object(temp_h, TP_, {"station": S("kew"), "t": {"hi": "2026-03-01T10:05:00.000000Z",
                                                                    "lo": "2026-03-01T09:55:00.000000Z", "type": "instant"}})
    num = F.slice_object(canon.function_hash(FUNCTIONS["data.example.org/sized"]), "data.example.org/sized",
                         {"size": {"hi": "2", "lo": "1.5", "type": "number"}})
    strs = F.slice_object(canon.function_hash(FUNCTIONS["data.example.org/name"]), "data.example.org/name",
                          {"company": {"hi": "m", "lo": "a", "type": "string"}})
    cell = {"args": {"item": S("bolt")}, "fn": "price", "fn_hash": canon.function_hash(FUNCTIONS["data.example.org/price"]),
            "ns": "data.example.org"}
    ver = {"cell": cell, "from": "2026-01-01T00:00:00.000000Z", "to": "2026-05-01T00:00:00.000000Z"}
    members = sorted([canon.sha256_hex(f"m{i}".encode()) for i in range(3)])
    for name, obj, d in [("unbounded", unb, "An unbounded slice: the cell object of SPEC 4.4 with a *; its id is that cell id."),
                         ("range", rng, "A bounded slice: a range object {hi, lo, type}, inclusive."),
                         ("two-open", two, "Two open arguments."),
                         ("range-instant", inst, "An instant range, as a bounded lookup records it."),
                         ("range-number", num, "A number range."), ("range-string", strs, "A string range (code point order)."),
                         ("version", ver, "A version slice: one cell's versions with tx in [from, to].")]:
        add(f"slice/{name}", "slice", d, text(obj))
    add("slice/manifest", "slice", "A manifest: the slice object and the sorted member receipt hashes; "
        "the entry is slice:<slice id>:<members hash>.", text(F.manifest(rng, members)))
    add("slice/manifest-empty", "slice", "An empty slice: the members hash is SHA-256 of [].", text(F.manifest(rng, [])))
    add("slice/manifest-version", "slice", "A version slice's manifest.", text(F.manifest(ver, members[:2])))
    add("slice/range-reversed", "slice", "lo > hi is an empty range, not an error, in a slice object (a narrowed "
        "lookup can record one).", text(F.slice_object(h, DL_, {"date": {"hi": "2026-03-01", "lo": "2026-03-05",
                                                                          "type": "date"}})))
    add("invalid/slice-no-open-argument", "slice", "A slice object has an open or ranged argument.",
        text(F.slice_object(h, DL_, {"date": D("2026-03-01")})), "E_SLICE")
    add("invalid/slice-range-boolean", "slice", "Booleans have no ranges.",
        text(F.slice_object(h, DL_, {"date": {"hi": "true", "lo": "false", "type": "boolean"}})), "E_CANON_TYPE")
    add("invalid/slice-range-lexical", "slice", "Range ends follow the lexical rules of their type.",
        text(F.slice_object(h, DL_, {"date": {"hi": "2026-02-30", "lo": "2026-02-01", "type": "date"}})), "E_CANON_DATE")
    add("invalid/slice-version-of-slice", "slice", "A version slice is of one cell.",
        text({"cell": dict(cell, args={"item": "*"}), "from": ver["from"], "to": ver["to"]}), "E_SLICE")
    add("invalid/slice-manifest-member-hex", "slice", "Members are receipt hashes.",
        text(F.manifest(rng, [m.upper() for m in members])), "E_CANON_HEX")
    add("invalid/slice-manifest-duplicate", "slice", "Members are a set: ascending, no duplicates.",
        text({"members": [members[0], members[0]], "slice": rng}), "E_CANON_SET")
    add("invalid/slice-schema", "slice", "A range object has exactly hi, lo and type.",
        text(F.slice_object(h, DL_, {"date": {"hi": "2026-03-05", "lo": "2026-03-01", "step": "1", "type": "date"}})),
        "E_SCHEMA")


# ---------------------------------------------------------------------------
# Descriptors with order and extent (kind function)

def function_vectors(add, text):
    base = stored({"base": STR, "date": arg("date", valid=True), "quote": STR}, ["base", "quote", "date"], RATE_UNIT)
    add("function/order", "function", "signature.order: every argument once, in the order positional arguments bind. "
        "Optional and hashed; absent, a descriptor is byte-identical to spec-0.3.0.", text(base))
    ext = stored({"currency": arg("string", extent=["CHF", "EUR", "GBP", "USD"]), "tenor": arg("number", "1", extent=[
        "0.25", "0.5", "1", "2", "10"])}, ["currency", "tenor"], "1")
    ext["code"] = {"body": "1\n", "lang": "formula"}
    add("function/extent-values", "function", "Per-argument extents: values in their type's order (numbers numerically).",
        text(ext))
    rng = stored({"tenor": arg("number", "1", extent={"hi": "10", "lo": "1"}), "date": arg(
        "date", valid=True, extent={"hi": "2026-12-31", "lo": "2026-01-01"})}, ["date", "tenor"], "1")
    add("function/extent-range", "function", "Extent ranges for date and integer number arguments.", text(rng))
    add("function/formula-descriptor", "function", "A formula descriptor as define writes it: body printed from the "
        "canonical AST, inputs derived, order present.", text(world_fib()["functions"][FIB]["descriptor"]))

    def bad(name, mutate, error, description):
        d = json.loads(json.dumps(base))
        mutate(d)
        add(f"invalid/function-{name}", "function", description, text(d), error)
    bad("order-missing-argument", lambda d: d["signature"].update(order=["base", "quote"]), "E_CANON_SET",
        "order lists every argument.")
    bad("order-duplicate", lambda d: d["signature"].update(order=["base", "quote", "date", "base"]), "E_CANON_SET",
        "order lists each argument once.")
    bad("order-unknown", lambda d: d["signature"].update(order=["base", "quote", "day"]), "E_CANON_SET",
        "order names only arguments.")
    bad("order-not-array", lambda d: d["signature"].update(order="base,quote,date"), "E_SCHEMA", "order is an array.")
    bad("extent-unsorted", lambda d: d["signature"]["args"]["base"].update(extent=["USD", "EUR"]), "E_CANON_SET",
        "Extent values are strictly ascending.")
    bad("extent-number-order", lambda d: d["signature"]["args"].update(n=arg("number", "1", extent=["10", "9"])) or
        d["signature"].update(order=["base", "quote", "date", "n"]), "E_CANON_SET",
        "Number extents ascend numerically: 9 before 10.")
    bad("extent-lexical", lambda d: d["signature"]["args"]["date"].update(extent=["2026-02-30"]), "E_CANON_DATE",
        "Extent values follow their type's lexical form.")
    bad("extent-boolean", lambda d: d["signature"]["args"].update(f=arg("boolean", extent=["false", "true"])) or
        d["signature"].update(order=["base", "quote", "date", "f"]), "E_CANON_TYPE", "A boolean has no extent.")
    bad("extent-range-reversed", lambda d: d["signature"]["args"]["date"].update(extent={"hi": "2026-01-01", "lo": "2026-12-31"}),
        "E_CANON_SET", "An extent range has lo <= hi.")
    bad("extent-range-decimal", lambda d: d["signature"]["args"].update(n=arg("number", "1", extent={"hi": "2.5", "lo": "1"}))
        or d["signature"].update(order=["base", "quote", "date", "n"]), "E_CANON_NUMBER", "Number ranges have integer ends.")
    bad("extent-range-string", lambda d: d["signature"]["args"]["base"].update(extent={"hi": "Z", "lo": "A"}),
        "E_CANON_TYPE", "A string extent lists its values.")
    bad("extent-shape", lambda d: d["signature"]["args"]["base"].update(extent={"hi": "Z", "lo": "A", "step": "1"}),
        "E_SCHEMA", "An extent range has exactly hi and lo.")


# ---------------------------------------------------------------------------
# Envelopes with a fault

def envelope_vectors(add, text):
    cid = canon.sha256_hex(b"any cell")
    add("envelope/not-covered-fault", "envelope", "A computed cell with no value: not_covered, with the formula fault "
        "code so that a fault is not mistaken for missing data (SPEC 5.5).",
        json.dumps({"fault": "E_FORMULA_DIV_ZERO", "outcome": "not_covered"}), status=404, keys={},
        request={"cell_id": cid})
    add("invalid/envelope-not-covered-fault-unknown", "envelope", "Only evaluation faults: running out of fuel is the "
        "mesh's failure (error, E_EVAL_UNAVAILABLE).", json.dumps({"fault": "E_FORMULA_BUDGET", "outcome": "not_covered"}),
        "E_ENVELOPE", status=404, keys={}, request={"cell_id": cid})
    add("invalid/envelope-ok-with-fault", "envelope", "fault belongs to not_covered only.",
        json.dumps({"fault": "E_FORMULA_DIV_ZERO", "outcome": "unlicensed"}), "E_ENVELOPE", status=403, keys={},
        request={"cell_id": cid})


# ---------------------------------------------------------------------------
# Slice-lineage receipts (kind receipt)

def engine_sign(unsigned):
    return canon.sign_receipt(unsigned, F.host_seed(F.ENGINE_HOST))


def _answer(spec, fq, args, asof, fuel=None):
    world = F.world_of(spec)
    a = world.get(fq, args, asof, fuel=fuel)
    return world, a


def _recompute(world, descriptor, value, lineage=None):
    rec = {"descriptor": descriptor, "inputs": dict(sorted(world.receipts.items())),
           "manifests": dict(sorted(world.manifests.items())), "value": value}
    if lineage is not None:
        rec["lineage"] = lineage
    return rec


def receipt_vectors(add, text):
    kp = keypair(F.ENGINE_HOST)

    def add_r(id_, description, receipt, recompute=None, error=None):
        extra = {"keypair": kp, "keys": KEYS}
        if recompute is not None:
            extra["recompute"] = recompute
        add(id_, "receipt", description, text(receipt), error, **extra)

    wspec = world_weighted(5)
    world, a = _answer(wspec, WMEAN, {"date": D("2026-03-01")}, LATER)
    wdesc = wspec["functions"][WMEAN]["descriptor"]
    value = {"type": "number", "value": a.receipt["value"]}
    rec = _recompute(world, wdesc, value)
    add_r("receipt/slice-weighted-mean", "A weighted mean over five stations: two slice entries (temperatures, weights), "
          "each one entry whatever the member count; recomputed through manifests and members.", a.receipt, rec)
    add_r("receipt/slice-signed-only", "Signature-valid without recomputation: a verifier at level signed only accepts "
          "the entry form in step 3.", a.receipt)
    add_r("invalid/receipt-slice-value-mismatch", "A recomputation that gives another value, without a lineage: "
          "E_VALUE_MISMATCH.", a.receipt, dict(rec, value={"type": "number", "value": "0"}), "E_VALUE_MISMATCH")
    add_r("invalid/receipt-slice-manifest-unavailable", "No manifest for a slice entry.", a.receipt,
          dict(rec, manifests={}), "E_INPUT_UNAVAILABLE")
    entry = a.receipt["inputs"][0]
    m = json.loads(rec["manifests"][entry])
    other = dict(rec["manifests"])
    other[entry] = json.dumps({"members": m["members"][:-1], "slice": m["slice"]})
    add_r("invalid/receipt-slice-manifest-mismatch", "A manifest that does not hash to the entry.", a.receipt,
          dict(rec, manifests=other), "E_INPUT_UNAVAILABLE")
    other = dict(rec["manifests"])
    other[entry] = json.dumps({"members": list(reversed(m["members"])), "slice": m["slice"]})
    add_r("invalid/receipt-slice-manifest-unsorted", "Manifest members are a set: checked before the hashes.", a.receipt,
          dict(rec, manifests=other), "E_CANON_SET")
    other = dict(rec["manifests"])
    other[entry] = json.dumps({"members": m["members"]})
    add_r("invalid/receipt-slice-manifest-schema", "A manifest has exactly members and slice.", a.receipt,
          dict(rec, manifests=other), "E_SCHEMA")
    inputs = dict(rec["inputs"])
    del inputs[m["members"][0]]
    add_r("invalid/receipt-slice-member-unavailable", "A member receipt that cannot be obtained.", a.receipt,
          dict(rec, inputs=inputs), "E_INPUT_UNAVAILABLE")
    inputs = dict(rec["inputs"])
    tampered = json.loads(inputs[m["members"][0]])
    tampered["summary"] = "Tampered."
    inputs[m["members"][0]] = json.dumps(tampered)
    add_r("invalid/receipt-slice-member-invalid", "A member receipt that is not signature-valid.", a.receipt,
          dict(rec, inputs=inputs), "E_INPUT_INVALID")

    # Hand-built receipts over the base world's daily values: one input slice, checked member by member.
    fns, receipts = _base()
    daily_receipts = sorted([r for r in receipts if r["cell"]["fn"] == "daily"], key=lambda r: r["cell"]["args"]["date"]["value"])
    texts = {canon.receipt_hash(r): json.dumps(r) for r in daily_receipts}
    hashes = [canon.receipt_hash(r) for r in daily_receipts]
    sdesc = define(E, {}, [], "sum(data.example.org/daily([2026-03-01..2026-03-05]))", "EUR", fns)
    cell = {"args": {}, "fn": "e", "fn_hash": canon.function_hash(sdesc), "ns": "calc.example.net"}

    def built(obj, members, value, tx=None, asof=None, extra_inputs=(), entries=None):
        entry = F.slice_entry(obj, members)
        txs = [json.loads(texts[mh])["tx"] for mh in members]
        txs += [json.loads(texts[mh])["tx"] for mh in extra_inputs]
        tx = tx or (max(txs) if txs else F.MIN_INSTANT)
        asof = asof or max([json.loads(texts[mh])["asof"] for mh in members] + [BOUND, tx])
        unsigned = {"asof": asof, "cell": cell, "computed_by": f"{F.ENGINE_HOST}#{kp['key_id']}",
                    "inputs": entries if entries is not None else sorted([entry] + list(extra_inputs), key=canon._utf16_key),
                    "issued": max(asof, F.KEY_FROM), "licence": F.COMPUTED_LICENCE, "proto": canon.PROTO,
                    "publisher": "calc.example.net", "summary": F.COMPUTED_SUMMARY, "tx": tx, "type": "number",
                    "valid": {}, "value": value}
        return engine_sign(unsigned), {entry: json.dumps(F.manifest(obj, members))}

    h = daily_hash()
    five = F.slice_object(h, DL_, {"date": {"hi": "2026-03-05", "lo": "2026-03-01", "type": "date"}})
    r5, man5 = built(five, hashes[:5], "57")
    rec5 = {"descriptor": sdesc, "inputs": texts, "manifests": man5, "value": N("57")}
    add_r("receipt/slice-range", "A bounded slice over five daily values: sum 57.", r5, rec5)
    r_out, man_out = built(F.slice_object(h, DL_, {"date": {"hi": "2026-03-03", "lo": "2026-03-01", "type": "date"}}),
                           hashes[:2] + [hashes[4]], "57")
    add_r("invalid/receipt-slice-member-outside", "A member whose date is outside the slice's range.", r_out,
          dict(rec5, manifests=man_out), "E_SLICE_MEMBER")
    r_tx, man_tx = built(five, hashes[:5], "57", tx=json.loads(texts[hashes[3]])["tx"])
    add_r("invalid/receipt-slice-tx", "tx is the latest tx of every input receipt, slice members included.", r_tx,
          dict(rec5, manifests=man_tx), "E_TIME_ORDER")
    # A member whose asof is later than the receipt's, though its tx is not.
    late = dict(daily_receipts[4])
    late["asof"], late["issued"] = "2026-03-08T00:00:00.000000Z", "2026-03-08T00:00:00.000000Z"
    late = F.canon.sign_receipt({k: v for k, v in late.items() if k != "sig"}, F.host_seed("data.example.org"))
    lh = canon.receipt_hash(late)
    texts_late = dict(texts)
    texts_late[lh] = json.dumps(late)
    members_late = sorted(hashes[:4] + [lh])
    entry_late = F.slice_entry(five, members_late)
    unsigned = {"asof": "2026-03-06T00:00:00.000000Z", "cell": cell, "computed_by": f"{F.ENGINE_HOST}#{kp['key_id']}",
                "inputs": [entry_late], "issued": "2026-03-06T00:00:00.000000Z", "licence": F.COMPUTED_LICENCE,
                "proto": canon.PROTO, "publisher": "calc.example.net", "summary": F.COMPUTED_SUMMARY,
                "tx": late["tx"], "type": "number", "valid": {}, "value": "57"}
    add_r("invalid/receipt-slice-member-later-asof", "A member receipt whose asof is after the receipt's.",
          engine_sign(unsigned), {"descriptor": sdesc, "inputs": texts_late,
                                  "manifests": {entry_late: json.dumps(F.manifest(five, members_late))}, "value": N("57")},
          "E_TIME_ORDER")
    # Undeclared: the same receipt shape over a price slice, which sdesc does not read.
    price_obj = F.slice_object(canon.function_hash(fns["data.example.org/price"]), "data.example.org/price", {"item": "*"})
    price_receipts = [r for r in receipts if r["cell"]["fn"] == "price" and r["tx"] < "2026-03-01"]
    ptexts = {canon.receipt_hash(r): json.dumps(r) for r in price_receipts}
    texts.update(ptexts)
    r_und, man_und = built(price_obj, sorted(ptexts), "57")
    add_r("invalid/receipt-slice-undeclared", "A slice of a function the descriptor does not read.", r_und,
          dict(rec5, manifests=man_und), "E_INPUT_UNDECLARED")
    two_versions = sorted(canon.receipt_hash(r) for r in receipts if r["cell"]["fn"] == "price"
                          and r["cell"]["args"]["item"]["value"] == "bolt")
    texts.update({canon.receipt_hash(r): json.dumps(r) for r in receipts if r["cell"]["fn"] == "price"})
    pdesc = define(E, {}, [], "sum(data.example.org/price(*))", "EUR", fns)
    pcell = dict(cell, fn_hash=canon.function_hash(pdesc))
    entry_dup = F.slice_entry(price_obj, two_versions)
    txd = max(json.loads(texts[x])["tx"] for x in two_versions)
    unsigned = {"asof": txd, "cell": pcell, "computed_by": f"{F.ENGINE_HOST}#{kp['key_id']}", "inputs": [entry_dup],
                "issued": txd, "licence": F.COMPUTED_LICENCE, "proto": canon.PROTO, "publisher": "calc.example.net",
                "summary": F.COMPUTED_SUMMARY, "tx": txd, "type": "number", "valid": {}, "value": "5.25"}
    add_r("invalid/receipt-slice-member-duplicate-cell", "Two versions of one cell in a membership slice.",
          engine_sign(unsigned), {"descriptor": pdesc, "inputs": texts,
                                  "manifests": {entry_dup: json.dumps(F.manifest(price_obj, two_versions))},
                                  "value": N("5.25")}, "E_SLICE_MEMBER")
    # Version slices.
    vdesc = define(E, {}, [], "count(versions(data.example.org/price(\"bolt\"), 2026-01-01T00:00:00.000000Z, "
                              "2026-05-01T00:00:00.000000Z))", "count", fns)
    vspec = world_for(vdesc)
    vworld, va = _answer(vspec, E, {}, LATER)
    add_r("receipt/slice-version", "A version slice: the receipt cites the cell's versions in [from, to] as one entry.",
          va.receipt, _recompute(vworld, vdesc, {"type": "number", "value": va.receipt["value"]}))
    ventry = va.receipt["inputs"][0]
    vm = json.loads(vworld.manifests[ventry])
    bad_obj = dict(vm["slice"], to="2026-03-01T00:00:00.000000Z")
    vcell = dict(va.receipt["cell"])
    entry_bad = F.slice_entry(bad_obj, vm["members"])
    unsigned = {k: v for k, v in va.receipt.items() if k != "sig"}
    unsigned["inputs"] = [entry_bad]
    unsigned["cell"] = vcell
    add_r("invalid/receipt-slice-version-outside", "A version outside the version slice's [from, to].",
          engine_sign(unsigned), dict(_recompute(vworld, vdesc, {"type": "number", "value": va.receipt["value"]}),
                                      manifests={entry_bad: json.dumps(F.manifest(bad_obj, vm["members"]))}),
          "E_SLICE_MEMBER")
    # Empty slice; mixed plain and slice inputs; computed members.
    edesc = define(E, {}, [], "sum(data.example.org/daily([2027-01-01..2027-01-31]))", "EUR", fns)
    eworld, ea = _answer(world_for(edesc), E, {}, LATER)
    add_r("receipt/slice-empty", "An empty slice is still one entry; with no input receipt, tx is unconstrained "
          "(here 0001-01-01, the engine's convention) and asof is the binding start.", ea.receipt,
          _recompute(eworld, edesc, {"type": "number", "value": "0"}))
    mdesc = define(E, {}, [], 'sum(data.example.org/daily(*)) + data.example.org/price("bolt")', "EUR", fns)
    mworld, ma = _answer(world_for(mdesc), E, {}, LATER)
    add_r("receipt/slice-mixed-inputs", "A plain receipt hash and a slice entry: hashes sort before slice entries.",
          ma.receipt, _recompute(mworld, mdesc, {"type": "number", "value": ma.receipt["value"]}))
    unsorted = {k: v for k, v in ma.receipt.items() if k != "sig"}
    unsorted["inputs"] = list(reversed(unsorted["inputs"]))
    add_r("invalid/receipt-slice-entries-unsorted", "Entries are a set in ascending order: slice entries last.",
          engine_sign(unsorted), None, "E_CANON_SET")
    for name, mutate, d in [
            ("entry-uppercase", lambda e: e.upper().replace("SLICE", "slice"), "Lowercase hex only."),
            ("entry-short", lambda e: e[:-1], "64 hex digits each side."),
            ("entry-prefix", lambda e: "Slice" + e[5:], "The prefix is slice:.")]:
        u = {k: v for k, v in ma.receipt.items() if k != "sig"}
        u["inputs"] = [x if not x.startswith("slice:") else mutate(x) for x in u["inputs"]]
        u["inputs"].sort(key=canon._utf16_key)
        add_r(f"invalid/receipt-slice-{name}", f"A malformed slice entry is E_CANON_HEX, as any malformed entry: {d}",
              engine_sign(u), None, "E_CANON_HEX")
    cspec = world_curve()
    cworld, ca = _answer(cspec, DF, {"tenor": N("3")}, LATER)
    add_r("receipt/slice-computed-members", "A slice over a computed function (the bootstrapped curve): members are "
          "computed receipts with their own lineage.", ca.receipt,
          _recompute(cworld, cspec["functions"][DF]["descriptor"], {"type": "number", "value": ca.receipt["value"]}))
    for name, fq, args, d in [
            ("slice-bounded-lookup", TEMP_AT, {"station": S("kew"), "t": I(T_KEW)},
             "A bounded lookup records the narrowed slice: t in [t - 10 min, t]."),
            ("slice-grouped", MEAN_TEMP, {"t": I("2026-03-01T10:08:00.000000Z")},
             "A grouped lookup over every station, one entry."),
            ("slice-latest", LATEST, {"station": S("kew")}, "latest over a station's whole history.")]:
        spec = world_weather()
        w, a = _answer(spec, fq, args, LATER)
        add_r(f"receipt/{name}", d, a.receipt,
              _recompute(w, spec["functions"][fq]["descriptor"], {"type": "number", "value": a.receipt["value"]}))
    jdesc = define(E, {}, [], "sum(data.example.org/price(*) * data.example.org/qty(*))", "EUR", fns)
    jworld, ja = _answer(world_for(jdesc), E, {}, LATER)
    add_r("receipt/slice-join", "An implicit join: two slice entries.", ja.receipt,
          _recompute(jworld, jdesc, {"type": "number", "value": ja.receipt["value"]}))
    # Supersession: a plain input, then a slice member.
    sspec = world_supersede()
    sworld, sa = _answer(sspec, TOTAL, {"item": S("bolt")}, LATER)
    sworld.add_receipt(backdated_correction())
    sb = sworld.get(TOTAL, {"item": S("bolt")}, sa.receipt["asof"])
    add_r("receipt/slice-superseded", "A backdated correction of an input: re-evaluated at the receipt's asof, the "
          "evaluation reads a later version of the same cell; the receipt is historical, not wrong: success at level "
          "signed with E_INPUT_SUPERSEDED.", sa.receipt,
          _recompute(sworld, sspec["functions"][TOTAL]["descriptor"], {"type": "number", "value": sb.receipt["value"]},
                     sb.receipt["inputs"]))
    rspec = world_running(10)
    rworld, ra = _answer(rspec, RUNNING, {"date": D(day(5))}, LATER)
    rworld.add_receipt(F.stored_receipt(FUNCTIONS[DAILY], DAILY, {"date": D(day(2))}, N("50"), day(3) + "T00:00:00.000000Z"))
    rb = rworld.get(RUNNING, {"date": D(day(5))}, ra.receipt["asof"])
    add_r("receipt/slice-superseded-member", "A backdated member: the same slice with other members in the evaluation's "
          "lineage: E_INPUT_SUPERSEDED.", ra.receipt,
          _recompute(rworld, rspec["functions"][RUNNING]["descriptor"], {"type": "number", "value": rb.receipt["value"]},
                     rb.receipt["inputs"]))


# ---------------------------------------------------------------------------
# Decimal vectors (kind decimal): every operation to the last digit, for other implementations.

DECIMAL_OPS = ("add", "sub", "mul", "div", "power", "sqrt", "exp", "ln", "pow", "sin", "cos", "atan2", "haversine",
               "sum", "mean", "median", "stdev", "stdev_p", "round", "mod")


def _num(rng, lo=-1000, hi=1000, places=12):
    import decimal
    d = decimal.Decimal(rng.uniform(lo, hi)).quantize(decimal.Decimal(1).scaleb(-rng.randrange(0, places)))
    t = format(d, "f")
    if "." in t:
        t = t.rstrip("0").rstrip(".")
    return "0" if t in ("-0", "") else t


def decimal_cases(op, rng, n):
    edge = {"add": [["9" * 34, "1"], ["1234567890123456789012345678901234", "0.5"], ["10", "-10"]],
            "div": [["1", "3"], ["2", "3"], ["1", "0"], ["-7", "2"]],
            "sqrt": [["2"], ["0"], ["-1"], ["0.0001"], [SQRT_HARD_CASE]],
            "exp": [["0"], ["1"], ["-1"], ["300.5"], ["290"], ["-290"]],
            "ln": [["1"], ["10"], ["0.1"], ["0"], ["2"]],
            "pow": [["2", "0.5"], ["0", "0.5"], ["-4", "0.5"], ["10", "-0.5"]],
            "sin": [["0"], ["1"], ["3.141592653589793238462643383279503"], ["10000000"]],
            "cos": [["0"], ["1"], ["1.570796326794896619231321691639751"]],
            "atan2": [["1", "1"], ["0", "0"], ["1", "0"], ["0", "-1"], ["-1", "-1"]],
            "haversine": [["51.5074", "-0.1278", "48.8566", "2.3522"], ["0", "0", "0", "180"], ["91", "0", "0", "0"]],
            "power": [["2", "10"], ["3", "-2"], ["0", "-1"], ["10", "200"], ["1", "1025"]],
            "round": [["2.5", "0"], ["-2.5", "0"], ["1.005", "2"], ["1234.5678", "-2"]],
            "mod": [["-3", "2"], ["5.5", "-2"], ["1", "0"]]}.get(op, [])
    cases = [list(c) for c in edge]
    for _ in range(n):
        if op in ("add", "sub", "mul", "div", "mod"):
            cases.append([_num(rng, -1e6, 1e6, 20), _num(rng, -1e6, 1e6, 20)])
        elif op == "power":
            cases.append([_num(rng, -10, 10, 6), str(rng.randrange(-20, 30))])
        elif op in ("sqrt", "ln"):
            cases.append([_num(rng, 0.001, 1e9, 15)])
        elif op == "exp":
            cases.append([_num(rng, -250, 250, 15)])
        elif op == "pow":
            cases.append([_num(rng, 0.01, 1000, 8), _num(rng, -10, 10, 6)])
        elif op in ("sin", "cos"):
            cases.append([_num(rng, -1000, 1000, 15)])
        elif op == "atan2":
            cases.append([_num(rng, -100, 100, 10), _num(rng, -100, 100, 10)])
        elif op == "haversine":
            cases.append([_num(rng, -90, 90, 6), _num(rng, -180, 180, 6), _num(rng, -90, 90, 6), _num(rng, -180, 180, 6)])
        elif op == "round":
            cases.append([_num(rng, -1000, 1000, 8), str(rng.randrange(-3, 6))])
        else:
            cases.append([_num(rng, -100, 100, 6) for _ in range(rng.randrange(1, 12))])
    return cases


def _sqrt_hard_case():
    """x = r * r for r = 10^33 + 2.5000001: the root's digits 35-41 are 5000001, so SQRT-T40 sees a tie
    at 40 digits and keeps the even neighbour, where correct rounding goes up."""
    import decimal
    ctx = decimal.Context(prec=200)
    r = ctx.add(decimal.Decimal(10 ** 33 + 2), decimal.Decimal("0.5000001"))
    t = format(ctx.multiply(r, r), "f")
    return t.rstrip("0").rstrip(".") if "." in t else t


SQRT_HARD_CASE = _sqrt_hard_case()
MPDECIMAL_OPS = ("sqrt", "exp", "ln", "pow")


def mpdecimal_reference(op, args):
    """The correctly rounded result from Python's decimal (mpdecimal), for comparison only."""
    import decimal
    ctx = decimal.Context(prec=34, rounding=decimal.ROUND_HALF_EVEN, Emin=-999999, Emax=999999)
    high = decimal.Context(prec=90, Emin=-999999, Emax=999999)
    try:
        xs = [decimal.Decimal(a) for a in args]
        if op == "sqrt":
            d = ctx.sqrt(xs[0])
        elif op == "exp":
            d = ctx.exp(xs[0])
        elif op == "ln":
            d = ctx.ln(xs[0])
        else:
            d = ctx.plus(high.exp(high.multiply(xs[1], high.ln(xs[0]))))
        t = format(d, "f")
        t = t.rstrip("0").rstrip(".") if "." in t else t
        return "0" if t in ("-0", "") else t
    except (decimal.InvalidOperation, decimal.DivisionByZero, ValueError):
        return None


def decimal_vectors(add):
    rng = random.Random(20261024)
    for op in DECIMAL_OPS:
        cases = decimal_cases(op, rng, 300)
        extra = {}
        if op in MPDECIMAL_OPS:
            ref = [mpdecimal_reference(op, c) for c in cases]
            ours = [fdecimal.run_case(op, c) for c in cases]
            extra["mpdecimal"] = ref
            extra["hard_cases"] = sum(1 for a, b in zip(ours, ref) if b is not None and not a.startswith("E_") and a != b)
        add(f"decimal/{op.replace('_', '-')}", "decimal", f"{op}: each case's exact 34-digit result or fault code (SPEC 15.9), generated "
            "by the Python reference; other implementations must agree to the last digit."
            + (" mpdecimal holds Python decimal's correctly rounded result for comparison; hard_cases counts the cases "
               "where the normative algorithm differs from it." if extra else ""), None, op=op, cases=cases, **extra)


def add_all(add, text):
    formula_vectors(add)
    eval_vectors(add)
    slice_vectors(add, text)
    function_vectors(add, text)
    envelope_vectors(add, text)
    receipt_vectors(add, text)
    decimal_vectors(add)
    excel_vectors(add)


# ---------------------------------------------------------------------------
# Excel equivalence (kind excel): Microsoft's documented semantics on sample inputs where Excel's
# binary doubles give the exact decimal result (irrational results are compared after ROUND).

DOCS = "https://support.microsoft.com/en-us/excel/functions/"
DOC_PATHS = {"COUNTIF": "https://support.microsoft.com/en-us/excel/get-started/use-the-countif-function-in-microsoft-excel",
             "FIND": "https://support.microsoft.com/en-us/excel/how-to-correct-a-value-error-in-find-findb-and-search-searchb-functions"}  # the FIND article itself redirects to a retired page (checked 2026-10-24)
SHEET = "sheet.example.org"
CASE = "sheet.example.net/case"


def doc_url(fn):
    return DOC_PATHS.get(fn, DOCS + fn.lower().replace(".", "-") + "-function")


def sheet_world():
    one = arg("number", "1")
    fns = {
        f"{SHEET}/a": stored({"row": one}, ["row"], "1"),
        f"{SHEET}/b": stored({"row": one}, ["row"], "1"),
        f"{SHEET}/s": stored({"row": one}, ["row"], "1"),
        f"{SHEET}/sales": stored({"item": STR, "region": STR, "row": one}, ["row", "item", "region"], "1"),
        f"{SHEET}/price": stored({"item": STR}, ["item"], "1"),
        f"{SHEET}/band": stored({"threshold": one}, ["threshold"], "1"),
        f"{SHEET}/holiday": stored({"date": arg("date", valid=True)}, ["date"], "string"),
    }
    r, tx = [], "2026-02-01T00:00:00.000000Z"

    def put(fn, args, value):
        r.append(F.stored_receipt(fns[f"{SHEET}/{fn}"], f"{SHEET}/{fn}", args, value, tx))
    for i, (a, b) in enumerate(zip([10, 20, 30, 40, 50], [1, 2, 3, 4, 5]), 1):
        put("a", {"row": N(str(i))}, N(str(a)))
        put("b", {"row": N(str(i))}, N(str(b)))
    for i, v in enumerate([2, 4, 4, 4, 5, 5, 7, 9], 1):
        put("s", {"row": N(str(i))}, N(str(v)))
    for i, (item, region, v) in enumerate([("bolt", "north", 10), ("nut", "south", 20), ("bolt", "south", 30),
                                           ("washer", "north", 40), ("nut", "north", 50)], 1):
        put("sales", {"item": S(item), "region": S(region), "row": N(str(i))}, N(str(v)))
    for item, p in (("bolt", "2.5"), ("nut", "0.25"), ("washer", "0.1")):
        put("price", {"item": S(item)}, N(p))
    for th, v in (("0", "0.1"), ("10000", "0.2"), ("50000", "0.4")):
        put("band", {"threshold": N(th)}, N(v))
    for dd, nm in (("2026-04-03", "Good Friday"), ("2026-04-06", "Easter Monday")):
        put("holiday", {"date": D(dd)}, S(nm))
    return fns, r


A_ = f"{SHEET}/a(*)"
SALES = "Sales table in A2:C6: item, region, amount = (bolt, north, 10), (nut, south, 20), (bolt, south, 30), " \
        "(washer, north, 40), (nut, north, 50)."
PRICES = "Price table A2:B4: (bolt, 2.5), (nut, 0.25), (washer, 0.1)."
A15 = "A1:A5 = 10, 20, 30, 40, 50; B1:B5 = 1, 2, 3, 4, 5."
S18 = "S1:S8 = 2, 4, 4, 4, 5, 5, 7, 9."
HOL = "Holidays in H1:H2 = 2026-04-03, 2026-04-06."
CAL = f"calendar: {SHEET}/holiday(*)"
EXCEL = [  # (function, status, Excel formula, sample, Excel's documented result, formula, returns)
    ("SUM", "supported", "=SUM(A1:A5)", A15, N("150"), f"sum({A_})", "1"),
    ("AVERAGE", "supported", "=AVERAGE(A1:A5)", A15, N("30"), f"mean({A_})", "1"),
    ("COUNT", "supported", "=COUNT(A1:A5)", A15, N("5"), f"count({A_})", "count"),
    ("COUNTA", "supported", "=COUNTA(A1:A5)", A15, N("5"), f"count({A_})", "count"),
    ("MIN", "supported", "=MIN(A1:A5)", A15, N("10"), f"min({A_})", "1"),
    ("MAX", "supported", "=MAX(A1:A5)", A15, N("50"), f"max({A_})", "1"),
    ("MEDIAN", "supported", "=MEDIAN(A1:A4)", A15, N("25"), f"median({SHEET}/a([1..4]))", "1"),
    ("STDEV.S", "supported", "=ROUND(STDEV.S(S1:S8),10)", S18, N("2.1380899353"), f"round(stdev({SHEET}/s(*)), 10)", "1"),
    ("STDEV.P", "supported", "=STDEV.P(S1:S8)", S18, N("2"), f"stdev_p({SHEET}/s(*))", "1"),
    ("IF", "supported", '=IF(A1>15,"big","small")', A15, S("small"), f'if {SHEET}/a(1) > 15 then "big" else "small"', "string"),
    ("IFS", "partial", '=IFS(A1>15,"big",TRUE,"small")', A15, S("small"),
     f'if {SHEET}/a(1) > 15 then "big" else "small"', "string"),
    ("AND", "supported", "=AND(A1>5,A2>25)", A15, B(False), f"and({SHEET}/a(1) > 5, {SHEET}/a(2) > 25)", "boolean"),
    ("OR", "supported", "=OR(A1>5,A2>25)", A15, B(True), f"{SHEET}/a(1) > 5 or {SHEET}/a(2) > 25", "boolean"),
    ("NOT", "supported", "=NOT(A1>5)", A15, B(False), f"not {SHEET}/a(1) > 5", "boolean"),
    ("ROUND", "supported", "=ROUND(-2.5,0)", "", N("-3"), "round(-2.5)", "1"),
    ("ROUNDUP", "supported", "=ROUNDUP(3.2,0)", "", N("4"), "round_up(3.2)", "1"),
    ("ROUNDDOWN", "supported", "=ROUNDDOWN(-3.7,0)", "", N("-3"), "round_down(-3.7)", "1"),
    ("INT", "supported", "=INT(-3.5)", "", N("-4"), "floor(-3.5)", "1"),
    ("FLOOR.MATH", "supported", "=FLOOR.MATH(-3.5)", "", N("-4"), "floor(-3.5)", "1"),
    ("CEILING.MATH", "supported", "=CEILING.MATH(-3.5)", "", N("-3"), "ceiling(-3.5)", "1"),
    ("MOD", "supported", "=MOD(-3,2)", "", N("1"), "mod(-3, 2)", "1"),
    ("ABS", "supported", "=ABS(-4.2)", "", N("4.2"), "abs(-4.2)", "1"),
    ("POWER", "supported", "=POWER(2,10)", "", N("1024"), "2 ^ 10", "1"),
    ("SQRT", "supported", "=SQRT(16)", "", N("4"), "sqrt(16)", "1"),
    ("EXP", "supported", "=ROUND(EXP(1),10)", "", N("2.7182818285"), "round(exp(1), 10)", "1"),
    ("LN", "supported", "=ROUND(LN(10),10)", "", N("2.302585093"), "round(ln(10), 10)", "1"),
    ("LOG", "partial", "=ROUND(LOG(1000,10),10)", "", N("3"), "round(ln(1000) / ln(10), 10)", "1"),
    ("LOG10", "partial", "=ROUND(LOG10(1000),10)", "", N("3"), "round(ln(1000) / ln(10), 10)", "1"),
    ("SIN", "supported", "=ROUND(SIN(PI()/6),10)", "", N("0.5"), "round(sin(pi() / 6), 10)", "1"),
    ("COS", "supported", "=ROUND(COS(PI()/3),10)", "", N("0.5"), "round(cos(pi() / 3), 10)", "1"),
    ("TAN", "partial", "=ROUND(TAN(PI()/4),10)", "", N("1"), "round(sin(pi() / 4) / cos(pi() / 4), 10)", "1"),
    ("ATAN2", "supported", "=ROUND(ATAN2(1,2),10)", "Excel's argument order is ATAN2(x, y).", N("1.1071487178"),
     "round(atan2(2, 1), 10)", "1"),
    ("ASIN", "partial", "=ROUND(ASIN(0.5),10)", "", N("0.5235987756"), "round(atan2(0.5, sqrt(1 - 0.5 ^ 2)), 10)", "1"),
    ("ACOS", "partial", "=ROUND(ACOS(0.5),10)", "", N("1.0471975512"), "round(atan2(sqrt(1 - 0.5 ^ 2), 0.5), 10)", "1"),
    ("ATAN", "partial", "=ROUND(ATAN(1),10)", "", N("0.7853981634"), "round(atan2(1, 1), 10)", "1"),
    ("PI", "supported", "=ROUND(PI(),14)", "", N("3.14159265358979"), "round(pi(), 14)", "1"),
    ("DEGREES", "partial", "=ROUND(DEGREES(PI()),10)", "", N("180"), 'round(convert(pi(), "deg"), 10)', "deg"),
    ("RADIANS", "partial", "=ROUND(RADIANS(180),10)", "", N("3.1415926536"), 'round(convert(180 deg, "1"), 10)', "1"),
    ("SUMPRODUCT", "supported", "=SUMPRODUCT(A1:A5,B1:B5)", A15, N("550"), f"sum({A_} * {SHEET}/b(*))", "1"),
    ("SUMIF", "partial", '=SUMIF(A2:A6,"bolt",C2:C6)', SALES, N("40"),
     f'sum({SHEET}/sales(row: *, item: "bolt", region: *))', "1"),
    ("SUMIFS", "partial", '=SUMIFS(C2:C6,A2:A6,"nut",B2:B6,"north")', SALES, N("50"),
     f'sum({SHEET}/sales(row: *, item: "nut", region: "north"))', "1"),
    ("AVERAGEIF", "partial", '=AVERAGEIF(A2:A6,"bolt",C2:C6)', SALES, N("20"),
     f'mean({SHEET}/sales(row: *, item: "bolt", region: *))', "1"),
    ("AVERAGEIFS", "partial", '=AVERAGEIFS(C2:C6,A2:A6,"nut",B2:B6,"north")', SALES, N("50"),
     f'mean({SHEET}/sales(row: *, item: "nut", region: "north"))', "1"),
    ("COUNTIF", "partial", '=COUNTIF(C2:C6,">25")', SALES, N("3"), f"count(filter({SHEET}/sales(*, *, *), v -> v > 25))",
     "count"),
    ("COUNTIFS", "partial", '=COUNTIFS(A2:A6,"nut",B2:B6,"north")', SALES, N("1"),
     f'count({SHEET}/sales(row: *, item: "nut", region: "north"))', "count"),
    ("VLOOKUP", "partial", '=VLOOKUP("nut",A2:B4,2,FALSE)', PRICES, N("0.25"), f'at({SHEET}/price(*), "nut")', "1"),
    ("HLOOKUP", "partial", '=HLOOKUP("washer",B1:D2,2,FALSE)', "The price table laid out in rows.", N("0.1"),
     f'at({SHEET}/price(*), "washer")', "1"),
    ("XLOOKUP", "partial", '=XLOOKUP("screw",A2:A4,B2:B4,0)', PRICES, N("0"),
     f'otherwise(at({SHEET}/price(*), "screw"), 0)', "1"),
    ("INDEX", "partial", '=INDEX(B2:B4,MATCH("washer",A2:A4,0))', PRICES, N("0.1"), f'at({SHEET}/price(*), "washer")', "1"),
    ("MATCH", "partial", '=INDEX(B2:B4,MATCH("bolt",A2:A4,0))', PRICES, N("2.5"), f'at({SHEET}/price(*), "bolt")', "1"),
    ("VLOOKUP-approximate", "partial", "=VLOOKUP(35000,A2:B4,2,TRUE)", "Bands A2:B4: (0, 0.1), (10000, 0.2), (50000, 0.4).",
     N("0.2"), f"last_before({SHEET}/band(*), 35000)", "1"),
    ("EDATE", "supported", "=EDATE(DATE(2024,1,31),1)", "", D("2024-02-29"), "add_months(2024-01-31, 1)", "date"),
    ("EOMONTH", "supported", "=EOMONTH(DATE(2024,1,15),1)", "", D("2024-02-29"), "end_of_month(add_months(2024-01-15, 1))",
     "date"),
    ("NETWORKDAYS", "supported", "=NETWORKDAYS(DATE(2026,4,1),DATE(2026,4,10),H1:H2)", HOL, N("6"),
     f"business_days(2026-04-01, 2026-04-10, {CAL})", "d"),
    ("WORKDAY", "supported", "=WORKDAY(DATE(2026,4,1),3,H1:H2)", HOL, D("2026-04-08"), f"add_days(2026-04-01, 3, {CAL})",
     "date"),
    ("YEARFRAC", "partial", "=YEARFRAC(DATE(2024,1,1),DATE(2024,7,1),0)", "Basis 0 (US 30/360).", N("0.5"),
     'year_fraction(2024-01-01, 2024-07-01, "30/360_us")', "1"),
    ("YEARFRAC-basis-2", "partial", "=ROUND(YEARFRAC(DATE(2024,1,1),DATE(2024,7,1),2),10)", "Basis 2 (actual/360).",
     N("0.5055555556"), 'round(year_fraction(2024-01-01, 2024-07-01, "act/360"), 10)', "1"),
    ("YEARFRAC-basis-3", "partial", "=ROUND(YEARFRAC(DATE(2024,1,1),DATE(2024,7,1),3),10)", "Basis 3 (actual/365).",
     N("0.498630137"), 'round(year_fraction(2024-01-01, 2024-07-01, "act/365f"), 10)', "1"),
    ("YEARFRAC-basis-4", "partial", "=YEARFRAC(DATE(2024,1,31),DATE(2024,7,31),4)", "Basis 4 (European 30/360).",
     N("0.5"), 'year_fraction(2024-01-31, 2024-07-31, "30e/360")', "1"),
    ("DATE", "supported", "=DATE(2024,3,15)", "", D("2024-03-15"), "date(2024, 3, 15)", "date"),
    ("YEAR", "supported", "=YEAR(DATE(2024,3,15))", "", N("2024"), "year(2024-03-15)", "1"),
    ("MONTH", "supported", "=MONTH(DATE(2024,3,15))", "", N("3"), "month(2024-03-15)", "1"),
    ("DAY", "supported", "=DAY(DATE(2024,3,15))", "", N("15"), "day(2024-03-15)", "1"),
    ("WEEKDAY", "supported", "=WEEKDAY(DATE(2024,3,15))", "Return type 1: Sunday is 1.", N("6"),
     "mod(weekday(2024-03-15), 7) + 1", "1"),
    ("LEN", "supported", '=LEN("Zürich")', "", N("6"), 'len("Zürich")', "1"),
    ("LEFT", "supported", '=LEFT("Datumesh",5)', "", S("Datum"), 'substr("Datumesh", 1, 5)', "string"),
    ("RIGHT", "supported", '=RIGHT("Datumesh",4)', "", S("mesh"), 'substr("Datumesh", len("Datumesh") - 4 + 1, 4)', "string"),
    ("MID", "supported", '=MID("Datumesh",3,4)', "", S("tume"), 'substr("Datumesh", 3, 4)', "string"),
    ("CONCAT", "supported", '=CONCAT("a","b","c")', "", S("abc"), 'concat("a", "b", "c")', "string"),
    ("CONCATENATE", "supported", '=CONCATENATE("a","b","c")', "", S("abc"), '"a" & "b" & "c"', "string"),
    ("FIND", "supported", '=FIND("m","Datumesh")', "", N("5"), 'find("m", "Datumesh")', "1"),
    ("SEARCH", "partial", '=SEARCH("MESH","Datumesh")', "", N("5"), 'find(lower("MESH"), lower("Datumesh"))', "1"),
    ("UPPER", "supported", '=UPPER("Zürich")', "", S("ZÜRICH"), 'upper("Zürich")', "string"),
    ("LOWER", "supported", '=LOWER("ÄBC")', "", S("äbc"), 'lower("ÄBC")', "string"),
    ("TRIM", "supported", '=TRIM("  a   b  ")', "", S("a b"), 'trim("  a   b  ")', "string"),
    ("FIXED", "supported", "=FIXED(1234.567,1,TRUE)", "", S("1234.6"), "fixed(1234.567, 1)", "string"),
    ("IFERROR", "partial", "=IFERROR(A1/0,0)", A15, N("0"), f"if 0 = 0 then 0 else {SHEET}/a(1) / 0", "1"),
    ("IFNA", "partial", '=IFNA(XLOOKUP("screw",A2:A4,B2:B4),-1)', PRICES, N("-1"),
     f'otherwise(at({SHEET}/price(*), "screw"), -1)', "1"),
]


def excel_id(fn):
    return "excel/" + fn.lower().replace(".", "-")


def excel_vectors(add):
    fns, receipts = sheet_world()
    for fn, status, excel, sample, result, source, returns in EXCEL:
        base_fn = fn.split("-")[0] if fn.startswith(("VLOOKUP-", "YEARFRAC-")) else fn
        descriptor = define(CASE, {}, [], source, returns, fns)
        hashes = {canon.function_hash(fns[n]) for n in descriptor["inputs"]}
        world = spec_of({n: fns[n] for n in descriptor["inputs"]}, [r for r in receipts if r["cell"]["fn_hash"] in hashes])
        vec = {"kind": "excel", "formula": source, "signature": descriptor["signature"], "world": world,
               "cell": {"args": {}, "fn": CASE}, "asof": LATER}
        got = F.run_vector(vec)
        if "error" in got or got["value"] != result:
            raise SystemExit(f"{excel_id(fn)}: Excel gives {result}, the formula gives {got}")
        add(excel_id(fn), "excel", f"{excel} is {status} as {source}. {sample}".strip(), None,
            excel=excel, doc=doc_url(base_fn), documentation_derived=True, status=status, sample=sample,
            excel_result=result, formula=source, signature=descriptor["signature"], world=world,
            cell=vec["cell"], asof=LATER)
