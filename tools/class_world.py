# SPDX-License-Identifier: Apache-2.0
"""The classes of the spec-0.5.0 vectors (SPEC.md section 16), built from the live seed shapes.

- `rates.example.org/fx_pair` (keys base, quote: upper_ascii): `rate` (the stored fx_rate), `spot`
  (a formula reading this.rate), `cross` (a formula over two rates), `forward` (a formula over
  this.spot, this.rate and two deposit rates, its inputs derived by the parser: one-way reads within
  the class, answer 11) and `named`, its `lookup` (label -> key, Q10 a). Since Q6 b every method's
  key arguments carry upper_ascii, the class's rule.
- `scripture.example.org/verse` (keys corpus, book, chapter, verse): `text` (the stored verse_text, a
  blob), `consonantal` (strip_niqqud: remove_chars(text_of(this.text(edition)), ...)) and `next`
  (returns a key of verse).
- `calc.example.net/fx_ndf`, a subclass of fx_pair by another namespace: a key `fixing`, `rate`
  overridden through `super`.
- `iso.example.org/currency` and `rates.example.org/ccy_pair`, whose keys are class-typed.
- `calc.example.net/bond` and `calc.example.net/swap`, both with `price`, dispatched to by
  `calc.example.net/price_of`.

Used by tools/gen_vectors.py and the tests. Standard library and the reference tools only.
"""

import unicodedata

import canon
import formula

BOUND = "2026-01-01T00:00:00.000000Z"
ASOF = "2026-06-01T00:00:00.000000Z"
DAY = "2026-03-16"
STR = {"type": "string", "valid": False}
DATE = {"type": "date", "valid": True}
ONE = {"type": "number", "unit": "1", "valid": False}
RATE_UNIT = {"of": {"arg": "quote"}, "per": {"arg": "base"}}
UPPER = {"key_normalisation": "upper_ascii", "type": "string"}
UKEY = dict(STR, key_normalisation="upper_ascii")  # a method's argument for an upper_ascii key (Q6 b)
NONE = {"key_normalisation": "none", "type": "string"}
H = canon.function_hash
HEBREW_MARKS = unicodedata.normalize("NFC", "".join(chr(c) for c in range(0x0591, 0x05C8)
                                                    if c not in (0x05BE, 0x05C0, 0x05C3, 0x05C6)))

FX = "rates.example.org/fx_pair"
VERSE = "scripture.example.org/verse"
NDF = "calc.example.net/fx_ndf"
CURRENCY = "iso.example.org/currency"
CCY_PAIR = "rates.example.org/ccy_pair"
BOND, SWAP = "calc.example.net/bond", "calc.example.net/swap"


def stored(args, order, returns):
    return {"code": {"body": "", "lang": "stored"}, "inputs": [],
            "signature": {"args": args, "order": order, "returns": returns}}


def steward(ns):
    return {"namespace": ns, "process": f"https://{ns.split('/')[0]}/classes/change"}


RATE = stored({"base": UKEY, "date": DATE, "quote": UKEY}, ["base", "quote", "date"], {"type": "number", "unit": RATE_UNIT})
# fx_pair's lookup (Q10 a): a label to a key of fx_pair, its recorded cells the alias table.
NAMED = stored({"label": STR}, ["label"], {"type": "string", "classes": ["rates.example.org/fx_pair"]})
LOOKUPS = {"rates.example.org/fx_pair": {"cable": 'rates.example.org/fx_pair(base:"GBP",quote:"USD")',
                                         "fiber": 'rates.example.org/fx_pair(base:"EUR",quote:"USD")'}}
DEPOSIT = stored({"currency": STR, "date": DATE, "tenor": STR}, ["currency", "tenor", "date"],
                 {"type": "number", "unit": "1"})
# fx_rate with an asof default on its date (16.7): fx_rate(EUR, GBP) reads the rate as of the evaluation asof.
FX_RATE_D = stored({"base": STR, "date": dict(DATE, default="asof"), "quote": STR}, ["base", "quote", "date"],
                   {"type": "number", "unit": RATE_UNIT})
TEXT = stored({"book": STR, "chapter": ONE, "corpus": STR, "edition": STR, "verse": ONE},
              ["corpus", "book", "chapter", "verse", "edition"], "blob")
VERSE_KEYS = {"book": NONE, "chapter": {"type": "number", "unit": "1"}, "corpus": NONE,
              "verse": {"type": "number", "unit": "1"}}
NEXT = stored({"book": STR, "chapter": ONE, "corpus": STR, "verse": ONE}, ["corpus", "book", "chapter", "verse"],
              {"type": "string", "classes": [VERSE]})
CCY_ARG = {"type": "string", "classes": [CURRENCY], "valid": False}
RATE2 = stored({"base": CCY_ARG, "date": DATE, "quote": CCY_ARG}, ["base", "quote", "date"], {"type": "number", "unit": "1"})
PRICE_ARGS = {"date": DATE, "isin": UKEY}
BOND_PRICE = stored(PRICE_ARGS, ["isin", "date"], {"type": "number", "unit": "1"})
SWAP_PRICE = dict(stored({"date": DATE, "isin": UKEY}, ["isin", "date"], {"type": "number", "unit": "1"}),
                  code={"body": "swap prices\n", "lang": "stored"})  # another hash: a table of its own
INSTRUMENT = {"type": "string", "classes": [BOND, SWAP], "valid": False}
EXTRA_CARRY = stored({"base": STR, "date": DATE, "quote": STR}, ["base", "quote", "date"], {"type": "number", "unit": "1"})


def fx_class(methods):
    d = {"keys": {"base": UPPER, "quote": UPPER}, "methods": methods, "order": ["base", "quote"],
         "steward": steward("rates.example.org")}
    if "named" in methods:
        d["lookup"] = "named"
    return d


def build():
    """Every function, class and binding of the scenario: {"functions": {name: descriptor},
    "classes": {name: flattened class descriptor}}."""
    functions = {f"{FX}/rate": RATE, f"{FX}/named": NAMED, "rates.example.org/deposit": DEPOSIT, "rates.example.org/fx_rate": FX_RATE_D,
                 f"{VERSE}/text": TEXT, f"{VERSE}/next": NEXT, f"{CCY_PAIR}/rate": RATE2, f"{BOND}/price": BOND_PRICE,
                 f"{SWAP}/price": SWAP_PRICE, "calc.example.net/fx_extra/carry": EXTRA_CARRY}
    classes = {}

    def env(method_of=None, sig=None, name=None):
        e = {"functions": dict(functions), "classes": dict(classes), "aliases": {}}
        if method_of:
            e["method_of"] = method_of
        return e

    def define(name, sig, body, method_of=None):
        e = env(method_of)
        d = formula.define(name, sig, body, e)
        functions[name] = d
        return d

    # fx_pair: rate and named first, then spot over this.rate, then cross (rate through objects) and
    # forward (this.spot and this.rate): one-way reads within the class, by name (answer 11).
    classes[FX] = fx_class({"named": H(NAMED), "rate": H(RATE)})
    spot = define(f"{FX}/spot", {"args": {"base": UKEY, "date": DATE, "quote": UKEY}, "order": ["base", "quote", "date"],
                                 "returns": {"type": "number", "unit": RATE_UNIT}}, "this.rate(date)", FX)
    classes[FX] = fx_class({"named": H(NAMED), "rate": H(RATE), "spot": H(spot)})
    cross = define(f"{FX}/cross", {"args": {"base": UKEY, "date": DATE, "quote": UKEY, "via": STR},
                                   "order": ["base", "quote", "via", "date"], "returns": {"type": "number", "unit": RATE_UNIT}},
                   f"{FX}(base, via).rate(date) * {FX}(via, quote).rate(date)", FX)
    forward = define(f"{FX}/forward", {"args": {"base": UKEY, "date": DATE, "quote": UKEY, "tenor": STR},
                                       "order": ["base", "quote", "tenor", "date"],
                                       "returns": {"type": "number", "unit": RATE_UNIT}},
                     "(this.spot(date) + this.rate(date)) / 2 * (1 + rates.example.org/deposit(quote, tenor, date)) / "
                     "(1 + rates.example.org/deposit(base, tenor, date))", FX)
    classes[FX] = canon.define_class(FX, fx_class({"cross": H(cross), "forward": H(forward), "named": H(NAMED),
                                                   "rate": H(RATE), "spot": H(spot)}),
                                     {"functions": list(functions.values()), "definer": "rates.example.org"})
    # verse: text, next, then consonantal over this.text.
    verse_desc = {"keys": VERSE_KEYS, "methods": {"next": H(NEXT), "text": H(TEXT)},
                  "order": ["corpus", "book", "chapter", "verse"], "steward": steward("scripture.example.org")}
    classes[VERSE] = verse_desc
    consonantal = define(f"{VERSE}/consonantal",
                         {"args": {"book": STR, "chapter": ONE, "corpus": STR, "edition": STR, "verse": ONE},
                          "order": ["corpus", "book", "chapter", "verse", "edition"], "returns": "string"},
                         f'remove_chars(text_of(this.text(edition)), "{HEBREW_MARKS}")', VERSE)
    classes[VERSE] = canon.define_class(VERSE, dict(verse_desc, methods=dict(verse_desc["methods"],
                                                                              consonantal=H(consonantal))),
                                        {"functions": list(functions.values()), "definer": "scripture.example.org"})
    # currency and ccy_pair: class-typed keys.
    classes[CURRENCY] = canon.define_class(CURRENCY, {"keys": {"code": UPPER}, "methods": {}, "order": ["code"],
                                                      "steward": steward("iso.example.org")}, {"functions": []})
    classes[CCY_PAIR] = canon.define_class(CCY_PAIR, {"keys": {"base": {"class": CURRENCY}, "quote": {"class": CURRENCY}},
                                                      "methods": {"rate": H(RATE2)}, "order": ["base", "quote"],
                                                      "steward": steward("rates.example.org")},
                                           {"functions": list(functions.values())})
    # bond and swap, dispatched to by price_of.
    for cls, fn in ((BOND, BOND_PRICE), (SWAP, SWAP_PRICE)):
        classes[cls] = canon.define_class(cls, {"keys": {"isin": UPPER}, "methods": {"price": H(fn)}, "order": ["isin"],
                                                "steward": steward("calc.example.net")},
                                          {"functions": list(functions.values())})
    define("calc.example.net/price_of", {"args": {"date": DATE, "instrument": INSTRUMENT},
                                         "order": ["instrument", "date"], "returns": {"type": "number", "unit": "1"}},
           "instrument.price(date)")
    # fx_ndf: a subclass by calc.example.net overriding rate through super.
    parent = canon.class_hash(classes[FX])
    ndf_own = {"keys": {"fixing": NONE}, "methods": {}, "order": ["fixing"], "parent": parent,
               "steward": steward("calc.example.net")}
    classes[NDF] = canon.define_class(NDF, ndf_own, {"classes": [classes[FX]], "functions": list(functions.values())})
    ndf_rate = define(f"{NDF}/rate", RATE["signature"], "super.rate(date) * 1", NDF)
    classes[NDF] = canon.define_class(NDF, dict(ndf_own, methods={"rate": H(ndf_rate)}),
                                      {"classes": [classes[FX]], "functions": list(functions.values()),
                                       "definer": "calc.example.net"})
    # Binding a class binds N/m for every method of its flattened descriptor (16.3).
    for cname, desc in classes.items():
        for m, h in desc["methods"].items():
            found = [d for d in functions.values() if H(d) == h]
            functions.setdefault(f"{cname}/{m}", found[0])
    return {"functions": functions, "classes": classes}


SCENARIO = build()


def env(name, sig, method_of=None, aliases=None):
    """A formula environment over the scenario."""
    e = {"aliases": aliases or {}, "classes": dict(SCENARIO["classes"]), "functions": dict(SCENARIO["functions"]),
         "name": name, "signature": sig}
    if method_of:
        e["method_of"] = method_of
    return e


def call_env(aliases=None, aliases_tx=None, now=None, lookups=None):
    e = {"aliases": aliases or {}, "classes": dict(SCENARIO["classes"]), "functions": dict(SCENARIO["functions"])}
    if lookups:
        e["lookups"] = lookups
    if aliases_tx:
        e["aliases_tx"] = aliases_tx
    if now:
        e["now"] = now
    return e


def world_spec(receipts, extra_functions=None, classes=True):
    functions = dict(SCENARIO["functions"], **(extra_functions or {}))
    spec = {"functions": {n: {"bound": BOUND, "descriptor": d} for n, d in sorted(functions.items())},
            "receipts": list(receipts)}
    if classes:
        spec["classes"] = {n: {"bound": BOUND, "descriptor": d} for n, d in sorted(SCENARIO["classes"].items())}
    return spec


def S(v):
    return {"type": "string", "value": v}


def N(v):
    return {"type": "number", "value": v}


def D(v):
    return {"type": "date", "value": v}


def rate_receipt(base, quote, value, day=DAY, fq=f"{FX}/rate", descriptor=RATE):
    return formula.stored_receipt(descriptor, fq, {"base": S(base), "date": D(day), "quote": S(quote)}, N(value),
                                  "2026-03-16T16:00:00.000000Z")


def deposit_receipt(ccy, tenor, value, day=DAY):
    return formula.stored_receipt(DEPOSIT, "rates.example.org/deposit",
                                  {"currency": S(ccy), "date": D(day), "tenor": S(tenor)}, N(value),
                                  "2026-03-16T16:00:00.000000Z")


def price_receipt(cls, isin, value, day=DAY):
    fn = BOND_PRICE if cls == BOND else SWAP_PRICE
    return formula.stored_receipt(fn, f"{cls}/price", {"date": D(day), "isin": S(isin)}, N(value),
                                  "2026-03-16T16:00:00.000000Z")


# The method-call equivalence pairs (the brief's test 2): (name, call form, plain read, returns, aliases).
RATE_RET = {"type": "number", "unit": {"of": "USD", "per": "EUR"}}
EQUIVALENT = [
    ("fx-rate", f'{FX}(EUR, USD).rate(2026-03-16)', f'{FX}/rate(base: "EUR", quote: "USD", date: 2026-03-16)',
     RATE_RET, {}),
    ("fx-forward", f'{FX}("EUR", "USD").forward(1M, 2026-03-16)',
     f'{FX}/forward(base: "EUR", quote: "USD", tenor: "1M", date: 2026-03-16)', RATE_RET, {}),
    ("fx-cross", f'{FX}(EUR, USD).cross(via: GBP, date: 2026-03-16)',
     f'{FX}/cross(base: "EUR", quote: "USD", via: "GBP", date: 2026-03-16)', RATE_RET, {}),
    ("verse-text", f'{VERSE}("tanakh", "Gen", 1, 1).text("uxlc")',
     f'{VERSE}/text(corpus: "tanakh", book: "Gen", chapter: 1, verse: 1, edition: "uxlc")', "blob", {}),
    ("verse-quran", f'{VERSE}("quran", "2", 1, 255).text("uthmani")',
     f'{VERSE}/text(corpus: "quran", book: "2", chapter: 1, verse: 255, edition: "uthmani")', "blob", {}),
    ("verse-consonantal", f'{VERSE}("tanakh", "Gen", 1, 1).consonantal(edition: "uxlc")',
     f'{VERSE}/consonantal(corpus: "tanakh", book: "Gen", chapter: 1, verse: 1, edition: "uxlc")', "string", {}),
    ("class-typed-keys", f'{CCY_PAIR}({CURRENCY}(EUR), {CURRENCY}(USD)).rate(2026-03-16)',
     f'{CCY_PAIR}/rate(base: "{CURRENCY}(code:""EUR"")", quote: "{CURRENCY}(code:""USD"")", date: 2026-03-16)',
     {"type": "number", "unit": "1"}, {}),
    # ("inherited", ...) is not here since the classes round (K5): an inherited method reads the cell of the class that
    # defines it, so the call form and the plain read under the subclass's name are no longer the same read (see
    # tools/gen_vectors_classes_round.py: formula/class-inherited and formula/class-inherited-plain).
    ("extension", f'{FX}(EUR, USD).calc.example.net/fx_extra/carry(2026-03-16)',
     'calc.example.net/fx_extra/carry(base: "EUR", quote: "USD", date: 2026-03-16)', {"type": "number", "unit": "1"}, {}),
    ("default-asof", 'rates.example.org/fx_rate(EUR, GBP)',
     'rates.example.org/fx_rate(base: "EUR", quote: "GBP", date: date_of(asof()))',
     {"type": "number", "unit": {"of": "GBP", "per": "EUR"}}, {}),
    ("alias", '@fx(EUR, USD).rate(2026-03-16)', f'{FX}/rate(base: "EUR", quote: "USD", date: 2026-03-16)',
     RATE_RET, {"fx": FX}),
]

