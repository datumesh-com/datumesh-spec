#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Classes-round vectors (SPEC.md section 11 vector format), written tests-first.

CONTRACT-classes-round.md, the spec side of K5, K8, K9, K10, K11, K13, C2 and C7. Like
tools/gen_vectors_0_6_2.py this builds the vectors from the fixtures of tools/gen_vectors.py and
tools/class_world.py (imported, never run) and states every expected result by hand from the contract:
the reference tools cannot produce them yet (the vectors are the tests the new tools are written against).
Where an expected output of a `formula` or `call` vector coincides with what the 0.6.2 tools give for an
equivalent input (the same read under the name the new rule gives it), it is taken from there and only the
name is substituted (`patched`, `via`): nothing else is computed by the 0.6.2 tools.

Files written under vectors/: new ones, and two rewritten ones, formula/class-inherited and
formula/class-inherited-plain (K5, BREAKING). Every other existing vector stays byte for byte as it is.

    python3 tools/gen_vectors_classes_round.py        # write the vectors
    python3 -c "import gen_vectors_classes_round"      # (from tools/) build them in memory: VECTORS

Choices the contract leaves open are listed in tests/test_classes_round.py (the module docstring).
"""

import copy
import json
import pathlib
import sys
import unicodedata

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))
import canon  # noqa: E402
import class_world as CW  # noqa: E402
import formula as F  # noqa: E402
import gen_vectors as gv  # noqa: E402  (the fixtures and keys; its main() is not run)

OUT = ROOT / "vectors"
VECTORS = []
PREFIX = "classes-round: "

text = gv.text
sha = canon.sha256_hex
S, N, D = gv.S, gv.N, gv.D
H = canon.function_hash


def add(id_, kind, description, input=None, error=None, **extra):
    vec = {"id": id_, "kind": kind, "description": PREFIX + description, "valid": error is None}
    if input is not None:
        vec["input"] = input
    vec.update(extra)
    if error is not None:
        vec["error"] = error
    VECTORS.append(vec)


def jcs_text(obj):
    return canon.jcs(obj).decode()


def patched(source, env, subs):
    """The compile of `source` under the 0.6.2 tools with names substituted: {ast, ast_sha256, body, inputs, returns,
    asof_dependent}. `subs` maps the old fully qualified name of a read to the one the new rule gives."""
    c = F.compile(source, env)
    ast, body, inputs = jcs_text(c.ast), c.body, list(c.inputs)
    for old, new in subs:
        ast, body = ast.replace(old, new), body.replace(old, new)
        inputs = [new if i == old else i for i in inputs]
    return {"ast": ast, "ast_sha256": sha(ast.encode()), "body": body, "inputs": sorted(set(inputs)),
            "returns": c.returns(), "asof_dependent": c.asof_dependent}


def via(source, env, old_source=None, subs=()):
    return patched(old_source or source, env, subs)


# ---------------------------------------------------------------------------
# K5: an inherited method reads the cells of the class that defines it (16.2, 16.3, 16.6).

FX, NDF, BOND = CW.FX, CW.NDF, CW.BOND
FXC = "calc.example.net/fx_cash"          # fx_pair's subclass: key venue; no methods of its own
GRT = "calc.example.net/fx_ndf_term"      # fx_ndf's subclass: key tenor; no methods of its own
GREEN = "calc.example.net/green_bond"     # bond's subclass: key grade; no methods of its own
FUNCS = list(CW.SCENARIO["functions"].values())


def subclass(name, parent_name, key, classes):
    own = {"keys": {key: CW.NONE}, "methods": {}, "order": [key], "parent": canon.class_hash(classes[parent_name]),
           "steward": CW.steward("calc.example.net")}
    classes[name] = canon.define_class(name, own, {"classes": [classes[parent_name]], "functions": FUNCS,
                                                   "definer": "calc.example.net"})


K5_CLASSES = dict(CW.SCENARIO["classes"])
subclass(FXC, FX, "venue", K5_CLASSES)
subclass(GRT, NDF, "tenor", K5_CLASSES)
subclass(GREEN, BOND, "grade", K5_CLASSES)

# 16.3 as of this round: binding S binds S/m for the methods S adds or overrides, never an inherited one.
OWN = {FX: set(K5_CLASSES[FX]["methods"]), NDF: {"rate"}, FXC: set(), GRT: set(), GREEN: set()}
INHERITED = [f"{NDF}/{m}" for m in ("cross", "forward", "named", "spot")]
K5_FUNCTIONS = {n: d for n, d in CW.SCENARIO["functions"].items() if n not in INHERITED}
# The names the 0.6.2 rule would bind besides (an older library's binding): they change nothing under the new rule.
LEGACY_FUNCTIONS = dict(CW.SCENARIO["functions"], **{
    f"{c}/{m}": CW.SCENARIO["functions"][f"{FX}/{m}"] for c, m in [(FXC, "rate"), (FXC, "cross"), (GRT, "cross")]},
    **{f"{GRT}/rate": CW.SCENARIO["functions"][f"{NDF}/rate"], f"{GREEN}/price": CW.SCENARIO["functions"][f"{BOND}/price"]})

CW_E = "calc.example.net/e"


def k5_env(sig, method_of=None, functions=None, classes=None):
    e = {"aliases": {}, "classes": dict(classes or K5_CLASSES), "functions": dict(functions or K5_FUNCTIONS),
         "name": CW_E, "signature": sig}
    if method_of:
        e["method_of"] = method_of
    return e


def k5_call_env(functions=None, classes=None):
    return {"aliases": {}, "classes": dict(classes or K5_CLASSES), "functions": dict(functions or K5_FUNCTIONS)}


def sig0(returns):
    return {"args": {}, "order": [], "returns": returns}


RATE_RET = CW.RATE_RET
NUM1 = {"type": "number", "unit": "1"}
RATE_SIG_RET = CW.RATE["signature"]["returns"]   # the unit of a method body over the class's own keys (args by name)
OLD_ENV_SIG = sig0(RATE_RET)


def formula_vector(vid, kind_desc, source, env, expect):
    add(vid, "formula", kind_desc, source, env=env, **expect)


def formula_invalid(vid, kind_desc, source, env, code):
    add(vid, "formula", kind_desc, source, code, env=env)


def old_env(sig, method_of=None):
    """An environment the 0.6.2 tools evaluate: every name the old rule binds."""
    return k5_env(sig, method_of, LEGACY_FUNCTIONS)


# --- bodies (the request lexer's twin: the dialect's call form, 15.5)
call_ndf_cross = f'{NDF}(EUR, USD, "F1").cross("GBP", 2026-03-16)'
exp_cross = via(call_ndf_cross, old_env(OLD_ENV_SIG), subs=[(f"{NDF}/cross", f"{FX}/cross")])
formula_vector("formula/class-inherited", f"spec-0.5.0, rewritten for the classes round (K5): {call_ndf_cross}  (a method call "
               f"of an inherited computed method: it reads {FX}/cross, the cell of the class that defines cross; "
               "under spec-0.6.2 it read calc.example.net/fx_ndf/cross)", call_ndf_cross, k5_env(OLD_ENV_SIG), exp_cross)
plain_ndf_cross = f'{NDF}/cross(base: "EUR", quote: "USD", via: "GBP", date: 2026-03-16)'
formula_invalid("formula/class-inherited-plain", f"spec-0.5.0, rewritten for the classes round (K5): {plain_ndf_cross}  "
                "(the plain read of an inherited method under the subclass's name: binding fx_ndf binds fx_ndf/rate "
                "only, the method it overrides, so fx_ndf/cross is not bound; under spec-0.6.2 this was the valid "
                "plain read of formula/class-inherited)", plain_ndf_cross, k5_env(OLD_ENV_SIG), "E_FORMULA_UNRESOLVED")
# The rewritten pair no longer fits a valid/valid equivalence: the pair is call form and plain read of D/m.
plain_fx_cross = f'{FX}/cross(base: "EUR", quote: "USD", via: "GBP", date: 2026-03-16)'
formula_vector("formula/class-inherited-defining-plain", f"K5: {plain_fx_cross}  (the plain read of formula/class-inherited: "
               "the same AST, body and inputs)", plain_fx_cross, k5_env(OLD_ENV_SIG), exp_cross)

call_fxc_rate = f'{FXC}(EUR, USD, "XLON").rate(2026-03-16)'
formula_vector("formula/class-inherited-stored", f"K5: {call_fxc_rate}  (an inherited stored method: it reads {FX}/rate)",
               call_fxc_rate, k5_env(OLD_ENV_SIG),
               via(call_fxc_rate, old_env(OLD_ENV_SIG), subs=[(f"{FXC}/rate", f"{FX}/rate")]))
call_grt_rate = f'{GRT}(EUR, USD, "F1", "1M").rate(2026-03-16)'
formula_vector("formula/class-inherited-middle", f"K5: {call_grt_rate}  (rate is defined by fx_ndf, the nearest ancestor "
               f"that wrote it: the read is {NDF}/rate, not {FX}/rate and not {GRT}/rate)", call_grt_rate,
               k5_env(OLD_ENV_SIG), via(call_grt_rate, old_env(OLD_ENV_SIG), subs=[(f"{GRT}/rate", f"{NDF}/rate")]))
call_grt_cross = f'{GRT}(EUR, USD, "F1", "1M").cross("GBP", 2026-03-16)'
formula_vector("formula/class-inherited-two-levels", f"K5: {call_grt_cross}  (cross is inherited through two classes: it "
               f"reads {FX}/cross, the class that defines it)", call_grt_cross, k5_env(OLD_ENV_SIG),
               via(call_grt_cross, old_env(OLD_ENV_SIG), subs=[(f"{GRT}/cross", f"{FX}/cross")]))
call_ndf_rate = f'{NDF}(EUR, USD, "F1").rate(2026-03-16)'
formula_vector("formula/class-override", f"K5: {call_ndf_rate}  (an override is the subclass's own: it stays {NDF}/rate)",
               call_ndf_rate, k5_env(OLD_ENV_SIG), via(call_ndf_rate, old_env(OLD_ENV_SIG)))
plain_fxc_rate = f'{FXC}/rate(base: "EUR", quote: "USD", venue: "XLON", date: 2026-03-16)'
formula_invalid("invalid/formula-inherited-plain-stored", f"K5: {plain_fxc_rate}  (the plain read of an inherited "
                "stored method under the subclass's name: fx_cash/rate is not bound)", plain_fxc_rate,
                k5_env(OLD_ENV_SIG), "E_FORMULA_UNRESOLVED")
# D unbound: no name is bound to the hash of fx_pair, the class that defines cross.
NO_FX = {n: d for n, d in K5_CLASSES.items() if n != FX}
formula_invalid("invalid/formula-inherited-unbound-definer", f"K5: {call_ndf_cross}  (no class name is bound to the "
                "hash of fx_pair, the class that defines cross: the parent hashes name no D; even a function name "
                "calc.example.net/fx_ndf/cross bound by an older library does not help)", call_ndf_cross,
                k5_env(OLD_ENV_SIG, functions=LEGACY_FUNCTIONS, classes=NO_FX), "E_FORMULA_UNRESOLVED")

# --- `this` in a method body of the subclass
THIS_SIG = {"args": {"base": CW.UKEY, "date": CW.DATE, "fixing": CW.STR, "quote": CW.UKEY, "via": CW.STR},
            "order": ["base", "quote", "fixing", "via", "date"], "returns": RATE_SIG_RET}
this_cross = "this.cross(via, date)"
formula_vector("formula/class-inherited-this", f"K5: {this_cross} in a method of fx_ndf  (this reads an inherited method "
               f"as {FX}/cross, with the keys of fx_pair)", this_cross, k5_env(THIS_SIG, NDF),
               via(this_cross, old_env(THIS_SIG, NDF), subs=[(f"{NDF}/cross", f"{FX}/cross")]))
this_rate = "this.rate(date)"
formula_vector("formula/class-override-this", f"K5: {this_rate} in a method of fx_ndf  (an overridden method read through "
               f"this is the class's own: {NDF}/rate)", this_rate,
               k5_env({"args": {"base": CW.UKEY, "date": CW.DATE, "fixing": CW.STR, "quote": CW.UKEY},
                       "order": ["base", "quote", "fixing", "date"], "returns": RATE_SIG_RET}, NDF),
               via(this_rate, old_env({"args": {"base": CW.UKEY, "date": CW.DATE, "fixing": CW.STR, "quote": CW.UKEY},
                                       "order": ["base", "quote", "fixing", "date"], "returns": RATE_SIG_RET}, NDF)))
THIS_FXC_SIG = {"args": {"base": CW.UKEY, "date": CW.DATE, "quote": CW.UKEY, "venue": CW.STR},
                "order": ["base", "quote", "venue", "date"], "returns": RATE_SIG_RET}
formula_vector("formula/class-inherited-this-stored", f"K5: {this_rate} in a method of fx_cash  (an inherited stored method "
               f"read through this: {FX}/rate)", this_rate, k5_env(THIS_FXC_SIG, FXC),
               via(this_rate, old_env(THIS_FXC_SIG, FXC), subs=[(f"{FXC}/rate", f"{FX}/rate")]))

# --- dispatch over a class and its subclass
DISPATCH_SIG = {"args": {"date": CW.DATE, "i": {"type": "string", "classes": [BOND, GREEN], "valid": False}},
                "order": ["i", "date"], "returns": NUM1}
dispatch_src = "i.price(date)"
formula_vector("formula/class-inherited-dispatch", f"K5: {dispatch_src} with i of bond or green_bond  (price is green_bond's "
               f"by inheritance: both classes read {BOND}/price, so it is the one input)", dispatch_src,
               k5_env(DISPATCH_SIG), via(dispatch_src, old_env(DISPATCH_SIG), subs=[(f"{GREEN}/price", f"{BOND}/price")]))

# --- requests (5.8): resolved says method -> D/m
FXC_CALL_ENV = k5_call_env()


def request_vector(vid, why, call_text, expected_text, from_to, env):
    """A call whose resolved method is D/m. `expected_text` is the call of the class whose method it is, under the
    0.6.2 tools; only the method resolution differs (from: the class as written, to: D/m)."""
    got = canon.parse_call(expected_text, K5_CALL_ENV_OLD)
    resolved = copy.deepcopy(got["resolved"])
    resolved["resolutions"] = [{"from": from_to[0], "kind": "method", "to": from_to[1]}]
    add(vid, "call", why, call_text, env=env, resolved=resolved, uri=got["uri"])


K5_CALL_ENV_OLD = dict(k5_call_env(), functions=LEGACY_FUNCTIONS)
request_vector("call/class-inherited", f"K5: a method the subclass inherits: {NDF}(...).cross is the cell of {FX}/cross, "
               "and resolved says so",
               f'{NDF}(EUR, USD, "F1").cross("GBP", 2026-03-16)', f'{FX}(EUR, USD).cross("GBP", 2026-03-16)',
               (f"{NDF}(...).cross", f"{FX}/cross"), k5_call_env())
request_vector("call/class-inherited-stored", f"K5: a stored method the subclass inherits: {FXC}(...).rate is the cell of "
               f"{FX}/rate", f'{FXC}(EUR, USD, "XLON").rate(2026-03-16)', f'{FX}(EUR, USD).rate(2026-03-16)',
               (f"{FXC}(...).rate", f"{FX}/rate"), k5_call_env())
request_vector("call/class-inherited-two-levels", f"K5: two classes down: {GRT}(...).cross is the cell of {FX}/cross",
               f'{GRT}(EUR, USD, "F1", "1M").cross("GBP", 2026-03-16)', f'{FX}(EUR, USD).cross("GBP", 2026-03-16)',
               (f"{GRT}(...).cross", f"{FX}/cross"), k5_call_env())
request_vector("call/class-inherited-middle", f"K5: {GRT}(...).rate is the cell of {NDF}/rate, the nearest ancestor "
               "that wrote rate", f'{GRT}(EUR, USD, "F1", "1M").rate(2026-03-16)',
               f'{NDF}(EUR, USD, "F1").rate(2026-03-16)', (f"{GRT}(...).rate", f"{NDF}/rate"), k5_call_env())
request_vector("call/class-override", f"K5: an override is the subclass's own: {NDF}(...).rate is the cell of {NDF}/rate",
               f'{NDF}(EUR, USD, "F1").rate(2026-03-16)', f'{NDF}(EUR, USD, "F1").rate(2026-03-16)',
               (f"{NDF}(...).rate", f"{NDF}/rate"), k5_call_env())
add("invalid/call-class-inherited-plain", "call", f"K5: the plain call {NDF}/cross(...) of an inherited method: the name "
    "is not bound (binding a class binds its own methods only)",
    f'{NDF}/cross("EUR", "USD", "F1", "GBP", 2026-03-16)', "E_NAME_UNBOUND", env=k5_call_env())
add("invalid/call-class-inherited-unbound-definer", "call", f"K5: no class name is bound to the hash of fx_pair, the class "
    "that defines cross: the request is E_NAME_UNBOUND, even with calc.example.net/fx_ndf/cross bound by an older "
    "library", f'{NDF}(EUR, USD, "F1").cross("GBP", 2026-03-16)', "E_NAME_UNBOUND",
    env=k5_call_env(LEGACY_FUNCTIONS, NO_FX))


# ---------------------------------------------------------------------------
# The shop world: a class with a label_fold lookup (K8) and a method returning a key (K10).

PRODUCT = "shop.example.org/product"
ASOF = "2026-06-01T00:00:00.000000Z"
DAY = "2026-03-16"
UP = {"type": "string", "valid": False, "key_normalisation": "upper_ascii"}
LABEL = {"type": "string", "valid": False, "key_normalisation": "label_fold"}
LOOKUP_FN = CW.stored({"label": LABEL}, ["label"], {"type": "string", "classes": [PRODUCT]})
PRICE_FN = CW.stored({"date": CW.DATE, "sku": UP}, ["sku", "date"], {"type": "number", "unit": "1"})
SUCCESSOR_FN = CW.stored({"sku": UP}, ["sku"], {"type": "string", "classes": [PRODUCT]})
SHOP_FUNCS = [LOOKUP_FN, PRICE_FN, SUCCESSOR_FN]
PRODUCT_OWN = {"keys": {"sku": CW.UPPER}, "lookup": "from_label",
               "methods": {"from_label": H(LOOKUP_FN), "price": H(PRICE_FN), "successor": H(SUCCESSOR_FN)},
               "order": ["sku"], "steward": CW.steward("shop.example.org")}
PRODUCT_CLASS = canon.define_class(PRODUCT, PRODUCT_OWN, {"functions": SHOP_FUNCS, "definer": "shop.example.org"})


def pkey(sku):
    return f'{PRODUCT}(sku:"{sku}")'


SHOP_FUNCTIONS = {f"{PRODUCT}/from_label": LOOKUP_FN, f"{PRODUCT}/price": PRICE_FN, f"{PRODUCT}/successor": SUCCESSOR_FN}
# The cells of the lookup as of the asof: labels are stored folded (K8); banana was withdrawn ("").
SHOP_LOOKUPS = {PRODUCT: {"apple": pkey("A1"), "green apple": pkey("A2"), "zürich": pkey("A3"), "banana": ""}}
# The cells of successor (K10): the key the cell holds, by the canonical call of the cell.
SHOP_CELLS = {f'{PRODUCT}/successor(sku: "A1")': pkey("A2"), f'{PRODUCT}/successor(sku: "A2")': pkey("A3")}


def shop_env(**more):
    e = {"aliases": {}, "classes": {PRODUCT: PRODUCT_CLASS}, "functions": dict(SHOP_FUNCTIONS), "lookups": SHOP_LOOKUPS,
         "cells": SHOP_CELLS}
    e.update(more)
    return e


def shop_expected(analog, lookup_label=None, lookup_key=None, chain=()):
    """uri and resolved of a shop call, from the 0.6.2 tools' answer to the analogue `analog` (an object call with
    the same method and arguments); the lookup and chain resolutions are stated by hand (each: from, to)."""
    got = canon.parse_call(analog, shop_env())
    res = copy.deepcopy(got["resolved"])
    entries = []
    if lookup_label is not None:
        entries.append({"asof": ASOF, "from": lookup_label, "kind": "lookup", "to": lookup_key})
    for frm, to in chain:
        entries.append({"asof": ASOF, "from": frm, "kind": "chain", "to": to})
    res["resolutions"] = entries + res["resolutions"]
    return got["uri"], res


# ---------------------------------------------------------------------------
# K8: labels (16.1, 16.4, 16.7, 16.8). label_fold: Unicode default case folding, then NFC, each run of White_Space one
# U+0020, leading and trailing spaces removed; a value is canonical when it equals its own folding.

for slug, value, error, why in [
    ("lower", "apple", None, "a lower-case word equals its folding"),
    ("inner-space", "green apple", None, "single inner spaces are kept"),
    ("digits", "route 66", None, "digits are not changed"),
    ("non-ascii", "zürich", None, "folded and NFC: a lower-case non-ASCII label equals its folding"),
    ("case-folded-sharp-s", "strasse", None, "the full case folding of ß is ss: this is the folded form"),
    ("upper-first", "Apple", "E_KEY_NORMALISATION", "an upper-case letter: its folding is lower case"),
    ("upper", "APPLE", "E_KEY_NORMALISATION", "all upper case"),
    ("mixed-non-ascii", "Zürich", "E_KEY_NORMALISATION", "a non-ASCII word with an upper-case initial"),
    ("sharp-s", "straße", "E_KEY_NORMALISATION", "default case folding turns ß into ss, so the value is not its folding"),
    ("double-space", "green  apple", "E_KEY_NORMALISATION", "an inner run of two spaces is one space when folded"),
    ("leading-space", " apple", "E_KEY_NORMALISATION", "a leading space is removed when folded"),
    ("trailing-space", "apple ", "E_KEY_NORMALISATION", "a trailing space is removed when folded"),
    ("only-spaces", "   ", "E_KEY_NORMALISATION", "spaces only fold to the empty string"),
    ("nbsp", "green apple", "E_KEY_NORMALISATION", "U+00A0 is White_Space: a run of White_Space becomes one U+0020"),
    ("ideographic-space", "green　apple", "E_KEY_NORMALISATION", "U+3000 is White_Space: it becomes U+0020"),
    ("tab", "green\tapple", "E_CANON_STRING", "a tab is a control character, refused by 3.5 under every rule"),
    ("nfd", unicodedata.normalize("NFD", "zürich"), "E_CANON_STRING", "a string that is not NFC is refused by 3.5, as under none"),
]:
    vid = f"normalisation/label-fold-{slug}" if error is None else f"invalid/normalisation-label-fold-{slug}"
    add(vid, "normalisation", f"label_fold: {why} (16.4, K8).", error=error, rule="label_fold", text=value)

add("function/lookup-label-fold", "function", "A lookup method's label argument carries key_normalisation label_fold (7, 16.1, "
    "16.4): a rule of 16.4 like the others, for the label of a lookup.", text(LOOKUP_FN), canonical=jcs_text(LOOKUP_FN),
    sha256=sha(canon.jcs(LOOKUP_FN)))
add("class/lookup-label-fold", "class", "A class whose lookup method takes a label_fold label (16.1): the lookup rule of "
    "spec-0.5.0 holds, the label argument may carry key_normalisation.", text(PRODUCT_OWN), name=PRODUCT,
    env={"classes": [], "definer": "shop.example.org", "functions": SHOP_FUNCS},
    flattened=jcs_text(PRODUCT_CLASS), class_hash=canon.class_hash(PRODUCT_CLASS))

for slug, label, folded, why in [
    ("canonical", "[apple]", "apple", "a label already folded: the lookup is read at it"),
    ("upper", "[APPLE]", "apple", "an upper-case label: the mesh folds it before the lookup is read"),
    ("capital", "[Apple]", "apple", "an initial capital: folded"),
    ("spaces", "[  Apple   ]", "apple", "leading and trailing spaces inside the brackets: folded away"),
    ("quoted-inner", '["  Green   APPLE "]', "green apple", "a quoted label: case and each inner run of spaces folded, "
                                                              "leading and trailing spaces removed"),
    ("non-ascii", '["ZÜRICH"]', "zürich", "Unicode case folding, then NFC"),
]:
    written = {"[apple]": "apple", "[APPLE]": "APPLE", "[Apple]": "Apple", "[  Apple   ]": "Apple"}.get(label)
    if written is None:
        written = label[2:-2]
    key = SHOP_LOOKUPS[PRODUCT][folded]
    sku = key[len(PRODUCT) + 6:-2]
    call_text = f"{PRODUCT}{label}.price({DAY})?asof={ASOF}"
    uri, resolved = shop_expected(f"{PRODUCT}({sku}).price({DAY})?asof={ASOF}", written, key)
    add(f"call/class-label-fold-{slug}", "call", f"K8: {why}; resolved records the label as written, the key and the instant "
        "of the lookup read.", call_text, env=shop_env(), resolved=resolved, uri=uri)

add("invalid/call-class-lookup-withdrawn", "call", "K8: banana's lookup cell is the empty string at the asof: the label was "
    "withdrawn, and a withdrawn label is E_NAME_UNBOUND as an unknown one is.",
    f"{PRODUCT}[banana].price({DAY})?asof={ASOF}", "E_NAME_UNBOUND", env=shop_env())
add("invalid/call-class-lookup-withdrawn-cased", "call", "K8: the label is folded before the lookup is read, so a cased "
    "spelling of a withdrawn label is withdrawn too.", f"{PRODUCT}[BANANA].price({DAY})?asof={ASOF}", "E_NAME_UNBOUND",
    env=shop_env())
add("invalid/call-class-lookup-folded-unknown", "call", "K8: a label that is no label of the lookup even folded: "
    "E_NAME_UNBOUND.", f"{PRODUCT}[PEAR].price({DAY})?asof={ASOF}", "E_NAME_UNBOUND", env=shop_env())
add("invalid/call-class-label-fold-keys-strict", "call", "K8: keys stay strict: a key with a lower-case letter is "
    "E_KEY_NORMALISATION, never folded (label_fold repairs a label, nothing else).",
    f"{PRODUCT}(a1).price({DAY})", "E_KEY_NORMALISATION", env=shop_env())
add("invalid/call-class-label-fold-keys-strict-quoted", "call", "K8: a quoted key is as strict as an unquoted one.",
    f'{PRODUCT}("a1").price({DAY})', "E_KEY_NORMALISATION", env=shop_env())

# describe/{id} accepts N[label] (16.8): the object answer, with resolved when the object was named by a label.
OBJ_A1 = canon.describe_object(PRODUCT, PRODUCT_CLASS, {"sku": S("A1")})
LOOKUP_ENTRY = {"asof": ASOF, "from": "Apple", "kind": "lookup", "to": pkey("A1")}
RESOLVED_A1 = {"call": OBJ_A1["call"], "resolutions": [LOOKUP_ENTRY]}
SHOP_HELD = {PRODUCT: PRODUCT_CLASS}
for vid, doc, error, why in [
    ("describe/object-label", dict(OBJ_A1, resolved=RESOLVED_A1), None,
     "describe of N[label] (here shop.example.org/product[Apple], folded to apple): the answer is the object's own, "
     "with resolved saying the lookup was made (16.8, 16.7)."),
    ("invalid/describe-object-resolved-kind", dict(OBJ_A1, resolved={"call": OBJ_A1["call"], "resolutions": [
        dict(LOOKUP_ENTRY, kind="method")]}), "E_DESCRIBE",
     "An object answer's resolved holds the lookup resolution only: a method resolution is not one."),
    ("invalid/describe-object-resolved-call", dict(OBJ_A1, resolved={"call": 'shop.example.org/product(sku: "A2")',
                                                                     "resolutions": [LOOKUP_ENTRY]}), "E_DESCRIBE",
     "resolved.call is the object's own call: the lookup named another object."),
    ("invalid/describe-object-resolved-key", dict(OBJ_A1, resolved={"call": OBJ_A1["call"], "resolutions": [
        dict(LOOKUP_ENTRY, to=pkey("A2"))]}), "E_DESCRIBE",
     "The lookup resolution's to is the key encoding of the object described."),
    ("invalid/describe-object-resolved-asof", dict(OBJ_A1, resolved={"call": OBJ_A1["call"], "resolutions": [
        {k: v for k, v in LOOKUP_ENTRY.items() if k != "asof"}]}), "E_DESCRIBE",
     "A lookup resolution carries asof, the instant the lookup cell was read as of."),
]:
    add(vid, "describe", f"K8: {why}", text(doc), error, classes=SHOP_HELD)
add("describe/object-label-absent", "describe", "K8: an object answer without resolved is as valid as ever: the member is "
    "additive, and only an answer to N[label] carries it.", text(OBJ_A1), classes=SHOP_HELD)


# ---------------------------------------------------------------------------
# K10: chaining (5.8, 16.6, 16.7): N(k).m(a).n(b) calls n on the key m returns. env.cells holds the cells of the
# methods that return a key, by their canonical call (without asof), as of the request's asof.

VERSE = CW.VERSE
VERSE_NEXT = {f'{VERSE}/next(book: "Gen", chapter: 1, corpus: "tanakh", verse: 1)':
              f'{VERSE}(book:"Gen",chapter:1,corpus:"tanakh",verse:2)',
              f'{VERSE}/next(book: "Gen", chapter: 1, corpus: "tanakh", verse: 2)':
              f'{VERSE}(book:"Gen",chapter:1,corpus:"tanakh",verse:3)'}


def verse_env(cells, classes=None):
    e = CW.call_env()
    e["cells"] = cells
    if classes:
        e["classes"] = classes
    return e


def verse_expected(analog):
    got = canon.parse_call(analog, CW.call_env())
    return got["uri"], copy.deepcopy(got["resolved"])


V1 = f'{VERSE}(tanakh, Gen, 1, 1)'
uri, res = verse_expected(f"{VERSE}(tanakh, Gen, 1, 3).text(uxlc)?asof={ASOF}")
res["resolutions"] = [{"asof": ASOF, "from": "next", "kind": "chain", "to": f'{VERSE}(book:"Gen",chapter:1,corpus:"tanakh",verse:2)'},
                      {"asof": ASOF, "from": "next", "kind": "chain", "to": f'{VERSE}(book:"Gen",chapter:1,corpus:"tanakh",verse:3)'}] \
    + res["resolutions"]
add("call/class-chain-two-links", "call", "K10: two links, three methods: next() of Genesis 1:1 is 1:2, next() of that is 1:3, "
    "and text is read there; resolved has a chain entry for each method whose key was read, in order, before the "
    "method resolution of the last cell.", f"{V1}.next().next().text(uxlc)?asof={ASOF}", env=verse_env(VERSE_NEXT),
    resolved=res, uri=uri)
uri, res = verse_expected(f"{VERSE}(tanakh, Gen, 1, 2).text(uxlc)?asof={ASOF}")
res["resolutions"] = [{"asof": ASOF, "from": "next", "kind": "chain",
                       "to": f'{VERSE}(book:"Gen",chapter:1,corpus:"tanakh",verse:2)'}] + res["resolutions"]
add("call/class-chain-one-link", "call", "K10: a chain of one link: next() then text; the answer is the envelope of the "
    "last cell, so the call denotes the cell of text at 1:2.", f"{V1}.next().text(uxlc)?asof={ASOF}",
    env=verse_env(VERSE_NEXT), resolved=res, uri=uri)
uri, res = shop_expected(f"{PRODUCT}(A2).price({DAY})?asof={ASOF}", "apple", pkey("A1"),
                         chain=[("successor", pkey("A2"))])
add("call/class-chain-from-label", "call", "K10: a chain from a label: the lookup resolution, then the chain entry, then the "
    "method: apple is A1, its successor is A2, and price is read there.",
    f"{PRODUCT}[apple].successor().price({DAY})?asof={ASOF}", env=shop_env(), resolved=res, uri=uri)
uri, res = shop_expected(f"{PRODUCT}(A3).price({DAY})?asof={ASOF}", "apple", pkey("A1"),
                         chain=[("successor", pkey("A2")), ("successor", pkey("A3"))])
add("call/class-chain-from-label-two-links", "call", "K10: a label, then two links.",
    f"{PRODUCT}[apple].successor().successor().price({DAY})?asof={ASOF}", env=shop_env(), resolved=res, uri=uri)
add("invalid/call-class-chain-after-non-key", "call", "K10: price returns a number, not a key: a link after it is "
    "E_PARSE_URI.", f"{PRODUCT}(A1).price({DAY}).successor()?asof={ASOF}", "E_PARSE_URI", env=shop_env())
add("invalid/call-class-chain-after-blob", "call", "K10: text returns a blob: a link after it is E_PARSE_URI.",
    f"{V1}.text(uxlc).next()?asof={ASOF}", "E_PARSE_URI", env=verse_env(VERSE_NEXT))
add("invalid/call-class-chain-dispatch-key", "call", "K10: a chain's key is a dispatch over the classes the method "
    "declares (16.6): the cell holds a key of fx_pair, not of verse: E_FORMULA_DISPATCH_KEY, a fault.",
    f"{V1}.next().text(uxlc)?asof={ASOF}", "E_FORMULA_DISPATCH_KEY",
    env=verse_env({f'{VERSE}/next(book: "Gen", chapter: 1, corpus: "tanakh", verse: 1)': f'{FX}(base:"EUR",quote:"USD")'}))
add("invalid/call-class-chain-no-now", "call", "K10: a chain reads its cells as of the call's asof, or the mesh's now: "
    "with neither, E_ARG_MISSING, as a lookup does (16.7).", f"{V1}.next().text(uxlc)", "E_ARG_MISSING",
    env=verse_env(VERSE_NEXT))


# ---------------------------------------------------------------------------
# K9: describe of an object lists the functions that extend its class (16.8): extensions, ascending by fn.

sys.path.append(str(ROOT / "crosscheck"))
import generate_060 as g60  # noqa: E402  (describe fixtures; its vectors are built in memory, never written)

FX_OBJ = canon.describe_object(FX, CW.SCENARIO["classes"][FX], {"base": S("EUR"), "quote": S("USD")})
CARRY = CW.EXTRA_CARRY
SPREAD = dict(CW.EXTRA_CARRY, code={"body": "spread table\n", "lang": "stored"})
EXT_CARRY = {"fn": "calc.example.net/fx_extra/carry", "fn_hash": H(CARRY), "publisher": "calc.example.net"}
EXT_SPREAD = {"fn": "calc.example.net/fx_extra/spread", "fn_hash": H(SPREAD), "publisher": "calc.example.net"}
EXT_OTHER = {"fn": "rates.example.org/fx_extra/cost", "fn_hash": H(dict(CARRY, code={"body": "cost\n", "lang": "stored"})),
             "publisher": "rates.example.org"}
FX_HELD = {FX: CW.SCENARIO["classes"][FX]}
for vid, exts, error, why in [
    ("describe/object-extensions", [EXT_CARRY, EXT_SPREAD], None,
     "an object answer lists the functions that extend its class, by name, ascending: fn, fn_hash and the publisher of fn"),
    ("describe/object-extensions-one", [EXT_CARRY], None, "one extension"),
    ("describe/object-extensions-two-hosts", sorted([EXT_CARRY, EXT_OTHER], key=lambda e: e["fn"]), None,
     "a function under any namespace may extend the class: two publishers, ascending by fn"),
    ("invalid/describe-object-extensions-unsorted", [EXT_SPREAD, EXT_CARRY], "E_DESCRIBE", "extensions is ascending by fn"),
    ("invalid/describe-object-extensions-duplicate", [EXT_CARRY, EXT_CARRY], "E_DESCRIBE",
     "extensions is ascending and unique: no function twice"),
    ("invalid/describe-object-extensions-empty", [], "E_DESCRIBE",
     "extensions is omitted when there is none: an empty list is not an answer"),
    ("invalid/describe-object-extensions-publisher", [dict(EXT_CARRY, publisher="rates.example.org")], "E_DESCRIBE",
     "publisher is the host of fn, as everywhere (D108)"),
    ("invalid/describe-object-extensions-member", [dict(EXT_CARRY, description="carry")], "E_DESCRIBE",
     "an entry has fn, fn_hash and publisher, nothing else"),
    ("invalid/describe-object-extensions-no-publisher", [{k: v for k, v in EXT_CARRY.items() if k != "publisher"}],
     "E_DESCRIBE", "an entry names its publisher"),
    ("invalid/describe-object-extensions-hash", [dict(EXT_CARRY, fn_hash="AB" * 32)], "E_DESCRIBE",
     "fn_hash is 64 lowercase hex digits"),
    ("invalid/describe-object-extensions-fn", [dict(EXT_CARRY, fn="fx_extra")], "E_DESCRIBE",
     "fn is a function name (2.3)"),
]:
    add(vid, "describe", f"K9: {why} (16.8).", text(dict(FX_OBJ, extensions=exts)), error, classes=FX_HELD)
add("invalid/describe-object-extensions-not-array", "describe", "K9: extensions is an array.",
    text(dict(FX_OBJ, extensions=EXT_CARRY)), "E_DESCRIBE", classes=FX_HELD)
add("describe/object-extensions-absent", "describe", "K9: an answer without extensions is as valid as before: the member "
    "is additive.", text(FX_OBJ), classes=FX_HELD)
add("invalid/describe-class-extensions", "describe", "K9: only an object answer carries extensions: a class answer does "
    "not.", text(dict(g60.ANSWER, extensions=[EXT_CARRY])), "E_DESCRIBE", classes=g60.HELD)


# ---------------------------------------------------------------------------
# K11: an unquoted run of ASCII digits and hyphens is a string in a string position (5.8).

COMPANY = "filings.example.org/company"
ONE = CW.ONE
COUNT_FN = CW.stored({"cik": CW.STR, "n": ONE}, ["cik", "n"], {"type": "number", "unit": "1"})
FILING_FN = CW.stored({"accession": CW.STR, "cik": CW.STR}, ["cik", "accession"], "string")
COMPANY_OWN = {"keys": {"cik": CW.NONE}, "methods": {"count": H(COUNT_FN), "filing": H(FILING_FN)}, "order": ["cik"],
               "steward": CW.steward("filings.example.org")}
COMPANY_CLASS = canon.define_class(COMPANY, COMPANY_OWN, {"functions": [COUNT_FN, FILING_FN], "definer": "filings.example.org"})
COMPANY_ENV = {"aliases": {}, "classes": {COMPANY: COMPANY_CLASS},
               "functions": {f"{COMPANY}/count": COUNT_FN, f"{COMPANY}/filing": FILING_FN}}
CIK, ACC = "0000320193", "0000320193-24-000123"
QUOTED = f'{COMPANY}("{CIK}").filing("{ACC}")'
got = canon.parse_call(QUOTED, COMPANY_ENV)
for slug, call_text, why in [
    ("key", f'{COMPANY}({CIK}).filing("{ACC}")',
     "an unquoted 10-digit CIK with leading zeros in a string key is that string"),
    ("argument", f'{COMPANY}("{CIK}").filing({ACC})',
     "an unquoted accession number (digits and hyphens) in a string argument is that string"),
    ("both", f"{COMPANY}({CIK}).filing({ACC})", "both unquoted"),
    ("labelled", f"{COMPANY}(cik: {CIK}).filing(accession: {ACC})", "both unquoted and labelled"),
    ("plain", f"{COMPANY}/filing({CIK}, {ACC})", "the plain call, both unquoted"),
]:
    add(f"call/class-unquoted-digits-{slug}", "call", f"K11: {why}; the same cell as the quoted spelling "
        f"{QUOTED}.", call_text, env=COMPANY_ENV, uri=got["uri"], **({"resolved": got["resolved"]} if "resolved" in got
                                                                     and slug != "plain" else {}))
for slug, call_text, error, why in [
    ("number-cik", f'{COMPANY}("{CIK}").count({CIK})', "E_CANON_NUMBER",
     "the same run in a number position keeps today's code: 0000320193 is not a canonical number (3.1)"),
    ("number-accession", f'{COMPANY}("{CIK}").count({ACC})', "E_CANON_NUMBER",
     "the accession run in a number position: the number lexer reads 0000320193 first, today's code"),
    ("number-hyphens", f'{COMPANY}("{CIK}").count(1-1)', "E_PARSE_URI",
     "a run that is no number in a number position keeps today's code: an unquoted value is one token"),
    ("leading-hyphen", f'{COMPANY}(-{CIK}).filing("{ACC}")', "E_CANON_NUMBER",
     "a run must start with a digit: -0000320193 keeps today's code, in a string position too"),
]:
    add(f"invalid/call-class-unquoted-digits-{slug}", "call", f"K11: {why}.", call_text, error, env=COMPANY_ENV)


# ---------------------------------------------------------------------------
# K13: literal defaults (7): an argument declaration may carry "default": a lexical value of its type.

RANK = {"type": "number", "unit": "1", "valid": False, "default": "1"}
SOURCE_SIG = {"args": {"rank": RANK, "subject": CW.STR}, "order": ["subject", "rank"], "returns": "string"}
SOURCE_FN = {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": SOURCE_SIG}
SOURCE_PLAIN = {"code": {"body": "", "lang": "stored"}, "inputs": [],
                "signature": dict(SOURCE_SIG, args={"rank": {k: v for k, v in RANK.items() if k != "default"},
                                                    "subject": CW.STR})}
SOURCE = "calc.example.net/subject_source"
CCY = {"type": "string", "valid": False, "default": "EUR"}
PRICE_IN_FN = {"code": {"body": "", "lang": "stored"}, "inputs": [],
               "signature": {"args": {"currency": CCY, "item": CW.STR}, "order": ["item", "currency"],
                             "returns": {"type": "number", "unit": "1"}}}


def fn_with(arg_name, decl, **extra):
    sig = {"args": {arg_name: decl, "subject": CW.STR}, "order": ["subject", arg_name], "returns": "string"}
    return {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": sig}


for slug, fn, why in [
    ("number", SOURCE_FN, 'a number argument with unit 1 and "default": "1"'),
    ("string", fn_with("kind", {"type": "string", "valid": False, "default": "main"}), 'a string argument with "default": "main"'),
    ("boolean", fn_with("flag", {"type": "boolean", "valid": False, "default": "true"}), 'a boolean argument with "default": "true"'),
    ("number-unit", fn_with("amount", {"type": "number", "unit": "USD", "valid": False, "default": "-1.5"}),
     'a number with a currency unit and "default": "-1.5": a lexical value of the number type (3.1)'),
]:
    add(f"function/default-literal-{slug}", "function", f"K13: {why}; the default is part of the descriptor, so it is hashed (7).",
        text(fn), canonical=jcs_text(fn), sha256=sha(canon.jcs(fn)))
add("function/default-literal-hash-differs", "function", "K13: the same function without the default: another descriptor, "
    "another hash (the default is hashed).", text(SOURCE_PLAIN), canonical=jcs_text(SOURCE_PLAIN),
    sha256=sha(canon.jcs(SOURCE_PLAIN)))
for slug, decl, why in [
    ("number-word", dict(RANK, default="one"), 'the default "one" is not a number'),
    ("number-leading-zero", dict(RANK, default="01"), 'the default "01" is not a canonical number (3.1)'),
    ("number-trailing-zero", dict(RANK, default="1.0"), 'the default "1.0" is not a canonical number (3.1)'),
    ("not-a-string", dict(RANK, default=1), "a default is a lexical value: a JSON string, not the number 1"),
    ("boolean", {"type": "boolean", "valid": False, "default": "yes"}, 'the default "yes" is not a boolean'),
    ("date", {"type": "date", "valid": False, "default": "tomorrow"}, 'the default "tomorrow" is not a date'),
    ("empty", dict(RANK, default=""), "the empty string is not a number"),
]:
    add(f"invalid/function-default-{slug}", "function", f"K13: {why}: E_SCHEMA at define (7).", text(fn_with("rank", decl)),
        "E_SCHEMA")

SRC_FUNCS = {SOURCE: SOURCE_FN}
SRC_PLAIN_FUNCS = {SOURCE: SOURCE_PLAIN}
got = canon.parse_call(f'{SOURCE}("fx", 1)', {"aliases": {}, "functions": SRC_PLAIN_FUNCS})
uri = got["uri"]
add("call/default-literal", "call", "K13: a request with the argument left out takes the literal default; resolved records "
    "a default resolution, the argument and the lexical value.", f'{SOURCE}("fx")',
    env={"aliases": {}, "functions": SRC_FUNCS}, uri=uri,
    resolved={"call": f'{SOURCE}(rank: 1, subject: "fx")', "resolutions": [{"from": "rank", "kind": "default", "to": "1"}]})
add("call/default-literal-labelled", "call", "K13: the same by label: subject given, rank left out.",
    f'{SOURCE}(subject: "fx")', env={"aliases": {}, "functions": SRC_FUNCS}, uri=uri,
    resolved={"call": f'{SOURCE}(rank: 1, subject: "fx")', "resolutions": [{"from": "rank", "kind": "default", "to": "1"}]})
got2 = canon.parse_call(f'{SOURCE}("fx", 2)', {"aliases": {}, "functions": SRC_PLAIN_FUNCS})
add("call/default-literal-given", "call", "K13: an argument that is given is not defaulted: no resolution.",
    f'{SOURCE}("fx", 2)', env={"aliases": {}, "functions": SRC_FUNCS}, uri=got2["uri"])
got3 = canon.parse_call(f'{SOURCE}(rank: 1, subject: "fx")', {"aliases": {}, "functions": SRC_PLAIN_FUNCS})
add("call/default-literal-given-equal", "call", "K13: the default written out is the same cell as the default left out, "
    "and has no default resolution.", f'{SOURCE}("fx", 1)', env={"aliases": {}, "functions": SRC_FUNCS}, uri=got3["uri"])
PRICE_PLAIN = {"code": {"body": "", "lang": "stored"}, "inputs": [], "signature": dict(
    PRICE_IN_FN["signature"], args={"currency": CW.STR, "item": CW.STR})}
got4 = canon.parse_call('calc.example.net/price_in("tea", "EUR")', {"aliases": {}, "functions": {
    "calc.example.net/price_in": PRICE_PLAIN}})
add("call/default-literal-string", "call", "K13: a string default: currency is EUR when left out.",
    'calc.example.net/price_in("tea")', env={"aliases": {}, "functions": {"calc.example.net/price_in": PRICE_IN_FN}},
    uri=got4["uri"], resolved={"call": 'calc.example.net/price_in(currency: "EUR", item: "tea")',
                               "resolutions": [{"from": "currency", "kind": "default", "to": "EUR"}]})
add("invalid/call-default-literal-missing", "call", "K13: an argument with no default stays E_ARG_MISSING when left out.",
    f"{SOURCE}(rank: 2)", "E_ARG_MISSING", env={"aliases": {}, "functions": SRC_FUNCS})

# Bodies: the canonical AST holds the literal, as 16.7 does for asof().
SRC_ENV = {"aliases": {}, "classes": {}, "functions": SRC_FUNCS, "name": CW_E, "signature": sig0("string")}
SRC_ENV_PLAIN = dict(SRC_ENV, functions=SRC_PLAIN_FUNCS)
written = patched(f'{SOURCE}("fx", 1)', SRC_ENV_PLAIN, [])
add("formula/default-literal-left-out", "formula", f'K13: {SOURCE}("fx")  (rank left out: the canonical AST holds the literal '
    "1, the same AST, body and inputs as with it written)", f'{SOURCE}("fx")', env=SRC_ENV, **written)
add("formula/default-literal-written", "formula", f'K13: {SOURCE}("fx", 1)  (rank written: the same AST as '
    "formula/default-literal-left-out)", f'{SOURCE}("fx", 1)', env=SRC_ENV, **written)
add("formula/default-literal-labelled", "formula", f'K13: {SOURCE}(subject: "fx")  (the same by label)',
    f'{SOURCE}(subject: "fx")', env=SRC_ENV, **written)
add("formula/default-literal-other-value", "formula", f'K13: {SOURCE}("fx", 2)  (a given value is not the default: its '
    "own literal)", f'{SOURCE}("fx", 2)', env=SRC_ENV, **patched(f'{SOURCE}("fx", 2)', SRC_ENV_PLAIN, []))
write_ccy = patched('calc.example.net/price_in("tea", "EUR")', dict(SRC_ENV_PLAIN, functions={
    "calc.example.net/price_in": PRICE_PLAIN}, signature=sig0(NUM1)), [])
add("formula/default-literal-string", "formula", 'K13: calc.example.net/price_in("tea")  (a string default: the literal '
    '"EUR" is in the AST)', 'calc.example.net/price_in("tea")',
    env=dict(SRC_ENV, functions={"calc.example.net/price_in": PRICE_IN_FN},
             signature=sig0(NUM1)), **write_ccy)
add("invalid/formula-default-literal-missing", "formula", "K13: an argument with no default left out is still "
    "E_FORMULA_ARG_MISSING (here subject).", f'{SOURCE}(rank: 2)', "E_FORMULA_ARG_MISSING", env=SRC_ENV)
# The signature of the function being defined may carry a default too (a body reading its own argument).
OWN_SIG = {"args": {"rank": RANK}, "order": ["rank"], "returns": {"type": "number", "unit": "1"}}
own_expect = patched("rank + 1", dict(SRC_ENV_PLAIN, signature={"args": {"rank": {k: v for k, v in RANK.items() if k != "default"}},
                                                               "order": ["rank"], "returns": {"type": "number", "unit": "1"}}), [])
add("formula/default-literal-own-argument", "formula", "K13: a body of a function whose argument has a literal default "
    "defines: the default is the signature's, the body reads rank as any argument.", "rank + 1",
    env=dict(SRC_ENV, signature=OWN_SIG), **own_expect)



# The envelope's resolved member (5.5, 16.7) takes the new resolutions: kind chain (K10), and default with a literal (K13).
def add_envelope(vid, why, body, status, error=None):
    request = {"asof": gv.ASOF, "cell_id": gv.cell_id(gv.FX_CELL)}
    extra = {"outcome": body["outcome"]} if error is None else {}
    add(vid, "envelope", why, text(body), error, status=status, keys=gv.ALL_KEYS, request=request, **extra)


_chain_uri, CHAIN_RESOLVED = shop_expected(f"{PRODUCT}(A2).price({DAY})?asof={ASOF}", "apple", pkey("A1"),
                                           chain=[("successor", pkey("A2"))])
add_envelope("envelope/resolved-chain", "K10: the answer to a chained call carries resolved: the lookup, each chain "
             "link (asof, from the method as written, kind chain, to the key read), then the method (5.5, 16.7).",
             {"outcome": "not_covered", "resolved": CHAIN_RESOLVED}, 404)
add_envelope("envelope/resolved-default-literal", "K13: a literal default is a default resolution: from the argument, "
             "to its lexical value.", {"outcome": "not_covered", "resolved": {
                 "call": f'{SOURCE}(rank: 1, subject: "fx")',
                 "resolutions": [{"from": "rank", "kind": "default", "to": "1"}]}}, 404)
add_envelope("invalid/envelope-resolved-chain-asof", "K10: a chain resolution carries asof, the instant the cell was "
             "read as of, as a lookup resolution does.", {"outcome": "not_covered", "resolved": dict(
                 CHAIN_RESOLVED, resolutions=[{k: v for k, v in r.items() if k != "asof"} if r["kind"] == "chain" else r
                                              for r in CHAIN_RESOLVED["resolutions"]])}, 404, "E_ENVELOPE")


# ---------------------------------------------------------------------------
# C2: facets on catalogue entries (16.8, 9.6): "facets" in a function answer, a class answer and a find result.
# Five optional keys; each a list of 1 to 8 names (2.2) of at most 32 bytes, ascending and unique.

FACETS = {"domain": ["finance"], "frequency": ["daily"], "measure": ["exchange_rate"], "region": ["ea"],
          "thing": ["currency"]}
FACETS_MANY = {"domain": ["finance", "tools"], "region": ["ea", "gb", "us", "world"]}
EIGHT = {"measure": ["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8"]}
NINE = {"measure": ["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"]}
LONG32, LONG33 = "x" * 32, "x" * 33
FACET_CASES = [
    ("facets", FACETS, None, "all five keys, one value each"),
    ("facets-several", FACETS_MANY, None, "several values, ascending, some keys omitted"),
    ("facets-eight", EIGHT, None, "eight values, the most a list holds"),
    ("facets-thirty-two", {"thing": [LONG32]}, None, "a value of 32 bytes, the longest"),
    ("facets-none-value", {"region": ["none"], "thing": ["none"]}, None, "none is a value like another"),
    ("facets-unknown-key", dict(FACETS, colour=["blue"]), "E_DESCRIBE", "a facet key other than the five is refused"),
    ("facets-unsorted", {"region": ["gb", "ea"]}, "E_DESCRIBE", "a list is ascending"),
    ("facets-duplicate", {"region": ["ea", "ea"]}, "E_DESCRIBE", "a list is unique"),
    ("facets-empty-list", {"region": []}, "E_DESCRIBE", "a list has at least one value"),
    ("facets-nine", NINE, "E_DESCRIBE", "a list has at most eight values"),
    ("facets-too-long", {"thing": [LONG33]}, "E_DESCRIBE", "a value is at most 32 bytes"),
    ("facets-not-a-name", {"measure": ["Exchange Rate"]}, "E_DESCRIBE", "a value is a name (2.2): lower snake case"),
    ("facets-not-a-list", {"region": "ea"}, "E_DESCRIBE", "a facet is a list of values, not a string"),
    ("facets-not-a-string", {"region": [1]}, "E_DESCRIBE", "a value is a string"),
    ("facets-empty", {}, "E_DESCRIBE", "facets, when present, holds at least one key"),
]
FN_ANSWER = g60.FUNCTION_ANSWER
CLASS_ANSWER = g60.ANSWER
FIND_RESULT = {"description": "The reference rate: units of quote per unit of base.", "fn": "rates.example.org/fx_rate",
               "publisher": "rates.example.org"}
for target, base, extra in [("function", FN_ANSWER, {"functions": [gv.FX]}), ("class", CLASS_ANSWER, {"classes": g60.HELD}),
                            ("find-result", FIND_RESULT, {})]:
    kind = "find-result" if target == "find-result" else "describe"
    for slug, facets, error, why in FACET_CASES:
        vid = f"describe/{target}-{slug}" if error is None else f"invalid/describe-{target}-{slug}"
        where = {"function": "a function answer", "class": "a class answer", "find-result": "a find result"}[target]
        add(vid, kind, f"C2: {why}, in {where} (16.8, 9.6).", text(dict(base, facets=facets)), error, **extra)
    add(f"describe/{target}-facets-absent", kind, f"C2: without facets, {'a find result' if target == 'find-result' else 'an answer'} is as "
        "valid as before: the member is additive.", text(base), **extra)
add("invalid/describe-object-facets", "describe", "C2: only a function answer, a class answer and a find result carry "
    "facets: an object answer does not.", text(dict(gv.CW_OBJECT_ANSWER, facets=FACETS)), "E_DESCRIBE",
    classes=gv.CW_DESCRIBE_CLASSES)
add("invalid/describe-method-facets", "describe", "C2: a method entry of a class answer has no facets: the class's are "
    "the entry's.", text(dict(CLASS_ANSWER, methods=dict(CLASS_ANSWER["methods"], rate=dict(
        CLASS_ANSWER["methods"]["rate"], facets=FACETS)))), "E_DESCRIBE", classes=g60.HELD)


# ---------------------------------------------------------------------------
# C7: describe of the catalogue root (16.8): kind "catalog", one call.

CAT_HOST = "mesh.example.org"
CAT_RULE = f"https://{CAT_HOST}/catalog/rule"


def subject(domain, thing, measure, region):
    return (f'{CAT_HOST}/catalog/subject(domain:"{domain}",measure:"{measure}",region:"{region}",thing:"{thing}")')


def top(domain, thing, measure, region, label, source):
    return {"label": label, "source": f"{CAT_HOST}/{source}", "subject": subject(domain, thing, measure, region)}


FINANCE = {"domain": "finance", "label": "Finance", "names": 7, "subjects": 5, "top": [
    top("finance", "currency", "exchange_rate", "ea", "exchange rate currency euro area", "relay/ecb.europa.eu/fx_reference"),
    top("finance", "rate", "interest_rate", "ea", "interest rate euro area", "relay/ecb.europa.eu/estr"),
    top("finance", "rate", "interest_rate", "gb", "interest rate United Kingdom", "relay/bankofengland.co.uk/bank_rate"),
    top("finance", "yield", "yield", "us", "yield United States", "relay/treasury.gov/par_yield"),
    top("finance", "company", "fundamentals", "us", "fundamentals company United States", "sec/company")]}
EARTH = {"domain": "earth", "label": "Earth", "names": 1, "subjects": 1, "top": [
    top("earth", "region", "rainfall", "world", "rainfall region world", "earth/monthly_rainfall")]}
SCRIPTURE = {"domain": "scripture", "label": "Scripture", "names": 2, "subjects": 1, "top": [
    top("scripture", "verse", "text", "world", "text verse world", "scripture/verse")]}
TOOLS = {"domain": "tools", "label": "Tools", "names": 4, "subjects": 1, "top": [
    top("tools", "none", "ratio", "none", "ratio", "ratio/percent")]}
CATALOG = {"domains": [FINANCE, EARTH, SCRIPTURE, TOOLS], "host": CAT_HOST, "kind": "catalog", "rule": CAT_RULE}


def cat(**change):
    return dict(CATALOG, **change)


def dom(index, **change):
    d = [dict(x) for x in CATALOG["domains"]]
    d[index] = dict(d[index], **change)
    return cat(domains=d)


for vid, doc, error, why in [
    ("describe/catalog", CATALOG, None, "the catalogue root in one call: the host, the domains by number of subjects "
     "(descending, ties by name), each with its label, counts and up to five top subjects with their rank-1 source, "
     "and the url of the rule"),
    ("describe/catalog-no-domains", cat(domains=[]), None, "a mesh with no catalogue entries yet: no domains"),
    ("describe/catalog-one-top", cat(domains=[EARTH]), None, "one domain with one top subject"),
    ("describe/catalog-tie-by-name", cat(domains=[EARTH, SCRIPTURE, TOOLS]), None,
     "domains with equal subjects are ascending by name"),
    ("invalid/describe-catalog-subjects-order", cat(domains=[EARTH, FINANCE]), "E_DESCRIBE",
     "domains are by subjects, descending: finance has more"),
    ("invalid/describe-catalog-tie-order", cat(domains=[TOOLS, EARTH]), "E_DESCRIBE",
     "equal subjects: ascending by domain name, earth before tools"),
    ("invalid/describe-catalog-duplicate-domain", cat(domains=[EARTH, EARTH]), "E_DESCRIBE", "a domain once"),
    ("invalid/describe-catalog-top-six", dom(0, top=FINANCE["top"] + [FINANCE["top"][0]]), "E_DESCRIBE",
     "top has at most five entries"),
    ("invalid/describe-catalog-top-empty", dom(1, top=[]), "E_DESCRIBE", "a domain has at least one top subject"),
    ("invalid/describe-catalog-top-member", dom(1, top=[dict(EARTH["top"][0], rank=1)]), "E_DESCRIBE",
     "a top entry has subject, label and source, nothing else"),
    ("invalid/describe-catalog-top-no-label", dom(1, top=[{k: v for k, v in EARTH["top"][0].items() if k != "label"}]),
     "E_DESCRIBE", "a top entry has a label"),
    ("invalid/describe-catalog-subject-not-key", dom(1, top=[dict(EARTH["top"][0], subject="rainfall")]), "E_DESCRIBE",
     "subject is a key encoding (16.5)"),
    ("invalid/describe-catalog-source-not-name", dom(1, top=[dict(EARTH["top"][0], source="monthly rainfall")]),
     "E_DESCRIBE", "source is a full name (2.3)"),
    ("invalid/describe-catalog-subjects-string", dom(1, subjects="1"), "E_DESCRIBE", "subjects is an integer"),
    ("invalid/describe-catalog-names-negative", dom(1, names=-1), "E_DESCRIBE", "names is a non-negative integer"),
    ("invalid/describe-catalog-domain-name", dom(1, domain="Earth"), "E_DESCRIBE", "a domain is a name (2.2)"),
    ("invalid/describe-catalog-domain-missing", dom(1, label=None), "E_DESCRIBE", "a domain has its label"),
    ("invalid/describe-catalog-domain-member", dom(1, extra=1), "E_DESCRIBE",
     "a domain has domain, label, names, subjects and top, nothing else"),
    ("invalid/describe-catalog-host", cat(host="Mesh.example.org"), "E_DESCRIBE", "host is a DNS name (2.1)"),
    ("invalid/describe-catalog-rule-http", cat(rule=f"http://{CAT_HOST}/catalog/rule"), "E_DESCRIBE",
     "rule is an https URL"),
    ("invalid/describe-catalog-rule-host", cat(rule="https://other.example.org/catalog/rule"), "E_DESCRIBE",
     "rule is the url of /catalog/rule on this host"),
    ("invalid/describe-catalog-no-rule", {k: v for k, v in CATALOG.items() if k != "rule"}, "E_DESCRIBE",
     "rule is required"),
    ("invalid/describe-catalog-no-host", {k: v for k, v in CATALOG.items() if k != "host"}, "E_DESCRIBE",
     "host is required"),
    ("invalid/describe-catalog-member", cat(note="x"), "E_DESCRIBE", "a catalog answer has host, domains, rule and kind"),
]:
    if "domains" in doc:
        doc = dict(doc, domains=[{k: v for k, v in d.items() if v is not None} for d in doc["domains"]])
    add(vid, "describe", f"C7: {why} (16.8).", text(doc), error)


def main():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for vec in VECTORS:
        path = OUT / f"{vec['id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(vec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    valid = sum(v["valid"] for v in VECTORS)
    print(f"wrote {len(VECTORS)} vectors ({valid} valid, {len(VECTORS) - valid} invalid)")


if __name__ == "__main__":
    main()
