# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.2: the user's decisions on the step 1.4 report (BRIEF-spec-0.4.2).

Text: one manifest path; the slice envelope (5.5); job TTL while the mesh runs; the /cells batch
response; E_SLICE_AT_CELL and E_NAME_UNBOUND; the optional versions endpoint; immutable answers for
a past asof.
Additions: pinning a function by hash (name@<fn_hash>(args), the URI's fn_hash=, the envelope's
echo; fn_hash reserved as an argument name); trust computed.
"""

import json
import re
import unittest

from helpers import ROOT, canon
import formula  # noqa: E402

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
H = "ab" * 32  # a function hash
H2 = "cd" * 32
SIG = {"args": {"base": {"type": "string", "valid": False}, "date": {"type": "date", "valid": True},
                "quote": {"type": "string", "valid": False}}, "order": ["base", "quote", "date"],
       "returns": {"type": "number", "unit": "1"}}
URI = "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=USD"
T = "2024-03-16T09:00:00.000000Z"


def code(fn, *args):
    try:
        return fn(*args)
    except canon.DatumeshError as e:
        return e.code


class Codes(unittest.TestCase):
    def test_new_codes_after_e_mesh_doc(self):
        self.assertEqual(canon.ERROR_CODES[-4:], ("E_JOB_UNKNOWN", "E_MESH_DOC", "E_SLICE_AT_CELL", "E_NAME_UNBOUND"))
        for c in ("E_SLICE_AT_CELL", "E_NAME_UNBOUND"):
            self.assertRegex(SPEC, rf"\| `{c}` \|")

    def env(self, env, status, request=None):
        try:
            return canon.check_envelope(status, json.dumps(env).encode(), {}, request or {"cell_id": "a" * 64})["outcome"]
        except canon.DatumeshError as e:
            return e.code

    def test_slice_at_cell_is_a_bad_request(self):
        self.assertEqual(self.env({"error": "E_SLICE_AT_CELL", "outcome": "bad_request"}, 400), "bad_request")
        self.assertEqual(self.env({"error": "E_SLICE_AT_CELL", "outcome": "error"}, 500), "E_ENVELOPE")

    def test_name_unbound_is_not_covered(self):
        self.assertEqual(self.env({"error": "E_NAME_UNBOUND", "outcome": "not_covered"}, 404), "not_covered")
        self.assertEqual(self.env({"error": "E_PARSE_URI", "outcome": "not_covered"}, 404), "E_ENVELOPE")
        self.assertEqual(self.env({"error": "E_NAME_UNBOUND", "fault": "E_FORMULA_DIV_ZERO", "outcome": "not_covered"},
                                  404), "E_ENVELOPE")
        self.assertEqual(self.env({"error": "E_NAME_UNBOUND", "outcome": "error"}, 500), "E_ENVELOPE")
        self.assertEqual(self.env({"error": "E_NAME_UNBOUND", "outcome": "bad_request"}, 400), "E_ENVELOPE")


class UriPin(unittest.TestCase):
    def test_parse_and_format(self):
        ref = canon.parse_uri(f"{URI}&fn_hash={H}&asof={T}", SIG)
        self.assertEqual(ref["fn_hash"], H)
        self.assertEqual(ref["asof"], T)
        self.assertEqual(canon.format_uri(ref), f"{URI}&fn_hash={H}&asof={T}")
        self.assertEqual(canon.check_ref(dict(ref)), ref)
        bare = canon.parse_uri(f"cell://math.example.net/pi?fn_hash={H}", {"args": {}})
        self.assertEqual(canon.format_uri(bare), f"cell://math.example.net/pi?fn_hash={H}")
        self.assertNotIn("fn_hash", canon.parse_uri(URI, SIG))

    def test_rules(self):
        for uri, expected in [
            (f"cell://rates.example.org/fx_rate?base=EUR&fn_hash={H}&date=2024-03-15&quote=USD", "E_CANON_ARG_ORDER"),
            (f"{URI}&fn_hash={H}&fn_hash={H}", "E_CANON_ARG_DUPLICATE"),
            (f"{URI}&asof={T}&fn_hash={H}", "E_CANON_ARG_ORDER"),
            (f"{URI}&fn_hash={H.upper()}", "E_CANON_HEX"),
            (f"{URI}&fn_hash={H[:63]}", "E_CANON_HEX"),
            (f"{URI}&fn_hash=*", "E_CANON_HEX"),
            (f"{URI}&fn_hash=", "E_CANON_HEX"),
        ]:
            with self.subTest(uri):
                self.assertEqual(code(canon.parse_uri, uri, SIG), expected)

    def test_fn_hash_is_reserved_as_an_argument_name(self):
        self.assertEqual(code(canon.check_arg_name, "fn_hash", "$"), "E_CANON_ARG_NAME")
        self.assertEqual(code(canon.check_ref, {"args": {"fn_hash": {"type": "string", "value": "x"}}, "fn": "f",
                                                "ns": "a.example.org"}), "E_CANON_ARG_NAME")
        self.assertEqual(code(canon.check_ref, {"args": {}, "fn": "f", "fn_hash": "A" * 64, "ns": "a.example.org"}),
                         "E_CANON_HEX")

    def test_vectors(self):
        for name in ("uri/pinned", "uri/pinned-asof", "uri/pinned-no-arguments", "ref/pinned"):
            with self.subTest(name):
                self.assertTrue(VECTORS[name]["valid"])
                self.assertEqual(canon.check_vector(VECTORS[name]), [])
        for name, c in [("invalid/uri-pin-not-last", "E_CANON_ARG_ORDER"), ("invalid/uri-pin-twice", "E_CANON_ARG_DUPLICATE"),
                        ("invalid/uri-pin-uppercase", "E_CANON_HEX"), ("invalid/uri-pin-after-asof", "E_CANON_ARG_ORDER"),
                        ("invalid/function-argument-fn-hash", "E_CANON_ARG_NAME"), ("invalid/ref-pin-short", "E_CANON_HEX")]:
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["error"], c)
                self.assertEqual(canon.check_vector(VECTORS[name]), [])


FX = {"code": {"lang": "stored"}, "inputs": [], "signature": SIG}
FX_HASH = canon.function_hash(FX)
CALL_ENV = {"functions": {"rates.example.org/fx_rate": FX}, "aliases": {"fx": "rates.example.org/fx_rate"},
            "descriptors": [FX]}


def call(text, env=CALL_ENV):
    try:
        return canon.parse_call(text, env)["uri"]
    except canon.DatumeshError as e:
        return e.code


class CallForm(unittest.TestCase):
    def test_calls(self):
        self.assertEqual(call('rates.example.org/fx_rate("EUR", "USD", 2024-03-15)'), URI)
        self.assertEqual(call('rates.example.org/fx_rate(quote: "USD", base: "EUR", date: 2024-03-15)'), URI)
        self.assertEqual(call('@fx("EUR", "USD", 2024-03-15)'), URI)
        self.assertEqual(call(f'rates.example.org/fx_rate("EUR", "USD", 2024-03-15)?asof={T}'), f"{URI}&asof={T}")
        self.assertEqual(call(f'rates.example.org/fx_rate@{FX_HASH}("EUR", "USD", 2024-03-15)'), f"{URI}&fn_hash={FX_HASH}")
        self.assertEqual(call(f'@fx@{FX_HASH}("EUR", "USD", 2024-03-15)?asof={T}'), f"{URI}&fn_hash={FX_HASH}&asof={T}")
        self.assertEqual(call('rates.example.org/fx_rate("EUR", *, 2024-03-15)'),
                         "cell://rates.example.org/fx_rate?base=EUR&date=2024-03-15&quote=*")

    def test_errors(self):
        for text, c in [
            ('rates.example.org/nope("EUR")', "E_NAME_UNBOUND"),
            ('@nope("EUR")', "E_NAME_UNBOUND"),
            (f'rates.example.org/fx_rate@{H}("EUR", "USD", 2024-03-15)', "E_FN_UNAVAILABLE"),
            (f'rates.example.org/fx_rate@{H[:63]}("EUR", "USD", 2024-03-15)', "E_PARSE_URI"),
            ('rates.example.org/fx_rate("EUR", "USD", 2024-03-15) + 1', "E_PARSE_URI"),
            ('rates.example.org/fx_rate("E" & "UR", "USD", 2024-03-15)', "E_PARSE_URI"),
            ('rates.example.org/fx_rate("EUR", "USD", [2024-03-01..2024-03-15])', "E_PARSE_URI"),
            ('rates.example.org/fx_rate("EUR", "USD", 2024-03-15', "E_PARSE_URI"),
            ('rates.example.org/fx_rate("EUR", "USD", "2024-03-15")', "E_CANON_TYPE"),
            ('rates.example.org/fx_rate("EUR", "USD", 2024-02-30)', "E_CANON_DATE"),
            ('rates.example.org/fx_rate("EUR", "USD", 2024-03-15, 1)', "E_ARG_UNKNOWN"),
            ('rates.example.org/fx_rate("EUR", "USD")', "E_ARG_MISSING"),
            ('rates.example.org/fx_rate(base: "EUR", base: "EUR", quote: "USD", date: 2024-03-15)', "E_CANON_ARG_DUPLICATE"),
            ('rates.example.org/fx_rate(base: "EUR", tenor: "1M", quote: "USD", date: 2024-03-15)', "E_ARG_UNKNOWN"),
            ('rates.example.org/fx_rate("EUR", "USD", 2024-03-15)?asof=2024-03-16', "E_CANON_INSTANT"),
            ('rates.example.org/fx_rate("EUR", "USD", 2024-03-15)?at=x', "E_PARSE_URI"),
        ]:
            with self.subTest(text):
                self.assertEqual(call(text), c)

    def test_numbers(self):
        env = {"functions": {"m.example.net/f": {"code": {"lang": "stored"}, "inputs": [],
                                                 "signature": {"args": {"x": {"type": "number", "unit": "1",
                                                                              "valid": False}},
                                                               "order": ["x"], "returns": {"type": "number", "unit": "1"}}}},
               "aliases": {}, "descriptors": []}
        self.assertEqual(call("m.example.net/f(-1.5)", env), "cell://m.example.net/f?x=-1.5")
        self.assertEqual(call("m.example.net/f(1.50)", env), "E_CANON_NUMBER")
        self.assertEqual(call("m.example.net/f(-0)", env), "E_CANON_NUMBER")
        self.assertEqual(call("m.example.net/f(1 EUR)", env), "E_PARSE_URI")

    def test_a_pinned_read_is_not_part_of_a_body(self):
        env = {"name": "calc.example.net/g", "signature": {"args": {}, "order": [], "returns": {"type": "number", "unit": "1"}},
               "functions": {"rates.example.org/fx_rate": FX}, "aliases": {}}
        with self.assertRaises(formula.FormulaError) as e:
            formula.compile(f'rates.example.org/fx_rate@{FX_HASH}("EUR", "USD", 2024-03-15)', env)
        self.assertEqual(e.exception.code, "E_FORMULA_PLACEMENT")

    def test_vectors(self):
        calls = [v for v in VECTORS.values() if v["kind"] == "call"]
        self.assertGreaterEqual(sum(v["valid"] for v in calls), 5)
        self.assertGreaterEqual(sum(not v["valid"] for v in calls), 8)
        self.assertIn("E_NAME_UNBOUND", {v.get("error") for v in calls})
        for v in calls:
            with self.subTest(v["id"]):
                self.assertEqual(canon.check_vector(v), [])
        self.assertEqual(VECTORS["invalid/formula-pinned-read"]["error"], "E_FORMULA_PLACEMENT")


# Receipts for the envelope tests, signed with fixed seeds.
SEEDS = {h: bytes([i + 71]) * 32 for i, h in enumerate(["rates.example.org", "mesh.example.net", "other.example.net"])}
KEYENV = {}
for host, seed in SEEDS.items():
    _, pub = canon.keypair(seed)
    KEYENV[host] = {"https": {"status": 200, "body": json.dumps({"host": host, "keys": [{
        "alg": "ed25519", "id": canon.key_id(pub), "public": pub.hex(), "valid_from": "2020-01-01T00:00:00.000000Z"}],
        "proto": canon.PROTO})}}


def receipt(signer, quote="USD", inputs=(), asof=T, fn_hash=H):
    _, pub = canon.keypair(SEEDS[signer])
    cell = {"args": {"base": {"type": "string", "value": "EUR"}, "date": {"type": "date", "value": "2024-03-15"},
                     "quote": {"type": "string", "value": quote}}, "fn": "fx_rate", "fn_hash": fn_hash,
            "ns": "rates.example.org"}
    r = {"asof": asof, "cell": cell, "computed_by": f"{signer}#{canon.key_id(pub)}", "inputs": list(inputs),
         "issued": asof, "licence": "CC0-1.0", "proto": canon.PROTO, "publisher": "rates.example.org",
         "summary": "A rate.", "tx": "2024-03-15T16:00:00.000000Z", "type": "number",
         "valid": {"date": cell["args"]["date"]}, "value": "1.0892"}
    return canon.sign_receipt(r, SEEDS[signer])


def cell_id(r):
    return canon.sha256_hex(canon.jcs(r["cell"]))


def check(env, request, status=200):
    try:
        return canon.check_envelope(status, json.dumps(env).encode(), KEYENV, request)
    except canon.DatumeshError as e:
        return e.code


def outcome(env, request, status=200):
    got = check(env, request, status)
    return got if isinstance(got, str) else got["outcome"]


INPUT = "e" * 64


class Echo(unittest.TestCase):
    def test_a_pinned_request_is_echoed(self):
        r = receipt("rates.example.org")
        req = {"asof": T, "cell_id": cell_id(r), "fn_hash": H}
        self.assertEqual(outcome({"fn_hash": H, "outcome": "ok", "receipt": r, "trust": "primary"}, req), "ok")
        self.assertEqual(outcome({"outcome": "ok", "receipt": r, "trust": "primary"}, req), "E_ENVELOPE")
        self.assertEqual(outcome({"fn_hash": H2, "outcome": "ok", "receipt": r, "trust": "primary"}, req), "E_ENVELOPE")
        self.assertEqual(outcome({"fn_hash": H, "outcome": "not_covered"}, req, 404), "not_covered")
        self.assertEqual(outcome({"outcome": "not_covered"}, req, 404), "E_ENVELOPE")
        self.assertEqual(outcome({"outcome": "rate_limited", "retry_after_seconds": 1}, req, 429), "rate_limited")
        self.assertEqual(outcome({"error": "E_CANON_HEX", "outcome": "bad_request"}, req, 400), "bad_request")

    def test_an_unpinned_request_may_carry_the_hash_it_resolved(self):
        r = receipt("rates.example.org")
        req = {"asof": T, "cell_id": cell_id(r)}
        self.assertEqual(outcome({"fn_hash": H, "outcome": "ok", "receipt": r, "trust": "primary"}, req), "ok")
        self.assertEqual(outcome({"fn_hash": H2, "outcome": "ok", "receipt": r, "trust": "primary"}, req), "E_ENVELOPE")
        self.assertEqual(outcome({"fn_hash": "AB" * 32, "outcome": "not_covered"}, req, 404), "E_ENVELOPE")

    def test_pending_echoes_the_pin_in_its_request(self):
        job = "0" * 32
        base = {"estimate_seconds": 1, "job": job, "outcome": "pending", "poll": f"https://mesh.example.net/jobs/{job}"}
        req = {"cell_id": "a" * 64, "fn_hash": H}
        self.assertEqual(outcome(dict(base, request={"cell_id": "a" * 64, "fn_hash": H}), req, 202), "pending")
        self.assertEqual(outcome(dict(base, request={"cell_id": "a" * 64}), req, 202), "E_ENVELOPE")
        self.assertEqual(outcome(dict(base, request={"cell_id": "a" * 64, "fn_hash": H}), {"cell_id": "a" * 64}, 202),
                         "E_ENVELOPE")
        self.assertEqual(outcome(dict(base, fn_hash=H, request={"cell_id": "a" * 64, "fn_hash": H}), req, 202), "E_ENVELOPE")


class TrustComputed(unittest.TestCase):
    def test_rules(self):
        computed = receipt("mesh.example.net", inputs=[INPUT])
        primary = receipt("rates.example.org")
        mirror = receipt("other.example.net")
        req = lambda r, **kw: dict({"asof": T, "cell_id": cell_id(r)}, **kw)  # noqa: E731
        ok = lambda r, t: {"outcome": "ok", "receipt": r, "trust": t}  # noqa: E731
        self.assertEqual(outcome(ok(computed, "computed"), req(computed)), "ok")
        self.assertEqual(outcome(ok(computed, "computed"), req(computed, mesh="mesh.example.net")), "ok")
        self.assertEqual(outcome(ok(computed, "verified"), req(computed, mesh="mesh.example.net")), "E_ENVELOPE")
        self.assertEqual(outcome(ok(computed, "unverified"), req(computed, mesh="mesh.example.net")), "E_ENVELOPE")
        self.assertEqual(outcome(ok(mirror, "computed"), req(mirror, mesh="mesh.example.net")), "E_ENVELOPE")
        self.assertEqual(outcome(ok(mirror, "verified"), req(mirror, mesh="mesh.example.net")), "ok")
        self.assertEqual(outcome(ok(primary, "computed"), req(primary)), "E_ENVELOPE")
        self.assertEqual(outcome(ok(primary, "primary"), req(primary, mesh="rates.example.org")), "ok")
        self.assertEqual(check(ok(computed, "computed"), req(computed))["trust"], "computed")

    def test_mesh_binds_poll(self):
        job = "0" * 32
        env = {"estimate_seconds": 1, "job": job, "outcome": "pending", "poll": f"https://other.example.net/jobs/{job}",
               "request": {"cell_id": "a" * 64}}
        self.assertEqual(outcome(env, {"cell_id": "a" * 64}, 202), "pending")
        self.assertEqual(outcome(env, {"cell_id": "a" * 64, "mesh": "mesh.example.net"}, 202), "E_ENVELOPE")

    def test_vectors(self):
        self.assertIn("computed", canon.TRUST)
        for name in ("envelope/ok-computed", "envelope/stale-computed", "envelope/ok-computed-mesh"):
            with self.subTest(name):
                self.assertEqual(canon.check_vector(VECTORS[name]), [])
        for name in ("invalid/envelope-computed-primary", "invalid/envelope-computed-other-signer",
                     "invalid/envelope-verified-own-receipt", "invalid/envelope-poll-other-mesh"):
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["error"], "E_ENVELOPE")
                self.assertEqual(canon.check_vector(VECTORS[name]), [])


def slice_obj(fn_hash=H):
    return {"args": {"base": {"type": "string", "value": "EUR"}, "date": {"type": "date", "value": "2024-03-15"},
                     "quote": "*"}, "fn": "fx_rate", "fn_hash": fn_hash, "ns": "rates.example.org"}


def member(r, trust="primary"):
    return {"outcome": "ok", "receipt": r, "trust": trust}


class SliceEnvelope(unittest.TestCase):
    def page(self, members, **over):
        env = {"members": members, "outcome": "ok", "slice": slice_obj()}
        env.update(over)
        return {k: v for k, v in env.items() if v is not None}

    def req(self, **kw):
        return dict({"asof": T, "slice_id": canon.slice_id(slice_obj())}, **kw)

    def test_valid(self):
        a, b = receipt("rates.example.org", "CHF"), receipt("rates.example.org", "USD")
        got = check(self.page([member(a), member(b)]), self.req())
        self.assertEqual(got["outcome"], "ok")
        self.assertEqual([m["receipt_hash"] for m in got["results"]], [canon.receipt_hash(a), canon.receipt_hash(b)])
        self.assertEqual(outcome(self.page([]), self.req()), "ok")
        self.assertEqual(outcome(self.page([member(b)], next="https://mesh.example.net/slice/x?after=1"),
                                 self.req(mesh="mesh.example.net")), "ok")
        stale = {"age_seconds": 5, "outcome": "stale", "receipt": a, "trust": "primary"}
        self.assertEqual(outcome(self.page([stale]), self.req()), "ok")
        self.assertEqual(outcome({"outcome": "not_covered"}, self.req(), 404), "not_covered")

    def test_rules(self):
        a, b = receipt("rates.example.org", "CHF"), receipt("rates.example.org", "USD")
        late = receipt("rates.example.org", "GBP", asof="2024-03-17T09:00:00.000000Z")
        other_fn = receipt("rates.example.org", "JPY", fn_hash=H2)
        after = {"quote": {"type": "string", "value": "CHF"}}
        for name, env, req, status in [
            ("out of order", self.page([member(b), member(a)]), self.req(), 200),
            ("duplicate", self.page([member(a), member(a)]), self.req(), 200),
            ("not a member", self.page([member(other_fn)]), self.req(), 200),
            ("later asof", self.page([member(late)]), self.req(), 200),
            ("another slice", self.page([member(a)], slice=slice_obj(H2)), self.req(), 200),
            ("not after the cursor", self.page([member(a)]), self.req(after=after), 200),
            ("member not_covered", self.page([{"outcome": "not_covered"}]), self.req(), 200),
            ("member with status", self.page([dict(member(a), status=200)]), self.req(), 200),
            ("next on another host", self.page([member(a)], next="https://other.example.net/slice/x"),
             self.req(mesh="mesh.example.net"), 200),
            ("next not https", self.page([member(a)], next="http://mesh.example.net/slice/x"), self.req(), 200),
            ("a receipt at the top", dict(self.page([member(a)]), receipt=a), self.req(), 200),
            ("status", self.page([member(a)]), self.req(), 202),
            ("pending at /slice", {"estimate_seconds": 1, "job": "0" * 32, "outcome": "pending",
                                   "poll": "https://mesh.example.net/jobs/" + "0" * 32,
                                   "request": {"cell_id": "a" * 64}}, self.req(), 202),
            ("stale at the top", {"age_seconds": 1, "outcome": "stale", "receipt": a, "trust": "primary"}, self.req(), 200),
        ]:
            with self.subTest(name):
                self.assertEqual(outcome(env, req, status), "E_ENVELOPE")
        self.assertEqual(outcome(self.page([member(b)]), self.req(after=after)), "ok")

    def test_a_member_receipt_is_verified(self):
        a = receipt("rates.example.org", "CHF")
        bad = dict(a, value="1.0893")
        self.assertEqual(outcome(self.page([member(bad)]), self.req()), "E_SIGNATURE")

    def test_vectors(self):
        for name in ("envelope/slice-page", "envelope/slice-last-page", "envelope/slice-empty", "envelope/slice-after"):
            with self.subTest(name):
                self.assertEqual(canon.check_vector(VECTORS[name]), [])
        for name in ("invalid/envelope-slice-unordered", "invalid/envelope-slice-not-member",
                     "invalid/envelope-slice-later-asof", "invalid/envelope-slice-other-slice",
                     "invalid/envelope-slice-before-cursor", "invalid/envelope-slice-member-outcome"):
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["error"], "E_ENVELOPE")
                self.assertEqual(canon.check_vector(VECTORS[name]), [])


class Batch(unittest.TestCase):
    def batch(self, items, requests, status=200):
        try:
            return canon.check_batch(status, json.dumps(items).encode(), KEYENV, requests)
        except canon.DatumeshError as e:
            return e.code

    def test_items_in_request_order_with_their_status(self):
        a, b = receipt("rates.example.org", "CHF"), receipt("rates.example.org", "USD")
        reqs = [{"asof": T, "cell_id": cell_id(a)}, {"asof": T, "cell_id": cell_id(b)}, {"cell_id": "f" * 64}]
        items = [{"envelope": member(a), "status": 200}, {"envelope": member(b), "status": 200},
                 {"envelope": {"outcome": "not_covered"}, "status": 404}]
        got = self.batch(items, reqs)
        self.assertEqual([r["outcome"] for r in got["results"]], ["ok", "ok", "not_covered"])
        self.assertEqual(got["results"][0]["receipt_hash"], canon.receipt_hash(a))
        swapped = [items[1], items[0], items[2]]
        self.assertEqual([r.get("error") for r in self.batch(swapped, reqs)["results"]], ["E_ENVELOPE", "E_ENVELOPE", None])
        wrong_status = [items[0], items[1], {"envelope": {"outcome": "not_covered"}, "status": 200}]
        self.assertEqual(self.batch(wrong_status, reqs)["results"][2], {"error": "E_ENVELOPE"})
        err = [items[0], items[1], {"envelope": {"error": "E_INPUT_UNAVAILABLE", "outcome": "error"}, "status": 503}]
        self.assertEqual(self.batch(err, reqs)["results"][2], {"outcome": "error"})

    def test_whole_batch_failures(self):
        a = receipt("rates.example.org", "CHF")
        reqs = [{"asof": T, "cell_id": cell_id(a)}]
        good = {"envelope": member(a), "status": 200}
        for name, items in [("not an array", {"envelope": member(a), "status": 200}), ("too few", []),
                            ("too many", [good, good]), ("extra member", [dict(good, id=1)]),
                            ("no status", [{"envelope": member(a)}]), ("status text", [{"envelope": member(a), "status": "200"}]),
                            ("status fraction", [{"envelope": member(a), "status": 200.5}])]:
            with self.subTest(name):
                self.assertEqual(self.batch(items, reqs), "E_ENVELOPE")
        self.assertEqual(self.batch({"outcome": "rate_limited", "retry_after_seconds": 3}, reqs, 429),
                         {"outcome": "rate_limited"})
        self.assertEqual(self.batch({"error": "E_CANON_LIMIT", "outcome": "bad_request"}, reqs, 400), {"outcome": "bad_request"})
        self.assertEqual(self.batch({"outcome": "ok", "receipt": a, "trust": "primary"}, reqs, 200), "E_ENVELOPE")

    def test_vectors(self):
        batches = [v for v in VECTORS.values() if v["kind"] == "batch"]
        self.assertGreaterEqual(sum(v["valid"] for v in batches), 3)
        self.assertGreaterEqual(sum(not v["valid"] for v in batches), 3)
        for v in batches:
            with self.subTest(v["id"]):
                self.assertEqual(canon.check_vector(v), [])


class MeshVersions(unittest.TestCase):
    def test_optional_versions_endpoint(self):
        self.assertEqual(canon.MESH_ENDPOINTS["versions"], ("cell",))
        self.assertNotIn("versions", canon.MESH_REQUIRED)
        self.assertEqual(canon.check_vector(VECTORS["mesh/versions"]), [])
        self.assertIn("versions", VECTORS["mesh/versions"]["endpoints"])
        self.assertEqual(VECTORS["invalid/mesh-versions-no-placeholder"]["error"], "E_MESH_DOC")
        self.assertTrue((ROOT / "schemas" / "versions.schema.json").exists())


class Schemas(unittest.TestCase):
    def test_envelopes_batches_and_versions(self):
        import jsonschema
        from test_vectors import validator
        envelope = validator("envelope")
        for v in VECTORS.values():
            if v["kind"] == "batch" and v["valid"] and v["status"] == 200:
                for item in json.loads(v["input"]):
                    if "error" not in json.dumps(v["results"]):
                        envelope.validate(item["envelope"])
            if v["kind"] == "envelope" and v["valid"] and "slice_id" in v["request"]:
                with self.subTest(v["id"]):
                    envelope.validate(json.loads(v["input"]))
        with self.assertRaises(jsonschema.ValidationError):
            envelope.validate({"error": "E_NAME_UNBOUND", "fault": "E_FORMULA_DIV_ZERO", "outcome": "not_covered"})
        with self.assertRaises(jsonschema.ValidationError):
            envelope.validate({"error": "E_SLICE_AT_CELL", "outcome": "error"})
        validator("versions").validate({"cell": {"args": {}, "fn": "pi", "fn_hash": H, "ns": "math.example.net"},
                                         "versions": [{"asof": T, "receipt": H2, "tx": T}]})
        validator("cell-ref").validate({"args": {}, "fn": "pi", "fn_hash": H, "ns": "math.example.net"})


class Text(unittest.TestCase):
    def test_statements(self):
        s15 = SPEC[SPEC.index("### 15.13"):SPEC.index("### 15.14")]
        self.assertNotIn("/slice/<slice id>/<members hash>", s15)
        self.assertIn("/manifest/", s15)
        for phrase in ("while the mesh runs", "### 5.6 Slices", "### 5.7 Batches", "### 5.8 Calls", "immutable",
                       "a later asof", "| `computed` |", "`fn_hash=`", "### spec-0.4.2"):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)
        for d in ("D70", "D71", "D72", "D73"):
            self.assertRegex(SPEC, rf"\| {d} \|")
        # Since spec-0.4.3 the status line names spec-0.4.3 (test_spec_0_4_3.py); this revision's
        # entry stays in section 14.


if __name__ == "__main__":
    unittest.main()
