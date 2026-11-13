# SPDX-License-Identifier: Apache-2.0
"""spec-0.5.0, part one (CONTRACT-spec-0.4.4, superseded into spec-0.5.0 by the user, 2026-11-13):

1. The loopback mesh document for unrooted hosts (the user's decision B3 b, verbatim: "for an
   unrooted host (a name under .invalid), mesh-document URLs and poll may be http:// on a loopback
   address only (127.0.0.1, [::1], localhost); rooted hosts stay https-only"): 9.6's URLs,
   `bindings` included, and 5.5's `poll` and 5.6's `next`; an optional port; one origin per
   mesh document.
3. The library findings: RS-44, RS-45, RS-46, DEF-57, JS 56-59 (10.3: collecting L as step 7.5
   does, with its codes; 8.5: the rule's arguments are checked; 2.5: is_unrooted takes a valid
   namespace; 11: a licence vector's declarations).

The key document of an unrooted host is not fetched over loopback http: it stays supplied out of
band (the user's answer, 2026-11-13). Decision 2 (E_UNROOTED_INPUT) is flagged: define has no
answer format in the spec.
"""

import json
import unittest

from helpers import ROOT, canon

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
T0 = "2020-01-01T00:00:00.000000Z"
FN = "calc.example.net/convert"
ISSUED = "2024-03-16T09:00:00.000000Z"


def code(fn, *args):
    try:
        return fn(*args)
    except canon.DatumeshError as e:
        return e.code


# ---------------------------------------------------------------------------
# 1. Loopback URLs of unrooted hosts


def mesh_env(host, base, **endpoint_bases):
    eps = {"cell": "cell/{cell}", "descriptor": "descriptor/{hash}", "jobs": "jobs/{job}",
           "manifest": "manifest/{slice_id}/{members_hash}", "receipt": "receipt/{hash}"}
    endpoints = {k: endpoint_bases.get(k, base) + v for k, v in eps.items()}
    mesh = {"bindings": endpoint_bases.get("bindings", base) + "bindings", "endpoints": endpoints, "host": host,
            "proto": "datumesh/1"}
    keys = {"host": host, "keys": [{"alg": "ed25519", "id": "d712b32a2cc5cb7c",
                                    "public": "843baeb22bfd0364fb1b7262b367fb3202e7886c69a070fecf8e343fedb1eabf",
                                    "valid_from": T0}], "proto": "datumesh/1"}
    return {"keys": {"https": {"status": 200, "body": json.dumps(keys)}},
            "mesh": {"https": {"status": 200, "body": json.dumps(mesh)}}}


class LoopbackMeshDocument(unittest.TestCase):
    def test_unrooted_hosts_may_use_one_loopback_origin(self):
        for base in ("http://127.0.0.1:8471/", "http://[::1]/", "http://localhost/", "http://localhost:65535/x/",
                     "https://local.invalid/"):
            with self.subTest(base):
                got = canon.resolve_mesh("local.invalid", mesh_env("local.invalid", base))
                self.assertEqual(got["bindings"], base + "bindings")

    def test_what_is_refused(self):
        cases = [
            ("local.invalid", "http://10.0.0.1/", {}),  # not loopback
            ("local.invalid", "http://127.0.0.2/", {}),
            ("local.invalid", "http://local.invalid/", {}),
            ("local.invalid", "http://LOCALHOST/", {}),
            ("local.invalid", "http://localhost:0/", {}),
            ("local.invalid", "http://localhost:08471/", {}),
            ("local.invalid", "http://localhost:65536/", {}),
            ("local.invalid", "http://localhost:/", {}),
            ("local.invalid", "http://localhost", {}),  # no path
            ("local.invalid", "http://user@localhost/", {}),
            ("local.invalid", "http://[0:0:0:0:0:0:0:1]/", {}),
            ("local.invalid", "http://127.0.0.1:8471/", {"jobs": "http://localhost:8471/"}),  # two origins
            ("local.invalid", "http://127.0.0.1:8471/", {"bindings": "http://127.0.0.1:8472/"}),
            ("local.invalid", "http://127.0.0.1/", {"receipt": "https://local.invalid/"}),
            ("local.invalid", "https://127.0.0.1/", {}),
            ("mesh.example.org", "http://127.0.0.1/", {}),  # rooted: https only
            ("mesh.example.org", "http://localhost:8471/", {}),
            ("mesh.example.org", "https://mesh.example.org:443/", {}),
        ]
        for host, base, over in cases:
            with self.subTest(host=host, base=base, over=over):
                self.assertEqual(code(canon.resolve_mesh, host, mesh_env(host, base, **over)), "E_MESH_DOC")

    def test_vectors(self):
        for name in ("unrooted-loopback-port", "unrooted-loopback-ipv6", "unrooted-loopback-localhost"):
            with self.subTest(name):
                v = VECTORS[f"mesh/{name}"]
                self.assertEqual(v["host"], "local.invalid")
                self.assertTrue(v["bindings"].startswith("http://"))
                self.assertEqual(canon.check_vector(v), [])
        for name in ("unrooted-http-not-loopback", "rooted-http-loopback", "unrooted-two-loopback-origins",
                     "unrooted-https-and-loopback", "unrooted-loopback-port-zero"):
            with self.subTest(name):
                v = VECTORS[f"invalid/mesh-{name}"]
                self.assertEqual(v["error"], "E_MESH_DOC")
                self.assertEqual(canon.check_vector(v), [])


JOB = "0123456789abcdef0123456789abcdef"
CELL_ID = "a" * 64


def pending(poll):
    return {"estimate_seconds": 1, "job": JOB, "outcome": "pending", "poll": poll, "request": {"cell_id": CELL_ID}}


def env(body, status, request):
    try:
        return canon.check_envelope(status, json.dumps(body).encode(), {}, request)["outcome"]
    except canon.DatumeshError as e:
        return e.code


class LoopbackPoll(unittest.TestCase):
    def test_poll(self):
        unrooted = {"cell_id": CELL_ID, "mesh": "local.invalid"}
        for poll in (f"http://127.0.0.1:8471/jobs/{JOB}", f"http://[::1]/jobs/{JOB}", f"http://localhost/x/jobs/{JOB}",
                     f"https://local.invalid/jobs/{JOB}"):
            with self.subTest(poll):
                self.assertEqual(env(pending(poll), 202, unrooted), "pending")
        loop = f"http://127.0.0.1:8471/jobs/{JOB}"
        self.assertEqual(env(pending(loop), 202, {"cell_id": CELL_ID, "mesh": "mesh.example.org"}), "E_ENVELOPE")
        self.assertEqual(env(pending(loop), 202, {"cell_id": CELL_ID}), "E_ENVELOPE")  # no mesh named
        for bad in (f"http://10.0.0.1/jobs/{JOB}", f"http://localhost:0/jobs/{JOB}", f"http://LOCALHOST/jobs/{JOB}",
                    f"https://127.0.0.1/jobs/{JOB}"):
            with self.subTest(bad):
                self.assertEqual(env(pending(bad), 202, unrooted), "E_ENVELOPE")
        # A rooted request keeps https on its host.
        self.assertEqual(env(pending(f"https://mesh.example.org/jobs/{JOB}"), 202,
                             {"cell_id": CELL_ID, "mesh": "mesh.example.org"}), "pending")

    def test_vectors(self):
        for name in ("envelope/pending-poll-loopback-unrooted", "envelope/slice-next-loopback-unrooted"):
            with self.subTest(name):
                self.assertTrue(VECTORS[name]["valid"])
                self.assertEqual(canon.check_vector(VECTORS[name]), [])
        for name in ("pending-poll-loopback-rooted", "pending-poll-loopback-no-mesh", "pending-poll-http-not-loopback",
                     "slice-next-loopback-rooted"):
            with self.subTest(name):
                v = VECTORS[f"invalid/envelope-{name}"]
                self.assertEqual(v["error"], "E_ENVELOPE")
                self.assertEqual(canon.check_vector(v), [])


# ---------------------------------------------------------------------------
# 3. The library findings


class RuleArguments(unittest.TestCase):
    """JS 56: the rule's arguments are checked (8.5)."""

    def inherit(self, licences, fn=FN, issued=ISSUED, own="CC-BY-4.0"):
        return code(canon.inherit_licence, licences, {}, fn, issued, own)

    def test_checked(self):
        self.assertEqual(self.inherit(["MIT License"]), "E_CANON_LICENCE")
        self.assertEqual(self.inherit(["CC0-1.0", "MIT License"]), "E_CANON_LICENCE")
        self.assertEqual(self.inherit(["A" * 65]), "E_CANON_LIMIT")
        self.assertEqual(self.inherit(["MIT"], fn="convert"), "E_CANON_NAME")
        self.assertEqual(self.inherit(["MIT"], issued="2024-03-16"), "E_CANON_INSTANT")
        self.assertEqual(self.inherit([], own="no such licence"), "E_CANON_LICENCE")
        # Order: the licences in order, then fn, then issued, then the mesh's own licence.
        self.assertEqual(self.inherit(["MIT License"], fn="x", issued="y", own="z z"), "E_CANON_LICENCE")
        self.assertEqual(self.inherit(["MIT"], fn="x", issued="y", own="z z"), "E_CANON_NAME")
        self.assertEqual(self.inherit(["MIT"], issued="y", own="z z"), "E_CANON_INSTANT")

    def test_vectors(self):
        for name, c in [("malformed-licence", "E_CANON_LICENCE"), ("bad-fn", "E_CANON_NAME"),
                        ("bad-issued", "E_CANON_INSTANT")]:
            with self.subTest(name):
                v = VECTORS[f"invalid/licence-{name}"]
                self.assertEqual((v["kind"], v["error"]), ("licence", c))
                self.assertEqual(canon.check_vector(v), [])


class CollectingL(unittest.TestCase):
    """RS-44, DEF-57, JS 57: an entitlement check collects L as step 7.5 obtains the inputs."""

    def test_vectors(self):
        for name, c in [("input-missing", "E_INPUT_UNAVAILABLE"), ("manifest-missing", "E_INPUT_UNAVAILABLE"),
                        ("input-other-hash", "E_INPUT_UNAVAILABLE"), ("input-bad-signature", "E_INPUT_INVALID"),
                        ("member-missing", "E_INPUT_UNAVAILABLE"), ("receipt-bad-signature", "E_SIGNATURE")]:
            with self.subTest(name):
                v = VECTORS[f"invalid/entitlement-{name}"]
                self.assertEqual((v["kind"], v["error"]), ("entitlement", c))
                self.assertEqual(canon.check_vector(v), [])

    def test_l_for_no_inputs_is_the_callers_error(self):
        """JS 58: a non-empty L for a receipt whose inputs are empty cannot be its input licences."""
        r = {"cell": {"args": {}, "fn": "convert", "fn_hash": "a" * 64, "ns": "calc.example.net"},
             "inputs": [], "issued": ISSUED, "licence": "MIT"}
        doc = {"host": "calc.example.net", "keys": [], "declarations": {}}
        with self.assertRaises(ValueError):
            canon.check_entitlement(r, ["MIT"], doc)
        self.assertEqual(canon.check_entitlement(r, [], doc), {"entitled": True, "reason": "no_inputs"})


class IsUnrooted(unittest.TestCase):
    """RS-45, JS 59: is_unrooted takes a valid namespace (a host, a namespace or a full function name)."""

    def test_valid_names(self):
        for name in ("local.invalid", "a.b.invalid", "local.invalid/notes", "local.invalid/notes/f"):
            self.assertTrue(canon.is_unrooted(name), name)
        for name in ("rates.example.org", "invalid.example.org/f"):
            self.assertFalse(canon.is_unrooted(name), name)

    def test_not_names(self):
        for name in ("invalid", "LOCAL.INVALID", "local.invalid/Bad", "local.invalid.", ""):
            with self.subTest(name):
                self.assertEqual(code(canon.is_unrooted, name), "E_CANON_NAME")


class Text(unittest.TestCase):
    def test_statements(self):
        for phrase in (
            "Status: draft, revision `spec-0.5.0` (in progress, part one).",
            "### spec-0.5.0 (in progress, part one)",
            "for an unrooted host (a name under .invalid), mesh-document URLs and poll may be http:// on a loopback "
            "address only (127.0.0.1, [::1], localhost); rooted hosts stay https-only",
            "**Loopback URLs**",
            "one origin",
            "libraries before their spec-0.5.0 releases",
            "never the key document",
            "The rule is defined for licences by 8.1",
            "as step 7.5 obtains them",
            "presumes",
            "| D79 |",
        ):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)

    def test_crosscheck(self):
        text = (ROOT / "crosscheck" / "README.md").read_text(encoding="utf-8")
        self.assertIn("spec-0.5.0", text)
        self.assertIn("LIBS=0.4.3", text)
        self.assertTrue((ROOT / "crosscheck" / "generate_050.py").exists())


if __name__ == "__main__":
    unittest.main()
