# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.1, two normative additions (the user's decision of 2026-10-25):

A. pending, a ninth envelope outcome (5.5): HTTP 202, job, estimate_seconds, poll (required), the
   original request; the job's result is bound to the original request, never the job URL; an
   unknown or expired job is bad_request with E_JOB_UNKNOWN.
B. The mesh document /.well-known/datumesh-mesh.json (9.6): it and the key document must agree on
   host and proto; cross-mesh resolution rejects the host with E_MESH_DOC otherwise.
"""

import json
import re
import unittest

from helpers import ROOT, canon

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
CELL = "a" * 64
JOB = "0123456789abcdef0123456789abcdef"


def pending(**over):
    env = {"estimate_seconds": 3, "job": JOB, "outcome": "pending",
           "poll": f"https://mesh.example/jobs/{JOB}", "request": {"asof": "2024-03-16T09:00:00.000000Z", "cell_id": CELL}}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def check(env, request, status=202):
    try:
        return canon.check_envelope(status, json.dumps(env).encode(), {}, request)["outcome"]
    except canon.DatumeshError as e:
        return e.code


REQ = {"asof": "2024-03-16T09:00:00.000000Z", "cell_id": CELL}


class Pending(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(check(pending(), REQ), "pending")
        self.assertEqual(check(pending(), dict(REQ, job=JOB)), "pending")  # polled: the same job
        no_asof = pending(request={"cell_id": CELL})
        self.assertEqual(check(no_asof, {"cell_id": CELL}), "pending")

    def test_members(self):
        for env in (pending(poll=None), pending(job=None), pending(request=None), pending(estimate_seconds=None),
                    pending(receipt={}), pending(trust="verified"), pending(job="ABC"), pending(job="0" * 31),
                    pending(poll=f"http://mesh.example/jobs/{JOB}"), pending(poll="https://mesh.example/jobs/other"),
                    pending(estimate_seconds=1.5), pending(request={"cell_id": CELL, "extra": 1})):
            with self.subTest(env=env):
                self.assertEqual(check(env, REQ), "E_ENVELOPE")
        self.assertEqual(check(pending(), REQ, status=200), "E_ENVELOPE")

    def test_binding_to_the_original_request(self):
        self.assertEqual(check(pending(), dict(REQ, cell_id="b" * 64)), "E_ENVELOPE")
        self.assertEqual(check(pending(), {"cell_id": CELL}), "E_ENVELOPE")  # an asof echoed that was not asked
        self.assertEqual(check(pending(request={"cell_id": CELL}), REQ), "E_ENVELOPE")  # the asof dropped
        self.assertEqual(check(pending(), dict(REQ, job="f" * 32)), "E_ENVELOPE")  # polled another job

    def test_unknown_job(self):
        env = {"error": "E_JOB_UNKNOWN", "outcome": "bad_request"}
        self.assertEqual(check(env, dict(REQ, job=JOB), status=400), "bad_request")

    def test_vectors(self):
        need = """envelope/pending envelope/pending-no-asof envelope/pending-polled envelope/job-result-ok
        envelope/job-result-not-covered envelope/job-unknown invalid/envelope-pending-missing-poll
        invalid/envelope-pending-missing-job invalid/envelope-pending-with-receipt invalid/envelope-pending-with-trust
        invalid/envelope-pending-other-cell invalid/envelope-pending-asof-dropped invalid/envelope-pending-polled-other-job
        invalid/envelope-pending-poll-other-job invalid/envelope-pending-status invalid/envelope-job-result-other-cell
        invalid/envelope-job-result-later-asof""".split()
        self.assertEqual([i for i in need if i not in VECTORS], [])
        for i in need:
            with self.subTest(i):
                self.assertEqual(canon.check_vector(VECTORS[i]), [])


MESH = "mesh.example.org"


def mesh_doc(**over):
    base = f"https://{MESH}"
    doc = {"bindings": f"{base}/bindings",
           "endpoints": {"blob": f"{base}/blob/{{sha256}}", "cell": f"{base}/cell/{{cell}}", "cells": f"{base}/cells",
                         "descriptor": f"{base}/descriptor/{{hash}}", "explain": f"{base}/explain/{{cell}}",
                         "find": f"{base}/find", "jobs": f"{base}/jobs/{{job}}",
                         "manifest": f"{base}/manifest/{{slice_id}}/{{members_hash}}",
                         "receipt": f"{base}/receipt/{{hash}}", "slice": f"{base}/slice/{{cell}}", "verify": f"{base}/verify"},
           "host": MESH, "proto": "datumesh/1"}
    doc.update(over)
    return {k: v for k, v in doc.items() if v is not None}


def key_doc(host=MESH, proto="datumesh/1"):
    _, public = canon.keypair(bytes(32))
    return {"host": host, "keys": [{"alg": "ed25519", "id": canon.key_id(public), "public": public.hex(),
                                    "valid_from": "2020-01-01T00:00:00.000000Z"}], "proto": proto}


def env(mesh=None, keys=None, mesh_status=200):
    e = {"keys": {"https": {"status": 200, "body": json.dumps(keys or key_doc())}},
         "mesh": {"https": {"status": mesh_status}}}
    if mesh_status == 200:
        e["mesh"]["https"]["body"] = mesh if isinstance(mesh, str) else json.dumps(mesh or mesh_doc())
    return e


def resolve(e):
    try:
        return canon.resolve_mesh(MESH, e)
    except canon.DatumeshError as err:
        return err.code


class MeshDocument(unittest.TestCase):
    def test_valid(self):
        got = resolve(env())
        self.assertEqual(got["bindings"], f"https://{MESH}/bindings")
        self.assertEqual(got["endpoints"]["cell"], f"https://{MESH}/cell/{{cell}}")
        ext = mesh_doc(x_status="beta")  # unknown members are ignored
        ext["endpoints"] = dict(ext["endpoints"], x_graphql=f"https://{MESH}/graphql")
        self.assertNotIn("x_status", resolve(env(ext)))
        minimal = mesh_doc()
        minimal["endpoints"] = {k: v for k, v in minimal["endpoints"].items()
                                if k in ("cell", "descriptor", "jobs", "manifest", "receipt")}
        self.assertEqual(sorted(resolve(env(minimal))["endpoints"]), ["cell", "descriptor", "jobs", "manifest", "receipt"])

    def test_rejected(self):
        other = mesh_doc()
        other["endpoints"] = dict(other["endpoints"], cell="https://elsewhere.example/cell/{cell}")
        no_placeholder = mesh_doc()
        no_placeholder["endpoints"] = dict(no_placeholder["endpoints"], receipt=f"https://{MESH}/receipt")
        missing = mesh_doc()
        missing["endpoints"] = {k: v for k, v in missing["endpoints"].items() if k != "jobs"}
        for name, e in [("host", env(mesh_doc(host="other.example.org"))),
                        ("proto", env(mesh_doc(proto="datumesh/2"))),
                        ("key doc names another host", env(keys=key_doc(host="other.example.org"))),
                        ("endpoint on another host", env(other)),
                        ("bindings on another host", env(mesh_doc(bindings="https://other.example.org/bindings"))),
                        ("malformed", env("{not json")), ("not an object", env("[]")),
                        ("no endpoints", env(mesh_doc(endpoints=None))), ("a required endpoint missing", env(missing)),
                        ("no placeholder", env(no_placeholder)), ("unavailable", env(mesh_status=404))]:
            with self.subTest(name):
                self.assertEqual(resolve(e), "E_MESH_DOC")

    def test_key_document_failures_keep_their_codes(self):
        e = env()
        e["keys"] = {"https": {"status": 404}}
        self.assertEqual(resolve(e), "E_KEY_UNAVAILABLE")

    def test_vectors(self):
        mesh = [v for v in VECTORS.values() if v["kind"] == "mesh"]
        self.assertGreaterEqual(sum(v["valid"] for v in mesh), 3)
        self.assertGreaterEqual(sum(not v["valid"] for v in mesh), 8)
        for name in ("invalid/mesh-host-mismatch", "invalid/mesh-proto-mismatch", "invalid/mesh-key-doc-other-host",
                     "invalid/mesh-endpoint-other-host", "invalid/mesh-malformed"):
            self.assertEqual(VECTORS[name]["error"], "E_MESH_DOC")
        for v in mesh:
            with self.subTest(v["id"]):
                self.assertEqual(canon.check_vector(v), [])


class Text(unittest.TestCase):
    def test_outcome_table_and_sections(self):
        self.assertRegex(SPEC, r"\| `pending` \| 202 \|")
        self.assertIn("### 9.6 Mesh document", SPEC)
        self.assertIn("### 9.7 Bindings", SPEC)
        for code in ("E_JOB_UNKNOWN", "E_MESH_DOC"):
            self.assertRegex(SPEC, rf"\| `{code}` \|")
        self.assertTrue(re.search(r"\| D6[89] \|", SPEC))


if __name__ == "__main__":
    unittest.main()
