# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.1, the verifier libraries' findings on the additions (Python DEF-48 to DEF-51,
JavaScript 46 to 50, Rust RS-38 to RS-41), settled before the tag:

1. Valid mesh vectors carry their outputs, bindings and endpoints, and the reference checks them.
2. 9.6 step 4 compares a key-document member only when the key document is an object and that
   member is a string; anything else is the key document's own failure at step 5 (E_KEY_DOC).
3. A 200 key-document response without a body is E_KEY_DOC at step 1, before the mesh document.
4. A URL is on the host only when it begins https://<host>/. Endpoint templates: every { and }
   belongs to one of the endpoint's placeholders, so a lone } and {} fail. bindings is a URL, not a
   template: its braces are not checked. Unknown endpoints are not checked.
5. poll is https://<DNS name>/...: an empty host, a port or userinfo is E_ENVELOPE. Comparing it
   with the host asked is the client's check, not the envelope check's.
"""

import json
import unittest

from helpers import ROOT, canon
from test_pending_mesh import JOB, MESH, REQ, check, env, key_doc, mesh_doc, pending, resolve

VECTORS = {v["id"]: v for v in canon.load_vectors()}
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
B = f"https://{MESH}"


def with_endpoint(name, value):
    doc = mesh_doc()
    doc["endpoints"] = dict(doc["endpoints"], **{name: value})
    return env(doc)


class Finding1Outputs(unittest.TestCase):
    def test_valid_mesh_vectors_carry_their_outputs(self):
        for name in ("mesh/full", "mesh/required-only", "mesh/extension-members"):
            vec = VECTORS[name]
            doc = json.loads(vec["env"]["mesh"]["https"]["body"])
            with self.subTest(name):
                self.assertEqual(vec["bindings"], doc["bindings"])
                self.assertEqual(vec["endpoints"], {k: v for k, v in doc["endpoints"].items()
                                                    if k in canon.MESH_ENDPOINTS})
        self.assertNotIn("x_graphql", VECTORS["mesh/extension-members"]["endpoints"])

    def test_the_reference_checks_them(self):
        vec = dict(VECTORS["mesh/full"])
        del vec["endpoints"]
        self.assertNotEqual(canon.check_vector(vec), [])
        vec = dict(VECTORS["mesh/full"], bindings=f"{B}/other")
        self.assertNotEqual(canon.check_vector(vec), [])


class Finding2KeyDocumentShape(unittest.TestCase):
    def keys(self, text):
        e = env()
        e["keys"] = {"https": {"status": 200, "body": text}}
        return resolve(e)

    def test_the_key_side_is_compared_only_for_string_members_of_an_object(self):
        doc = key_doc()
        for name, text in [("an array", "[]"), ("a number", "5"), ("a string", '"x"'),
                           ("no proto", json.dumps({k: v for k, v in doc.items() if k != "proto"})),
                           ("a non-string proto", json.dumps(dict(doc, proto=1))),
                           ("no host", json.dumps({k: v for k, v in doc.items() if k != "host"})),
                           ("a non-string host", json.dumps(dict(doc, host=["x"])))]:
            with self.subTest(name):
                self.assertEqual(self.keys(text), "E_KEY_DOC")
        self.assertEqual(self.keys(json.dumps(dict(doc, proto="datumesh/2"))), "E_MESH_DOC")
        self.assertEqual(self.keys(json.dumps(dict(doc, host="other.example.org"))), "E_MESH_DOC")


class Finding3KeyDocumentWithoutBody(unittest.TestCase):
    def test_e_key_doc_before_the_mesh_document(self):
        e = env(mesh_status=404)
        e["keys"] = {"https": {"status": 200}}
        self.assertEqual(resolve(e), "E_KEY_DOC")


class Finding4Urls(unittest.TestCase):
    def test_on_this_host_means_beginning_https_host_slash(self):
        for url in (f"https://{MESH}:443/cell/{{cell}}", f"https://user@{MESH}/cell/{{cell}}",
                    f"https://{MESH}?x=/cell/{{cell}}", f"https://{MESH}", f"https://{MESH}.evil.example/cell/{{cell}}",
                    f"https://{MESH}#/cell/{{cell}}"):
            with self.subTest(url):
                self.assertEqual(resolve(with_endpoint("cell", url)), "E_MESH_DOC")
        self.assertEqual(resolve(env(mesh_doc(bindings=f"https://{MESH}"))), "E_MESH_DOC")
        self.assertEqual(resolve(env(mesh_doc(bindings=f"https://{MESH}/")))["bindings"], f"https://{MESH}/")

    def test_braces_in_templates(self):
        for url in (f"{B}/cell/{{cell}}}}", f"{B}/cell/{{cell}}/{{}}", f"{B}/cell/{{Cell}}", f"{B}/cell/{{cell}}{{cell}}",
                    f"{B}/cell/}}{{cell}}", f"{B}/cell/{{{{cell}}}}", f"{B}/cell/{{cell"):
            with self.subTest(url):
                self.assertEqual(resolve(with_endpoint("cell", url)), "E_MESH_DOC")
        for name in ("find", "verify", "cells"):
            with self.subTest(name):
                self.assertEqual(resolve(with_endpoint(name, f"{B}/{name}/}}")), "E_MESH_DOC")

    def test_bindings_is_a_url_not_a_template(self):
        self.assertEqual(resolve(env(mesh_doc(bindings=f"{B}/b/{{x}}}}")))["bindings"], f"{B}/b/{{x}}}}")

    def test_unknown_endpoints_are_not_checked(self):
        got = resolve(with_endpoint("x_graphql", "not a url {"))
        self.assertNotIn("x_graphql", got["endpoints"])

    def test_vectors(self):
        for name in ("invalid/mesh-endpoint-lone-brace", "invalid/mesh-endpoint-empty-placeholder",
                     "invalid/mesh-endpoint-port", "invalid/mesh-endpoint-userinfo", "invalid/mesh-endpoint-no-path"):
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["error"], "E_MESH_DOC")
                self.assertEqual(canon.check_vector(VECTORS[name]), [])
        for name in ("mesh/bindings-with-braces", "mesh/unknown-endpoint-unchecked"):
            with self.subTest(name):
                self.assertTrue(VECTORS[name]["valid"])
                self.assertEqual(canon.check_vector(VECTORS[name]), [])


class Finding2And3Vectors(unittest.TestCase):
    def test_vectors(self):
        for name, code in [("invalid/mesh-key-doc-not-object", "E_KEY_DOC"), ("invalid/mesh-key-doc-no-proto", "E_KEY_DOC"),
                           ("invalid/mesh-key-doc-no-body", "E_KEY_DOC")]:
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["error"], code)
                self.assertEqual(canon.check_vector(VECTORS[name]), [])


class Finding5Poll(unittest.TestCase):
    def test_poll_names_a_dns_host(self):
        for poll in (f"https:///jobs/{JOB}", f"https://mesh.example:8443/jobs/{JOB}",
                     f"https://user@mesh.example/jobs/{JOB}", f"https://MESH.example/jobs/{JOB}",
                     f"https://localhost/jobs/{JOB}", f"https://192.0.2.1/jobs/{JOB}", f"https://mesh.example?/jobs/{JOB}"):
            with self.subTest(poll):
                self.assertEqual(check(pending(poll=poll), REQ), "E_ENVELOPE")

    def test_the_host_asked_is_the_clients_check(self):
        self.assertEqual(check(pending(poll=f"https://other.example.net/jobs/{JOB}"), REQ), "pending")
        self.assertEqual(check(pending(poll=f"https://mesh.example/a/b/jobs/{JOB}"), REQ), "pending")

    def test_vectors(self):
        for name in ("invalid/envelope-pending-poll-empty-host", "invalid/envelope-pending-poll-port"):
            with self.subTest(name):
                self.assertEqual(VECTORS[name]["error"], "E_ENVELOPE")
                self.assertEqual(canon.check_vector(VECTORS[name]), [])
        self.assertEqual(canon.check_vector(VECTORS["envelope/pending-poll-other-host"]), [])


class Text(unittest.TestCase):
    def test_rules_are_stated(self):
        for phrase in ("begins `https://<host>/`", "a lone `}`", "not a template", "Unknown endpoints are not checked",
                       "the client's HTTP layer", "is not an object", "without a body"):
            with self.subTest(phrase):
                self.assertIn(phrase, SPEC)


if __name__ == "__main__":
    unittest.main()
