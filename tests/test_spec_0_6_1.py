# SPDX-License-Identifier: Apache-2.0
"""spec-0.6.1 (CONTRACT-build2-spec-0.6.1.md S1-S3), tests first:

S1 DNS names as namespace segments after the host (a label only, no authority); S2 the `test_case`
convention; S3 `publisher` in describe.

(a) every new vector is on disk as crosscheck/generate_061.py builds it, and the spec-0.6.0 vectors are
    untouched (read from git at the spec-0.6.0 tag; this needs git and the full history);
(b) the reference tools reproduce every new vector's expected result (the vectors are written first:
    these fail until the tools of spec-0.6.1 are written);
(c) SPEC.md states each rule;
(d) the schemas know the new member and the new segments.
"""

import json
import re
import shutil
import subprocess
import sys
import unittest

import jsonschema
import referencing

from helpers import ROOT, canon

sys.path.insert(0, str(ROOT / "crosscheck"))
import generate_061  # noqa: E402  (builds the vectors in memory)

SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
FLAT = re.sub(r"\s+", " ", SPEC)
NEW = {v["id"]: v for v in generate_061.VECTORS}
ON_DISK = {v["id"]: {k: x for k, x in v.items() if k != "_file"} for v in canon.load_vectors() if v["id"] in NEW}
OLD_COMMIT = "941d9b5"  # tagged spec-0.6.0


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def run(vec):
    try:
        return canon.check_vector(vec)
    except Exception as e:
        return [f"{type(e).__name__}: {e}"]


class VectorFiles(unittest.TestCase):
    def test_every_new_vector_is_on_disk_unchanged(self):
        self.assertEqual(set(ON_DISK), set(NEW))
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertEqual(ON_DISK[id_], vec)

    def test_counts(self):
        self.assertEqual(len(NEW), 142)
        for kind in ("define", "cell", "uri"):  # every row of the names table, accepted and refused
            self.assertGreaterEqual(sum(v["kind"] == kind and v["valid"] for v in NEW.values()), 7)
            self.assertGreaterEqual(sum(v["kind"] == kind and not v["valid"] for v in NEW.values()), 15)
        self.assertGreaterEqual(sum(v["kind"] == "formula" for v in NEW.values()), 10)
        self.assertEqual(sum(v["kind"] == "formula-eval" for v in NEW.values()), 3)
        self.assertGreaterEqual(sum(v["kind"] == "describe" and v["valid"] for v in NEW.values()), 8)

    def test_table_codes(self):
        """The contract's table: each refused row has E_CANON_NAME in every place a name is read."""
        for slug in ("uppercase", "trailing-dot", "underscore", "empty-label", "leading-hyphen", "all-digit-last-label",
                     "last-segment"):
            for kind in ("define", "cell", "uri"):
                self.assertEqual(NEW[f"invalid/{kind}-dns-segment-{slug}"]["error"], "E_CANON_NAME", (kind, slug))
        for slug in ("relay-ecb", "hyphen", "punycode", "three-labels"):
            for kind in ("define", "cell", "uri"):
                self.assertTrue(NEW[f"{kind}/dns-segment-{slug}"]["valid"], (kind, slug))
        self.assertEqual(NEW["invalid/define-dns-segment-too-long"]["error"], "E_CANON_LIMIT")
        self.assertEqual(NEW["invalid/define-dns-segment-name-65"]["error"], "E_CANON_LIMIT")
        self.assertEqual(NEW["invalid/class-dns-segment-method-name"]["error"], "E_CANON_NAME")
        self.assertEqual(NEW["invalid/define-dns-segment-invalid-segment-reads-unrooted"]["error"], "E_UNROOTED_INPUT")


@unittest.skipUnless(shutil.which("git"), "git is needed to read the spec-0.6.0 files")
class Migration061(unittest.TestCase):
    """No spec-0.6.0 vector changes: vectors/ only gains files, and they all still pass."""

    @classmethod
    def setUpClass(cls):
        try:
            git("cat-file", "-e", f"{OLD_COMMIT}^{{commit}}")
        except subprocess.CalledProcessError:
            raise AssertionError(f"commit {OLD_COMMIT} (spec-0.6.0) is not in this clone; fetch the full history")
        names = git("ls-tree", "-r", "--name-only", OLD_COMMIT, "--", "vectors", "examples").decode().split("\n")
        cls.old = {n: git("show", f"{OLD_COMMIT}:{n}") for n in names if n.endswith(".json")}

    def test_every_file_is_byte_identical_and_still_passes(self):
        self.assertEqual(sum(p.startswith("vectors/") for p in self.old), 1569)
        for path, data in self.old.items():
            with self.subTest(path):
                new = ROOT / path
                self.assertTrue(new.exists(), "a spec-0.6.0 file was removed or moved")
                self.assertEqual(new.read_bytes(), data)
                if path.startswith("vectors/"):
                    self.assertEqual(canon.check_vector(json.loads(data)), [])

    def test_the_new_files_are_all_the_generator_wrote(self):
        now = {str(p.relative_to(ROOT)) for p in (ROOT / "vectors").rglob("*.json")}
        added = now - set(self.old)
        self.assertEqual(added, {f"vectors/{i}.json" for i in NEW})


class ReferenceTools(unittest.TestCase):
    """(b): fails until tools/canon.py and tools/formula.py implement spec-0.6.1."""

    def test_every_new_vector(self):
        for id_, vec in NEW.items():
            with self.subTest(id_):
                self.assertEqual(run(vec), [])


class SpecText(unittest.TestCase):
    def test_status_line_names_this_revision(self):
        self.assertRegex(SPEC, r"(?m)^Status: draft, revision `spec-0\.6\.1`")
        self.assertRegex(SPEC, r"(?m)^### spec-0\.6\.1\s*$")
        self.assertIn("revision `spec-0.6.1`", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_s1_dns_segments(self):
        a = SPEC.index("### 2.3")
        section = SPEC[a:SPEC.index("### 2.4")]
        flat = re.sub(r"\s+", " ", section)
        self.assertIn('namespace     = dns-name *( "/" segment )', section)
        self.assertIn("segment       = name / dns-name", section)
        self.assertIn("A DNS name in a later segment is a label only", flat)
        self.assertIn("It gives that domain no authority and proves nothing about it", flat)
        self.assertIn("The host alone, the first segment, decides", flat)
        for word in ("keys", "rooted", "unrooted", "publisher", "never fetches anything"):
            self.assertIn(word, flat)
        self.assertIn("the 64 applies to `name` segments only", flat)
        self.assertIn("253", flat)
        self.assertIn("512", flat)
        self.assertRegex(flat, r"last segment of a function name[^.]*class name[^.]*method name")
        self.assertIn("`example.org/x/foo.invalid/f` is rooted", flat)
        self.assertRegex(flat, r"Libraries before their `spec-0\.6\.1` releases refuse it")
        appendix = SPEC[SPEC.index("## Appendix A"):]
        self.assertRegex(appendix, r"(?m)^segment\s*= name / dns-name")
        self.assertRegex(appendix, r'(?m)^qualified-name = dns-name \*\( "/" segment \) "/" name')

    def test_s1_formula_rule(self):
        self.assertIn("after a `/`, a run of letters, digits, `_`, `.` and `-` that contains `.` or `-` is a DNS segment "
                      "only when a `/` follows it", FLAT)
        self.assertIn("the last segment is a name", FLAT)
        self.assertIn(".status()", FLAT)

    def test_s2_test_case(self):
        self.assertRegex(SPEC, r"(?m)^### 7\.3 Test cells")
        self.assertIn("<host>/test_case(function_hash: string, case: string) -> boolean", FLAT)
        self.assertIn("`datumesh.com/test_case`", FLAT)
        self.assertIn("`mesh-test.datumesh.com/test_case`", FLAT)
        self.assertIn("first 16 lowercase hex digits of the SHA-256 of the JCS", FLAT)
        for member in ("`call`", "`asof`", "`inputs`", "`expect`"):
            self.assertIn(member, FLAT)
        self.assertIn("so its trust is `primary`", FLAT)
        self.assertIn("Anyone may publish `<their host>/test_case` for any function hash", FLAT)
        self.assertIn("open counterexample", FLAT)
        self.assertRegex(FLAT, r"`tests\.counterexamples` for a function .{0,160}`false` `test_case` cells")

    def test_s3_publisher(self):
        describe = SPEC[SPEC.index("### 16.8"):SPEC.index("### 16.9")]
        flat = re.sub(r"\s+", " ", describe)
        self.assertIn("`publisher`** (since `spec-0.6.1`", flat)
        self.assertIn("a domain inside a name is never the publisher", flat)
        self.assertIn("additive", flat)
        mesh = SPEC[SPEC.index("### 9.6"):SPEC.index("### 9.7")]
        self.assertRegex(mesh, r"`publisher`[^|]*`source`")

    def test_section_14_and_decisions(self):
        entry = SPEC[SPEC.index("### spec-0.6.1"):SPEC.index("### spec-0.6.0")]
        for word in ("dns names", "test_case", "publisher", "core < 0.3.10", "formula < 0.5.1", "142"):
            self.assertIn(word, entry.lower() if word.islower() else entry, word)
        for d in ("D106", "D107", "D108", "D109", "D110"):
            self.assertRegex(SPEC, rf"(?m)^\| {d} \|")


def validator(name):
    resources = []
    for path in sorted((ROOT / "schemas").glob("*.json")):
        schema = json.loads(path.read_text())
        resources.append((schema["$id"], referencing.Resource.from_contents(schema)))
    registry = referencing.Registry().with_resources(resources)
    schema = registry.contents(f"https://datumesh.com/schemas/1/{name}.schema.json")
    return jsonschema.Draft202012Validator(schema, registry=registry)


class Schemas(unittest.TestCase):
    def test_describe_publisher(self):
        for id_, name in (("describe/function-publisher", "describe-function"),
                          ("describe/function-relay-publisher-source", "describe-function"),
                          ("describe/class-publisher", "describe-class"),
                          ("describe/function-without-publisher", "describe-function")):
            with self.subTest(id_):
                doc = json.loads(NEW[id_]["input"])
                self.assertEqual([], list(validator(name).iter_errors(doc)))
        self.assertTrue(list(validator("describe-function").iter_errors(
            json.loads(NEW["invalid/describe-publisher-namespace"]["input"]))))  # a path is not a DNS name

    def test_names(self):
        defs = json.loads((ROOT / "schemas" / "defs.schema.json").read_text())["$defs"]
        ns = re.compile(defs["namespace"]["pattern"])
        fn = re.compile(defs["functionName"]["pattern"])
        for slug, full, error, _ in generate_061.NAMES:
            if error is not None or len(full) > 512:
                continue
            with self.subTest(full):
                self.assertTrue(fn.match(full), "a valid name matches the schema pattern")
                self.assertTrue(ns.match(full.rpartition("/")[0]))
        for slug in ("uppercase", "trailing-dot", "underscore", "empty-label", "leading-hyphen", "last-segment",
                     "hyphen-without-dot"):
            full = {n[0]: n[1] for n in generate_061.NAMES}[slug]
            with self.subTest(slug):
                self.assertFalse(fn.match(full), "a refused name does not match the schema pattern")


if __name__ == "__main__":
    unittest.main()
