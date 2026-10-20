# SPDX-License-Identifier: Apache-2.0
"""Test 3: canonical bytes ignore key order, whitespace and escaping, and any
change of value changes them. Also: non-canonical lexical forms are rejected,
never normalised, and the URI mapping round-trips.

DATUMESH_FUZZ_N sets the number of cases (default 100000).
"""

import json
import os
import random
import unicodedata
import unittest

from helpers import canon

N = int(os.environ.get("DATUMESH_FUZZ_N", "100000"))
SEED = int(os.environ.get("DATUMESH_FUZZ_SEED", "20261020"))

# Code points to draw string characters from: a mix of ASCII, Latin, combining
# marks (so NFC matters), CJK, RTL, astral emoji, ZWJ, and the URI-reserved set.
POOLS = [
    [chr(c) for c in range(0x20, 0x7F)],
    [chr(c) for c in range(0xA0, 0x250)],
    [chr(c) for c in range(0x300, 0x370)],
    [chr(c) for c in range(0x4E00, 0x4E80)],
    [chr(c) for c in range(0x5D0, 0x5EB)] + [chr(c) for c in range(0x620, 0x64B)],
    [chr(c) for c in range(0x1F600, 0x1F650)] + ["‍", "️"],
    list("*&=+%/?#:~ \"\\"),
]


def random_text(rng, max_len=12):
    raw = "".join(rng.choice(rng.choice(POOLS)) for _ in range(rng.randint(0, max_len)))
    text = unicodedata.normalize("NFC", raw)
    while len(text.encode()) > 1024:
        text = text[:-1]
    return text


def random_name(rng):
    words = rng.randint(1, 3)
    return "_".join(
        rng.choice("abcdefghijklmnopqrstuvwxyz") + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(0, 6)))
        for _ in range(words)
    )


def random_number(rng):
    whole = str(rng.choice([0, rng.randint(1, 9), rng.randint(1, 10**6), rng.randint(1, 10**40)]))
    frac = "".join(rng.choice("0123456789") for _ in range(rng.randint(0, 12))).rstrip("0")
    text = whole + ("." + frac if frac else "")
    if text != "0" and rng.random() < 0.4:
        text = "-" + text
    return text


def random_date(rng):
    ordinal = rng.randint(1, 3652059)  # 0001-01-01 .. 9999-12-31
    import datetime

    return datetime.date.fromordinal(ordinal).isoformat()


def random_instant(rng):
    return (
        f"{random_date(rng)}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:"
        f"{rng.randint(0, 59):02d}.{rng.randint(0, 999999):06d}Z"
    )


MEDIA_TYPES = ("text/plain", "text/csv", "application/json", "application/ld+json", "image/png",
               "application/vnd.ms-excel", "application/octet-stream")


def random_blob(rng):
    digest = "".join(rng.choice("0123456789abcdef") for _ in range(64))
    return f"{digest}:{rng.choice([0, rng.randint(1, 10**6), rng.randint(1, 2**53 - 1)])}:{rng.choice(MEDIA_TYPES)}"


def random_scalar(rng, type_=None):
    type_ = type_ or rng.choice(canon.TYPES)
    value = {
        "blob": lambda: random_blob(rng),
        "boolean": lambda: rng.random() < 0.5,
        "date": lambda: random_date(rng),
        "instant": lambda: random_instant(rng),
        "number": lambda: random_number(rng),
        "string": lambda: random_text(rng),
    }[type_]()
    return {"type": type_, "value": value}


def random_cell(rng):
    labels = [random_name(rng).replace("_", "-") for _ in range(rng.randint(2, 4))]
    ns = ".".join(labels) + "".join("/" + random_name(rng) for _ in range(rng.randint(0, 2)))
    args = {}
    for _ in range(rng.randint(0, 8)):
        args[random_name(rng)] = random_scalar(rng)
    args = {k: v for k, v in args.items() if k != "asof" and not k.startswith("dm_")}
    if args and rng.random() < 0.2:
        args[rng.choice(list(args))] = canon.SLICE
    return {
        "args": args,
        "fn": random_name(rng),
        "fn_hash": "".join(rng.choice("0123456789abcdef") for _ in range(64)),
        "ns": ns,
    }


def shuffled(rng, value):
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {k: shuffled(rng, value[k]) for k in keys}
    return value


def random_serialisation(rng, value):
    """The same JSON value as text, with random member order, whitespace and escaping."""
    indent = rng.choice([None, None, 0, 1, 4, "\t"])
    separators = rng.choice([(",", ":"), (", ", ": "), (" ,", " : "), (",\n", ":\t")])
    text = json.dumps(shuffled(rng, value), ensure_ascii=rng.random() < 0.5, indent=indent, separators=separators)
    if rng.random() < 0.3:
        text = rng.choice([" ", "\n", "\t", "\r\n"]) + text + rng.choice([" ", "\n", ""])
    return text


def mutate(rng, cell):
    """Change exactly one value, keeping it valid. Returns a new cell."""
    other = json.loads(json.dumps(cell))
    bound = [k for k, v in other["args"].items() if v != canon.SLICE]
    if not bound:
        other["fn_hash"] = format((int(other["fn_hash"], 16) + 1) % 16**64, "064x")
        return other
    name = rng.choice(bound)
    old = other["args"][name]
    while True:
        new = random_scalar(rng, old["type"])
        if new != old:
            other["args"][name] = new
            return other


class Fuzz(unittest.TestCase):
    def test_canonical_bytes_are_order_whitespace_and_escape_invariant(self):
        rng = random.Random(SEED)
        seen = {}
        for _ in range(N):
            cell = random_cell(rng)
            canon.check_cell(cell)
            expected = canon.jcs(cell)
            for _ in range(2):
                parsed = canon.parse_json(random_serialisation(rng, cell))
                canon.check_cell(parsed)
                self.assertEqual(canon.jcs(parsed), expected)
            other = mutate(rng, cell)
            canon.check_cell(other)
            self.assertNotEqual(canon.jcs(other), expected)
            # No two distinct objects share canonical bytes (or hashes).
            digest = canon.sha256_hex(expected)
            if digest in seen:
                self.assertEqual(seen[digest], cell)
            seen[digest] = cell

    def test_uri_round_trip(self):
        rng = random.Random(SEED + 1)
        for _ in range(N // 4):
            cell = random_cell(rng)
            ref = {"args": cell["args"], "fn": cell["fn"], "ns": cell["ns"]}
            if rng.random() < 0.5:
                ref["asof"] = random_instant(rng)
            signature = {
                "args": {k: {"type": rng.choice(canon.TYPES) if v == canon.SLICE else v["type"], "valid": False}
                         for k, v in ref["args"].items()},
                "returns": "number",
            }
            uri = canon.format_uri(ref)
            self.assertEqual(canon.parse_uri(uri, signature), ref)
            self.assertEqual(canon.format_uri(canon.parse_uri(uri, signature)), uri)

    def test_non_canonical_forms_are_rejected_not_normalised(self):
        rng = random.Random(SEED + 2)
        variants = {
            "number": [lambda t: t + ("0" if "." in t else ".0"), lambda t: "0" + t.lstrip("-"),
                       lambda t: "+" + t.lstrip("-"), lambda t: t + "e0", lambda t: " " + t],
            "date": [lambda t: t.replace("-", "/"), lambda t: t + "T00:00:00Z", lambda t: t[2:]],
            "instant": [lambda t: t[:-4] + "Z", lambda t: t[:-1] + "+00:00", lambda t: t.lower(),
                        lambda t: t[:-1] + "0Z", lambda t: t.replace("T", " ")],
            "blob": [lambda t: t.upper(), lambda t: t.replace(":", ":0", 1), lambda t: t + ";q=1",
                     lambda t: t.replace(":", " :", 1)],
        }
        for _ in range(N // 10):
            type_ = rng.choice(list(variants))
            good = random_scalar(rng, type_)
            bad = dict(good, value=rng.choice(variants[type_])(good["value"]))
            with self.assertRaises(canon.DatumeshError, msg=bad):
                canon.check_scalar(bad, "$")
        # A string that changes under NFC is rejected.
        rejected = 0
        for _ in range(N // 10):
            text = random_text(rng, 20)
            nfd = unicodedata.normalize("NFD", text)
            if nfd != text:
                with self.assertRaises(canon.DatumeshError):
                    canon.check_text(nfd, "$", "string")
                rejected += 1
        self.assertGreater(rejected, 100)


if __name__ == "__main__":
    unittest.main()
