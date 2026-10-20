# SPDX-License-Identifier: Apache-2.0
"""Test 4: sign-then-verify holds for every receipt vector, and flipping any
single bit of the receipt or of the signature makes verification fail."""

import unittest

from helpers import canon

RECEIPTS = [v for v in canon.load_vectors() if v["kind"] == "receipt" and v["valid"]]


class Signatures(unittest.TestCase):
    def test_sign_then_verify(self):
        for vec in RECEIPTS:
            with self.subTest(vec["id"]):
                r = canon.parse_json(vec["input"])
                unsigned = {k: v for k, v in r.items() if k != "sig"}
                resigned = canon.sign_receipt(unsigned, bytes.fromhex(vec["keypair"]["seed"]))
                self.assertEqual(resigned["sig"], vec["sig"])  # Ed25519 is deterministic
                canon.verify_receipt(canon.jcs(resigned), vec["keys"])

    def test_every_receipt_bit_flip_fails(self):
        flips = 0
        for vec in RECEIPTS:
            wire = bytearray(canon.jcs(canon.parse_json(vec["input"])))
            canon.verify_receipt(bytes(wire), vec["keys"])
            for i in range(len(wire) * 8):
                wire[i // 8] ^= 1 << (i % 8)
                with self.assertRaises(canon.DatumeshError, msg=f"{vec['id']} bit {i}"):
                    canon.verify_receipt(bytes(wire), vec["keys"])
                wire[i // 8] ^= 1 << (i % 8)
                flips += 1
        self.assertGreater(flips, 50000)

    def test_every_signature_bit_flip_fails(self):
        for vec in RECEIPTS:
            r = canon.parse_json(vec["input"])
            sig = bytearray.fromhex(r["sig"])
            for i in range(512):
                sig[i // 8] ^= 1 << (i % 8)
                bad = dict(r, sig=sig.hex())
                with self.assertRaises(canon.DatumeshError) as cm:
                    canon.verify_receipt(canon.jcs(bad), vec["keys"])
                self.assertEqual(cm.exception.code, "E_SIGNATURE", f"{vec['id']} bit {i}")
                sig[i // 8] ^= 1 << (i % 8)

    def test_receipt_hash_is_hash_of_signed_bytes(self):
        for vec in RECEIPTS:
            r = canon.parse_json(vec["input"])
            self.assertEqual(canon.receipt_hash(r), canon.sha256_hex(canon.receipt_payload(r)))
            self.assertNotIn(b'"sig"', canon.receipt_payload(r))


if __name__ == "__main__":
    unittest.main()
