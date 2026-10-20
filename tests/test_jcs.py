# SPDX-License-Identifier: Apache-2.0
"""The JCS implementation in tools/canon.py against the examples in RFC 8785."""

import struct
import unittest

from helpers import canon


def jcs_text(json_text):
    return canon.jcs(canon.parse_json(json_text)).decode("utf-8")


class RFC8785Examples(unittest.TestCase):
    def test_section_3_2_2_main_example(self):
        source = (
            '{\n  "numbers": [333333333.33333329, 1E30, 4.50,\n'
            "              2e-3, 0.000000000000000000000000001],\n"
            '  "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",\n'
            '  "literals": [null, true, false]\n}'
        )
        expected = (
            '{"literals":[null,true,false],'
            '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
            '"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
        )
        self.assertEqual(jcs_text(source), expected)

    def test_section_3_2_3_sorting(self):
        source = (
            '{"\\u20ac": "Euro Sign", "\\r": "Carriage Return",'
            ' "\\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One",'
            ' "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control",'
            ' "\\u00f6": "Latin Small Letter O With Diaeresis"}'
        )
        expected = (
            '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
            '"\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign",'
            '"\U0001f600":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}'
        )
        self.assertEqual(jcs_text(source), expected)

    # RFC 8785 Appendix B: IEEE 754 bit patterns and their JCS serialisations.
    NUMBERS = [
        ("0000000000000000", "0"),
        ("8000000000000000", "0"),
        ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ]

    def test_appendix_b_numbers(self):
        for bits, expected in self.NUMBERS:
            with self.subTest(bits=bits):
                value = struct.unpack(">d", bytes.fromhex(bits))[0]
                self.assertEqual(canon.jcs(value).decode(), expected)
                # And through the parser, from the shortest decimal text.
                self.assertEqual(jcs_text(repr(value)), expected)

    def test_nan_and_infinity_rejected(self):
        for bits in ("7fffffffffffffff", "7ff0000000000000", "fff0000000000000"):
            value = struct.unpack(">d", bytes.fromhex(bits))[0]
            with self.assertRaises(canon.DatumeshError) as cm:
                canon.jcs(value)
            self.assertEqual(cm.exception.code, "E_PARSE_JSON")


class StrictParsing(unittest.TestCase):
    def assertParseError(self, data, code):
        with self.assertRaises(canon.DatumeshError) as cm:
            canon.parse_json(data)
        self.assertEqual(cm.exception.code, code)

    def test_rejections(self):
        self.assertParseError('{"a":1,"a":2}', "E_PARSE_DUPLICATE_KEY")
        self.assertParseError('{"a":1,"\\u0061":2}', "E_PARSE_DUPLICATE_KEY")
        self.assertParseError('"\\ud800"', "E_PARSE_JSON")
        self.assertParseError("NaN", "E_PARSE_JSON")
        self.assertParseError("1e400", "E_PARSE_JSON")
        self.assertParseError(b"\xef\xbb\xbf{}", "E_PARSE_JSON")
        self.assertParseError(b'"\xff"', "E_PARSE_JSON")
        self.assertParseError('"tab\there"', "E_PARSE_JSON")
        self.assertParseError("{} {}", "E_PARSE_JSON")

    def test_escapes_and_literals(self):
        self.assertEqual(jcs_text('"\\u001f\\u007f\\u2028"'), '"\\u001f\x7f\u2028"')
        self.assertEqual(jcs_text('"\\b\\f\\n\\r\\t"'), '"\\b\\f\\n\\r\\t"')
        self.assertEqual(jcs_text(' [ 1 , { "b" : [] , "a" : {} } ] '), '[1,{"a":{},"b":[]}]')


if __name__ == "__main__":
    unittest.main()
