# SPDX-License-Identifier: Apache-2.0
"""Hand-built Ed25519 signatures for the strictness vectors (SPEC.md 10.1 step 6).

Each signature satisfies the permissive (cofactored, lenient-decoding) verification equation
but breaks one strictness rule, except mixed_order_key, which a strict verifier must accept.
Pure-Python curve arithmetic; used only by gen_vectors.py to build the vectors.
"""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


def _x(y, sign):
    xx = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * SQRT_M1 % P
    if x & 1 != sign:
        x = -x % P
    return x


_BY = 4 * pow(5, -1, P) % P
BASE = (_x(_BY, 0), _BY, 1, _x(_BY, 0) * _BY % P)


def add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa, pb = (y1 - x1) * (y2 - x2) % P, (y1 + x1) * (y2 + x2) % P
    c, d = 2 * t1 * t2 * D % P, 2 * z1 * z2 % P
    e, f, g, h = pb - pa, d - c, d + c, pb + pa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(k, pt):
    out = IDENTITY
    while k:
        if k & 1:
            out = add(out, pt)
        pt = add(pt, pt)
        k >>= 1
    return out


def encode(pt):
    x, y, z, _ = pt
    zi = pow(z, -1, P)
    x, y = x * zi % P, y * zi % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def decode(data):
    v = int.from_bytes(data, "little")
    y, sign = v & (2**255 - 1), v >> 255
    x = _x(y % P, sign)
    return (x, y % P, 1, x * y % P)


def _k(r, a, msg):
    return int.from_bytes(hashlib.sha512(r + a + msg).digest(), "little") % L


def _s(n):
    return n.to_bytes(32, "little")


# An order-8 point (a published small-order encoding) and a fixed secret scalar.
TORSION = decode(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))
SECRET = int.from_bytes(hashlib.sha256(b"datumesh ed25519 edge secret").digest(), "little") % L
PUBLIC = encode(mul(SECRET, BASE))


def honest(msg, secret=SECRET, public=PUBLIC, r=7):
    rb = encode(mul(r, BASE))
    return rb + _s((r + _k(rb, public, msg) * secret) % L)


def s_not_reduced(msg):
    """S + L: the equation still holds mod L, but S >= L."""
    sig = honest(msg)
    return PUBLIC, sig[:32] + _s(int.from_bytes(sig[32:], "little") + L)


def small_order_key(msg):
    """A = identity, R = identity, S = 0: [0]B - [k]A = R for every k."""
    ident = encode(IDENTITY)
    return ident, ident + _s(0)


def _r_with_identity_value(r_bytes, msg):
    """R given as bytes that decode to the identity; S = k*a makes [S]B - [k]A the identity."""
    return PUBLIC, r_bytes + _s(_k(r_bytes, PUBLIC, msg) * SECRET % L)


def small_order_r(msg):
    return _r_with_identity_value(encode(IDENTITY), msg)


def non_canonical_r(msg):
    """The identity with y written as p + 1."""
    return _r_with_identity_value((P + 1).to_bytes(32, "little"), msg)


def negative_zero_r(msg):
    """The identity with the sign bit set although x = 0."""
    return _r_with_identity_value((1 | 1 << 255).to_bytes(32, "little"), msg)


def mixed_order_key(msg):
    """A = aB + T (T of order 8), signed honestly with an r chosen so that 8 divides k: then
    [S]B - [k]A = rB - kT = R exactly. Not small order, so a strict verifier accepts it."""
    public = encode(add(mul(SECRET, BASE), TORSION))
    for r in range(1, 10000):
        rb = encode(mul(r, BASE))
        k = _k(rb, public, msg)
        if k % 8 == 0:
            return public, rb + _s((r + k * SECRET) % L)
    raise AssertionError("no r found")
