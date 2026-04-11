"""NIST P-256 / P-384 curve parameters (FIPS 186-5 / SEC 2).

All values are Python ints. Field elements in the C64 implementation are
little-endian, but the NIST constants themselves are curve-level invariants
with no endianness -- endianness is a memory-layout concern handled by
the test code, not here.

This module is intentionally small and self-contained: the oracle helpers
in loader.py may rely on these constants, but no test should ever *trust*
a hand-rolled implementation built on top of them as the source of truth.
The external `cryptography` library is the canonical oracle for scalar
multiplication; these constants exist so that jacobian_to_affine and the
unambiguous group-law math (which `cryptography` does not expose) can be
computed in plain Python with zero ambiguity.
"""

# P-256 (secp256r1) -- FIPS 186-5, SEC 2
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3  # a = -3 mod p
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# P-384 (secp384r1) -- FIPS 186-5, SEC 2
P384_P = 2**384 - 2**128 - 2**96 + 2**32 - 1
P384_A = P384_P - 3
P384_B = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
P384_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
P384_GX = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
P384_GY = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F


CURVES = {
    "p256": {
        "p": P256_P, "a": P256_A, "b": P256_B, "n": P256_N,
        "gx": P256_GX, "gy": P256_GY, "byte_len": 32,
    },
    "p384": {
        "p": P384_P, "a": P384_A, "b": P384_B, "n": P384_N,
        "gx": P384_GX, "gy": P384_GY, "byte_len": 48,
    },
}
