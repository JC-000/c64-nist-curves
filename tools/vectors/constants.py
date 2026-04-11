"""NIST P-256 / P-384 curve parameters sourced verbatim from FIPS 186-5.

This is the ONLY place in the test suite where the curve constants
live. Test files must import from here instead of redefining their
own copies -- otherwise an adversarial editor can rewrite both the
test and its "oracle" in one file.

Source:
  NIST FIPS 186-5, "Digital Signature Standard (DSS)", Feb 2023.
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
  Appendix D.1.2.3 (P-256) and D.1.2.4 (P-384).

Short-Weierstrass form: y^2 = x^3 + a*x + b  (mod p), with a = p - 3.

Two naming conventions are exported for historical reasons:

  * P256, N256, A256, B256, GX256, GY256 and CURVE_P256 -- the "short"
    names used by the field-arithmetic test suites.
  * P256_P, P256_N, P256_A, P256_B, P256_GX, P256_GY and the CURVES
    dict -- the "prefixed" names used by the point / bench oracle
    helpers in loader.py.

Both point at the same Python ints; the self-check at the bottom
asserts the generator satisfies the curve equation so that tampering
with either set is caught on import.
"""

# ---- P-256 (secp256r1 / prime256v1) ----
P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A256 = P256 - 3
B256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Prefixed aliases for loader.py / point tests.
P256_P = P256
P256_N = N256
P256_A = A256
P256_B = B256
P256_GX = GX256
P256_GY = GY256

CURVE_P256 = {
    "name": "P-256",
    "p": P256,
    "n": N256,
    "a": A256,
    "b": B256,
    "Gx": GX256,
    "Gy": GY256,
    "coord_bytes": 32,
}

# ---- P-384 (secp384r1) ----
P384 = 2**384 - 2**128 - 2**96 + 2**32 - 1
N384 = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFC7634D81F4372DDF581A0DB248B0A77A"
    "ECEC196ACCC52973",
    16,
)
A384 = P384 - 3
B384 = int(
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6E"
    "FE8141120314088F5013875AC656398D8A2ED19D"
    "2A85C8EDD3EC2AEF",
    16,
)
GX384 = int(
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B62"
    "8BA79B9859F741E082542A385502F25DBF55296C"
    "3A545E3872760AB7",
    16,
)
GY384 = int(
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD"
    "289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D"
    "7A431D7C90EA0E5F",
    16,
)

P384_P = P384
P384_N = N384
P384_A = A384
P384_B = B384
P384_GX = GX384
P384_GY = GY384

CURVE_P384 = {
    "name": "P-384",
    "p": P384,
    "n": N384,
    "a": A384,
    "b": B384,
    "Gx": GX384,
    "Gy": GY384,
    "coord_bytes": 48,
}

# Loader-facing dict indexed by short curve id. The "gx"/"gy"/"byte_len"
# keys match loader.py's original call sites.
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


# ---- Sanity self-check (cheap; runs on import) --------------------
def _verify_generator_on_curve(curve):
    """Assert Gy^2 == Gx^3 + a*Gx + b (mod p). If this ever fails,
    the constants above have been tampered with and every test that
    depends on this module should refuse to run."""
    p = curve["p"]
    lhs = (curve["Gy"] * curve["Gy"]) % p
    rhs = (pow(curve["Gx"], 3, p) + curve["a"] * curve["Gx"] + curve["b"]) % p
    if lhs != rhs:
        raise RuntimeError(
            f"{curve['name']} generator fails curve equation -- "
            f"constants.py has been tampered with."
        )


_verify_generator_on_curve(CURVE_P256)
_verify_generator_on_curve(CURVE_P384)
