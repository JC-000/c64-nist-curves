"""Shared oracle constants, NIST KAT loaders, and affine helpers for
the c64-nist-curves test suite.

Two test surfaces share this package:

  * Field-arithmetic tests (test_fp256.py, test_fp384.py) import the
    short curve-constant names (`P256`, `GX256`, ...), the curve-params
    dicts (`CURVE_P256`, `CURVE_P384`), and the field-KAT `load_kat` /
    `KAT` parser for the `nist_p{256,384}_kat.rsp` files.
  * Point / bench tests (test_points256.py, test_points384.py,
    bench_p256.py, bench_p384.py) import the prefixed names
    (`P256_P`, `P384_GX`, ...), the `CURVES` dict, the
    `cryptography`-backed `scalar_mul_oracle`, the affine helpers
    (`affine_add`, `affine_double`, `affine_neg`, `jacobian_to_affine`,
    `is_infinity`, `INFINITY`), the NIST-CAVS loaders
    (`load_rsp`, `load_ecdh_kats`, `load_nist_scalar_mul_kats`), and
    the startup `self_check`.

Both sets of constants alias the same Python ints. See constants.py
for the FIPS 186-5 sourcing and the generator self-check that runs on
import, and loader.py for the external-oracle invariant.

Do not add self-written scalar-mul helpers here. The `cryptography`
library is the canonical oracle.
"""

from .constants import (
    CURVES,
    CURVE_P256, CURVE_P384,
    P256, N256, A256, B256, GX256, GY256,
    P384, N384, A384, B384, GX384, GY384,
    P256_P, P256_N, P256_A, P256_B, P256_GX, P256_GY,
    P384_P, P384_N, P384_A, P384_B, P384_GX, P384_GY,
)
from .loader import (
    INFINITY,
    KAT,
    affine_add,
    affine_double,
    affine_neg,
    is_infinity,
    jacobian_to_affine,
    load_ecdh_kats,
    load_kat,
    load_nist_scalar_mul_kats,
    load_rsp,
    scalar_mul_oracle,
    self_check,
)

__all__ = [
    # short names (field tests)
    "P256", "N256", "A256", "B256", "GX256", "GY256", "CURVE_P256",
    "P384", "N384", "A384", "B384", "GX384", "GY384", "CURVE_P384",
    "load_kat", "KAT",
    # prefixed names (point / bench tests)
    "CURVES",
    "INFINITY",
    "P256_P", "P256_N", "P256_A", "P256_B", "P256_GX", "P256_GY",
    "P384_P", "P384_N", "P384_A", "P384_B", "P384_GX", "P384_GY",
    "affine_add",
    "affine_double",
    "affine_neg",
    "is_infinity",
    "jacobian_to_affine",
    "load_ecdh_kats",
    "load_nist_scalar_mul_kats",
    "load_rsp",
    "scalar_mul_oracle",
    "self_check",
]
