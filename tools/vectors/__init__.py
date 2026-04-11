"""NIST CAVP vector loader + cryptography-backed oracle helpers.

See `loader.py` for the oracle invariant and usage. See `constants.py`
for the P-256 / P-384 curve parameters. See `README.md` for the refresh
procedure and threat model.
"""

from .constants import (
    CURVES,
    P256_A, P256_B, P256_GX, P256_GY, P256_N, P256_P,
    P384_A, P384_B, P384_GX, P384_GY, P384_N, P384_P,
)
from .loader import (
    INFINITY,
    affine_add,
    affine_double,
    affine_neg,
    is_infinity,
    jacobian_to_affine,
    load_ecdh_kats,
    load_nist_scalar_mul_kats,
    load_rsp,
    scalar_mul_oracle,
    self_check,
)

__all__ = [
    "CURVES",
    "INFINITY",
    "P256_A", "P256_B", "P256_GX", "P256_GY", "P256_N", "P256_P",
    "P384_A", "P384_B", "P384_GX", "P384_GY", "P384_N", "P384_P",
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
