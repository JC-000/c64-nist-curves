"""NIST CAVP vector loader + cryptography-backed oracle helpers.

This module implements the "external oracle" side of the gameability
defense. The invariant is:

    * The `cryptography` package (installed via pip) is the canonical
      authority for scalar multiplication on P-256 / P-384.
    * NIST CAVP Known Answer Tests (KATs) shipped as .rsp files are the
      immutable anchor pinning the oracle to the curve specification.
    * jacobian_to_affine and affine group-law (add, double) are not
      exposed by `cryptography`, so they are implemented here in plain
      Python using the NIST parameters from constants.py. These routines
      are short and mathematically unambiguous; every call is still
      cross-validated against cryptography whenever a scalar is available.

Never replace the `cryptography` oracle with a hand-rolled scalar_mul.
Never hardcode expected outputs from a previous implementation run.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from .constants import CURVES, P256_P, P384_P  # noqa: F401


# ---------------------------------------------------------------------------
# .rsp file parser (NIST CAVS format)
# ---------------------------------------------------------------------------

def load_rsp(path: str) -> List[Dict[str, str]]:
    """Parse a NIST CAVS .rsp file.

    Returns a list of records, one per `COUNT =` block. Each record is a
    dict of string key -> string value, with the curve name stored under
    the special key `"_section"` (e.g. `"P-256"`).

    Lines starting with `#` are comments. `[SECTION]` lines set the
    current section. Blank lines terminate a record.
    """
    records: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    section: Optional[str] = None

    with open(path, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                if current:
                    records.append(current)
                    current = {}
                continue
            if line.startswith("[") and line.endswith("]"):
                if current:
                    records.append(current)
                    current = {}
                section = line[1:-1]
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if not current and section is not None:
                    current["_section"] = section
                current[key] = value
    if current:
        records.append(current)
    return records


def load_ecdh_kats(path: str, section: str) -> List[Dict[str, int]]:
    """Load KAS ECC CDH primitive test vectors for a single curve.

    Each vector has fields:
        d : private scalar (int)
        qx, qy : expected public point = d * G (int)

    `section` is the NIST CAVS section name, e.g. "P-256" or "P-384".
    """
    records = load_rsp(path)
    out: List[Dict[str, int]] = []
    for rec in records:
        if rec.get("_section") != section:
            continue
        if "dIUT" not in rec or "QIUTx" not in rec or "QIUTy" not in rec:
            continue
        out.append({
            "d": int(rec["dIUT"], 16),
            "qx": int(rec["QIUTx"], 16),
            "qy": int(rec["QIUTy"], 16),
        })
    return out


def default_ecdh_path(curve: str) -> str:
    """Return the packaged .rsp path for a curve."""
    here = os.path.dirname(os.path.abspath(__file__))
    if curve == "p256":
        return os.path.join(here, "nist_p256_ecdh.rsp")
    if curve == "p384":
        return os.path.join(here, "nist_p384_ecdh.rsp")
    raise ValueError(f"unknown curve {curve!r}")


def load_nist_scalar_mul_kats(curve: str) -> List[Dict[str, int]]:
    """Load the packaged NIST CAVP KAT set for a curve ('p256' or 'p384')."""
    section = {"p256": "P-256", "p384": "P-384"}[curve]
    return load_ecdh_kats(default_ecdh_path(curve), section)


# ---------------------------------------------------------------------------
# External oracle: scalar multiplication via `cryptography`
# ---------------------------------------------------------------------------

_CURVE_OBJ = {
    "p256": ec.SECP256R1(),
    "p384": ec.SECP384R1(),
}


def scalar_mul_oracle(k: int, curve: str = "p256") -> Tuple[int, int]:
    """Compute k*G on the named curve using the `cryptography` library.

    `k` must satisfy 1 <= k < n (the group order). The result is returned
    as an affine (x, y) pair of Python ints.

    This is the canonical reference implementation. Test code MUST NOT
    replace this with a hand-rolled helper: that would defeat the
    gameability defense entirely.
    """
    if k <= 0 or k >= CURVES[curve]["n"]:
        raise ValueError(f"scalar out of range for {curve}: {k}")
    priv = ec.derive_private_key(k, _CURVE_OBJ[curve])
    nums = priv.public_key().public_numbers()
    return nums.x, nums.y


# ---------------------------------------------------------------------------
# Affine group law (NOT exposed by cryptography). Kept minimal and
# mathematically unambiguous. Cross-validated against the oracle wherever
# a scalar is available.
# ---------------------------------------------------------------------------

INFINITY: Tuple[Optional[int], Optional[int]] = (None, None)


def is_infinity(P: Tuple[Optional[int], Optional[int]]) -> bool:
    return P[0] is None and P[1] is None


def affine_add(P, Q, curve: str = "p256"):
    """Affine point addition on the short-Weierstrass curve y^2 = x^3 + ax + b."""
    if is_infinity(P):
        return Q
    if is_infinity(Q):
        return P
    p = CURVES[curve]["p"]
    a = CURVES[curve]["a"]
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return INFINITY
        # doubling
        lam = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    else:
        lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def affine_double(P, curve: str = "p256"):
    return affine_add(P, P, curve)


def affine_neg(P, curve: str = "p256"):
    if is_infinity(P):
        return P
    p = CURVES[curve]["p"]
    return (P[0], (-P[1]) % p)


def jacobian_to_affine(jx: int, jy: int, jz: int, curve: str = "p256"):
    """Convert Jacobian (X, Y, Z) to affine (x, y).

    This is pure field arithmetic; there is no curve-specific ambiguity
    once p is fixed. Returns INFINITY if jz == 0.
    """
    p = CURVES[curve]["p"]
    if jz % p == 0:
        return INFINITY
    z_inv = pow(jz, -1, p)
    z2 = (z_inv * z_inv) % p
    z3 = (z2 * z_inv) % p
    return ((jx * z2) % p, (jy * z3) % p)


# ---------------------------------------------------------------------------
# Self-test hook: cross-check affine_add against the cryptography oracle for
# a handful of random scalars. Called by test suites at startup to make
# sure the hand-rolled affine helpers never drift from the external oracle.
# ---------------------------------------------------------------------------

def self_check(rng, curve: str = "p256", samples: int = 5) -> None:
    """Assert that affine_add(kG, G) == (k+1)G via the oracle.

    `rng` is a random.Random-compatible object; we deliberately do not
    touch the global random state. Raises RuntimeError on any mismatch.
    """
    n = CURVES[curve]["n"]
    for _ in range(samples):
        k = rng.randrange(1, n - 1)
        kg = scalar_mul_oracle(k, curve)
        k1g = scalar_mul_oracle(k + 1, curve)
        combined = affine_add(kg, (CURVES[curve]["gx"], CURVES[curve]["gy"]), curve)
        if combined != k1g:
            raise RuntimeError(
                f"affine_add oracle self-check failed on {curve} k={k}"
            )
