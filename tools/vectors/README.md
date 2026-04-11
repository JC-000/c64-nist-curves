# tools/vectors — NIST CAVP KATs + cryptography oracle

## Purpose

This directory holds the **external oracle** used by the field and point
tests in `tools/test_fp*.py`, `tools/test_points*.py`, and the benchmark
harnesses `tools/bench_p*.py`. It exists to make those tests **un-gameable**:
an adversary who edits both the Python test file and the C64 assembly in
the same commit must still produce output that matches an external,
independently-specified reference.

## The oracle invariant

Three layers, from most authoritative to least:

1. **NIST CAVP Known Answer Tests** (`nist_p256_ecdh.rsp`,
   `nist_p384_ecdh.rsp`) — immutable `.rsp` files shipped with this
   repository. Each entry pins a specific `(scalar, scalar * G)` pair to
   the P-256 / P-384 specification. These files are checked into git and
   are the ultimate anchor.

2. **The `cryptography` Python package** — used via
   `scalar_mul_oracle(k, curve)` in `loader.py`. This wraps
   `ec.derive_private_key(k, SECP256R1())` and is the canonical reference
   for scalar multiplication across the 2^256 scalar space. At test
   startup we cross-validate **every** NIST KAT against the library, so
   a compromised `cryptography` install would be caught by the KATs
   themselves.

3. **Hand-rolled affine group law** in `loader.py::affine_add` — used only
   for point addition / point doubling reference values, because
   `cryptography` does not expose affine add. Every such helper is
   self-checked at test startup (`self_check()` verifies
   `affine_add(kG, G) == (k+1)G` against the oracle).

**Hard rules — do not cross these:**

* Never replace `scalar_mul_oracle` with a hand-rolled scalar multiplier
  living in this repository. The whole point of the oracle is that it is
  external to the code under test.
* Never hardcode expected outputs from a previous C64 implementation run.
  Every expected value in a test must come from the oracle or a NIST KAT.
* Never trim or edit `nist_p*_ecdh.rsp`. If you need to refresh them,
  re-download the NIST source (see below) and commit the fresh copy.

## NIST vector source

The KAT files here are the `[P-256]` and `[P-384]` sections extracted
from:

* **Filename:** `KAS_ECC_CDH_PrimitiveTest.txt`
* **Source:** NIST CAVP Component Testing — ECC CDH Primitive (SP 800-56A
  §5.7.1.2)
* **Download:**
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip
* **Landing page:**
  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing
* **CAVS version:** 14.1 (generated 2012-11-19)

Each vector has the form:

    COUNT = N
    QCAVSx = ...   # peer public X (unused here)
    QCAVSy = ...   # peer public Y (unused here)
    dIUT   = ...   # private scalar d (hex)
    QIUTx  = ...   # expected d * G, X coordinate
    QIUTy  = ...   # expected d * G, Y coordinate
    ZIUT   = ...   # shared secret (unused here)

For scalar_mul validation we use `(dIUT, QIUTx, QIUTy)`: compute
`dIUT * G` on the C64, convert to affine, and compare.

There are **25 vectors per curve**.

## Refresh procedure

1. Download and unzip `ecccdhtestvectors.zip` from the URL above.
2. Copy the file header plus the `[P-256]` section into
   `nist_p256_ecdh.rsp`, and similarly `[P-384]` into
   `nist_p384_ecdh.rsp`. The existing files were produced by
   `sed -n '1,4p; 412,614p'` (for P-256) against the 2012 master file.
3. Run `python3 tools/test_points256.py` and `tools/test_points384.py`.
   Startup performs `load_nist_scalar_mul_kats` + cross-check against
   `cryptography` and will fail loudly on any parse or integrity error.
4. Commit the updated `.rsp` files in the same commit that bumps the
   CAVS version footer in this README.

## Files

| File | Contents |
|------|----------|
| `__init__.py` | Re-exports the public API (parameters + oracle + loader). |
| `constants.py` | P-256 / P-384 curve parameters (p, a, b, n, Gx, Gy). |
| `loader.py` | `.rsp` parser, `scalar_mul_oracle`, affine group law. |
| `nist_p256_ecdh.rsp` | 25 NIST CAVP KATs for P-256 (scalar, scalar * G). |
| `nist_p384_ecdh.rsp` | 25 NIST CAVP KATs for P-384 (scalar, scalar * G). |
| `README.md` | This file. |

## Threat model

The baseline threat we defend against is an adversarial agent that can
edit **both** the Python test file **and** the C64 assembly source in a
single commit. Concretely, such an agent could:

* Replace `fp_mul` with a stub that returns 0 and pass any test whose
  expected output is also 0.
* Replace `ec_scalar_mul` with a 4-entry lookup table keyed on the input
  scalar and pass any test whose scalars are all present in the table.
* Replace any routine with `rts` and pass any test whose expected output
  matches the output buffer's previous contents.

The oracle closes these attacks by:

* **Unseeded random scalars** — `secrets.randbelow(n)` or
  `random.Random()` seeded from the OS. The adversary cannot pre-compute
  a lookup table for 2^256 possible inputs.
* **External reference** — the expected output is produced by a separate
  process (Python + `cryptography`) that the adversarial commit has no
  way to influence.
* **NIST KATs** — a fixed, immutable anchor set. Even a random-seed
  failure would still be caught because the KATs run on every boot and
  the adversary cannot alter their hex contents without failing the
  oracle cross-check.
* **Bench correctness gates** — every benchmarked routine runs one
  validated call against the oracle before cycle counts are accepted.
  A stub routine cannot pass the gate and therefore cannot record a
  cycle count.
