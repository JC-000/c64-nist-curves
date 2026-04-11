# tools/vectors — NIST KAT anchors + cryptography oracle

## Purpose

This directory holds the **external oracle** used by the field-,
point-, and benchmark-test harnesses in `tools/test_fp*.py`,
`tools/test_points*.py`, and `tools/bench_p*.py`. Its purpose is
to make those tests **un-gameable**: an adversary who edits both
the Python test file and the C64 assembly in a single commit must
still produce output that matches an external, independently-
specified reference.

## The oracle invariant

Four layers, from most authoritative to least:

1. **NIST CAVP Known Answer Tests** (`nist_p256_ecdh.rsp`,
   `nist_p384_ecdh.rsp`) — immutable `.rsp` files shipped with
   this repository. Each entry pins a specific
   `(scalar, scalar * G)` pair to the P-256 / P-384 specification.
   These are the ultimate anchor for scalar multiplication and
   are consumed by the point and benchmark tests.

2. **The `cryptography` Python package** — used via
   `scalar_mul_oracle(k, curve)` in `loader.py`. This wraps
   `ec.derive_private_key(k, SECP256R1())` and is the canonical
   reference for scalar multiplication across the full scalar
   space. At test startup we cross-validate **every** NIST KAT
   against the library, so a compromised `cryptography` install
   would be caught by the KATs themselves.

3. **Field-arithmetic KAT bundles** (`nist_p256_kat.rsp`,
   `nist_p384_kat.rsp`) — sectioned `.rsp` files carrying curve
   parameters plus `[KG k=N]` (`k*G` for small `k`) and
   `[EcPoint tcId=N]` (Wycheproof "valid" public points) records.
   These are consumed by the field-arithmetic tests
   (`test_fp256.py` / `test_fp384.py`) to anchor `fp_mod_mul /
   add / sub` via the curve equation `y^2 == x^3 - 3x + b mod p`
   on known points. A stub that returns constant zero from all
   `fp_mod_*` routines cannot pass this check because
   `0 != 0 - 0 + B mod p` for non-zero `B`.

4. **Hand-rolled affine group law** in `loader.py::affine_add` —
   used only for point addition / point doubling reference
   values, because `cryptography` does not expose affine add.
   Every such helper is self-checked at test startup
   (`self_check()` verifies `affine_add(kG, G) == (k+1)G` against
   the oracle).

Plus two process invariants for the Python test code itself:

5. **No self-written helpers that re-implement the operation
   under test.** Field-op reference values come from Python
   `int` `+`, `-`, `*`, `%`, `pow(a, p-2, p)` — interpreter
   primitives, not editable helpers.
6. **Random inputs are unseeded by default.** The tests use
   `secrets.token_bytes()` / `secrets.randbelow(n)` (OS CSPRNG).
   Every run exercises a fresh sample from a 2^256-wide space.
   A `--seed N` flag is available for reproducing specific
   failures.

**Hard rules — do not cross these:**

* Never replace `scalar_mul_oracle` with a hand-rolled scalar
  multiplier living in this repository. The whole point of the
  oracle is that it is external to the code under test.
* Never hardcode expected outputs from a previous C64
  implementation run. Every expected value in a test must come
  from the oracle, a NIST KAT, or a Python interpreter primitive
  applied to random inputs.
* Never trim or edit the checked-in `.rsp` files without
  re-running the refresh procedure and cross-checking against
  the authoritative source.

## Files

| File | Purpose |
|------|---------|
| `__init__.py` | Re-exports the public API (constants + loaders + oracle). |
| `constants.py` | P-256 / P-384 curve parameters, from FIPS 186-5. Exports both the short names (`P256`, `GX256`, ...) used by field tests and the prefixed names (`P256_P`, `P256_GX`, ..., `CURVES`) used by point and bench tests. |
| `loader.py` | `.rsp` parsers (both flavours), `scalar_mul_oracle`, affine group law, startup self-check. |
| `nist_p256_ecdh.rsp` | 25 NIST CAVP KAS ECC CDH KATs for P-256 (scalar, scalar * G). |
| `nist_p384_ecdh.rsp` | 25 NIST CAVP KAS ECC CDH KATs for P-384 (scalar, scalar * G). |
| `nist_p256_kat.rsp` | Field-KAT bundle: FIPS 186-5 curve params + `[KG k=N]` + `[EcPoint tcId=N]` for P-256. |
| `nist_p384_kat.rsp` | Field-KAT bundle: FIPS 186-5 curve params + `[KG k=N]` + `[EcPoint tcId=N]` for P-384. |
| `README.md` | This file. |

## Sources

### NIST CAVP KAS ECC CDH (for scalar-mul KATs)

The ECDH vector files are the `[P-256]` and `[P-384]` sections
extracted from:

* **Filename:** `KAS_ECC_CDH_PrimitiveTest.txt`
* **Source:** NIST CAVP Component Testing — ECC CDH Primitive
  (SP 800-56A §5.7.1.2)
* **Download:**
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip
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
`dIUT * G` on the C64, convert to affine, and compare. 25 vectors
per curve.

### NIST FIPS 186-5 (for curve parameters)

* **URL:** https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
* **Sections:** D.1.2.3 (P-256), D.1.2.4 (P-384)
* Used directly in `constants.py`. `constants.py` has a
  module-load-time self-check asserting `Gy^2 == Gx^3 + a*Gx + b
  mod p` for both curves, so tampering with a single constant
  breaks import.

### Wycheproof ECDH EcPoint (for the `[EcPoint tcId=N]` anchors)

* **URL:** https://github.com/C2SP/wycheproof/tree/main/testvectors_v1
* **Files consumed:**
  - `ecdh_secp256r1_ecpoint_test.json`
  - `ecdh_secp384r1_ecpoint_test.json`
* Only tests with `result = "valid"` are adopted, and each point
  is re-verified to satisfy `y^2 = x^3 - 3x + b mod p` at
  vector-save time. `tcId` is preserved from the Wycheproof JSON
  so a failing case can be traced back to the source.

### `[KG k=N]` anchors in the field-KAT bundles

These are `k*G` for small `k` (1..16, 255, 256, 1023) computed
**at vector-save time** via a pure-Python scalar-multiplication
routine that only uses Python `int`/`pow`/`%`. This is strictly
weaker than NIST-published vectors because the computation lives
in the generation script. It is still useful because:

- `Gx`/`Gy` come from FIPS 186-5 directly.
- The pure-Python scalar-mul has been cross-validated against
  the Wycheproof `[EcPoint ...]` records, which are externally
  audited.
- Any edit to the KAT file shows in the diff, and an edit to a
  `[KG k=N]` record that no longer satisfies the curve equation
  is caught by the on-C64 curve-equation anchor test.

## KAT file format — `nist_p*_kat.rsp`

```
# comment
[Curve = P-256]
p = <hex>
a = <hex>
b = <hex>
Gx = <hex>
Gy = <hex>

[KG k=N]
x = <hex>
y = <hex>

[EcPoint tcId=N]
x = <hex>
y = <hex>
```

Blank lines separate records. `loader.py::load_kat` returns a
`KAT` dataclass whose `.point_records()` gives an iterable of
`(label, x, y)` tuples.

## KAT file format — `nist_p*_ecdh.rsp`

Standard NIST CAVS flat layout. `loader.py::load_rsp` returns a
list of `dict[str, str]` records. `load_ecdh_kats` /
`load_nist_scalar_mul_kats` project these to
`{"d": int, "qx": int, "qy": int}`.

## Refresh procedure

### Scalar-mul KATs (`nist_p*_ecdh.rsp`)

1. Download and unzip `ecccdhtestvectors.zip` from the NIST URL
   above.
2. Copy the file header plus the `[P-256]` section into
   `nist_p256_ecdh.rsp`, and similarly `[P-384]` into
   `nist_p384_ecdh.rsp`.
3. Run `python3 tools/test_points256.py` and
   `python3 tools/test_points384.py`. Startup performs
   `load_nist_scalar_mul_kats` and cross-checks every record
   against `cryptography`; any parse or integrity error fails
   loudly.
4. Commit the updated `.rsp` files in the same commit that bumps
   the CAVS version footer in this README.

### Field-KAT bundles (`nist_p*_kat.rsp`)

```bash
curl -sSL -o /tmp/ecdh_p256.json \
    https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ecdh_secp256r1_ecpoint_test.json
curl -sSL -o /tmp/ecdh_p384.json \
    https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ecdh_secp384r1_ecpoint_test.json
# Then re-run the vector generator (pure-Python, uses only
# int/pow/% so that regenerating does not introduce a new trust
# dependency).
```

The file header in each `.rsp` documents the source URL and the
verification invariant (`y^2 == x^3 - 3x + b mod p`) so a refresh
can always be cross-checked.

## How tests use the oracle

Field-arithmetic sketch (`test_fp256.py`):

```python
from vectors import P256, GX256, GY256, B256, load_kat

kat = load_kat("nist_p256_kat.rsp")
for label, x, y in kat.point_records():
    # On the C64: compute y^2, x^3-3x+b, check equality.
    lhs = c64_fp_mod_mul(y, y)
    x2  = c64_fp_mod_mul(x, x)
    x3  = c64_fp_mod_mul(x2, x)
    t   = c64_fp_mod_sub(x3, c64_fp_mod_add(c64_fp_mod_add(x, x), x))
    rhs = c64_fp_mod_add(t, B256)
    assert lhs == rhs, f"C64 curve equation failed for {label}"
```

A C64 stub that returns constant zero from all `fp_mod_*`
routines cannot pass this check because `0 != 0 - 0 + B256 mod p`
for non-zero `B256`.

Scalar-mul sketch (`test_points256.py`):

```python
from tools.vectors import load_nist_scalar_mul_kats, scalar_mul_oracle

for v in load_nist_scalar_mul_kats("p256"):
    # Cross-check the KAT against the cryptography oracle first.
    assert scalar_mul_oracle(v["d"], "p256") == (v["qx"], v["qy"])
    # Then run the C64 scalar_mul on v["d"] and compare to (qx, qy).
```

## Threat model

The baseline threat we defend against is an adversarial agent
that can edit **both** the Python test file **and** the C64
assembly source in a single commit. Concretely, such an agent
could:

* Replace `fp_mul` with a stub that returns 0 and pass any test
  whose expected output is also 0.
* Replace `ec_scalar_mul` with a 4-entry lookup table keyed on
  the input scalar and pass any test whose scalars are all
  present in the table.
* Replace any routine with `rts` and pass any test whose
  expected output matches the output buffer's previous contents.

The oracle closes these attacks by:

* **Unseeded random scalars** — the adversary cannot pre-compute
  a lookup table for 2^256 possible inputs.
* **External reference** — expected outputs come from a separate
  process (Python + `cryptography`) that the adversarial commit
  has no way to influence.
* **NIST KATs and curve-equation anchors** — fixed, immutable
  anchor sets. Even a random-seed failure is caught because the
  KATs run on every boot and the adversary cannot alter their
  hex contents without failing the oracle cross-check or the
  on-C64 curve-equation verification.
* **Bench correctness gates** — every benchmarked routine runs
  one validated call against the oracle before cycle counts are
  accepted. A stub routine cannot pass the gate and therefore
  cannot record a cycle count.
