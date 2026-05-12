# c64-nist-curves v0.2.0 — Release Notes

Released 2026-05-12. Compared to v0.1.0 (2026-04-13).

This is a MINOR release. v0.2.0 adds the variable-base scalar
multiplication + packaged ECDSA verify API surface needed by downstream
TLS-style callers (planned `c64-https`, `c64-wireguard`), lands a
correctness defence against caller REU register residue, and introduces
a reproducible release tarball builder. No public symbols were removed
or renamed.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md); this
file is the concise release summary.

## What's new

### Added — public API surface

- **Variable-base scalar multiplication**: `ec_scalar_mul_var`
  (P-256), `ec_scalar_mul_var_384` (P-384). Left-to-right binary
  double-and-add. **Non-constant-time** (public inputs only). Unlocks
  ECDSA verify's `u2 * Q` limb.
- **Packaged ECDSA verify** with big-endian ABI: `ecdsa_verify_256`
  (160-byte input struct), `ecdsa_verify_384` (240-byte input struct).
  Input pointer in A/X, return via carry flag (`C=0` valid, `C=1`
  invalid). Non-constant-time (TLS verifier context); a constant-time
  variant is NOT provided because it is unnecessary for verify.
- **Byte-reversal helpers**: `fp_reverse32`, `fp_reverse48`. Exported
  for callers driving native LE primitives from BE wire-format inputs.
- **Mod-order multiplication primitives**: `fp_mod_mul_n`,
  `fp_mod_mul_n_384`. Bit-serial top-down reduction.
- **NIST CAVP SigVer KAT bundles** (15 vectors per curve) for the new
  ECDSA verify test (`tools/test_ecdsa_verify.py`).

### Added — tooling

- **Reproducible release tarball builder** (this file is produced by
  it): `tools/build_release.sh <tag>` / `make dist VERSION=<tag>`.
- **U64E ECDSA bench tool** (`tools/bench_ecdsa_u64.py`) with optional
  DebugCapture integration via the U64E cycle-accurate debug
  bus-stream (UDP :11002).
- **Diagnostic reproducers** retained as upstream-regression sentinels
  (`tools/diag_*.py`).

### Security / correctness defences

- **Issue #33-class REU register-residue defence** (ported from
  c64-x25519 commit `817f525`). 10 public entry points that initiate
  REU DMA now defensively re-establish `$DF04 = 0` and `$DF0A = 0`
  before touching DMA, so a caller (sibling REU consumer in a composed
  system) cannot silently route the per-row multiply fetch to the
  wrong offset and produce deterministic-but-wrong field results.
  ~80 raw bytes of code, +6 cy per call, CT-neutral (unconditional).

### Fixed

- **Issue #18**: `fp_sqr_384` hung in standalone-link consumer builds
  because `reu_fetch_mul_row` was defined in `src/main.s`, which
  consumers omit per `API.md` §8.2. Relocated to `src/mul_8x8.s`.
- **Issue #17 Task #4 — LDA-clobbers-Z** bug in 144-byte Jacobian
  copy loops in `ec_scalar_mul_var_384`. Fixed via X-counter
  countdown pattern.
- **CPX-clobbers-C** bug in draft `fp_mod_mul_n` (caught pre-landing
  during Task #10).

See [`CHANGELOG.md`](../CHANGELOG.md) `## [0.2.0]` for the complete
per-bullet list including earlier `[Unreleased]` items not summarised
above.

## Upgrade notes for consumers

- **Semver minor bump.** Additive only. Existing v0.1.0 symbol calls
  remain ABI-compatible — `fp_mul`, `fp_mod_mul`, `ec_scalar_mul`,
  `ec_point_double`, etc. all unchanged in calling convention.
- **`LIB_VERSION_MINOR` is now `2`** in `src/lib_version.s`. Update
  any `.if LIB_VERSION_MINOR < ... / .error` compatibility gates.
- The REU register-residue defence is **always-on** and transparent.
  Callers that previously polluted `$DF04` / `$DF0A` will no longer
  cause silent wrong-result bugs in `fp_mul` / `fp_sqr` / downstream
  composers.

## Tarball

`c64-nist-curves-v0.2.0.tar.gz` is produced reproducibly by
`make dist VERSION=v0.2.0`. Canonical artifact:

- Size:   79173 bytes
- SHA256: `2ed4cf0a795e6e00d69c9fd65c5da23b1ecadeda7b81e843efd44dc6f12bb1d4`

Re-running `make dist VERSION=v0.2.0` against this tag must reproduce
the recorded SHA256 byte-for-byte (`git archive` is deterministic;
`gzip -n` drops the timestamp header). The canonical vendoring file
list lives in `tools/build_release.sh`.

## Verification

All 1038 oracle-gated tests pass on a quiet machine (no contending
VICE processes):

| Suite                       | Result          |
|-----------------------------|-----------------|
| `test_fp256.py`             | 471 / 471 PASS  |
| `test_fp384.py`             | 473 / 473 PASS  |
| `test_points256.py`         | 33 / 33 PASS    |
| `test_points384.py`         | 33 / 33 PASS    |
| `test_ecdsa_verify.py`      | 28 / 28 PASS    |

`tools/test_ecdsa_verify.py` covers RFC 6979 §A.2.5 (P-256) and §A.3.1
(P-384) positive vectors, 8 negatives per curve, and a 5-vector slice
of NIST CAVP SigVer KATs per curve. All results oracle-gated against
the `cryptography` Python package.

## Cross-references

- c64-x25519 sibling: commit `817f525` (the REU-residue defence shape
  ported here), commit `535ea7a` (the reproducible tarball recipe).
- c64-test-harness: PR #89 (closes issue #88 we filed during the
  v0.2.0 investigation; fixes a flaky-`read_bytes` shape in the
  binary-monitor protocol that surfaced in our test runs).
