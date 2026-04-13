# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases: https://github.com/JC-000/c64-nist-curves/releases — tagged
releases track `MAJOR.MINOR.PATCH` and are the supported consumption
points for downstream projects (see `API.md` §8 for the integration
contract).

## [0.1.0] — 2026-04-13

First audited, tagged release. Establishes a consumable library state for
downstream projects (planned: c64-https, c64-wireguard once migrated to ca65).

### Added

- NIST P-256 and P-384 field arithmetic (add, sub, mul, sqr, mod variants, inv)
- Jacobian point double and mixed Jacobian+affine point addition
- Fixed-base scalar multiplication `k * G` via an h=8 Lim-Lee comb over a
  256-entry REU-resident precompute table (Wave 7a)
- Jacobian-to-affine conversion for result export
- REU DMA multiply-table caching with persistent descriptor state (Wave 7b)
- Dedicated squaring with deferred doubling of cross terms (Wave 4e)
- Carry-propagation INC fusion in fp_mul / fp_sqr accumulator spill (Wave 4b)
- Solinas fast reduction with self-modifying dispatch
- Binary GCD inversion with unrolled shift loops
- VIC-II blanking for +20–25% CPU headroom during compute-bound operations
- Ultimate 64 Elite turbo-mode benchmarking via DMA trampoline at 16 / 48 MHz
- Oracle-driven test suite: NIST CAVP KAS-ECC-CDH anchors, `cryptography`
  Python library oracle, unseeded CSPRNG random inputs, correctness-gated
  benchmarks; 1074 total vectors across test_fp256, test_points256 --full,
  test_fp384, test_points384 --full
- Consumer integration reference in API.md §8 (ca65/ld65 target)
- Library version constants exported from src/lib_version.s

### Build and toolchain

- ca65 / ld65 (cc65 toolchain) on 6502; see README.md "Build" section for
  the one-line `make clean && make` invocation
- Multi-object build: 15 modules compiled individually per `src/c64.cfg`

### Notes on scope

- Fixed-base scalar multiplication only. Variable-base `k * P` is not yet
  implemented, which blocks ECDH and ECDSA-verify. Planned for a future
  MINOR bump.
- Not re-entrant. Library calls must be serialized; see API.md §4 for the
  calling contract.
- Consumer programs must accommodate the library's fixed C64 data addresses,
  ZP slots, and REU bank assignments — see API.md §8.3 for the memory map.

### Wave history preceding v0.1.0

- **Wave 4** (landed): width-5 signed wNAF, carry-prop INC fusion (4b),
  deferred-doubling fp_sqr (4e)
- **Wave 4c** (reverted): subtractive Karatsuba at N=32 — see CLAUDE.md
  "Negative findings"
- **Wave 4d** (reverted): CMO98 relative Jacobian doubling for P-256 — see
  CLAUDE.md
- **Wave 5a / 5b** (landed): Lim-Lee h=4 fixed-base comb for P-256 / P-384
- **Wave 5c** (reverted): Meloni / Fay analysis for P-384 — see CLAUDE.md
- **Wave 7a** (landed): Lim-Lee h=8 upgrade (256-entry REU-resident table),
  −48% P-256 / −50% P-384 on scalar_mul vs wNAF-5 baseline
- **Wave 7b** (landed and documented): persistent REU DMA descriptor state,
  <1% per-row DMA overhead inside fp_mul
- **Wave 8a** (reverted): mixed-add audit (moot — already landed),
  fp_add/sub unroll, `beq mul_src2_buf=0` fast-path removal. Reverted after
  A/B diagnostic showed the `beq` was load-bearing for sparse Jacobian
  intermediates. See CLAUDE.md "Negative findings" and .research/wave8a.txt.

### Cumulative scalar_mul performance vs wNAF-5 baseline

| Curve | Baseline (wNAF-5) | v0.1.0 (h=8 comb) | Speedup |
|---|---:|---:|---:|
| P-256 | ~91.9 M cycles | 46.7 M cycles | 1.97× |
| P-384 | ~270.6 M cycles | 131.4 M cycles | 2.06× |

[0.1.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.1.0
