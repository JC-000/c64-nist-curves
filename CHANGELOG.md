# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases: https://github.com/JC-000/c64-nist-curves/releases — tagged
releases track `MAJOR.MINOR.PATCH` and are the supported consumption
points for downstream projects (see `API.md` §8 for the integration
contract).

## [Unreleased]

### Added

- **`tools/ct_mul_brute_check.py`** — brute-force correctness check for
  the constant-time `mul_8x8`. Exercises all 65 536 `(a, b)` pairs in
  `[0, 255]²` against Python `a * b` and asserts byte equality of the
  16-bit product. Used as the primary validation for the issue #14
  remediation (see below). Uses the canonical `$02A7` init sentinel
  pattern + a 256-byte inner-loop shim at `$C000` for batched reads,
  so the 65 536-pair sweep completes in ~2.5 s of warp-mode runtime
  after the one-time init.

### Fixed

- **Issue #14 (constant-time bug in `mul_8x8`)** — the quarter-square
  8×8→16 multiply primitive at `src/mul_8x8.s` had two secret-dependent
  branches (`bcs :+` at the |a−b| sign test, `beq @s0` at the sum-page
  dispatch) that would leak the high bit of `a−b` and the carry of
  `a+b` via branch-timing on any caller passing secret operands. Both
  branches removed via a branchless port of `ct_mul_8x8` from
  `c64-ChaCha20-Poly1305` v0.3.0 (`src/lib/poly1305_lib.s`, design memo
  `docs/design/ct_mul_8x8.md`). The new implementation uses a sign-mask
  trick for `|a−b|` (`lda #0 / sbc #0` produces `$00` / `$FF` then
  `eor` + `sec / sbc`) and SMC-patches the high byte of two `lda abs,x`
  loads for the sum-page dispatch. All table loads use page-aligned
  bases (`sqtab_lo` at `$7800`, `sqtab_hi` at `$7a00`) so `abs,x` and
  `abs,y` are always 4-cy with no page-cross penalty. Body is
  straight-line with no conditional branches.

  In this project `mul_8x8` has exactly one caller — `reu_mul_init` at
  boot, which walks `(a, b) ∈ [0, 255]²` once to build the REU DMA
  multiply-table cache — so no runtime field or point op is affected.
  All `fp_*` / `ec_*` cycle counts are flat within measurement noise.
  Boot-time impact: +2.8 M cy (≈ +2.8 s on a real C64, lost in the
  ~120 s warp-mode init noise under VICE).

  Per-call cost: 86 cy body + 6 cy caller-side `jsr` = 92 cy at the
  call site (up from ~46–50 cy for the old branchy body). The
  adaptation from the reference's SMC-baked entry to this project's
  register calling convention keeps `a` live in Y across the sum
  block, so the diff block recovers it with a 2-cy `tya` instead of
  a 3-cy `lda mul_a` round-trip — saving 2 cy versus a naive port.
  Validated by a new brute-force test tool
  (`tools/ct_mul_brute_check.py`) that exercises all 65 536 `(a, b)`
  pairs and asserts byte equality against Python `a * b`. All
  existing tests (fp256, fp384, points256 --full, points384 --full,
  ct_mul_brute_check, test_inv_fast) pass.

- **`tools/test_inv_fast.py`** was failing on both baseline and
  post-fix because it used the stale `wait_for_text("READY.")`
  boot-wait pattern; `src/main.s`'s `start:` ends in an infinite
  `jmp main_loop`, so BASIC never regains control and the `READY.`
  prompt never appears. Ported to the canonical `$02A7` init sentinel
  pattern (per CLAUDE.md "Init sentinel pattern" section, same shape
  as `test_fp384.py` / `test_points384.py`). 10/10 `fp_mod_inv_fast`
  tests now pass.

- **`tools/bench_p256.py`** had the same stale
  `wait_for_text("READY.")` pattern. It was working by luck on
  short-init runs but became unreliable once the issue #14 boot-cost
  increase pushed total init past the 180 s text-wait budget. Ported
  to the sentinel pattern to match `bench_p384.py`. Also dropped the
  post-wait `sqtab_init` / `reu_mul_init` re-invocation — the sentinel
  is written after every table build, so the re-init was both
  redundant and would have doubled boot cost under the slower
  ct_mul_8x8.

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
