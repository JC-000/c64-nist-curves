# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases: https://github.com/JC-000/c64-nist-curves/releases — tagged
releases track `MAJOR.MINOR.PATCH` and are the supported consumption
points for downstream projects (see `API.md` §8 for the integration
contract).

## [Unreleased]

### Measured (post-merge retrospective, 2026-05-18)

- **PR #26 and PR #34 ECDSA verify savings are 10-20× smaller than
  predicted.** Both PRs forecast ~800 kcy P-256 / ~1.7 Mcy P-384
  per-verify savings from eliminating `fp_mod_inv` calls (primitive
  bench: ~750 kcy/call). Three-point U64E bench at fw 3.14d (PR #19
  README baseline at `d53971e` / PR #26 build at `460de8f` /
  PR #34 master at `788adc3`):

  | Stage | Predicted | Measured P-256 @16 MHz | Measured P-384 @16 MHz |
  |---|---|---|---|
  | PR #19 → PR #26 | ~800 kcy / ~1700 kcy | −51 kcy (3 jiffies) | −85 kcy (5 jiffies) |
  | PR #26 → PR #34 | ~800 kcy / ~1700 kcy | −17 kcy (1 jiffy) | −102 kcy (6 jiffies) |
  | Combined | ~1.6 Mcy / ~3.4 Mcy | −68 kcy (≈0.16%) | −187 kcy (≈0.17%) |

  Combined RAM cost: ~2 KB PRG + 192 B DATA. RAM-per-cycle-saved is
  dramatically worse than the predictions implied. Likely root cause:
  `fp_mod_inv` is binary GCD with input-sensitive runtime; the Z
  coordinates emerging from `ec_scalar_mul` consistently hit GCD
  fast paths (byte alignment, low Hamming weight, or small magnitude),
  so the eliminated inversions were already cheap in context.

  No code reverted — PR #34 added the `ec_point_add_jj` primitive as
  a useful building block and the sqtab/mul_dma collision fix is
  independently valuable. But the verify-rewiring portion of PR #34
  buys very little measured benefit for its RAM cost.

  **Process change going forward:** any optimization PR that costs
  PRG or DATA bytes must measure on the integrated bench
  (`bench_ecdsa_u64.py`, `bench_p256/p384_u64.py`) before merge and
  cite measured cycles before/after in the PR description. Primitive-
  cost extrapolation is unreliable when the eliminated primitive has
  data-dependent runtime — sibling to the Wave 8a `beq`-removal
  negative finding in the opposite direction. See CLAUDE.md "Negative
  findings" §PR #26+#34 entry for the full lesson.

### Added

- **`ec_point_add_jj` / `ec_point_add_jj_384`** — full Jacobian + Jacobian
  point addition primitives (Bernstein-Lange add-2007-bl, 11M + 5S +
  ~10 add/sub) in `src/points256.s` and `src/points384.s`. Inputs read
  ec_p1 and ec_p2 as full Jacobian points (both Z values consumed,
  unlike the existing `ec_point_add` mixed-add which treats Z2 as 1).
  Result lands in ec_p3. Handles all degenerate cases natively: P1 or
  P2 = infinity (verbatim copy of the other), same projective point
  (tail-call to `ec_point_double`), P1 = -P2 (zero output), both
  infinity. New scratch slot per curve (`ec_jj_tmp` 32 B and
  `ec384_jj_tmp` 48 B in `src/data.s`); existing `ec_t1..t6` cover the
  rest of the formula. Cycle cost is roughly 2x `ec_point_add` (which
  is 7M + 4S mixed-add) — the extra Z2 work is the price for
  eliminating a final inversion in the verify pipeline below.
  Tested via new `test_point_add_jj` / `test_point_add_jj_384` cases
  in `tools/test_points{256,384}.py`: 5 edge cases (P1∞, P2∞, both∞,
  P+P with different Z lifts → 2P, P+(-P) → ∞) + 3 random pairs each
  with independent random Z lifts; oracle = `loader.affine_add` on the
  affine projections.

### Changed

- **ECDSA verify pipeline** (`src/ecdsa256.s`, `src/ecdsa384.s`) — replace
  the final `u1*G + u2*Q` mixed-add (and its preceding affine conversion
  of u1*G) with the new full Jacobian + Jacobian add. Saves one binary-
  GCD inversion + three mod-p multiplies per verify on top of the PR #26
  cofactor-compare landing (which removed the final-point inversion).
  The `@ev_r_from_u1g` short-circuit branch (handling the rare
  u2*Q = infinity case via affine compare of u1*G.x mod n vs r) is
  deleted; the cofactor compare's `r * R.Z² ≡ R.X (mod p)` gate handles
  both Z = 1 and Z ≠ 1 cases uniformly, so it subsumes the special path.
  Replaces `ecdsa_u1g_x` / `ecdsa_u1g_y` (32 + 32 B P-256, 48 + 48 B
  P-384) with `ecdsa_u1g_jac` / `ecdsa384_u1g_jac` (96 B / 144 B) —
  net DATA delta is +96 B for P-256 and +96 B for P-384 (the affine
  pair was 64 B / 96 B; the Jacobian buffer is 96 B / 144 B). Combined
  with the J+J primitives, total PRG delta is +1440 B (35862 → 37302).

### Fixed

- **`sqtab` memory-map collision** (`src/mul_8x8.s`). The quarter-square
  multiply table at the hard-coded equate `sqtab_lo = $7800` had no
  guard against the linker-managed `mul_dma_lo` / `mul_dma_hi` page-
  aligned slots (`src/data.s` TABLES segment) growing into the same
  address as code expanded. The `ec_point_add_jj` primitive's ~1 KB of
  new code pushed `mul_dma_hi` from `$7500` to `$7800`, silently
  aliasing `sqtab_lo` — which `sqtab_init` then clobbered, leaving
  multiply rows zero and hanging the boot sentinel. Same bug shape as
  the PR #27 / w-NAF re-land hang. Surgical fix: move sqtab equates
  to `$9C00` / `$9E00`, ~1 KB of headroom above the current top of
  DATA (~$988A). The SMC-page-delta math in `mul_8x8` is computed
  from the equates so the page-aligned-base constant-time invariant is
  preserved automatically. See the file header comment for the full
  rationale and the page-bump procedure if future growth threatens
  the new address.

- **SHA-384 streaming hash** (`src/sha384.s`, ~970 lines). FIPS 180-4 §6.4
  compression with SHA-384 IV and 48-byte BE truncated output. Streaming
  ABI: `sha384_init` (clear + IV) / `sha384_update` (absorb sha_len bytes
  from sha_src) / `sha384_final` (pad + finalize → sha384_digest). LE
  storage on-chip with byte reversal at the wire boundaries. Self-contained
  module — no REU DMA, no shared field/point scratch. Test coverage:
  `tools/test_sha384.py`, 25/25 against the `hashlib.sha384` oracle (4
  mandatory FIPS 180-4 KATs + 17 boundary-length random + 4 multi-block
  stress including 4 KB). PRG grew 24322 → 32022 B (~7.7 KB; ~1.7 KB of
  that is a test scratch buffer).

- **`ecdsa_verify_with_message_384`** (`src/ecdsa384.s`). One-shot wrapper
  that hashes a contiguous message via the new SHA-384 module, splices the
  digest into a 240-byte caller-owned BE struct (`r | s | h_unused | Qx |
  Qy`), then tail-calls `ecdsa_verify_384`. C=0 valid / C=1 invalid; same
  return convention as the underlying verify. For TLS-style transcripts
  spanning multiple buffers, callers should drive `sha384_init/update*/final`
  directly and call `ecdsa_verify_384` with the digest pre-spliced. New
  tests in `tools/test_ecdsa_verify.py`: 5 positive (random msgs 1/17/100/500/1023 B
  with fresh `cryptography` keypairs) + 2 negative (tampered msg / wrong
  pubkey).

### Changed

- **`read_bytes_verified` integration in field-arithmetic tests.** The
  four single-byte carry/borrow verifier reads inside `c64_fp_add`
  and `c64_fp_sub` in `tools/test_fp256.py` and `tools/test_fp384.py`
  now use `c64_test_harness.read_bytes_verified` rather than plain
  `read_bytes`. Future flakes at those sites will raise
  `FlakeyReadError` (a distinct exception type) instead of silently
  returning corrupted bytes that masquerade as wrong-answer assertion
  failures. Bulk coordinate reads, wide-result reads, and the
  `$02A7` startup sentinel poll are deliberately NOT converted — the
  helper doubles wire traffic per call and is only worth it at
  verifier sites where a flake would silently look like a test bug.
  Requires c64-test-harness PR #89 (`read_bytes_verified` helper) or
  later; older harness installs will fail on the import. Tests still
  pass cleanly: 471/471 (P-256) and 473/473 (P-384).
- **VICE-contention preflight warning** in all eight VICE-targeting
  scripts under `tools/`: `test_fp256.py`, `test_fp384.py`,
  `test_points256.py`, `test_points384.py`, `test_ecdsa_verify.py`,
  `test_inv_fast.py`, `bench_p256.py`, `bench_p384.py`. Each `main()`
  now calls `_warn_if_vice_running()`, which shells out to
  `pgrep -c x64sc` (2 s timeout, all exceptions swallowed) and prints
  a one-line stderr warning when another `x64sc` is already running
  — surfaces the wall-clock-contention pattern that previously
  manifested as spurious per-call timeouts in concurrent test runs.
  Purely observational; never blocks or fails. U64-hardware bench
  tools (`bench_p256_u64.py`, `bench_p384_u64.py`,
  `bench_ecdsa_u64.py`, `bench_u64_common.py`) deliberately skipped —
  those don't drive VICE.
- **API.md v0.1.x → v0.2.x example refresh.** Five sites refreshed
  in §8.1 / §8.5 / §8.6 to suggest the current release as the
  default pin for new consumers: submodule integration example
  (`git checkout v0.2.0` + commit message), bumping example
  (`v0.2.1` placeholder), version-pinning check
  (`LIB_VERSION_MINOR < 2`, error string `"c64-nist-curves v0.2.0 or
  newer is required"`), PATCH-bump example (`v0.2.0 → v0.2.1`), and
  the `c64-https` / `c64-wireguard` "as of" reference. The historical
  release-ledger line in `README.md` is preserved unchanged. No
  library code or ABI changes; documentation only.
- **Doc staleness sweep, post-PR #23.** Five drift fixes accumulated
  across v0.1.0 → v0.2.0 → SHA-384 work. (1) API.md §2 PRG-size cell
  no longer pins a specific byte count — points readers at
  `build/labels.txt` instead. (2) API.md §7 limitations entry on
  scalar multiplication rewritten — `ec_scalar_mul_var[_384]` exists
  as of v0.2.0 and ECDSA-verify is provided; the actual surviving
  limitation is "both scalar-mul paths are non-constant-time, public-input
  only" (the fixed-base comb also branches on comb index and infinity flag).
  (3) CLAUDE.md ECDSA-verify-API buffer accounting refreshed for the +3 B
  `ecdsa_verify_with_message_384` wrapper additions
  (`ecdsa384_msg_struct_ptr` + `ecdsa_result_msg_384`). (4) README.md
  feature-bullet list rejoined (stray blank line removed). (5) README.md
  `## Status` checklist gains rows for packaged ECDSA verify and SHA-384
  streaming hash.

## [0.2.0] — 2026-05-12

### Security

- **Issue #33-class REU register-residue defence** (ported from
  c64-x25519 commit `817f525`). The per-row REU DMA fetch in `fp_mul`
  / `fp_sqr` (256+384) writes only 3 of 8 REU registers per call,
  trusting `reu_reu_lo` (`$DF04`) and `reu_addr_ctrl` (`$DF0A`) remain
  `$00` from `reu_mul_init`'s tail. A caller that touched those two
  registers after boot (e.g. a sibling REU consumer in a composed
  system like the planned `c64-https` / `c64-wireguard` integrations)
  would have caused row fetches to DMA from the wrong REU offset or
  with hold-C64-address mode, silently producing
  deterministic-but-wrong field results. The x25519 sibling reported
  exactly this composition-bug shape under c64-https TLS handshake
  derivation. Defence: defensive `lda #0 / sta reu_reu_lo / sta
  reu_addr_ctrl` at every public entry point that initiates DMA —
  `fp_mul` / `fp_sqr` (×2 curves), `ec_scalar_mul` / `_var` (×2
  curves), `ecdsa_verify_256` / `_384`. ~80 raw bytes of code across
  10 sites; +6 cycles per call (transparent CT-neutral, unconditional
  stores). PRG grows from 24322 → 24578 bytes; +176 of that is
  page-alignment shift on the TABLES segment, not real code. Same bug
  shape and fix as the x25519 sibling.

### Fixed

- **Issue #18 (`fp_sqr_384` hangs in standalone-link consumer builds)** —
  `fp_sqr_384`'s diagonal loop called `reu_fetch_mul_row`, which was
  defined in `src/main.s`. Per `API.md` §8.2, consumers of the math
  library do NOT link `main.s` into their PRG (it is the library's own
  test/bench driver), so the `jsr reu_fetch_mul_row` site resolved to
  an unresolved / garbage target and squaring hung. `fp_mul_384` was
  unaffected because it inlines the REU DMA sequence; `fp_sqr` (P-256)
  also inlines, so this was a P-384-squaring-only asymmetry. Fix:
  relocated `reu_fetch_mul_row` into `src/mul_8x8.s` (its natural home
  as the REU row-fetch helper for the multiply primitive), refreshed
  `src/exports.inc` to reflect the new home, and cleared the
  pre-existing ca65-migration TODO note on this routine. Zero
  algorithm change; PRG size unchanged at 24322 bytes. Covered by the
  existing P-384 point-ops suite (`test_points384.py`), which drives
  `ec_point_double_384 → fp_mod_sqr_384 → fp_sqr_384` and is the
  canonical gate for this issue.

### Added

- Variable-base scalar multiplication: `ec_scalar_mul_var` (P-256),
  `ec_scalar_mul_var_384` (P-384). Left-to-right binary double-and-add
  over 256 / 384 bits. Non-constant-time (public inputs only). Unlocks
  ECDSA verify's `u2 * Q` limb.
- Packaged ECDSA verify with big-endian ABI: `ecdsa_verify_256`
  (160-byte input struct), `ecdsa_verify_384` (240-byte input struct).
  Input pointer in A/X, return via carry flag (`C=0` valid, `C=1`
  invalid). Non-constant-time (TLS verifier context); a constant-time
  variant is NOT provided because it is unnecessary for verify.
- Byte-reversal helpers: `fp_reverse32`, `fp_reverse48`. Exported for
  callers who want to drive the library's native little-endian
  primitives from big-endian wire-format inputs directly.
- Mod-order multiplication primitives: `fp_mod_mul_n`, `fp_mod_mul_n_384`.
  Needed because `fp_mod_mul` hardcodes Solinas mod-p reduction; the
  group-order mod-n reduction uses bit-serial top-down division.
- U64E ECDSA bench tool (`tools/bench_ecdsa_u64.py`) with optional
  DebugCapture integration via the U64E cycle-accurate debug bus-stream
  (UDP :11002). Four bench trampolines added in `src/main.s` emitting
  `$80`..`$87` markers at `$BFFF`.
- Diagnostic reproducer `tools/diag_verify384_turbo.py` for the
  Task #12 `ecdsa_verify_384` turbo timeout investigation.
- Diagnostic reproducers used during the c64-test-harness issue #88
  investigation (flaky `read_bytes` from the binary-monitor protocol;
  fixed upstream by `c64-test-harness` PR #89):
  `tools/diag_fp_mod_add.py`, `tools/diag_fp_mod_add_after_mul.py`,
  `tools/diag_fp_mul.py`, `tools/diag_read_consistency.py`. Each is a
  standalone, single-purpose reproducer that JSRs one library entry
  point with fixed or randomized inputs and compares against the
  Python oracle. Retained as upstream-regression sentinels.
- **Reproducible release tarball builder** (`tools/build_release.sh`,
  invoked via `make dist VERSION=v0.2.0`). Codifies the canonical
  v0.2.0+ vendoring file list and produces a byte-deterministic
  source tarball from a named git tag. SHA256 is printed and must
  match the value recorded in `docs/RELEASE_NOTES_<tag>.md`. Mirrors
  the c64-x25519 sibling's `tools/build_release.sh` recipe (commit
  `535ea7a`).
- NIST CAVP SigVer KAT bundles for P-256 and P-384 (15 vectors each,
  `tools/vectors/nist_p256_sigver.rsp` + `nist_p384_sigver.rsp`)
  consumed by the new `tools/test_ecdsa_verify.py`. Tests run RFC 6979
  A.2.5 / A.3.1 positive vectors, 8 negatives per curve, and a
  configurable slice of the CAVP vectors; all oracle-gated via the
  `cryptography` Python package.

### Fixed

- **LDA-clobbers-Z bug pattern in 144-byte Jacobian copy loops**
  (`ec_scalar_mul_var_384`, issue #17 Task #4). Extension of the
  `LDY #143 / BPL` infinity-fill bug family already documented in
  CLAUDE.md. The variant was a counter/Y-indexing mismatch where
  `LDA abs,y` clobbered the Z flag that a subsequent `BNE` was trying
  to test against a separate counter. Fixed via the X-counter
  countdown pattern `ldx #144 / ... / iny / dex / bne @l`.
- **CPX-clobbers-C bug in `fp_mod_mul_n`** (draft revision, caught
  pre-landing during Task #10). The bit-serial top-down reduction's
  ROL loop used `CPX #0` as the counter test, which clobbered C
  between the `ROL acc` and the conditional subtract. Fixed by
  switching to `DEC` / `DEX` counters, which preserve C and mirror
  the style already used in `fp_mod_mul_n_384`.

Closes #17.

### Added (earlier in [Unreleased], pre-Task #9)

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

[0.2.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.2.0
[0.1.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.1.0
