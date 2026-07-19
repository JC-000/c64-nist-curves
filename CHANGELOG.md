# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases: https://github.com/JC-000/c64-nist-curves/releases — tagged
releases track `MAJOR.MINOR.PATCH` and are the supported consumption
points for downstream projects (see `API.md` §8 for the integration
contract).

## [Unreleased]

### Archive linkability (2026-07-18)

- **`ecdsa_verify_with_message_384` now links from consumer archives
  (issue #63).** The test-only trampoline
  `ecdsa_verify_with_msg_384_tramp` moved from `src/ecdsa384_msg.s` to
  `src/main.s` (the test-driver home, never archived), so
  `ecdsa384_msg.o` no longer imports the test-driver buffers
  `ecdsa_inputs_384` / `ecdsa_result_msg_384`. The wrapper links clean
  from the full `nistcurves.a`; from `lib-p384-curve` it now fails only
  on the comb (`ec_scalar_mul_384`, issue #60/#61 territory), no longer
  on test buffers. `check_archives.py` expectations flipped accordingly
  (nistcurves.a: no gaps). Standalone PRG size unchanged (37171 B; code
  relocated between objects, so addresses shift but the test trampoline
  keeps its exported name and the Python driver is unaffected).

## [0.4.0] — 2026-07-17

### Archive linkability contract + ratchet (issue #60, 2026-07-16)

- **Documented the packaged-verifier archive contract (API.md §8.4.1).**
  The trimmed verify archives exclude the Lim-Lee fixed-base comb by
  design, so the packaged verifiers `ecdsa_verify_256` /
  `ecdsa_verify_384` — which `jsr` the comb (`ec_scalar_mul` /
  `ec_scalar_mul_384`) for the `u1·G` step — are **not linkable from
  those archives alone**. Pre-existing since PR #40; now stated
  explicitly where consumers look (API.md §8.4.1, the Makefile archive
  banner, CLAUDE.md Known issues) with the supported variable-base
  building-block path and the comb add-on link recipe
  (`points256_comb.o` + `data_p256_limlee.o`, or the full `nistcurves.a`)
  plus its boot cost (`ec_precompute_*` ~25 s / ~80 s at 1 MHz) and REU
  bank-2 residency.
- **Blast-radius finding:** verified the P-384 mirror
  (`lib-p384-verify` / `lib-p384-curve`) and additionally found that
  `ecdsa_verify_with_message_384` is unlinkable even from the full
  `nistcurves.a` — its object `ecdsa384_msg.o` carries a *test-only*
  trampoline referencing the test-driver buffers `ecdsa_inputs_384` /
  `ecdsa_result_msg_384` (excluded from every archive). Documented as a
  second gap; tracked in #63 (relocate the test-only trampoline out of
  `ecdsa384_msg.o`).
- **New `tools/check_archives.py` + `make check-archives` target.** A
  contract ratchet: an od65 import/export closure sweep plus `ld65`
  dummy-link smoke tests per archive, checked against a documented
  per-archive allowlist of deliberate gaps. Fails if reality drifts
  *looser* (a new unresolved symbol — regression) or *tighter* (a
  documented gap that unexpectedly resolves — stale docs). Object lists
  are parsed from the Makefile `ar65` recipes (single source of truth),
  not hardcoded. python3 stdlib only; no VICE. Standalone PRG unchanged
  (byte-identical); docs + tooling only.

### Archive slimming (2026-07-16)

- **`lib-p256-verify` BSS trimmed to verify-path-only slots (issue #54,
  −261 B).** `LIB_NISTCURVES_P256_BSS` extent on a consumer link drops
  1573 B → **1312 B**:
  - `fp_tmp1` (32 B) → new `src/data_p256_invref.s` (segment
    `LIB_NISTCURVES_P256_INVREF_BSS`) riding with `inv256.o` — full
    archive + standalone PRG only;
  - `ec_sc_byte` / `ec_sc_mask` (2 B) → `src/data_p256_limlee.s`
    (comb-only scalar-walker state, already excluded from the verify
    archive);
  - `fp_tmp2..4` (96 B) → `src/data_test.s`: referenced by NO .s code,
    but the Python test/bench harness stages field operands there, so
    they move to the test-only object instead of the outright delete
    the issue proposed (consumer-side effect identical);
  - `fp_r1..3`, `fp_inv_iter`, `fp_red_tmp` (131 B) deleted —
    unreferenced by any .s or tool.
  Standalone PRG: 37302 B → 37171 B. Verified: full P-256 field
  (471/471) + point (41/41) + ECDSA-verify suites pass; dummy consumer
  link against the trimmed archive resolves every import on the
  variable-base verify path.
- **Known pre-existing gap (NOT introduced here):** `lib-p256-verify`
  cannot link the packaged `ecdsa_verify_256` — it `jsr`s the fixed-base
  comb `ec_scalar_mul` (u1·G step), which `points256_comb.o` provides
  and the archive excludes by design since #40. Confirmed identical on
  the pre-trim baseline. Tracked separately.

### Tooling / research — REU multiply-table audit (PR #58, 2026-07-16)

- **Committed the REU multiply-table footprint/ROI audit**
  (`.research/reu_mult_audit_2026_05_21/report.md`) and its measurement
  tool `tools/bench_reu_mult.py` (added to the Test-section command
  list). Verdict: keep the 128 KB table (~2× fp_mul speedup vs the
  no-table alternative; REU banks 0–1 are otherwise idle).
- **Corrected the CLAUDE.md per-row DMA-cost claims.** The prior "20
  cycles per row / <1% of fp_mul" figures counted only the register
  setup head. Measured full row fetch is ~542 cy (20 cy setup + ~512 cy
  DMA cycle-steal stall); DMA is ~23% of `fp_mul` / ~18% of
  `fp_mul_384`. The Wave 4c Karatsuba negative-finding passage was
  reworded to match. Docs/tooling only — standalone PRG byte-identical.

### Shared-primitives shape (2026-07-15)

- **§8.3 manifest bit landed + §8.0 conditional mask adopted
  (c64-lib-contract v0.4.0).** `src/lib_manifest.s` now defines
  `LIB_SHARED_PRIMITIVES_CT_MUL_8X8 = $0004` and builds
  `LIB_NISTCURVES_SHARED_PRIMITIVES` in the conditional form required by
  SPEC §8.0 (issue #21): each bit is included iff this build does NOT
  defer that primitive via its migration switch. Standalone build
  exports `$0007` (sqtab | reu_mul | ct_mul_8x8); a build with
  `-D SHARED_CT_MUL_8X8` drops to `$0003`; deferring all three yields
  `$0000` (verified via `od65 --dump-exports`). PRG byte-identical
  (37302 B) — equates only, no runtime impact.

### Shared-primitives shape (2026-06-19)

- **`mul_8x8` body migrated to the canonical `ct_mul_8x8` shape
  (c64-lib-contract issue #14 / §8.3 candidate).** The constant-time
  quarter-square body in `src/mul_8x8.s` is now byte-identical to
  c64-ChaCha20-Poly1305's canonical `ct_mul_8x8` (59 B, sum-first,
  SMC-baked `a` + `b` in Y, `ct_diff_raw`/`ct_sign_mask` scratch),
  replacing the prior register-entry adaptation (A=a/X=b with a
  `tay`/`stx mul_b` preamble + Y-shuttle). This satisfies the
  cross-adopter byte-identity gate `tools/ct_mul_brute_check.py`
  (`chacha vs nist-curves = YES`). `mul_8x8` is retained as a
  back-compat alias of `ct_mul_8x8`; the body is gated on
  `.ifndef SHARED_CT_MUL_8X8` (mirrors §8.1 `SHARED_SQTAB_INIT`).
- **`reu_mul_init` (src/main.s) rewired** to SMC-bake `a` into
  `smc_sum_a_imm+1` / `smc_diff_a_imm+1` once per outer-a iteration and
  pass `b` in Y across the inner loop — chacha's amortized calling
  convention. Boot-only path; no runtime field/point op calls `mul_8x8`.
- No functional or size change: PRG stays 37302 B and all P-256/P-384
  field tests pass. The §8.3 manifest bit (`$0004`) is deferred to a
  follow-up after the contract clause allocates it.

### Shared-primitives shape (c64-lib-contract SPEC v0.3.x, 2026-05-24)

- **§8.2 `reu_mul` promoted to a placement-overridable shared primitive
  (PR #55).** `src/reu_config.s` adds `.ifndef`-guarded
  `LIB_SHARED_REU_MUL_BANK` / `_OFFSET` equates (spec `.assert`s:
  offset `$0000`, bank `< $FE`) plus the derived two-bank mask
  `LIB_SHARED_REU_MUL_BANKS_USED`. The legacy
  `LIB_NISTCURVES_REU_BANK_MUL` stays as a back-compat alias.
  `src/main.s` wraps the `reu_mul_init` body under
  `.ifndef SHARED_REU_MUL_INIT` and exports the SPEC-canonical alias
  `reu_mul_tables_init = reu_mul_init` (safe-to-call-twice). The manifest
  gains `LIB_SHARED_PRIMITIVES_REU_MUL = $0002`, OR-ed into
  `LIB_NISTCURVES_SHARED_PRIMITIVES` alongside the §8.1 sqtab bit.
- **§8.0 step-6 catch-loop enumeration (PR #55).** New
  `src/precalc_table.inc` (copied verbatim from c64-lib-contract so the
  `LIB_PRECALC_TABLE` macro is byte-identical across adopters) and
  `src/precalc_manifest.s` enumerate every precalculated table: the two
  normative shared primitives (sqtab §8.1, reu_mul §8.2) plus three
  library-private tables, with `lim_lee_comb` split per-curve
  (`_p256` 16 KB / `_p384` 24 KB) to match the per-curve verify-archive
  membership. Human-readable rationale in new `docs/precalc-tables.md`
  (authoritative against the manifest; asymmetry blocks adopter PRs).
- **No build-output change:** PRG byte-identical at 37302 B (equates +
  new assemble-only manifest modules; no code growth).

## [0.3.0] — 2026-05-20

### Shared-primitives shape (2026-05-20)

- **`sqtab` migrated to c64-lib-contract SPEC §8.1 placement contract.**
  `sqtab_lo` / `sqtab_hi` in `src/mul_8x8.s` now derive from
  `LIB_SHARED_SQTAB_BASE` — `.ifndef`-guarded with the historical `$9c00`
  default for standalone builds, overridable by consumers linking against
  multiple sqtab-using sibling libs into one PRG via
  `ca65 --asm-define LIB_SHARED_SQTAB_BASE=$<addr>`. Two `.assert` guards
  catch the failure mode that drove the 2026-05-17 `$7800 → $9c00` move
  at assemble time rather than at boot:
  `(LIB_SHARED_SQTAB_BASE & $00ff) = 0` (page-aligned base for cycle-stable
  `abs,x`) and `sqtab_hi = sqtab_lo + $0200` (SMC dispatch's lo→hi delta).
- **`sqtab_init` body gated on `.ifndef SHARED_SQTAB_INIT`.** When a
  consumer defines `SHARED_SQTAB_INIT`, the library's per-lib init body
  (and its scratch) is excluded so a shared-primitives module can supply
  the canonical `mul_tables_init` per SPEC §8.1 without source patching.
  Standalone build behavior unchanged.
- **Manifest equate `LIB_NISTCURVES_SHARED_PRIMITIVES`** added to
  `src/lib_manifest.s` per SPEC §5 + §8.0, OR-composed from the §8.x bit
  constants the library consumes. Currently
  `LIB_SHARED_PRIMITIVES_SQTAB = $0001` only. Lets consumers
  `.assert (LIB_NISTCURVES_SHARED_PRIMITIVES .and LIB_X_SHARED_PRIMITIVES) = 0`
  to catch duplicate ownership at assemble time. Append-only — future §8.x
  primitives get the next free bit.
- **No build-output change.** PRG byte-identical (37302 B); `sqtab_lo`
  still at `$9c00`, `sqtab_hi` still at `$9e00`. Tracking issue
  [JC-000/c64-lib-contract#5](https://github.com/JC-000/c64-lib-contract/issues/5);
  paired with c64-lib-contract PR #6 (SPEC §8 patch) and
  c64-https PR #46 (stub size fix).

### Library packaging (2026-05-20)

- **`c64-lib-contract` SPEC §1 + §3 + §4 + §5 adoption** — landed across
  PRs #43, #45, #46, #48 alongside the §6 work below. The library now
  exposes every contract symbol downstream consumers (c64-https,
  c64-wireguard, future TLS / IPsec clients) need to ingest it without
  patching library sources at integration time:
  - **§1 version equates.** Added the fourth SPEC §1 equate
    `LIB_ABI_VERSION = 0` (matches `LIB_VERSION_MAJOR`; bumps in
    lockstep on breaking exports) to `src/lib_version.s` alongside the
    pre-existing `LIB_VERSION_MAJOR/MINOR/PATCH`. PR #48.
  - **§3 REU symbol contract.** New `src/reu_config.s` exports four
    `.ifndef`-guarded `:abs` equates: `LIB_NISTCURVES_REU_BANK_MUL`
    (`$00`; claims banks MUL and MUL+1 for the 128 KB mul cache),
    `LIB_NISTCURVES_REU_BANK_COMB` (`$02`; Lim-Lee anchors),
    `LIB_NISTCURVES_REU_OFFSET_COMB_P256` (`$0000`),
    `LIB_NISTCURVES_REU_OFFSET_COMB_P384` (`$4000`). Replaces hardcoded
    REU bank/offset literals at every mul-row fetch and comb-table
    stash/fetch site (`main.s`, `mul_8x8.s`, `fp256.s`, `fp384.s`,
    `points256.s`, `points384.s`). Consumer override:
    `ca65 --asm-define LIB_NISTCURVES_REU_BANK_COMB=$05 ...`. PR #43.
  - **§4 segment naming.** Renamed every library `.segment "CODE"` /
    `"RODATA"` / `"DATA"` / `"TABLES"` / `"BSS"` to per-variant
    `LIB_NISTCURVES_*` segments: `LIB_NISTCURVES_P256_CODE` / `_RODATA`,
    `LIB_NISTCURVES_P384_CODE` / `_RODATA` / `_BSS` (for fp384's small
    BSS block), `LIB_NISTCURVES_SHA384_CODE` / `_RODATA` / `_TABLES`,
    `LIB_NISTCURVES_MUL_CODE`, `LIB_NISTCURVES_MAIN_CODE` / `_RODATA`
    (test-driver-only), `LIB_NISTCURVES_TABLES`, `LIB_NISTCURVES_BSS`.
    `src/c64.cfg` gains a SEGMENTS{} alias block so the standalone test
    PRG builds byte-identically. Closes #41. PR #45.
  - **§5 aggregate manifest equates.** New `src/lib_manifest.s` exports
    `LIB_NISTCURVES_REU_BANKS_USED = $07` (bitmask: banks 0+1 mul cache,
    bank 2 comb anchors), `LIB_NISTCURVES_ZP_USAGE_BYTES = 31`,
    `LIB_NISTCURVES_RESIDENT_BYTES = 27000`,
    `LIB_NISTCURVES_COLD_BYTES = 2500`. Consumer cfgs use these for
    assemble-time fit checks against ld65 `__<MEMORY>_SIZE__` symbols
    before kicking off long compile + VICE test cycles. Closes #42.
    PR #46.
  - The PRG and every test pass without change. The adoption is purely
    additive on the public symbol surface (no removals or renames). See
    [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
    adopters.md for the cross-library status table.
- **Per-curve / per-feature `data.s` split + minimal-archive build
  targets** — implementing `c64-lib-contract` SPEC §6 (closes #40).
  The monolithic `src/data.s` is now split into seven self-describing
  files: `data_shared` (mul scratch + page-aligned DMA pages),
  `data_p256` / `data_p256_limlee` (P-256 core / Lim-Lee anchors),
  `data_p384` / `data_p384_limlee` (P-384 mirror),
  `data_sha` (SHA-384 stream state + digest), and `data_test` (the
  test-driver staging buffers `ecdsa_inputs_*` / `sha384_msg_buf`).
  Each file declares its own `LIB_NISTCURVES_*_BSS` segment so a
  consumer pulling a minimal archive does not link in buffers it
  cannot reach. `src/c64.cfg` gains the new segments with
  `optional = yes` so the standalone PRG and full-library archive
  both link unchanged (PRG remains 37,302 bytes loaded at $0801).
- **`points256.s` / `points384.s` split into `_core.s` + `_comb.s`.**
  The core file hosts `ec_point_double`, `ec_point_add` (mixed
  J+affine), `ec_point_add_jj` (full J+J), `ec_scalar_mul_var`
  (variable-base for ECDSA verify), and `ec_jacobian_to_affine`.
  The comb file hosts `ec_precompute_*` and `ec_scalar_mul`
  (Wave 7a h=8 Lim-Lee fixed-base) plus the `sm256_reu_*` /
  `sm384w_*` REU-table stash/fetch helpers, which are only called
  by the comb code. Verify-only consumers exclude the comb file
  and recover ~10 KB of code + 4-6 KB of Lim-Lee anchors per curve.
- **`ecdsa_verify_with_message_384` factored into
  `src/ecdsa384_msg.s`.** The one-shot SHA-384 + verify wrapper
  pulls in the SHA-384 primitives transitively; consumers driving
  streaming SHA themselves (TLS-style multi-buffer transcripts) link
  the bare `ecdsa_verify_384` without dragging in the wrapper.
- **Five new `make lib*` archive targets** (`lib`, `lib-p256-verify`,
  `lib-p384-verify`, `lib-p384-sha384`, `lib-p384-curve`) published
  under `build/lib/nistcurves-*.a`. Each is composed by name from the
  per-curve / per-feature object sets above; see API.md §8.4 for the
  inventory and intended use cases. The pre-existing `make` (no args)
  standalone test PRG target is unaffected and continues to build a
  byte-identical 37,302-byte PRG. `ar65 t build/lib/nistcurves-*.a`
  confirms object counts: full archive ships 26 objects;
  `p256-verify` and `p384-verify` ship 12 each; `p384-curve` ships
  15; `p384-sha384` is the tightest at 4 (no REU / no multiply
  tables, since SHA-384 is self-contained).

### Added (2026-05-19, second wave)

- **Bench coverage for `ec_point_add_jj{,_384}` and `fp_mod_mul_n{,_384}`** —
  four new primitive bench rows so the J+J point-add (load-bearing at
  the ECDSA verify `u1*G + u2*Q` join since PR #34) and the mod-n
  multiply (called twice per verify for `u1 = h*w` and `u2 = r*w`) are
  finally measurable. Four new trampolines in `src/main.s` with marker
  tokens `$8A`/`$8B` (P-256 J+J), `$8C`/`$8D` (P-384 J+J), `$8E`/`$8F`
  (P-256 mod-n mul), `$90`/`$91` (P-384 mod-n mul). New `BENCH_PLAN`
  rows in `tools/bench_p256.py`, `tools/bench_p384.py`,
  `tools/bench_p256_u64.py`, `tools/bench_p384_u64.py`. PRG remains
  37,302 bytes — the four trampolines absorbed cleanly into the
  existing TABLES alignment pad (no new page needed). J+J operand
  setup lifts `(3G, 5G)` to Jacobian with non-trivial Z values so the
  formula must execute the `Z1*Z2` / `Z1^2` / `Z2^2` multiplies it
  would otherwise skip in the mixed-add path; oracle verifier composes
  `affine(3G) + affine(5G)` via the existing library helpers.
  Motivation: the PR #26 + PR #34 measured-vs-predicted retrospective
  showed primitive-bench extrapolation overshot real ECDSA savings by
  10-20×; making the J+J and mod-n-mul primitives directly measurable
  closes one of the gaps that retrospective identified (audit
  Section 8 / `.research/audit_2026_05_18/a4_call_graph.md` §1.3, §1.9).
  Measured @ VICE 1 MHz (cycles/call, 1-MHz-equivalent):

  | Primitive            | P-256 cyc   | P-384 cyc   |
  |----------------------|------------:|------------:|
  | `fp_mod_mul_n`       |     463,624 |   1,036,336 |
  | `ec_point_add_jj`    |   1,295,420 |   2,454,480 |

  Measured @ U64E NTSC (cycles/call, 1-MHz-equivalent wall-clock — see
  CLAUDE.md "Jiffy-clock / REU-DMA wall-clock non-linearity" known
  issue):

  | Primitive            | P-256 @16 MHz | P-256 @48 MHz | P-384 @16 MHz | P-384 @48 MHz |
  |----------------------|--------------:|--------------:|--------------:|--------------:|
  | `fp_mod_mul_n`       |        33,024 |        14,346 |        70,310 |        28,692 |
  | `ec_point_add_jj`    |       168,958 |       122,866 |       284,438 |       194,833 |

  48-MHz speedup is sub-linear (~2.3× for mod-n-mul, ~1.4× for J+J)
  rather than the naïve 3×, because REU DMA fixed-rate dominates the
  bench surface — consistent with the wall-clock non-linearity bound
  documented in CLAUDE.md. Sweep was co-measured (both speeds in one
  invocation) to immunise against the CIA Timer A drift documented at
  48 MHz cross-run.

### Added (2026-05-19)

- **`tools/bench_sha384.py` — VICE 1 MHz SHA-384 per-block bench.**
  New primitive bench that resolves the per-block `sha_compress` cost
  that the U64E turbo bench (`bench_ecdsa_u64.py`) can only bound from
  above at 17,045 1-MHz-equivalent cycles (one jiffy) for short
  messages. Length sweep `{0, 55, 56, 111, 112, 127, 128, 129, 200,
  1024, 4096}` covers SHA-2 padding boundaries (55/56 and 111/112),
  block-boundary transitions (127/128/129), and multi-block
  amortisation (1024, 4096). Oracle gate is `hashlib.sha384` for each
  length. Trampoline at `$C000` (no `src/main.s` edits — reuses
  `bench_start` / `bench_stop`); PRG byte-identical to master at 37,302
  bytes. Measured per-block compress cost = **~517 kcy / block at
  1 MHz** (~30 jiffies), stable across the L=1024 → L=4096 and
  L=0 → L=1024 differencing rows. Resolves the audit Tier-1 #2
  follow-up from `.research/audit_2026_05_18/perf_audit_2026_05_18.md`
  §10 / §11.
- **Bench coverage for `ecdsa_verify_with_message_384`** — the one-shot
  SHA-384 + ECDSA verify wrapper now has a U64E bench row. Added
  `bench_ecdsa_verify_with_msg_384_tramp` to `src/main.s` (marker
  tokens `$88` / `$89`; the 24-byte trampoline is absorbed into the
  existing TABLES alignment pad, so PRG remains 37,302 bytes — exactly
  byte-neutral). Added `setup_ecdsa_verify_with_msg_384` +
  `verify_ecdsa_verify_with_msg_384` + BENCH_PLAN row to
  `tools/bench_ecdsa_u64.py`. Message = RFC 6979 A.3.1 "sample"
  (6 bytes). Oracle gate (`cryptography.hazmat` ECDSA verify on the
  same vector) passed. Measured @ 16 MHz / 48 MHz:

  | Speed   | `ecdsa_verify_384` | `ecdsa_verify_with_msg_384` | Δ (SHA cost) |
  |---------|-------------------:|----------------------------:|-------------:|
  | 16 MHz  | 111,065,220 cyc    | 111,082,265 cyc             | +17,045 cyc (1 jiffy) |
  | 48 MHz  |  80,605,805 cyc    |  80,605,805 cyc             | 0 cyc (sub-jiffy)     |

  SHA-384 hash overhead for a 6-byte message is bounded above by
  17,045 cyc (1-MHz-equivalent) at both speeds, including `sha384_init`
  + `sha384_update` + `sha384_final` (one compress for the padding
  block). The earlier audit-internal estimate of ~1.2 Mcy per
  `sha_compress` block is revised downward by **~70×**; actual compress
  is sub-jiffy at U64E turbo. Resolving the per-block compress cost
  precisely will need a dedicated SHA-384 bench at canonical TLS
  message lengths {0, 55, 56, 111, 112, 200, 1024, 4096 B}, ideally
  run at VICE 1 MHz where one block lands at ~3-9 jiffies (not
  implemented in this PR).

### Fixed (2026-05-19)

- **`tools/bench_p384.py:331` init-sentinel timeout** raised from 180 s
  → 600 s (matching `tools/bench_p256.py:406`). The h=8 Lim-Lee
  precompute boot path takes ~205-246 s at HEAD; the previous 180 s
  ceiling made the tracked bench script broken-at-HEAD without source
  modification. P-256 already used 600 s for the same sentinel and
  passed. The 600 s budget gives ~2.5×-3× headroom over the observed
  init wall time across both VICE and U64E.

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
