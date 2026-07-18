# c64-nist-curves v0.4.0 — Release Notes

Released 2026-07-17. Compared to v0.3.0 (2026-05-20).

This is a MINOR release. v0.4.0 completes [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
SPEC v0.4.0 §8 adoption (the shared-primitive contract): the constant-time
`ct_mul_8x8` multiply body is now byte-identical across all three sibling
adopters, the §8.2 `reu_mul` table is a placement-overridable shared
primitive, and the manifest `LIB_NISTCURVES_SHARED_PRIMITIVES` bitmask now
takes the conditional §8.0 form (a bit drops when the build defers that
primitive to a canonical provider). It also trims the `lib-p256-verify`
archive's BSS footprint to the verify path only, makes the packaged-verifier
archive-linkability contract explicit (API.md §8.4.1) with a `make
check-archives` ratchet, and commits the REU multiply-table ROI audit plus a
CLAUDE.md DMA-cost correction.

No public entry points were removed or renamed; `LIB_ABI_VERSION` remains
`0`. A set of undocumented, consumer-unreferenced field scratch **exports**
were removed or relocated out of the archive objects as part of the issue #54
BSS trim — see "Upgrade notes / compatibility" below for the honest list.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md) `## [0.4.0]`;
this file is the concise release summary.

## What's new

### Shared-primitive contract — c64-lib-contract SPEC v0.4.0 §8

- **Canonical `ct_mul_8x8` body, byte-identical across adopters (§8.3,
  PR #56).** The constant-time quarter-square multiply body in
  `src/mul_8x8.s` was adopted verbatim from c64-ChaCha20-Poly1305's
  canonical `ct_mul_8x8` (59 B, sum-first, SMC-baked `a` + `b` in Y). The
  cross-adopter byte-identity gate (`ct_mul_brute_check.py`) now sees
  identical opcodes across all three adopters. `mul_8x8` is retained as a
  back-compat alias; the body is gated on `.ifndef SHARED_CT_MUL_8X8`.
  Boot-only path, zero constant-time exposure at runtime — no field or
  point op calls it. PRG byte-identical.
- **§8.3 manifest bit + §8.0 conditional shared-primitives mask (PR #57).**
  `src/lib_manifest.s` defines `LIB_SHARED_PRIMITIVES_CT_MUL_8X8 = $0004`
  and builds `LIB_NISTCURVES_SHARED_PRIMITIVES` in the SPEC §8.0
  conditional form (issue #21): each bit is included **iff** this build
  does not defer that primitive via its migration switch
  (`SHARED_SQTAB_INIT` / `SHARED_REU_MUL_INIT` / `SHARED_CT_MUL_8X8`). The
  standalone build exports `$0007` (sqtab | reu_mul | ct_mul_8x8); a build
  with `-D SHARED_CT_MUL_8X8` drops to `$0003`; deferring all three yields
  `$0000`. Equates only — PRG byte-identical.
- **§8.2 `reu_mul` placement-overridable shared primitive + §8.0
  catch-loop (PR #55).** `src/reu_config.s` adds `.ifndef`-guarded
  `LIB_SHARED_REU_MUL_BANK` / `_OFFSET` consumer-override equates and the
  derived `LIB_SHARED_REU_MUL_BANKS_USED` two-bank mask;
  `LIB_NISTCURVES_REU_BANK_MUL` remains a back-compat alias. `src/main.s`
  exports the SPEC-canonical alias `reu_mul_tables_init = reu_mul_init`
  (safe to call twice) under an `.ifndef SHARED_REU_MUL_INIT` migration
  switch. New `src/precalc_manifest.s` + `src/precalc_table.inc` +
  `docs/precalc-tables.md` mechanically enumerate every precalculated
  table (the two normative shared primitives plus three library-private
  tables) per the §8.0 step-6 catch-loop. PRG byte-identical.

### Archive slimming (issue #54, PR #59)

- **`lib-p256-verify` BSS trimmed to verify-path-only slots.** The
  `LIB_NISTCURVES_P256_BSS` extent on a consumer link drops
  **1573 B → 1312 B** (−261 B):
  - `fp_tmp1` (32 B) moved to new `src/data_p256_invref.s` (new segment
    `LIB_NISTCURVES_P256_INVREF_BSS`) riding with `inv256.o` — full
    archive + standalone PRG only;
  - `ec_sc_byte` / `ec_sc_mask` (2 B) moved to `src/data_p256_limlee.s`
    (comb-only, already excluded from the verify archive);
  - `fp_tmp2..4` (96 B) moved to `src/data_test.s` (referenced by no
    library `.s` code, but the Python test/bench harness stages field
    operands there);
  - `fp_r1..3`, `fp_inv_iter`, `fp_red_tmp` (131 B) **deleted** —
    unreferenced by any `.s` source or tool.
  - Standalone PRG: **37302 B → 37171 B** (−131 B).

### Archive linkability contract + ratchet (issue #60, PR #62)

- **The packaged-verifier archive contract is now explicit (API.md
  §8.4.1).** The trimmed verify archives exclude the Lim-Lee fixed-base
  comb by design, so the packaged verifiers `ecdsa_verify_256` /
  `ecdsa_verify_384` — which `jsr` the comb (`ec_scalar_mul` /
  `ec_scalar_mul_384`) for the `u1·G` step — are **not linkable from those
  trimmed archives alone**. This has been true since PR #40; it is now
  stated where consumers look, with the supported variable-base
  building-block path and the comb add-on link recipe (`points256_comb.o`
  + `data_p256_limlee.o`, or the full `nistcurves.a`) and its boot cost
  (`ec_precompute_*` ~25 s / ~80 s at 1 MHz).
- **`make check-archives` ratchet + `tools/check_archives.py`.** An od65
  import/export closure sweep plus `ld65` dummy-link smoke tests per
  archive, checked against a documented per-archive allowlist of
  deliberate gaps. Fails if reality drifts *looser* (a new unresolved
  symbol) or *tighter* (a documented gap that unexpectedly resolves).
  python3 stdlib only; no VICE.
- **Follow-ups filed:** #61 (a variable-base `u1·G` fallback so the
  trimmed archives can host a self-contained verify) and #63 (relocate the
  test-only trampoline out of `ecdsa384_msg.o`, which makes
  `ecdsa_verify_with_message_384` unlinkable even from the full archive).

### Tooling / research — REU multiply-table audit (PR #58)

- **Committed the REU multiply-table footprint/ROI audit**
  (`.research/reu_mult_audit_2026_05_21/report.md`) + measurement tool
  `tools/bench_reu_mult.py`. Verdict: keep the 128 KB table (~2× `fp_mul`
  speedup vs the no-table alternative; REU banks 0–1 otherwise idle).
- **Corrected the CLAUDE.md per-row DMA-cost claims.** The prior "20
  cycles per row / <1% of `fp_mul`" figures counted only the register
  setup head. Measured full row fetch is **~542 cy** (20 cy setup + ~512
  cy DMA cycle-steal stall); DMA is **~23% of `fp_mul`** / ~18% of
  `fp_mul_384`. Docs/tooling only.

See [`CHANGELOG.md`](../CHANGELOG.md) `## [0.4.0]` for the complete
per-bullet list.

## Upgrade notes for consumers

- **Semver minor bump; `LIB_ABI_VERSION` stays `0`.** All public entry
  points (`ec_scalar_mul_var`, `ecdsa_verify_*`, `ec_point_add`,
  `ec_point_add_jj`, `ec_point_double`, `fp_mod_mul_n`, `fp_reverse*`,
  `sha384_*`, `ec_scalar_mul`, …) are unchanged in calling convention. Per
  issue #54's own definition-of-done the BSS trim is treated as
  additive/MINOR.
- **Removed / relocated scratch exports (honest compatibility note).** The
  issue #54 trim deleted the exports `fp_r1`, `fp_r2`, `fp_r3`,
  `fp_inv_iter`, `fp_red_tmp` from `data_p256.o`, and moved `fp_tmp2..4`
  to a non-archive test object. These were **undocumented internal field
  scratch** slots, verified unreferenced by any consumer, tool, or library
  `.s` source — they were never part of the documented API surface, so
  `LIB_ABI_VERSION` was **not** bumped. A consumer that had reached into
  these private slots (unsupported) would need to allocate its own scratch;
  no supported integration is affected.
- **`LIB_VERSION_MINOR` is now `4`** in `src/lib_version.s`. Update any
  `.if LIB_VERSION_MINOR < … / .error` compatibility gates.
  `LIB_ABI_VERSION` remains `0`.
- **New `LIB_NISTCURVES_P256_INVREF_BSS` segment.** The `fp_tmp1` slot for
  the reference Fermat inverter (`inv256.o`) now lives in its own segment.
  Consumers linking the **full** archive or standalone PRG may need to add
  this segment to their `.cfg` (map it to any RAM region; it is only
  populated when `inv256.o` is linked). It is **optional** — the trimmed
  verify archives do not include `inv256.o` and therefore never reference
  it.
- **`LIB_NISTCURVES_SHARED_PRIMITIVES` changed form.** It moved from an
  unconditional `$0003` (sqtab | reu_mul) to the SPEC §8.0 **conditional**
  mask: standalone `$0007` (sqtab | reu_mul | ct_mul_8x8), with each bit
  dropping when the corresponding deferral switch is defined. Consumers
  that `.assert` on the AND of sibling masks being zero continue to work;
  consumers that hard-compared the literal value must update their
  expected constant.
- **`LIB_NISTCURVES_P256_BSS` extent is now 1312 B** (was 1573 B). Consumer
  `.cfg` fit checks against `__…_SIZE__` gain 261 B of headroom.
- **Archive linkability (API.md §8.4.1).** New consumers building against a
  trimmed `lib-p256-verify` / `lib-p384-verify` archive must drive the
  variable-base building blocks (`ec_scalar_mul_var` + `ec_point_add_jj` +
  `fp_mod_inv` + `fp_mod_mul_n`) directly, or link the comb add-on
  (`points256_comb.o` + `data_p256_limlee.o`) / the full `nistcurves.a` to
  use the packaged `ecdsa_verify_*`. Run `make check-archives` to validate
  a custom object set against the contract.

## Tarball

`c64-nist-curves-v0.4.0.tar.gz` is produced reproducibly by
`make dist VERSION=v0.4.0`. Canonical artifact:

- Size:   _TBD (filled in at tag time — see note below)_
- SHA256: _TBD (filled in at tag time — see note below)_

Re-running `make dist VERSION=v0.4.0` against the tag must reproduce the
recorded SHA256 byte-for-byte (`git archive` is deterministic; `gzip -n`
drops the gzip timestamp header). The canonical vendoring file list lives in
`tools/build_release.sh`; if you add a new `src/*.s` file, update both the
`MODULES` list in `Makefile:19` AND the `git archive` invocation in
`tools/build_release.sh`.

**Why Size/SHA256 are filled at tag time.** This release notes file is
itself vendored into the tarball, so writing the SHA256 into it would change
the tarball's SHA256 — a hash fixed-point that cannot be solved by direct
computation. As with v0.3.0 (commit `3fb2155`), the tag is applied with these
two lines as `_TBD_` placeholders, then the measured values from a
reproducible `make dist VERSION=v0.4.0` against the tag are spliced in a
follow-up commit (which is *not* part of the tagged tarball, so the recorded
SHA stays valid for the published artifact). The v0.4.0 file-list adds
`src/data_p256_invref.s`, `tools/check_archives.py`, and
`tools/bench_reu_mult.py` to the vendored set.

## Verification

- **Build:** `make clean && make` → `build/nist-curves.prg` = **37171 B**
  (down from 37302 B at v0.3.0 via the issue #54 BSS trim). The v0.4.0
  release-prep version-equate changes (`VERSION`, `LIB_VERSION_MINOR`,
  the `lib_manifest.s` comment) do not alter emitted bytes: the built PRG
  is **byte-identical** (sha256) to master at the release-prep base.
- **`make check-archives`:** PASS — all five archives
  (`lib`, `lib-p256-verify`, `lib-p384-verify`, `lib-p384-sha384`,
  `lib-p384-curve`) match the documented per-archive symbol contract.
- **`make dist VERSION=v0.4.0`:** reproducible — two back-to-back builds
  produce a byte-identical tarball (SHA recorded at tag time per the note
  above).
- **VICE oracle-gated test suites:** not re-run for this release-prep PR —
  it contains no runtime code changes (version equates + docs + build
  metadata only; PRG byte-identical to master). The v0.3.0 suite results
  (1082/1082) carry forward; the source that produces the verify/point/SHA
  paths is unchanged.

## Cross-references

- [c64-lib-contract](https://github.com/JC-000/c64-lib-contract) — the
  umbrella SPEC this release completes §8 adoption against (v0.4.0 §8.0
  conditional mask / §8.2 reu_mul / §8.3 ct_mul_8x8).
- This release's PRs against the c64-nist-curves repo: #55 (§8.2 reu_mul +
  §8.0 catch-loop), #56 (canonical `ct_mul_8x8` body), #57 (§8.3 manifest
  bit + conditional mask), #58 (REU multiply-table audit + DMA-cost
  correction), #59 (issue #54 BSS trim), #62 (issue #60 archive contract +
  `check-archives`).
- Follow-up issues: #61 (variable-base `u1·G` fallback for trimmed
  archives), #63 (relocate the test-only trampoline out of
  `ecdsa384_msg.o`).
