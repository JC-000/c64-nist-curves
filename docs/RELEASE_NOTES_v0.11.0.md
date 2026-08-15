# c64-nist-curves v0.11.0 — P-256 comb archives + vic_blank figure correction

**Released:** 2026-08-15
**Tarball:** `c64-nist-curves-v0.11.0.tar.gz` (238,482 bytes)
**SHA256:** `251c5d12f6ad59bf54108ae1f6606a75fa5340f76d1117c89061338d148e9abe`

MINOR release. `build/nist-curves.prg` is **byte-identical** to
v0.10.0/v0.10.1/v0.10.2 (`18701274…`, 37480 B); no exported symbol is
removed or renamed; `LIB_NISTCURVES_ABI_VERSION` stays **2**. The MINOR
bump is for the additive consumer surface: two new archive targets and
one new variant switch.

## P-256 comb archives (issue #117)

Two new SPEC §6.1 targets make the comb-accelerated P-256 verify set —
the fastest verify configuration this library offers (consumer-measured
12.4 s @64 MHz on a C64 Ultimate vs 22.9 s no-comb onchip) — reachable
without member surgery:

| Target | Archive | Profile |
|---|---|---|
| `make lib-p256-comb` | `nistcurves-p256-comb.a` | DMA multiply table |
| `make lib-p256-comb-onchip` | `nistcurves-p256-comb-onchip.a` | on-chip multiply |

Member set = the `lib-p256-verify[-onchip]` set with the comb-fast
`ecdsa256.o` in place of `ecdsa256_nocomb.o`, plus `points256_comb.o` +
`data_p256_limlee.o`. No P-384 or SHA-384 members. Previously this
configuration was reachable only by building the full archive and
deleting members by hand — non-conformant per SPEC §6.1 (an edited
member set is outside every §5/§8.0 manifest claim it ships), and the
reason c64-https had to exclude the comb profile from its §6.6 asserts
(c64-https#119).

Both archives carry their own §6.4 manifest triple, gated by the new
`LIB_P256_COMB_ONLY` variant switch and measured from the built objects.
The `lim_lee_comb_*` precalc rows now gate **per curve**, so the archive
enumerates its own 16 KB P-256 table without advertising the 24 KB P-384
one it lacks. Boot obligation vs the verify archives grows by
`ec_precompute_256` (~25 s at 1 MHz), and REU bank 2 gains the 16 KB
anchor table **in both profiles** — the onchip arm still populates and
DMA-fetches comb anchors; it is the multiply table it does without.

> **Correction (2026-08-15, issue #121):** the paragraph above originally
> quoted the `ec_precompute_256` boot cost as "~25 s at 1 MHz", inherited
> from API.md §8.5. That figure was ~40× low — VICE warp-mode *wall*
> seconds had been passed off as real-C64 time since Wave 7a. Measured
> (jiffy clock, VICE): **~1038 Mcyc ≈ 17 min at 1 MHz** in this archive's
> default profile; the onchip arm measures ~2061 Mcyc ≈ 34 min at 1 MHz
> but scales with the host clock (~45 s at 48 MHz, consumer-measured). At
> stock clock the
> comb fill amortises only over multiple verifies — see API.md §8.5's
> sizing note before picking a comb archive for a 1 MHz target.

## Footprint values, per (profile × variant) — SPEC §6.6 obligation

All ten pre-existing archives: **unchanged** in every §5/§6.6 equate.
The two new archives declare:

| archive | `ZP` | `REU banks` | `RESIDENT_BYTES` | `COLD_BYTES` | masks (own/consume) |
|---|---:|---|---:|---:|---|
| `nistcurves-p256-comb.a` | 17 | `$07` | 9216 | 1050 | `$0007`/`$0007` |
| `nistcurves-p256-comb-onchip.a` | 17 | `$04` | 9216 | 870 | `$0005`/`$0005` |

Derivations: ZP is the verify 9 slots + `nistcurves_zp_ptr1` (the
`ec_precompute_256` anchor-copy pointer; **not** `zp_tmp1`/`zp_tmp2`,
whose only archived user is the P-384 comb) — od65 import-union over the
members. RESIDENT measured 8991 (DMA) / 9094 (onchip); 1.1% apart, so
variant-shared per §5's ±5% band, declared at the §6.6 next-256-boundary
above the larger measurement. COLD is the verify cold set +
`ec_precompute_256`'s 616 B, measured 1045 / 859, declared fine-grained
≥ measured (the 256-boundary convention would breach ±5% at this size).

## Also in this release

- **vic_blank speedup figure corrected** (issue #116): ~20-25% → ~6.3%
  NTSC / ~5.5% PAL on the plain text screen the harness runs. The old
  figure misread the ~40-43 cycle VIC-II steal as per-rasterline when it
  is per-badline (one per character row). Established by measurement +
  badline arithmetic in c64-x25519#103. Comment/doc-only.
- **check-archives coverage grows to 12 archives**: member sets, §5
  value pins, the R2 ZP address-union arm for `zp_config_p256comb`,
  per-curve precalc rows, and comb-fast linkability
  (`ecdsa_verify_256` + `ec_scalar_mul` + `ec_precompute_256` link from
  the archive alone) — negative-tested (a mis-pinned value and a
  falsely-required export both trip).

## Upgrading from v0.10.2

Every existing entry point, export, archive, and buffer layout is
unchanged — the PRG is byte-identical and ABI stays 2. No action needed
unless you want the new targets. Comb-speed packaged P-256 verify:
link `nistcurves-p256-comb.a` (stock/1 MHz-class hosts) or
`nistcurves-p256-comb-onchip.a` (turbo hosts, ~22 MHz+ crossover). Pin
**v0.11.0**.

## Verification

- PRG byte-identical to v0.10.2: `18701274…`, 37480 B.
- All twelve archives build; `make check-archives` PASS (incl. §1
  identity check at 0.11.0, R2 ZP alias audit over six arms, gated
  surface, per-archive value pins). `make check-docs` PASS.
- Tarball reproducible across two independent `make dist` runs.
- Worktree-rebuild byte-identity at the tag: PASS (fresh worktree at
  v0.11.0: PRG `18701274…` identical; check-archives PASS inside it).
- Tarball builds standalone: PASS (extracted to a scratch directory,
  `make` produces the byte-identical PRG and check-archives passes over
  all twelve archives — completeness proven by construction).
