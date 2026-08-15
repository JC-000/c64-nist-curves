# c64-nist-curves v0.11.1 — APP_OWNED × onchip reachable + measured precompute cost

**Released:** 2026-08-15
**Tarball:** `c64-nist-curves-v0.11.1.tar.gz` (SIZE_PLACEHOLDER bytes)
**SHA256:** `SHA256_PLACEHOLDER`

PATCH release. `build/nist-curves.prg` is **byte-identical** to
v0.10.0 through v0.11.0 (`18701274…`, 37480 B); `LIB_NISTCURVES_ABI_VERSION`
stays **2**; every §8.3-**owning** archive is byte-unchanged. Two
consumer-reported defects fixed (issues #121, #123 — both filed from the
c64-https consumer side, both same-day).

## `-D SHARED_CT_MUL_8X8` now assembles against the on-chip TU (issue #123)

`og_common` calls the canonical `ct_mul_8x8` at runtime (the per-row `a*a`
diagonal product) and SMC-bakes `a` into the body's two `smc_*_a_imm`
sites; the §8.3 deferral gate removed those definitions without importing
them, so every onchip target failed to assemble under the switch —
**APP_OWNED × onchip was unreachable** through §6.1 targets + §6.2 defines
(SPEC §6.3). Fixed: under `SHARED_CT_MUL_8X8` + `FP_ONCHIP_MUL` the TU now
**imports** the five-symbol §8.3 provider surface (`ct_mul_8x8`,
`smc_sum_a_imm`, `smc_diff_a_imm`, `poly_prod_lo`, `poly_prod_hi`) instead
of defining it. Both repro commands from the issue build; the
previously-working REU deferral combination is regression-checked.

**One deliberate surface change, flagged prominently:** the
`poly_prod_lo/hi` product cells moved **inside** the deferral gate — a
deferring build's runtime callers must read the cells the *provider's*
body writes (a private exported pair would hand `og_common` stale zeros
for every diagonal, or collide at link with an exporting owner; both fleet
providers export the pair, and c64-x25519's deferring arm already imports
it). Consequently `nistcurves-app-owned.a` now carries `poly_prod_lo/hi`
as **documented unresolved externals** — the app's §8.3 provider supplies
them, as every real provider already does. If your APP_OWNED integration
relied on the archive's own `poly_prod` export while providing the §8.3
body elsewhere, that configuration was silently mis-wired (the body you
supplied was writing cells `og_common` never read); the link error you may
now see at the fix is the defect becoming visible. All ten §8.3-owning
archives still export the full surface, now pinned by `make
check-archives`, which also gains a §6.3 reachability leg assembling
APP_OWNED × both profiles (negative-tested).

## `ec_precompute_*` boot cost measured — docs were ~40-86× low (issue #121)

VICE warp-mode *wall* seconds had been documented as real-C64 time since
Wave 7a. Measured via the KERNAL jiffy clock (VICE, NTSC, VIC blanked):

| profile | `ec_precompute_256` | `ec_precompute_384` |
|---|---|---|
| default (REU DMA) | **1038 Mcyc ≈ 17 min @1 MHz** | **2108 Mcyc ≈ 34 min** |
| `FP_ONCHIP_MUL` | **2061 Mcyc ≈ 34 min** | **4782 Mcyc ≈ 78 min** |

Only the onchip cost scales with the host clock (~45 s @48 MHz
consumer-measured); the default profile's REU row fetches are
wall-clock-anchored at turbo (issue #83). Corrected across API.md (§8.5 is
now a per-profile table with a consumer amortisation note), README,
CLAUDE.md, the source comment, and the v0.11.0 release notes (annotated).
**Re-size your comb-vs-verify archive choice against §8.5 if the old
figures informed it** — at stock 1 MHz the comb fill amortises only over
multiple verifies.

## Upgrading from v0.11.0

- Not using `SHARED_CT_MUL_8X8`: no action; every owning archive is
  byte-unchanged. Pin **v0.11.1**.
- Using APP_OWNED (any profile): your §8.3 provider must export
  `poly_prod_lo/hi` alongside `ct_mul_8x8` and the two SMC sites (both
  fleet providers already do).
- Onchip + deferral consumers (the blocked c64-https images): the glue-TU
  workaround can be retired; `-D SHARED_CT_MUL_8X8` is sufficient.

## Verification

- PRG byte-identical to v0.11.0: `18701274…`, 37480 B.
- `make check-archives` PASS (12 archives; new §8.3 provider-surface pins
  + §6.3 APP_OWNED×profile reachability legs, both negative-tested).
  `make check-docs` PASS.
- Tarball reproducible across two independent `make dist` runs.
- Worktree-rebuild byte-identity at the tag: WORKTREE_PLACEHOLDER
- Tarball builds standalone: TARBALL_BUILD_PLACEHOLDER
