# c64-nist-curves v0.8.0 — Release Notes

Released 2026-07-28. Compared to v0.7.0 (2026-07-25).

This is a MINOR release. v0.8.0 makes the consumer archives honest:
the SPEC §8.2 `reu_mul` provider (`reu_mul_init` /
`reu_mul_tables_init`) now actually ships in the default-profile
archives (issue #81), the FP_ONCHIP_MUL archives stop claiming §8.0/§8.2
ownership they don't exercise (issue #78), and the reference docs were
brought back in sync with the shipped build (issue #77 — the API.md §2
memory map was ~$3000 stale) with the turbo/onchip performance claims
scoped to their measurement device (issue #83 part 2).

No public entry points were removed or renamed; archives gained
newly-linkable public symbols and §5 manifest equate VALUES changed, so
this is MINOR with `LIB_ABI_VERSION` unchanged at `0`. The standalone
PRG stays 37683 B (not byte-identical — issue #81 reorders the boot
window; see CHANGELOG).

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md)
`## [0.8.0]`; this file is the concise release summary.

## What's new

### SPEC §8.2 provider ships in the default-profile archives (issue #81 / PR #82)

`reu_mul_init` / `reu_mul_tables_init` moved from the never-archived
`src/main.s` into the new `src/reu_mul_init.s` and joined
`LIB_MUL_OBJS`, so `nistcurves.a` and the p256-verify / p384-verify /
p384-curve archives now contain the provider. Before this, API.md §3
made `jsr reu_mul_init` mandatory at boot yet **no archive contained
the symbol** — an unresolved external for every archive consumer — and
the §8.0 ownership bit `$0002` claimed by `lib_manifest.o` was
untruthful in every archive. The FP_ONCHIP_MUL archives and
`lib-p384-sha384` deliberately do NOT gain the object (onchip never
builds or reads the REU multiply table; verify-onchip stays
zero-REU-DMA). `check_archives.py` ratchets both directions.

### FP_ONCHIP_MUL manifest alignment (issue #78 / PR #80)

Onchip builds no longer claim the §8.2 `reu_mul` ownership bit —
`LIB_NISTCURVES_SHARED_PRIMITIVES` is `$0005` standalone under the
profile (was `$0007`), guarded by a permanent `.assert` — and the
onchip archives no longer enumerate the `reu_mul` precalc table
(`precalc_manifest_onchip.o`). §5 accounting was refreshed against
v0.7.0 labels; combined with the issue #81 re-baseline the net
movement this release is `COLD_BYTES` **2500 → 1800** (and
resident/cold profile split 28200/1900 → shared 27000/2000 at the #78
step). This resolves the tidy flagged in the v0.7.0 release notes
("`RESIDENT_BYTES` / `COLD_BYTES` are approximate and were not
re-baselined"). Default PRG byte-identical at this step.

### Post-v0.7.0 docs currency sweep (issue #77 / PR #79)

Docs-only, PRG byte-identical. API.md §2 memory map regenerated from
`build/labels.txt` at v0.7.0 — the previous table was ~$3000 stale
(`mul_dma_lo/hi` are at `$7B00`/`$7C00`, not `$4B00`/`$4C00`), and the
map is now symbol-anchored with `build/labels.txt` named authoritative.
"Running without an REU" is now discoverable (README Requirements,
API.md §1 carve-out, profile-conditional init/REU obligations in
§3/§8.3/§8.5). Stale file names, ZP footprint counts, version-pin
examples, and the §8.4.1 archive table were refreshed; the SPEC §8.0
precalc manifest is referenced from API.md §8.6.1.

### Turbo/onchip claim scoping (issue #83 part 2 / PR #85)

Docs-only, PRG untouched. The FP_ONCHIP_MUL floor and crossover figures
(22.2 s / 87% of wall @64 MHz, crossovers ~22 MHz P-256 / ~33 MHz
P-384) in README, API.md §8.4.2, and CLAUDE.md are now explicitly
scoped to their C64 Ultimate fw 1.1.0 measurement. Cross-device data
from the c64-x25519 onchip hardware gate shows the per-row REU DMA
stall is a firmware/generation-dependent wall-clock constant (~160
wall-ticks C64U fw 1.1.0 vs ~189 U64E fw 3.14 per 512 B row; 532 cy on
real-1750/VICE), so floors and crossovers do not transfer across
devices or workloads; "real 1750 + accelerator" figures are labeled
projections. No numeric claim changed.

## Artifact

| | |
|---|---|
| Tarball | `c64-nist-curves-v0.8.0.tar.gz` |
| Size | 171068 bytes |
| SHA256 | `afad80342f8c747793f0502939cdbb439adf107e79d0fedd8269bcfc08c77145` |

Reproducible via `make dist VERSION=v0.8.0` at tag `v0.8.0`
(byte-identical re-runs verified).

## Upgrade notes / compatibility

- **No source changes needed.** No symbols were removed or renamed;
  `LIB_ABI_VERSION` remains `0`. Existing consumer link lists and boot
  sequences keep working — archive consumers who previously had to
  vendor `reu_mul_init` from the standalone tree can now drop that
  workaround and take the symbol from the archive.
- **Manifest equate VALUES changed.** Consumers that `.import` and
  `.assert` against `LIB_NISTCURVES_COLD_BYTES` (2500 → 1800 net),
  `LIB_NISTCURVES_RESIDENT_BYTES`, or — under `-D FP_ONCHIP_MUL` —
  `LIB_NISTCURVES_SHARED_PRIMITIVES` (`$0007` → `$0005`) must update
  their pinned values. The equate NAMES and semantics are unchanged.
- **Onchip archive consumers:** the `-onchip` archives no longer export
  the `reu_mul` precalc-table row or the §8.2 ownership bit — sibling
  libraries that genuinely ship a §8.2 provider no longer trip the
  consumer disjointness `.assert` spuriously.
- Standalone PRG is 37683 B as in v0.7.0 but not byte-identical (boot
  window reordered by the issue #81 move); everything from
  `fp_copy $0B21` up is address-identical.
- The verifiers remain NOT constant-time (public verify inputs only);
  do not repurpose for signing.
