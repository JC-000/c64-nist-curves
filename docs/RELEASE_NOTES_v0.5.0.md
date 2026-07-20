# c64-nist-curves v0.5.0 — Release Notes

Released 2026-07-20. Compared to v0.4.0 (2026-07-17).

This is a MINOR release. v0.5.0 ships the **FP_ONCHIP_MUL turbo profile**
(issue #69) — a second, parallel build profile of the field layer for
accelerated hosts (Ultimate 64 / C64 Ultimate turbo, SuperCPU-class) where
the REU's ~1 MHz-anchored DMA makes the multiply-table row fetch a
speed-invariant wall-clock floor — and completes the archive-linkability
arc (issues #60/#61/#63): every published archive is now link-complete,
with the verify archives shipping `-D ECDSA_NO_COMB` packaged verifiers.

No public entry points were removed or renamed; `LIB_ABI_VERSION` remains
`0`. The default build profile is unchanged — the standalone PRG is
byte-identical to v0.4.0's.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md) `## [0.5.0]`;
this file is the concise release summary.

## What's new

### FP_ONCHIP_MUL turbo profile (issue #69)

Measured on a C64 Ultimate (fw 1.1.0) across a 16/48/64 MHz turbo sweep,
`ecdsa_verify_256` carries a **22.2 s speed-invariant floor** — 87% of its
25.5 s wall time at 64 MHz — because REU DMA transfers at the ~1 MHz bus
rate regardless of CPU speed. `ecdsa_verify_384`'s floor is 51.7 s.
Quadrupling the CPU clock improves verify wall time by only ~1.5×.

The turbo profile (`-D FP_ONCHIP_MUL`) replaces all six REU row-fetch
sites in `fp_mul` / `fp_sqr` (both curves) with sparse on-chip row
generation via the canonical §8.3 `ct_mul_8x8` (body untouched — the
cross-adopter byte-identity gate is unaffected). Only the `mul_dma_lo/hi`
entries the inner loops actually read are computed; the 4×-unrolled inner
loops, SMC accumulators, and sparse zero-byte fast path are byte-identical
to the default profile.

Measured, oracle-gated, on C64 Ultimate hardware:

| `ecdsa_verify_256` wall | 16 MHz | 48 MHz | 64 MHz |
|---|---|---|---|
| default (REU DMA table) | 37.9 s | 28.2 s | 25.5 s |
| turbo (`FP_ONCHIP_MUL`) | 62.9 s | 21.4 s | **16.0 s (1.60×)** |

Crossovers: ~30 MHz (P-256), ~55 MHz (P-384). At stock 1 MHz the default
DMA-table profile remains ~3× faster — the turbo profile is a complement,
not a replacement. Correctness: full oracle ECDSA suite 35/35 against the
onchip test PRG, including NIST CAVP SigVer negative vectors.

**New build targets:**

- `make lib-onchip` → `nistcurves-onchip.a` (full library, turbo field layer)
- `make lib-p256-verify-onchip` → `nistcurves-p256-verify-onchip.a`
- `make lib-p384-verify-onchip` → `nistcurves-p384-verify-onchip.a`
- `make lib-p384-curve-onchip` → `nistcurves-p384-curve-onchip.a`
- `make onchip-prg` → variant test PRG for the oracle suite

The verify-onchip archives issue **no REU DMA at all** (the comb is also
excluded per issue #61), and the consumer boot obligation shrinks to
`sqtab_init` only — no SPEC §8.2 `reu_mul` provider, no `ec_precompute_*`.
The onchip manifest (`lib_manifest_onchip.o`) reports the profile-aware
SPEC §5 equates: `LIB_NISTCURVES_REU_BANKS_USED = $04`,
`RESIDENT_BYTES = 28200`, `COLD_BYTES = 1900`. See API.md §8.4.2.

### Archive linkability closure (issues #61 / #63)

- `ecdsa_verify_with_message_384` links from consumer archives: the
  test-only trampoline moved out of `ecdsa384_msg.o` into the
  never-archived `main.s` (issue #63).
- The verify / curve archives ship `-D ECDSA_NO_COMB` packaged verifiers:
  `u1·G` routes through the variable-base ladder seeded at G, so
  `ecdsa_verify_256` / `ecdsa_verify_384` /
  `ecdsa_verify_with_message_384` link standalone without the Lim-Lee
  comb objects (issue #61). Trade-off: a verify costs roughly two
  variable-base scalar multiplies (up to ~2× slower) but drops the comb
  boot pass and REU bank-2 residency.
- `make check-archives` ratchet now pins the contract for **all nine
  archives** (five default-profile + four onchip); reality drifting
  looser or tighter than API.md §8.4.1/§8.4.2 fails the build.

### Tooling

- `tools/bench_u64_common.py` accepts 64 MHz turbo (C64 Ultimate
  fw 1.1.0+; U64E firmware rejects it at set time).
- `tools/test_ecdsa_verify.py` honors `C64_INIT_TIMEOUT` for variant PRGs
  that boot slower under VICE warp.

## Artifact

| | |
|---|---|
| Tarball | `c64-nist-curves-v0.5.0.tar.gz` |
| Size | 156655 bytes |
| SHA256 | `a0f7f05a30afc7c204b1fad433478583849d2673f9a0d795b729ef415a50a03e` |

Reproducible via `make dist VERSION=v0.5.0` at tag `v0.5.0` (byte-identical
re-runs verified).

## Upgrade notes / compatibility

- Default-profile consumers: no action. Archives, symbols, ZP, segments,
  and the standalone PRG are unchanged from v0.4.0.
- Turbo-profile adopters: link a `*-onchip.a` archive instead of its
  default counterpart. Do not mix profiles in one link (the field objects
  export the same symbols). Boot: call `sqtab_init` before any field op;
  `reu_mul_init` is unnecessary (harmless if called). The profile is
  NOT constant-time, same as the default verify path — public inputs only.
- The onchip manifest values differ (see above); consumer `.assert`s
  keyed on `LIB_NISTCURVES_REU_BANKS_USED = $07` should switch to the
  profile-aware values when adopting the turbo archives.
