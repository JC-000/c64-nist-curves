# c64-nist-curves v0.6.0 — Release Notes

Released 2026-07-20. Compared to v0.5.0 (2026-07-20).

This is a MINOR release. v0.6.0 upgrades the `FP_ONCHIP_MUL` turbo
profile's row generator to an inline quarter-square (issue #71, "shape
2"), roughly a further 26% faster at every clock speed, and
runtime-proves the zero-REU verify configuration introduced in v0.5.0.

No public entry points were removed or renamed; `LIB_ABI_VERSION`
remains `0`. The default build profile is unchanged — the standalone
PRG is byte-identical to v0.5.0's (and v0.4.0's).

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md)
`## [0.6.0]`; this file is the concise release summary.

## What's new

### Inline quarter-square row generation (issue #71)

The turbo profile's `og_common` row generator no longer pays the
`jsr ct_mul_8x8` protocol per product (~134 cycles including operand
reloads); it computes each product with an inline, non-constant-time
quarter-square (~70 cycles: SMC-baked `a`, `X = |a−v|` difference
index, `Y` = sum index with a sum-page branch). The canonical §8.3
`ct_mul_8x8` body is untouched — it still computes the per-row diagonal
product, and the cross-adopter byte-identity gate is unaffected.

Measured same-run A/B on C64 Ultimate hardware (16/48/64 MHz,
oracle-gated; the v0.5.0 shape rebuilt byte-identical from its tag as
the reference):

| `ecdsa_verify_256` wall | 16 MHz | 48 MHz | 64 MHz |
|---|---|---|---|
| default (REU DMA table) | 37.9 s | 28.2 s | 25.5 s |
| turbo v0.5.0 (shape 1)  | 62.9 s | 21.4 s | 16.0 s |
| **turbo v0.6.0 (shape 2)** | 46.4 s | **15.8 s (1.78×)** | **11.8 s (2.16×)** |

`ecdsa_verify_384` @64 MHz: 62.0 → 39.1 s (1.59×). Profile crossovers
vs the DMA-table default drop to **~22 MHz (P-256) / ~33 MHz (P-384)**
(from ~30/~55 in v0.5.0); the stock-1 MHz penalty shrinks to ~2.5×.
The DMA-table profile remains the default and the right choice at or
near stock clocks. Raw data: `.research/issue71_shape2_2026_07_20/`.

### Zero-REU operation runtime-validated

New `make onchip-nocomb-prg` builds the `FP_ONCHIP_MUL +
ECDSA_NO_COMB` test PRG — the exact configuration of the
`*-verify-onchip` archives — and `tools/test_ecdsa_verify.py` grew a
`C64_NO_REU=1` switch that launches VICE with no REU at all. The full
oracle suite passes **35/35 with no REU in the machine** (RFC 6979 +
CAVP SigVer positives and negatives + the hash-then-verify wrapper),
converting v0.5.0's link-level zero-REU claim into a runtime-proven
one: packaged ECDSA verify runs on a stock, expansion-less C64.

### Tooling fix

`tools/ct_mul_brute_check.py` had been silently broken since the
2026-06-19 §8.3 verbatim adoption: its test shim still used the
pre-§8.3 register calling convention, so it reported 65535/65536
mismatches against a correct `mul_8x8` (the observed values were the
canonical body correctly multiplying stale-baked inputs). The shim now
uses the canonical convention (`Y = b`, caller bakes
`smc_sum_a_imm+1` / `smc_diff_a_imm+1`): **PASS 65536/65536**.

## Artifact

| | |
|---|---|
| Tarball | `c64-nist-curves-v0.6.0.tar.gz` |
| Size | `TBD_SIZE` bytes |
| SHA256 | `TBD_SHA256` |

Reproducible via `make dist VERSION=v0.6.0` at tag `v0.6.0`
(byte-identical re-runs verified).

## Upgrade notes / compatibility

- Default-profile consumers: no action. Archives, symbols, ZP,
  segments, manifest values, and the standalone PRG are unchanged.
- Turbo-profile consumers: relink against the rebuilt `*-onchip.a`
  archives to pick up the faster row generator; no interface or
  manifest changes (`REU_BANKS_USED = $04`, resident/cold values
  unchanged from v0.5.0). Boot obligation unchanged (`sqtab_init`
  only).
- The row generator remains NOT constant-time (as before): public
  verify inputs only; do not repurpose for signing.
