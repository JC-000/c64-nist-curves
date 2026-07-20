# Issue #71 — shape-2 inline quarter-square + zero-REU validation

**Date:** 2026-07-20
**Device:** C64 Ultimate (fw 1.1.0), same as `.research/issue69_onchip_2026_07_19/`.
**Method:** back-to-back same-run A/B, `bench_ecdsa_u64.py --speeds 16,48,64`:
shape-1 PRG rebuilt byte-identical from tag `v0.5.0` (worktree; sha
`f164b118…` reproduced), then shape-2 PRG. All 30 measurements
oracle-gated; zero UNVERIFIED/TIMEOUT. Shape-1's rows reproduced the
2026-07-19 sweep within 1–3 jiffies at every speed.

## What changed

`og_common` (src/mul_8x8.s, FP_ONCHIP_MUL only): the per-product
`jsr ct_mul_8x8` (~134 cy including reload overhead) is replaced by an
inline non-CT quarter-square (~70 cy): SMC-baked `a`, X = |a−v| diff
index, Y = sum index with a sum-page branch, store via Y = v. The
canonical §8.3 `ct_mul_8x8` body is untouched (still used for the
per-row diagonal product); default PRG byte-identical (`09cf7008…`).

Collateral fix: `tools/ct_mul_brute_check.py` had been silently broken
since the 2026-06-19 §8.3 verbatim adoption — its $C000 shim still used
the pre-§8.3 register convention (A=a / X=b), so every pair "mismatched"
with stale-bake artifacts (measured `$06f9`/`$f708` = 255×7 / 255×248,
the |a−b| feedback 2-cycle of the canonical body — i.e. mul_8x8 was
computing *correctly* on garbage inputs). Fixed to the canonical
convention (Y=b, caller bakes `smc_sum_a_imm+1`/`smc_diff_a_imm+1`):
**PASS 65536/65536**.

## A/B results (1-MHz-equivalent wall seconds)

| Routine | MHz | default (DMA) | shape 1 (v0.5.0) | shape 2 | s2 vs default |
|---|---|---|---|---|---|
| ecdsa_verify_256 | 16 | 37.9 | 62.9 | 46.4 | 0.82× (slower) |
| | 48 | 28.2 | 21.4 | 15.8 | **1.78×** |
| | 64 | 25.5 | 16.0 | **11.8** | **2.16×** |
| ecdsa_verify_384 | 16 | 98.7 | 211.5 | 153.8 | 0.64× |
| | 48 | 69.2 | 72.0 | 52.3 | 1.32× |
| | 64 | 62.0 | 53.7 | **39.1** | **1.59×** |
| ec_scalar_mul_var | 64 | 22.2 | 13.9 | 10.3 | 2.16× |
| ec_scalar_mul_var_384 | 64 | 53.4 | 46.3 | 33.6 | 1.59× |

Shape-2/shape-1 ratio is a uniform **0.74× at every speed** — the
expected signature of a pure CPU-side change in a DMA-free profile.

Fits (shape 2): verify_256 C ≈ 743 Mcy, residual floor ≈ 0.3 s;
verify_384 C ≈ 2461 Mcy. **Crossovers vs the DMA-table default:
~22 MHz (P-256), ~33 MHz (P-384)** (were ~30/~55 at shape 1). Stock
1 MHz penalty shrinks to ~2.5× (was ~3×).

The ~11.8 s measured vs the ~8 s issue-#71 projection: the projection
assumed ~50 cy/product; the realized inline is ~70 cy (page-branch +
store-index reload overhead). Remaining headroom would need loop
restructuring (e.g. product caching or dedupe), diminishing returns.

## Zero-REU runtime validation

`make onchip-nocomb-prg` (FP_ONCHIP_MUL + ECDSA_NO_COMB, the
verify-onchip archive configuration) run under VICE with **no REU
configured** (`C64_NO_REU=1` → `+reu`): boots clean (the boot-time REU
writes vanish into open bus; no polling hangs — the comb code's REU
register read-backs are scratch arithmetic, not status polls) and the
full oracle suite passes **35/35**, including CAVP SigVer negatives and
the hash-then-verify wrapper. The v0.5.0 zero-REU claim is now
runtime-proven, not just link-level.

## Files

- `bench_71_s1.log` / `bench_71_s2.log` — back-to-back A/B sweeps
- Suite logs (session scratchpad): shape-2 35/35, zero-REU 35/35
