# Issue #69 — REU row-fetch DMA turbo floor + FP_ONCHIP_MUL A/B

**Date:** 2026-07-19/20
**Device:** C64 Ultimate (`c64-ultimate-500434`, fw 1.1.0, core 1.49) — first
use of the 64 MHz turbo step (harness `CPU_SPEED_VALUES` includes `"64"` for
this generation; U64E firmware rejects it).
**Method:** `tools/bench_ecdsa_u64.py --speeds 16,48,64`, two back-to-back
cold-boot invocations (baseline PRG then `--prg build/nist-curves-onchip.prg`),
every routine oracle-gated. Three-point least-squares fit `wall = F + C/f`
(`fit_floor.py` + `sweep_run2.json`); the debug bus-stream is unavailable on
this firmware (`PUT /v1/streams/debug:start` → HTTP 500 "No Operational
Network Interface"), so fits are the measurement method.

## Baseline floor (speed-invariant DMA component)

| Primitive | F | C | floor share @64 MHz | fit residuals |
|---|---|---|---|---|
| ecdsa_verify_256 | **22.19 s** | 252.8 Mcy | 87.1% | ≤0.74 s (≤2.6%) |
| ecdsa_verify_384 | **51.70 s** | 755.4 Mcy | 83.5% | ≤1.74 s |
| ec_scalar_mul_var | 19.39 s | 219.4 Mcy | 87.2% | ≤0.65 s |
| ec_scalar_mul_var_384 | 44.62 s | 646.3 Mcy | 83.6% | ≤1.50 s |

16→64 MHz (4× clock) improves verify_256 wall by only 1.49×. The issue
title's "28.4 s" figure does not reproduce (nor did ~26 s fit from the
archived U64E 16/48 data — cross-device absolute comparison is invalid;
this C64U runs ~12% faster verify cycles at 16 MHz than the U64E baseline).

## FP_ONCHIP_MUL A/B (wall seconds = 1-MHz-equivalent cyc / 1e6)

| Routine | MHz | baseline | onchip | ratio |
|---|---|---|---|---|
| ecdsa_verify_256 | 16 | 37.91 | 62.90 | 0.60× |
| | 48 | 28.19 | 21.41 | 1.32× |
| | 64 | 25.48 | 15.97 | **1.60×** |
| ecdsa_verify_384 | 16 | 98.72 | 211.49 | 0.47× |
| | 48 | 69.19 | 71.96 | 0.96× |
| | 64 | 61.96 | 53.69 | 1.15× |
| ec_scalar_mul_var | 64 | 22.24 | 13.93 | 1.60× |
| ec_scalar_mul_var_384 | 64 | 53.38 | 46.26 | 1.15× |

Onchip verify_256 fit: **residual floor ≈ 0.33 s, C ≈ 1001 Mcy** — the DMA
floor is eliminated (3.94× scaling for a 4× clock). Crossover ≈ 30 MHz
(P-256) / ≈ 55 MHz (P-384). At stock 1 MHz the DMA-table profile is ~3×
faster (extrapolated from the C fits) — profile, not replacement.

Hardware init (at the 48 MHz init speed) is *faster* for the onchip PRG:
200.7–202.3 s vs baseline 219.4–220.8 s — precompute's DMA row fetches cost
more wall time than the on-chip products replacing them.

Correctness: full oracle suite (`test_ecdsa_verify.py`) 35/35 against the
onchip PRG, including NIST CAVP SigVer negative vectors and the
`ecdsa_verify_with_message_384` tampered-message rejections.

## Follow-up lever (not in v0.5.0)

Shape (2): inline non-CT quarter-square in the row generator (~50 cy/product
vs ~134 via `jsr ct_mul_8x8`) projects verify_256 @64 MHz to ~8 s (≈3.2×)
and pulls the P-256 crossover toward ~10 MHz. Combined with `ECDSA_NO_COMB`
(#68) it yields a fully REU-less verify archive (runtime validation of
REU-absent operation still pending — the 35/35 suite ran with an REU
configured).

## Files

- `bench_issue69_run2.log` — baseline 16/48/64 sweep (raw tool output)
- `bench_issue69_onchip.log` — onchip variant sweep
- `sweep_run2.json` + `fit_floor.py` — fit inputs + tool
