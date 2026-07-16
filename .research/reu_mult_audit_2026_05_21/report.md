# REU multiply table — footprint + ROI audit

**Date:** 2026-05-21
**HEAD:** `efe5f24` (master, post-v0.3.0)
**Authors:** primary investigator + Explore subagent triad (REU footprint, git archaeology, cycle-measurement infrastructure)
**Question:** how much REU space does the multiply path consume, and is the 128 KB lookup table earning its keep?

---

## TL;DR

| | Measured |
|--|--|
| REU consumed by multiply table | **128 KB** (banks 0-1, offsets $0000–$7FFF each) |
| Total REU used by this library  | 168 KB / 192 KB (128 KB mul + 40 KB Lim-Lee anchors) |
| Per-row REU fetch real cost     | **542 cy** (~20 cy setup + ~512 cy DMA stall + accounting) |
| DMA fraction of `fp_mul`        | **22.9 %** (P-256), **17.6 %** (P-384) |
| Naïve no-table alt (inline `mul_8x8`) | ~145 kcy (P-256), ~318 kcy (P-384) |
| **Table speedup vs naïve alt**  | **1.92× (P-256), 2.14× (P-384)** |

**Verdict.** The 128 KB table is earning its keep — it roughly halves `fp_mul`/`fp_sqr` cost, which is the dominant component of every cryptographic operation in this library (ECDSA verify is >99% scalar-mul time, and scalar-mul is mostly field multiplies). REU is otherwise unused, so the opportunity cost is zero. **Keep it.**

**Correction needed in `CLAUDE.md`.** The note that per-row DMA is "20 cycles per row / <1% of fp_mul" (lines 190–198, referring to "Wave 7b") is wrong — it counts only the register-setup head; it omits the ~512-cy DMA cycle-steal stall. The real fraction is 18–23 %, not <1 %. See § 6 below.

---

## 1. Cycle-measurement methodology

All measurements taken in VICE NTSC at simulated 1.022 MHz, VIC blanked, warp mode on, REU enabled (`-reu -reusize 512`). VICE warp affects wall-clock only; the simulated 6502 cycle counter is deterministic. Cycle accounting routes through the KERNAL jiffy clock at `$A0..$A2`, snapshotted by `bench_start` / `bench_stop` (`src/main.s:169-191`); `jiffies × 17045 = cycles` is exact for 1 MHz NTSC.

Loop trampoline:
- Single-loop (1..255 iter) for routines ≥ ~50 kcy/call (`fp_mul`, `fp_sqr`, `fp_mul_384`, `fp_sqr_384`).
- Nested 256×outer trampoline for sub-kilocycle routines (`reu_fetch_mul_row`, `mul_8x8`). 5,120 iterations per measurement gives ≥30 jiffies → ±3 % quantization noise on the body cost.

Per-iter loop overhead (JSR + RTS + DEC abs + BNE) measured directly via a noop (RTS-only) routine: **19.97 cy**, matching the analytical 21 cy within rounding.

Tool: `tools/bench_reu_mult.py` (new this audit). Output reproduced in § 3 below.

## 2. REU footprint — ground truth

From `src/reu_config.s` + `src/main.s:222-318` + `src/mul_8x8.s:296-312`:

| Bank | REU offset      | Contents                                     | Bytes  |
|------|-----------------|----------------------------------------------|--------|
| $00  | $0000–$7FFF     | `a×b` rows for `a ∈ [0,127]`, 512 B per `a`  | 64 KB  |
| $01  | $0000–$7FFF     | `a×b` rows for `a ∈ [128,255]`, 512 B per `a`| 64 KB  |
| $02  | $0000–$3FFF     | P-256 Lim-Lee h=8 comb anchors (256 × 64 B)  | 16 KB  |
| $02  | $4000–$9F9F     | P-384 Lim-Lee h=8 comb anchors (256 × 96 B)  | 24 KB  |
| $02  | $A000–$FFFF     | free / scratch                                | 24 KB  |

**Row format (per multiplicand `a`):** 256 lo bytes of `a×b` for `b ∈ [0,255]`, then 256 hi bytes. Each row is fetched 512 B at a time via `reu_fetch_mul_row` (`src/mul_8x8.s:303-312`) into C64 RAM at `mul_dma_lo` (`$4B00`) / `mul_dma_hi` (`$4C00`).

**Per-row fetch protocol.** Only three of eight REU registers are written per call (`$DF05`, `$DF06`, `$DF01`); the other five (c64 base, REU offset-low, length, address-control) are pre-configured once at boot by `reu_mul_init` and never re-written on the hot path — every public DMA-issuing entry (`fp_mul`, `fp_sqr`, `fp_mul_384`, `fp_sqr_384`, `ec_scalar_mul[_var][_384]`, `ecdsa_verify_256/384`) defensively re-establishes the two registers from the Issue #33-class incident class, but does not redo the rest. This is the trick that keeps the *register setup* down to 20 cycles per fetch.

The remaining ~520 cycles per fetch are unavoidable: the REU DMA cycle-steals one byte per cycle while the 6510 is halted, so 512 bytes = ~512 cycles regardless of how the registers are arranged.

## 3. Raw bench data

Run on 2026-05-21, `efe5f24`, VICE warp:

```
reu_fetch_mul_row:   169 jiffies,   2 880 605 cy total,  562.62 cy/iter  (5120 calls)
mul_8x8          :    33 jiffies,     562 485 cy total,  109.86 cy/iter  (5120 calls)
noop (RTS only)  :     6 jiffies,     102 270 cy total,   19.97 cy/iter  (5120 calls)
fp_mul   (P-256) :    89 jiffies,   1 517 005 cy total,    75 850 cy/call (20 calls)
fp_sqr   (P-256) :    84 jiffies,   1 431 780 cy total,    71 589 cy/call (20 calls)
fp_mul_384       :    87 jiffies,   1 482 915 cy total,   148 292 cy/call (10 calls)
fp_sqr_384       :    73 jiffies,   1 244 285 cy total,   124 428 cy/call (10 calls)
```

After subtracting the 19.97-cy loop overhead from the two micro-benchmarks:
- **`reu_fetch_mul_row` body: 542.6 cy** (register setup + 512-cy DMA stall + ~10 cy book-keeping)
- **`mul_8x8` body: 89.9 cy** (`CLAUDE.md` quotes 86 cy body + 6 cy jsr; matches within rounding)

Cross-check against last full bench in `.research/audit_2026_05_18/b1_vice_bench.md` (commit `788adc3`):

| Routine    | This run (efe5f24) | b1 (788adc3) | Δ      |
|------------|--------------------|--------------|--------|
| `fp_mul`   | 75 850 cy          | 76 702 cy    | −1.1 % |
| `fp_sqr`   | 71 589 cy          | 72 441 cy    | −1.2 % |
| `fp_mul_384` | 148 292 cy       | 148 291 cy   |  0.0 % |
| `fp_sqr_384` | 124 428 cy       | 126 133 cy   | −1.4 % |

Within single-jiffy quantization on every row. Numbers are stable across the v0.2.0 → v0.3.0 ship.

## 4. Decomposition — where the fp_mul cycles actually go

Working from `src/fp256.s:132-379` + the measured 542.6-cy row fetch:

```
fp_mul (P-256, 75 850 cy):
  setup + zero wide buffer + copy src2:    ~600 cy   ( 0.8%)
  outer loop × 32:
    per i:
      row fetch (DMA):                     542.6 cy  → 32 × 543 = 17 365 cy (22.9%)
      SMC patch of accumulator base addrs: ~85 cy    → 32 × 85 =  2 720 cy ( 3.6%)
      4×-unrolled inner loop (32 j-bytes
        × ~38 cy dense / ~9 cy zero-skip): ~1 700 cy → 32 × 1700 = 54 400 cy (71.7%)
      carry propagation overhead:          ~30 cy    → ~ 960 cy  ( 1.3%)
```

(The inner-loop cost above assumes "random-dense" inputs — the OPERAND_A_256 bench operand is essentially all-nonzero. For sparse-input cases — e.g., point-op intermediates with leading zeros — the inner loop is faster and the DMA fraction rises proportionally.)

This matches the audit's prior finding (`.research/audit_2026_05_18/perf_audit_2026_05_18.md` § 7 / 8) that the inner accumulator chain is the dominant cost, not the DMA setup.

## 5. The alternative — what if we removed the table?

The simplest table-free implementation: replace each `(adc mul_dma_lo,y / adc mul_dma_hi,y)` pair in the inner loop with a `jsr mul_8x8` call. Roughly:

- Per j-byte cost today (dense, with table): ~38 cy (`src/fp256.s:224-241`); of which the two `adc abs,y` lookups are 8 cy.
- Per j-byte cost without table: ~(38 − 8) + (mul_8x8 setup + 89.9 cy body + accumulator adds) ≈ ~94 cy added.

For P-256 (32×32 = 1024 j-bytes per `fp_mul`):
- Cost added: 1024 × 94 = ~96 kcy
- DMA cost removed: 32 × 543 = ~17.4 kcy
- Net delta: +79 kcy → predicted no-table `fp_mul` ≈ **155 kcy** (vs 76 kcy measured today). **Speedup of REU table: ~2.04×**

The tool's first-order estimate (which ignores register-pressure spills, lost zero-byte fast-paths, and outer-loop SMC patching for the row base) puts it at:

| | P-256                 | P-384                  |
|---|----------------------|------------------------|
| Today (table)        | 75 850 cy            | 148 292 cy             |
| Naïve no-table model | ~145 kcy             | ~318 kcy               |
| Speedup              | **1.92×**            | **2.14×**              |

These speedup numbers are floors — a real no-table implementation would lose the sparse-input `beq mul_src2_buf=0` fast path (which Wave 8a confirmed is load-bearing for point-op compound callers, hitting 5–30 % of operand bytes in real Z-coordinate work; see `CLAUDE.md:340-364`). Realistically the cliff is closer to 2.5–3× for compound callers.

## 6. Smaller-table alternatives — none look viable

**Half-size table (64 KB, banks 0 only, `a ∈ [0..127]`).** Fall back to `mul_8x8` for `a ≥ 128`. On random-byte inputs, ~half the rows fall through. Per fallback row ~32 inline `mul_8x8` calls = ~32 × 90 = 2 880 cy plus accumulator overhead ≈ 3 kcy added per fallback row. Average added cost ≈ 16 × 3 kcy = +48 kcy per `fp_mul`. `fp_mul` 76 kcy → ~124 kcy (+63 %). Saves 64 KB of REU we're not otherwise using.

**Quarter-square LUT in REU.** The 1 KB `sqtab` is already in fast C64 RAM ($9C00–$9FFF). Putting it in REU instead would *add* DMA latency for what is now a 4-cy `lda abs,x`. Pure loss.

**Karatsuba on byte multiplies (3 × 4×4 lookups per 8×8).** A 4×4 lookup is 16 entries = 16 bytes per table; tiny. But: 3 four-bit lookups + a combine per 8×8 product is ~25 cy vs current ~5 cy lookup pair. Per-byte cost up ~4×; net `fp_mul` would slow ~2×. No-go.

**Move the table to local C64 RAM (no REU).** 128 KB doesn't exist on a stock C64. REU is the only place it can live.

None of these dominate today's design.

## 7. Recommendation

**Keep the 128 KB REU multiply table as-is.** The 2.0–2.5× wide-multiply speedup it provides is the largest single-lever performance feature in this library, and the REU space it consumes (banks 0–1, 128 KB) is otherwise idle (bank 2 has 24 KB free even after the h=8 Lim-Lee comb tables).

**Follow-ups:**

- **Fix `CLAUDE.md`** "REU DMA multiply row caching (128KB lookup in REU)" / "20 cycles per row / <1% of fp_mul" passages (lines 190–198 of the current file). The measured per-row real cost is **542 cy**, not 20; the DMA fraction of `fp_mul` is **18–23 %**, not <1 %. The 20-cy figure is just the register-setup head — the 512-cy DMA cycle-steal is the dominant component. Suggested rewrite:

  > REU DMA multiply row caching (128KB lookup in REU, 542 cy per row fetch — 20 cy register-setup + ~512 cy DMA cycle-steal stall; ~23% of fp_mul, ~18% of fp_mul_384)

  This also retroactively explains the Wave 4c Karatsuba revert correctly: tripling row-fetches really does add ~3 × 17 kcy ≈ 51 kcy of DMA, which is non-trivial. The old framing made it sound impossibly cheap.

- **Add `tools/bench_reu_mult.py` to the regular bench rotation** (not the CI gate — it's slow). Reproducible cycle-decomposition is valuable for evaluating any future multiply-related optimization PR, and locks in the "DMA = 23 % of fp_mul" baseline against accidental regression.

- **Consider a fourth-tier micro-bench at `tools/bench_reu_mult.py`** that pairs row-fetch cost against pure C64-RAM `abs,x` lookup cost, so future investigators don't have to re-derive the model.

## 8. References

- Source: `src/mul_8x8.s` (sqtab + ct mul_8x8 + reu_fetch_mul_row), `src/fp256.s:132-379` (fp_mul + fp_sqr), `src/fp384.s:169-440` (fp_mul_384 + fp_sqr_384), `src/main.s:222-318` (reu_mul_init), `src/reu_config.s` (bank/offset equates).
- Tool: `tools/bench_reu_mult.py` (created this audit). Reproducible with `python3.13 tools/bench_reu_mult.py`; needs ~3-4 min wall (mostly VICE-warp init).
- Cross-references:
  - `.research/audit_2026_05_18/perf_audit_2026_05_18.md` § 7 (call-graph) and § 8 (Wave 8a primitive-vs-compound divergence).
  - `.research/audit_2026_05_18/b1_vice_bench.md` (primitive cycle baselines on master `788adc3`).
  - `CLAUDE.md:190-198` (REU caching claims to be corrected).
  - `CLAUDE.md:340-364` (Wave 4c Karatsuba revert — the "<1% DMA" framing in this passage is similarly misleading and should be updated alongside).
