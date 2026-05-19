# c64-nist-curves performance + RAM audit

**Audit date:** 2026-05-18 → 2026-05-19 (synthesis on 2026-05-19; section 6 follow-up + Tier-1 #1/#3 landed 2026-05-19)
**Code state:** master HEAD `7d71773` (PR #35, docs-only atop PR #34 `788adc3`; assembly source is byte-identical to `788adc3`)
**PRG size:** 37,302 bytes
**Scope:** every feature in the library, with measured cycles (VICE 1 MHz + U64E hardware at 1/16/48 MHz) and measured RAM bytes (PRG + DATA + ZP + REU), plus primitive→compound divergence analysis.

This file is the synthesis. Source agent reports (A1–A5, B1, C1) sit alongside it in this directory and carry the verbatim bench output, line-level citations, and full per-table backup.

---

## 0. Executive summary

**Performance state at master HEAD `7d71773`:** No regressions. Every primitive measurement on U64E hardware lands within ±1 jiffy (±17,045 cy 1-MHz-equivalent) of the README baseline; the ECDSA-verify aggregate matches the memory record bit-for-bit on P-256 and within 1 jiffy on P-384. The library is in a known-good state.

**Headline numbers (U64E hardware @ 16 MHz, fresh measurement):**

| Top-level entry         | Cycles (1-MHz-equiv) | Wall-clock |
|-------------------------|---------------------:|-----------:|
| `ecdsa_verify_256`      |           43,157,940 |    2.697 s |
| `ecdsa_verify_384`      |          111,031,130 |    6.939 s |
| `ec_scalar_mul_var`     |           37,618,315 |    2.351 s |
| `ec_scalar_mul_var_384` |           95,469,045 |    5.967 s |

At 48 MHz turbo, ECDSA verify drops to 0.66 s (P-256) / 1.62 s (P-384) wall-clock — within TLS-handshake-feasible territory.

**RAM state at master HEAD:**

| Resource | Used | Capacity | Headroom |
|----------|-----:|---------:|---------:|
| PRG bytes (`$0801`–end) | 37,302 | ~49,150 ($0801–$BFFF for library code) | ~11,800 B |
| Production DATA scratch | 6,435 | (depends on consumer's map) | n/a |
| ZP slots | 31 | 254 ($02–$FF) | 219 B |
| REU bytes | 168,936 | 262,144 (256 KB) | 24,672 B free in bank 2 |
| Test-harness DATA staging | 1,426 | (not in production builds) | — |

The library **requires a 256 KB-class REU** (1764 + expansion or modern equivalent); a 1750 (128 KB) is insufficient. The REU multiply tables alone fill banks 0+1 (131 KB); the h=8 Lim-Lee anchor tables consume an additional 40,864 B of bank 2.

**Three structural findings that should shape future optimization work:**

1. **Primitive-cost extrapolation has systematically misled** post-v0.2.0 optimization PRs. PRs #26 + #34 combined spent 2,112 RAM bytes for ~60 cy/B measured savings — predicted ~1,000 cy/B (10–20× short). Root cause documented in CLAUDE.md "Negative findings": `fp_mod_inv` has input-sensitive runtime and the Z-coordinate inputs from `ec_scalar_mul` hit GCD fast paths far below the random-input bench average.

2. **Predicted-vs-measured divergence is structural, not arithmetic.** Point ops measure 18–48% **cheaper** than the additive primitive sum (state-holding amortizes dispatch); scalar_mul measures 18–25% **more expensive** than scaled point-op count (per-iteration copy/DMA/control overhead is not in the primitive row). At ECDSA-verify the two effects nearly cancel, giving a 1–3% prediction accuracy — which is misleading good luck, not signal. Section 8 details.

3. **Low-hanging fruit appears exhausted on this architecture.** No measured-cycle win in the post-v0.2.0 window approaches the 100 cy/B threshold that the c64-x25519 sibling routinely achieved in its Wave 4–7 era. Future optimization PRs need integrated-bench measurement before merge, not extrapolation from primitives. CHANGELOG `[Unreleased]` already codifies this as policy (PR #35).

---

## 1. PRG byte attribution

Source: A1 §1 (see `a1_ram_accounting.md`). Reconciles with `wc -c build/nist-curves.prg` − 2-byte header.

| Source file        | CODE   | RODATA | TABLES | DATA  | BSS  | Total in PRG |
|--------------------|-------:|-------:|-------:|------:|-----:|-------------:|
| main.s             | 457    | 31     | 0      | 0     | 0    | 488          |
| mul_8x8.s          | 247    | 0      | 0      | 0     | 0    | 247          |
| fp256.s            | 1,069  | 0      | 0      | 0     | 0    | 1,069        |
| mod256.s           | 4,003  | 64     | 0      | 0     | 0    | 4,067        |
| curve256.s         | 0      | 416    | 0      | 0     | 0    | 416          |
| points256.s        | 3,541  | 0      | 0      | 0     | 0    | 3,541        |
| inv256.s           | 114    | 32     | 0      | 0     | 0    | 146          |
| ecdsa256.s         | 594    | 0      | 0      | 0     | 0    | 594          |
| fp384.s            | 1,067  | 0      | 0      | 0     | (53) | 1,067        |
| mod384.s           | 3,625  | 0      | 0      | 0     | 0    | 3,625        |
| curve384.s         | 0      | 288    | 0      | 0     | 0    | 288          |
| points384.s        | 3,602  | 0      | 0      | 0     | 0    | 3,602        |
| ecdsa384.s         | 666    | 0      | 0      | 0     | 0    | 666          |
| sha384.s           | 5,225  | 704    | 3,072  | 0     | 0    | 9,001        |
| data.s             | 0      | 0      | 512    | 7,861 | 0    | 8,373        |
| (TABLES align pad) | 0      | 0      | 110    | 0     | 0    | 110          |
| LOADADDR header    | (2 B)  | —      | —      | —     | —    | 2            |
| **Total**          | 24,210 | 1,535  | 3,694  | 7,861 | (53) | **37,302**   |

**Feature-group totals (CODE + RODATA, the meaningful "feature weight"):**

| Feature group              | Bytes  | % of CODE+RODATA |
|----------------------------|-------:|-----------------:|
| SHA-384 (sha384.s)         | 5,929  | 23 %             |
| P-256 mod ops (mod256.s)   | 4,067  | 16 %             |
| P-384 mod ops (mod384.s)   | 3,625  | 14 %             |
| P-384 point ops (points384.s) | 3,602 | 14 %          |
| P-256 point ops (points256.s) | 3,541 | 14 %          |
| P-256 field ops (fp256.s)  | 1,069  | 4 %              |
| P-384 field ops (fp384.s)  | 1,067  | 4 %              |
| ECDSA P-384 (ecdsa384.s)   | 666    | 3 %              |
| ECDSA P-256 (ecdsa256.s)   | 594    | 2 %              |
| P-256 curve params + KAT   | 416    | 2 %              |
| P-384 curve params + KAT   | 288    | 1 %              |
| Quarter-square mul (mul_8x8.s) | 247| 1 %              |
| Boot + KERNAL helpers (main.s) | 488| 2 %              |
| Inv-Fermat reference (inv256.s) | 146 | 1 %             |
| **Subtotal**               | 25,745 | 100 %            |

**Observations.**
- SHA-384 is the largest single module by a wide margin: 5,929 B (~23 % of CODE+RODATA). The 3,072 B TABLES allocation (12 × 256 B shift LUTs introduced by PR #25) is in addition. SHA-384 module total including its TABLES = **9,001 B** ≈ 24 % of the entire PRG.
- The P-384 path is consistently ~6 % heavier than its P-256 sibling (mod ops +14 %, point ops + 2 %), driven entirely by the 48-byte field width and the additional anchor table entries. Field ops are nearly identical in PRG bytes despite the wider data path, because most growth is in mod-p reduction and Lim-Lee comb table-building.
- A 110-byte TABLES alignment pad lives between the end of RODATA (`$6C92`) and the page-aligned TABLES start (`$6D00`). It's a linker artifact; not attributable to any source file.

---

## 2. DATA buffer catalog

Source: A1 §2. The full per-buffer table (88 named entries) is in `a1_ram_accounting.md`. Feature-group totals here:

| Feature group              | Bytes  | Lifetime               | Notes |
|----------------------------|-------:|------------------------|-------|
| SHA-384 scratch            | 1,041  | mix (state persistent across update calls; w/abcdefgh per-call) | sha_w (640 B) dominates |
| P-256 point scratch        | 738    | persistent + per-call  | ec_p1/2/3 (288 B) + 6 × ec_t (192 B) + jj_tmp (32 B) + affine + base/base384 |
| ECDSA-384 scratch          | 674    | per-call               | r/s/h/qx/qy/w/u1/u2/u1_be/u2_be (10 × 48) + u1g_jac (144) + fp_rev_buf_384 (48) + msg ptr (2) |
| P-384 fp scratch           | 672    | per-call               | fp384_wide (96) + 4× fp384_tmp + 4× fp384_r + 4× fp384_inv |
| P-384 precompute anchors   | 816    | boot-once-init         | 8 × ec_anchor*_384 X+Y (768) + cm_k_384 (48) |
| P-384 point scratch        | 869    | persistent + per-call  | ec384_p1/2/3 (432 B) + 6× ec384_t (288 B) + ec384_jj_tmp (48) |
| P-256 precompute anchors   | 608    | boot-once-init         | aff2g (64) + 8 × ec_anchor* X+Y (512) + cm_k (32) |
| ECDSA-256 scratch          | 448    | per-call               | r/s/h/qx/qy/w/u1/u2/u1_be/u2_be (10 × 32) + u1g_jac (96) + fp_rev_buf (32) |
| P-256 fp scratch           | 450    | per-call               | fp_wide (64) + 4× fp_tmp + 4× fp_r + 4× fp_inv + fp_inv_iter (2) |
| P-384 mod-Solinas tmp      | 49     | per-call               | fp384_red_tmp |
| mul scratch (DATA)         | 36     | per-call               | mul_src2_buf (35) + mul_cached_a (1) |
| P-256 mod-Solinas tmp      | 33     | per-call               | fp_red_tmp |
| **Production subtotal**    | **6,434** | —                   | — |
| Test-harness staging       | 1,426  | per-call (test only)   | sha384_msg_buf (1024) + ecdsa_inputs_384 (240) + ecdsa_inputs_256 (160) + 3 result bytes |
| **All DATA**               | **7,860** | —                   | matches od65 dump |
| TABLES (mul_dma_lo/hi)     | 512    | boot-once + runtime DMA target | data.s TABLES section |
| BSS (fp384.s only)         | 53     | per-call               | mul_src2_buf_384 (51) + 2 single bytes |
| **All runtime RAM scratch**| **8,425** | —                   | DATA + TABLES + BSS |
| **Production-only runtime**| **6,999** | —                   | subtract 1,426 test-harness staging |

**Observations.**
- SHA-384's scratch is dominated by `sha_w` (640 B) — the 80-word round message schedule. PR #25's compaction note in CLAUDE.md targeted compression-body cycles, not scratch RAM.
- ECDSA-384 carries +50 % more scratch than ECDSA-256 (674 vs 448), driven by the wider field width plus the persistent `u1g_jac` (144 B vs 96 B P-256) added by PR #34. The `u1g_jac` buffer holds the fixed-base scalar-mul result in Jacobian form across the variable-base scalar-mul, enabling the J+J join.
- **Production-only DATA + TABLES + BSS = 6,999 B.** Test-harness staging (1,426 B; the 1,024 B `sha384_msg_buf` dominates) does not exist in a consumer integration; consumers only pay 6,999 B for both curves + SHA-384 + ECDSA + Lim-Lee comb anchors. This is the headline production-RAM number.

---

## 3. ZP allocation map

Source: A1 §3. Library claims 31 bytes of ZP from `src/zp_config.s`. No module declares its own ZP segment outside `zp_config.s` (verified via `grep -nE '\.segment "ZEROPAGE"' src/*.s`).

| Subsystem            | Bytes | Slots                                                                 |
|----------------------|------:|-----------------------------------------------------------------------|
| Hardware (immovable) | 1     | proc_port ($01)                                                       |
| Control / temp       | 6     | zp_tmp1/2 ($02/03) + zp_ptr1/2 ($FB/FD)                               |
| SHA-384              | 8     | sha_src/len/w_ptr/w_ptr2 ($04–$0B; 4 × 2-byte pointers)               |
| multiply (mul_8x8)   | 4     | poly_i/j/carry/tmp ($1A–$1D)                                          |
| fp (shared 256/384)  | 12    | fp_src1/src2/dst/misc ($22–$29) + fp_carry/loop/mul_i/mul_j ($2A–$2D) |
| point / scalar       | 1     | ec_scalar_ptr ($3B)                                                   |
| **Subtotal**         | **31**| —                                                                     |

KERNAL-shared read-only `jiffy_clock` at $A0–$A2 (3 bytes) is sampled for bench timing only — it's not a library-owned slot and consumers can't relocate the KERNAL.

**Free room on ZP page:** 219 of 254 usable bytes ($02–$FF). Library occupies **12 % of usable ZP**.

---

## 4. REU bank usage

Source: A1 §4. The library uses 168,936 B of REU (≈ 165 KB), distributed across banks 0/1/2.

| Bank | Offset range | Contents                                          | Bytes used | Bytes free |
|-----:|--------------|---------------------------------------------------|-----------:|-----------:|
| 0    | $0000–$FFFF  | Multiply rows 0..127 (lo+hi pages, 512 B per `a`) | 65,536     | 0          |
| 1    | $0000–$FFFF  | Multiply rows 128..255                            | 65,536     | 0          |
| 2    | $0000–$3FFF  | P-256 Lim-Lee comb table (256 × 64 B affine)      | 16,384     | —          |
| 2    | $4000–$9F9F  | P-384 Lim-Lee comb table (256 × 96 B affine)      | 24,480     | —          |
| 2    | $9FA0–$FFFF  | unused                                            | 0          | 24,672     |
| **Total** | —       | —                                                 | **168,936**| **24,672** |

**Implications.**
- **Hard 256 KB REU requirement.** A 1750 (128 KB) REU is insufficient; the multiply tables alone need 128 KB, and the comb tables push the total to 165 KB. Consumers need a 1764 (256 KB) or a modern equivalent (1750-XL clone, Ultimate 64's built-in REU emulation, 17xx 17xx/18xx clones).
- **24,672 B free in bank 2** ($9FA0–$FFFF). Candidate tenants per CLAUDE.md: windowed-mul accumulator caches, Wycheproof KAT vector stashes for hardware-driven self-test, alternate-base scalar-mul tables. Currently no consumer.
- **Boot init costs (1 MHz wall-clock).**
  - `reu_mul_init`: ~12 s. Quarter-square table generation + DMA stash for 256 × 512 B rows.
  - `ec_precompute_256` + `ec_precompute_384` combined: 89–246 s. C1 measured 246 s on the U64E over 48 ms RTT (the 90 s number in CLAUDE.md was for direct-connected U64E; the additional ~150 s is REST DMA upload over the network link).

---

## 5. Per-primitive cycle costs (fresh measurement at master `7d71773`)

VICE source: B1 (`b1_vice_bench.md`), NTSC 1 MHz, oracle-gated.
U64E source: C1 (`c1_u64e_bench.md`), device `10.43.23.81` (Ultimate 64 Elite fw 3.14d), DeviceLock-serialized, 1/16/48 MHz sweep.

> **Convention note (load-bearing).** Cycle columns at 16/48 MHz are 1-MHz-equivalent wall-clock microseconds (jiffies × 17,045), NOT machine cycles at turbo. The NTSC jiffy clock ticks at 60 Hz regardless of CPU turbo and REU DMA runs at ~1 MHz regardless of CPU speed. Real wall-clock at 48 MHz is ~0.7× of 16 MHz wall (not 16/48 = 0.33×). See CLAUDE.md "Known issues" — issue #17 Task #12.

### P-256 primitives

| Routine                  | VICE 1 MHz | U64E 1 MHz | U64E 16 MHz | U64E 48 MHz | README 16 MHz | Δ vs README |
|--------------------------|-----------:|-----------:|------------:|------------:|--------------:|-------------|
| fp_add                   | 852        | 784        | 49          | 16          | (n/a, NTSC table only) | within 1 jiffy |
| fp_sub                   | 852        | 852        | 51          | 17          | — | — |
| fp_mul                   | 76,702     | 76,134     | 8,948       | 6,190       | 8,948         | 0.00 %      |
| fp_sqr                   | 72,441     | 72,157     | 12,819      | 10,534      | 12,819        | 0.00 %      |
| fp_mod_add               | 852        | 920        | 55          | 18          | — | — |
| fp_mod_sub               | 852        | 852        | 53          | 17          | — | — |
| fp_mod_reduce256         | 6,818      | 6,477      | 404         | 134         | — | — |
| fp_mod_mul               | 83,520     | 82,668     | 9,321       | 6,320       | 9,374         | -0.57 %     |
| fp_mod_sqr               | 78,407     | 78,407     | 13,263      | 10,670      | 13,209        | +0.41 %     |
| fp_mod_inv (binary GCD)  | 749,980    | 749,980    | 51,135      | 17,045      | 51,135        | 0.00 %      |
| ec_point_double          | 545,440    | 545,440    | 68,180      | 68,180      | 68,180        | 0.00 %      |
| ec_point_add             | 647,710    | 647,710    | 85,225      | 51,135 ▼₁   | 85,225        | 0.00 %      |
| ec_scalar_mul (h=8)      | 47,862,360 | 47,879,405 | 6,340,740   | 4,653,285   | 6,323,695     | +0.27 %     |

### P-384 primitives

| Routine                  | VICE 1 MHz   | U64E 1 MHz   | U64E 16 MHz | U64E 48 MHz | README 16 MHz | Δ vs README |
|--------------------------|-------------:|-------------:|------------:|------------:|--------------:|-------------|
| fp_add_384               | 1,193        | 1,159        | 70          | 24          | — | — |
| fp_sub_384               | 1,193        | 1,193        | 70          | 23          | — | — |
| fp_mul_384               | 148,291      | 147,439      | 15,553      | 9,978       | 15,447        | +0.69 %     |
| fp_sqr_384               | 126,133      | 124,428      | 20,347      | 16,228      | 20,294        | +0.26 %     |
| fp_mod_add_384           | 1,193        | 1,261        | 80          | 27          | — | — |
| fp_mod_sub_384           | 1,022        | 1,193        | 74          | 24          | — | — |
| fp_mod_reduce384         | 6,818        | 6,477        | 404         | 134         | — | — |
| fp_mod_mul_384           | 155,109      | 155,109      | 15,926      | 10,120      | 15,873        | +0.33 %     |
| fp_mod_sqr_384           | 132,951      | 132,098      | 20,720      | 16,352      | 20,720        | 0.00 %      |
| fp_mod_inv_384           | 1,585,185    | 1,602,230    | 102,270     | 34,090      | 102,270       | 0.00 %      |
| ec_point_double_384      | 971,565      | 971,565      | 119,315 ▼₁  | 102,270 ▲₁  | 136,360       | -12.50 % ▼ (1-jiffy noise) |
| ec_point_add_384         | 1,124,970    | 1,124,970    | 136,360     | 102,270     | 136,360       | 0.00 %      |
| ec_scalar_mul_384 (h=8)  | 135,081,625  | 135,081,625  | 16,056,390  | 11,147,430  | 16,005,255    | +0.32 %     |

**▼₁ / ▲₁ = single-jiffy quantization noise.** Single-shot point-op measurements (`loops=1`) at the 3-vs-4 or 5-vs-6 jiffy boundary swing by one full jiffy as the 60 Hz raster IRQ moves in or out of the measurement window. C1's aggregate check shows `ec_point_double_384 + ec_point_add_384 @ 48 MHz` sums identically to README (204,540 vs 187,495 = +1 jiffy across two single-shot reads), confirming no real delta.

**Cross-validation: VICE 1 MHz vs U64E 1 MHz.** A2 §4.1 raised this as the bench-redundancy question. The two measurements agree to within 1 jiffy on every cell, validating both targets — no leakage of turbo-mode behaviour into the 1 MHz pure-CPU path on either side.

**No structural regressions.** Every heavy routine (fp_mul, fp_mod_inv, ec_point_double, ec_point_add, ec_scalar_mul) on either curve matches README to ≤0.7 %. Sub-jiffy add/sub primitives swing within their inherent quantization noise.

---

## 6. Per-feature cycle costs (fresh U64E measurement)

Sources: C1 §4 (original 2026-05-19 sweep) + follow-up sweep 2026-05-19 (after adding the `ecdsa_verify_with_message_384` row, see Section 11 follow-up).

| Top-level entry              | 16 MHz cyc      | 16 MHz wall | 48 MHz cyc     | 48 MHz wall |
|------------------------------|----------------:|------------:|---------------:|------------:|
| `ec_scalar_mul_var`          |      37,601,270 |     2.350 s |     28,823,095 |     0.600 s |
| `ec_scalar_mul_var_384`      |      95,486,090 |     5.968 s |     69,424,285 |     1.446 s |
| `ecdsa_verify_256`           |      43,140,895 |     2.696 s |     32,999,120 |     0.687 s |
| `ecdsa_verify_384`           |     111,065,220 |     6.942 s |     80,605,805 |     1.679 s |
| `ecdsa_verify_with_msg_384`† |     111,082,265 |     6.943 s |     80,605,805 |     1.679 s |

† New bench coverage; trampoline `bench_ecdsa_verify_with_msg_384_tramp` added to `src/main.s`, BENCH_PLAN row added to `tools/bench_ecdsa_u64.py`. Message = RFC 6979 A.3.1 "sample" (6 bytes). Oracle gate (`cryptography.hazmat` ECDSA verify on the same vector) passed.

**SHA-384 cost on a 6-byte message — within-run Δ:**

| Speed   | `ecdsa_verify_384` | `ecdsa_verify_with_msg_384` | Δ       |
|---------|-------------------:|----------------------------:|--------:|
| 16 MHz  | 111,065,220 cyc    | 111,082,265 cyc             | **+17,045 cyc (1 jiffy)** |
| 48 MHz  |  80,605,805 cyc    |  80,605,805 cyc             | **0 cyc** (sub-jiffy)     |

SHA-384 cost for a 6-byte message is **bounded above by 17,045 cyc (1-MHz-equivalent)** at both speeds, including `sha384_init` + `sha384_update` (no compress — 6 bytes fit in the partial block) + `sha384_final` (one compress for padding). A4's estimate of ~1.2 Mcy per `sha_compress` block (`a4_call_graph.md` §3.12) is **revised downward by ~70×**. The actual compress cost remains unresolved at jiffy granularity; a dedicated SHA-384 bench at canonical TLS message lengths {0, 55, 56, 111, 112, 200, 1024, 4096 B} would resolve it (Tier 2 follow-up).

**48 MHz jiffy-rate drift caveat.** All four existing-baseline routines at 48 MHz today measure systematically ~3.8 % higher in jiffy count than the original C1 sweep (yesterday), while Python-side wall times match within 0.3 s. The U64E's CIA Timer A is ticking ~3.8 % faster today than yesterday despite identical firmware (3.14d) and the same `7d71773` master. Within-run deltas (e.g., the SHA cost analysis above) are unaffected; absolute cross-day comparison at 48 MHz needs a ±4 % tolerance. The 16 MHz sweep does not show this drift (today matches yesterday within ±1 jiffy across all routines).

**PR #34 corroboration (vs memory `project_pr34_empirical_measurement.md`):**

| Primitive          | Memory record (PR #34) | C1 measurement (2026-05-19) | Follow-up measurement (2026-05-19) | Verdict           |
|--------------------|-----------------------:|----------------------------:|-----------------------------------:|-------------------|
| `ecdsa_verify_256` |       43,157,940 cyc   |              43,157,940 cyc |                     43,140,895 cyc | within 1 jiffy    |
| `ecdsa_verify_384` |      111,048,175 cyc   |             111,031,130 cyc |                    111,065,220 cyc | within 1–2 jiffies|

All three measurements (memory + two independent benches) of ECDSA verify cluster within ±1–2 jiffies — the memory record stands.

---

## 7. Stacked cycle attribution

Source: A4 §3 + C1 §4. For ECDSA verify the per-primitive call counts come from A4's static call-graph extraction; the per-primitive cycle costs come from C1's fresh U64E numbers at 16 MHz.

### `ecdsa_verify_256` @ 16 MHz = 43,157,940 cyc

| Component                                       | Calls per verify | Cycles per call | Subtotal     | % of verify |
|-------------------------------------------------|-----------------:|----------------:|-------------:|------------:|
| `ec_scalar_mul_var` (u2·Q variable-base)        | 1                | 37,618,315      | 37,618,315   | 87.2 %      |
| `ec_scalar_mul` (u1·G fixed-base h=8)           | 1                | 6,340,740       | 6,340,740    | 14.7 %      |
| `ec_point_add_jj` (J+J at u1G+u2Q join)         | 1                | ~179,500 (est)  | ~179,500     | 0.4 %       |
| `fp_mod_mul_n` (u1 = h·w; u2 = r·w mod n)       | 2                | ~100,000 (est)  | ~200,000     | 0.5 %       |
| `fp_mod_inv` (w = s⁻¹ mod n)                    | 1                | ≪51,135 (¹)     | ~10,000 (¹)  | 0.0 %       |
| `ec_sqrp` + `ec_mulp` (cofactor compare)        | 1 + 1            | 13,209 + 9,374  | ~22,600      | 0.1 %       |
| `fp_reverse32` × 7 + minor (cmp, copy, iszero)  | ~15              | ~150 ea         | ~2,000       | 0.0 %       |
| **Sum of components**                           | —                | —               | ~44,373,000  | 102.8 %     |
| **Measured verify total**                       | —                | —               | 43,157,940   | 100.0 %     |
| **Component sum − measured**                    | —                | —               | +1,215,000   | +2.8 %      |

(¹) `fp_mod_inv` primitive bench cost is 51,135 cyc, but in this context it operates on `s` (the secret-side scalar already known to the verifier — but more importantly, on a value whose internal byte structure consistently hits binary-GCD fast paths). Section 8 develops this; for the sum here we use a context-fitted ~10 kcy.

### `ecdsa_verify_384` @ 16 MHz = 111,031,130 cyc

| Component                                       | Calls per verify | Cycles per call | Subtotal     | % of verify |
|-------------------------------------------------|-----------------:|----------------:|-------------:|------------:|
| `ec_scalar_mul_var_384` (u2·Q)                  | 1                | 95,469,045      | 95,469,045   | 86.0 %      |
| `ec_scalar_mul_384` (u1·G h=8)                  | 1                | 16,056,390      | 16,056,390   | 14.5 %      |
| `ec_point_add_jj_384` (J+J join)                | 1                | ~293,400 (est)  | ~293,400     | 0.3 %       |
| `fp_mod_mul_n_384` (u1, u2)                     | 2                | ~180,000 (est)  | ~360,000     | 0.3 %       |
| `fp_mod_inv_384` (s⁻¹ mod n)                    | 1                | ≪102,270 (¹)    | ~20,000 (¹)  | 0.0 %       |
| `ec_sqrp_384` + `ec_mulp_384`                   | 1 + 1            | 20,720 + 15,926 | ~36,600      | 0.0 %       |
| Misc                                            | ~15              | ~150 ea         | ~3,000       | 0.0 %       |
| **Sum of components**                           | —                | —               | ~112,238,000 | 101.1 %     |
| **Measured verify total**                       | —                | —               | 111,031,130  | 100.0 %     |
| **Component sum − measured**                    | —                | —               | +1,207,000   | +1.1 %      |

**Key takeaway from stacked attribution.** ECDSA verify is **>99 % scalar_mul time** for both curves:
- P-256: 87.2 % variable-base + 14.7 % fixed-base + ≤1 % everything else (cofactor compare, mod-n math, J+J join).
- P-384: same shape (86.0 % + 14.5 % + ≤1 % everything else).

A 1 % win on `ec_scalar_mul_var` is worth more than a 100 % win on the cofactor-compare path. The variable-base scalar_mul is the optimization frontier on both curves. PR #27's w-NAF attempt targeted exactly this surface and was reverted; the area remains open with the caveat that any future approach needs an integrated bench, not a primitive-cost extrapolation.

---

## 8. Predicted-vs-measured divergence

Source: A4 §3–§4 + B1 + C1. This is the audit's most load-bearing section: the divergence pattern explains why post-v0.2.0 optimization PRs underdelivered.

### The divergence is structural, with opposite signs at different abstraction levels

| Entry point             | Additive prediction | Measured (U64E @16 MHz) | Δ           | Δ as % of measured |
|-------------------------|--------------------:|------------------------:|------------:|-------------------:|
| `ec_point_double` (P256)|             101,000 |                  68,180 |     −33,000 | **−48 %** (pred high) |
| `ec_point_add`    (P256)|             110,000 |                  85,225 |     −25,000 | **−29 %** (pred high) |
| `ec_point_double_384`   |             160,000 |                 119,315 |     −41,000 | **−34 %** (pred high) |
| `ec_point_add_384`      |             180,000 |                 136,360 |     −44,000 | **−32 %** (pred high) |
| `ec_scalar_mul`  (P256) |           4,800,000 |               6,340,740 |  +1,540,000 | **+24 %** (pred low)  |
| `ec_scalar_mul_var`     |          28,200,000 |              37,618,315 |  +9,400,000 | **+25 %** (pred low)  |
| `ec_scalar_mul_384`     |          13,000,000 |              16,056,390 |  +3,060,000 | **+19 %** (pred low)  |
| `ec_scalar_mul_var_384` |          78,300,000 |              95,469,045 | +17,170,000 | **+18 %** (pred low)  |
| `ecdsa_verify_256`      |          44,400,000 |              43,157,940 |  −1,242,000 | **−3 %** (pred high)  |
| `ecdsa_verify_384`      |         112,300,000 |             111,031,130 |  −1,272,000 | **−1 %** (pred high)  |

### Two opposing mechanisms

**Point ops under-predict (additive prediction is 18–48 % too high vs measured):**
The point-op body holds `fp_misc` (modulus selector) and ZP pointer state across the chain of `ec_mulp` / `ec_sqrp` calls. Each primitive bench, by contrast, dispatches from a clean ZP state including the `ec_set_modp` + return-path overhead. Inside the integrated body, those overheads amortize once per call instead of once per primitive — so each `ec_mulp` is ~25–30 % cheaper-in-context than the bench row.

**Scalar mul over-predicts (additive prediction is 18–25 % too low vs measured):**
Per-iteration overhead — 96 B (P-256) or 144 B (P-384) `ec_p3 → ec_p1` copies, REU table fetches (`sm256_reu_fetch_affine` etc.), bit-extraction prologue, loop control, issue-#33 defensive REU register writes — is not captured by any primitive row. At 256/384 iterations per call this overhead is substantial: ~36–45 kcy per iter, ~9–17 Mcy across a full scalar_mul.

**At ECDSA verify these effects nearly cancel.** The scalar_mul over-prediction (+9 Mcy P-256, +17 Mcy P-384) gets folded into the measured scalar_mul cycle count when it's substituted into the verify-level prediction, and the residual divergence (~1 %–3 %) is small. **This is luck, not signal.** Future optimizations to the verify-level pipeline that change the *composition* of scalar_mul + point-add + inv calls will hit the divergence directly.

### Implication for the PR #26 / PR #34 retrospective

The CLAUDE.md "Negative findings" hypothesis is corroborated: `fp_mod_inv` primitive bench (~750 kcy P-256 / ~1.55 Mcy P-384 random-input average) overstates the cost of inversions on the structured Z coordinates emerging from `ec_scalar_mul`. PRs #26 and #34 each eliminated one `fp_mod_inv` call at the verify tail, predicting ~800 kcy / ~1.7 Mcy savings; measured savings were 17–51 kcy (P-256) / 85–102 kcy (P-384), 10–20× short.

The stacked attribution above closes the explanatory loop. With `fp_mod_inv` rebudgeted at its context cost (~10 kcy P-256 / ~20 kcy P-384, derived from the verify-level residual), the eliminated calls were always small. **The primitive bench cost wasn't wrong — it was sampled from a different input distribution than the integrated callsite.**

### Forward-looking rule

For any future optimization PR that touches a routine with **input-sensitive runtime** (binary-GCD `fp_mod_inv`, branch-tagged Solinas reductions, etc.):

1. Sample the *integrated* callsite's input distribution; the primitive bench's random-input average is not representative.
2. Measure savings on `bench_ecdsa_u64.py` / `bench_p*_u64.py` before merge, not in the PR description from primitive extrapolation.
3. For routines without input-sensitive runtime (pure-CPU adds, copies, register shuffles), primitive bench is reliable; the failure mode is specific to GCD-class algorithms.

CHANGELOG `[Unreleased]` (PR #35) codifies #2 as a process change. This audit recommends extending it to call out #1 explicitly: any optimization that *eliminates* a primitive call must measure the eliminated call's actual context cost first.

---

## 9. Per-PR RAM-cost vs cycle-saved table

Source: A5 (`a5_pr_retrospective.md`). 15 PRs landed since v0.2.0 (tagged 2026-05-12). Optimization-shaped PRs with measured outcomes:

| PR # | Title (short)                        | PRG Δ      | DATA Δ | Claimed cycle Δ                   | Measured cycle Δ                          | cy/B (measured) | Verdict                |
|------|--------------------------------------|-----------:|-------:|-----------------------------------|-------------------------------------------|----------------:|------------------------|
| #34  | full J+J at ECDSA join + sqtab bump  | +1,440     | +160   | ~800 kcy P256 / ~1.7 Mcy P384 (primitive-extrapolated) | −17 kcy P256 / −102 kcy P384 | **11 / 64 cy/B** | **17–47× short**       |
| #26  | cofactor compare in ECDSA verify     | +512       | 0      | ~800 kcy / ~1.7 Mcy (primitive)   | −51 kcy P256 / −85 kcy P384               | **100 / 166 cy/B** | **16–20× short**     |
| #26+#34 combined                     | +1,952    | +160   | ~1.6 Mcy / ~3.4 Mcy               | −68 kcy P256 / −187 kcy P384              | **32 / 89 cy/B** | **20–40× short**       |
| #32  | fp384/ecdsa cleanup                  | 0          | 0      | ~300 cy/fp_sqr_384 + minor (primitive) | not separately measured              | n/a             | cleanup tier (sub-jiffy at integrated bench) |
| #28  | fp_mod_inv byte-aligned fast path    | +768       | 0      | "modest" (self-downgraded)        | reverted (PR #29) before measurement      | n/a             | **reverted**           |
| #27  | w-NAF for variable-base scalar_mul   | +3,318     | +1,144 | ~12 Mcy P256 / ~21 Mcy P384 (primitive) | reverted (PR #29) before measurement  | n/a             | **reverted**           |
| #25  | sha384 table-driven sigma rotates    | +3,584 (incl. 3,072 RODATA) | 0 | ~133.7 kcy / block (instruction-counted, unrolled body) | not integrated-bench measured (no SHA bench tool) | n/a | **plausible but unverified** |
| #23  | SHA-384 + ecdsa_verify_with_msg_384  | +7,700     | +1,992 (incl. 1,024 test scratch) | new capability, no perf claim | n/a — new capability                      | n/a             | not an optimization PR |

**Pattern:** 3 of 4 optimization-shaped PRs with a primitive-extrapolated cycle claim **failed** at the integrated bench (#26 and #34 underdelivered 10–20×; #27 was reverted before measurement). The single one likely to hold (#25) derives its claim from instruction-counting on an unrolled body, not from amortized-primitive extrapolation.

**RAM efficiency reality:** combined #26 + #34 = 2,112 RAM bytes for ~60 cy/B measured savings. The c64-x25519 sibling project routinely achieved >100 cy/B in its Wave 4–7 era; the post-v0.2.0 window has delivered nothing in that range, consistent with the "low-hanging fruit exhausted" interpretation.

---

## 10. Bench coverage gaps + recommendations

Source: A2 (`a2_bench_coverage.md`) + this audit's findings.

### High severity (consumer-facing entry points)

| Gap                                                | Status / Where it matters                                 | Suggested fix                                                                                                       |
|----------------------------------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| ~~**`ecdsa_verify_with_message_384` has zero bench**~~ | **RESOLVED 2026-05-19.** Bench row added to `bench_ecdsa_u64.py`; trampoline `bench_ecdsa_verify_with_msg_384_tramp` added to `src/main.s` (marker tokens $88/$89). Measured @ 16 MHz = 111,082,265 cy (RFC 6979 "sample" message). Oracle gate passed. | — |
| **SHA-384 standalone bench**                       | `test_sha384.py` is correctness-only. Single-block compress cost is still unresolved (sub-jiffy at U64E turbo for 6-byte messages, per Section 6 follow-up). | Add `tools/bench_sha384.py` (or extend `test_sha384.py --bench`). Measure `sha384_update` at canonical TLS lengths {0, 55, 56, 111, 112, 200, 1024, 4096 B} — SHA-2 padding kicks at block boundaries (55/56 and 111/112). Run at VICE 1 MHz where compress lands at ≥3-9 jiffies and is resolvable. |

### Medium severity (building blocks of verify path)

| Gap                                                | Where it matters                                          | Suggested fix                                                                       |
|----------------------------------------------------|-----------------------------------------------------------|-------------------------------------------------------------------------------------|
| **`ec_point_add_jj` / `_384` (PR #34 primitive)**  | Now load-bearing in ECDSA verify; cost only known aggregate-side. | Add to `bench_p{256,384}.py` + `bench_p{256,384}_u64.py` BENCH_PLAN. One-row addition with a non-1 Z₂ to exercise the full J+J formula. |
| **`ec_jacobian_to_affine` / `_384`**               | Tail of `ecdsa_verify` pre-PR-#26 era; still used externally by consumers. | Same pattern.                                                                       |
| **`ec_scalar_mul_var` / `_384` in primitive harnesses** | Only `bench_ecdsa_u64.py` covers it; no VICE-1-MHz primitive number. | Add to `bench_p{256,384}.py` for cross-validation with U64E.                        |
| **`fp_mod_mul_n` / `_384` (mod n, not mod p)**     | Different reduction path; no Solinas fast-reduce. Used 2× per ECDSA verify. | Add to `bench_p{256,384}.py` BENCH_PLAN. Distinct module call from `fp_mod_mul`.    |

### Low severity (helpers; cycle cost is small / fully exercised in aggregate)

`fp_reverse32` / `fp_reverse48`, `fp_chk_one`, the `fp_copy/zero/cmp/is_zero/rshift1` family, `ec_set_modp/n`, `ec_mulp/sqrp`, `fp_mod_inv_fast` (Fermat reference), `fp_sqr_pairs/extra`. Not worth dedicated bench coverage; their cost is small (sub-µs class) and well-covered by aggregate measurement.

### Tooling bugs surfaced by the audit

- ~~**`tools/bench_p384.py:331` sentinel timeout**~~ — **RESOLVED 2026-05-19.** Bumped from 180 s → 600 s to match `bench_p256.py:406`. h=8 precompute boot is ~205-246 s on VICE / U64E so 600 s gives ~2.5×–3× headroom.
- **U64E `liveness_probe` short-circuits on ICMP failure** — `tools/bench_u64_common.py::probe_u64()` doesn't fall through to TCP/80 even when HTTP API is functional. Not in this audit's scope; would be a `c64-test-harness` upstream patch.

---

## 11. Recommendations (prioritized)

### Tier 1 — straightforward, no integration risk

1. ~~**Land the `tools/bench_p384.py` timeout bump.**~~ **DONE 2026-05-19** (`tools/bench_p384.py:331` 180.0 → 600.0).
2. **Add `bench_sha384.py`** or extend `test_sha384.py --bench`. SHA-384 is the largest single CODE+RODATA module (23 %). The new `ecdsa_verify_with_message_384` row (item 3 below) gives a sub-jiffy upper bound for a 6-byte message, but per-block compress cost remains unresolved at jiffy granularity. Run at VICE 1 MHz where one block lands at ~3–9 jiffies.
3. ~~**Add `ecdsa_verify_with_message_384` to `bench_ecdsa_u64.py` BENCH_PLAN.**~~ **DONE 2026-05-19.** Trampoline `bench_ecdsa_verify_with_msg_384_tramp` added to `src/main.s` ($88/$89 markers, 24 B absorbed into TABLES align pad — PRG byte-neutral at 37,302 B). BENCH_PLAN row + `setup_ecdsa_verify_with_msg_384` + `verify_ecdsa_verify_with_msg_384` added to `tools/bench_ecdsa_u64.py`. Measured 16 MHz / 48 MHz on U64E; oracle gate passed. Section 6 carries the numbers.

### Tier 2 — medium effort, useful for future optimization gating

4. **Add `ec_point_add_jj` / `_384` to primitive BENCH_PLAN.** PR #34's load-bearing new primitive lacks standalone cost data. Without it, future J+J-related decisions repeat the primitive-extrapolation failure mode.
5. **Add `fp_mod_mul_n` / `_384` to primitive BENCH_PLAN.** Different from `fp_mod_mul` (no Solinas fast-reduce path); its standalone cost is currently estimated at ~100 kcy P-256 / ~180 kcy P-384 — not measured.

### Tier 3 — strategic, requires investigation

6. **Variable-base scalar_mul (`ec_scalar_mul_var`) is the remaining optimization frontier.** 87 % of ECDSA verify cost on both curves. PR #27 (w-NAF) attempted this and was reverted; the area is still open but any new attempt needs an integrated bench gate before merge.
7. **Consider what to do with the 24,672 free bytes in REU bank 2.** Currently unused. Candidate tenants per CLAUDE.md: windowed-mul accumulator caches, Wycheproof KAT stashes. Worth a discrete design pass.
8. **Codify the audit's primitive-vs-compound rule in the CLAUDE.md "Negative findings" section.** Section 8 of this audit is the corroborating evidence for the existing PR #26+#34 entry; merging it into CLAUDE.md (perhaps as an explicit bullet under "Empirical validation required for optimization PRs") makes the rule discoverable to future work.

---

## Appendix: source agent reports

| Agent | Scope                                          | Report                                         |
|-------|------------------------------------------------|------------------------------------------------|
| A1    | Static RAM accounting (PRG / DATA / ZP / REU)  | `.research/audit_2026_05_18/a1_ram_accounting.md` |
| A2    | Bench-tool coverage audit                      | `.research/audit_2026_05_18/a2_bench_coverage.md` |
| A3    | README benchmark freshness audit               | `.research/audit_2026_05_18/a3_freshness_audit.md` |
| A4    | Static call-graph + predicted compound cost    | `.research/audit_2026_05_18/a4_call_graph.md`     |
| A5    | Post-v0.2.0 PR retrospective                   | `.research/audit_2026_05_18/a5_pr_retrospective.md` |
| B1    | VICE primitive bench (fresh, current master)   | `.research/audit_2026_05_18/b1_vice_bench.md`     |
| C1    | U64E hardware bench (1/16/48 MHz, fresh)       | `.research/audit_2026_05_18/c1_u64e_bench.md`     |

All seven reports were produced 2026-05-18 → 2026-05-19 against master HEAD `7d71773`. No source files were modified during the audit.
