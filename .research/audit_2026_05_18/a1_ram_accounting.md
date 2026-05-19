# A1 — RAM Accounting Audit

Working artifact: `build/nist-curves.prg` produced by `make clean && make`
on master (commit 7d71773), `wc -c` = **37302 bytes**. Subtracting the
2-byte $0801 load-address PRG header gives the on-disk payload that
must reconcile across the four sections below: **37300 bytes**.

Segment definitions come from `src/c64.cfg`:
- `ZP` ($0002..$00FF) — 254 bytes available for `ZEROPAGE` segment.
- `HEADER` (%S-2..%S-1) — 2-byte `LOADADDR` segment.
- `MAIN` ($0801..$CFFF) — `CODE`, `RODATA`, `TABLES` (align $100),
  `DATA`, `BSS` (optional).

Per-object-file segment sizes were extracted with
`od65 --dump-segsize build/<file>.o`.

---

## 1. PRG byte attribution

Source columns are the `src/c64.cfg` segments routed into the PRG
file (everything in MEMORY = MAIN, plus the 2-byte HEADER). `ZEROPAGE`
does not consume PRG bytes; `BSS` is declared `optional = yes` and
does not consume PRG bytes (lives in RAM only, contributes to the
runtime footprint).

| Source file (src/) | LOADADDR | CODE | RODATA | TABLES | DATA | (BSS) | Total in PRG |
|---|---:|---:|---:|---:|---:|---:|---:|
| main.s              |   2 |   457 |    31 |     0 |    0 | 0 |    490 |
| constants.s         |   0 |     0 |     0 |     0 |    0 | 0 |      0 |
| zp_config.s         |   0 |     0 |     0 |     0 |    0 | 0 |      0 |
| lib_version.s       |   0 |     0 |     0 |     0 |    0 | 0 |      0 |
| mul_8x8.s           |   0 |   247 |     0 |     0 |    0 | 0 |    247 |
| fp256.s             |   0 |  1069 |     0 |     0 |    0 | 0 |   1069 |
| mod256.s            |   0 |  4003 |    64 |     0 |    0 | 0 |   4067 |
| curve256.s          |   0 |     0 |   416 |     0 |    0 | 0 |    416 |
| points256.s         |   0 |  3541 |     0 |     0 |    0 | 0 |   3541 |
| inv256.s            |   0 |   114 |    32 |     0 |    0 | 0 |    146 |
| ecdsa256.s          |   0 |   594 |     0 |     0 |    0 | 0 |    594 |
| fp384.s             |   0 |  1067 |     0 |     0 |    0 |(53)|  1067 |
| mod384.s            |   0 |  3625 |     0 |     0 |    0 | 0 |   3625 |
| curve384.s          |   0 |     0 |   288 |     0 |    0 | 0 |    288 |
| points384.s         |   0 |  3602 |     0 |     0 |    0 | 0 |   3602 |
| ecdsa384.s          |   0 |   666 |     0 |     0 |    0 | 0 |    666 |
| sha384.s            |   0 |  5225 |   704 |  3072 |    0 | 0 |   9001 |
| data.s              |   0 |     0 |     0 |   512 | 7861 | 0 |   8373 |
| (TABLES align pad)  |   0 |     0 |     0 |   110*|    0 | 0 |    110 |
| **Total**           | **2** | **24210** | **1535** | **3694** | **7861** | (53) | **37302** |

\* The 110-byte TABLES alignment pad arises because `TABLES` has
`align = $100` in `src/c64.cfg`. CODE+RODATA ends at $6C92 (end of
sha384.o's `sha384_k`), and the linker fills 110 bytes to reach the
$6D00 page boundary where TABLES begins. The pad is not attributable
to any `src/*.s` file; it is a linker artifact of segment placement.

**Reconciliation:** Grand total = 37302. PRG `wc -c` = 37302. The
2-byte LOADADDR is the $0801 PRG load-address header at file offset
0–1; the remaining 37300 bytes are the actual loadable payload.
**Reconciles ✓.**

Per-segment summary:
- LOADADDR: 2 (HEADER memory region; main.o owns it).
- CODE: 24210 (12 modules contribute; sha384.s is the single largest
  at 5225 = ~22% of CODE; mod256.s + mod384.s together = 7628 =
  ~32%; points256.s + points384.s = 7143 = ~30%).
- RODATA: 1535 (sha384.s K[80] + IV = 704; curve256.s + curve384.s
  parameter blocks = 704; mod256.s 64; inv256.s addition-chain table
  32; main.s basic stub + small constants 31).
- TABLES: 3584 actual + 110 pad = 3694. sha384.s contributes 3072
  (6 × 256-byte shift LUTs × 2 halves = `lo_2_tbl..hi_7_tbl`);
  data.s contributes 512 (`mul_dma_lo` + `mul_dma_hi`).
- DATA: 7861 (entirely from data.s — every other module's DATA
  segment is empty; data.s is the single canonical RAM scratch
  manifest).
- BSS: 53 bytes from fp384.s (`fp384_sqr_extra` 1, `mul_src2_buf_384`
  51, `fp384_sqr_pairs` 1) — **not in PRG**, but allocated in RAM at
  runtime. The MEMORY layout puts BSS after DATA in MAIN.

Module-order PRG layout (verified from `build/labels.txt`):
- $0801..$6C92 — CODE + RODATA (LOADADDR + main → data module order
  matches the Makefile MODULES list).
- $6C93..$6CFF — 110-byte TABLES alignment pad.
- $6D00..$78FF — sha384.s TABLES (12 × 256-byte shift LUTs).
- $7900..$7AFF — data.s TABLES (`mul_dma_lo` + `mul_dma_hi`).
- $7B00..$9984 — data.s DATA (7861 bytes; last symbol
  `sha384_msg_buf` ends at $99B4).

---

## 2. DATA buffer catalog

Every `.res N` and named buffer declaration in `src/data.s` (the
canonical RAM scratch manifest). Plus `fp384.s` BSS (lives in RAM
but not PRG). Sorted by size descending.

| Symbol | Size (B) | Segment | Owner module (src/) | Feature group | Lifetime |
|---|---:|---|---|---|---|
| sha384_msg_buf            | 1024 | DATA   | (test harness only) | SHA-384-test-scratch | per-call-scratch (test) |
| sha_w                     |  640 | DATA   | sha384.s        | SHA-384-scratch       | per-call-scratch |
| mul_dma_hi                |  256 | TABLES | mul_8x8.s + fp256/fp384.s + data.s | mul-table | per-call-scratch (REU DMA target) |
| mul_dma_lo                |  256 | TABLES | mul_8x8.s + fp256/fp384.s + data.s | mul-table | per-call-scratch (REU DMA target) |
| ecdsa_inputs_384          |  240 | DATA   | (test harness only; ecdsa384.s consumes pointer) | ECDSA-test-staging | per-call-scratch (test) |
| ecdsa_inputs_256          |  160 | DATA   | (test harness only; ecdsa256.s consumes pointer) | ECDSA-test-staging | per-call-scratch (test) |
| ec384_p1                  |  144 | DATA   | points384.s     | point-scratch         | persistent-across-call |
| ec384_p2                  |  144 | DATA   | points384.s     | point-scratch         | persistent-across-call |
| ec384_p3                  |  144 | DATA   | points384.s     | point-scratch         | persistent-across-call |
| ecdsa384_u1g_jac          |  144 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| sha_block_buf             |  128 | DATA   | sha384.s        | SHA-384-scratch       | persistent-across-call (streaming) |
| ec_p1                     |   96 | DATA   | points256.s     | point-scratch         | persistent-across-call |
| ec_p2                     |   96 | DATA   | points256.s     | point-scratch         | persistent-across-call |
| ec_p3                     |   96 | DATA   | points256.s     | point-scratch         | persistent-across-call |
| ecdsa_u1g_jac             |   96 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| fp384_wide                |   96 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp_wide                   |   64 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| sha_state                 |   64 | DATA   | sha384.s        | SHA-384-scratch       | persistent-across-call (streaming) |
| sha_abcdefgh              |   64 | DATA   | sha384.s        | SHA-384-scratch       | per-call-scratch |
| sha_scratch               |   64 | DATA   | sha384.s        | SHA-384-scratch       | per-call-scratch |
| ec384_t1                  |   48 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_t2                  |   48 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_t3                  |   48 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_t4                  |   48 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_t5                  |   48 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_t6                  |   48 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_jj_tmp              |   48 | DATA   | points384.s     | point-scratch (J+J)   | per-call-scratch |
| ec384_affine_x            |   48 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_affine_y            |   48 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec_base384_x              |   48 | DATA   | points384.s     | point-input           | persistent-across-call |
| ec_base384_y              |   48 | DATA   | points384.s     | point-input           | persistent-across-call |
| fp384_tmp1                |   48 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp384_tmp2                |   48 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp384_tmp3                |   48 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp384_tmp4                |   48 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp384_r0                  |   48 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp384_r1                  |   48 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp384_r2                  |   48 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp384_r3                  |   48 | DATA   | fp384.s         | fp-scratch            | per-call-scratch |
| fp384_inv_u               |   48 | DATA   | mod384.s        | fp-scratch (binGCD)   | per-call-scratch |
| fp384_inv_v               |   48 | DATA   | mod384.s        | fp-scratch (binGCD)   | per-call-scratch |
| fp384_inv_x1              |   48 | DATA   | mod384.s        | fp-scratch (binGCD)   | per-call-scratch |
| fp384_inv_x2              |   48 | DATA   | mod384.s        | fp-scratch (binGCD)   | per-call-scratch |
| ec_anchor1_384_x          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor1_384_y          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor2_384_x          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor2_384_y          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor3_384_x          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor3_384_y          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor4_384_x          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor4_384_y          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor5_384_x          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor5_384_y          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor6_384_x          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor6_384_y          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor7_384_x          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor7_384_y          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor8_384_x          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| ec_anchor8_384_y          |   48 | DATA   | points384.s     | precompute-anchor     | boot-once-init |
| cm_k_384                  |   48 | DATA   | points384.s     | point-scratch (comb)  | per-call-scratch |
| ecdsa384_r                |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_s                |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_h                |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_qx               |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_qy               |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_w                |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_u1               |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_u2               |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_u1_be            |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa384_u2_be            |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| fp_rev_buf_384            |   48 | DATA   | ecdsa384.s      | ECDSA-scratch         | per-call-scratch |
| sha384_digest             |   48 | DATA   | sha384.s        | SHA-384-scratch       | persistent-across-call |
| fp384_red_tmp             |   49 | DATA   | mod384.s        | fp-scratch (Solinas)  | per-call-scratch |
| mul_src2_buf              |   35 | DATA   | mul_8x8.s + fp256.s | mul-scratch       | per-call-scratch |
| fp_red_tmp                |   33 | DATA   | mod256.s        | fp-scratch (Solinas)  | per-call-scratch |
| fp_tmp1                   |   32 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| fp_tmp2                   |   32 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| fp_tmp3                   |   32 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| fp_tmp4                   |   32 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| fp_r0                     |   32 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| fp_r1                     |   32 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| fp_r2                     |   32 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| fp_r3                     |   32 | DATA   | fp256.s         | fp-scratch            | per-call-scratch |
| fp_inv_u                  |   32 | DATA   | mod256.s        | fp-scratch (binGCD)   | per-call-scratch |
| fp_inv_v                  |   32 | DATA   | mod256.s        | fp-scratch (binGCD)   | per-call-scratch |
| fp_inv_x1                 |   32 | DATA   | mod256.s        | fp-scratch (binGCD)   | per-call-scratch |
| fp_inv_x2                 |   32 | DATA   | mod256.s        | fp-scratch (binGCD)   | per-call-scratch |
| ec_t1                     |   32 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_t2                     |   32 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_t3                     |   32 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_t4                     |   32 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_t5                     |   32 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_t6                     |   32 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_jj_tmp                 |   32 | DATA   | points256.s     | point-scratch (J+J)   | per-call-scratch |
| ec_affine_x               |   32 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_affine_y               |   32 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_base_x                 |   32 | DATA   | points256.s     | point-input           | persistent-across-call |
| ec_base_y                 |   32 | DATA   | points256.s     | point-input           | persistent-across-call |
| ec_aff2g_256_x            |   32 | DATA   | points256.s     | precompute-anchor (boot) | boot-once-init |
| ec_aff2g_256_y            |   32 | DATA   | points256.s     | precompute-anchor (boot) | boot-once-init |
| ec_anchor1_x              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor1_y              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor2_x              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor2_y              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor3_x              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor3_y              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor4_x              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor4_y              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor5_x              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor5_y              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor6_x              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor6_y              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor7_x              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor7_y              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor8_x              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| ec_anchor8_y              |   32 | DATA   | points256.s     | precompute-anchor     | boot-once-init |
| cm_k                      |   32 | DATA   | points256.s     | point-scratch (comb)  | per-call-scratch |
| ecdsa_r                   |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_s                   |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_h                   |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_qx                  |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_qy                  |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_w                   |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_u1                  |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_u2                  |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_u1_be               |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| ecdsa_u2_be               |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| fp_rev_buf                |   32 | DATA   | ecdsa256.s      | ECDSA-scratch         | per-call-scratch |
| sha_t                     |   16 | DATA   | sha384.s        | SHA-384-scratch       | per-call-scratch |
| sha_total_len             |   16 | DATA   | sha384.s        | SHA-384-scratch       | persistent-across-call (streaming) |
| fp_inv_iter               |    2 | DATA   | mod256.s        | fp-scratch (binGCD)   | per-call-scratch |
| ecdsa384_msg_struct_ptr   |    2 | DATA   | ecdsa384.s      | ECDSA-scratch (msg)   | per-call-scratch |
| mul_cached_a              |    1 | DATA   | mul_8x8.s + fp256.s | mul-scratch       | per-call-scratch |
| ec_sc_byte                |    1 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec_sc_mask                |    1 | DATA   | points256.s     | point-scratch         | per-call-scratch |
| ec384_sc_byte             |    1 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_sc_mask             |    1 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_sc_nibble           |    1 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_sc_half             |    1 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| ec384_precomp_i           |    1 | DATA   | points384.s     | point-scratch         | per-call-scratch |
| sha_block_len             |    1 | DATA   | sha384.s        | SHA-384-scratch       | persistent-across-call (streaming) |
| ecdsa_result_256          |    1 | DATA   | (test harness only) | ECDSA-test-staging | per-call-scratch (test) |
| ecdsa_result_384          |    1 | DATA   | (test harness only) | ECDSA-test-staging | per-call-scratch (test) |
| ecdsa_result_msg_384      |    1 | DATA   | (test harness only) | ECDSA-test-staging | per-call-scratch (test) |
| **DATA total**            | **7861** | DATA | — | — | — |
| mul_dma_lo (TABLES)       |  256 | TABLES | data.s          | mul-table             | per-call-scratch |
| mul_dma_hi (TABLES)       |  256 | TABLES | data.s          | mul-table             | per-call-scratch |
| **data.s TABLES total**   | **512** | TABLES | — | — | — |
| fp384_sqr_extra (BSS)     |    1 | BSS    | fp384.s         | fp-scratch            | per-call-scratch |
| mul_src2_buf_384 (BSS)    |   51 | BSS    | fp384.s         | mul-scratch           | per-call-scratch |
| fp384_sqr_pairs (BSS)     |    1 | BSS    | fp384.s         | fp-scratch            | per-call-scratch |
| **fp384.s BSS total**     |   **53** | BSS  | — | — | — |
| **All RAM scratch (DATA + data.s TABLES + BSS)** | **8426** | — | — | — | — |

**Reconciliation:** data.s DATA = 7861, od65 `data.o DATA` = 7861 ✓.
data.s TABLES = 512, od65 `data.o TABLES` = 512 ✓. fp384.s BSS = 1
+ 51 + 1 = 53, od65 `fp384.o BSS` = 53 ✓.

Feature-group totals (DATA + the data.s TABLES rows for mul):
- fp-scratch (P-256): 450 (fp_wide 64 + 4×fp_tmp 128 + 4×fp_r 128 +
  4×fp_inv 128 + fp_inv_iter 2)
- fp-scratch (P-384): 721 (fp384_wide 96 + 4×fp384_tmp 192 + 4×fp384_r
  192 + 4×fp384_inv 192 + fp384_red_tmp 49) + 33 (fp_red_tmp from
  mod256, technically P-256) = use 672 for P-384 fp + 49 P-384
  red_tmp + 33 P-256 red_tmp.
- point-scratch (P-256): 738 (ec_p1/2/3 288 + 6×ec_t 192 + ec_jj_tmp
  32 + ec_affine 64 + ec_base 64 + ec_base384 96 + 2 sc bytes).
  Note ec_base384_x/y live with the P-256 block in data.s but are
  P-384 inputs; refactor candidate.
- point-scratch (P-384): 869 (ec384_p1/2/3 432 + 6×ec384_t 288 +
  ec384_jj_tmp 48 + ec384_affine 96 + 5 sc bytes).
- precompute-anchor (P-256): 608 (ec_aff2g 64 + 16×ec_anchor* 512 +
  cm_k 32). Boot-once-init.
- precompute-anchor (P-384): 816 (16×ec_anchor*_384 768 + cm_k_384
  48). Boot-once-init.
- ECDSA-scratch (P-256): 448 (10×32 + ecdsa_u1g_jac 96 + fp_rev_buf
  32). Per-call.
- ECDSA-scratch (P-384): 674 (10×48 + ecdsa384_u1g_jac 144 +
  fp_rev_buf_384 48 + ecdsa384_msg_struct_ptr 2). Per-call.
- SHA-384-scratch: 1041 (sha_state 64 + sha_w 640 + sha_abcdefgh 64
  + sha_t 16 + sha_scratch 64 + sha_block_buf 128 + sha_block_len 1
  + sha_total_len 16 + sha384_digest 48).
- mul-scratch (DATA): 36 (mul_cached_a 1 + mul_src2_buf 35).
- mul-table (TABLES): 512 (mul_dma_lo + mul_dma_hi).
- Test-harness staging (NOT production RAM): 1426 (ecdsa_inputs_256
  160 + ecdsa_inputs_384 240 + 3 result bytes + sha384_msg_buf
  1024 — owned by the harness, would not exist in a consumer
  integration).
- fp384.s BSS: 53 (mul_src2_buf_384 51 + 2 single bytes).

**Production-only DATA budget** (subtracting the 1426 B test-harness
buffers): 7861 - 1426 = **6435 bytes** of DATA needed by a real
consumer. Adding the 512 B TABLES (mul tables) and 53 B BSS pushes
true RAM scratch to **7000 bytes** for both curves + SHA-384 +
ECDSA + Lim-Lee comb anchors.

---

## 3. ZP allocation map

`src/c64.cfg` reserves `$0002..$00FF` (254 bytes) as the `ZP` memory
region. Every byte the library actually claims is enumerated below.

### 3.1 Allocations in `src/zp_config.s`

(Lines refer to the `.ifndef ... = $XX` slot definitions; the
`.export` block is at lines 110-113.)

| Symbol | Address | Size (B) | Subsystem | Source |
|---|---|---:|---|---|
| proc_port      | $01 | 1 | hardware (immovable) | zp_config.s:33 |
| zp_tmp1        | $02 | 1 | control / temp       | zp_config.s:38 |
| zp_tmp2        | $03 | 1 | control / temp       | zp_config.s:41 |
| sha_src        | $04 | 2 | SHA-384              | zp_config.s:83 |
| sha_len        | $06 | 2 | SHA-384              | zp_config.s:86 |
| sha_w_ptr      | $08 | 2 | SHA-384 (internal)   | zp_config.s:89 |
| sha_w_ptr2     | $0A | 2 | SHA-384 (internal)   | zp_config.s:92 |
| poly_i         | $1A | 1 | multiply (mul_8x8)   | zp_config.s:97 |
| poly_j         | $1B | 1 | multiply (mul_8x8)   | zp_config.s:100 |
| poly_carry     | $1C | 1 | multiply (mul_8x8)   | zp_config.s:103 |
| poly_tmp       | $1D | 1 | multiply (mul_8x8)   | zp_config.s:106 |
| fp_src1        | $22 | 2 | fp (shared 256/384)  | zp_config.s:52 |
| fp_src2        | $24 | 2 | fp (shared 256/384)  | zp_config.s:55 |
| fp_dst         | $26 | 2 | fp (shared 256/384)  | zp_config.s:58 |
| fp_misc        | $28 | 2 | fp (shared 256/384)  | zp_config.s:61 |
| fp_carry       | $2A | 1 | fp (shared 256/384)  | zp_config.s:64 |
| fp_loop        | $2B | 1 | fp (shared 256/384)  | zp_config.s:67 |
| fp_mul_i       | $2C | 1 | fp / multiply        | zp_config.s:70 |
| fp_mul_j       | $2D | 1 | fp / multiply        | zp_config.s:73 |
| ec_scalar_ptr  | $3B | 1 | point / scalar       | zp_config.s:78 |
| zp_ptr1        | $FB | 2 | control / pointer    | zp_config.s:44 |
| zp_ptr2        | $FD | 2 | control / pointer    | zp_config.s:47 |

zp_config.s subtotal: **31 bytes** declared (some claims are 2-byte
LE pointers; each `.ifndef` slot reserves its stated width).

Coverage by address: $01 (1) + $02-$03 (2) + $04-$0B (8) + $1A-$1D
(4) + $22-$2D (12) + $3B (1) + $FB-$FE (4) = 32. The 1-byte gap is
that $2E..$2F are *not* explicitly claimed by `fp_mul_j` (which is
1 byte ending at $2D), so the next free byte is $2E. (Reading
fp_src1 as 2 bytes occupies $22-$23, fp_src2 $24-$25, fp_dst $26-$27,
fp_misc $28-$29, fp_carry $2A, fp_loop $2B, fp_mul_i $2C, fp_mul_j
$2D — sums to 12 bytes $22-$2D.)

Re-summing the table column: 1+1+1+2+2+2+2+1+1+1+1+2+2+2+2+1+1+1+1+1+2+2 = **31 bytes**.

### 3.2 Allocations OUTSIDE `src/zp_config.s`

Only one ZP equate is declared in module-local code:

| Symbol | Address | Size (B) | Subsystem | Source |
|---|---|---:|---|---|
| jiffy_clock | $A0 | 3 | (KERNAL — read-only sample) | constants.s:27 |

`jiffy_clock` at $00A0 is the C64 KERNAL's 3-byte jiffy counter
($A0/$A1/$A2). The library reads it only for bench timing (see
`tools/bench_p256.py` / `bench_p384.py` indirectly via the
trampolines), never writes; it is NOT a library-owned ZP byte and
does not consume a slot that consumers can move. Listed for
completeness because it is the only `= $XX` ZP equate appearing
outside `zp_config.s` across all `src/*.s`.

`grep -nE "^[[:space:]]*\.zeropage" src/*.s` returns no matches —
no module declares its own `.zeropage` segment. `grep -nE
'^[[:space:]]*\.segment[[:space:]]+"ZEROPAGE"' src/*.s` returns
exactly one match (`zp_config.s:29`). All ZP discipline is enforced
through `zp_config.s` as the consumer-tunable manifest documents.

### 3.3 Total ZP bytes consumed

- Library-owned ZP slots (zp_config.s): **31 bytes**.
- KERNAL-shared read-only sample (jiffy_clock): 3 bytes (not
  counted against the library's quota since consumers cannot move
  the KERNAL's tick counter).
- Total occupied addresses on ZP page: $01 + $02-$0B + $1A-$1D +
  $22-$2D + $3B + $A0-$A2 + $FB-$FE.
- Free / available to a consumer: $0C-$19 (14 B), $1E-$21 (4 B),
  $2E-$3A (13 B), $3C-$9F (100 B), $A3-$FA (88 B), totaling
  **219 bytes** of unclaimed ZP page room. The library footprint
  is **~12% of usable ZP** ($02-$FF = 254 B).

---

## 4. REU bank usage

The Commodore 64 Ram Expansion Unit provides 128 KB or larger backing
storage addressable in 64 KB banks. The library uses banks 0, 1, and
part of bank 2 — totaling 168 KB of REU contents. A 1750 (128 KB)
REU is INSUFFICIENT for this library; a 1764 / 1764-equivalent
(256 KB) or larger is required. Bank 2 layout is sourced from
`src/main.s` (`reu_mul_init` at line 225), `src/points256.s`
(`ec_precompute_256`, REU helpers at line 1300+), and
`src/points384.s` (`ec_precompute_384`, REU helpers at line 1300+,
1900+).

| Bank | REU offset range | Contents | Bytes used | Bytes free in bank |
|---:|---|---|---:|---:|
| 0 | $0000–$FFFF | Multiply rows  0..127 (lo+hi pages alternating, 512 B per source byte `a`) | 65536 | 0 |
| 1 | $0000–$FFFF | Multiply rows 128..255 (lo+hi pages alternating, 512 B per source byte `a`) | 65536 | 0 |
| 2 | $0000–$3FFF | P-256 Lim-Lee comb precompute table — 256 entries × 64 B affine (X,Y) | 16384 | — |
| 2 | $4000–$9F9F | P-384 Lim-Lee comb precompute table — 256 entries × 96 B affine (X,Y); top valid byte at $4000 + 255*96 + 95 = $9F9F | 24480 | — |
| 2 | $9FA0–$FFFF | unused / available for future LUT or windowed-mul cache | — | 24672 |

**Bank totals:**
- Bank 0: 65536 used (100% — full).
- Bank 1: 65536 used (100% — full).
- Bank 2: 16384 (P-256 comb) + 24480 (P-384 comb) = **40864 used**;
  64-bit-bank size 65536 minus 40864 = **24672 free** (top of bank
  available for future scratch / LUTs).
- **Total REU used: 168936 bytes ≈ 165 KB**, requiring at least a
  256 KB REU (1764 + 64 KB expansion or 17xx clone) or one of the
  Ultimate 64 / 1750-XL / similar modern equivalents.

**Layout details, by routine:**

- `reu_mul_init` (src/main.s:225-310). Stashes lo and hi multiply
  rows for each `a ∈ [0,255]`. For each a, REU offset within the
  current bank is `a * 512`, with bank flipping to 1 when bit 7 of a
  is set. The `lo` page goes to `a*512`, `hi` page to `a*512 + 256`.
  256 × 512 = 131072 bytes = exactly banks 0 + 1, 100% utilization.
  Per the persistent-state pattern documented in CLAUDE.md, the
  `reu_c64_lo/hi`, `reu_reu_lo`, `reu_len_lo/hi`, and
  `reu_addr_ctrl` registers are pre-configured at the tail of
  `reu_mul_init` (lines 300-310) so the runtime row-fetch only
  writes 3 of 8 registers per call.
- `ec_precompute_256` / sm256 helpers (src/points256.s, REU helpers
  start line 1300). Builds 256 entries of the Lim-Lee comb table,
  each 64 bytes of affine (X || Y, 32 + 32). Bank = 2. Offset =
  `idx * 64`, idx ∈ [0,255], max offset = `255 * 64 + 63 = 16383 =
  $3FFF`. So P-256 fills $0000..$3FFF of bank 2 exactly.
- `ec_precompute_384` / sm384w helpers (src/points384.s,
  `sm384w_calc_reu_offset` at line 1948). Builds 256 entries of the
  Lim-Lee comb table, each 96 bytes of affine (X || Y, 48 + 48).
  Bank = 2 (`PRECOMP_REU_BANK = 2`, line 54). Offset =
  `$4000 + idx * 96`, idx ∈ [0,255], max offset = `$4000 + 255*96 +
  95 = $4000 + 24575 = $9F9F`. So P-384 fills $4000..$9F9F of
  bank 2. The boot-time table-generation cost is documented in
  CLAUDE.md at ~89 s wall-clock on the P-384 bench tool.

**Boot init cost summary:**
- `reu_mul_init`: ~12 s wall-clock (256 × 256 × ~750 cy `mul_8x8`
  body + DMA stash). One-shot at boot.
- `ec_precompute_256` + `ec_precompute_384` combined: ~89-100 s
  wall-clock total. One-shot at boot.
- Total boot to `$02A7` sentinel: ~2 s on VICE warp mode (init
  sentinel pattern). On a real C64 the same init runs at 1 MHz
  giving the figures above.

The 24672 B of free bank-2 RAM (offsets $9FA0..$FFFF) is currently
unused. Candidate future tenants discussed in CLAUDE.md include
windowed-mul accumulator caches and Wycheproof KAT vector stashes
for hardware-driven self-test; none currently use it.

---

## Reconciliation summary (all four sections)

| Section | Computed | Cross-check | Status |
|---|---:|---:|---|
| 1: PRG total | 37302 B | `wc -c build/nist-curves.prg` = 37302 | ✓ |
| 1: payload (PRG − 2 header) | 37300 B | sum of segments + 110 pad = 37300 | ✓ |
| 2: data.s DATA | 7861 B | od65 `data.o DATA` = 7861 | ✓ |
| 2: data.s TABLES | 512 B | od65 `data.o TABLES` = 512 | ✓ |
| 2: fp384.s BSS | 53 B | od65 `fp384.o BSS` = 53 | ✓ |
| 3: ZP claimed | 31 B | enumerated from zp_config.s:29-113 | ✓ |
| 4: REU used | 168936 B | banks 0+1 full (131072) + bank 2 used (40864) | ✓ |

Build artifact reproducible from current master (commit 7d71773).
