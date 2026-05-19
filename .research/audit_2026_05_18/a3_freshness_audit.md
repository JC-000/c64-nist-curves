# A3 — README benchmark freshness audit (2026-05-18)

**Scope.** Determine FRESH / STALE / UNCERTAIN status for every benchmark row
in `README.md` against current `master` HEAD.

**Audit anchor.** `git rev-parse HEAD = 7d717732b74534c11fc92aac7a2f69b640cc9d84`
(commit `7d71773`, PR #35, docs, 2026-05-18). The task brief named
`788acc3` as "today's HEAD"; the actual HEAD short-SHA is `7d71773` and
PR #34 (which the brief is plausibly referencing) is `788adc3` — one
commit behind HEAD. The single commit between PR #34 and HEAD is `7d71773`
itself, a docs-only commit that touched `README.md` lines 122–125 and
the negative-findings paragraph beneath them (no source edits). For this
audit, master state = post-PR-#34 source tree + PR #35 README refresh of
the ECDSA bench rows.

**Method.** For each row: blame the README line to find the SHA that last
wrote that number; `git log -- src/<file>.s` for the implementing file's
most-recent SHA; classify FRESH / STALE / UNCERTAIN based on whether any
post-row-date src change can plausibly move the cycle count.

**Post-v0.2.0 PR ledger** (squash-merge, one line = one PR; reverse chronological):

| SHA | Date | PR | Net src impact on bench surface |
|---|---|---|---|
| `7d71773` | 2026-05-18 | #35 | None (docs only; rewrites README ECDSA table) |
| `788adc3` | 2026-05-17 | #34 | adds `ec_point_add_jj[_384]` + rewires ECDSA verify; sqtab address bump; `ec_point_double/_add/_scalar_mul` byte-identical |
| `f451978` | 2026-05-17 | #33 | None (bench tooling only) |
| `fbb4f8b` | 2026-05-17 | #32 | `fp_sqr_384` inlines `reu_fetch_mul_row` (~−300 cy/call × 48 diag iters); collapses ecdsa BE→LE reversal blocks |
| `2ac34a0` | 2026-05-17 | #31 | None (build system: emits `.dbg`; PRG byte-identical) |
| `c328e75` | 2026-05-16 | #30 | None (harness tooling only) |
| `fb37d67` | 2026-05-16 | #29 | REVERT of #27 and #28; restores `mod256/384.s` and `points256/384.s` to v0.2.0 state |
| `34beb1f` | 2026-05-16 | #28 | reverted by #29 — net zero |
| `b5d0c57` | 2026-05-16 | #27 | reverted by #29 — net zero |
| `460de8f` | 2026-05-16 | #26 | cofactor compare in ECDSA verify (eliminates final Z^-1 inv); only `ecdsa256/384.s` |
| `d09d294` | 2026-05-16 | #25 | None on bench surface (sha384 LUT only) |
| `90830c9` | 2026-05-15 | #24 | None (docs only) |
| `09f9ee1` | 2026-05-15 | #23 | adds sha384 + ecdsa_verify_with_message_384; no points/fp changes |
| `e8c4d4f` | 2026-05-15 | #22 | None (tools / API.md only) |
| `7071d55` | 2026-05-12 | #21 | v0.2.0: adds REU-residue defence (+6 cy/call) at fp_mul, fp_sqr, ec_scalar_mul[_var], ecdsa_verify_* for BOTH curves |
| `8e66670` | 2026-04-20 | #20 | relocates `reu_fetch_mul_row`; no semantic delta to fp ops |
| `d53971e` | 2026-04-20 | #19 | adds ECDSA verify, variable-base scalar_mul (new public symbols only) |

**Net code state at master HEAD vs pre-v0.2.0 baseline (the era when most
README benches were measured):**

- `src/fp256.s`: only PR #21 +6 cy defence at `fp_mul` / `fp_sqr`.
- `src/fp384.s`: PR #21 +6 cy defence + PR #32 fp_sqr_384 inline (~−300 cy/call).
- `src/mod256.s`, `src/mod384.s`: net byte-identical to v0.2.0 (PR #28 reverted).
- `src/points256.s`: only PR #21 +6 cy defence at `ec_scalar_mul[_var]` +
  PR #34 ADDED `ec_point_add_jj` (does not touch `ec_point_double` /
  `ec_point_add` (mixed) / `ec_scalar_mul`).
- `src/points384.s`: same pattern as 256, plus the PR #32 inline benefits
  `ec_point_double_384` / `ec_point_add_384` / `ec_scalar_mul_384` /
  `ec_scalar_mul_var_384` via the `fp_sqr_384` callgraph.
- `src/ecdsa256.s` / `src/ecdsa384.s`: heavily rewritten by PR #26 (cofactor
  compare) + PR #32 (BE↔LE collapse, infinity fuse) + PR #34 (J+J join +
  drop `@ev_r_from_u1g`).

---

## 1. Per-row freshness table

### Table I — "Benchmarks (NTSC, ~1.02 MHz, VIC blanked)" (README lines 60–74)

| Line | Routine | Impl file | Impl last-changed | Row blame | Status | Rationale |
|---|---|---|---|---|---|---|
| 62 | fp_add (256/384) | src/fp256.s / src/fp384.s | `7071d55` 2026-05-12 (v0.2.0 +6 cy defence; affects fp_mul/sqr not fp_add) / `fbb4f8b` 2026-05-17 | `6e69610` 2026-04-05 | **FRESH** | fp_add was never touched by any of the +6 cy DMA-entry defences; only fp_mul/fp_sqr DMA initiators got it. fp_add ≈ memcpy with carry; impl is byte-identical to row date. |
| 63 | fp_sub (256/384) | src/fp256.s / src/fp384.s | `7071d55` 2026-05-12 / `fbb4f8b` 2026-05-17 | `d6baa4e` 2026-04-05 | **FRESH** | Same logic — fp_sub has no REU DMA call; unmodified since 2026-04-05. |
| 64 | fp_mul (wide) | src/fp256.s / src/fp384.s | `7071d55` 2026-05-12 / `fbb4f8b` 2026-05-17 | `5849973` 2026-04-10 | **STALE** | v0.2.0 (PR #21) added +6 cy/call to BOTH `fp_mul` and `fp_mul_384`; row predates v0.2.0. Impact is +6 cy in ~76k-cycle P-256 `fp_mul` (~0.008%) — below VICE jiffy quantisation, but the row date is technically older than the implementation. Cosmetically stale; numerically within noise. |
| 65 | fp_sqr (wide) | src/fp256.s / src/fp384.s | `7071d55` 2026-05-12 / `fbb4f8b` 2026-05-17 | `5849973` 2026-04-10 | **STALE** (P-384 row only); FRESH-equivalent (P-256) | Same +6 cy story; ADDITIONALLY P-384 `fp_sqr_384` gained ~−300 cy/call from PR #32 inline (`fbb4f8b`, 2026-05-17). 300 cy / ~120k P-384 fp_sqr ≈ 0.25%; still below VICE jiffy quant (~17 ms), but the P-384 ms-column number 121.666 ms predates `fbb4f8b`. P-256 `fp_sqr` is unchanged, so its number is FRESH (modulo the +6 cy cosmetic stale). |
| 66 | fp_mod_add | src/mod256.s / src/mod384.s | net unchanged since v0.2.0 (PR #28 reverted by #29) | `5849973` 2026-04-10 | **FRESH** | mod256/384.s at HEAD is byte-identical to its 2026-04-10 state. |
| 67 | fp_mod_sub | src/mod256.s / src/mod384.s | net unchanged | `d6baa4e` 2026-04-05 | **FRESH** | Same. |
| 68 | fp_mod_reduce (Solinas) | src/mod256.s / src/mod384.s | net unchanged | `6e69610` 2026-04-05 | **FRESH** | Same. |
| 69 | fp_mod_mul | src/mod256.s + src/fp256.s | inherits fp_mul +6 cy | `5849973` 2026-04-10 | **STALE (cosmetic)** | Same +6 cy as fp_mul row; below jiffy quant. |
| 70 | fp_mod_sqr | src/mod256.s + src/fp256.s / 384 | inherits fp_sqr | `5849973` 2026-04-10 | **STALE** (P-384); cosmetic (P-256) | P-384 row inherits the ~−300 cy/call PR #32 gain (`fbb4f8b`). Same as row 65. |
| 71 | fp_mod_inv (binary GCD) | src/mod256.s / src/mod384.s | net unchanged | `6e69610` 2026-04-05 | **FRESH** | Binary-GCD impl not modified at master; PR #28's u/v low-byte-zero fast path was reverted with #27 by #29. |
| 72 | ec_point_double (Jacobian) | src/points256.s / src/points384.s | core impl unchanged since 2026-04-10 (only +6 cy defence at the top-level scalar_mul entries) | `5849973` 2026-04-10 | **STALE (P-384 cascade)**; FRESH-equivalent (P-256) | `ec_point_double` itself byte-identical. P-384 path benefits from PR #32 `fp_sqr_384` inline (4 sqr/double × ~300 cy ≈ −1200 cy / call). Below jiffy quant (~17 ms vs ~950 ms total). P-256 row is FRESH. |
| 73 | ec_point_add (Jacobian) | src/points256.s / src/points384.s | core impl unchanged | `5849973` 2026-04-10 | **STALE (P-384 cascade)**; FRESH-equivalent (P-256) | Same logic; PR #32 fp_sqr_384 helps the P-384 add chain. |
| 74 | ec_scalar_mul (k=RFC 6979) | src/points256.s / src/points384.s | top-level routine got +6 cy in v0.2.0; ~32 (P-256) / 48 (P-384) doublings per call propagate fp_sqr_384 deltas in P-384 | `b90dc80` 2026-04-11 | **STALE** | P-256 row predates the v0.2.0 +6 cy (negligible). P-384 row inherits ~48 × ~1200 cy (`fp_sqr_384` PR #32) ≈ ~58k cy faster per call = ~0.04% of 131,433.3 ms — below VICE jiffy quant. Cosmetic. |

**Table I overall takeaway.** The VICE table values are quantised to NTSC
jiffy (~17.045 ms = ~17,045 cy at 1 MHz), so individual rows can survive
small per-call deltas without numerically changing. None of the post-row
src changes (+6 cy DMA defence, ~−300 cy/call P-384 fp_sqr_384 inline) is
large enough to move a row by one jiffy at 1 MHz. **Treat every "STALE"
flag in Table I as cosmetic-only**: the README number is technically
older than the implementation but the numerical difference is below the
measurement resolution.

### Table II — "Ultimate 64 Elite turbo benchmarks (VIC blanked)" (README lines 84–93)

All rows blame to `c3772774` (2026-04-12). Cycle counts are
1-MHz-equivalent wall-clock (jiffy × 17045) — same jiffy quant as
Table I but better noise margin because the turbo numbers count fewer
jiffies per call.

| Line | Routine | Impl file | Impl last-changed | Status | Rationale |
|---|---|---|---|---|---|
| 86 | fp_mul (256 / 384) | src/fp256.s / src/fp384.s | `7071d55` 2026-05-12 / `fbb4f8b` 2026-05-17 | **STALE (cosmetic)** | +6 cy DMA defence (v0.2.0); below 1-jiffy quant at any speed. Numbers match 16/48 MHz @ ~8.9k / 6.2k (P-256) and ~15.4k / 10.0k (P-384) cy — these are 1-MHz-equivalent µs (page rule: see lines 145–154); +6 raw cy at 1 MHz = 6 µs, well below 17,045 µs jiffy. |
| 87 | fp_sqr (256 / 384) | src/fp256.s / src/fp384.s | `7071d55` 2026-05-12 / `fbb4f8b` 2026-05-17 | **STALE** (P-384); cosmetic (P-256) | P-384 fp_sqr_384 ~−300 cy/call inline (PR #32). At 1 MHz that's 300 µs / ~20k µs = 1.5% — still below jiffy quant in the cycle column but the wall-clock at turbo could differ by ~1 ms over a full benchmark frame. Worth re-measuring once VICE/U64E benches re-run; P-384 fp_sqr row of 20,294 cy @ 16 MHz / 16,210 cy @ 48 MHz should drop to ~19,990 / ~15,910 (one jiffy = 17,045 cy). |
| 88 | fp_mod_mul (256 / 384) | inherits fp_mul | as fp_mul | **STALE (cosmetic)** | Same as row 86. |
| 89 | fp_mod_sqr (256 / 384) | inherits fp_sqr | as fp_sqr | **STALE** (P-384); cosmetic (P-256) | Same as row 87. |
| 90 | fp_mod_inv (binary GCD) | src/mod256.s / src/mod384.s | net unchanged since v0.2.0 | **FRESH** | Binary GCD untouched at master; PR #28 fast-path reverted. |
| 91 | ec_point_double (256 / 384) | src/points256.s / src/points384.s | core untouched; cascade via fp_sqr_384 | **STALE (P-384 cascade)**; cosmetic (P-256) | P-384 ec_point_double uses ~4 `fp_sqr_384` per call: ~4 × −300 cy ≈ −1200 cy. At 16 MHz turbo (1-MHz-equiv 136,360 cy) that's −0.9%; would shave roughly one jiffy. |
| 92 | ec_point_add (256 / 384) | src/points256.s / src/points384.s | core untouched; cascade via fp_sqr_384 | **STALE (P-384 cascade)**; cosmetic (P-256) | P-384 ec_point_add ~3 sqr ≈ −900 cy. Borderline jiffy. |
| 93 | ec_scalar_mul (h=8 comb) | src/points256.s / src/points384.s | top-level +6 cy in v0.2.0; deep cascade in P-384 | **STALE** (P-384); cosmetic (P-256) | P-384 ec_scalar_mul_384 has 48 iters × ~4 sqr ≈ ~57k cy savings from PR #32, ~0.4% of 16M cy. Crosses jiffy resolution — could see a 3–4 jiffy delta (~50k–70k cy) in the cycle column. Numerically detectable at U64E. |

**Table II overall takeaway.** P-256 rows are **cosmetic-stale**
(implementation is +6 cy newer, far below measurement resolution).
**P-384 rows for fp_sqr, fp_mod_sqr, ec_point_double, ec_point_add,
ec_scalar_mul are NUMERICALLY STALE** — the PR #32 `fp_sqr_384`
inline ladder propagates through the entire P-384 point-op callgraph
and a fresh measurement should detect the difference at U64E
resolution (probably 1–4 jiffies per row).

### Table III — "ECDSA verify / variable-base scalar_mul bench (U64E)" (README lines 120–125)

Lines 127–128 of README explicitly state: *"Numbers above are the
measured-2026-05-18 values at master HEAD 788adc3 (post-PR-#34
cofactor approach (a))."* and rows 123–125 are blamed to commit
`7d717732` 2026-05-18 (PR #35), confirming the rows reflect today's
master.

| Line | Primitive | Impl file | Impl last-changed | Row blame | Status | Rationale |
|---|---|---|---|---|---|---|
| 122 | ec_scalar_mul_var | src/points256.s | core ec_scalar_mul_var unchanged from PR #19 baseline at HEAD (PR #27 reverted) | `d53971e` 2026-04-20 (PR #19 — initial table) | **FRESH** | Only intervening src change to ec_scalar_mul_var is PR #21 +6 cy at entry — well below jiffy quant. PR #27 (w-NAF) was reverted. Row value is consistent with current master behaviour. |
| 123 | ec_scalar_mul_var_384 | src/points384.s | PR #32 (`fbb4f8b`) fp_sqr_384 inline cascades into ec_scalar_mul_var_384 | `7d717732` 2026-05-18 (PR #35) | **FRESH** | Row was rewritten on 2026-05-18 (today) to reflect post-PR-#32+#34 master. |
| 124 | ecdsa_verify_256 | src/ecdsa256.s | PR #34 J+J rewrite (`788adc3`) + PR #32 (`fbb4f8b`) BE/LE collapse + PR #26 (`460de8f`) cofactor | `7d717732` 2026-05-18 (PR #35) | **FRESH** | Memory note `project_pr34_empirical_measurement.md` confirms 43.16 Mcy @ 16 MHz match. |
| 125 | ecdsa_verify_384 | src/ecdsa384.s | same PR cascade + PR #23 wrapper | `7d717732` 2026-05-18 (PR #35) | **FRESH** | Memory note confirms 111.05 Mcy @ 16 MHz match. |

**Table III overall takeaway.** Three of four ECDSA-table rows
(123, 124, 125) were refreshed today by PR #35; row 122 was last
written by PR #19 but no relevant src change has moved it since.
**All Table III rows are FRESH.**

### Other benchmark tables?

Reading the full README, there are no other discrete benchmark
tables. The post-table prose at lines 95–104 (waves 5 / 7a wins) and
lines 130–143 (PR #26+#34 measured-vs-predicted savings) cite numbers
inline; those are mentioned for completeness but treated as
narrative, not table rows. The PR-#26+#34 narrative was authored
2026-05-18 (`7d71773`) and matches the memory record — **FRESH**.

---

## 2. Stale rows summary (ranked by impl-vs-row delta magnitude)

Filtering out cosmetic-only entries (where the impl change is below
the bench's measurement resolution at 1 MHz), the rows that have a
plausible chance of changing detectably under a fresh
measurement are:

| Rank | Row | Reason | Expected magnitude of delta |
|---|---|---|---|
| 1 | Table II row 93 (ec_scalar_mul P-384 @16/48 MHz) | 48 iters × ~4 `fp_sqr_384` per iter × ~300 cy/iter inline (PR #32) | ~−50k–60k cy (≈ 3–4 jiffies); detectable at U64E |
| 2 | Table II row 91 (ec_point_double P-384) | ~4 fp_sqr_384/call × −300 cy = ~−1200 cy/call | ~−1200 cy; borderline one jiffy |
| 3 | Table II row 92 (ec_point_add P-384) | ~3 fp_sqr_384/call × −300 cy ≈ −900 cy | borderline one jiffy |
| 4 | Table II row 87 (fp_sqr P-384) | PR #32 inline | ~−300 cy/call; below one jiffy in isolation but the 16/48 MHz numbers might shift by one jiffy across measurement aliasing |
| 5 | Table II row 89 (fp_mod_sqr P-384) | inherits fp_sqr_384 | as row 87 |
| 6 | Table I row 65 (fp_sqr wide P-384) | inherits fp_sqr_384 | 300/120k ≈ 0.25%; below VICE jiffy quant (one 1-MHz jiffy = 17,045 cy ≈ 17 ms) — **cosmetic** at VICE resolution |
| 7 | Table I row 70 (fp_mod_sqr P-384) | inherits fp_sqr_384 | cosmetic at VICE resolution |
| 8 | Table I row 72/73 (ec_point_double/add P-384 wide) | cascades | cosmetic |
| 9 | Table I row 74 (ec_scalar_mul P-384 wide) | cascades | ~0.04%, deep cosmetic |
| 10 | Table I/II all P-256 rows that pass through fp_mul / fp_sqr | v0.2.0 +6 cy/call | always cosmetic; rooms in the noise floor |

**Bottom line:** of the 8 row-cells in Table II (P-256 + P-384 split
× 2 turbo speeds × the listed primitives), **~5 P-384 rows** are
numerically worth a re-measurement at U64E. Table I has zero rows
that should change by enough to update the column at NTSC jiffy
resolution; Table III is entirely fresh.

---

## 3. Recommended re-measurement priority

For the synthesis step, given B1 (VICE bench) and C1 (U64E bench)
are running in parallel:

1. **C1 (U64E) re-runs of Table II's P-384 rows.** Highest yield:
   `ec_scalar_mul_384` at 16/48 MHz (row 93 P-384 columns),
   `ec_point_double_384` (row 91), `ec_point_add_384` (row 92).
   These are the rows whose PR #32 cascade is plausibly detectable
   (1–4 jiffies). One full `bench_p384_u64.py` run on a clean U64E
   covers all of them in a single artifact.

2. **C1 follow-up: Table II's P-384 fp_sqr / fp_mod_sqr** (rows 87,
   89). Same `bench_p384_u64.py` artifact already covers them; no
   extra run needed.

3. **B1 (VICE) re-runs are LOW priority for refreshing the README
   table itself.** The 1-MHz VICE jiffy quant (17,045 cy) eats every
   post-row src delta. B1 is still useful for cross-checking the
   2026-04 anchors against the current build (sanity: did anything
   regress that would push a row by ≥1 jiffy in the WRONG direction?).
   If B1's output for any row differs by ≥1 ms (~1k cy at 1 MHz) from
   the README, escalate — likely indicates a build/runtime regression
   rather than a small PR-32-class win.

4. **Table III (ECDSA verify) is already fresh as of today.** Skip
   re-measurement unless C1 detects a discrepancy >1 jiffy from the
   recorded 16/48 MHz values; cross-check against the memory note
   `project_pr34_empirical_measurement.md` if anomaly.

5. **Table I (1 MHz NTSC):** no re-measurement priority. All
   "STALE" classifications here are cosmetic. If a refresh is
   desired purely for hygiene (so the row date column tracks the
   implementation date), one VICE `bench_p256.py` + `bench_p384.py`
   run captures everything; otherwise defer.

---

## Notes / caveats

- **HEAD-SHA discrepancy.** Task brief named `788acc3` (PR #34 short-SHA
  is `788adc3`); actual master HEAD at audit time is `7d71773` (PR #35,
  docs). I audited against the actual HEAD; the only meaningful
  difference is that PR #35 already refreshed README rows 123–125, which
  I've correctly flagged as FRESH.
- **PR #28 + PR #27 revert.** Both PRs landed on 2026-05-16 and were
  reverted the SAME day by PR #29. Their `git log -- src/<file>.s`
  appearance can mislead a naïve audit into marking `mod256/384.s` and
  `points256/384.s` as recently changed when in fact the net master state
  is byte-identical to v0.2.0 for those files (verified with `git diff
  7071d55 HEAD -- src/<file>.s` showing empty diff for mod256/384.s).
- **Jiffy-quant convention.** Both VICE and U64E benches report
  jiffy-quantised wall-clock multiplied by 17,045 (1-MHz-equivalent µs).
  At 1 MHz a jiffy = 17,045 cy; at 16/48 MHz the "cyc" column is still
  1-MHz-equivalent so the same 17,045 quantum applies (per README
  §1-MHz-equivalent cycle convention lines 145–154). A 300-cy/call PR
  #32 inline contribution is sub-jiffy by 50× at 1 MHz; only after
  accumulating across ~50+ calls (e.g. inside `ec_scalar_mul_384`)
  does it cross the resolution boundary.
- This audit relies on the git history being squash-merge linear (one
  line = one PR), which it is per CLAUDE.md's release notes; if a
  future workflow change introduces real merge commits, the
  "src/<file>.s last-changed" lookup needs to follow first-parent.
