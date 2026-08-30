# REU settle experiment — hardware-run PRG manifest, 2026-08-30

Branch `test/reu-hw-builds`, cut from `origin/master` @ `92ef7bc`.
**No U64 device was touched.** `U64_HOST` was never set; nothing that opens a
device connection was imported. Only VICE ran, and only via the harness.

Built artifacts live **outside git**:

```
/private/tmp/claude-501/-Users-someone-Documents-c64-nist-curves/d7b94edb-f409-4de4-a582-b86f3ff5a8d3/scratchpad/hwmatrix/
```

Machine-readable twin of this file: `manifest.json` in that directory
(carries the full per-site evidence dump, not just the summary below).

> **Scope note.** This started as a 15-PRG matrix (settle ladder ITER ∈
> {1,2,3,4,6,8} × REU bank axis {$00,$03}). Mid-run the design changed to an
> in-place poke of `nistcurves_reu_dma_wait`, which needs one PRG, so the
> ladder and bank variants were dropped. They were all built and verified
> before the cut; what they showed is recorded in §4 because two of those
> findings outlive the ladder. The dropped PRGs were moved to
> `../dropped_variants/` rather than deleted, in case the poke approach
> falls through.

---

## 1. The two PRGs for the run

| name | build command (verbatim) | sha256 | size | purpose |
|---|---|---|---|---|
| `neg-v0.11.2.prg` | `git worktree add --detach <path> v0.11.2` then, in that worktree, `make clean && make` | `1870127499acca7fe9ae3414afc444ac50b03117530c3547943cf67e2fcc1ef1` | 37480 B | **NEGATIVE CONTROL.** Genuine pre-fix tree: no SPEC v0.13.0 §8.2 completion confirm, no post-execute settle, no issue #132 guards. The only artifact that exercises the six hot `fp_mul`/`fp_sqr` execute sites with **no confirm at all** — those sites' confirm is inlined `bit`/`bvs`, so no memory poke can reach them. **MUST** produce wrong multiply-table rows at 48 MHz; a PASS here means c64-lib-contract#144 was not reproduced and the rest of the run is uninterpretable. |
| `iter8-default.prg` | `make clean && make` | `e070a554056b7fa8c84ed51eadfeb98b9c544b768c0b2c40bc2612f016ba3412` | 37483 B | Shipped default (SETTLE_ITER = 8, REU mul banks $00+$01). The PRG the poke experiment patches in place, and the PASS reference the control is read against. |

**Build wall-clock: 0.15–0.25 s each** (`/usr/bin/time -p`; 33 `ca65`
invocations + one `ld65`). Budget nothing for builds — the entire original
15-variant matrix rebuilt from scratch in under 5 s. All the cost is device
time.

### `iter8-default.prg` is the v0.12.0 release build

Confirmed by rebuild, not by prefix-matching: checking out the `v0.12.0`
tree into the worktree and running `make clean && make` produces
`e070a554056b7fa8c84ed51eadfeb98b9c544b768c0b2c40bc2612f016ba3412`, byte for
byte the same as a pristine `origin/master` @ `92ef7bc` build. That is
consistent with the two commits master carries on top of v0.12.0 — #132's
guards ("PRG size unchanged; the code lands in MAIN's alignment slack") and
#135's comment-only change. Matches the `e070a554056b7fa8c84e…` prefix in
the brief.

---

## 2. Proof from the built bytes that the control really is pre-fix

This is the check that distinguishes "we built the old tag" from "we built
the new tree with a flag that did nothing". Everything below is read out of
the `.prg` image and that build's own `build/labels.txt` — nothing is
inferred from the command line.

### 2a. The symbol does not exist

| build | `nistcurves_reu_dma_wait` in `build/labels.txt` |
|---|---|
| `neg-v0.11.2` | **ABSENT** |
| `iter8-default` | `al C:0A6A .nistcurves_reu_dma_wait` |

### 2b. The confirm opcode does not appear anywhere in the image

Searching the whole PRG for `2C 00 DF` = `bit $DF00` (the §8.2 (a)
completion confirm — `$DF00` is `reu_status`):

| build | occurrences | addresses |
|---|---|---|
| `neg-v0.11.2` | **0** | — |
| `iter8-default` | 7 | $0A72 (inside `nistcurves_reu_dma_wait`) + $0BF8, $0DAA, $0F4D, $3189, $333B, $34DE (the six inline hot-site confirms) |

Zero occurrences in 37 480 bytes is a stronger statement than "the six sites
lack it": the pre-fix image contains no REU status read at all.

### 2c. Every execute site, and what follows it

All 13 `8D 01 DF` = `sta $DF01` (REU execute) sites, with the eight bytes
that follow. The enclosing routine is resolved from that build's labels.

**`neg-v0.11.2.prg` — no confirm at any of the 13 sites:**

| addr | enclosing | next 8 bytes | confirm |
|---|---|---|---|
| $0A63 | `reu_fetch_mul_row`+16 | `60 a9 00 8d 1f 0b ad 1f` | **none** (`rts` immediately) |
| $0AC2 | `reu_mul_init` `@inner`+72 | `a9 00 8d 02 df a9 7b 8d` | **none** — next REU write (`sta $DF02`) is 2 instructions away |
| $0AF9 | `reu_mul_init` `@inner`+127 | `ee 1f 0b f0 03 4c 6c 0a` | **none** |
| **$0BC5** | **`fp_mul` `@nonzero_i`+16** | `a9 24 18 65 2c 8d 43 0c` | **none** — hot P-256 row fetch |
| **$0D6F** | **`fp_sqr` `@sqr_nonzero_i`+16** | `a9 24 18 65 2c 8d f8 0d` | **none** — hot P-256 row fetch |
| **$0F0A** | **`fp_sqr` `@diag_outer`+22** | `ac 00 7c b9 00 7a 8d 14` | **none** — hot P-256 diagonal |
| $28A2 | `sm256_reu_stash_affine`+48 | `4c f3 28 8d 0e 29 20 de` | **none** |
| $28D8 | `sm256_reu_fetch_affine`+48 | `4c f3 28 ad 0e 29 0a 0a` | **none** |
| **$30FE** | **`fp_mul_384` `@nonzero_i`+16** | `a9 fb 18 65 2c 8d 7c 31` | **none** — hot P-384 row fetch |
| **$32A8** | **`fp_sqr_384` `@sqr_nonzero_i`+16** | `a9 fb 18 65 2c 8d 31 33` | **none** — hot P-384 row fetch |
| **$3443** | **`fp_sqr_384` `@diag_outer`+22** | `ac 00 7c b9 00 7a 8d 14` | **none** — hot P-384 diagonal |
| $5040 | `sm384w_stash_p2`+28 | `20 a5 50 60 8d 5f 8a 20` | **none** — `jsr $50A5` is the register *restore*, not a wait |
| $5066 | `sm384w_fetch_to_p2`+31 | `20 a5 50 60 ad 5f 8a 0a` | **none** — same |

The two `jsr` at $5040/$5066 are worth calling out because they superficially
resemble the fixed build's `jsr nistcurves_reu_dma_wait`. They are not:
$50A5 is `sm384w`'s REU-register restore routine, and the wait symbol does
not exist in this image (§2a). Both sites jump straight into rewriting REU
registers with no confirm and no settle — which is exactly the c64-lib-contract#144
shape.

**`iter8-default.prg` — all 13 sites protected, for contrast:**

six inline (`2c 00 df 70 03 20 6a 0a` = `bit $DF00 / bvs +3 / jsr $0A6A`) at
$0BF5, $0DA7, $0F4A, $3186, $3338, $34DB — the same six hot routines listed
in bold above — and seven `jsr $0A6A` at $0A63, $0AEC, $0B26, $2924, $295D,
$511A, $5143.

### 2d. Side finding — the execute-site count in our docs is wrong

`CLAUDE.md` and `src/reu_dma_done.inc` both say "all 14 execute sites … six
hot … eight tight". The tree has **13** `sta reu_command` sites: **6 hot +
7 tight** (`reu_mul_init` ×2, `points256_comb` ×2, `points384_comb` ×2,
`reu_fetch_mul_row` ×1). Confirmed three ways — `grep -c 'sta reu_command'`
over `src/*.s`, `grep -c 'jsr nistcurves_reu_dma_wait'`, and the 13 `8D 01
DF` sites found in each PRG image above. Comment-only drift; not fixed on
this branch.

---

## 3. Independent count of the settle-loop distance

Asked for as a second opinion. **I get `34 + 9·ITER`, measured `jsr` through
`rts` inclusive — agreeing with the reviewer and not with the shipped
comment.**

Derived from the emitted bytes, not the source. `nistcurves_reu_dma_wait`
occupies $0A6A..$0A90 (39 B) in `iter8-default.prg`; the whole routine lies
inside page $0A, so **no branch crosses a page** and no branch pays the
+1 penalty:

```
        A9 00        lda #0                          2
        8D 24 7C     sta nistcurves_reu_wait_cnt     4   ($7C24, absolute)
        8D 25 7C     sta nistcurves_reu_wait_cnt+1   4
@spin:  2C 00 DF     bit reu_status                  4
        70 0F        bvs @settle                     3   (taken, no page cross)
        ...          bounded-spin arm, not on the normal path
@settle:
        A9 08        lda #<LIB_NISTCURVES_REU_SETTLE_ITER  2
        8D 24 7C     sta nistcurves_reu_wait_cnt     4
@loop:  CE 24 7C     dec nistcurves_reu_wait_cnt     6   } per iteration
        D0 FB        bne @loop                       3   } taken
        60           rts                             6
```

* caller's `jsr` = 6
* fixed head/tail = 6 + (2+4+4) + (4+3) + (2+4) + 6 = **35**
* settle loop = 9·(ITER−1) + **8** = **9·ITER − 1**
  — the last pass' `bne` **falls through**: `dec` 6 + `bne` not-taken 2 = 8,
  not 9.
* **total = 34 + 9·ITER**

At ITER = 8 that is **106**, not the 107 in `src/mul_8x8.s:355`. The error is
exactly one cycle and it is in the optimistic direction, so any margin
claimed against the 49-cycle floor is one cycle smaller than documented. Two
places to correct if you fix the docs: `src/mul_8x8.s:352-360` ("8\*9 = 72 …
= 107 cycles") and `src/reu_config.s:92-97` ("Default 8 -> ~107 cycles"; the
"2.2x the measured floor" ratio survives — 106/49 = 2.16×).

Two caveats on interpreting the number, unchanged by the arithmetic:

* It is a **floor** on the real execute→next-REU-register-write distance.
  The caller's `sta reu_command` completes immediately before the `jsr`, and
  the caller needs 2–6 more cycles after the `rts` to reach its next REU
  write (e.g. `lda #< / sta reu_c64_lo` = +2 at `src/reu_mul_init.s:130`).
  Conservative direction.
* These are 1 MHz cycles. Whether the settle hazard is cycle-anchored or
  wall-clock-anchored is the open question the run decides.

| ITER | 34 + 9·ITER | (shipped) 35 + 9·ITER |
|---|---|---|
| 1 | 43 | 44 |
| 2 | 52 | 53 |
| 4 | 70 | 71 |
| 8 (default) | **106** | 107 |

---

## 4. Findings from the dropped ladder that outlive it

Recorded because they are about shipped code, not about the experiment.

### 4a. The settle knob does not build on master — blocking, if anyone uses it

`make CONTRACT_DEFINES='-D LIB_NISTCURVES_REU_SETTLE_ITER=<n>'` **fails** on
`origin/master` @ `92ef7bc` for every value of `<n>`:

```
src/mul_8x8.s(365): Error: Symbol 'LIB_NISTCURVES_REU_SETTLE_ITER' is already defined
```

`CONTRACT_DEFINES` reaches *every* TU (SPEC §6.2), so `-D` defines the symbol
locally in `mul_8x8.s` — which also carried an unconditional
`.import LIB_NISTCURVES_REU_SETTLE_ITER` of `reu_config.s`'s export. Local
definition plus import of the same name is a hard ca65 error. `reu_config.s`'s
own `.ifndef` guard is correct; the *importer* was not guarded.

So the documented consumer path at `src/reu_config.s:98` — "a consumer
claiming that clock raises this (`ca65 -D LIB_NISTCURVES_REU_SETTLE_ITER=<n>`,
1..255)" — cannot be exercised at all, and neither can `make lib-*
CONTRACT_DEFINES=…` for any archive containing `mul_8x8.o`. `make
check-archives`' §6.3 staleness leg does not catch it: that leg drives the
two knobs it knows about (`LIB_SHARED_SQTAB_BASE`, ZP slots), not this one.

The one-line fix (verified, then reverted — this branch carries no source
change):

```asm
.import reu_status
.ifndef LIB_NISTCURVES_REU_SETTLE_ITER
.import LIB_NISTCURVES_REU_SETTLE_ITER
.endif
```

With it applied, all six ladder values and both bank values built, `make
check-archives` PASSed and `make check-docs` PASSed, and the default `make`
PRG stayed byte-identical at `e070a554…` — i.e. the fix is artifact-inert.
Worth filing as an issue even though the poke supersedes the ladder: the
knob is shipped, documented, and non-functional.

### 4b. The knob would never have reached the six hot sites

`LIB_NISTCURVES_REU_SETTLE_ITER` governs **only** the 7 tight sites that
`jsr nistcurves_reu_dma_wait`. The 6 hot `fp_mul`/`fp_sqr` sites use the
inline 7-cycle `REU_DMA_CONFIRM` and meet obligation (b) *structurally* —
identical bytes in every ladder rung (`cmp -l` between adjacent rungs showed
**exactly one differing byte**, the settle immediate at $0A87, and nothing
else). Independent corroboration of the review's conclusion, and the reason
the negative control cannot be replaced by a poke.

### 4c. What the ladder did verify, before it was dropped

Kept for the record; the PRGs are in `../dropped_variants/`.

* All six ITER values produced **distinct** sha256 on both bank axes; the
  knob was not vacuous once 4a was fixed. `iter8` built via the knob was
  byte-identical to the plain `make` default.
* The bank override took effect in the built object, not just on the command
  line: `od65 --dump-exports build/reu_config.o` gave
  `LIB_NISTCURVES_SHARED_REU_MUL_BANK = 0x03` and `…_BANKS_USED = 0x18`
  (banks $03,$04) versus `0x00` / `0x03` by default. At machine-code level,
  `cmp -l` against the default showed **exactly 9 differing bytes, every one
  0 → 3**, each in the pattern `a9 03 69 00 8d 06 df` = `lda #$03 / adc #$00
  / sta $DF06` — all nine `reu_reu_bank` operands and nothing else. Both
  §8.2 assemble-time guards in `src/reu_config.s:67-68` hold for that
  override (offset stays $0000; base $03 < $FE).
* Note for any future bank-axis run: banks $03+$04 for the multiply table
  with the comb still in bank $02 needs a **≥ 320 KB REU**. A 256 KB REU
  would silently alias.

---

## 5. Not done / not verified

* **VICE smoke tests: not completed, and no longer applicable.** A
  `test_prims_adversarial.py --strict` run against `iter1.prg` was started
  and reached 291 rows with **0 FAIL** before being stopped at the scope
  cut, part-way through the P-384 variable-base ladder (individual
  `scalar_mul_var` rows cost 60–120 s under warp). No result for
  `bank03-iter8.prg`. The harness cleaned up its VICE; no `x64sc` was
  launched or killed by hand and none is left running.
  For the record on the question that was asked: the harness **does** give
  VICE an REU — `tools/audit_common.py:152` launches with
  `-reu -reusize 512`, i.e. 512 KB covering banks $00–$07 — so a bank-$03
  run would have been a real test rather than a false pass.
* **Neither surviving PRG was smoke-tested under VICE.** For
  `iter8-default.prg` this is not a gap: it is a pristine `origin/master`
  build, byte-identical to the v0.12.0 release, already covered by the
  standing suites. For `neg-v0.11.2.prg` a VICE PASS would have been
  meaningless — VICE sets `$DF00` bit 6 immediately and has **no
  post-transfer restore window at all**, so the settle defect is invisible
  to it by construction (`src/reu_dma_done.inc`; CLAUDE.md's §8.2 known
  issue says the same). Its *failure on hardware at turbo* is the whole
  point.
* **Not verified, and not verifiable off-device:** that any settle length is
  sufficient at 48 or 64 MHz. Note the standing asymmetry the review
  identified — the only datum in existence is a **PASS at ~49 cycles**; no
  settle length has ever been observed to fail. The negative control is the
  one artifact that can produce the missing FAIL.
* **Not exercised:** the `FP_ONCHIP_MUL` profile (onchip archives issue no
  row-fetch DMA, so they are off-axis for a settle question) and ITER values
  above 8. Either is a ~0.2 s build if wanted.
* **Left alone deliberately:** the §2d site-count drift, the 107-vs-106
  figure in `src/mul_8x8.s:355` / `src/reu_config.s:96`, and the §4a import
  guard. All three are real; none is committed here, so this branch stays a
  measurement branch.
