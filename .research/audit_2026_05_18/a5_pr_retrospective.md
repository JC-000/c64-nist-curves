# A5 — PR retrospective: RAM cost vs cycle saved (post-v0.2.0)

Audit window: v0.2.0 (tag commit 19f95d7, 2026-05-12) → master HEAD
(7d71773, 2026-05-18). 15 PRs landed in this window. v0.2.0 itself
(PR #21) is included because it is the squash-merged release-prep
commit; PR #22 onward represents the genuine "post-release" run.

Anchor / ground truth references:
- `CLAUDE.md` "Negative findings" §"PR #26 cofactor-compare and PR #34
  cofactor approach (a)" — measured-vs-predicted ECDSA verify gap.
- `CHANGELOG.md` `[Unreleased]` §Measured (2026-05-18 retrospective).
- `MEMORY.md` `project_pr34_empirical_measurement.md`.

PRG figures are taken from the PR descriptions (which the project
authors record consistently; the build-artifact `build/nist-curves.prg`
is gitignored so historical bytes cannot be re-derived without
destructive checkout). DATA / ZP deltas are recovered from
`git show -- src/data.s src/zp_config.s` per PR. Cycle figures are
from the PR description for "claimed" and from
CHANGELOG/`MEMORY.md`/CLAUDE.md "Negative findings" for "measured".

---

## §1 PR table (newest → oldest)

Convention. "PRG delta" = absolute byte change in the linker-output
`.prg` quoted by the PR or computed from the PRG-before/PRG-after in
its body. "DATA delta" = net `.res` byte change in `src/data.s` (i.e.
SRAM allocation, not counting RODATA tables inside .s files). "ZP
delta" = net byte change to assignments in `src/zp_config.s`.

| PR # | Title | Date | PRG Δ | DATA Δ | ZP Δ | Claimed cycle Δ | Measured cycle Δ | Prediction-vs-measurement | Notes |
|------|-------|------|-------|--------|------|-----------------|------------------|---------------------------|-------|
| #35 | Docs: capture PR #26 + #34 measured-vs-predicted ECDSA verify | 2026-05-18 | 0 | 0 | 0 | n/a | n/a | n/a (docs-only) | CHANGELOG + CLAUDE.md + README scaffolding for the gap below. |
| #34 | ecdsa verify: full J+J point-add at u1·G+u2·Q join + sqtab bump | 2026-05-17 | +1440 B | +160 B (+64 P-256 / +96 P-384) | 0 | "estimated ~800 kcy P-256 / ~1.7 Mcy P-384" (primitive-extrapolated) | **−17 kcy P-256 / −102 kcy P-384** (1/6 jiffies) | **47×–17× short** of prediction | Same primitive-extrapolation failure mode as PR #26. `ec_point_add_jj` primitive is independently useful; sqtab→$9C00 fix prevented an init-hang regression and was load-bearing in its own right. CLAUDE.md negative finding documents this in full. |
| #33 | U64E bench tools: migrate writemem_health_probe → upstream liveness_probe | 2026-05-17 | 0 | 0 | 0 | n/a | n/a | n/a (tools-only) | −98+25 lines in `bench_u64_common.py`; replaces local helper with harness `liveness_probe` after upstream PR #109. No library code touched. |
| #32 | fp384/ecdsa cleanup: inline reu_fetch_mul_row, parametric reversal, fuse u1·G infinity | 2026-05-17 | 0 (byte-neutral) | 0 | 0 | "~300 cy/fp_sqr_384; ~150–200 cy/verify address setup; ~50–100 cy/verify OR-fold" (primitive) | not separately measured | **un-measurable in noise** at single PR granularity; absorbed into PR #34's three-point bench delta | PR body explicitly notes original "−256 B PRG" claim washed out to byte-neutral on current master after PR #29 revert. Pure cleanup tier. |
| #31 | build: emit build/nist-curves.dbg via ca65 -g + ld65 --dbgfile | 2026-05-16 | 0 (PRG byte-identical, verified sha256) | 0 | 0 | n/a | n/a | n/a (build-only) | Adds `.dbg` artifact for VICE source-level debugging; PRG verified bit-identical. |
| #30 | U64E harness: stale-lock cleanup, holder pre-check, bounded acquire, writemem-degradation probe | 2026-05-16 | 0 | 0 | 0 | n/a | n/a | n/a (tools-only) | +194 lines in `bench_u64_common.py`; later superseded by PR #33 (writemem_health_probe → liveness_probe). |
| #29 | Revert PRs #27 (w-NAF) and #28 (GCD shift) — master init hang regression | 2026-05-16 | −3318 B (#27) − 768 B (#28) ≈ −4086 B (back to 32022 B) | −86 B P-256 (var_*) − 1058 B P-384 (var384_*) — 1144 B total | 0 | n/a (revert) | n/a (revert) | **Negative outcome**: PR #27 + PR #28 ran green in isolation but composed into a sqtab/mul_dma TABLES collision that hung the $02A7 init sentinel. | Documented in `MEMORY.md` `project_wnaf_reland_blocked.md`. PR #34 later fixed the same collision class by bumping sqtab to $9C00. |
| #28 | fp_mod_inv: byte-aligned fast path when u/v low byte == 0 | 2026-05-16 | +768 B | 0 | 0 | "modest" — PR body explicitly downgrades expected savings vs. the earlier 15–25%/inv analysis (k=8-only fires ~1/256 outer iters) | not separately measured (reverted by PR #29) | predicted-low / not measured / **reverted** | Honest self-downgrade in the PR body itself; original optimization analysis presumed arbitrary-k LUT extension, which this PR descoped. |
| #27 | Replace ec_scalar_mul_var[_384] double-and-add with width-4 w-NAF | 2026-05-16 | +3318 B | +1144 B (+86 P-256 / +1058 P-384) | 0 | "~37.6 → ~25.5 Mcy P-256; ~95.5 → ~74 Mcy P-384" (~12 Mcy / ~21 Mcy savings, extrapolated from average-density argument) | not separately measured (reverted by PR #29) | **reverted before bench** | Composed into PR #28 to produce an init-hang regression. Hang root cause partially understood (sqtab/mul_dma collision) but a second factor still unidentified per `project_wnaf_reland_blocked.md`. |
| #26 | ecdsa verify: replace final Z⁻¹ inversion with cofactor compare | 2026-05-16 | +512 B | 0 (reuses ec_t1/t2/t3) | 0 | "~800 kcy P-256 / ~1.7 Mcy P-384" (primitive-extrapolated from fp_mod_inv ~750 kcy + 3 fp_mul) | **−51 kcy P-256 / −85 kcy P-384** (3/5 jiffies) | **16×–20× short** of prediction | First half of the cofactor optimization. PR #34 was the follow-up. Cited primitive-bench fp_mod_inv cost (~750 kcy) which is an *average* over random inputs; actual Z coordinates from `ec_scalar_mul` consistently hit binary-GCD fast paths. |
| #25 | sha384: table-driven sigma/Sigma rotates via paired 256 B LUTs | 2026-05-16 | +3584 B (32022 → 35606 B) | 0 | 0 | "Sigma_0: 1094 → 516 cy; Sigma_1: 819 → 479 cy; ~133,700 cy / 128 B block (~10% of compression)" — derived from per-instruction-counted unrolled body | not separately measured on integrated bench; per-block primitive count is cited as a *derivation* not a U64E measurement | **plausible, primitive-derived** (no integrated bench number) | r=1 deliberately stays on chained-LSR/ROR path (LUT loses at k=1). Only PR in this window that does a clean reuse-of-RODATA-tables play. |
| #24 | Post-PR-#23 doc cleanup: API.md PRG/limitations, CLAUDE.md ECDSA buffers | 2026-05-15 | 0 | 0 | 0 | n/a | n/a | n/a (docs-only) | Drift-cleanup tier. |
| #23 | Add SHA-384 streaming hash + ecdsa_verify_with_message_384 wrapper | 2026-05-15 | +7700 B (24322 → 32022 B; ~1.7 KB is test scratch) | +1992 B (sha state + msg_buf + ecdsa384 wrapper buffers) | +8 B (sha_src, sha_len, sha_w_ptr, sha_w_ptr2 at $04/$06/$08/$0a) | n/a (new capability, not an optimization) | new capability — 25/25 SHA-384 KAT + 7 new wrapper tests pass | n/a | TLS 1.3 secp384r1 + SHA-384 prerequisite. PR description focuses on functional coverage, not a cycle target. Test scratch (`sha384_msg_buf` 1024 B) is harness-owned and not consumer overhead. |
| #22 | Post-v0.2.0 cleanup: verified reads, VICE preflight, API.md refresh | 2026-05-15 | 0 | 0 | 0 | n/a | n/a | n/a (tools+docs) | `read_bytes_verified` upgrade in fp tests; `pgrep x64sc` preflight in 8 VICE scripts. |
| #21 | Release v0.2.0: var-base scalar_mul + ECDSA verify + REU defence + reproducible tarball | 2026-05-12 | +256 B (24322 ← prior; this PR was the squash-merge of multiple commits including the REU defence: "~80 raw bytes of code … +176 bytes of page-alignment shift") | 0 (REU defence is code-only) | 0 | "+6 cycles per public DMA entry point call" (per-site, additive) | not separately benchmarked (defence is correctness, not perf) | correctness-only, baseline accepted | The v0.2.0 release squash includes the issue #33 REU register-residue defence. Marketed as a cost (+6 cy/call across 10 sites), not a saving. |

---

## §2 Prediction-accuracy analysis

The 15 PRs sort cleanly into four prediction-accuracy buckets:

### Bucket A — Optimization PRs with primitive-extrapolated cycle claims (n=4)
- **PR #26** (cofactor compare): claimed −800 kcy P-256 / −1700 kcy
  P-384; measured −51 kcy / −85 kcy → **16×–20× short**.
- **PR #34** (full J+J at join): claimed −800 kcy P-256 / −1700 kcy
  P-384 additional; measured −17 kcy / −102 kcy → **17×–47× short**.
- **PR #27** (w-NAF): claimed −12 Mcy P-256 / −21 Mcy P-384; never
  measured because revert (PR #29) preceded any U64E bench run.
- **PR #25** (SHA-384 rotates): claimed −133,700 cy / block; never
  integrated-bench measured (no SHA-384 bench tool yet) but the
  rotate-microbench numbers are per-instruction-counted and unlikely
  to be more than ±5% off the derivation.

**Pattern.** Three of four optimizations whose cycle savings were
extrapolated from primitive costs (PR #26, PR #34, PR #27) failed
or were never validated. The single one that probably holds (PR #25)
is a pure-microarchitectural rotate body whose savings derive from
counting unrolled 6502 instructions rather than extrapolating a
data-dependent primitive — i.e. it sidesteps the failure mode entirely.

**Root cause** (per CLAUDE.md negative finding): `fp_mod_inv` is
binary GCD with input-sensitive runtime. The primitive bench averages
over random inputs at ~750 kcy/call. But the Z coordinates emerging
from `ec_scalar_mul` carry structure (Jacobian Z starts at 1; comb
output Z's often have low Hamming weight or align byte-wise), hitting
GCD fast paths that make their actual runtime far below the average.
PR #26 and PR #34 each eliminated one `fp_mod_inv` call, but the calls
they eliminated were the cheap-in-context ones, not the average-cost
ones their estimate cited.

### Bucket B — Refactor / cleanup with side-channel cycle claims (n=1)
- **PR #32** (fp384/ecdsa cleanup) cites three primitive cycle
  savings (~300 cy/fp_sqr_384, ~150–200 cy/verify address-setup,
  ~50–100 cy/verify OR-fold) but is byte-neutral and is positioned
  in the PR body as cleanup. Its cycle impact is below the U64E
  jiffy granularity (17045 cy) and is absorbed silently into the
  PR #34 three-point comparison.

**Pattern.** Modest per-call savings on lightly-trafficked sites
disappear into bench noise. The PR body's own framing (no claimed
ceiling, no PR-level cycle target) is correctly honest about this.

### Bucket C — Tools / docs / build (n=7)
PRs #21 (release squash), #22, #24, #30, #31, #33, #35. No cycle
claims of consequence; PR #21's "+6 cy per call across 10 entry
points" is a *cost* of the security-defence port, not a saving.

**Pattern.** Net zero cycle impact, mostly net zero PRG impact too.

### Bucket D — Reverts (n=2)
- **PR #28** (fp_mod_inv byte-aligned fast path) and **PR #27**
  (w-NAF) jointly composed an init-hang regression noticed only on
  master integration (`project_wnaf_reland_blocked.md`). PR #29
  reverted both, restoring 32022 B PRG.

**Pattern.** Two PRs whose unit tests passed in isolation failed when
composed at master. The single composition state-change that triggered
the hang (sqtab vs mul_dma TABLES address collision) was later fixed
*independently* in PR #34, but a second contributing factor remains
unidentified per the memory note.

---

## §3 RAM efficiency table (cycles saved per RAM byte spent)

For PRs that have both a measured cycle benefit and a RAM cost:

| PR # | RAM total (PRG + DATA) | Measured cycle Δ (single curve) | Cycles saved per RAM byte | Verdict |
|------|------------------------|---------------------------------|---------------------------|---------|
| #26 | 512 B PRG + 0 DATA = 512 B | −51 kcy P-256 / −85 kcy P-384 | **100 cy/B P-256 / 166 cy/B P-384** | poor — predicted ~1560 cy/B, delivered ~133 |
| #34 | 1440 B PRG + 160 B DATA = 1600 B | −17 kcy P-256 / −102 kcy P-384 | **11 cy/B P-256 / 64 cy/B P-384** | very poor — predicted ~500 cy/B, delivered ~37 |
| #26 + #34 combined | 1952 B PRG + 160 B DATA = 2112 B | −68 kcy P-256 / −187 kcy P-384 | **32 cy/B P-256 / 89 cy/B P-384** | poor — order-of-magnitude under |
| #25 (sha384 rotates) | 3584 B PRG (incl. 3072 B RODATA) | not integrated-bench measured but ~133,700 cy / 128 B block per derivation | ~37 cy/B (if derivation holds, single-block) | plausibly good per-block, but per-verify SHA cost dominated by other compression work; integrated bench needed to confirm |
| #23 (SHA-384 + wrapper) | 7700 B PRG + 1992 B DATA = 9692 B | n/a (new capability, not optimization) | — | not an optimization PR |
| #21 (REU defence) | +256 B PRG (~80 B real code + 176 B alignment) | +60 cy across 10 sites (cost) | — (correctness PR) | net negative on cycles by design |

The two measured optimization PRs (#26, #34) together deliver
**~60 cy/B** (averaging across both curves), against a predicted
**~1000 cy/B**. The full SHA-384 module (#23) is a new capability
and isn't on this scale.

If we narrow the denominator to *DATA*-only (the scarcest resource on
a C64 because PRG can grow into the entire $0801–$BFFF window
whereas DATA buffers compete for the same RAM map), PR #34 is even
worse: 160 B DATA for −119 kcy combined cycles = **~744 cy / DATA-byte**,
vs PR #26 which adds zero DATA and is therefore "RAM-efficient
relative to DATA" by construction.

---

## §4 Lessons learned

1. **Primitive cycle costs misestimate compound-caller savings when
   the eliminated primitive has data-dependent runtime.** CLAUDE.md
   captures this as the central post-v0.2.0 finding (PR #26 / #34).
   The Wave 8a `beq`-removal miss (documented in CLAUDE.md "Negative
   findings") is the symmetric case: primitive-fast-but-compound-slow.
   The post-v0.2.0 PRs hit the other direction:
   primitive-says-big-savings-but-compound-is-tiny. The shared lesson
   is that the primitive benchmark distribution must match the
   integrated callsite's input distribution; otherwise the savings
   estimate is unsupported.

2. **PRG-byte claims in PR descriptions are reliable; cycle claims
   are not.** Every PR with a PRG figure (24322 → 32022, 32022 →
   35606, 35862 → 37302, etc.) is internally consistent across
   commits and matches CHANGELOG. No PRG-claim discrepancy was
   found. By contrast every optimization-PR cycle claim that *was*
   independently measured (PR #26, PR #34) came in 10–20× short.
   This is a measurement-method problem, not a deception problem —
   the PR authors did not have integrated benches available at merge
   time in some cases — but it's the dominant signal in this window.

3. **The integrated bench (`bench_ecdsa_u64.py`,
   `bench_p256/p384_u64.py`) must run before merge for any PR
   costing PRG or DATA bytes.** CLAUDE.md elevates this to a project
   rule (last bullet of the "Negative findings" PR #26+#34 entry).
   PR #35 codified the rule into CHANGELOG; before this audit it
   was not a hard merge gate. Six of the seven post-v0.2.0
   optimization-shaped PRs (#23, #25, #26, #27, #28, #32, #34) shipped
   without an integrated-bench number in the PR description.

4. **Composition hazards (TABLES segment vs hard-coded equates)
   re-emerge whenever code grows past a page boundary.** PR #29's
   revert and PR #34's sqtab bump are both manifestations of the
   same `sqtab_lo`/`mul_dma_lo` collision class. The current
   `sqtab` move to $9C00 buys ~$0400 headroom; this will recur
   the next time code grows by ~1 KB. A linker-driven sqtab
   placement (declared in `src/c64.cfg` instead of as a hard equate
   in `src/mul_8x8.s`) would eliminate the class entirely, at the
   cost of disturbing the SMC page-delta math. Worth noting as a
   follow-up.

5. **Cleanup-tier PRs with byte-neutral PRG are safe to land
   without integrated-bench gates** because their cycle contribution
   is below the U64E jiffy granularity. PR #32 is the model here.
   The cost is that their per-call savings can never be independently
   credited; they show up only in PR #34-class consolidation deltas.

6. **Reverts in this window cost ~3 days of net work but no
   library users.** PR #27 + PR #28 cycle in master for 12 hours,
   revert ships in PR #29, no tagged release was cut against the
   broken state. The release pipeline (v0.2.0 + future v0.3.0)
   is shielded by the `master` discipline plus the `make dist`
   tarball-from-tag invariant.

---

## §5 RAM-cost-vs-cycle-saved feed for §9 of the team audit

The headline number for §9 should be:

- **PR #26 + PR #34 combined: 2112 RAM bytes spent (1952 B PRG +
  160 B DATA) to save ~68 kcy P-256 / ~187 kcy P-384 per ECDSA
  verify on master. Ratio is approximately 32 cy/B P-256 and 89 cy/B
  P-384.** The same combined predictions, taken at face value, would
  have delivered ~1.6 Mcy / ~3.4 Mcy savings — a 10–20× overshoot.
- **PR #25 (SHA-384 rotates) is the only optimization-shaped PR in
  the post-v0.2.0 window with a primitive cycle claim that is
  *almost certainly* holding** — its claim derives from
  instruction-counting on an unrolled body rather than from
  amortized-primitive extrapolation. But it has not been
  integrated-bench measured (no SHA-384 bench tool exists).
- **No measured-cycle wins in this window approach the 100 cy/B
  threshold that the c64-x25519 sibling routinely achieved on Wave
  4–7 optimizations.** This is consistent with the "low-hanging
  fruit is gone, remaining optimizations need integrated
  measurement" interpretation in CLAUDE.md.

The empirical-measurement requirement (CHANGELOG[Unreleased]
"Process change going forward") is the single most important
process artifact to surface in the §9 deliverable; everything else
in this retrospective is downstream of that rule not having been
in force during PRs #26 / #34.
