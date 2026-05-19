# A2 — Bench Coverage Audit (section 10 input)

**Date:** 2026-05-18
**Scope:** Map which library features the existing bench tools measure, identify gaps, flag redundancy.

Sources:
- `src/exports.inc` (cross-module dependency map)
- `grep -hn "\.export" src/*.s` (canonical public symbol surface)
- `tools/bench_p256.py`, `tools/bench_p384.py` (VICE primitive)
- `tools/bench_p256_u64.py`, `tools/bench_p384_u64.py` (U64E primitive)
- `tools/bench_ecdsa_u64.py` (U64E ECDSA + scalar_mul_var)
- `tools/test_sha384.py` (confirmed correctness-only — no `BENCH_PLAN`,
  no `bench_start/bench_stop`, no jiffy measurement)

---

## 1. Public callable surface

Derived from `.export` directives in `src/*.s`, filtered to executable
routines (data exports omitted unless they back a per-curve init).
Each entry tagged **API** (consumer-facing per `API.md`) or
**internal** (library-internal helper / unstable / pre-init only).

### 1.1 Boot / init (consumer must call once at startup)

| Symbol | Module | Tag | Notes |
|---|---|---|---|
| `sqtab_init` | mul_8x8.s | API (init) | quarter-square table |
| `reu_mul_init` | main.s | API (init) | 128 KB REU mul row table |
| `ec_precompute_256` | points256.s | API (init) | h=8 Lim-Lee anchor in REU bank 2 |
| `ec_precompute_384` | points384.s | API (init) | h=8 Lim-Lee anchor in REU bank 2 |

### 1.2 P-256 field arithmetic (`fp256.s`)

| Symbol | Tag | Notes |
|---|---|---|
| `fp_add`, `fp_sub` | API | 256-bit add/sub mod 2^256 |
| `fp_mul`, `fp_sqr` | API | 256x256→512 schoolbook with REU rows |
| `fp_copy`, `fp_zero`, `fp_cmp`, `fp_is_zero`, `fp_rshift1` | internal | byte helpers |
| `fp_sqr_pairs`, `fp_sqr_extra` | internal | sub-pieces of fp_sqr |

### 1.3 P-256 modular ops (`mod256.s`)

| Symbol | Tag | Notes |
|---|---|---|
| `fp_mod_add`, `fp_mod_sub` | API | mod p |
| `fp_mod_reduce256` | API | wide(64) → narrow(32) |
| `fp_mod_mul`, `fp_mod_sqr` | API | (calls `fp_mul/_sqr` + `fp_mod_reduce256`) |
| `fp_mod_mul_n` | API | mod **n** (group order) — ECDSA verify u1/u2 calc |
| `fp_mod_inv` | API | binary GCD inverse, mod p or mod n |
| `fp_chk_one` | internal | constant-time `== 1` check |
| `ec_set_modp`, `ec_set_modn` | internal | switches `fp_misc` between p / n |
| `ec_mulp`, `ec_sqrp` | internal | inline-call shim used by `points256` |

### 1.4 P-256 inversion reference (`inv256.s`)

| Symbol | Tag | Notes |
|---|---|---|
| `fp_mod_inv_fast` | internal (Fermat reference) | 41× slower than `fp_mod_inv`; tutorial only |

### 1.5 P-256 point ops (`points256.s`)

| Symbol | Tag | Notes |
|---|---|---|
| `ec_point_double` | API | a=-3 Jacobian doubling, 4M+4S |
| `ec_point_add` | API | mixed Jacobian+affine, 7M+4S |
| `ec_point_add_jj` | API | full Jacobian+Jacobian (BL add-2007-bl), 11M+5S |
| `ec_scalar_mul` | API | fixed-base, h=8 Lim-Lee comb |
| `ec_scalar_mul_var` | API | variable-base |
| `ec_jacobian_to_affine` | API | Z⁻¹ projective → affine |

### 1.6 P-256 ECDSA (`ecdsa256.s`)

| Symbol | Tag | Notes |
|---|---|---|
| `ecdsa_verify_256` | API | BE-ABI packaged verify |
| `fp_reverse32` | API | BE↔LE 32 B helper |
| `ecdsa_verify_256_tramp` | bench-only | tramp used by `bench_ecdsa_u64.py` |
| `bench_ecdsa_verify_256_tramp` | bench-only | tramp w/ debug markers |
| `bench_ec_scalar_mul_var_256_tramp` | bench-only | tramp w/ debug markers |

### 1.7 P-384 field arithmetic (`fp384.s`)

| Symbol | Tag |
|---|---|
| `fp_add_384`, `fp_sub_384` | API |
| `fp_mul_384`, `fp_sqr_384` | API |
| `fp_copy_384`, `fp_zero_384`, `fp_cmp_384`, `fp_is_zero_384`, `fp_rshift1_384` | internal |

### 1.8 P-384 modular ops (`mod384.s`)

| Symbol | Tag |
|---|---|
| `fp_mod_add_384`, `fp_mod_sub_384` | API |
| `fp_mod_reduce384` | API |
| `fp_mod_mul_384`, `fp_mod_sqr_384` | API |
| `fp_mod_mul_n_384` | API (ECDSA u1/u2 calc) |
| `fp_mod_inv_384` | API |
| `fp_chk_one_384` | internal |
| `ec_set_modp_384`, `ec_set_modn_384`, `ec_mulp_384`, `ec_sqrp_384` | internal |

### 1.9 P-384 point ops (`points384.s`)

| Symbol | Tag |
|---|---|
| `ec_point_double_384` | API |
| `ec_point_add_384` | API (mixed J+affine) |
| `ec_point_add_jj_384` | API (J+J) |
| `ec_scalar_mul_384` | API (fixed-base h=8) |
| `ec_scalar_mul_var_384` | API |
| `ec_jacobian_to_affine_384` | API |

### 1.10 P-384 ECDSA + SHA-384 wrapper (`ecdsa384.s`)

| Symbol | Tag |
|---|---|
| `ecdsa_verify_384` | API |
| `ecdsa_verify_with_message_384` | API (one-shot SHA+verify) |
| `fp_reverse48` | API |
| `ecdsa_verify_384_tramp` | bench-only |
| `ecdsa_verify_with_msg_384_tramp` | bench-only |
| `bench_ecdsa_verify_384_tramp` | bench-only |
| `bench_ec_scalar_mul_var_384_tramp` | bench-only |

### 1.11 SHA-384 (`sha384.s`)

| Symbol | Tag | Notes |
|---|---|---|
| `sha384_init` | API | reset state |
| `sha384_update` | API | absorb up to 64 KB per call |
| `sha384_final` | API | pad + emit 48 B BE digest |

### 1.12 Misc (`main.s`, `constants.s`)

| Symbol | Tag | Notes |
|---|---|---|
| `bench_start`, `bench_stop`, `bench_ticks` | bench infrastructure | timing primitives |
| `vic_blank`, `vic_unblank` | infrastructure | CPU steal-back |
| `print_string`, `print_hex_byte`, `clrscr` | infrastructure | KERNAL helpers |
| `main_loop` | infrastructure | parked entry for U64 trampolines |

---

## 2. Coverage matrix

Columns:
- **V256** = `tools/bench_p256.py` (VICE NTSC 1 MHz, oracle-gated)
- **V384** = `tools/bench_p384.py` (VICE NTSC 1 MHz, oracle-gated)
- **U256** = `tools/bench_p256_u64.py` (U64E sweep, default all 16 turbo speeds)
- **U384** = `tools/bench_p384_u64.py` (U64E sweep, default all 16 turbo speeds)
- **UECD** = `tools/bench_ecdsa_u64.py` (U64E ECDSA verify + variable-base scalar_mul; default 16,48 MHz)
- **TSHA** = `tools/test_sha384.py` (correctness-only; no bench mode)

Cells: `Y` = full coverage (in BENCH_PLAN, oracle-gated); `partial` = covered as part of a larger call but not measured in isolation (footnoted); `N` = no coverage.

### 2.1 P-256

| Feature | V256 | V384 | U256 | U384 | UECD | TSHA |
|---|---|---|---|---|---|---|
| `fp_add` | Y | - | Y | - | N | - |
| `fp_sub` | Y | - | Y | - | N | - |
| `fp_mul` | Y | - | Y | - | partial¹ | - |
| `fp_sqr` | Y | - | Y | - | partial¹ | - |
| `fp_mod_add` | Y | - | Y | - | partial¹ | - |
| `fp_mod_sub` | Y | - | Y | - | partial¹ | - |
| `fp_mod_reduce256` | Y | - | Y | - | partial¹ | - |
| `fp_mod_mul` | Y | - | Y | - | partial¹ | - |
| `fp_mod_sqr` | Y | - | Y | - | partial¹ | - |
| `fp_mod_mul_n` | N² | - | N² | - | partial¹ | - |
| `fp_mod_inv` | Y | - | Y | - | partial¹ | - |
| `ec_point_double` | Y | - | Y | - | partial¹ | - |
| `ec_point_add` (mixed) | Y | - | Y | - | partial¹ | - |
| `ec_point_add_jj` (J+J) | **N** | - | **N** | - | partial¹ | - |
| `ec_jacobian_to_affine` | **N** | - | **N** | - | partial¹ | - |
| `ec_scalar_mul` (fixed) | Y | - | Y | - | partial¹ | - |
| `ec_scalar_mul_var` | **N** | - | **N** | - | **Y** | - |
| `ecdsa_verify_256` | N | - | N | - | **Y** | - |
| `fp_reverse32` | **N** | - | **N** | - | partial¹ | - |

¹ `ecdsa_verify_256` exercises one fixed-base scalar_mul + one variable-base scalar_mul + one mixed `ec_point_add` (or J+J via cofactor-compare path post PR #34) + one `ec_jacobian_to_affine` + one `fp_mod_inv` (binary GCD) + multiple `fp_mod_mul_n` + two `fp_reverse32`. Measured only at the verify-level aggregate, never per-primitive.
² `fp_mod_mul_n` (the mod-**n** multiply, distinct from `fp_mod_mul` which is mod p) has no standalone primitive bench coverage. It is internally exercised by `ecdsa_verify_256`'s u1 = h·w and u2 = r·w steps.

### 2.2 P-384

| Feature | V256 | V384 | U256 | U384 | UECD | TSHA |
|---|---|---|---|---|---|---|
| `fp_add_384` | - | Y | - | Y | N | - |
| `fp_sub_384` | - | Y | - | Y | N | - |
| `fp_mul_384` | - | Y | - | Y | partial³ | - |
| `fp_sqr_384` | - | Y | - | Y | partial³ | - |
| `fp_mod_add_384` | - | Y | - | Y | partial³ | - |
| `fp_mod_sub_384` | - | Y | - | Y | partial³ | - |
| `fp_mod_reduce384` | - | Y | - | Y | partial³ | - |
| `fp_mod_mul_384` | - | Y | - | Y | partial³ | - |
| `fp_mod_sqr_384` | - | Y | - | Y | partial³ | - |
| `fp_mod_mul_n_384` | - | N² | - | N² | partial³ | - |
| `fp_mod_inv_384` | - | Y | - | Y | partial³ | - |
| `ec_point_double_384` | - | Y | - | Y | partial³ | - |
| `ec_point_add_384` (mixed) | - | Y | - | Y | partial³ | - |
| `ec_point_add_jj_384` (J+J) | - | **N** | - | **N** | partial³ | - |
| `ec_jacobian_to_affine_384` | - | **N** | - | **N** | partial³ | - |
| `ec_scalar_mul_384` (fixed) | - | Y | - | Y | partial³ | - |
| `ec_scalar_mul_var_384` | - | **N** | - | **N** | **Y** | - |
| `ecdsa_verify_384` | - | N | - | N | **Y** | - |
| `ecdsa_verify_with_message_384` | - | **N** | - | **N** | **N** | - |
| `fp_reverse48` | - | **N** | - | **N** | partial³ | - |

³ Same caveat as footnote ¹ — exercised only via the verify aggregate.

### 2.3 SHA-384

| Feature | V256 | V384 | U256 | U384 | UECD | TSHA |
|---|---|---|---|---|---|---|
| `sha384_init` | - | - | - | - | - | correctness only⁴ |
| `sha384_update` | - | - | - | - | - | correctness only⁴ |
| `sha384_final` | - | - | - | - | - | correctness only⁴ |

⁴ `tools/test_sha384.py` runs 25 KAT/random/stress vectors with oracle = `hashlib.sha384`. It uses `jsr()` to invoke each hash routine but never installs the bench trampoline or reads `bench_ticks`. There is no recorded cycles/call for any SHA-384 entry point — neither under VICE nor on U64E.

---

## 3. Coverage gaps

### High severity (consumer-facing entry point, TLS hot path)

| Routine | Severity | Suggestion |
|---|---|---|
| `ecdsa_verify_with_message_384` | High | Add a fifth row to `bench_ecdsa_u64.py`'s `BENCH_PLAN`, point an existing `ecdsa_verify_with_msg_384_tramp` trampoline (already exported from `ecdsa384.s`) at it, and stage a typical TLS-sized message (e.g. 200 B mocked CertificateVerify transcript). The delta vs `ecdsa_verify_384` directly is the SHA-384 cost on a representative-length input. |
| `sha384_update` / `_init` / `_final` | High | Add `tools/bench_sha384.py` (or extend `test_sha384.py` with a `--bench` flag). Measure `sha384_update` at canonical TLS lengths {0, 55, 56, 111, 112, 200, 1024, 4096 B} since SHA-2 padding behaviour kicks at block boundaries (55/56 and 111/112). Re-use the VICE jiffy-bench harness from `bench_p256.py`. |

### Medium severity (building block of public verify path)

| Routine | Severity | Suggestion |
|---|---|---|
| `ec_point_add_jj` / `_384` | Medium | Add a row to `bench_p{256,384}.py` and `bench_p{256,384}_u64.py` (same pattern as `ec_point_add`). Important: the J+J cost is what the post-PR #34 ECDSA join uses, and the measured-vs-predicted delta in the recent (2026-05-18) audit is precisely the kind of question this routine's primitive cost answers. |
| `ec_jacobian_to_affine` / `_384` | Medium | Bench under the existing primitive harness. Cost dominates `ecdsa_verify`'s tail (one `fp_mod_inv` plus 3 `fp_mod_mul`). Empirical primitive cost is needed to feed the post-PR #34 root-cause hypothesis (the `fp_mod_inv` fast-path on real Z coordinates note in CLAUDE.md). |
| `ec_scalar_mul_var` / `_384` under `bench_p{256,384}*` | Medium | Currently only covered by `bench_ecdsa_u64.py`. Adding it to the per-curve primitive harnesses gives VICE-1MHz numbers for cross-comparison with the fixed-base `ec_scalar_mul`. The two scalar_mul variants should differ by ~comb table lookup vs Montgomery ladder margin; missing primitive data hides regressions. |
| `fp_mod_mul_n` / `_384` | Medium | Add to `bench_p{256,384}*` BENCH_PLAN. Different from `fp_mod_mul` because it uses the group order n (no Solinas fast reduction available) and reduces via a different fp_mod_reduce path. Per-call cost is unknown standalone. |

### Low severity (helpers, exercised in aggregate only)

| Routine | Severity | Suggestion |
|---|---|---|
| `fp_reverse32` / `fp_reverse48` | Low | Trivial cost (~256-384 byte swap, dominated by indexing overhead). Could be added to primitive bench if completeness matters but the value is small. Skip for now. |
| `fp_chk_one` / `_384` | Low | `ecdsa_verify` calls this twice per verify (R.X normalization step), but cost is O(n) byte compare. Could fold into primitive bench at minor cost. |
| `fp_copy` / `fp_zero` / `fp_cmp` / `fp_is_zero` / `fp_rshift1` (×2 curves) | Low | Library-internal helpers. Microsecond-class cost. Not worth bench coverage. |
| `ec_set_modp` / `ec_set_modn` / `ec_mulp` / `ec_sqrp` (×2 curves) | Low | Inline-trampolines / mode switches. Constant 8-12 cycle cost. Not worth bench coverage. |
| `fp_mod_inv_fast` (Fermat reference, P-256 only) | Low | Already documented as 41× slower than `fp_mod_inv`. Not on any hot path. Skip. |
| `fp_sqr_pairs` / `fp_sqr_extra` | Low | Sub-pieces of `fp_sqr`; benching the parent already covers them. Skip. |

---

## 4. Redundancy

### 4.1 VICE vs U64E at 1 MHz (same-curve, same-primitive)

`bench_p256.py` and `bench_p256_u64.py @ 1 MHz` measure the SAME 13 primitives
(identical `BENCH_PLAN` row set: `fp_add`, `fp_sub`, `fp_mul`, `fp_sqr`,
`fp_mod_add`, `fp_mod_sub`, `fp_mod_reduce256`, `fp_mod_mul`, `fp_mod_sqr`,
`fp_mod_inv`, `ec_point_double`, `ec_point_add`, `ec_scalar_mul`).
Same for P-384 between `bench_p384.py` and `bench_p384_u64.py @ 1 MHz`.

Both lines of measurement go through `bench_start` / `bench_stop` reading
the NTSC jiffy clock at the same 17045 cy/jiffy resolution. **They
should agree to within rounding** (sub-jiffy timing of pure-CPU
primitives is irrelevant; REU DMA on both targets runs at ~1 MHz REU
clock).

The README cycles table at line 96 ("`ec_scalar_mul_384` completes in
~10.9 s vs ~131 s") cites a single canonical 1-MHz cycle count, but
section 9 / 10 of the audit doc should verify VICE and U64@1MHz agree to
within 1-2% on each row. If they diverge (e.g. a turbo-side-effect leak
into 1-MHz mode), that is a real bug worth flagging.

**Action for audit:** Cross-check `bench_p256.py` output against
`bench_p256_u64.py --speeds 1` output on the same PRG build; same for
P-384. Disagreement >1 jiffy on any primitive is a measurement bug.

### 4.2 Three-way redundancy on `ec_scalar_mul_var` (P-256 + P-384)

- **U256** `bench_p256_u64.py`: **no** coverage (gap, see §3).
- **U384** `bench_p384_u64.py`: **no** coverage (gap, see §3).
- **UECD** `bench_ecdsa_u64.py`: **Y** coverage at 16 / 48 MHz.

There IS no redundancy here — the variable-base scalar_mul has exactly
one bench coverage site. If `U256` / `U384` BENCH_PLAN gain a
`ec_scalar_mul_var[_384]` row (recommended in §3), the same primitive
will be measured by `UECD` as well; both numbers should agree at
overlapping speeds (16 / 48 MHz).

### 4.3 Wall-clock vs cycles units in `bench_ecdsa_u64.py`

`bench_ecdsa_u64.py` already documents in its README block (lines 14-30)
the jiffy-clock × 17045 conversion vs the optional UDP:11002 debug-bus
cross-check. This is not redundancy in the sense of section 4 of this
audit (two tools measuring the same thing) — it is one tool offering
two timing channels. The bench reports both numbers side-by-side when
`BENCH_DEBUG_STREAM=1`; CLAUDE.md (§ "Jiffy-clock / REU-DMA
wall-clock non-linearity at U64E turbo", issue #17 Task #12) flags that
the jiffy column at turbo is **1-MHz-equivalent µs**, not raw turbo
cycles. Worth restating in the audit's redundancy section so consumers
of the README data don't mis-extrapolate.

---

## 5. Notable structural observations

1. **No bench measures the `_with_message_384` wrapper.** The TLS hot
   path is precisely "give me a message + signature, give me a
   yes/no". The library exposes `ecdsa_verify_with_message_384` for
   exactly this; benching only the digest-already-spliced variant
   (`ecdsa_verify_384`) systematically under-measures TLS verify
   cost by the SHA-384 envelope. With ~200 B realistic TLS
   transcripts, SHA-384 is non-trivial.

2. **SHA-384 has zero bench coverage anywhere.** `test_sha384.py` is
   exclusively correctness. Cost is unknown from public artifacts;
   only the `[Unreleased]` CHANGELOG growth-budget note tells consumers
   anything quantitative ("24322 → 32022 B PRG"). For TLS 1.3
   feasibility analysis, SHA-384 update cost per block is the
   load-bearing number.

3. **`ec_point_add_jj` (added by PR #34) has no primitive bench.**
   Given the CLAUDE.md "PR #26 + PR #34 measured vs predicted ECDSA
   verify savings" record explicitly notes the predicted savings were
   10-20× off, the primitive-level cost of `ec_point_add_jj` (vs the
   mixed `ec_point_add`) is the right number to feed any future
   J+J-related decisions. Adding it to the primitive BENCH_PLAN is
   a one-line setup change (just set the second Z to a non-1 Jacobian
   value).

4. **`fp_mod_mul_n` (mod n) is measured only via aggregate ECDSA
   verify.** It is structurally different from `fp_mod_mul` (no
   Solinas fast-reduce path; uses a generic reduction), so a regression
   here would not be visible in `fp_mod_mul`'s number.

5. **Five `bench_*_tramp` trampolines exist in src/main.s and
   src/ecdsa{256,384}.s, but only four are consumed by a bench tool.**
   `ecdsa_verify_with_msg_384_tramp` (declared `.export` in
   `src/ecdsa384.s`) is wired and ready, but no bench plan row uses
   it. Adding the bench is a ~10-line change in `bench_ecdsa_u64.py`.
