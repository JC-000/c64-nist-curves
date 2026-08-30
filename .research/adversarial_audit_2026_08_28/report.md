# Adversarial audit — c64-nist-curves (P-256 / P-384 / ECDSA verify / SHA-384)

Date: 2026-08-28. Branch `fix/spec-v0.13.0-reu-dma-settle`, PRG
`build/nist-curves.prg` sha256
`2f57f9dd5d740529dd6821c860b09cf9eaf3bd53b4b9eef75a4283aed8b8b1a1`.
Oracle: `cryptography.hazmat` (OpenSSL) on python3.13, plus a second
pure-Python-int FIPS 186-5 verifier (`py_verify` in `audit_ecdsa.py`)
that had to agree with hazmat on every ECDSA case (it did, except where
OpenSSL deliberately reduces non-canonical coordinates — F-3). No
expected value was taken from a previous C64 run. All runs went through
`c64_test_harness` (`ViceInstanceManager`, `$02A7` sentinel,
`transport.resume()` per poll); each batch booted VICE once (~5.5 min
boot, three instances in parallel). Nothing under `src/`, `tools/`,
`Makefile` or docs was modified; the mutation tests patch bytes inside
the running emulator and restore them.

Scripts and raw logs live next to this file: `scripts/`
(`audit_common.py`, `audit_ecdsa.py`, `audit_prims.py`,
`dryrun_ecdsa.py`, `probe_hazmat_noncanon.py`, `gen_appendix.py`) and
`logs/` (`.out`/`.log`/`.jsonl` for every batch, including the two
aborted attempts).

## 1. Verdict

No wrong-accept and no wrong-result was found in the implementation.
Across 94 unique ECDSA-verify cases (61 P-256, 33 P-384 — including the
u1=0, h≥n, R=∞, u1·G=u2·Q, cofactor-fallback and non-canonical-key
constructions), 383 field/point cases and 45 SHA-384 cases, the C64
agreed with the hazmat oracle everywhere the library's documented
contract applies. The one implementation defect reproduced is a **hard
hang** in `fp_mod_inv` on input 0, reachable through the public
`ec_jacobian_to_affine` on a point at infinity (no Z=0 guard) — a
consumer-triggerable lock-up, but not on the ECDSA-verify path (verify
rejects s=0 and tests Z≠0 before the cofactor compare). The weightier
results are on the test suite: the issue-#66 public-key-validation group
is **vacuous** (proved by mutation — with the Qx≥p gate NOP'd out all
four of its cases still pass while a constructed signature is then
wrongly accepted), the `fp_cmp`/`fp_is_zero` tests in both field suites
cannot fail, and the shipped suite never exercises h≥n, u1=0, R=∞, the
cofactor fallback branch, P+P / P+(−P) through the mixed add, k≥n on the
comb, or SHA chaining at non-1024 offsets. Two documentation
inaccuracies (`fp_cmp` "Z=1 if equal" is false; non-reduced-input
behaviour of `fp_mod_add/sub` undocumented) round it out.

## 2. Findings (ranked)

| id | severity | component | claim | reproduction | evidence (actual vs expected) |
|---|---|---|---|---|---|
| F-1 | HIGH (DoS via public API; not reachable through ECDSA verify) | `src/mod256.s` `fp_mod_inv`; `src/points256_core.s:1450-1457` `ec_jacobian_to_affine` (`_384` twins by identical structure — not run) | `fp_mod_inv` never terminates on input 0 (u=0 stays even forever in the binary-GCD halving loop; the only exits are `fp_chk_one(u/v)`); `ec_jacobian_to_affine` inverts Z without a zero test, so converting a point at infinity — the library's own Z=0 encoding, produced by `ec_scalar_mul` (k≡0 mod n), `ec_scalar_mul_var` (k≡0), `ec_point_add(P,−P)`, `ec_point_add_jj` negation — hangs the machine. | `python3.13 scripts/audit_prims.py` → section `hang probes`: `mod_inv(0)`, `fp_misc→ec_p256`, 90 s timeout | `c64_test_harness.transport.TimeoutError: No stopped event within 90.0s` (`logs/run_prims.out:422-464`); every other inversion in that session returned in <20 s. `mod_inv(p)` and `j2a(Z=0)` were **not reached** (transport unusable after the hang) — suspicions by code reading only. |
| F-2 | MEDIUM (test suite; gate untested) | `tools/test_ecdsa_verify.py::run_q_validation_tests` (issue #66) | All four cases reuse the RFC 6979 signature (key U) with a *substituted* Q, so the signature is invalid regardless of any Q gate; a verifier with step 3b deleted still returns C=1. | `python3.13 scripts/audit_ecdsa.py --p256-only --mutate` (mutation 3; `logs/run_ecdsa_p256.out`) | Gate sites found at `$2E1F,$2E37,$2E4F,$2E67` (r,s,Qx,Qy) + `$3076`. With the 3 bytes at `$2E4F` (`jmp @ev_fail` after the Qx≥p `fp_cmp`) set to NOP the suite group reports `4 passed, 0 failed`; the mutant then **accepts (C=0, 25.7 s)** the h=0 signature `(r,s)=(x(kQ) mod n, r·k⁻¹)` under Q=(0+p, y0), and rejects it (C=1) once the bytes are restored. |
| F-3 | MEDIUM (test-suite oracle assumption) | `tools/test_ecdsa_verify.py` comment in `run_q_validation_tests` ("cryptography refuses out-of-range … with ValueError") | OpenSSL reduces Qx≥p mod p and verifies; the suite's INVALID for case (a) comes from the wrong key, not the encoding. Any future test that is valid under the reduced point will see hazmat=VALID vs library=INVALID (library is right per FIPS 186-5). | `python3.13 scripts/probe_hazmat_noncanon.py` | P-256: `x=0 canonical: True | x+p: True`, `x=5 … x+p: True`; P-384 same for x=0, x=2. Off-curve points *are* refused (`ERR:pubkey:ValueError`). |
| F-4 | MEDIUM (tests that cannot fail) | `tools/test_fp256.py:459-500` (`test_fp_cmp`, `test_fp_is_zero`), `tools/test_fp384.py:270-297` | `passed += 1` unconditionally after the `jsr`; neither A nor flags are read. These are the primitives behind every ECDSA range gate. An `rts`-only `fp_cmp` passes both suites. | code reading; audit re-tested via the register dict `jsr()` returns | 26+26 "cases" per curve can only pass. Audit: 13 `fp_cmp` C-flag cases and 5 `fp_is_zero` Z-flag cases per curve, all correct (`logs/run_prims.out`). |
| F-5 | LOW (doc/contract) | `src/ecdsa256.s:174,178` and `src/ecdsa384.s:178` comments; `src/fp256.s:59-68` | `fp_cmp` does not leave Z=1 on equality: the final `dey` (Y 0→$FF) clears Z. C is correct; no caller uses Z. | `audit_prims.py` "cmp a==b: documented 'Z=1 if equal'" | `(C,Z)=(1,0)` for a==b, p vs p, n vs n on both curves (FL=$A1). |
| F-6 | LOW (doc/contract) | `fp_mod_add`, `fp_mod_sub` (+`_384`) | Inputs ≥p give non-canonical outputs (single conditional ±p). Undocumented; all in-library callers pass canonical values and the ECDSA gate guarantees Qx,Qy<p. `fp_mod_mul`, `fp_mod_sqr`, `fp_mod_reduce{256,384}` are exact for any full-width input. | `audit_prims.py` `NONRED` cases | P-256: `mod_add(p+1,p−1)`→p (exp 0); `mod_sub(p,0)`→p; `mod_sub(p+1,1)`→p; `mod_sub(1,W)`→p+2; `mod_sub(0,W)`→p+1; `mod_add(W,W)` non-canonical. 6 INFO per curve; `mod_add(p,0)`, `mod_add(p,1)`, `mod_add(W,0)`, `mod_add(W,1)`, `mod_sub(W,W)`, `mod_sub(0,p)` happened to be correct. |
| F-7 | LOW (coverage) | all suites, fast mode | Small fast-mode samples and absent classes (§4): 3 random per point routine, 5/15 CAVP per curve (`--full` asks for 20 of 15), no h≥n, u1=0, R=∞, cofactor fallback, P+P/P+(−P) via `ec_point_add`, k≥n on comb, SHA chaining at non-1024 offsets; CAVP "F" reason codes printed but never asserted; `mod_inv(0)` never tested. | code reading | see §4 |
| F-8 | INFO | `fp_mod_mul_n[_384]` | Documented precondition (≥1 operand < n) is real and load-bearing: with both operands ≥ n the output is wrong / non-reduced. ECDSA always passes `w<n` as the second operand; h≥n as first operand verified correct end-to-end. | `audit_prims.py` `mod_mul_n UNDOC` | P-256 `W·(n+1)`→2^256−1 (non-reduced), `W·W`→wrong; P-384 same shape. 11 in-contract cases per curve correct (`W·w`, `n·w`, `(n+1)·w`, `p·w`, `n·1`, `1·n`, `n·0`, `n·(n−1)`, `W·(n−1)`, swapped order). |
| F-9 | INFO (clean) | ECDSA verify, both curves | Every adversarial construction agreed with hazmat / the FIPS contract (list in §5). | `scripts/audit_ecdsa.py` | 61/61 P-256, 33/33 P-384 sweep cases PASS; details in the appendix. |

No CRITICAL finding.

## 3. Finding details

### F-1 — `fp_mod_inv(0)` hangs; `ec_jacobian_to_affine` has no Z=0 guard

`fp_mod_inv` (`src/mod256.s:714`) is a binary extended GCD whose main
loop leaves only through `fp_chk_one(u)` / `fp_chk_one(v)`. With u=0 the
"u even → halve" branch (`@halfu`) is taken on every iteration and u
stays 0; v=p is never reduced. The audit set `fp_src1→0`,
`fp_misc→ec_p256` and called it with a 90 s `jsr` timeout: no return
(every other inversion in the same session returned in < 20 s under
warp). By the same structure `fp_mod_inv(p)` (u=p≡0) and
`fp_mod_inv_384(0)` should hang too; they were not run because the
transport is unusable after a hang — **suspicion, not reproduced**.

`ec_jacobian_to_affine` (`src/points256_core.s:1450-1457`) does
`jsr ec_set_modp` and immediately inverts `ec_p3+64` (Z). Z=0 is the
library's own infinity encoding — this audit confirmed Z=0 is emitted by
`ec_scalar_mul` for k∈{0,n}, by `ec_scalar_mul_var` for k≡0, by
`ec_point_add(P,−P)` and by `ec_point_add_jj(P,−P)` — so a consumer that
converts such a result to affine locks up. `ecdsa_verify_*` is unaffected
(rejects s=0 before the mod-n inversion; tests Z≠0 before the cofactor
compare). Suggested fix: `fp_is_zero` on Z in `ec_jacobian_to_affine`
with a defined return, and/or document "never call on Z=0" in API.md;
add `mod_inv(0)` and `j2a(Z=0)` to the suites under a timeout.

### F-2 / F-3 — the issue-#66 Q-validation group is vacuous

`run_q_validation_tests` takes the RFC 6979 vector (signature made under
key U) and substitutes Q ∈ {(x_small+p, y), (Ux, Uy^2), (random≥p, Uy),
(Ux, random≥p)}. Under every one of these the signature itself is
invalid, so a verifier with the whole step-3b gate removed still returns
C=1. Mutation proof: the `jsr fp_cmp / bcc +3 / jmp @ev_fail` triples in
`ecdsa_verify_256` were located by pattern search; with the three bytes
of the Qx `jmp` NOP'd, the suite's group printed `4 passed, 0 failed`.
The same mutant then accepted (C=0) the signature
`(r,s) = (x(k·Q0) mod n, r·k⁻¹)`, h = 0, under Q = (0+p, y0) — valid
under the reduced point Q0=(0, y0) — and rejected it (C=1) after the
bytes were restored. The h=0 construction (u1=0 ⇒ `(r,s)` verifies under
any Q without knowing d) is the shape the suite needs: it fails exactly
when the gate is missing.

The oracle comment compounds this: OpenSSL does not reject Qx≥p; it
reduces (`probe_hazmat_noncanon.py`). Off-curve points are rejected
(`ValueError`), so case (b) has a correct oracle but is still vacuous on
the C64 side for the reason above.

### F-4 — `fp_cmp` / `fp_is_zero` tests cannot fail

`tools/test_fp256.py:459-500` and `tools/test_fp384.py:270-297` run the
routine and increment `passed` without reading anything back. The
register dict returned by `jsr()` carries `FL`; the audit's `flags_of()`
used it to check C for 13 comparisons per curve (a<b, a==b, a>b, p−1/p/p+1
vs p, n±1 vs n, W vs 0, 0 vs W, high-byte-only differences) and Z for 5
`fp_is_zero` inputs per curve. All correct — the routines are fine, the
tests are not. Note `fp_is_zero` returns A = first non-zero byte (not
$FF) for non-zero input; only Z is contractual.

### F-5 — `fp_cmp` Z flag

`fp_cmp` (`src/fp256.s:59`): `cmp` / `bne @done` / `dey` / `bpl`. On full
equality the last flag-setting instruction is `dey` with Y=0 → Z=0, N=1.
The comments in `ecdsa256.s` / `ecdsa384.s` promising Z=1 are wrong; only
C is meaningful. Every `jsr fp_cmp` in `src/` is followed by `bcc`/`bcs`.

### F-6 — non-reduced inputs to `fp_mod_add/sub`

Recorded (P-256; P-384 identical shape): `mod_add(p+1,p−1)=p`,
`mod_add(W,W)` non-canonical, `mod_sub(p,0)=p`, `mod_sub(p+1,1)=p`,
`mod_sub(1,W)=p+2`, `mod_sub(0,W)=p+1`. In contrast `fp_mod_mul`,
`fp_mod_sqr` and `fp_mod_reduce{256,384}` returned the exact `x mod p`
for every full-width and Solinas worst-case input tried: all-ones 32-bit
limb at each of the 16/24 positions, all-ones high halves at each
boundary, `p·W`, `W·W`, `p²`, `p<<bits`, `W<<bits`, `(p−1)²`, `2^(2·bits)−1`,
and `p`, `p+1`, `W` as single operands. One sentence "inputs must be < p"
in the two routine headers would close this.

## 4. Test-suite blind spots and suggested cases

1. **Q validation** (`test_ecdsa_verify.py`): add the h=0 construction
   for a non-canonical or otherwise-substituted Q' — pick k, R=k·Q_reduced,
   r=x(R) mod n, s=r·k⁻¹, h=0; expect C=1. This is the only shape that
   fails when the gate is removed (proved in F-2). Add Qy+p where it fits.
2. **Range gate strictness**: r=n+1, s=n+1, r=2^bits−1, s=2^bits−1 with an
   otherwise-valid signature (audit: all rejected at the gate, 0.0 s).
3. **h ≥ n end-to-end**: sign with e = h mod n but feed raw h ∈ {n, n+1,
   2^bits−1, p, random ≥ n}; expect VALID (audit: all VALID on both
   curves). Pins the `fp_mod_mul_n` precondition (`mod256.s:617-624`).
4. **u1 = 0 / h = 0**: constructed signature under any Q; expect VALID.
   Exercises the comb with a zero scalar and `ec_point_add_jj` with P2=∞
   (audit: VALID; comb emitted Z=0).
5. **R = ∞**: h ≡ −r·d (mod n); expect INVALID (audit: INVALID).
6. **u1·G = u2·Q** (J+J same-point → `ec_point_double` tail call):
   u1 free, R=2u1·G, r=x(R) mod n, h=r·d, s=r·d·u1⁻¹; expect VALID.
7. **Cofactor fallback** (`@ev_cof_fallback`): Q with x ∈ [n,p), h=0,
   (r,s)=(x−n, x−n) [u2=1] and the u2=2 lift Q'=(1/2)·Q; expect VALID;
   r=x−n+1 expect INVALID. The suite never executes that branch.
8. **Malleability**: (r, n−s) must VERIFY (audit: VALID) — state it
   explicitly so nobody "fixes" it.
9. **`fp_cmp` / `fp_is_zero`**: assert C (and Z for is_zero) from the
   `jsr()` register dict; include a==b, p vs p, high-byte-only
   differences; fix the "Z=1 if equal" comment.
10. **`fp_mod_inv(0)` / `j2a(Z=0)`** under a timeout — currently hangs.
11. **`ec_point_add` degeneracies**: P(Z=1)+P, lift(P,z)+P (H=0 with Z≠1),
    P+(−P), lift(P,z)+(−P), ∞(Z=0, garbage X/Y)+P (audit: all correct,
    Z=0 emitted for infinity).
12. **`ec_scalar_mul_var`** with k ∈ {n+1, n+2 (forces the R==P mixed-add
    doubling mid-ladder), 2^bits−1, 2^(bits−1), (n±1)/2, n−2}; base −G
    with k=n−1 (audit: all correct). k=2n does not fit the field width
    on either curve.
13. **Comb** with k ∈ {0, n, n+1, 2^bits−1, 2^(bits−1), all K_i=1 (idx 255
    at column 0), all K_i top-bit (idx 255 at column 31), K0 all-ones,
    top limb all-ones, 2^32}; comb-vs-var-base agreement (audit: all
    correct, Z=0 for k∈{0,n}).
14. **SHA-384**: chained updates split at 0/1/64/100/111/112/127/128/255
    offsets, repeated zero-length updates, `update(len=0)` alone, 1024+1,
    lengths 65, 119, 120, 191, 192, 239, 240, 241, 2047, 2048 (audit: all
    correct). A single 2^16−1 update needs a >1 KB buffer; not attempted.
15. **CAVP SigVer**: `--full` requests 20 vectors of 15; reason codes
    ("F (2 − R changed)" etc.) are printed but never asserted; the P-384
    fast subset contains no "Message changed" vector.
16. **Random sample sizes**: 3 per point routine, 3 random `mod_mul_n`,
    20 random field cases in fast mode. The structured cases above found
    more than extra random draws would.
17. **Struct bounds (task 5d)**: the 160/240 B layout is asserted only on
    the Python side; the C64 reads exactly 5×32 / 5×48 bytes through
    `fp_reverse32/48` and has no length concept — nothing to enforce
    on-chip. The harness scalar buffer at `$033C` (48 B → `$036C`) does
    not overlap the `jsr()` trampoline (`$0334-$0338`) or the `$0339`
    guard.

## 5. Covered and found clean (negative space)

- **ECDSA P-256 (61 cases, ~33 s each for full verifies)**: baseline;
  (r, n−s); r,s ∈ {0, 1, n−1, n, n+1, 2^256−1}; h ∈ {0, 1, n−1, n, n+1,
  p, 2^255, 2^256−1, random ≥ n} each with a signature made for e=h mod n
  (VALID) and h∈{0, 2^256−1} with the baseline signature (INVALID); h=0
  constructed signatures under Q ∈ {random, G, −G, 2G, (0,y0), (0,−y0)};
  (r,s)=(Qx,Qx) with h=0; cofactor fallback (u2=1 and u2=2 lifts) +
  negative; R=∞; u1·G=u2·Q; Qx+p (×2, must reject); Q ∈ {(0,0), (p,p),
  (W,W), off-curve, −Q, wrong-b curve}; d ∈ {1, 2, n−1, n−2}; r with 1
  and 2 leading zero bytes, s with 1; nonce k ∈ {1, n−1}; 4 hazmat-signed
  random positives + 4 single-bit-flip negatives (r/s/h).
- **ECDSA P-384 (33 cases, ~65–95 s each)**: the trimmed subset of the
  above (baseline, malleable, r=n−1, s=n−1, s=n, r=n+1, s=n+1,
  s=2^384−1, r=0, h∈{0, n, 2^384−1} valid, h∈{0, 2^384−1} with baseline
  sig, h=0 under random Q and −G, (Qx,Qx), cofactor fallback + negative,
  R=∞, u1·G=u2·Q, x=0 point, Qx+p ×2, (0,0), (p,p), off-curve, wrong
  curve, d=n−1, short r, k=1, hazmat random valid, h bit flipped).
- **Field, per curve**: `fp_mod_add/sub` 4+4 reduced; `fp_mod_reduce`
  12 structured + 16/24 limb sweeps + 8/12 high-half sweeps + 4 random;
  `fp_mod_mul` 5 reduced + 6 full-width; `fp_mod_sqr` vs `fp_mod_mul` 5;
  `fp_mod_mul_n` 11 in-contract; `fp_mod_inv` mod p 4 (p−1, 2, 2^(bits−1),
  random) and mod n 2; `fp_is_zero` 5; `fp_cmp` 13.
- **Points, per curve**: mixed add 9 (P+P, lift+P, P+(−P), lift+(−P),
  ∞+P with garbage X/Y, ∞(all-zero)+P, lift+G, P+G, G+G) with Z=0
  encoding checks; double 5 (Z=1, lift, Z=0 garbage, Z=0 zero, junk);
  J+J 5 (same point two lifts, negation two lifts, distinct, P+∞, ∞+P);
  `scalar_mul_var` 9 (P-256) / 4 (P-384) structured + base −G;
  comb 13 (P-256) / 7 (P-384) structured; comb vs var-base vs hazmat on
  one random k per curve.
- **SHA-384**: 28 lengths (0…2048 incl. every pad boundary), 12 chaining
  splits, zero-length update alone, 1024+1, re-init, 4133 B multi-chunk.
- **Mutation** (`ecdsa_verify_256` entry patched in the emulator):
  `clc;rts` → suite RFC group 1/9 (8 failures); `sec;rts` → 8/9
  (1 failure). The ECDSA suite does detect a stuck verifier. The
  `fp_cmp`/`fp_is_zero` tests would not detect anything (F-4) — a test
  with no comparison needs no run to prove that.
- **Oracle leakage**: none — the only long hex literals in the tests are
  RFC 6979 A.2.5/A.3.1 and FIPS constants; every expectation comes from
  `cryptography`, Python ints, `hashlib`, or the NIST `.rsp` files.
- **Behaviour-only records (INFO, not defects)**: `point_double` on
  (0,0,1) → (9, 27, 0) (∞); `scalar_mul_var` on base (0,0) → Z=0;
  `sha384_final` twice without `init` → different digest (must re-init,
  as documented).

## 6. Exact case counts

Recorded log records (all batches, all verdicts): **634** — PASS 591,
FAIL 7, INFO 36. Of the 7 FAILs, 1 is the intended mutation
demonstrator (F-2, "suite issue#66 group detects Qx range gate removal"
— failing is the finding) and 6 are audit-script expectation errors in
the aborted first primitives attempt (`fp_is_zero` A-register and
`fp_cmp` Z expectations, corrected and re-run: see F-4/F-5); no FAIL is
a library defect. The hang (F-1) is recorded as a traceback, not a case
row.

Unique C64 cases (excluding the 4 P-384 cases duplicated by the stopped
untrimmed attempt and the P-256 field/point cases re-run after the
script fix):

| batch | unique cases | notes |
|---|---|---|
| ECDSA P-256 sweep | 61 | + 5 mutation records (3 suite-group runs = 9+9+4 suite cases, 2 direct) |
| ECDSA P-384 sweep (trimmed) | 33 | untrimmed attempt: 4 (duplicates) |
| SHA-384 | 45 | 44 checked + 1 INFO |
| field P-256 | 123 | 112 PASS + 11 INFO (attempt 1 had 106+8 of these) |
| field P-384 | 135 | 124 PASS + 11 INFO |
| point P-256 | 47 | 45 PASS + 2 INFO |
| point P-384 | 38 | 36 PASS + 2 INFO |
| hang probe | 1 | `mod_inv(0)` — hung |
| **total** | **483** | + 5 mutation records |

VICE wall time: P-256 batch ≈ 45 min, P-384 batch ≈ 42 min (trimmed;
untrimmed attempt 13 min before stop), primitives ≈ 25 + 40 min (two
attempts); three instances ran concurrently.

## Appendix — every recorded case

Total recorded cases: PASS=591 FAIL=7 INFO=36 (sum 634)


### ECDSA P-256 sweep + mutation (one boot) — `ecdsa_p256.jsonl`

PASS=66 FAIL=1 INFO=0

| verdict | section | case | expected | got | s |
|---|---|---|---|---|---|
| PASS | ecdsa-p256 | baseline valid (hazmat key, manual k) | 0 | 0 | 35.2 |
| PASS | ecdsa-p256 | malleable (r, n-s) must VERIFY | 0 | 0 | 35.3 |
| PASS | ecdsa-p256 | r = n-1 (random) | 1 | 1 | 34.2 |
| PASS | ecdsa-p256 | s = n-1 (random) | 1 | 1 | 36.1 |
| PASS | ecdsa-p256 | r = n | 1 | 1 | 0.3 |
| PASS | ecdsa-p256 | s = n | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | r = n+1 | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | s = n+1 | 1 | 1 | 0.6 |
| PASS | ecdsa-p256 | r = 2^bits-1 | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | s = 2^bits-1 | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | r = 0 | 1 | 1 | 0.1 |
| PASS | ecdsa-p256 | s = 0 | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | r = 1 (random sig) | 1 | 1 | 34.7 |
| PASS | ecdsa-p256 | s = 1 (random sig) | 1 | 1 | 35.2 |
| PASS | ecdsa-p256 | h = 0 via signing (u1 = 0 path) | 0 | 0 | 30.9 |
| PASS | ecdsa-p256 | h = n (≡0 mod n, unreduced input) | 0 | 0 | 31.2 |
| PASS | ecdsa-p256 | h = n+1 | 0 | 0 | 33.5 |
| PASS | ecdsa-p256 | h = 2^bits-1 (>= n, unreduced) | 0 | 0 | 34.1 |
| PASS | ecdsa-p256 | h = n-1 | 0 | 0 | 33.6 |
| PASS | ecdsa-p256 | h = 1 | 0 | 0 | 32.8 |
| PASS | ecdsa-p256 | h = 2^(bits-1) (top bit only) | 0 | 0 | 34.8 |
| PASS | ecdsa-p256 | h = p (field prime as hash) | 0 | 0 | 33.5 |
| PASS | ecdsa-p256 | h = 2^bits - (2^bits - n) - 1 + ... random >= n | 0 | 0 | 34.0 |
| PASS | ecdsa-p256 | h = 0 with baseline sig (must reject) | 1 | 1 | 28.9 |
| PASS | ecdsa-p256 | h = 2^bits-1 with baseline sig (must reject) | 1 | 1 | 33.8 |
| PASS | ecdsa-p256 | h=0 constructed sig, random Q | 0 | 0 | 28.4 |
| PASS | ecdsa-p256 | h=0 constructed sig, Q = G | 0 | 0 | 28.3 |
| PASS | ecdsa-p256 | h=0 constructed sig, Q = -G | 0 | 0 | 27.7 |
| PASS | ecdsa-p256 | h=0 constructed sig, Q = 2G | 0 | 0 | 29.3 |
| PASS | ecdsa-p256 | h=0, (r,s)=(Qx,Qx): u2=1, R=Q, x(R)=r | 0 | 0 | 0.2 |
| PASS | ecdsa-p256 | cofactor fallback: Q.x in [n,p), r = Qx-n, s = r, h=0 | 0 | 0 | 0.2 |
| PASS | ecdsa-p256 | cofactor fallback negative: r = Qx-n+1 | 1 | 1 | 28.4 |
| PASS | ecdsa-p256 | cofactor fallback via u2=2: Q=(1/2)R, r=Qx(R)-n, s=r/2, h=0 | 0 | 0 | 0.2 |
| PASS | ecdsa-p256 | u1*G + u2*Q = infinity (h = -r*d mod n) must REJECT | 1 | 1 | 34.4 |
| PASS | ecdsa-p256 | u1*G == u2*Q (J+J doubling path), valid | 0 | 0 | 32.9 |
| PASS | ecdsa-p256 | h=0 constructed sig, Q with smallest x=0 | 0 | 0 | 28.3 |
| PASS | ecdsa-p256 | same but Qx+p (non-canonical) must REJECT | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | h=0 constructed sig, Q = (x0, -y0) | 0 | 0 | 27.1 |
| PASS | ecdsa-p256 | same but Qx+p (non-canonical) must REJECT | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | Q = (0,0) infinity-ish encoding | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | Q = (p, p) | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | Q = (2^bits-1, 2^bits-1) | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | Q off-curve (qy+1) | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | Q = (qx, -qy) i.e. -Q with Q's sig | 1 | 1 | 33.4 |
| PASS | ecdsa-p256 | Q on wrong curve (b+1) | 1 | 1 | 0.0 |
| PASS | ecdsa-p256 | valid sig, d=1 (Q=G) | 0 | 0 | 33.0 |
| PASS | ecdsa-p256 | valid sig, d=2 | 0 | 0 | 34.2 |
| PASS | ecdsa-p256 | valid sig, d=n-1 (Q=-G) | 0 | 0 | 33.0 |
| PASS | ecdsa-p256 | valid sig, d=n-2 | 0 | 0 | 33.1 |
| PASS | ecdsa-p256 | valid sig with r top byte 0 (r=0xf34d9502c2c2d3416e202ebd2713afd4e5eb9549e96f958970d6588d1ab773) | 0 | 0 | 32.4 |
| PASS | ecdsa-p256 | valid sig with s top byte 0 (s=0xceffb67e720cc14c85b2bc7c01900879d6b3ca030de3a1162a9aa5d3aa242) | 0 | 0 | 33.9 |
| PASS | ecdsa-p256 | valid sig with r top 2 bytes 0 (r=0xc36c5c6aa7cc1713add140ec77a1b548f232993888a0ec6b3a6de98a47d4) | 0 | 0 | 34.4 |
| PASS | ecdsa-p256 | valid sig with k=1 (r = Gx mod n) | 0 | 0 | 32.8 |
| PASS | ecdsa-p256 | valid sig with k=n-1 | 0 | 0 | 33.7 |
| PASS | ecdsa-p256 | hazmat random valid #0 | 0 | 0 | 33.5 |
| PASS | ecdsa-p256 | hazmat random #0, r bit flipped | 1 | 1 | 31.7 |
| PASS | ecdsa-p256 | hazmat random valid #1 | 0 | 0 | 31.4 |
| PASS | ecdsa-p256 | hazmat random #1, h bit flipped | 1 | 1 | 31.5 |
| PASS | ecdsa-p256 | hazmat random valid #2 | 0 | 0 | 30.7 |
| PASS | ecdsa-p256 | hazmat random #2, s bit flipped | 1 | 1 | 32.4 |
| PASS | ecdsa-p256 | hazmat random valid #3 | 0 | 0 | 31.6 |
| PASS | ecdsa-p256 | hazmat random #3, r bit flipped | 1 | 1 | 32.5 |
| PASS | mutation | suite detects verify_256 := always-VALID (clc;rts) | fails>0 | fails=8 |  |
| PASS | mutation | suite detects verify_256 := always-INVALID (sec;rts) | fails>0 | fails=1 |  |
| FAIL | mutation | suite issue#66 group detects Qx range gate removal | fails>0 | fails=0 |  |
| PASS | mutation | gate-removed mutant ACCEPTS Qx+p with h=0 sig (shows constructed case is load-bearing) | 0 | 0 | 25.7 |
| PASS | mutation | restored build rejects the same Qx+p case | 1 | 1 | 0.0 |

### ECDSA P-384 sweep, trimmed list (one boot) — `ecdsa_p384.jsonl`

PASS=33 FAIL=0 INFO=0

| verdict | section | case | expected | got | s |
|---|---|---|---|---|---|
| PASS | ecdsa-p384 | baseline valid (hazmat key, manual k) | 0 | 0 | 90.8 |
| PASS | ecdsa-p384 | malleable (r, n-s) must VERIFY | 0 | 0 | 93.8 |
| PASS | ecdsa-p384 | r = n-1 (random) | 1 | 1 | 93.3 |
| PASS | ecdsa-p384 | s = n-1 (random) | 1 | 1 | 93.0 |
| PASS | ecdsa-p384 | s = n | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | r = n+1 | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | s = n+1 | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | s = 2^bits-1 | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | r = 0 | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | h = 0 via signing (u1 = 0 path) | 0 | 0 | 79.2 |
| PASS | ecdsa-p384 | h = n (≡0 mod n, unreduced input) | 0 | 0 | 79.3 |
| PASS | ecdsa-p384 | h = 2^bits-1 (>= n, unreduced) | 0 | 0 | 86.7 |
| PASS | ecdsa-p384 | h = 0 with baseline sig (must reject) | 1 | 1 | 73.5 |
| PASS | ecdsa-p384 | h = 2^bits-1 with baseline sig (must reject) | 1 | 1 | 86.8 |
| PASS | ecdsa-p384 | h=0 constructed sig, random Q | 0 | 0 | 68.7 |
| PASS | ecdsa-p384 | h=0 constructed sig, Q = -G | 0 | 0 | 65.0 |
| PASS | ecdsa-p384 | h=0, (r,s)=(Qx,Qx): u2=1, R=Q, x(R)=r | 0 | 0 | 0.3 |
| PASS | ecdsa-p384 | cofactor fallback: Q.x in [n,p), r = Qx-n, s = r, h=0 | 0 | 0 | 0.3 |
| PASS | ecdsa-p384 | cofactor fallback negative: r = Qx-n+1 | 1 | 1 | 60.5 |
| PASS | ecdsa-p384 | u1*G + u2*Q = infinity (h = -r*d mod n) must REJECT | 1 | 1 | 71.5 |
| PASS | ecdsa-p384 | u1*G == u2*Q (J+J doubling path), valid | 0 | 0 | 73.0 |
| PASS | ecdsa-p384 | h=0 constructed sig, Q with smallest x=0 | 0 | 0 | 55.2 |
| PASS | ecdsa-p384 | same but Qx+p (non-canonical) must REJECT | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | same but Qx+p (non-canonical) must REJECT | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | Q = (0,0) infinity-ish encoding | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | Q = (p, p) | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | Q off-curve (qy+1) | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | Q on wrong curve (b+1) | 1 | 1 | 0.0 |
| PASS | ecdsa-p384 | valid sig, d=n-1 (Q=-G) | 0 | 0 | 65.9 |
| PASS | ecdsa-p384 | valid sig with r top byte 0 (r=0x39a5049712fef05ddd0a0d4b5d3eb45ca69f922c53cae0a3ade3c7f2bac9591e6ec498a12b00f59ff1b10f1f7c67c) | 0 | 0 | 66.5 |
| PASS | ecdsa-p384 | valid sig with k=1 (r = Gx mod n) | 0 | 0 | 65.8 |
| PASS | ecdsa-p384 | hazmat random valid #0 | 0 | 0 | 67.2 |
| PASS | ecdsa-p384 | hazmat random #1, h bit flipped | 1 | 1 | 68.4 |

### ECDSA P-384 untrimmed attempt (stopped early; 4 cases) — `ecdsa_p384_attempt1.jsonl`

PASS=3 FAIL=0 INFO=0

| verdict | section | case | expected | got | s |
|---|---|---|---|---|---|
| PASS | ecdsa-p384 | baseline valid (hazmat key, manual k) | 0 | 0 | 98.7 |
| PASS | ecdsa-p384 | malleable (r, n-s) must VERIFY | 0 | 0 | 94.6 |
| PASS | ecdsa-p384 | r = n-1 (random) | 1 | 1 | 97.0 |

### Primitives attempt 1 (SHA-384 + field-p256 + part of point-p256; aborted by a script bug) — `prims_attempt1.jsonl`

PASS=172 FAIL=6 INFO=10

| verdict | section | case | expected | got | s |
|---|---|---|---|---|---|
| PASS | sha384 | len=0 | 38b060a751ac96384cd9327eb1b1e36a21fdb... | 38b060a751ac96384cd9327eb1b1e36a21fdb... |  |
| PASS | sha384 | len=1 | c4f5e040694c9905be0ecde44986bc8797e9c... | c4f5e040694c9905be0ecde44986bc8797e9c... |  |
| PASS | sha384 | len=55 | 71894fc0e37c7729d52358491b121e1d88e44... | 71894fc0e37c7729d52358491b121e1d88e44... |  |
| PASS | sha384 | len=56 | dc6c6aea6ec5fa85e417918974dd473d1e38c... | dc6c6aea6ec5fa85e417918974dd473d1e38c... |  |
| PASS | sha384 | len=57 | b0029248dcc07603ac2ee9ae35963366d5564... | b0029248dcc07603ac2ee9ae35963366d5564... |  |
| PASS | sha384 | len=63 | 604567cd71be620890cad34fbb5b85107bdb8... | 604567cd71be620890cad34fbb5b85107bdb8... |  |
| PASS | sha384 | len=64 | fe6ee1f562fda1ca0fac75982f2a740987f6e... | fe6ee1f562fda1ca0fac75982f2a740987f6e... |  |
| PASS | sha384 | len=65 | ef423cca63603c713b4e6c92f84ef55d231c8... | ef423cca63603c713b4e6c92f84ef55d231c8... |  |
| PASS | sha384 | len=111 | 2340d9c596ebdf9dc4f7a9d5f2458538108fe... | 2340d9c596ebdf9dc4f7a9d5f2458538108fe... |  |
| PASS | sha384 | len=112 | cb16727722eb903c04b583b26aa803c356dd5... | cb16727722eb903c04b583b26aa803c356dd5... |  |
| PASS | sha384 | len=113 | 04b415cc01447ef8cd5093bd75be5abdd2e65... | 04b415cc01447ef8cd5093bd75be5abdd2e65... |  |
| PASS | sha384 | len=119 | 5b688e5fd12285e7580dfc3f79560eab1fc07... | 5b688e5fd12285e7580dfc3f79560eab1fc07... |  |
| PASS | sha384 | len=120 | 709be7b2bcedcd101bf6fea8d5a87b238dfe0... | 709be7b2bcedcd101bf6fea8d5a87b238dfe0... |  |
| PASS | sha384 | len=127 | 884fa3ef99f2ee4be2a53dcc5f9b003028758... | 884fa3ef99f2ee4be2a53dcc5f9b003028758... |  |
| PASS | sha384 | len=128 | ee5da92e1c6f717366da2332a218e9d470bae... | ee5da92e1c6f717366da2332a218e9d470bae... |  |
| PASS | sha384 | len=129 | 0fa5951661819795ceab4e9db2e390cf344d6... | 0fa5951661819795ceab4e9db2e390cf344d6... |  |
| PASS | sha384 | len=191 | 0a642330999b34439498e0bb6aab37d60ac67... | 0a642330999b34439498e0bb6aab37d60ac67... |  |
| PASS | sha384 | len=192 | 18c8f79e07b162633623eaa3f814f685a72d7... | 18c8f79e07b162633623eaa3f814f685a72d7... |  |
| PASS | sha384 | len=239 | 4152d3f8621ef405115c9d458a6e301ad5dfd... | 4152d3f8621ef405115c9d458a6e301ad5dfd... |  |
| PASS | sha384 | len=240 | 5395e95f9d79299346b656a65c7e5403a58ed... | 5395e95f9d79299346b656a65c7e5403a58ed... |  |
| PASS | sha384 | len=241 | 718599733d2306c897ada4ff98f7235158cbf... | 718599733d2306c897ada4ff98f7235158cbf... |  |
| PASS | sha384 | len=255 | b6dba0c74b7621aa0a3cf28d1cee1d0492e25... | b6dba0c74b7621aa0a3cf28d1cee1d0492e25... |  |
| PASS | sha384 | len=256 | 0c1c27a6fb031cab56357048f1d0746c71334... | 0c1c27a6fb031cab56357048f1d0746c71334... |  |
| PASS | sha384 | len=1023 | cb713b191665a4ce83c6793079f83410681cd... | cb713b191665a4ce83c6793079f83410681cd... |  |
| PASS | sha384 | len=1024 | bac9824ae54882575b8596e7887088c899ee7... | bac9824ae54882575b8596e7887088c899ee7... |  |
| PASS | sha384 | len=1025 | 1eb9333d1b566300e675778c1b43864b59ebf... | 1eb9333d1b566300e675778c1b43864b59ebf... |  |
| PASS | sha384 | len=2048 | 82c5f2f3f52174f31fa0fe262a58d2090eb19... | 82c5f2f3f52174f31fa0fe262a58d2090eb19... |  |
| PASS | sha384 | len=2047 | ad2faff53a027e4a3beac23d90bf6e82cffea... | ad2faff53a027e4a3beac23d90bf6e82cffea... |  |
| PASS | sha384 | chained updates splits=(0,) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(1,) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(64,) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(100,) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(128,) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(1, 1, 1) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(0, 0) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(128, 128) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(127, 1) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(111, 1) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(112, 0, 1) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | chained updates splits=(255, 45) (300 B) | 2ee72d7d7c6b07e52ca95383056d13d5496b9... | 2ee72d7d7c6b07e52ca95383056d13d5496b9... |  |
| PASS | sha384 | init; update(len=0); final == sha384(b'') | 38b060a751ac96384cd9327eb1b1e36a21fdb... | 38b060a751ac96384cd9327eb1b1e36a21fdb... |  |
| PASS | sha384 | 1024 + 1 chained | dfc8baf2b710b1b9e07ac4fb19d6103b725d2... | dfc8baf2b710b1b9e07ac4fb19d6103b725d2... |  |
| INFO | sha384 | final twice without re-init (behaviour) | cb00753f45a35e8bb5a03d699ac65007272c3... | cc63528d778b88ad3fa8674926647f6d3ec77... |  |
| PASS | sha384 | re-init discards previous partial data | cb00753f45a35e8bb5a03d699ac65007272c3... | cb00753f45a35e8bb5a03d699ac65007272c3... |  |
| PASS | sha384 | len=4133 in 1024-chunks | 4d616c18611260e0855321cefdd5ac142d2c5... | 4d616c18611260e0855321cefdd5ac142d2c5... |  |
| PASS | field-p256 | mod_add (p-1)+(p-1) | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_add (p-1)+1 | 0 | 0 |  |
| PASS | field-p256 | mod_add 0+0 | 0 | 0 |  |
| PASS | field-p256 | mod_add a+a | 24691357802469135780 | 24691357802469135780 |  |
| PASS | field-p256 | mod_add NONRED p+0 | 0 | 0 |  |
| PASS | field-p256 | mod_add NONRED p+1 | 1 | 1 |  |
| INFO | field-p256 | mod_add NONRED (p+1)+(p-1) | 0 | 1157920892103562487626974469494075735... |  |
| INFO | field-p256 | mod_add NONRED W+W | 5391989332174707611856066864636768250... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_add NONRED W+0 | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_add NONRED W+1 | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_sub 0-(p-1) | 1 | 1 |  |
| PASS | field-p256 | mod_sub 0-1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_sub 1-1 | 0 | 0 |  |
| PASS | field-p256 | mod_sub (p-1)-(p-1) | 0 | 0 |  |
| INFO | field-p256 | mod_sub NONRED 1-W | 1157920891833963021018239088901272392... | 1157920892103562487626974469494075735... |  |
| INFO | field-p256 | mod_sub NONRED p-0 | 0 | 1157920892103562487626974469494075735... |  |
| INFO | field-p256 | mod_sub NONRED (p+1)-1 | 0 | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_sub NONRED W-W | 0 | 0 |  |
| INFO | field-p256 | mod_sub NONRED 0-W | 1157920891833963021018239088901272392... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_sub NONRED 0-p | 0 | 0 |  |
| PASS | field-p256 | mod_reduce 2^(2w)-1 | 1347997333231989955025617139070862921... | 1347997333231989955025617139070862921... |  |
| PASS | field-p256 | mod_reduce (p-1)^2 | 1 | 1 |  |
| PASS | field-p256 | mod_reduce p*(W) | 0 | 0 |  |
| PASS | field-p256 | mod_reduce W*W | 8087984000145191938400104526071860965... | 8087984000145191938400104526071860965... |  |
| PASS | field-p256 | mod_reduce p*p | 0 | 0 |  |
| PASS | field-p256 | mod_reduce p<<(8nb) | 0 | 0 |  |
| PASS | field-p256 | mod_reduce W<<(8nb) | 1078397866623254574432813795839024509... | 1078397866623254574432813795839024509... |  |
| PASS | field-p256 | mod_reduce p | 0 | 0 |  |
| PASS | field-p256 | mod_reduce p+1 | 1 | 1 |  |
| PASS | field-p256 | mod_reduce 2p | 0 | 0 |  |
| PASS | field-p256 | mod_reduce W | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_reduce p-1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_reduce limb0 all-ones | 4294967295 | 4294967295 |  |
| PASS | field-p256 | mod_reduce limb1 all-ones | 18446744069414584320 | 18446744069414584320 |  |
| PASS | field-p256 | mod_reduce limb2 all-ones | 79228162495817593519834398720 | 79228162495817593519834398720 |  |
| PASS | field-p256 | mod_reduce limb3 all-ones | 340282366841710300949110269838224261120 | 340282366841710300949110269838224261120 |  |
| PASS | field-p256 | mod_reduce limb4 all-ones | 1461501636990620551282746369252908412... | 1461501636990620551282746369252908412... |  |
| PASS | field-p256 | mod_reduce limb5 all-ones | 6277101733925179126504886505003981583... | 6277101733925179126504886505003981583... |  |
| PASS | field-p256 | mod_reduce limb6 all-ones | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_reduce limb7 all-ones | 1157920892103562487564203452140208927... | 1157920892103562487564203452140208927... |  |
| PASS | field-p256 | mod_reduce limb8 all-ones | 1157920891833963020955468071547405584... | 1157920891833963020955468071547405584... |  |
| PASS | field-p256 | mod_reduce limb9 all-ones | 1157920891833963021018239088886657375... | 1157920891833963021018239088886657375... |  |
| PASS | field-p256 | mod_reduce limb10 all-ones | 340282367079394788491903282614561144831 | 340282367079394788491903282614561144831 |  |
| PASS | field-p256 | mod_reduce limb11 all-ones | 1461501638011467652045561759624585490... | 1461501638011467652045561759624585490... |  |
| PASS | field-p256 | mod_reduce limb12 all-ones | 6277101738309684038497595259535807919... | 6277101738309684038497595259535807919... |  |
| PASS | field-p256 | mod_reduce limb13 all-ones | 2695994667970484326544037661435092715... | 2695994667970484326544037661435092715... |  |
| PASS | field-p256 | mod_reduce limb14 all-ones | 8087983999517481764715286285955191731... | 8087983999517481764715286285955191731... |  |
| PASS | field-p256 | mod_reduce limb15 all-ones | 5391989330919287264632580548102491836... | 5391989330919287264632580548102491836... |  |
| PASS | field-p256 | mod_reduce high limbs 8.. all ones | 1078397866623254574432813795839024509... | 1078397866623254574432813795839024509... |  |
| PASS | field-p256 | mod_reduce high limbs 9.. all ones | 1347997333294760972379483946712623639... | 1347997333294760972379483946712623639... |  |
| PASS | field-p256 | mod_reduce high limbs 10.. all ones | 1617596799903496352986902306317771081... | 1617596799903496352986902306317771081... |  |
| PASS | field-p256 | mod_reduce high limbs 11.. all ones | 1617596799903496352986902306314368257... | 1617596799903496352986902306314368257... |  |
| PASS | field-p256 | mod_reduce high limbs 12.. all ones | 1617596799903496352972287289934253580... | 1617596799903496352972287289934253580... |  |
| PASS | field-p256 | mod_reduce high limbs 13.. all ones | 1617596799840725335589190449549277628... | 1617596799840725335589190449549277628... |  |
| PASS | field-p256 | mod_reduce high limbs 14.. all ones | 1347997333043676902934786683405768356... | 1347997333043676902934786683405768356... |  |
| PASS | field-p256 | mod_reduce high limbs 15.. all ones | 5391989330919287264632580548102491836... | 5391989330919287264632580548102491836... |  |
| PASS | field-p256 | mod_reduce rand wide #0 | 6248706765162118432338387450794493257... | 6248706765162118432338387450794493257... |  |
| PASS | field-p256 | mod_reduce rand wide #1 | 1789829365733894562299197542394762629... | 1789829365733894562299197542394762629... |  |
| PASS | field-p256 | mod_reduce rand wide #2 | 6459964295414030835919385747159598038... | 6459964295414030835919385747159598038... |  |
| PASS | field-p256 | mod_reduce rand wide #3 | 2469624805273676175067569613270196628... | 2469624805273676175067569613270196628... |  |
| PASS | field-p256 | mod_mul (p-1)*(p-1) | 1 | 1 |  |
| PASS | field-p256 | mod_mul (p-1)*1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_mul 0*(p-1) | 0 | 0 |  |
| PASS | field-p256 | mod_mul rand*rand | 9658933827418939441096490018597718095... | 9658933827418939441096490018597718095... |  |
| PASS | field-p256 | mod_mul rand*(p-1) | 4974031786551291683279737042785972485... | 4974031786551291683279737042785972485... |  |
| PASS | field-p256 | mod_mul NONRED p*1 | 0 | 0 |  |
| PASS | field-p256 | mod_mul NONRED (p+1)*1 | 1 | 1 |  |
| PASS | field-p256 | mod_mul NONRED W*W | 8087984000145191938400104526071860965... | 8087984000145191938400104526071860965... |  |
| PASS | field-p256 | mod_mul NONRED W*1 | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_mul NONRED p*p | 0 | 0 |  |
| PASS | field-p256 | mod_mul NONRED W*(p-1) | 1157920891833963021018239088901272392... | 1157920891833963021018239088901272392... |  |
| PASS | field-p256 | mod_sqr rand | 1465157698268085023285295489995519277... | 1465157698268085023285295489995519277... |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency rand | 1465157698268085023285295489995519277... | 1465157698268085023285295489995519277... |  |
| PASS | field-p256 | mod_sqr p-1 | 1 | 1 |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency p-1 | 1 | 1 |  |
| PASS | field-p256 | mod_sqr 2^(8nb-1) | 8684406694146711990282283408769610862... | 8684406694146711990282283408769610862... |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency 2^(8nb-1) | 8684406694146711990282283408769610862... | 8684406694146711990282283408769610862... |  |
| PASS | field-p256 | mod_sqr NONRED W | 8087984000145191938400104526071860965... | 8087984000145191938400104526071860965... |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency NONRED W | 8087984000145191938400104526071860965... | 8087984000145191938400104526071860965... |  |
| PASS | field-p256 | mod_sqr NONRED p | 0 | 0 |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency NONRED p | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n (n-1)*(n-1) | 1 | 1 |  |
| PASS | field-p256 | mod_mul_n h=W * w<n (documented ok) | 1019279870850732513906402253172082965... | 1019279870850732513906402253172082965... |  |
| PASS | field-p256 | mod_mul_n h=n * w<n | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n h=n+1 * w<n | 9963474068188711751256717134775579228... | 9963474068188711751256717134775579228... |  |
| PASS | field-p256 | mod_mul_n h=p * w<n | 9657343329205773159569781497978505773... | 9657343329205773159569781497978505773... |  |
| PASS | field-p256 | mod_mul_n w<n * h=W (swapped) | 1019279870850732513906402253172082965... | 1019279870850732513906402253172082965... |  |
| PASS | field-p256 | mod_mul_n h=W * (n-1) | 1157920891833963021018239088901272392... | 1157920891833963021018239088901272392... |  |
| PASS | field-p256 | mod_mul_n n*1 | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n 1*n | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n n*0 | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n n * (n-1) | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n UNDOC both>=n: n*n | 0 | 0 |  |
| INFO | field-p256 | mod_mul_n UNDOC both>=n: W*W | 4653376568548642097637396064859033011... | 5428031343339130993844007122839936175... |  |
| PASS | field-p256 | mod_mul_n UNDOC both>=n: (n+1)*(n+1) | 1 | 1 |  |
| INFO | field-p256 | mod_mul_n UNDOC both>=n: W*(n+1) | 2695994666087353805928033432327302944... | 1157920892373161954235709850086879078... |  |
| PASS | field-p256 | mod_inv p-1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_inv 2 | 5789604460517812438134872347470378676... | 5789604460517812438134872347470378676... |  |
| PASS | field-p256 | mod_inv 2^(8nb-1) | 1157920891564363554660587777636246181... | 1157920891564363554660587777636246181... |  |
| PASS | field-p256 | mod_inv rand | 1020500087298933143081925453483514987... | 1020500087298933143081925453483514987... |  |
| PASS | field-p256 | mod_inv mod n: (n-1)^-1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_inv mod n: rand^-1 | 6847061636778138015219600315349409559... | 6847061636778138015219600315349409559... |  |
| PASS | field-p256 | is_zero(0) -> A | 0 | 0 |  |
| FAIL | field-p256 | is_zero(1) -> A | 255 | 1 |  |
| FAIL | field-p256 | is_zero(2^(8nb-1)) -> A | 255 | 128 |  |
| FAIL | field-p256 | is_zero(1<<8) -> A | 255 | 1 |  |
| PASS | field-p256 | is_zero(W) -> A | 255 | 255 |  |
| PASS | field-p256 | cmp a<b -> (C,Z) | [0, 0] | [0, 0] |  |
| FAIL | field-p256 | cmp a==b -> (C,Z) | [1, 1] | [1, 0] |  |
| PASS | field-p256 | cmp a>b -> (C,Z) | [1, 0] | [1, 0] |  |
| PASS | field-p256 | cmp p-1 vs p -> (C,Z) | [0, 0] | [0, 0] |  |
| FAIL | field-p256 | cmp p vs p -> (C,Z) | [1, 1] | [1, 0] |  |
| PASS | field-p256 | cmp p+1 vs p -> (C,Z) | [1, 0] | [1, 0] |  |
| PASS | field-p256 | cmp W vs 0 -> (C,Z) | [1, 0] | [1, 0] |  |
| PASS | field-p256 | cmp 0 vs W -> (C,Z) | [0, 0] | [0, 0] |  |
| FAIL | field-p256 | cmp n vs n -> (C,Z) | [1, 1] | [1, 0] |  |
| PASS | field-p256 | cmp n-1 vs n -> (C,Z) | [0, 0] | [0, 0] |  |
| PASS | field-p256 | cmp n+1 vs n -> (C,Z) | [1, 0] | [1, 0] |  |
| PASS | field-p256 | cmp hi-byte-only 1<<(8nb-8) vs 1 -> (C,Z) | [1, 0] | [1, 0] |  |
| PASS | field-p256 | cmp 1 vs 1<<(8nb-8) -> (C,Z) | [0, 0] | [0, 0] |  |
| PASS | point-p256 | point_add P(Z=1) + P  (must double) | [908884590630699600543914872455248187... | [908884590630699600543914872455248187... |  |
| PASS | point-p256 | point_add lift(P,z) + P  (H==0 with Z!=1) | [908884590630699600543914872455248187... | [908884590630699600543914872455248187... |  |
| PASS | point-p256 | point_add P + (-P) -> infinity | [None, None] | [None, None] |  |
| PASS | point-p256 | point_add P + (-P) -> infinity: Z==0 encoding | 0 | 0 |  |
| PASS | point-p256 | point_add lift(P,z) + (-P) -> infinity | [None, None] | [None, None] |  |
| PASS | point-p256 | point_add lift(P,z) + (-P) -> infinity: Z==0 encoding | 0 | 0 |  |
| PASS | point-p256 | point_add inf(Z=0,X=Y=garbage) + P -> P | [972689692036215313625623877878133811... | [972689692036215313625623877878133811... |  |
| PASS | point-p256 | point_add inf(all zero) + P -> P | [972689692036215313625623877878133811... | [972689692036215313625623877878133811... |  |
| PASS | point-p256 | point_add lift(P,z) + Q random | [790122327969264251158559114987552034... | [790122327969264251158559114987552034... |  |
| PASS | point-p256 | point_add P + G | [790122327969264251158559114987552034... | [790122327969264251158559114987552034... |  |
| PASS | point-p256 | point_add G + G (double via add) | [565152197906911714131090579040116886... | [565152197906911714131090579040116886... |  |
| PASS | point-p256 | point_double P Z=1 | [908884590630699600543914872455248187... | [908884590630699600543914872455248187... |  |
| PASS | point-p256 | point_double lift(P,z) | [908884590630699600543914872455248187... | [908884590630699600543914872455248187... |  |
| PASS | point-p256 | point_double Z=0 garbage -> infinity | [None, None] | [None, None] |  |
| PASS | point-p256 | point_double Z=0 all zero -> infinity | [None, None] | [None, None] |  |
| INFO | point-p256 | point_double X=Y=0,Z=1 (off-curve junk) (behaviour only) | n/a | ['0x9', '0x1b', '0x0'] |  |
| PASS | point-p256 | point_add_jj lift(P,z)+lift(P,z2) same point -> 2P | [908884590630699600543914872455248187... | [908884590630699600543914872455248187... |  |
| PASS | point-p256 | point_add_jj lift(P,z)+lift(-P,z2) -> inf | [None, None] | [None, None] |  |
| PASS | point-p256 | point_add_jj lift(P,z)+lift(G,z2) | [790122327969264251158559114987552034... | [790122327969264251158559114987552034... |  |
| PASS | point-p256 | point_add_jj P + inf(Z=0 garbage) -> P | [972689692036215313625623877878133811... | [972689692036215313625623877878133811... |  |
| PASS | point-p256 | point_add_jj inf(Z=0 garbage) + lift(P,z) -> P | [972689692036215313625623877878133811... | [972689692036215313625623877878133811... |  |
| PASS | point-p256 | scalar_mul_var k=n+1 -> P | [972689692036215313625623877878133811... | [972689692036215313625623877878133811... | 33.8 |
| PASS | point-p256 | scalar_mul_var k=n+2 -> 2P (mid-ladder R==P mixed add) | [908884590630699600543914872455248187... | [908884590630699600543914872455248187... | 33.6 |

### Primitives rerun (field/point both curves + hang probes; SHA skipped) — `prims.jsonl`

PASS=317 FAIL=0 INFO=26

| verdict | section | case | expected | got | s |
|---|---|---|---|---|---|
| PASS | field-p256 | mod_add (p-1)+(p-1) | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_add (p-1)+1 | 0 | 0 |  |
| PASS | field-p256 | mod_add 0+0 | 0 | 0 |  |
| PASS | field-p256 | mod_add a+a | 24691357802469135780 | 24691357802469135780 |  |
| PASS | field-p256 | mod_add NONRED p+0 | 0 | 0 |  |
| PASS | field-p256 | mod_add NONRED p+1 | 1 | 1 |  |
| INFO | field-p256 | mod_add NONRED (p+1)+(p-1) | 0 | 1157920892103562487626974469494075735... |  |
| INFO | field-p256 | mod_add NONRED W+W | 5391989332174707611856066864636768250... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_add NONRED W+0 | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_add NONRED W+1 | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_sub 0-(p-1) | 1 | 1 |  |
| PASS | field-p256 | mod_sub 0-1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_sub 1-1 | 0 | 0 |  |
| PASS | field-p256 | mod_sub (p-1)-(p-1) | 0 | 0 |  |
| INFO | field-p256 | mod_sub NONRED 1-W | 1157920891833963021018239088901272392... | 1157920892103562487626974469494075735... |  |
| INFO | field-p256 | mod_sub NONRED p-0 | 0 | 1157920892103562487626974469494075735... |  |
| INFO | field-p256 | mod_sub NONRED (p+1)-1 | 0 | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_sub NONRED W-W | 0 | 0 |  |
| INFO | field-p256 | mod_sub NONRED 0-W | 1157920891833963021018239088901272392... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_sub NONRED 0-p | 0 | 0 |  |
| PASS | field-p256 | mod_reduce 2^(2w)-1 | 1347997333231989955025617139070862921... | 1347997333231989955025617139070862921... |  |
| PASS | field-p256 | mod_reduce (p-1)^2 | 1 | 1 |  |
| PASS | field-p256 | mod_reduce p*(W) | 0 | 0 |  |
| PASS | field-p256 | mod_reduce W*W | 8087984000145191938400104526071860965... | 8087984000145191938400104526071860965... |  |
| PASS | field-p256 | mod_reduce p*p | 0 | 0 |  |
| PASS | field-p256 | mod_reduce p<<(8nb) | 0 | 0 |  |
| PASS | field-p256 | mod_reduce W<<(8nb) | 1078397866623254574432813795839024509... | 1078397866623254574432813795839024509... |  |
| PASS | field-p256 | mod_reduce p | 0 | 0 |  |
| PASS | field-p256 | mod_reduce p+1 | 1 | 1 |  |
| PASS | field-p256 | mod_reduce 2p | 0 | 0 |  |
| PASS | field-p256 | mod_reduce W | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_reduce p-1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_reduce limb0 all-ones | 4294967295 | 4294967295 |  |
| PASS | field-p256 | mod_reduce limb1 all-ones | 18446744069414584320 | 18446744069414584320 |  |
| PASS | field-p256 | mod_reduce limb2 all-ones | 79228162495817593519834398720 | 79228162495817593519834398720 |  |
| PASS | field-p256 | mod_reduce limb3 all-ones | 340282366841710300949110269838224261120 | 340282366841710300949110269838224261120 |  |
| PASS | field-p256 | mod_reduce limb4 all-ones | 1461501636990620551282746369252908412... | 1461501636990620551282746369252908412... |  |
| PASS | field-p256 | mod_reduce limb5 all-ones | 6277101733925179126504886505003981583... | 6277101733925179126504886505003981583... |  |
| PASS | field-p256 | mod_reduce limb6 all-ones | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_reduce limb7 all-ones | 1157920892103562487564203452140208927... | 1157920892103562487564203452140208927... |  |
| PASS | field-p256 | mod_reduce limb8 all-ones | 1157920891833963020955468071547405584... | 1157920891833963020955468071547405584... |  |
| PASS | field-p256 | mod_reduce limb9 all-ones | 1157920891833963021018239088886657375... | 1157920891833963021018239088886657375... |  |
| PASS | field-p256 | mod_reduce limb10 all-ones | 340282367079394788491903282614561144831 | 340282367079394788491903282614561144831 |  |
| PASS | field-p256 | mod_reduce limb11 all-ones | 1461501638011467652045561759624585490... | 1461501638011467652045561759624585490... |  |
| PASS | field-p256 | mod_reduce limb12 all-ones | 6277101738309684038497595259535807919... | 6277101738309684038497595259535807919... |  |
| PASS | field-p256 | mod_reduce limb13 all-ones | 2695994667970484326544037661435092715... | 2695994667970484326544037661435092715... |  |
| PASS | field-p256 | mod_reduce limb14 all-ones | 8087983999517481764715286285955191731... | 8087983999517481764715286285955191731... |  |
| PASS | field-p256 | mod_reduce limb15 all-ones | 5391989330919287264632580548102491836... | 5391989330919287264632580548102491836... |  |
| PASS | field-p256 | mod_reduce high limbs 8.. all ones | 1078397866623254574432813795839024509... | 1078397866623254574432813795839024509... |  |
| PASS | field-p256 | mod_reduce high limbs 9.. all ones | 1347997333294760972379483946712623639... | 1347997333294760972379483946712623639... |  |
| PASS | field-p256 | mod_reduce high limbs 10.. all ones | 1617596799903496352986902306317771081... | 1617596799903496352986902306317771081... |  |
| PASS | field-p256 | mod_reduce high limbs 11.. all ones | 1617596799903496352986902306314368257... | 1617596799903496352986902306314368257... |  |
| PASS | field-p256 | mod_reduce high limbs 12.. all ones | 1617596799903496352972287289934253580... | 1617596799903496352972287289934253580... |  |
| PASS | field-p256 | mod_reduce high limbs 13.. all ones | 1617596799840725335589190449549277628... | 1617596799840725335589190449549277628... |  |
| PASS | field-p256 | mod_reduce high limbs 14.. all ones | 1347997333043676902934786683405768356... | 1347997333043676902934786683405768356... |  |
| PASS | field-p256 | mod_reduce high limbs 15.. all ones | 5391989330919287264632580548102491836... | 5391989330919287264632580548102491836... |  |
| PASS | field-p256 | mod_reduce rand wide #0 | 2476977260025207712772493240415840339... | 2476977260025207712772493240415840339... |  |
| PASS | field-p256 | mod_reduce rand wide #1 | 3150598386438528308138279726854330880... | 3150598386438528308138279726854330880... |  |
| PASS | field-p256 | mod_reduce rand wide #2 | 7099108616744608182535951402318840625... | 7099108616744608182535951402318840625... |  |
| PASS | field-p256 | mod_reduce rand wide #3 | 1140563202522176072496648300836537606... | 1140563202522176072496648300836537606... |  |
| PASS | field-p256 | mod_mul (p-1)*(p-1) | 1 | 1 |  |
| PASS | field-p256 | mod_mul (p-1)*1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_mul 0*(p-1) | 0 | 0 |  |
| PASS | field-p256 | mod_mul rand*rand | 3581113452698235996677624580616139298... | 3581113452698235996677624580616139298... |  |
| PASS | field-p256 | mod_mul rand*(p-1) | 8979359606331721476621315302200280930... | 8979359606331721476621315302200280930... |  |
| PASS | field-p256 | mod_mul NONRED p*1 | 0 | 0 |  |
| PASS | field-p256 | mod_mul NONRED (p+1)*1 | 1 | 1 |  |
| PASS | field-p256 | mod_mul NONRED W*W | 8087984000145191938400104526071860965... | 8087984000145191938400104526071860965... |  |
| PASS | field-p256 | mod_mul NONRED W*1 | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p256 | mod_mul NONRED p*p | 0 | 0 |  |
| PASS | field-p256 | mod_mul NONRED W*(p-1) | 1157920891833963021018239088901272392... | 1157920891833963021018239088901272392... |  |
| PASS | field-p256 | mod_sqr rand | 8914004244862953680722876347690620308... | 8914004244862953680722876347690620308... |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency rand | 8914004244862953680722876347690620308... | 8914004244862953680722876347690620308... |  |
| PASS | field-p256 | mod_sqr p-1 | 1 | 1 |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency p-1 | 1 | 1 |  |
| PASS | field-p256 | mod_sqr 2^(8nb-1) | 8684406694146711990282283408769610862... | 8684406694146711990282283408769610862... |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency 2^(8nb-1) | 8684406694146711990282283408769610862... | 8684406694146711990282283408769610862... |  |
| PASS | field-p256 | mod_sqr NONRED W | 8087984000145191938400104526071860965... | 8087984000145191938400104526071860965... |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency NONRED W | 8087984000145191938400104526071860965... | 8087984000145191938400104526071860965... |  |
| PASS | field-p256 | mod_sqr NONRED p | 0 | 0 |  |
| PASS | field-p256 | mod_sqr vs mod_mul consistency NONRED p | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n (n-1)*(n-1) | 1 | 1 |  |
| PASS | field-p256 | mod_mul_n h=W * w<n (documented ok) | 1944073706429345811436425618639148806... | 1944073706429345811436425618639148806... |  |
| PASS | field-p256 | mod_mul_n h=n * w<n | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n h=n+1 * w<n | 1137739116287073475862706939932237305... | 1137739116287073475862706939932237305... |  |
| PASS | field-p256 | mod_mul_n h=p * w<n | 1052573429061445600808046007034533146... | 1052573429061445600808046007034533146... |  |
| PASS | field-p256 | mod_mul_n w<n * h=W (swapped) | 1944073706429345811436425618639148806... | 1944073706429345811436425618639148806... |  |
| PASS | field-p256 | mod_mul_n h=W * (n-1) | 1157920891833963021018239088901272392... | 1157920891833963021018239088901272392... |  |
| PASS | field-p256 | mod_mul_n n*1 | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n 1*n | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n n*0 | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n n * (n-1) | 0 | 0 |  |
| PASS | field-p256 | mod_mul_n UNDOC both>=n: n*n | 0 | 0 |  |
| INFO | field-p256 | mod_mul_n UNDOC both>=n: W*W | 4653376568548642097637396064859033011... | 5428031343339130993844007122839936175... |  |
| PASS | field-p256 | mod_mul_n UNDOC both>=n: (n+1)*(n+1) | 1 | 1 |  |
| INFO | field-p256 | mod_mul_n UNDOC both>=n: W*(n+1) | 2695994666087353805928033432327302944... | 1157920892373161954235709850086879078... |  |
| PASS | field-p256 | mod_inv p-1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_inv 2 | 5789604460517812438134872347470378676... | 5789604460517812438134872347470378676... |  |
| PASS | field-p256 | mod_inv 2^(8nb-1) | 1157920891564363554660587777636246181... | 1157920891564363554660587777636246181... |  |
| PASS | field-p256 | mod_inv rand | 9119731926695299112770431294060538602... | 9119731926695299112770431294060538602... |  |
| PASS | field-p256 | mod_inv mod n: (n-1)^-1 | 1157920892103562487626974469494075735... | 1157920892103562487626974469494075735... |  |
| PASS | field-p256 | mod_inv mod n: rand^-1 | 9204211589373368626099859728248355539... | 9204211589373368626099859728248355539... |  |
| PASS | field-p256 | is_zero(0) -> Z flag | 1 | 1 |  |
| PASS | field-p256 | is_zero(1) -> Z flag | 0 | 0 |  |
| PASS | field-p256 | is_zero(2^(8nb-1)) -> Z flag | 0 | 0 |  |
| PASS | field-p256 | is_zero(1<<8) -> Z flag | 0 | 0 |  |
| PASS | field-p256 | is_zero(W) -> Z flag | 0 | 0 |  |
| PASS | field-p256 | cmp a<b -> C | 0 | 0 |  |
| PASS | field-p256 | cmp a==b -> C | 1 | 1 |  |
| INFO | field-p256 | cmp a==b: documented 'Z=1 if equal' | 1 | 0 |  |
| PASS | field-p256 | cmp a>b -> C | 1 | 1 |  |
| PASS | field-p256 | cmp p-1 vs p -> C | 0 | 0 |  |
| PASS | field-p256 | cmp p vs p -> C | 1 | 1 |  |
| INFO | field-p256 | cmp p vs p: documented 'Z=1 if equal' | 1 | 0 |  |
| PASS | field-p256 | cmp p+1 vs p -> C | 1 | 1 |  |
| PASS | field-p256 | cmp W vs 0 -> C | 1 | 1 |  |
| PASS | field-p256 | cmp 0 vs W -> C | 0 | 0 |  |
| PASS | field-p256 | cmp n vs n -> C | 1 | 1 |  |
| INFO | field-p256 | cmp n vs n: documented 'Z=1 if equal' | 1 | 0 |  |
| PASS | field-p256 | cmp n-1 vs n -> C | 0 | 0 |  |
| PASS | field-p256 | cmp n+1 vs n -> C | 1 | 1 |  |
| PASS | field-p256 | cmp hi-byte-only 1<<(8nb-8) vs 1 -> C | 1 | 1 |  |
| PASS | field-p256 | cmp 1 vs 1<<(8nb-8) -> C | 0 | 0 |  |
| PASS | point-p256 | point_add P(Z=1) + P  (must double) | [401194641335532002002480026877397771... | [401194641335532002002480026877397771... |  |
| PASS | point-p256 | point_add lift(P,z) + P  (H==0 with Z!=1) | [401194641335532002002480026877397771... | [401194641335532002002480026877397771... |  |
| PASS | point-p256 | point_add P + (-P) -> infinity | [None, None] | [None, None] |  |
| PASS | point-p256 | point_add P + (-P) -> infinity: Z==0 encoding | 0 | 0 |  |
| PASS | point-p256 | point_add lift(P,z) + (-P) -> infinity | [None, None] | [None, None] |  |
| PASS | point-p256 | point_add lift(P,z) + (-P) -> infinity: Z==0 encoding | 0 | 0 |  |
| PASS | point-p256 | point_add inf(Z=0,X=Y=garbage) + P -> P | [449255611889299915765708363542519289... | [449255611889299915765708363542519289... |  |
| PASS | point-p256 | point_add inf(all zero) + P -> P | [449255611889299915765708363542519289... | [449255611889299915765708363542519289... |  |
| PASS | point-p256 | point_add lift(P,z) + Q random | [867854586415569744414969836361310936... | [867854586415569744414969836361310936... |  |
| PASS | point-p256 | point_add P + G | [867854586415569744414969836361310936... | [867854586415569744414969836361310936... |  |
| PASS | point-p256 | point_add G + G (double via add) | [565152197906911714131090579040116886... | [565152197906911714131090579040116886... |  |
| PASS | point-p256 | point_double P Z=1 | [401194641335532002002480026877397771... | [401194641335532002002480026877397771... |  |
| PASS | point-p256 | point_double lift(P,z) | [401194641335532002002480026877397771... | [401194641335532002002480026877397771... |  |
| PASS | point-p256 | point_double Z=0 garbage -> infinity | [None, None] | [None, None] |  |
| PASS | point-p256 | point_double Z=0 all zero -> infinity | [None, None] | [None, None] |  |
| INFO | point-p256 | point_double X=Y=0,Z=1 (off-curve junk) (behaviour only) | n/a | ['0x9', '0x1b', '0x0'] |  |
| PASS | point-p256 | point_add_jj lift(P,z)+lift(P,z2) same point -> 2P | [401194641335532002002480026877397771... | [401194641335532002002480026877397771... |  |
| PASS | point-p256 | point_add_jj lift(P,z)+lift(-P,z2) -> inf | [None, None] | [None, None] |  |
| PASS | point-p256 | point_add_jj lift(P,z)+lift(G,z2) | [867854586415569744414969836361310936... | [867854586415569744414969836361310936... |  |
| PASS | point-p256 | point_add_jj P + inf(Z=0 garbage) -> P | [449255611889299915765708363542519289... | [449255611889299915765708363542519289... |  |
| PASS | point-p256 | point_add_jj inf(Z=0 garbage) + lift(P,z) -> P | [449255611889299915765708363542519289... | [449255611889299915765708363542519289... |  |
| PASS | point-p256 | scalar_mul_var k=n+1 -> P | [449255611889299915765708363542519289... | [449255611889299915765708363542519289... | 31.8 |
| PASS | point-p256 | scalar_mul_var k=n+2 -> 2P (mid-ladder R==P mixed add) | [401194641335532002002480026877397771... | [401194641335532002002480026877397771... | 32.1 |
| PASS | point-p256 | scalar_mul_var k=2^(8nb)-1 | [115485094786085501542723711052915084... | [115485094786085501542723711052915084... | 39.8 |
| PASS | point-p256 | scalar_mul_var k=2^(8nb-1) (top bit only) | [103110071509792813208131952770078010... | [103110071509792813208131952770078010... | 16.7 |
| PASS | point-p256 | scalar_mul_var k=(n-1)/2 | [150030138024994496659493197823496383... | [150030138024994496659493197823496383... | 31.3 |
| PASS | point-p256 | scalar_mul_var k=(n+1)/2 | [150030138024994496659493197823496383... | [150030138024994496659493197823496383... | 31.6 |
| PASS | point-p256 | scalar_mul_var k=n-2 | [401194641335532002002480026877397771... | [401194641335532002002480026877397771... | 31.8 |
| INFO | point-p256 | scalar_mul_var k=2, base=(0,0) off-curve (behaviour) | n/a | ['0x9', '0x1b', '0x0'] |  |
| PASS | point-p256 | scalar_mul_var k=n-1, base=-G -> G | [484395612939064517590525852527979142... | [484395612939064517590525852527979142... |  |
| PASS | point-p256 | scalar_mul(comb) k=0 -> inf | [None, None] | [None, None] | 0.0 |
| PASS | point-p256 | scalar_mul(comb) k=0 -> inf: Z==0 encoding | 0 | 0 |  |
| PASS | point-p256 | scalar_mul(comb) k=1 -> G | [484395612939064517590525852527979142... | [484395612939064517590525852527979142... | 0.0 |
| PASS | point-p256 | scalar_mul(comb) k=n -> inf | [None, None] | [None, None] | 4.8 |
| PASS | point-p256 | scalar_mul(comb) k=n -> inf: Z==0 encoding | 0 | 0 |  |
| PASS | point-p256 | scalar_mul(comb) k=n-1 -> -G | [484395612939064517590525852527979142... | [484395612939064517590525852527979142... | 4.9 |
| PASS | point-p256 | scalar_mul(comb) k=n+1 -> G | [484395612939064517590525852527979142... | [484395612939064517590525852527979142... | 4.9 |
| PASS | point-p256 | scalar_mul(comb) k=2^(8nb)-1 | [111800320273024984500305388361104400... | [111800320273024984500305388361104400... | 4.8 |
| PASS | point-p256 | scalar_mul(comb) k=2^(8nb-1) | [541398006904834262973019526314379251... | [541398006904834262973019526314379251... | 2.0 |
| PASS | point-p256 | scalar_mul(comb) k=all sub-scalars K_i=1 (idx 255 at col 0) | [990352353677715418842257070019526801... | [990352353677715418842257070019526801... | 0.0 |
| PASS | point-p256 | scalar_mul(comb) k=all sub-scalars top bit (idx 255 at col 31) | [107749152069818254120148356809617270... | [107749152069818254120148356809617270... | 2.1 |
| PASS | point-p256 | scalar_mul(comb) k=2^32-1 (K0 all ones) | [441082791910206722696765243844723901... | [441082791910206722696765243844723901... | 4.9 |
| PASS | point-p256 | scalar_mul(comb) k=(2^32-1)<<(8nb-32) (top limb all ones) | [174032861540028004358466987867521692... | [174032861540028004358466987867521692... | 4.9 |
| PASS | point-p256 | scalar_mul(comb) k=2 -> 2G | [565152197906911714131090579040116886... | [565152197906911714131090579040116886... | 0.1 |
| PASS | point-p256 | scalar_mul(comb) k=2^32 -> A2 | [578455462845191377598680718795808647... | [578455462845191377598680718795808647... | 0.0 |
| PASS | point-p256 | comb vs var-base agree on random k (and vs hazmat) | [592183151002403596661865135499720422... | [592183151002403596661865135499720422... |  |
| PASS | point-p256 | var-base(G) vs hazmat on same k | [592183151002403596661865135499720422... | [592183151002403596661865135499720422... |  |
| PASS | field-p384 | mod_add (p-1)+(p-1) | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_add (p-1)+1 | 0 | 0 |  |
| PASS | field-p384 | mod_add 0+0 | 0 | 0 |  |
| PASS | field-p384 | mod_add a+a | 24691357802469135780 | 24691357802469135780 |  |
| PASS | field-p384 | mod_add NONRED p+0 | 0 | 0 |  |
| PASS | field-p384 | mod_add NONRED p+1 | 1 | 1 |  |
| INFO | field-p384 | mod_add NONRED (p+1)+(p-1) | 0 | 3940200619639447921227904010014361380... |  |
| INFO | field-p384 | mod_add NONRED W+W | 680564734000333251955277890042034388992 | 340282367000166625977638945021017194495 |  |
| PASS | field-p384 | mod_add NONRED W+0 | 340282367000166625977638945021017194496 | 340282367000166625977638945021017194496 |  |
| PASS | field-p384 | mod_add NONRED W+1 | 340282367000166625977638945021017194497 | 340282367000166625977638945021017194497 |  |
| PASS | field-p384 | mod_sub 0-(p-1) | 1 | 1 |  |
| PASS | field-p384 | mod_sub 0-1 | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_sub 1-1 | 0 | 0 |  |
| PASS | field-p384 | mod_sub (p-1)-(p-1) | 0 | 0 |  |
| INFO | field-p384 | mod_sub NONRED 1-W | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| INFO | field-p384 | mod_sub NONRED p-0 | 0 | 3940200619639447921227904010014361380... |  |
| INFO | field-p384 | mod_sub NONRED (p+1)-1 | 0 | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_sub NONRED W-W | 0 | 0 |  |
| INFO | field-p384 | mod_sub NONRED 0-W | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_sub NONRED 0-p | 0 | 0 |  |
| PASS | field-p384 | mod_reduce 2^(2w)-1 | 1157920892912360887641493663304856155... | 1157920892912360887641493663304856155... |  |
| PASS | field-p384 | mod_reduce (p-1)^2 | 1 | 1 |  |
| PASS | field-p384 | mod_reduce p*(W) | 0 | 0 |  |
| PASS | field-p384 | mod_reduce W*W | 1157920892912360887641493663304856155... | 1157920892912360887641493663304856155... |  |
| PASS | field-p384 | mod_reduce p*p | 0 | 0 |  |
| PASS | field-p384 | mod_reduce p<<(8nb) | 0 | 0 |  |
| PASS | field-p384 | mod_reduce W<<(8nb) | 1157920892912360887641493663304856155... | 1157920892912360887641493663304856155... |  |
| PASS | field-p384 | mod_reduce p | 0 | 0 |  |
| PASS | field-p384 | mod_reduce p+1 | 1 | 1 |  |
| PASS | field-p384 | mod_reduce 2p | 0 | 0 |  |
| PASS | field-p384 | mod_reduce W | 340282367000166625977638945021017194496 | 340282367000166625977638945021017194496 |  |
| PASS | field-p384 | mod_reduce p-1 | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_reduce limb0 all-ones | 4294967295 | 4294967295 |  |
| PASS | field-p384 | mod_reduce limb1 all-ones | 18446744069414584320 | 18446744069414584320 |  |
| PASS | field-p384 | mod_reduce limb2 all-ones | 79228162495817593519834398720 | 79228162495817593519834398720 |  |
| PASS | field-p384 | mod_reduce limb3 all-ones | 340282366841710300949110269838224261120 | 340282366841710300949110269838224261120 |  |
| PASS | field-p384 | mod_reduce limb4 all-ones | 1461501636990620551282746369252908412... | 1461501636990620551282746369252908412... |  |
| PASS | field-p384 | mod_reduce limb5 all-ones | 6277101733925179126504886505003981583... | 6277101733925179126504886505003981583... |  |
| PASS | field-p384 | mod_reduce limb6 all-ones | 2695994666087353805928033432318384125... | 2695994666087353805928033432318384125... |  |
| PASS | field-p384 | mod_reduce limb7 all-ones | 1157920892103562487564203452140208927... | 1157920892103562487564203452140208927... |  |
| PASS | field-p384 | mod_reduce limb8 all-ones | 4973232362939945529180660527232498550... | 4973232362939945529180660527232498550... |  |
| PASS | field-p384 | mod_reduce limb9 all-ones | 2135987035423586845985235064014169866... | 2135987035423586845985235064014169866... |  |
| PASS | field-p384 | mod_reduce limb10 all-ones | 9173994461824299010522373498813326057... | 9173994461824299010522373498813326057... |  |
| PASS | field-p384 | mod_reduce limb11 all-ones | 3940200618722048474831875405370033022... | 3940200618722048474831875405370033022... |  |
| PASS | field-p384 | mod_reduce limb12 all-ones | 1461501637330902918124456670183571937... | 1461501637330902918124456670183571937... |  |
| PASS | field-p384 | mod_reduce limb13 all-ones | 6277101735386680763495507056207499790... | 6277101735386680763495507056207499790... |  |
| PASS | field-p384 | mod_reduce limb14 all-ones | 2695994666715063979320551344934844538... | 2695994666715063979320551344934844538... |  |
| PASS | field-p384 | mod_reduce limb15 all-ones | 1157920892373161954172938832718397254... | 1157920892373161954172938832718397254... |  |
| PASS | field-p384 | mod_reduce limb16 all-ones | 4973232364097866421284223014733930985... | 4973232364097866421284223014733930985... |  |
| PASS | field-p384 | mod_reduce limb17 all-ones | 2135987035920910082279229616905275972... | 2135987035920910082279229616905275972... |  |
| PASS | field-p384 | mod_reduce limb18 all-ones | 9173994463960286045945960344682769031... | 9173994463960286045945960344682769031... |  |
| PASS | field-p384 | mod_reduce limb19 all-ones | 3940200619639447921014305306372538048... | 3940200619639447921014305306372538048... |  |
| PASS | field-p384 | mod_reduce limb20 all-ones | 3940200618722048474618276701877406661... | 3940200618722048474618276701877406661... |  |
| PASS | field-p384 | mod_reduce limb21 all-ones | 3940200618722048475259072812504482715... | 3940200618722048475259072812504482715... |  |
| PASS | field-p384 | mod_reduce limb22 all-ones | 1834798892578458505696565708002167382... | 1834798892578458505696565708002167382... |  |
| PASS | field-p384 | mod_reduce limb23 all-ones | 3940200618722048474831875405370033022... | 3940200618722048474831875405370033022... |  |
| PASS | field-p384 | mod_reduce high limbs 12.. all ones | 1157920892912360887641493663304856155... | 1157920892912360887641493663304856155... |  |
| PASS | field-p384 | mod_reduce high limbs 13.. all ones | 1157920892912360887641493663290241138... | 1157920892912360887641493663290241138... |  |
| PASS | field-p384 | mod_reduce high limbs 14.. all ones | 1157920892912360887578722645936374331... | 1157920892912360887578722645936374331... |  |
| PASS | field-p384 | mod_reduce high limbs 15.. all ones | 1157920892642761420907216248004319196... | 1157920892642761420907216248004319196... |  |
| PASS | field-p384 | mod_reduce high limbs 16.. all ones | 2695994667342774152859219421318423481... | 2695994667342774152859219421318423481... |  |
| PASS | field-p384 | mod_reduce high limbs 17.. all ones | 3940200619639447921227904009964629056... | 3940200619639447921227904009964629056... |  |
| PASS | field-p384 | mod_reduce high limbs 18.. all ones | 3940200619639447921014305306372538048... | 3940200619639447921014305306372538048... |  |
| PASS | field-p384 | mod_reduce high limbs 19.. all ones | 3940200618722048474618276701777942014... | 3940200618722048474618276701777942014... |  |
| PASS | field-p384 | mod_reduce high limbs 20.. all ones | 3940200618722048474831875405419765346... | 3940200618722048474831875405419765346... |  |
| PASS | field-p384 | mod_reduce high limbs 21.. all ones | 2135987035423586846101027153305405955... | 2135987035423586846101027153305405955... |  |
| PASS | field-p384 | mod_reduce high limbs 22.. all ones | 9173994461824299010522373498929118146... | 9173994461824299010522373498929118146... |  |
| PASS | field-p384 | mod_reduce high limbs 23.. all ones | 3940200618722048474831875405370033022... | 3940200618722048474831875405370033022... |  |
| PASS | field-p384 | mod_reduce rand wide #0 | 2142059251525262828879693146642431696... | 2142059251525262828879693146642431696... |  |
| PASS | field-p384 | mod_reduce rand wide #1 | 2966465520567455029024699625000935481... | 2966465520567455029024699625000935481... |  |
| PASS | field-p384 | mod_reduce rand wide #2 | 1582836072607979911288880085156055652... | 1582836072607979911288880085156055652... |  |
| PASS | field-p384 | mod_reduce rand wide #3 | 1535683101054621669583543792451123611... | 1535683101054621669583543792451123611... |  |
| PASS | field-p384 | mod_mul (p-1)*(p-1) | 1 | 1 |  |
| PASS | field-p384 | mod_mul (p-1)*1 | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_mul 0*(p-1) | 0 | 0 |  |
| PASS | field-p384 | mod_mul rand*rand | 1163986235053289584051751601403352718... | 1163986235053289584051751601403352718... |  |
| PASS | field-p384 | mod_mul rand*(p-1) | 4842042784847178441700921900825416339... | 4842042784847178441700921900825416339... |  |
| PASS | field-p384 | mod_mul NONRED p*1 | 0 | 0 |  |
| PASS | field-p384 | mod_mul NONRED (p+1)*1 | 1 | 1 |  |
| PASS | field-p384 | mod_mul NONRED W*W | 1157920892912360887641493663304856155... | 1157920892912360887641493663304856155... |  |
| PASS | field-p384 | mod_mul NONRED W*1 | 340282367000166625977638945021017194496 | 340282367000166625977638945021017194496 |  |
| PASS | field-p384 | mod_mul NONRED p*p | 0 | 0 |  |
| PASS | field-p384 | mod_mul NONRED W*(p-1) | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_sqr rand | 8562314772327011175594110103253694460... | 8562314772327011175594110103253694460... |  |
| PASS | field-p384 | mod_sqr vs mod_mul consistency rand | 8562314772327011175594110103253694460... | 8562314772327011175594110103253694460... |  |
| PASS | field-p384 | mod_sqr p-1 | 1 | 1 |  |
| PASS | field-p384 | mod_sqr vs mod_mul consistency p-1 | 1 | 1 |  |
| PASS | field-p384 | mod_sqr 2^(8nb-1) | 9850501549098619803069760025035903451... | 9850501549098619803069760025035903451... |  |
| PASS | field-p384 | mod_sqr vs mod_mul consistency 2^(8nb-1) | 9850501549098619803069760025035903451... | 9850501549098619803069760025035903451... |  |
| PASS | field-p384 | mod_sqr NONRED W | 1157920892912360887641493663304856155... | 1157920892912360887641493663304856155... |  |
| PASS | field-p384 | mod_sqr vs mod_mul consistency NONRED W | 1157920892912360887641493663304856155... | 1157920892912360887641493663304856155... |  |
| PASS | field-p384 | mod_sqr NONRED p | 0 | 0 |  |
| PASS | field-p384 | mod_sqr vs mod_mul consistency NONRED p | 0 | 0 |  |
| PASS | field-p384 | mod_mul_n (n-1)*(n-1) | 1 | 1 |  |
| PASS | field-p384 | mod_mul_n h=W * w<n (documented ok) | 2142079529459993888120833847161875853... | 2142079529459993888120833847161875853... |  |
| PASS | field-p384 | mod_mul_n h=n * w<n | 0 | 0 |  |
| PASS | field-p384 | mod_mul_n h=n+1 * w<n | 3937037453546634976682332752687255336... | 3937037453546634976682332752687255336... |  |
| PASS | field-p384 | mod_mul_n h=p * w<n | 5670087148763555766452260363120148418... | 5670087148763555766452260363120148418... |  |
| PASS | field-p384 | mod_mul_n w<n * h=W (swapped) | 2142079529459993888120833847161875853... | 2142079529459993888120833847161875853... |  |
| PASS | field-p384 | mod_mul_n h=W * (n-1) | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_mul_n n*1 | 0 | 0 |  |
| PASS | field-p384 | mod_mul_n 1*n | 0 | 0 |  |
| PASS | field-p384 | mod_mul_n n*0 | 0 | 0 |  |
| PASS | field-p384 | mod_mul_n n * (n-1) | 0 | 0 |  |
| PASS | field-p384 | mod_mul_n UNDOC both>=n: n*n | 0 | 0 |  |
| INFO | field-p384 | mod_mul_n UNDOC both>=n: W*W | 1926889955270807207284364373743377144... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_mul_n UNDOC both>=n: (n+1)*(n+1) | 1 | 1 |  |
| INFO | field-p384 | mod_mul_n UNDOC both>=n: W*(n+1) | 1388124618062372383947042015309946732... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_inv p-1 | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_inv 2 | 1970100309819723960613952005007180690... | 1970100309819723960613952005007180690... |  |
| PASS | field-p384 | mod_inv 2^(8nb-1) | 3669597786438509233065035042186644107... | 3669597786438509233065035042186644107... |  |
| PASS | field-p384 | mod_inv rand | 1731387064178237921826157970172383441... | 1731387064178237921826157970172383441... |  |
| PASS | field-p384 | mod_inv mod n: (n-1)^-1 | 3940200619639447921227904010014361380... | 3940200619639447921227904010014361380... |  |
| PASS | field-p384 | mod_inv mod n: rand^-1 | 3732283584116762514484793940925571340... | 3732283584116762514484793940925571340... |  |
| PASS | field-p384 | is_zero(0) -> Z flag | 1 | 1 |  |
| PASS | field-p384 | is_zero(1) -> Z flag | 0 | 0 |  |
| PASS | field-p384 | is_zero(2^(8nb-1)) -> Z flag | 0 | 0 |  |
| PASS | field-p384 | is_zero(1<<8) -> Z flag | 0 | 0 |  |
| PASS | field-p384 | is_zero(W) -> Z flag | 0 | 0 |  |
| PASS | field-p384 | cmp a<b -> C | 0 | 0 |  |
| PASS | field-p384 | cmp a==b -> C | 1 | 1 |  |
| INFO | field-p384 | cmp a==b: documented 'Z=1 if equal' | 1 | 0 |  |
| PASS | field-p384 | cmp a>b -> C | 1 | 1 |  |
| PASS | field-p384 | cmp p-1 vs p -> C | 0 | 0 |  |
| PASS | field-p384 | cmp p vs p -> C | 1 | 1 |  |
| INFO | field-p384 | cmp p vs p: documented 'Z=1 if equal' | 1 | 0 |  |
| PASS | field-p384 | cmp p+1 vs p -> C | 1 | 1 |  |
| PASS | field-p384 | cmp W vs 0 -> C | 1 | 1 |  |
| PASS | field-p384 | cmp 0 vs W -> C | 0 | 0 |  |
| PASS | field-p384 | cmp n vs n -> C | 1 | 1 |  |
| INFO | field-p384 | cmp n vs n: documented 'Z=1 if equal' | 1 | 0 |  |
| PASS | field-p384 | cmp n-1 vs n -> C | 0 | 0 |  |
| PASS | field-p384 | cmp n+1 vs n -> C | 1 | 1 |  |
| PASS | field-p384 | cmp hi-byte-only 1<<(8nb-8) vs 1 -> C | 1 | 1 |  |
| PASS | field-p384 | cmp 1 vs 1<<(8nb-8) -> C | 0 | 0 |  |
| PASS | point-p384 | point_add P(Z=1) + P  (must double) | [148771834061775352652192971875997896... | [148771834061775352652192971875997896... |  |
| PASS | point-p384 | point_add lift(P,z) + P  (H==0 with Z!=1) | [148771834061775352652192971875997896... | [148771834061775352652192971875997896... |  |
| PASS | point-p384 | point_add P + (-P) -> infinity | [None, None] | [None, None] |  |
| PASS | point-p384 | point_add P + (-P) -> infinity: Z==0 encoding | 0 | 0 |  |
| PASS | point-p384 | point_add lift(P,z) + (-P) -> infinity | [None, None] | [None, None] |  |
| PASS | point-p384 | point_add lift(P,z) + (-P) -> infinity: Z==0 encoding | 0 | 0 |  |
| PASS | point-p384 | point_add inf(Z=0,X=Y=garbage) + P -> P | [364601580488240219188648103780369026... | [364601580488240219188648103780369026... |  |
| PASS | point-p384 | point_add inf(all zero) + P -> P | [364601580488240219188648103780369026... | [364601580488240219188648103780369026... |  |
| PASS | point-p384 | point_add lift(P,z) + Q random | [621440388644964419527109040559434943... | [621440388644964419527109040559434943... |  |
| PASS | point-p384 | point_add P + G | [621440388644964419527109040559434943... | [621440388644964419527109040559434943... |  |
| PASS | point-p384 | point_add G + G (double via add) | [136213830851146652236115370699992493... | [136213830851146652236115370699992493... |  |
| PASS | point-p384 | point_double P Z=1 | [148771834061775352652192971875997896... | [148771834061775352652192971875997896... |  |
| PASS | point-p384 | point_double lift(P,z) | [148771834061775352652192971875997896... | [148771834061775352652192971875997896... |  |
| PASS | point-p384 | point_double Z=0 garbage -> infinity | [None, None] | [None, None] |  |
| PASS | point-p384 | point_double Z=0 all zero -> infinity | [None, None] | [None, None] |  |
| INFO | point-p384 | point_double X=Y=0,Z=1 (off-curve junk) (behaviour only) | n/a | ['0x9', '0x1b', '0x0'] |  |
| PASS | point-p384 | point_add_jj lift(P,z)+lift(P,z2) same point -> 2P | [148771834061775352652192971875997896... | [148771834061775352652192971875997896... |  |
| PASS | point-p384 | point_add_jj lift(P,z)+lift(-P,z2) -> inf | [None, None] | [None, None] |  |
| PASS | point-p384 | point_add_jj lift(P,z)+lift(G,z2) | [621440388644964419527109040559434943... | [621440388644964419527109040559434943... |  |
| PASS | point-p384 | point_add_jj P + inf(Z=0 garbage) -> P | [364601580488240219188648103780369026... | [364601580488240219188648103780369026... |  |
| PASS | point-p384 | point_add_jj inf(Z=0 garbage) + lift(P,z) -> P | [364601580488240219188648103780369026... | [364601580488240219188648103780369026... |  |
| PASS | point-p384 | scalar_mul_var k=n+1 -> P | [364601580488240219188648103780369026... | [364601580488240219188648103780369026... | 95.0 |
| PASS | point-p384 | scalar_mul_var k=n+2 -> 2P (mid-ladder R==P mixed add) | [148771834061775352652192971875997896... | [148771834061775352652192971875997896... | 95.4 |
| PASS | point-p384 | scalar_mul_var k=2^(8nb)-1 | [341994135531513169684707920493730041... | [341994135531513169684707920493730041... | 109.6 |
| PASS | point-p384 | scalar_mul_var k=2^(8nb-1) (top bit only) | [388658563251981650514082836158948328... | [388658563251981650514082836158948328... | 43.6 |
| INFO | point-p384 | scalar_mul_var k=2, base=(0,0) off-curve (behaviour) | n/a | ['0x9', '0x1b', '0x0'] |  |
| PASS | point-p384 | scalar_mul_var k=n-1, base=-G -> G | [262470350957996892686231567445669818... | [262470350957996892686231567445669818... |  |
| PASS | point-p384 | scalar_mul(comb) k=0 -> inf | [None, None] | [None, None] | 0.0 |
| PASS | point-p384 | scalar_mul(comb) k=0 -> inf: Z==0 encoding | 0 | 0 |  |
| PASS | point-p384 | scalar_mul(comb) k=1 -> G | [262470350957996892686231567445669818... | [262470350957996892686231567445669818... | 0.0 |
| PASS | point-p384 | scalar_mul(comb) k=n -> inf | [None, None] | [None, None] | 12.8 |
| PASS | point-p384 | scalar_mul(comb) k=n -> inf: Z==0 encoding | 0 | 0 |  |
| PASS | point-p384 | scalar_mul(comb) k=n-1 -> -G | [262470350957996892686231567445669818... | [262470350957996892686231567445669818... | 13.0 |
| PASS | point-p384 | scalar_mul(comb) k=n+1 -> G | [262470350957996892686231567445669818... | [262470350957996892686231567445669818... | 13.0 |
| PASS | point-p384 | scalar_mul(comb) k=2^(8nb)-1 | [218859933985726025933999190612080809... | [218859933985726025933999190612080809... | 12.9 |
| PASS | point-p384 | scalar_mul(comb) k=2^(8nb-1) | [350745930374392076903908386689782533... | [350745930374392076903908386689782533... | 5.4 |
| PASS | point-p384 | comb vs var-base agree on random k (and vs hazmat) | [272339934318252017450388723322521515... | [272339934318252017450388723322521515... |  |
| PASS | point-p384 | var-base(G) vs hazmat on same k | [272339934318252017450388723322521515... | [272339934318252017450388723322521515... |  |
