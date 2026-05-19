# A4 Call-Graph: Static jsr counts per public entry point

Agent A4 deliverable. Per-invocation static counts of primitive `jsr`s under
each public top-level entry point, plus a rolled-up matrix and a predicted-vs-
measured cycle worksheet. All counts derived by reading the source bodies and
grepping `jsr ` mnemonics in the relevant line ranges.

For modular field op cost conventions used downstream of the entry point:
- `ec_mulp` (`src/mod256.s:958`) = `ec_set_modp` + `fp_mod_mul` + result copy.
- `ec_sqrp` (`src/mod256.s:963`) = `ec_set_modp` + `fp_mod_sqr` + result copy.
- `fp_mod_mul` (`src/mod256.s:600`) = `fp_mul` + `fp_mod_reduce256`.
- `fp_mod_sqr` (`src/mod256.s:691`) = `fp_sqr` + `fp_mod_reduce256`.
- `fp_mod_mul_n` (`src/mod256.s:618`) = `fp_mul` + bit-serial 256-iteration
  reduction (NOT the cheap Solinas reduction; ~5-10x slower than `fp_mod_mul`
  in expectation; no primitive cycle row in README so flagged as ~estimate).
- `fp_mod_inv` (`src/mod256.s:700`) takes its modulus from `fp_misc`; called
  after `ec_set_modn` it computes mod-n inversion (used once in ECDSA verify
  for `w = s^-1 mod n`); called after `ec_set_modp` it would compute mod-p
  inversion (no longer reached by ECDSA verify since PR #26 cofactor compare
  + PR #34 J+J at the join eliminated the final `ec_jacobian_to_affine`).
- The 384-suffixed variants follow the same dispatch tree against
  `fp_mod_mul_384` / `fp_mod_sqr_384` / `fp_mul_384` / `fp_sqr_384` /
  `fp_mod_reduce384` / `fp_mod_inv_384`.

In the per-entry-point tables below the **primitive count column** is the
count of jsr invocations of the named routine *at the source-text level
inside the function body*. Calls through `ec_mulp` / `ec_sqrp` etc. are
tracked at the wrapper level; the lower-level expansion is reconciled in
the rolled-up matrix and in the worksheet.

---

## 1. Per-entry-point breakdowns

### 1.1 `ec_point_double` (P-256)

- Source: `src/points256.s:60-409` (function body lines 60-409, generic
  branch from line 77 onward).
- No internal loop.
- Two branches: (a) Z1=0 (infinity) returns early after `fp_is_zero` — 0
  field-op jsrs; (b) generic (Z1!=0) executes the full doubling formula
  with 4M+4S+12 lin. The branch table below reports (b), which is the
  case the bench primitive measures.

Per-invocation jsr table (generic path, lines 77-409):

| Callee                      | Count | Notes |
|-----------------------------|------:|-------|
| `fp_is_zero`                | 1     | Z1=0 fast-path test (early-return branch not taken in generic case) |
| `ec_set_modp`               | 1     | One-time modulus selector at body entry |
| `ec_mulp`                   | 4     | 4 mod-p multiplies |
| `ec_sqrp`                   | 4     | 4 mod-p squarings (S=4) |
| `fp_mod_add`                | 8     | 8 modular additions |
| `fp_mod_sub`                | 4     | 4 modular subtractions |

a=-3 short-Weierstrass form: standalone 4M+4S as documented in CLAUDE.md
"Negative findings → CMO98 / Fay".

### 1.2 `ec_point_add` (P-256, mixed Jacobian+affine)

- Source: `src/points256.s:422-760`.
- Branches: (a) P1=infinity → copy P2 to P3 and set Z=1, 1 `fp_is_zero` call,
  no field ops; (b) H=0,R=0 → tail-call to `ec_point_double` (not counted as
  a primitive op here since it dispatches into the double formula); (c)
  H=0,R!=0 → zero ec_p3, no field ops; (d) generic (H!=0) — the formula
  body. Generic case below.

Per-invocation jsr table (generic H!=0 path, lines 456-760):

| Callee                      | Count | Notes |
|-----------------------------|------:|-------|
| `fp_is_zero`                | 3     | P1-inf check + H test + R test |
| `ec_set_modp`               | 1     |   |
| `ec_mulp`                   | 7     | 7M (incl. Z3 = H*Z1, S2=Y2*Z^3, U2=X2*Z^2, etc.) |
| `ec_sqrp`                   | 3     | 3S (Z^2, H^2, R^2) |
| `fp_mod_add`                | 1     | 2*X1*H^2 |
| `fp_mod_sub`                | 5     | H, R, X3 (twice in chain), Y3, t3=X1H^2-X3 |

Mixed add count matches the 7M+4S claim in CLAUDE.md "Jacobian addition
naming" (4S vs 3S discrepancy: one of the four "squarings" is the
`fp_is_zero` Z^2 test? No — re-counted: `ec_sqrp` lines 472, 591, 637 are
the only three `ec_sqrp` calls. So the formula is 7M + 3S + 1A + 5sub. The
CLAUDE.md 7M+4S note appears to fold Z^2 from the first `ec_sqrp` into a
"squaring" abstraction in the doc; static count is unambiguous).

### 1.3 `ec_point_add_jj` (P-256, full Jacobian+Jacobian)

- Source: `src/points256.s:800-1286`.
- Branches: (a) P1=infinity → 96-byte copy P2→P3, 1 fp_is_zero, no field
  ops; (b) P2=infinity → 96-byte copy P1→P3, 2 fp_is_zero; (c) H=0,r=0 →
  tail-call ec_point_double on P1; (d) H=0,r!=0 → zero ec_p3, 4
  fp_is_zero, 2 mul + 2 sqr + 2 sub already issued before infinity store;
  (e) generic (H!=0). Generic case is what the verify-time J+J join hits.

Per-invocation jsr table (generic H!=0 path, lines 835-1284):

| Callee                      | Count | Notes |
|-----------------------------|------:|-------|
| `fp_is_zero`                | 4     | P1-inf, P2-inf, H-zero, r-zero tests |
| `ec_set_modp`               | 1     |   |
| `ec_mulp`                   | 11    | 11M (Bernstein-Lange add-2007-bl) |
| `ec_sqrp`                   | 5     | 5S |
| `fp_mod_add`                | 5     | 2*S2-S1, (Z1+Z2), 2H, 2V, 2*S1*J |
| `fp_mod_sub`                | 8     | H=U2-U1, S2-S1, (Z1+Z2)^2-Z1Z1, -Z2Z2, r^2-J, X3=jjtmp-2V, V-X3, Y3=jjtmp-2S1J |

Static formula footprint matches CLAUDE.md "Jacobian addition naming"
documented 11M + 5S + ~10 add/sub (here exactly 13 lin ops). The cost
ratio J+J / J+aff ≈ (11M+5S) / (7M+3S) ≈ 1.55x in M+S terms, which lines
up with the README primitive bench (one M+S is the dominant cost so a
P-256 J+J add costs ~85225 + ~50% ≈ ~130-140k cy if the lin ops are
amortized — not directly measured in README).

### 1.4 `ec_scalar_mul` (P-256, h=8 Lim-Lee fixed-base comb)

- Source: `src/points256.s:1790-1975`.
- Inner loop: `cm_loop` at `src/points256.s:1823-1953`, 32 iterations
  (counter `cm_loop_ctr` initialized to 32 at line 1816, decremented at
  line 1951). The h=8 comb pulls one of 8 bits from each of K_7..K_0
  per iteration; the constructed 8-bit `cm_idx` indexes a 256-entry REU
  affine table.
- Per iteration:
  - `ec_point_double` (skipped while R=∞ in the seed-pending state, but
    once R is non-∞ this runs every iteration; for a random 256-bit
    scalar the first idx is non-zero with probability ~1 − 1/256, so
    typically only iteration 1's double is skipped).
  - On idx=0: skip the add (probability ~1/256 per iteration, so
    expected count is ≈ 32/256 ≈ 0.125 across the whole call).
  - On idx!=0, first non-∞: seed R with the table entry (no add jsr).
  - On idx!=0, subsequent: 1 `ec_point_add` call.
  - 1 `sm256_reu_fetch_affine` call to pull the 64-byte affine T[idx]
    from REU bank 2 into ec_p2 (DMA primitive — no field-op cost, ~few
    hundred cycles).

Per-call totals for a generic random 256-bit BE scalar (no zero idx
windows; modal case):

| Callee                      | Count | Notes |
|-----------------------------|------:|-------|
| `ec_set_modp`               | 1     | One-time at entry |
| `ec_point_double`           | 31    | Skipped once at first iteration while R=∞; otherwise 32× |
| `ec_point_add`              | 31    | One seed iteration writes R directly from the table without an add; otherwise 32× |
| `sm256_reu_fetch_affine`    | 32    | ~32× (one per non-zero idx; expected ≈ 31.875) |

Variability: 1/256-per-iteration probability of an all-zero column,
yielding occasional savings of one (double+add)+fetch. For RFC 6979
A.2.5 P-256 (pinned in the README bench) the scalar is fixed and the
zero-column count is deterministic.

### 1.5 `ec_scalar_mul_var` (P-256, variable-base double-and-add)

- Source: `src/points256.s:1994-2137`.
- Inner loop: `v_loop` at `src/points256.s:2027-2116`, 256 iterations
  (counter `var_loop_ctr_lo` / `_hi` = $00 / $01 → 256).
- Per iteration:
  - `ec_point_double` (skipped while R=∞).
  - If scalar bit is 1 and R=∞: seed R from base (no add jsr).
  - If scalar bit is 1 and R!=∞: 1 `ec_point_add` call.
  - If scalar bit is 0: skip.

For a uniform random 256-bit BE scalar (high bit set or unset is random),
expected Hamming weight ≈ 128.

Per-call totals for a generic random 256-bit BE scalar:

| Callee                      | Count | Notes |
|-----------------------------|------:|-------|
| `ec_set_modp`               | 1     | One-time at entry |
| `ec_point_double`           | 255   | Skipped only at the leading runs of zero bits; for a random scalar the first set bit is at position ~255-ε so doubles ≈ 255 |
| `ec_point_add`              | 127   | Hamming weight of scalar minus 1 (one set bit seeds R) |

Worst case: scalar = 2^255 − 1 yields 255 doubles + 254 adds. Best case:
scalar = 1 yields 0 doubles + 0 adds. For ECDSA verify u2 = r*w mod n,
u2 is essentially uniform random in [1, n-1] so the 255 doubles + 127
adds expectation holds.

### 1.6 `ecdsa_verify_256`

- Source: `src/ecdsa256.s:88-458`.
- No inner loop. Pipeline:
  1. 5× `fp_reverse32` calls in `@rev_loop` (lines 100-124) to byte-flip
     r, s, h, Qx, Qy from BE to LE. The loop iterates 5 times.
  2. 2× `fp_is_zero` calls (r==0?, s==0?).
  3. 2× `fp_cmp` calls (r<n?, s<n?).
  4. 1× `ec_set_modn` + 1× `fp_mod_inv` (w = s^-1 mod n).
  5. 1× `fp_copy` (fp_r0 → ecdsa_w).
  6. 2× `fp_mod_mul_n` (u1 = h*w mod n; u2 = r*w mod n).
  7. 1× `fp_reverse32` (u1 LE → u1_be BE for the comb scalar input).
  8. 1× `ec_scalar_mul` (u1*G fixed-base).
  9. 2× `fp_copy` (Qx, Qy into ec_base_x / ec_base_y).
 10. 1× `fp_reverse32` (u2 LE → u2_be BE).
 11. 1× `ec_scalar_mul_var` (u2*Q variable-base).
 12. 1× `ec_set_modp` + 1× `ec_point_add_jj` (R = u1G + u2Q, full J+J).
 13. 1× `fp_is_zero` (R == ∞? early-fail).
 14. Cofactor compare:
     - 1× `ec_sqrp` (Z^2 mod p).
     - 1× `ec_mulp` (r * Z^2 mod p).
     - Byte-equality compare ec_t2 ?= ec_p3 (no field-op jsrs).
     - On miss: 1× `fp_add` + 1× `fp_cmp` + 1× `ec_mulp` for the
       fallback `(r+n) * Z^2` check (almost never taken; treat as 0 in
       the typical case).

Per-call jsr inventory for the success (cofactor-compare-passes-first)
path on a generic valid signature:

| Callee                          | Count | Notes |
|---------------------------------|------:|-------|
| `fp_reverse32`                  | 7     | 5 in @rev_loop + 1 u1 + 1 u2 |
| `fp_is_zero`                    | 3     | r, s, R-infinity |
| `fp_cmp`                        | 2     | r<n, s<n |
| `fp_copy`                       | 3     | w-stash + 2 Q-copy |
| `ec_set_modn`                   | 1     |   |
| `ec_set_modp`                   | 1     | Before the J+J add |
| `fp_mod_inv`                    | 1     | mod n (since ec_set_modn just ran); ~ 750 kcy on primitive bench but in practice cheaper on the s-specific input (see CLAUDE.md PR #34 retrospective) |
| `fp_mod_mul_n`                  | 2     | u1, u2 |
| `ec_scalar_mul`                 | 1     | u1*G (32 doubles + ~31 adds) |
| `ec_scalar_mul_var`             | 1     | u2*Q (~255 doubles + ~127 adds) |
| `ec_point_add_jj`               | 1     | u1G + u2Q join |
| `ec_sqrp`                       | 1     | Z^2 mod p |
| `ec_mulp`                       | 1     | r*Z^2 mod p |

Fallback path (only when r is in [p-n, p-1] AND the initial cofactor
compare misses, which is essentially never on honest inputs since
p-n ~ 2^128 for P-256) adds: 1 `fp_add`, 1 `fp_cmp`, 1 `ec_mulp`.

### 1.7 `ec_point_double_384`

- Source: `src/points384.s:65-417` (the doubling body extends to ~417
  reflecting the 48-byte data width; structurally identical to P-256).
- No internal loop. Same a=-3 short-Weierstrass formula.

Per-invocation jsr table (generic path):

| Callee                          | Count | Notes |
|---------------------------------|------:|-------|
| `fp_is_zero_384`                | 1     |   |
| `ec_set_modp_384`               | 1     |   |
| `ec_mulp_384`                   | 4     | 4M |
| `ec_sqrp_384`                   | 4     | 4S |
| `fp_mod_add_384`                | 8     |   |
| `fp_mod_sub_384`                | 4     |   |

### 1.8 `ec_point_add_384`

- Source: `src/points384.s:428-767`.
- Same shape as P-256 mixed add.

Per-invocation jsr table (generic H!=0 path):

| Callee                          | Count | Notes |
|---------------------------------|------:|-------|
| `fp_is_zero_384`                | 3     |   |
| `ec_set_modp_384`               | 1     |   |
| `ec_mulp_384`                   | 7     | 7M |
| `ec_sqrp_384`                   | 3     | 3S |
| `fp_mod_add_384`                | 1     |   |
| `fp_mod_sub_384`                | 5     |   |

### 1.9 `ec_point_add_jj_384`

- Source: `src/points384.s:790-1275`.
- Same shape as P-256 J+J.

Per-invocation jsr table (generic H!=0 path):

| Callee                          | Count | Notes |
|---------------------------------|------:|-------|
| `fp_is_zero_384`                | 4     |   |
| `ec_set_modp_384`               | 1     |   |
| `ec_mulp_384`                   | 11    | 11M |
| `ec_sqrp_384`                   | 5     | 5S |
| `fp_mod_add_384`                | 5     |   |
| `fp_mod_sub_384`                | 8     |   |

### 1.10 `ec_scalar_mul_384` (h=8 Lim-Lee fixed-base comb)

- Source: `src/points384.s:1697-1884`.
- Inner loop `cm384_loop` at `src/points384.s:1729-1861`, 48 iterations
  (`cm384_loop_ctr` initialized to 48 at line 1722).

Per-call totals for a generic random 384-bit BE scalar (modal case):

| Callee                          | Count | Notes |
|---------------------------------|------:|-------|
| `ec_set_modp_384`               | 1     |   |
| `ec_point_double_384`           | 47    | Skipped once at first iteration |
| `ec_point_add_384`              | 47    | One seed iteration writes R directly |
| `sm384w_fetch_to_p2`            | 48    | Each non-zero idx fetches 96 B affine from REU |

Variability: 1/256 per-iteration probability of a fully-zero column;
~48/256 = 0.19 expected zero-idx iterations.

### 1.11 `ec_scalar_mul_var_384` (variable-base double-and-add)

- Source: `src/points384.s:2013-2170`.
- Inner loop `v384_loop` at `src/points384.s:2049-2146`, 384 iterations
  (counter lo=$80 + hi=$02 → 128 + 256 = 384).

Per-call totals for a generic random 384-bit BE scalar:

| Callee                          | Count | Notes |
|---------------------------------|------:|-------|
| `ec_set_modp_384`               | 1     |   |
| `ec_point_double_384`           | 383   | First-set-bit iteration skips the leading-∞ double |
| `ec_point_add_384`              | 191   | Hamming weight of scalar minus 1 (one set bit seeds R) |

Worst case: 383 doubles + 382 adds. The ECDSA verify u2 hits expectation
~192 Hamming weight.

### 1.12 `ecdsa_verify_384`

- Source: `src/ecdsa384.s:104-471`.
- Same pipeline as `ecdsa_verify_256` with 48-byte fields.

Per-call jsr inventory for the success path:

| Callee                              | Count | Notes |
|-------------------------------------|------:|-------|
| `fp_reverse48`                      | 7     | 5 in @rev_loop + 1 u1 + 1 u2 |
| `fp_is_zero_384`                    | 3     | r, s, R-infinity |
| `fp_cmp_384`                        | 2     | r<n, s<n |
| `fp_copy_384`                       | 3     | w-stash + 2 Q-copy |
| `ec_set_modn_384`                   | 1     |   |
| `ec_set_modp_384`                   | 1     |   |
| `fp_mod_inv_384`                    | 1     | mod n; primitive ~ 1.55 Mcy, in practice cheaper at the s-specific input |
| `fp_mod_mul_n_384`                  | 2     | u1, u2 |
| `ec_scalar_mul_384`                 | 1     | u1*G fixed-base (48 doubles + ~47 adds) |
| `ec_scalar_mul_var_384`             | 1     | u2*Q variable-base (~383 doubles + ~191 adds) |
| `ec_point_add_jj_384`               | 1     | u1G + u2Q join |
| `ec_sqrp_384`                       | 1     | Z^2 mod p |
| `ec_mulp_384`                       | 1     | r*Z^2 mod p |

Fallback path adds 1 `fp_add_384` + 1 `fp_cmp_384` + 1 `ec_mulp_384`
(essentially never taken).

### 1.13 `ecdsa_verify_with_message_384`

- Source: `src/ecdsa384.s:510-549`.
- Wrapper. Same struct ABI; the wrapper hashes the caller-pre-set
  `(sha_src, sha_len)` message into `sha384_digest`, splices the digest
  into struct[96..143], then tail-calls `ecdsa_verify_384`.

Per-call jsr inventory:

| Callee                              | Count | Notes |
|-------------------------------------|------:|-------|
| `sha384_init`                       | 1     |   |
| `sha384_update`                     | 1     | One call; absorbs `sha_len` bytes |
| `sha384_final`                      | 1     |   |
| `ecdsa_verify_384`                  | 1     | Tail-jump (not jsr) at line 549; included for completeness |

Number of underlying `sha_compress` invocations: depends on message
length M (bytes):
- `sha384_update` issues ⌊(M + buffered_residue) / 128⌋ compressions
  during the absorb. With empty initial buffer that's ⌊M / 128⌋.
- `sha384_final` issues 1 compression always, +1 more if
  `block_len > 112` after appending the 0x80 byte (which happens when
  `M mod 128` is in `[111, 127]`).

Total: `⌈(M + 17) / 128⌉` compressions for M-byte messages with the
17 = 1 (0x80 byte) + 16 (length tail) padding overhead.

### 1.14 SHA-384 streaming primitives

- `sha384_init` (`src/sha384.s:138-158`): copies the 64-byte IV into
  state, zeros block_len and total_len. No `jsr` calls. ~ negligible
  cost.
- `sha384_update` (`src/sha384.s:173-239`): byte-at-a-time absorb. Inner
  loop body issues a `jsr sha_compress` only when `sha_block_len`
  reaches 128 (line 227). For M-byte input that's exactly ⌊M / 128⌋
  compressions (with empty starting buffer).
- `sha384_final` (`src/sha384.s:252-337`): 1 or 2 `jsr sha_compress`
  calls. 2 when the buffer has > 112 bytes left after the 0x80 append
  (which forces an extra zero-padded block to make room for the 16-byte
  length tail). 1 otherwise.

Per-block jsr inventory inside `sha_compress` (`src/sha384.s:346-479`):

| Callee                              | Count per block | Notes |
|-------------------------------------|----------------:|-------|
| `load_w_rel_to_in` (`:490`)         | 4 × 64 = 256    | One per expand iter (lines 376, 382, 391, 397); loop runs 64 times (t = 16..79) |
| `sigma1_in_to_tmp1`                 | 64              |   |
| `sigma0_in_to_tmp2`                 | 64              |   |
| `sha_round` (`:522`)                | 80              | Main rounds 0..79 |
| `add64` macros                      | ~10/round × 80  | Inline macros, not jsrs; mentioned for cost weighting |

Round body (`sha_round`) itself issues an additional ~6 jsrs to
Sigma0/Sigma1/Ch/Maj sigma helpers — these are the dominant cost driver
inside the 80-round main loop. The compressor is the main cost surface
of the SHA path; one full block dominates whatever sha384_update
overhead exists in the byte-by-byte absorb loop. For an empty message
(M = 0) the full SHA cost is 1 `sha_compress` (final padding block);
for M = 128 it's 2; for M ≤ 111 it's 1; for M in [112, 127] it's also
1; the worst case for short messages is M = 112..127 since the 0x80
forces a second block.

---

## 2. Rolled-up matrix (per top-level call, generic input)

Row = entry point. Column = primitive. Cell = static jsr count (or
expected count for loop-bearing entries). `EC.dbl` / `EC.add` /
`EC.add_jj` are point-op-level proxies that themselves expand into M, S,
and lin ops as documented in Section 1.

| Entry point                       | EC.dbl | EC.add | EC.add_jj | ec.mulp | ec.sqrp | fp.modadd | fp.modsub | fp.modinv | fp.modmul_n | fp.cmp | fp.copy | fp.iszero | fp.rev | sha384.init | sha384.upd | sha384.fin |
|-----------------------------------|-------:|-------:|----------:|--------:|--------:|----------:|----------:|----------:|------------:|-------:|--------:|----------:|-------:|------------:|-----------:|-----------:|
| `ec_point_double` (P-256)         |        |        |           | 4       | 4       | 8         | 4         |           |             |        |         | 1         |        |             |            |            |
| `ec_point_add` (P-256, mixed)     |        |        |           | 7       | 3       | 1         | 5         |           |             |        |         | 3         |        |             |            |            |
| `ec_point_add_jj` (P-256, J+J)    |        |        |           | 11      | 5       | 5         | 8         |           |             |        |         | 4         |        |             |            |            |
| `ec_scalar_mul` (P-256, h=8)      | 31     | 31     |           |         |         |           |           |           |             |        |         |           |        |             |            |            |
| `ec_scalar_mul_var` (P-256)       | 255    | 127    |           |         |         |           |           |           |             |        |         |           |        |             |            |            |
| `ecdsa_verify_256`                |        |        | 1         | 1       | 1       |           |           | 1         | 2           | 2      | 3       | 3         | 7      |             |            |            |
| `ec_point_double_384`             |        |        |           | 4       | 4       | 8         | 4         |           |             |        |         | 1         |        |             |            |            |
| `ec_point_add_384`                |        |        |           | 7       | 3       | 1         | 5         |           |             |        |         | 3         |        |             |            |            |
| `ec_point_add_jj_384`             |        |        |           | 11      | 5       | 5         | 8         |           |             |        |         | 4         |        |             |            |            |
| `ec_scalar_mul_384` (h=8)         | 47[1]  | 47[1]  |           |         |         |           |           |           |             |        |         |           |        |             |            |            |
| `ec_scalar_mul_var_384`           | 383    | 191    |           |         |         |           |           |           |             |        |         |           |        |             |            |            |
| `ecdsa_verify_384`                |        |        | 1         | 1       | 1       |           |           | 1         | 2           | 2      | 3       | 3         | 7      |             |            |            |
| `ecdsa_verify_with_message_384`   | (sub)  | (sub)  | (sub)     | (sub)   | (sub)   |           |           | (sub)     | (sub)       | (sub)  | (sub)   | (sub)     | (sub)  | 1           | 1[2]       | 1[2]       |
| `sha384_init`                     |        |        |           |         |         |           |           |           |             |        |         |           |        |             |            |            |
| `sha384_update`                   |        |        |           |         |         |           |           |           |             |        |         |           |        |             | ⌊M/128⌋    |            |
| `sha384_final`                    |        |        |           |         |         |           |           |           |             |        |         |           |        |             |            | 1 or 2     |

Footnotes:
- [1] Variability: a zero-column iteration (probability ~1/256 per loop
  iteration) skips both the add (or seed) and the fetch but still
  performs the double. Modal counts shown.
- [2] `sha384_update` issues ⌊M / 128⌋ compressions for an M-byte
  message; `sha384_final` issues 1 or 2 compressions depending on
  whether the residual buffer has room for the 16-byte length tail.
  Total compressions = ⌈(M + 17) / 128⌉.

ec.* and fp.* in the matrix above refer to mod-p operations except where
suffixed `_n` (mod n). The row for `ecdsa_verify_with_message_384` shows
`(sub)` for fields inherited from the tail-called `ecdsa_verify_384`;
add the `ecdsa_verify_384` row to it to get the full count.

---

## 3. Predicted compound cost worksheet

All cycle costs in this worksheet are sourced from README §"Ultimate 64
Elite turbo benchmarks" 1-MHz-equivalent column (read off
README.md:84-93, NTSC, 16 MHz). Costs at other speeds scale by their
own row. The intent is to compare predicted vs measured to expose
hidden compound-time overhead (loop control, copies, scalar
transposition, REU fetch, etc.).

README primitive cycle anchors (cyc = 1-MHz-equivalent µs at 16 MHz
column):

| Primitive            | P-256 cyc | P-384 cyc |
|----------------------|----------:|----------:|
| fp_mod_mul           | 9,374     | 15,873    |
| fp_mod_sqr           | 13,209    | 20,720    |
| fp_mod_inv           | 51,135    | 102,270   |
| ec_point_double      | 68,180    | 136,360   |
| ec_point_add         | 85,225    | 136,360   |
| ec_scalar_mul (h=8)  | 6,323,695 | 16,005,255|
| ec_scalar_mul_var    | 37,618,315| 95,486,090|
| ecdsa_verify         | 43,157,940|111,048,175|

The fp_mod_add/sub, fp_cmp, fp_copy, fp_is_zero, fp_reverse32/48 rows
are not separately listed in README; from the NTSC primitive table
fp_mod_add ≈ 1000 cy and fp_mod_sub ≈ 666 cy per call (table at
README.md:62-72 in 1-MHz µs). For the rolled-up estimates below these
sub-microsecond items are folded into a single line-item per entry
point (and noted as low single-digit-percent of total).

`fp_mod_mul_n` primitive cost is not directly published; estimate from
the source body (`src/mod256.s:618-688`): one `fp_mul` (~9k cy P-256)
+ 256 bit-serial reduction iterations each doing one 64-byte ROL chain
+ one 32-byte compare + occasional 32-byte subtract. Empirical
estimate ~ 80-120k cy P-256, ~ 150-220k cy P-384. Treated as ~100k cy
(P-256) / ~180k cy (P-384) below.

### 3.1 `ec_point_double` (P-256, sanity check)

```
predicted = 4 * fp_mod_mul + 4 * fp_mod_sqr + 8 * fp_mod_add + 4 * fp_mod_sub
          + 1 * ec_set_modp + 1 * fp_is_zero
          ≈ 4 * 9374 + 4 * 13209 + 8 * 1000 + 4 * 666 + (~negligible)
          ≈ 37496 + 52836 + 8000 + 2664
          ≈ 100,996 cy
```

README measured: 68,180 cy at 16 MHz.

Predicted / measured ratio: 100996 / 68180 ≈ 1.48 — i.e. the README
measured cost is **30% LESS** than the additive prediction would suggest.
This is the expected direction: `ec_mulp` / `ec_sqrp` save the dispatch
overhead (`ec_set_modp` is inlined-once at the body level rather than
inside each multiply call) and the body holds `fp_misc` in a known
state across consecutive mul/sqr calls. Also, the `fp_mod_mul` /
`fp_mod_sqr` primitive bench inflates per-call cost slightly because
each measured call re-establishes ZP pointer state from scratch.

### 3.2 `ec_point_add` (P-256, mixed)

```
predicted = 7 * 9374 + 3 * 13209 + 1 * 1000 + 5 * 666 + (~negligible)
          ≈ 65618 + 39627 + 1000 + 3330
          ≈ 109,575 cy
```

README measured: 85,225 cy at 16 MHz.

Ratio 109575 / 85225 ≈ 1.29 — same direction, slightly smaller delta
than doubling (consistent with fewer mod-reduce calls per body).

### 3.3 `ec_point_add_jj` (P-256, NOT in README; predicted only)

```
predicted = 11 * 9374 + 5 * 13209 + 5 * 1000 + 8 * 666
          ≈ 103114 + 66045 + 5000 + 5328
          ≈ 179,500 cy (P-256)
```

For P-384:
```
predicted = 11 * 15873 + 5 * 20720 + 5 * 1167 + 8 * 1167
          ≈ 174603 + 103600 + 5835 + 9336
          ≈ 293,400 cy (P-384)
```

These are useful for the verify worksheet below; no direct primitive
bench row exists.

### 3.4 `ec_scalar_mul` (P-256, h=8 comb)

```
predicted = 1 * ec_set_modp
          + 31 * ec_point_double + 31 * ec_point_add
          + 32 * sm256_reu_fetch_affine   (REU DMA stash + restore; ~1500 cy each estimate)
          + scalar transpose + copy overhead
          ≈ 31 * 68180 + 31 * 85225 + 32 * ~1500
          ≈ 2,113,580 + 2,641,975 + 48,000
          ≈ 4,803,555 cy
```

README measured: 6,323,695 cy at 16 MHz.

Ratio 4803555 / 6323695 ≈ 0.76 — i.e. measured is **32% HIGHER** than
predicted. Most likely sources of the gap:
- The REU DMA fetch of a 64-byte affine table entry per loop iteration
  is hand-implemented; if the per-fetch cost is ~30k cy not ~1.5k cy
  the gap closes immediately (32 * 30k ≈ 960k cy).
- Per-loop copy ec_p3 → ec_p1 (96 bytes per iteration × 32 iterations
  ≈ ~50k cy total).
- Bit-extraction prologue (~50 cy per iteration × 32 ≈ 1.6k cy).

The 32% gap is roughly consistent with ~960k cy of REU fetch overhead
+ ~50k cy of copies + ~10k cy of loop control / bit extraction +
~500k cy of "the primitives are slightly slower in the integrated
loop than they are when measured in isolation" — the last bucket is
where the audit's section 7 stacked-attribution exercise should focus.

### 3.5 `ec_scalar_mul_var` (P-256)

```
predicted = 1 * ec_set_modp
          + 255 * ec_point_double + 127 * ec_point_add
          + 256 iterations of bit-test / branch overhead
          ≈ 255 * 68180 + 127 * 85225
          ≈ 17,385,900 + 10,823,575
          ≈ 28,209,475 cy
```

README measured: 37,618,315 cy at 16 MHz.

Ratio 28209475 / 37618315 ≈ 0.75 — same 25% gap shape as the fixed-base
comb. Predicted under-estimates the per-iteration copy/control cost
which scales with the iteration count (256 vs 32, so larger absolute
total but same proportional). Per-iteration overhead ≈ (37618315 -
28209475) / 256 ≈ 36.8k cy per iteration — consistent with a 96-byte
ec_p3 → ec_p1 copy (~ 1k cy) + base copy on bit-set iterations + bit
walk + loop control. The dominant unexplained line item is again the
"primitive doesn't run at primitive-bench cycles when inside the loop"
factor (likely because of inner DMA-state-restore overhead — every
fp_mul inside ec_point_double pays the issue #33 defensive
`reu_reu_lo = 0` / `reu_addr_ctrl = 0` write, which is amortized away
when only one fp_mul is measured per primitive jiffy but adds up
across the integrated call).

### 3.6 `ecdsa_verify_256`

```
predicted = ec_scalar_mul (1× u1*G)
          + ec_scalar_mul_var (1× u2*Q)
          + ec_point_add_jj (1× join)
          + fp_mod_inv (1× s^-1 mod n)
          + 2 * fp_mod_mul_n (u1, u2)
          + ec_sqrp + ec_mulp (cofactor compare)
          + 7 * fp_reverse32 + 3 * fp_is_zero + 2 * fp_cmp + 3 * fp_copy
          + ec_set_modn + ec_set_modp
          ≈ 6,323,695 + 37,618,315 + 179,500 + 51,135 + 2 * 100,000
            + 13,209 + 9,374 + (~7 * ~150) + (~3 * ~200) + (~2 * ~600) + (~3 * ~200)
          ≈ 44,395,228 cy + ~few thousand for low-cost ops
          ≈ ~44,400,000 cy
```

README measured: 43,157,940 cy at 16 MHz.

Ratio 44400000 / 43157940 ≈ 1.03 — predicted is **3% higher** than
measured. This is the most accurate prediction across the worksheet
because ecdsa_verify is a near-pure composition of two already-measured
scalar mul calls + a J+J add + an inversion. The fact that the
prediction over-counts by ~1.3M cy strongly suggests:
- `fp_mod_inv` mod n in this call is consistently cheaper than the
  primitive-bench ~51k cy figure (CLAUDE.md PR #34 retrospective:
  "fp_mod_inv is binary GCD with input-sensitive runtime" — the s^-1
  computation may hit fast paths).
- `fp_mod_mul_n` may actually be cheaper than the ~100k cy estimate
  used above. A 50k cy real cost would close almost the entire gap.

PR #26 + PR #34 predicted ~ 1.6 Mcy P-256 savings from eliminating
1× fp_mod_inv + 3× ec_mulp; measured −68 kcy (CLAUDE.md). The
worksheet here corroborates that interpretation: the inversion's
context-specific cost is ~3-10x lower than the primitive bench
suggests, so eliminating it gives correspondingly smaller savings.

### 3.7 `ec_point_double_384`

```
predicted = 4 * 15873 + 4 * 20720 + 8 * 1167 + 4 * 1167
          ≈ 63492 + 82880 + 9336 + 4668
          ≈ 160,376 cy
```

README measured: 136,360 cy at 16 MHz.

Ratio 160376 / 136360 ≈ 1.18 — same 18% prediction overshoot pattern.

### 3.8 `ec_point_add_384` (mixed)

```
predicted = 7 * 15873 + 3 * 20720 + 1 * 1167 + 5 * 1167
          ≈ 111111 + 62160 + 1167 + 5835
          ≈ 180,273 cy
```

README measured: 136,360 cy at 16 MHz.

Ratio 180273 / 136360 ≈ 1.32 — slightly larger overshoot, possibly
because P-384 mod-add/sub costs are roughly equal to P-256 in the
README primitive bench (1167 vs ~1000 cy) — but the P-384 mul-heavy
body amortizes them differently.

### 3.9 `ec_scalar_mul_384`

```
predicted = 47 * 136360 + 47 * 136360 + 48 * ~3000 (REU 96-B fetch)
          ≈ 6408920 + 6408920 + 144000
          ≈ 12,961,840 cy
```

README measured: 16,005,255 cy at 16 MHz.

Ratio 12961840 / 16005255 ≈ 0.81 — 19% measured overshoot, very similar
to the P-256 fixed-base comb gap. Same root-cause hypothesis: REU
fetch (96 B per slot for P-384 vs 64 B for P-256, so ~50% larger DMA
window per fetch — but still much smaller than the integrated gap), copy
overhead (144 B vs 96 B per iter), and primitive-inside-loop cost.

### 3.10 `ec_scalar_mul_var_384`

```
predicted = 383 * 136360 + 191 * 136360
          ≈ 52,217,880 + 26,044,760
          ≈ 78,262,640 cy
```

README measured: 95,486,090 cy at 16 MHz.

Ratio 78262640 / 95486090 ≈ 0.82 — 22% measured overshoot, again
consistent. Per-iteration overhead ≈ (95486090 − 78262640) / 384 ≈
~44.8k cy — slightly higher than the P-256 var per-iteration gap
because the 144-byte copies (ec_p3 → ec_p1) cost ~1.5x more.

### 3.11 `ecdsa_verify_384`

```
predicted = ec_scalar_mul_384 (1×) + ec_scalar_mul_var_384 (1×)
          + ec_point_add_jj_384 (1×) + fp_mod_inv_384 (1×)
          + 2 * fp_mod_mul_n_384 (~180k cy estimate)
          + ec_sqrp_384 + ec_mulp_384 (cofactor compare)
          + 7 * fp_reverse48 + 3 * fp_is_zero_384 + 2 * fp_cmp_384 + 3 * fp_copy_384
          + ec_set_modn_384 + ec_set_modp_384
          ≈ 16,005,255 + 95,486,090 + 293,400 + 102,270 + 360,000
            + 20720 + 15873 + ~few thousand
          ≈ ~112,283,000 cy
```

README measured: 111,048,175 cy at 16 MHz.

Ratio 112283000 / 111048175 ≈ 1.01 — predicted essentially matches
measured (1% high). Same interpretation as P-256: the composition cost
is well-predicted from the scalar-mul + J+J + inv + 2× mul_n primitive
costs. The 1.6 Mcy savings PR #34 predicted (1× inv + 3× mulp savings)
mapped to only ~190 kcy actual savings — strongly suggests that
fp_mod_inv_384 on the join's Z output hits fast paths, and that mulp
overhead vs primitive bench is small in context.

### 3.12 `sha384_*` compositional cost

`sha_compress` is the dominant cost. No primitive bench row exists for
single-block compress in README; it's not in the public benchmark
surface. From `src/sha384.s` structure:
- 16 word copies in pre-expand (cheap).
- 64 expand iterations × (~4 jsrs + several `add64` macros) ≈ ~64 * ~5k
  cy ≈ 320k cy (rough estimate).
- 80 round bodies × (~6 jsrs + macros) ≈ ~80 * ~10k cy ≈ 800k cy.
- Final H accumulation (cheap).

Estimated `sha_compress` cost: ~1.1-1.5 Mcy per block. For a typical
TLS handshake message (~few hundred to ~few thousand bytes), the total
SHA cost would be ⌈M / 128⌉ + 1 compressions × ~1.2 Mcy. The
`ecdsa_verify_with_message_384` total is therefore ~ verify_384 cost +
SHA cost: for M = 256 the SHA cost adds 3 × 1.2 Mcy ≈ 3.6 Mcy on top
of the 111 Mcy verify, a ~3% surcharge. The wrapper's own overhead
(48-byte digest splice + struct pointer save/restore) is < 1k cy.

The audit may wish to bench `sha_compress` standalone to refine the
~1.2 Mcy estimate; the entry point cost is not currently in the README
table.

---

## 4. Divergence summary table

| Entry point             | Predicted (cyc, 16 MHz) | Measured (cyc, 16 MHz) | Δ (meas-pred) | Δ / measured |
|-------------------------|------------------------:|-----------------------:|--------------:|-------------:|
| ec_point_double         |                 101,000 |                 68,180 |       -33,000 |        -48% |
| ec_point_add (mixed)    |                 110,000 |                 85,225 |       -25,000 |        -29% |
| ec_scalar_mul (h=8)     |               4,800,000 |              6,323,695 |    +1,524,000 |        +24% |
| ec_scalar_mul_var       |              28,200,000 |             37,618,315 |    +9,418,000 |        +25% |
| ecdsa_verify_256        |              44,400,000 |             43,157,940 |    -1,242,000 |         -3% |
| ec_point_double_384     |                 160,000 |                136,360 |       -24,000 |        -18% |
| ec_point_add_384        |                 180,000 |                136,360 |       -44,000 |        -32% |
| ec_scalar_mul_384       |              13,000,000 |             16,005,255 |    +3,005,000 |        +19% |
| ec_scalar_mul_var_384   |              78,300,000 |             95,486,090 |   +17,186,000 |        +18% |
| ecdsa_verify_384        |             112,300,000 |            111,048,175 |    -1,252,000 |         -1% |

Two distinct divergence patterns visible:

1. **Point ops under-predict per-call cost.** ec_point_double /
   ec_point_add are 18-48% cheaper than the multiply-and-sum-of-
   primitives prediction. Mechanism: the entry-point body holds the
   modulus and ZP state across the multiplies, so each mulp/sqrp is
   cheaper inside the body than its primitive-bench cost (which
   includes dispatch overhead).

2. **Scalar mul over-predicts per-call cost.** The fixed-base comb and
   variable-base double-and-add are 18-25% more expensive than the
   scaled-up point-op count would suggest. Mechanism: per-iteration
   overhead (96/144 B copies, REU table fetches, bit-walk control,
   issue #33-style REU-state writes) is not folded into the primitive
   row. The two effects partially cancel at the ECDSA-verify level,
   where the prediction is accurate to 1-3%.

The audit's section 8 should consider:
- Adding ec_point_add_jj / ec_point_add_jj_384 to the U64E primitive
  bench (currently only the mixed add and scalar muls are benched);
  the J+J add is now load-bearing in ECDSA verify but un-measured.
- Adding fp_mod_mul_n / fp_mod_inv_n cost rows; current estimates
  are coarse.
- The accurate ECDSA verify prediction means a corresponding
  conclusion about PR #26 + PR #34's predicted savings: the
  measurement gap is real and consistent with the CLAUDE.md
  hypothesis (fp_mod_inv on Z outputs is cheaper than primitive-bench
  average), not an artifact of the call-graph model.
