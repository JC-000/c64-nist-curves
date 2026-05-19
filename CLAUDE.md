# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# c64-nist-curves

## Project overview
P-256 and P-384 elliptic curve arithmetic optimized for the Commodore 64 (6502 CPU at 1 MHz). Optimizations ported from the c64-x25519 project.

Companion docs (read alongside this file):
- `README.md` — user-facing overview, full benchmark tables, ECDSA ABI walkthrough.
- `API.md` — library API reference; §4 (re-entrancy contract) and §8 (consumer integration / submodule pinning) are load-bearing.
- `CHANGELOG.md` — release history with wave-by-wave optimization log.
- `tools/vectors/README.md` — oracle invariant + KAT refresh procedure.

## Build
```
make clean && make           # ca65/ld65 build → build/nist-curves.prg
make build-acme              # legacy ACME build of *.asm (diff testing only)
make bench-u64               # alias for tools/bench_ecdsa_u64.py (needs U64_HOST)
```
Assembler: ca65/ld65 (cc65 toolchain). Multi-object build: each .s file compiles
to a separate .o, linked by ld65 with `src/c64.cfg`. Outputs:
- `build/nist-curves.prg` — loadable PRG (loaded at $0801).
- `build/labels.txt` — VICE symbol table, post-processed from ld65 `-Ln` format.
- `build/nist-curves.dbg` — aggregated source-line debug info (cc65 .dbg format)
  produced by ca65 `-g` + ld65 `--dbgfile`. Loadable by VICE binary monitor
  (`monitor> dbgfile build/nist-curves.dbg`) and other cc65-aware debuggers for
  source-level stepping / breakpoints / span lookup. `.dbg` is a separate
  artifact; the .prg is byte-identical with or without `-g` (verified by
  sha256 round-trip).
Current PRG size: ~36.4 KB (37302 bytes), loaded at $0801.

`src/*.s` is canonical (ca65). `src/*.asm` files exist for the legacy
ACME build path used in side-by-side diff testing only — do not edit
them for new work.

## Test
```
python3 tools/test_fp256.py          # P-256 field arithmetic tests (field KAT + random)
python3 tools/test_points256.py      # P-256 point operation tests (add --full for 10x samples)
python3 tools/test_fp384.py          # P-384 field arithmetic tests (field KAT + random)
python3 tools/test_points384.py      # P-384 point operation tests (add --full for 10x samples)
python3 tools/bench_p256.py          # P-256 primitive benchmarks (oracle-gated)
python3 tools/bench_p384.py          # P-384 primitive benchmarks (oracle-gated)
python3 tools/bench_p256_u64.py      # P-256 on Ultimate 64 Elite (16/48 MHz turbo)
python3 tools/bench_p384_u64.py      # P-384 on Ultimate 64 Elite (16/48 MHz turbo)
python3 tools/test_ecdsa_verify.py   # ECDSA verify (both curves, RFC 6979 + CAVP SigVer)
python3 tools/bench_ecdsa_u64.py     # ECDSA verify + variable-base scalar_mul on U64E
python3 tools/bench_sha384.py        # SHA-384 per-block compress cost (VICE 1 MHz, oracle-gated)
```
Tests use the c64-test-harness package (ViceInstanceManager). VICE must NOT be launched directly.

Each test/bench is a single Python entrypoint — there is no pytest
runner. To narrow scope: `--seed N` reproduces a specific failure
(default unseeded via `secrets`); `--full` on the point tests expands
3→10 random samples per routine and exercises all 25 CAVP KATs;
`--verbose` is supported by most. To run a single routine in
isolation, edit the test file's `main()` selection or run the
matching standalone diag tool (e.g. `tools/diag_verify384_turbo.py`,
`tools/test_inv_fast.py`, `tools/ct_mul_brute_check.py`).

U64E benches require `U64_HOST=<ip>` env var (and optionally
`U64_PASSWORD=<pw>`). Set `BENCH_DEBUG_STREAM=1` on `bench_ecdsa_u64.py`
to enable the cycle-accurate UDP :11002 bus-trace cross-check
(stream destination must be configured on the U64E). Hardware benches
serialize on `DeviceLock` for cross-process safety — one stuck job
blocks every other on the device.

### Oracle-driven testing model
All test suites use an **external oracle** -- the `cryptography`
Python package plus NIST KAT files shipped under `tools/vectors/` --
to produce expected outputs. Test code never hard-codes values from
a previous implementation run. Benchmarks run a one-shot correctness
gate against the oracle before recording cycle counts for each
routine; a routine that fails the gate is marked UNVERIFIED and its
cycles are dropped. Random scalars are unseeded by default
(`secrets.token_bytes` / `secrets.randbelow`); `--seed N` reproduces
a failure. `--full` on the point tests expands sample counts from 3
per routine to 10 and runs all 25 NIST CAVP KATs. See
`tools/vectors/README.md` for the full invariant and refresh
procedure.

The invariant enforced across `tools/vectors/`:

1. **Shared constants.** P-256 and P-384 curve parameters live in
   `tools/vectors/constants.py` (FIPS 186-5 D.1.2.3 / D.1.2.4) and
   are imported by every test. They are never redefined inside the
   test files. The module self-checks at load time that
   `Gy^2 == Gx^3 + a*Gx + b mod p`. Both short names (`P256`,
   `GX256`, ...) and prefixed names (`P256_P`, `P256_GX`, ...,
   `CURVES`) are exported; they alias the same Python ints.
2. **Oracles are external.** Scalar multiplication goes through
   `loader.scalar_mul_oracle` which wraps the `cryptography` library.
   Field-op expected values come from Python `int` `+ - * %` and
   `pow(a, p-2, p)` -- interpreter primitives, not editable helpers.
   The only hand-rolled helpers are the affine group law (needed
   because `cryptography` does not expose affine add); `self_check`
   cross-validates them against the oracle at startup.
3. **Unseeded random inputs by default.** Field and scalar inputs
   come from the OS CSPRNG. Each run exercises a fresh sample.
4. **Two flavours of NIST-derived KATs** are checked in:
   - `nist_p{256,384}_ecdh.rsp` -- 25 NIST CAVP KAS ECC CDH vectors
     per curve. Consumed by the point tests and bench gates; each
     vector pins a `(scalar, scalar * G)` pair to the P-256 / P-384
     specification.
   - `nist_p{256,384}_kat.rsp` -- field-arithmetic KAT bundles
     (FIPS 186-5 curve params + `[KG k=N]` + `[EcPoint tcId=N]`
     from Wycheproof "valid" records). Consumed by the field tests
     via a `test_nist_kat_curve_equation` that composes the C64
     `fp_mod_mul`, `fp_mod_add`, and `fp_mod_sub` routines to verify
     `y^2 == x^3 - 3x + b mod p` for every KAT point -- a stub that
     returns 0 cannot pass this.

### Init sentinel pattern (replaces wait_for_text race)
The program writes `$42` to `$02A7` as the very last step of `start:` after all
init (sqtab, REU multiply tables, precompute tables via `ec_precompute_256` and
`ec_precompute_384`, etc.) completes. Tests poll this sentinel
byte via `peek(0x02A7)` instead of racing with `wait_for_text("READY.")` + a
`jsr()` re-init (which would cost ~2 minutes to repopulate REU tables). In
warp mode the sentinel appears in roughly 2 seconds after VICE launch.
See `tools/test_fp384.py` and `tools/test_points384.py` for the canonical
pattern.

## Architecture
All field elements are **little-endian** (byte 0 = LSB). This matches 6502 carry propagation.

### Source files (src/)
| File | Purpose |
|------|---------|
| main.s | Entry point, VIC blanking, REU DMA init (`reu_mul_init`), precompute table generation, benchmarking. Test/bench driver for the library's own PRG — NOT linked into consumer projects (see API.md §8.2). |
| constants.s | Hardware addresses, REU registers |
| zp_config.s | Zero-page allocations (consumer-tunable) |
| mul_8x8.s | Quarter-square 8x8->16 multiply table init + constant-time `mul_8x8` primitive (issue #14, ported from c64-ChaCha20-Poly1305 v0.3.0 `ct_mul_8x8`). Also hosts `reu_fetch_mul_row`, the REU DMA row-fetch helper used by `fp_sqr_384` (moved here from main.s by issue #18 fix so standalone-link consumers resolve it). |
| fp256.s | 32-byte field arithmetic (add/sub/mul/sqr) with X25519 optimizations |
| mod256.s | P-256 Solinas reduction, modular ops, binary GCD inverse, P-256 prime |
| curve256.s | P-256 parameters + RFC 6979 test vectors (little-endian) |
| points256.s | P-256 point double/add/windowed scalar_mul, Jacobian->affine, REU precompute |
| inv256.s | P-256 Fermat inversion via addition chain (reference only; 41x slower than binary GCD) |
| fp384.s | 48-byte field arithmetic (add/sub/mul/sqr) for P-384 |
| mod384.s | P-384 Solinas reduction, modular ops, binary GCD inverse, P-384 prime |
| curve384.s | P-384 parameters + test vectors (little-endian) |
| points384.s | P-384 point double/add/windowed scalar_mul, Jacobian->affine, REU precompute |
| ecdsa256.s | P-256 ECDSA verify (`ecdsa_verify_256`) + BE<->LE helper `fp_reverse32`. Non-constant-time (public-input-only) |
| ecdsa384.s | P-384 ECDSA verify (`ecdsa_verify_384`) + BE<->LE helper `fp_reverse48`. Non-constant-time (public-input-only). Also hosts `ecdsa_verify_with_message_384`, the one-shot SHA-384 + verify wrapper. |
| sha384.s | SHA-384 streaming hash (FIPS 180-4 §6.4) — `sha384_init` / `sha384_update` / `sha384_final` + 48 B BE digest at `sha384_digest`. Self-contained (no REU DMA, no shared field/multiply scratch). Used by `ecdsa_verify_with_message_384`. |
| data.s | Buffers, point storage, page-aligned DMA targets |
| c64.cfg | ld65 linker configuration (memory regions, segment placement) |
| exports.inc | Cross-module .import/.export dependency map |

### Benchmarks
VICE: `tools/bench_p256.py` and `tools/bench_p384.py` (use `jsr()`, VICE-only).
Ultimate 64 Elite: `tools/bench_p256_u64.py` and `tools/bench_p384_u64.py`
(DMA trampoline at $C000, atomic single-byte hijack via shim at $0800,
`DeviceLock` for cross-process safety). Shared helpers in `tools/bench_u64_common.py`.
Results in README.md.

U64 bench architecture: boot at 48 MHz for fast init (~5s), poll $02A7
sentinel, switch to target speed, install trampoline, single-byte hijack
($0836: $35→$00 turns `JMP $0835` into `JMP $0800`→shim→$C000). Done
sentinel at $02A8. Full reboot between speed changes (REU DMA state
gets stale otherwise).

### Key optimizations
- REU DMA multiply row caching (128KB lookup in REU)
- Persistent REU DMA descriptor state: `reu_mul_init` pre-configures the
  C64 base ($DF02/03 = mul_dma_lo), REU offset low ($DF04 = 0),
  length ($DF07/08 = 512), and address-control ($DF0A = 0) ONCE at boot.
  The per-row fetch inside fp_mul / fp_sqr (and the `_384` variants)
  writes only three bytes per row: reu_reu_hi ($DF05), reu_reu_bank
  ($DF06), reu_command ($DF01) — 20 cycles total per row fetch, which
  works out to <1% of a full fp_mul. Point-level DMA routines
  (`.sm_reu_restore` / `.sm384w_restore_reu`) restore this invariant
  state on exit so the mul-fetch path never has to re-initialize it.
  **Caller residue defence**: each public entry point that initiates
  REU DMA (`fp_mul`, `fp_sqr`, `fp_mul_384`, `fp_sqr_384`,
  `ec_scalar_mul[_var][_384]`, `ecdsa_verify_256/384`) re-establishes
  `$DF04 = 0` and `$DF0A = 0` defensively before touching DMA, so a
  caller that polluted those two registers between boot and a library
  call cannot silently route the row fetch to the wrong REU offset.
  Issue #33-class defence; ported from c64-x25519 commit 817f525.
- Self-modifying code for multiply accumulation addresses
- 4x unrolled inner multiply loop with inlined REU DMA
- Dedicated squaring with deferred doubling of cross terms (Wave 4e)
- Carry-propagation INC fusion in fp_mul / fp_sqr accumulator spill (Wave 4b)
- Solinas fast reduction with self-modifying dispatch and register-resident accumulator
- h=8 Lim-Lee fixed-base comb for P-256 and P-384 scalar_mul with 256-entry REU-resident anchor table (Wave 7a; h=4 landed in Wave 5a/5b)
- Unrolled binary GCD shift loops for modular inversion
- VIC-II screen blanking (+20-25% CPU)

### Negative findings (do not re-attempt without a new angle)
- **One-level subtractive Karatsuba at N=32** (Wave 4c, reverted). Three N=16
  leaves plus combine cost more than one monolithic N=32 multiply on this
  codebase. The dominant cost is NOT REU DMA setup — Wave 7b verified that
  per-row DMA setup is already only 20 cycles per row / <1% of fp_mul, so
  tripling row-fetches only adds ~2% overhead. The real bottleneck is the
  4x-unrolled inner-loop accumulator body itself (the `ldy mul_src2_buf,x /
  adc mul_dma_lo,y / adc mul_dma_hi,y / sta` chain per byte). Three N=16
  sub-multiplies do 3*16*16 = 768 byte-muls plus ~N*3 combine adds; one
  N=32 does 32*32 = 1024. Naively 25% fewer, but the combine chain (three
  add-with-carry passes across 32-64 bytes) plus the sub-multiply call
  overhead, extra zeroing, and loss of the outer-loop-zero fast-skip that
  saves ~20% of monolithic N=32 time on sparse inputs together erase the
  byte-mul savings. Pending re-attempts would need a materially different
  approach (Toom-3, fused combine, or a DMA-batched fetch that amortizes
  across multiple rows).
- **CMO98 / Fay relative Jacobian doubling** (Wave 4d reverted for P-256;
  Wave 5c analysis confirmed unprofitable for P-384 — see
  `.research/wave5c_p384.txt`). CMO98's advertised "4M + 4S" J^m doubling
  is measured against plain Jacobian doubling at 4M + 6S. But both
  ec_point_double (P-256) and ec_point_double_384 (P-384) already use
  the a=-3 short-Weierstrass trick ((X-Z^2)(X+Z^2) = X^2 - Z^4), which
  gets standalone Jacobian doubling to exactly 4M + 4S on its own. CMO98
  is tied in operation count, and worse in constants because it still
  needs an aZ^4 carry update (+1M) which the a=-3 trick avoids entirely.
  No headroom to exploit regardless of S/M ratio — the 2S saving the
  paper quotes is versus non-a=-3 Jacobian, not versus the trick form
  already in use here. Fay 2014 relative/co-Z is a scalar_mul-level
  fused DoubleAdd restructure (not a drop-in doubling replacement) and
  is only applicable to window schemes where each step is exactly one
  double followed by one add; the Wave 5a/5b Lim-Lee comb runs
  back-to-back doubling chains of length h=4 with a single add per
  chain, where Meloni reuse is unavailable for most doublings. A
  plausible future angle only if the comb loop is ever restructured
  around a fused DoubleAdd primitive.
- **Removal of the `beq mul_src2_buf=0` fast-path in fp_mul/fp_sqr inner
  loops** (Wave 8a, reverted). The 4x-unrolled mul inner loop has a
  `beq @next_j_*` immediately after `ldy mul_src2_buf,x` which skips the
  ~25-cycle accumulator body when the multiplier byte is zero. A
  random-dense input analysis says the `beq` is net-negative (2-cycle
  fall-through tax × 255/256 beats 25-cycle save × 1/256). Wave 8a removed
  it accordingly, tests passed (1074/1074), and the primitive bench confirmed
  the expected ~2% fp_mul / fp_mod_mul speedup. **But `ec_point_double`
  regressed +5-6% and `ec_point_add` regressed +10-15% on both curves.**
  Root cause: point-op fp_mul callers feed sparse intermediate Jacobian
  coordinates (Z starts at 1 so Z^2/Z^3 carry many zero high bytes; the
  a=-3 trick `(X-Z^2)(X+Z^2)` produces bytes that often cancel to zero;
  Lim-Lee comb precompute entries have non-uniform entropy). The `beq` was
  skipping ~5-30 real accumulator cycles per fp_mul call on point ops, not
  the <0.1 expected from random dense input. The original fast-path was
  load-bearing for the compound-caller workload; the random-input primitive
  audit was blind to that. Task #16 A/B confirmed: reverting just Part 1
  does not restore point ops; Part 2 alone accounts for the full regression.
  See `.research/wave8a.txt` for the full A/B data. Do not re-remove the
  `beq` without a refined fast-path (e.g. a mini-body that only advances
  the loop counter) that preserves the sparse-input skip, and only after
  A/B-benching compound callers in addition to primitives.
- **PR #26 cofactor-compare and PR #34 cofactor approach (a) ECDSA verify
  optimizations** (both merged; measured 2026-05-18). Both PRs predicted
  ~800 kcy P-256 / ~1.7 Mcy P-384 verify savings from "eliminating 1
  `fp_mod_inv` call (~750 kcy from primitive bench) + 3 `ec_mulp` calls
  per verify". Three-point U64E bench comparison (PR #19 README baseline
  / PR #26 build at `460de8f` / PR #34 master at `788adc3`):

  | Stage | Predicted | Measured P-256 @16 MHz | Measured P-384 @16 MHz |
  |---|---|---|---|
  | PR #19 → PR #26 | ~800 kcy / ~1700 kcy | **−51 kcy (3 jiffies)** | **−85 kcy (5 jiffies)** |
  | PR #26 → PR #34 | ~800 kcy / ~1700 kcy | **−17 kcy (1 jiffy)** | **−102 kcy (6 jiffies)** |
  | Combined | ~1.6 Mcy / ~3.4 Mcy | **−68 kcy (~0.16%)** | **−187 kcy (~0.17%)** |

  10-20× short. RAM cost: PR #26 +512 B PRG; PR #34 +1440 B PRG +192 B
  DATA (96 B per curve for `ecdsa_u1g_jac`). Combined ~2 KB PRG + 192 B
  DATA for ~70 kcy / ~190 kcy verify savings — roughly an order of
  magnitude worse than the prediction implied.

  Root-cause hypothesis: `fp_mod_inv` is binary GCD with input-sensitive
  runtime. The primitive bench averages random-input cost (~750 kcy);
  the Z coordinates emerging from `ec_scalar_mul` likely hit GCD fast
  paths (byte alignment, low Hamming weight, or small magnitude),
  making the actual inversions consistently cheap and their elimination
  near-pointless. Symmetric to the Wave 8a `beq`-removal case above:
  primitive benchmarks can mislead about compound-caller behaviour in
  BOTH directions (Wave 8a primitive-fast / compound-slow; PR #26+#34
  primitive-says-big-savings / compound-shows-tiny-savings). Lesson:
  **for any optimization costing PRG or DATA bytes, measure on the
  integrated bench (`bench_ecdsa_u64.py`, `bench_p256/p384_u64.py`)
  before merge, not just predict from primitive costs.** PR descriptions
  must cite measured cycles before/after, not extrapolated savings.
  Do not re-attempt similar inversion-elimination opts without first
  measuring the actual `fp_mod_inv` cost on the specific inputs the
  callsite receives (instrumentation of `ec_jacobian_to_affine` against
  the bench fixture would suffice).

### Jacobian addition naming

The library provides **two** point-add primitives per curve, with
different operand contracts and different consumers:

- **`ec_point_add` / `ec_point_add_384`** (src/points256.s, src/points384.s):
  **mixed Jacobian + affine addition** (7M + 4S). P1 (ec_p1/ec384_p1) is
  read as full Jacobian; P2 (ec_p2/ec384_p2) is treated as affine with Z2
  implicitly 1 — the function body never reads a Z2 byte. The Lim-Lee
  comb evaluate loop relies on this: table entries are stored X,Y only
  in REU bank 2, fetched into P2, and folded via the mixed add without a
  Z=1 fill step. The only place a real Z=1 fill happens is the comb
  *seeding* branch (first non-zero column when the accumulator is still
  ∞, src/points256.s:1393-1400 and src/points384.s:1318-1325).

- **`ec_point_add_jj` / `ec_point_add_jj_384`** (Bernstein-Lange
  add-2007-bl, 11M + 5S + ~10 add/sub): **full Jacobian + Jacobian
  addition**. Both ec_p1 and ec_p2 are read as Jacobian points
  (including Z). Handles P1∞, P2∞, both∞, same projective point
  (tail-calls `ec_point_double`), and P1=-P2 (zeros ec_p3) natively.
  One added scratch slot per curve (`ec_jj_tmp` 32 B / `ec384_jj_tmp`
  48 B in src/data.s); the rest of the formula maps onto the existing
  `ec_t1..t6` slots.

The ECDSA verify pipeline (`ecdsa_verify_256` / `ecdsa_verify_384`)
uses `ec_point_add_jj` at the `u1*G + u2*Q` join: u1*G is held in a
persistent Jacobian buffer (`ecdsa_u1g_jac` 96 B / `ecdsa384_u1g_jac`
144 B in src/data.s) across the u2*Q scalar_mul, copied into ec_p2
just before the J+J call. This eliminates the affine conversion that
PR #26's cofactor compare landing had left in place (one binary-GCD
inversion + 3 mod-p multiplies per verify). The `@ev_r_from_u1g`
short-circuit branch from PR #26 is no longer needed: the J+J
primitive's native P2-infinity handling plus the cofactor compare's
`r * R.Z² ≡ R.X (mod p)` gate cover the u2*Q=infinity case uniformly
for both Z=1 and Z≠1 result lifts.

The mixed `ec_point_add` is still load-bearing for the Lim-Lee comb
evaluate loop — its affine-only fast path saves the 2 Z² multiplies the
J+J version pays. Both primitives stay in the library; consumers pick by
operand-shape need.

### ECDSA verify API

`ecdsa_verify_256` (src/ecdsa256.s) and `ecdsa_verify_384` (src/ecdsa384.s)
are packaged ECDSA verifiers with a big-endian ABI sized for direct
consumption by TLS callers (planned `c64-https` integration path).

- **Input:** pointer in A (low) / X (high) to a flat BE struct.
  P-256 struct is 160 B laid out as `r(32) | s(32) | h(32) | Qx(32) | Qy(32)`.
  P-384 struct is 240 B laid out as `r(48) | s(48) | h(48) | Qx(48) | Qy(48)`.
  All five fields are big-endian (wire order for X.509 / ASN.1 and SHA-2).
  Internally the verifier byte-reverses into the library's native LE via
  `fp_reverse32` / `fp_reverse48`.
- **Output:** carry flag. `C=0` VALID, `C=1` INVALID or malformed. No
  register-returned status byte; callers branch on `bcc` / `bcs`.
- **NOT constant-time.** Branches on bits of `r`, `s`, `h`, `Qx`, `Qy`,
  all of which are public inputs in the verify context (signature +
  peer certificate). A constant-time verify would be correct but strictly
  slower and is unnecessary for TLS. The library does NOT provide one;
  do not repurpose these routines for ECDSA *signing*.
- **Building blocks:** verify composes `ec_scalar_mul` (fixed-base
  `u1 * G`), `ec_scalar_mul_var` (variable-base `u2 * Q`), `ec_point_add`,
  `fp_mod_inv` (mod n for `w = s^-1`), and `fp_mod_mul_n` (mod-n multiply
  for `u1 = h*w`, `u2 = r*w`). All of those remain callable directly for
  consumers who want to drive the LE primitives without the BE wrapper.
- **Buffers:** ~448 B P-256 scratch (`ecdsa_r/s/h/qx/qy`, `ecdsa_w/u1/u2`,
  `ecdsa_u1_be/u2_be`, `ecdsa_u1g_jac` 96 B, `fp_rev_buf`) + ~675 B P-384
  equivalents (includes `ecdsa384_u1g_jac` 144 B, `ecdsa384_msg_struct_ptr`
  (2 B) and `ecdsa_result_msg_384` (1 B) added by
  `ecdsa_verify_with_message_384`), all declared in src/data.s. The
  `_u1g_jac` buffers replace the previous `ecdsa_u1g_x/y` affine pair
  (eliminated when the join switched from mixed `ec_point_add` to
  `ec_point_add_jj`; see "Jacobian addition naming" above).
- **`ecdsa_verify_with_message_384` (src/ecdsa384.s):** one-shot
  hash-then-verify wrapper. Same A/X-pointer ABI and 240 B BE struct
  layout as `ecdsa_verify_384` (the `h` slot is overwritten with the
  computed digest, so callers may leave it zero). Caller pre-sets ZP
  `sha_src` / `sha_len` to point at the message; the wrapper runs
  `sha384_init / sha384_update / sha384_final`, splices `sha384_digest`
  into struct[96..143], then tail-calls `ecdsa_verify_384`. C=0 valid /
  C=1 invalid (matches the underlying verify). **Streaming caveat:** the
  wrapper issues exactly one `sha384_update`; for TLS-style transcripts
  spanning multiple buffers, callers should drive
  `sha384_init / update (n times) / final` directly and then jsr
  `ecdsa_verify_384` with the digest already spliced into the h slot.
  No P-256/SHA-384 wrapper is provided: TLS 1.3 cipher-suite pairings
  are `secp256r1+SHA-256` and `secp384r1+SHA-384`, and only SHA-384 is
  implemented at present.

### SHA-384 hash API

`sha384_init` / `sha384_update` / `sha384_final` (src/sha384.s) implement
the FIPS 180-4 §6.4 SHA-384 streaming hash. Algorithm is the SHA-512
compression with the SHA-384 IV; on-chip output is `H[0..5]` truncated to
48 bytes (the SHA-384 spec discards `H[6..7]`).

- **Inputs:** `sha384_update` consumes `sha_len` bytes from `sha_src`
  (both ZP). The 16-bit length means a single update call caps at 64 KB;
  callers may chain multiple updates to absorb arbitrarily long messages.
- **Outputs:** `sha384_final` writes 48 BE bytes to `sha384_digest`.
  After `sha384_final`, the running state must be reset with
  `sha384_init` before any further calls.
- **Endianness on-chip:** 64-bit words are stored little-endian within
  each word (matches 6502 ADC carry propagation). Wire / FIPS-spec
  format is BE-within-word; byte reversal happens at the
  `sha_block_buf` ↔ `sha_w` boundary on each compression and at the
  digest output (and at the 128-bit length-tail encoding in the final
  pad block). See src/sha384.s lines 28-40 for the full endianness
  contract.
- **Buffers:** ~2 KB total in DATA — `sha_state` (64 B), `sha_w`
  (640 B), `sha_abcdefgh` (64 B), `sha_t` (16 B), `sha_scratch` (64 B),
  `sha_block_buf` (128 B), `sha_block_len` (1 B), `sha_total_len`
  (16 B), `sha384_digest` (48 B), plus a 1024 B `sha384_msg_buf` test
  scratch buffer (owned by the harness; consumers don't need to use it).
  K[80] round constants (640 B) live in RODATA inside src/sha384.s.
  ZP slots: `sha_src` (2 B), `sha_len` (2 B); plus internal-only
  `sha_w_ptr` (2 B) and `sha_w_ptr2` (2 B) used during compression.
- **Re-entrancy:** not re-entrant (same constraint as the rest of the
  library). No shared scratch with the field / point / ECDSA code paths,
  so SHA state is independent of curve work but a single SHA stream
  cannot be interleaved with itself.
- **Dependencies:** self-contained — no REU DMA, no shared
  `mul_*` / `fp_*` ZP slots. Safe to call without `sqtab_init` /
  `reu_mul_init` (though consumers that also want curve ops still need
  the curve init sequence).
- **Test coverage:** `tools/test_sha384.py`, oracle = `hashlib.sha384`.
  25/25 in `--full` mode: 4 mandatory FIPS 180-4 KATs + 17 random
  boundary lengths {0, 1, 17, 55, 56, 57, 63, 64, 111, 112, 113, 127,
  128, 129, 200, 255, 256} + 4 multi-block stress lengths {1023, 1024,
  1025, 4096}.
- **PRG growth:** 24322 B (pre-SHA) → 32022 B (post-SHA + wrapper),
  of which ~1.7 KB is the test scratch buffer.

### Conventions
- Scalars (private keys, nonces) are big-endian for compatibility with standards
- Field elements, curve parameters, and coordinates are little-endian
- P-256 point layout: X at offset 0, Y at offset 32, Z at offset 64 (96 bytes Jacobian)
- P-384 point layout: X at offset 0, Y at offset 48, Z at offset 96 (144 bytes Jacobian)
- ca65 assembler syntax (cc65 toolchain), 6502 CPU
- Multi-object build: each module is a separate compilation unit with explicit .import/.export
- Linker config: src/c64.cfg (segment placement, page alignment, PRG header)

### Calling contract / re-entrancy
Library routines are NOT re-entrant. The multiply DMA buffers
(`mul_dma_lo`/`mul_dma_hi` at $4b00/$4c00), the `mul_cached_a`/
`mul_src2_buf` scratch, and the `fp_src1`/`fp_src2`/`fp_dst`/`fp_misc`
zero-page slots are all clobbered by every field operation and are
shared between the P-256 and P-384 code paths. Sequential cross-curve
use is fine, but the host program must serialize all library calls:
do not invoke a field op (or anything that calls one, including
point-op and scalar-mul routines) from an IRQ handler while another
field op is running in mainline, or state will be corrupted. The
simplest safe pattern is to mask IRQs around a crypto operation, or
keep all library calls on a single thread of control.

### REU precompute table layout (Wave 7a h=8)
- P-256: bank 2, offset $0000..$3FFF, 256 entries x 64 bytes (X,Y only) = 16 KB
- P-384: bank 2, offset $4000..$9F9F, 256 entries x 96 bytes (X,Y only) = 24 KB
- Total used in bank 2: 40 KB of 64 KB (banks 0-1 hold multiply tables; bank 2 scratch $A000-$FFFF = 24 KB free)
- Tables are computed once at boot by `ec_precompute_256` and `ec_precompute_384`
- Boot cost at h=8: ~100s additional over h=4 baseline (~89s measured on P-384 bench tool; P-256 comparable)
- Windowed scalar_mul fetches table entries via REU DMA during the multiply loop

### Known issues
- **U64E CIA Timer A jiffy-rate drift between runs at 48 MHz** (observed
  2026-05-19, fw 3.14d). Two back-to-back ECDSA bench runs against
  the same `master` HEAD, on the same U64E (cold power-cycled between
  runs), produced 48-MHz jiffy counts ~3.8 % apart on every routine
  (`ec_scalar_mul_var`, `ec_scalar_mul_var_384`, `ecdsa_verify_256`,
  `ecdsa_verify_384` all drifted in lock-step), while Python-side
  `time.time()` wall-clock measurements matched within ±0.3 s. The
  CIA Timer A IRQ that ticks the C64 jiffy clock at $A0-$A2 is running
  ~3.8 % faster in some boot configurations than in others, despite
  identical fw, identical source, and identical bench tool. **16 MHz
  measurements are unaffected — today matches yesterday within
  ±1 jiffy across all routines.** Within-run deltas (e.g., comparing
  two routines in the same sweep) are unaffected because both
  measurements share the same wrong-by-3.8 % clock. Cross-day absolute
  comparison at 48 MHz needs a ±4 % tolerance band; for tighter
  cross-day comparison, either re-measure both endpoints in one run
  or compute the within-run delta against a reference primitive in
  the same sweep. Possibly related to U64E PAL/NTSC mode switching
  side effects across reboots; not fully diagnosed. Future bench
  tools that report "% improvement" across builds should measure
  baseline and target in the same bench invocation to immunise
  against this.
- **`sqtab` memory-map equate (`src/mul_8x8.s` line 19-20)**. The
  quarter-square multiply tables `sqtab_lo` and `sqtab_hi` live at the
  hard-coded equates `$9C00` / `$9E00` (1 KB total), bumped from the
  original `$7800` / `$7A00` on 2026-05-17 because code growth from the
  J+J primitives + SHA-384 LUTs + h=8 Lim-Lee anchors was pushing the
  linker-managed `mul_dma_lo` / `mul_dma_hi` page-aligned TABLES slots
  (in `src/data.s`) into the same address as `sqtab_lo`, silently
  clobbering the multiply table at `sqtab_init` time and hanging the
  `$02A7` boot sentinel. Same bug shape as the PR #27 / w-NAF re-land
  hang noted in MEMORY.md. The new address gives ~$0400 of headroom
  above the current top of DATA (~$988A) and stays below BASIC ROM
  `$A000`. The SMC page-delta math in `mul_8x8` is computed from the
  equates so the page-aligned-base constant-time invariant is preserved
  automatically. If future code growth threatens the new address, bump
  `sqtab_lo` / `sqtab_hi` higher (any page-aligned pair satisfying
  `sqtab_hi = sqtab_lo + $0200` works).
- **Issue #33-class REU register-residue defence (ported from
  c64-x25519 commit 817f525, 2026-05-10)**. The library's per-row REU
  DMA fetch in `fp_mul`/`fp_sqr` (256+384) writes only 3 of 8 REU
  registers per call, trusting `reu_reu_lo` (`$DF04`) and
  `reu_addr_ctrl` (`$DF0A`) remain `$00` from `reu_mul_init`'s tail.
  A caller that touched those two registers after boot (e.g. a sibling
  REU consumer) would have caused the row fetch to DMA from the wrong
  REU offset, silently producing a deterministic-but-wrong field
  result. Defence: defensive `lda #0 / sta reu_reu_lo / sta
  reu_addr_ctrl` at every public entry point that initiates DMA --
  `fp_mul`/`fp_sqr` (×2 curves), `ec_scalar_mul`/`_var` (×2 curves),
  `ecdsa_verify_256/384`. ~80 raw bytes of code, transparent runtime
  cost (6 cy per call). Same bug shape and fix as the x25519 sibling.
- Issue #14 (constant-time bug in `mul_8x8`) was
  remediated via Option B: the quarter-square primitive in `src/mul_8x8.s`
  was replaced with a branchless, SMC-dispatched implementation ported
  from `c64-ChaCha20-Poly1305` v0.3.0 `ct_mul_8x8`. The old body had two
  secret-dependent branches (`bcs :+` at |a-b|, `beq @s0` at sum-page
  dispatch); both were removed. In this project `mul_8x8` has only a
  single caller — `reu_mul_init` at boot — which walks `(a,b)` over the
  full `[0,255]^2` enumeration once, so the CT bug was theoretical only
  (no secret inputs ever reach the routine). The fix was taken anyway
  to prevent downstream confusion if a future consumer hot-paths it.
  Per-call cost: 86 cy body + 6 cy jsr = 92 cy at the call site, ~+42 cy
  vs the old ~46-50 cy average. Runtime impact: zero — no runtime field
  or point op calls `mul_8x8`. Boot-time impact: +2.8 M cy ≈ +2.8 s on
  a real C64 (lost in the ~120 s warp-mode init noise under VICE).
  `tools/test_inv_fast.py` and `tools/bench_p256.py` were ported from
  the stale `wait_for_text("READY.")` boot-wait pattern to the `$02A7`
  init sentinel pattern as collateral cleanup — both were broken on
  baseline because `main.s` ends in an infinite `jmp main_loop` and
  BASIC never regains control. See CHANGELOG.md "[Unreleased]".
- The `LDY #143 / BPL` infinity-fill bug family (BPL
  never branches on the first iteration because `$8F` bit 7 is set, so
  only one byte got written) was fixed in Wave 5 across all sites in
  `ec_point_double_384` and `ec_point_add_384`. The fix pattern is
  `LDY #144 / DEY / STA ec384_p3,Y / BNE loop` (count down through $00
  via BNE). `ec_point_add_384` and `ec_jacobian_to_affine_384` no longer
  require the Python-side pre-zero workaround.
- **LDA-clobbers-Z extension of the BPL bug family** (issue #17 Task #4).
  Hit again in `ec_scalar_mul_var_384`'s 144-byte Jacobian copy loops:
  the intuitive rewrite `ldy #0 / @l: lda src,y / sta dst,y / iny / cpy
  #144 / bne @l` is fine, but `ldy #0 / @l: lda src,y / sta dst,y / iny
  / bne @l` is NOT — with the terminator test elided, the loop relies on
  Y wrapping from $FF to $00, which only works for 256-byte blocks.
  The actual variant caught on src/points384.s was `ldx #144 / @l: ... /
  dex / bne @l` paired with a countdown: correct. The hazard worth
  remembering is that `LDA abs,y` always updates Z on the loaded byte,
  so any `BNE` intended to test a separate counter must either re-load
  the counter into a register that wasn't clobbered by the body (use
  `DEX / BNE` with X holding the counter and the body using Y for
  indexing), or explicitly re-test via `CPY` / `CPX` before the branch.
  Same remediation shape as the original BPL bug: prefer decrementing
  X and `BNE` against the known-preserved counter register. See
  Task #4 notes for the full site list.
- **CPY-clobbers-C between ADC iterations (sha384.s
  `sha_total_len`)**. Third pattern in the same forward-looking
  hazard family as the BPL infinity-fill bug and the LDA-clobbers-Z
  extension above. The 16-byte little-endian increment of
  `sha_total_len` (after each absorbed byte/block) was originally
  written as `ldy #0 / clc / @l: lda sha_total_len,y / adc #0 /
  sta sha_total_len,y / iny / cpy #16 / bne @l` to chain the carry
  across all 16 bytes. The bug: `CPY #16` updates the carry flag
  based on the comparison, destroying the ADC carry-out between
  iterations — so any byte that overflowed past the first one
  silently dropped its carry. Fix: fully unroll the 15-byte
  carry-propagation chain (no `CPY` between ADC steps); the
  unrolled form keeps C live across the chain. Forward-looking
  rule for arithmetic loops: any multi-precision ADC / SBC chain
  must use a counter register that does NOT itself touch C
  between steps, or the loop must be unrolled. `DEY / BNE` and
  `DEX / BNE` are safe (DEC* updates N/Z but preserves C);
  `CPY` / `CPX` / `CMP` are not.
- **Jiffy-clock / REU-DMA wall-clock non-linearity at U64E turbo**
  (issue #17 Task #12). `tools/bench_ecdsa_u64.py`'s "cycles" column
  is 1-MHz-equivalent wall-clock µs (jiffies × 17045), NOT machine
  cycles at turbo. The NTSC jiffy clock ticks at 60 Hz regardless of
  CPU turbo, and REU DMA runs at ~1 MHz regardless of CPU speed.
  Real wall-clock at 48 MHz is ~0.7× of 16 MHz wall (not 16/48 = 0.33×)
  across all four Task #9 primitives: a pure CPU-cycle extrapolation
  will overestimate the 48 MHz speedup by ~3×. Future bench tools MUST
  leave 3× headroom on per-call timeouts at turbo, or measure
  wall-clock directly via `time.monotonic()` rather than inferring it
  from jiffy-cycles. The original `max(60.0, base_timeout / mhz)`
  formula at `base_timeout=3600` yielded only 75 s at 48 MHz, which
  landed ~1 s short of `ecdsa_verify_384`'s intrinsic ~76 s wall time
  and misfired as a spurious per-call timeout. Current formula
  `max(180.0, 3 * base_timeout / mhz)` gives 225 s of headroom. Not
  a C64 bug; a bench-tool design rule.
