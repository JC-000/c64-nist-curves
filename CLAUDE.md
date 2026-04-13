# c64-nist-curves

## Project overview
P-256 and P-384 elliptic curve arithmetic optimized for the Commodore 64 (6502 CPU at 1 MHz). Optimizations ported from the c64-x25519 project.

## Build
```
make clean && make
```
Assembler: ca65/ld65 (cc65 toolchain). Multi-object build: each .s file compiles
to a separate .o, linked by ld65 with `src/c64.cfg`. Output: build/nist-curves.prg
+ build/labels.txt (VICE symbol table, post-processed from ld65 `-Ln` format).
Current PRG size: ~20.2 KB (20672 bytes), loaded at $0801.

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
```
Tests use the c64-test-harness package (ViceInstanceManager). VICE must NOT be launched directly.

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
| main.s | Entry point, VIC blanking, REU DMA init, precompute table generation, benchmarking |
| constants.s | Hardware addresses, REU registers |
| zp_config.s | Zero-page allocations (consumer-tunable) |
| mul_8x8.s | Quarter-square 8x8->16 multiply tables |
| fp256.s | 32-byte field arithmetic (add/sub/mul/sqr) with X25519 optimizations |
| mod256.s | P-256 Solinas reduction, modular ops, binary GCD inverse, P-256 prime |
| curve256.s | P-256 parameters + RFC 6979 test vectors (little-endian) |
| points256.s | P-256 point double/add/windowed scalar_mul, Jacobian->affine, REU precompute |
| inv256.s | P-256 Fermat inversion via addition chain (reference only; 41x slower than binary GCD) |
| fp384.s | 48-byte field arithmetic (add/sub/mul/sqr) for P-384 |
| mod384.s | P-384 Solinas reduction, modular ops, binary GCD inverse, P-384 prime |
| curve384.s | P-384 parameters + test vectors (little-endian) |
| points384.s | P-384 point double/add/windowed scalar_mul, Jacobian->affine, REU precompute |
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

### Jacobian addition naming

`ec_point_add` (src/points256.s) and `ec_point_add_384` (src/points384.s) are
**mixed Jacobian+affine addition** routines (7M + 4S), NOT full
Jacobian+Jacobian adds. The second operand P2 is treated as affine with Z2
implicitly 1; the function body never reads a Z2 byte. The Lim-Lee comb
evaluate loop relies on this — table entries are stored X,Y only in REU
bank 2, fetched into P2, and folded via ec_point_add without any Z=1 fill
step. The name is retained for historical continuity but the body is a
mixed-add formula. The only place a real Z=1 fill happens is the comb
*seeding* branch (first non-zero column when the accumulator is still ∞,
src/points256.s:1393-1400 and src/points384.s:1318-1325).

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
- None outstanding. The `LDY #143 / BPL` infinity-fill bug family (BPL
  never branches on the first iteration because `$8F` bit 7 is set, so
  only one byte got written) was fixed in Wave 5 across all sites in
  `ec_point_double_384` and `ec_point_add_384`. The fix pattern is
  `LDY #144 / DEY / STA ec384_p3,Y / BNE loop` (count down through $00
  via BNE). `ec_point_add_384` and `ec_jacobian_to_affine_384` no longer
  require the Python-side pre-zero workaround.
