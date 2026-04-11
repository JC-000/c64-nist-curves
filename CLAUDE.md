# c64-nist-curves

## Project overview
P-256 and P-384 elliptic curve arithmetic optimized for the Commodore 64 (6502 CPU at 1 MHz). Optimizations ported from the c64-x25519 project.

## Build
```
make clean && make
```
Assembler: ACME. Output: build/nist-curves.prg + build/labels.txt (VICE symbol table).
Current PRG size: ~20.2 KB (20695 bytes post-Wave-7a), loaded at $0801.

## Test
```
python3 tools/test_fp256.py          # 134 P-256 field arithmetic tests
python3 tools/test_points256.py      # 8 P-256 point operation tests
python3 tools/test_fp384.py          # 140 P-384 field arithmetic tests
python3 tools/test_points384.py      # 8 P-384 point operation tests
python3 tools/bench_p256.py          # P-256 primitive benchmarks
python3 tools/bench_p384.py          # P-384 primitive benchmarks
```
Tests use the c64-test-harness package (ViceInstanceManager). VICE must NOT be launched directly.

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
| main.asm | Entry point, VIC blanking, REU DMA init, precompute table generation, benchmarking |
| constants.asm | Zero-page allocations, hardware addresses |
| mul_8x8.asm | Quarter-square 8x8->16 multiply tables |
| fp256.asm | 32-byte field arithmetic (add/sub/mul/sqr) with X25519 optimizations |
| mod256.asm | P-256 Solinas reduction, modular ops, binary GCD inverse, P-256 prime |
| curve256.asm | P-256 parameters + RFC 6979 test vectors (little-endian) |
| points256.asm | P-256 point double/add/windowed scalar_mul, Jacobian->affine, REU precompute |
| inv256.asm | P-256 Fermat inversion via addition chain (reference only; 41x slower than binary GCD) |
| fp384.asm | 48-byte field arithmetic (add/sub/mul/sqr) for P-384 |
| mod384.asm | P-384 Solinas reduction, modular ops, binary GCD inverse, P-384 prime |
| curve384.asm | P-384 parameters + test vectors (little-endian) |
| points384.asm | P-384 point double/add/windowed scalar_mul, Jacobian->affine, REU precompute |
| data.asm | Buffers, point storage, page-aligned DMA targets |

### Benchmarks
See `tools/bench_p256.py` and `tools/bench_p384.py`. Results in README.md.

### Key optimizations
- REU DMA multiply row caching (128KB lookup in REU)
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
  codebase. The dominant cost is REU DMA setup inside the inner-loop: tripling
  the number of leaves triples DMA setup overhead, which is not amortized by
  the 25% saving in 8x8 multiplies at this size. Would require a radically
  different DMA strategy (batched / persistent descriptors) or a larger N to
  break even.
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

### Conventions
- Scalars (private keys, nonces) are big-endian for compatibility with standards
- Field elements, curve parameters, and coordinates are little-endian
- P-256 point layout: X at offset 0, Y at offset 32, Z at offset 64 (96 bytes Jacobian)
- P-384 point layout: X at offset 0, Y at offset 48, Z at offset 96 (144 bytes Jacobian)
- ACME assembler syntax, 6502 CPU

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
