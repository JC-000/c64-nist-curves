# c64-nist-curves

Optimized NIST P-256 and P-384 elliptic curve arithmetic for the Commodore 64.

## Features

- Full P-256 field arithmetic (256-bit add, subtract, multiply, square)
- Full P-384 field arithmetic (384-bit add, subtract, multiply, square)
- Solinas fast reduction for both P-256 and P-384 primes
- Jacobian coordinate point operations (double, add, scalar multiply)
- RFC 6979 test vector validation
- Optimizations ported from [c64-x25519](https://github.com/JC-000/c64-x25519):
  REU DMA multiply tables, self-modifying code, loop unrolling, dedicated squaring
- Width-5 signed wNAF scalar multiplication with REU-resident precompute table
- Deferred-doubling squaring (half as many doubling passes over cross terms)
- Carry-propagation INC fusion in fp_mul / fp_sqr accumulator spill
- Unrolled binary GCD shift loops for modular inversion
- Self-modifying dispatch in Solinas reduction

## Requirements

- [ACME](https://sourceforge.net/projects/acme-crossass/) cross-assembler
- [VICE](https://vice-emu.sourceforge.io/) emulator (for testing) with REU support
- Python 3.10+ with [c64-test-harness](https://github.com/JC-000/c64-test-harness)

## Build & Test

```bash
make                              # build nist-curves.prg
python3 tools/test_fp256.py       # 134 P-256 field arithmetic tests
python3 tools/test_points256.py   # 8 P-256 point operation tests
python3 tools/test_fp384.py       # 140 P-384 field arithmetic tests
python3 tools/test_points384.py   # 8 P-384 point operation tests
python3 tools/bench_p256.py       # P-256 primitive benchmarks
python3 tools/bench_p384.py       # P-384 primitive benchmarks
```

## Benchmarks (NTSC, ~1.02 MHz, VIC blanked)

| Routine                     | P-256 ms/call | P-384 ms/call | P-384 / P-256 |
|-----------------------------|--------------:|--------------:|--------------:|
| fp_add                      |         0.666 |         1.167 |         1.75x |
| fp_sub                      |         0.833 |         0.999 |         1.20x |
| fp_mul (wide)               |        74.166 |       145.000 |         1.96x |
| fp_sqr (wide)               |        70.000 |       121.666 |         1.74x |
| fp_mod_add                  |         0.999 |         1.167 |         1.17x |
| fp_mod_sub                  |         0.666 |         1.167 |         1.75x |
| fp_mod_reduce (Solinas)     |         6.667 |         6.667 |         1.00x |
| fp_mod_mul                  |        81.666 |       150.000 |         1.84x |
| fp_mod_sqr                  |        76.667 |       128.333 |         1.67x |
| fp_mod_inv (binary GCD)     |       716.667 |      1550.000 |         2.16x |
| ec_point_double (Jacobian)  |       533.333 |       950.000 |         1.78x |
| ec_point_add (Jacobian)     |       633.333 |      1100.000 |         1.74x |

S/M ratio after Wave 4e: P-256 fp_mod_sqr / fp_mod_mul = 0.94; P-384 = 0.86.

## Wave 4 optimization round

Wave 4 landed three primitive-level wins and recorded two clean negative
findings. The full series history lives on the `optimization-wave-4a` branch.

Landed:

- **Wave 4a — width-5 signed wNAF.** Replaces the unsigned 4-bit window in
  `ec_scalar_mul_256` / `ec_scalar_mul_384` with a signed-digit recoding that
  halves the average non-zero digit density and uses point negation for the
  negative digits, cutting the number of point-adds per scalar multiply.
- **Wave 4b — carry-propagation INC fusion.** The accumulator spill path in
  `fp_mul` / `fp_sqr` for both 256 and 384 now folds multi-byte carry
  propagation into `INC abs,x` chains guarded by `BCC`, eliminating a pile of
  `LDA / ADC #0 / STA` cycles on every inner-loop spill.
- **Wave 4e — deferred-doubling fp_sqr.** Cross terms in the dedicated square
  path are accumulated once and doubled at the end instead of doubled on every
  accumulate, turning `fp_sqr` from ~1.2x `fp_mul` into ~0.94x (P-256) and
  ~0.84x (P-384). This required fixing a pre-existing carry-drop bug in the
  original deferred variant; see the `Wave 4e` commit.

Negative findings (investigated, reverted, documented for the record):

- **Wave 4c — one-level subtractive Karatsuba (N=32).** Three N=16 leaves plus
  the combine step cost more than the single N=32 multiply on this codebase.
  The dominant cost is REU DMA setup inside each leaf's inner loop: tripling
  the number of leaves triples the DMA setup overhead, which is not amortized
  by the 25% reduction in 8x8 multiplies at this size. Karatsuba would need
  either a much larger N or a radically different DMA strategy to break even.
- **Wave 4d — CMO98 / Fay relative Jacobian doubling.** The relative Jacobian
  formula saves 2S per doubling in exchange for some M's and bookkeeping. The
  savings only matter when S/M is comfortably below 1. Wave 4e pushed S/M to
  ~0.94 on P-256, which leaves too little headroom for the saved S's to beat
  the added bookkeeping. P-384 at S/M=0.86 is marginal (~3% headroom), noted
  below as a possible follow-up.

## Status

- [x] P-256 field arithmetic with X25519 optimizations
- [x] Solinas fast reduction (both primes)
- [x] Point operations (Jacobian coordinates)
- [x] P-384 implementation
- [x] Benchmarking suite
- [x] Width-5 signed wNAF scalar multiplication with REU-resident precompute table
- [x] Comprehensive test suite (290 tests)
- [ ] Fermat inversion (addition chain): implemented for P-256 in
      `src/inv256.asm` but 41x slower than binary GCD, retained for reference
- [ ] CMO98 / Fay relative-Jacobian doubling on P-384 (S/M=0.86 leaves ~3%
      headroom; not yet investigated whether bookkeeping fits into that budget)
