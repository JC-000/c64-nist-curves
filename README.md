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
- 4-bit windowed scalar multiplication with REU-resident precompute table
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
| fp_mul (wide)               |        76.667 |       146.667 |         1.91x |
| fp_sqr (wide)               |        92.499 |       163.333 |         1.77x |
| fp_mod_add                  |         0.999 |         1.333 |         1.33x |
| fp_mod_sub                  |         0.666 |         1.167 |         1.75x |
| fp_mod_reduce (Solinas)     |         6.667 |         6.667 |         1.00x |
| fp_mod_mul                  |        83.333 |       151.666 |         1.82x |
| fp_mod_sqr                  |       100.000 |       170.000 |         1.70x |
| fp_mod_inv (binary GCD)     |       716.667 |      1550.000 |         2.16x |
| ec_point_double (Jacobian)  |       566.667 |      1033.333 |         1.82x |
| ec_point_add (Jacobian)     |       650.000 |      1166.667 |         1.79x |

## Status

- [x] P-256 field arithmetic with X25519 optimizations
- [x] Solinas fast reduction (both primes)
- [x] Point operations (Jacobian coordinates)
- [x] P-384 implementation
- [x] Benchmarking suite
- [x] 4-bit windowed scalar multiplication with REU-resident precompute table
- [x] Comprehensive test suite (290 tests)
- [ ] Fermat inversion (addition chain): implemented for P-256 in
      `src/inv256.asm` but 41x slower than binary GCD, retained for reference
