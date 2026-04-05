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

## Requirements

- [ACME](https://sourceforge.net/projects/acme-crossass/) cross-assembler
- [VICE](https://vice-emu.sourceforge.io/) emulator (for testing) with REU support
- Python 3.10+ with [c64-test-harness](https://github.com/JC-000/c64-test-harness)

## Build & Test

```bash
make                              # build nist-curves.prg
python3 tools/test_fp256.py       # 134 P-256 field arithmetic tests
python3 tools/test_points256.py   # 7 P-256 point operation tests
python3 tools/test_fp384.py       # 140 P-384 field arithmetic tests
python3 tools/test_points384.py   # 6 P-384 point operation tests
python3 tools/bench_p256.py       # P-256 primitive benchmarks
python3 tools/bench_p384.py       # P-384 primitive benchmarks
```

## Benchmarks (NTSC, ~1.02 MHz, VIC blanked)

| Routine                     | P-256 ms/call | P-384 ms/call | P-384 / P-256 |
|-----------------------------|--------------:|--------------:|--------------:|
| fp_add                      |         0.833 |         1.333 |         1.60x |
| fp_sub                      |         0.833 |         0.999 |         1.20x |
| fp_mul (wide)               |       101.666 |       208.333 |         2.05x |
| fp_sqr (wide)               |        98.333 |       188.333 |         1.92x |
| fp_mod_add                  |         0.999 |         1.167 |         1.17x |
| fp_mod_sub                  |         0.666 |         1.167 |         1.75x |
| fp_mod_reduce (Solinas)     |        10.000 |        13.333 |         1.33x |
| fp_mod_mul                  |       111.666 |       221.666 |         1.98x |
| fp_mod_sqr                  |       108.333 |       201.666 |         1.86x |
| fp_mod_inv (binary GCD)     |      1050.000 |      2266.667 |         2.16x |
| ec_point_double (Jacobian)  |       750.000 |      1483.333 |         1.98x |
| ec_point_add (Jacobian)     |       850.000 |      1650.000 |         1.94x |

## Status

- [x] P-256 field arithmetic with X25519 optimizations
- [x] Solinas fast reduction (both primes)
- [x] Point operations (Jacobian coordinates)
- [x] P-384 implementation
- [x] Benchmarking suite
- [x] Comprehensive test suite (287 tests)
- [ ] Fermat inversion (addition chain): implemented for P-256 in
      `src/inv256.asm` but 41x slower than binary GCD, retained for reference
