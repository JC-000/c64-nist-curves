# c64-nist-curves

Optimized NIST P-256 elliptic curve arithmetic for the Commodore 64.

## Features

- Full P-256 field arithmetic (256-bit add, subtract, multiply, square)
- Solinas fast reduction for the P-256 prime
- Jacobian coordinate point operations (double, add, scalar multiply)
- RFC 6979 test vector validation
- Optimizations ported from [c64-x25519](https://github.com/JC-000/c64-x25519):
  REU DMA multiply tables, self-modifying code, loop unrolling, dedicated squaring

## Requirements

- [ACME](https://sourceforge.net/projects/acme-crossass/) cross-assembler
- [VICE](https://vice-emu.sourceforge.io/) emulator (for testing)
- Python 3.10+ with [c64-test-harness](https://github.com/JC-000/c64-test-harness)

## Build & Test

```bash
make                              # build nist-curves.prg
python3 tools/test_fp256.py       # 134 field arithmetic tests
python3 tools/test_points256.py   # 7 point operation tests
```

## Status

- [x] P-256 field arithmetic with X25519 optimizations
- [x] Solinas fast reduction
- [x] Point operations (Jacobian coordinates)
- [x] Comprehensive test suite (141 tests)
- [ ] P-384 implementation
- [ ] Fermat inversion (addition chain, replacing binary GCD)
- [ ] Benchmarking suite
