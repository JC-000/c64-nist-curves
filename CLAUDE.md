# c64-nist-curves

## Project overview
P-256 (and future P-384) elliptic curve arithmetic optimized for the Commodore 64 (6502 CPU at 1 MHz). Optimizations ported from the c64-x25519 project.

## Build
```
make clean && make
```
Assembler: ACME. Output: build/nist-curves.prg + build/labels.txt (VICE symbol table).

## Test
```
python3 tools/test_fp256.py          # 134 field arithmetic tests
python3 tools/test_points256.py      # 7 point operation tests
```
Tests use the c64-test-harness package (ViceInstanceManager). VICE must NOT be launched directly.

## Architecture
All field elements are **little-endian** (byte 0 = LSB). This matches 6502 carry propagation.

### Source files (src/)
| File | Purpose |
|------|---------|
| main.asm | Entry point, VIC blanking, REU DMA init, benchmarking |
| constants.asm | Zero-page allocations, hardware addresses |
| mul_8x8.asm | Quarter-square 8x8->16 multiply tables |
| fp256.asm | 32-byte field arithmetic (add/sub/mul/sqr) with X25519 optimizations |
| mod256.asm | Solinas fast reduction, modular ops, binary GCD inverse, P-256 prime |
| curve256.asm | P-256 parameters + RFC 6979 test vectors (little-endian) |
| points256.asm | Point double/add/scalar_mul, Jacobian->affine conversion |
| data.asm | Buffers, point storage, page-aligned DMA targets |

### Key optimizations
- REU DMA multiply row caching (128KB lookup in REU)
- Self-modifying code for multiply accumulation addresses
- 2x unrolled inner multiply loop
- Dedicated squaring with symmetry exploitation
- Solinas fast reduction (replaces 512-iteration binary long division)
- VIC-II screen blanking (+20-25% CPU)

### Conventions
- Scalars (private keys, nonces) are big-endian for compatibility with standards
- Field elements, curve parameters, and coordinates are little-endian
- Point layout: X at offset 0, Y at offset 32, Z at offset 64 (96 bytes total, Jacobian)
- ACME assembler syntax, 6502 CPU
