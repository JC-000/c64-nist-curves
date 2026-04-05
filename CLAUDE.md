# c64-nist-curves

## Project overview
P-256 and P-384 elliptic curve arithmetic optimized for the Commodore 64 (6502 CPU at 1 MHz). Optimizations ported from the c64-x25519 project.

## Build
```
make clean && make
```
Assembler: ACME. Output: build/nist-curves.prg + build/labels.txt (VICE symbol table).
Current PRG size: ~19.5 KB, loaded at $0801.

## Test
```
python3 tools/test_fp256.py          # 134 P-256 field arithmetic tests
python3 tools/test_points256.py      # 7 P-256 point operation tests
python3 tools/test_fp384.py          # 140 P-384 field arithmetic tests
python3 tools/test_points384.py      # 6 P-384 point operation tests
python3 tools/bench_p256.py          # P-256 primitive benchmarks
python3 tools/bench_p384.py          # P-384 primitive benchmarks
```
Tests use the c64-test-harness package (ViceInstanceManager). VICE must NOT be launched directly.

### Init sentinel pattern (replaces wait_for_text race)
The program writes `$42` to `$02A7` as the very last step of `start:` after all
init (sqtab, REU multiply tables, etc.) completes. Tests poll this sentinel
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
| main.asm | Entry point, VIC blanking, REU DMA init, benchmarking |
| constants.asm | Zero-page allocations, hardware addresses |
| mul_8x8.asm | Quarter-square 8x8->16 multiply tables |
| fp256.asm | 32-byte field arithmetic (add/sub/mul/sqr) with X25519 optimizations |
| mod256.asm | P-256 Solinas reduction, modular ops, binary GCD inverse, P-256 prime |
| curve256.asm | P-256 parameters + RFC 6979 test vectors (little-endian) |
| points256.asm | P-256 point double/add/scalar_mul, Jacobian->affine conversion |
| inv256.asm | P-256 Fermat inversion via addition chain (reference only; 41x slower than binary GCD) |
| fp384.asm | 48-byte field arithmetic (add/sub/mul/sqr) for P-384 |
| mod384.asm | P-384 Solinas reduction, modular ops, binary GCD inverse, P-384 prime |
| curve384.asm | P-384 parameters + test vectors (little-endian) |
| points384.asm | P-384 point double/add/scalar_mul, Jacobian->affine conversion |
| data.asm | Buffers, point storage, page-aligned DMA targets |

### Benchmarks
See `tools/bench_p256.py` and `tools/bench_p384.py`. Results in README.md.

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
- P-256 point layout: X at offset 0, Y at offset 32, Z at offset 64 (96 bytes Jacobian)
- P-384 point layout: X at offset 0, Y at offset 48, Z at offset 96 (144 bytes Jacobian)
- ACME assembler syntax, 6502 CPU

### Known issues
- `ec_point_double_384`'s infinity branch uses `LDY #143 / DEY / BPL loop` to zero
  `ec384_p3`. Because `$8F` has bit 7 set, BPL never branches on the first
  iteration, so only one byte gets written. Workaround: tests pre-zero
  `ec384_p3` from Python. Fix would be to change the loop to
  `LDY #144 / DEY / STA ec384_p3,Y / BNE loop` (count down through $00 via BNE).
