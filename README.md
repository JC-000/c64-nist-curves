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
- h=8 Lim-Lee fixed-base comb scalar multiplication with 256-entry REU-resident anchor table (Wave 7a)
- Deferred-doubling squaring (half as many doubling passes over cross terms)
- Carry-propagation INC fusion in fp_mul / fp_sqr accumulator spill
- Unrolled binary GCD shift loops for modular inversion
- Self-modifying dispatch in Solinas reduction

## Requirements

- [ACME](https://sourceforge.net/projects/acme-crossass/) cross-assembler
- [VICE](https://vice-emu.sourceforge.io/) emulator (for testing) with REU support
- Python 3.10+ with [c64-test-harness](https://github.com/JC-000/c64-test-harness)
- Python `cryptography` package (external oracle for point tests / benches)

## Build & Test

```bash
make                              # build nist-curves.prg
python3 tools/test_fp256.py       # P-256 field arithmetic tests
python3 tools/test_points256.py   # P-256 point ops (add --full for 10x random samples)
python3 tools/test_fp384.py       # P-384 field arithmetic tests
python3 tools/test_points384.py   # P-384 point ops (add --full for 10x random samples)
python3 tools/bench_p256.py       # P-256 benchmarks (oracle correctness gate)
python3 tools/bench_p384.py       # P-384 benchmarks (oracle correctness gate)
```

Point tests and benches validate every routine's output against an
external oracle (`cryptography` Python package plus NIST CAVP KATs
shipped in `tools/vectors/`). Benchmarks refuse to record cycles for
any routine that fails the gate. See `tools/vectors/README.md` for the
oracle invariant and refresh procedure.

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
| ec_scalar_mul (k=RFC 6979)  |       46733.3 |      131433.3 |         2.81x |

S/M ratio after Wave 4e: P-256 fp_mod_sqr / fp_mod_mul = 0.94; P-384 = 0.86.

Wave 7a doubled the Lim-Lee comb from h=4 to h=8 (256-entry table) on both
curves: P-256 `ec_scalar_mul` drops from 91.9M cycles (89.87 s) to 47.8M
cycles (46.73 s), a further **-48.0%** on top of Wave 5. P-384
`ec_scalar_mul_384` drops from 270.6M (264.57 s) to 134.4M (131.43 s),
**-50.3%**. Cumulatively versus the wNAF-5 baseline both curves are now
~4.3-5.0x faster in scalar multiply. Boot time grows by ~90 seconds to
build the 16 KB / 24 KB precompute tables in REU bank 2.

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
- **Wave 4d / 5c — CMO98 / Fay relative Jacobian doubling.** CMO98's
  advertised "4M + 4S" J^m doubling is measured against plain Jacobian
  doubling at 4M + 6S. Both `ec_point_double` and `ec_point_double_384`
  already use the a=-3 short-Weierstrass trick
  ((X - Z^2)(X + Z^2) = X^2 - Z^4), which gets standalone Jacobian
  doubling to exactly 4M + 4S on its own. CMO98 ties in operation count
  and loses in constants because it still needs a 1M aZ^4 carry update
  the a=-3 trick avoids. Fay 2014 relative / co-Z is a scalar_mul-level
  fused DoubleAdd restructure (not a drop-in doubling replacement) and
  is only applicable to window schemes; the Wave 5 Lim-Lee comb runs
  back-to-back doubling chains of length h=4 where Meloni reuse is
  unavailable for most doublings. See `.research/wave5c_p384.txt` for
  the full analysis.

## Wave 5 optimization round

Wave 5 replaced the width-5 wNAF scalar multiplier on both curves with a
4-way Lim-Lee fixed-base comb (h=4, 15-entry anchor table in REU bank 2):

- **Wave 5a — Lim-Lee comb for P-256.** `ec_scalar_mul` drops from
  206,431,995 cycles to 91,906,640 cycles (-55.5%) on the RFC 6979
  sample-message private key. 64 doublings + ~60 mixed adds replace
  256 doublings + ~51 adds.
- **Wave 5b — Lim-Lee comb for P-384.** `ec_scalar_mul_384` drops from
  the wNAF-5 baseline to 270,572,330 cycles. Same algorithmic shape as
  5a, adapted to the 384-bit scalar split into four 96-bit sub-scalars.
- **Wave 5c — CMO98 / Fay negative finding (P-384).** See Wave 4d/5c
  bullet above; documented in `.research/wave5c_p384.txt`.

## Wave 7a optimization round

Wave 7a doubles the Lim-Lee comb width from h=4 to h=8 on both curves.
The precompute table grows from 16 entries to 256 entries in REU bank 2:

- **P-256:** `ec_scalar_mul` drops from 91,906,640 cycles to 47,794,180
  cycles (-48.0%) on the RFC 6979 sample-message private key. The comb
  runs 32 iterations (1 double + up to 1 mixed add each) instead of 64.
  The precompute table occupies REU bank 2 `$0000`..`$3FFF` (16 KB).
- **P-384:** `ec_scalar_mul_384` drops from 270,572,330 cycles to
  134,416,870 cycles (-50.3%). 48 iterations instead of 96. The
  precompute table occupies REU bank 2 `$4000`..`$9F9F` (24 KB).
- **Boot cost:** building the 256-entry tables adds roughly 89 seconds
  of init time (measured via the P-384 bench tool: 17.6 s h=4 baseline
  to 106.3 s h=8). Within budget; deliberate trade for a one-shot
  per-process cost in exchange for ~2x per-call scalar_mul speedup.

## Status

- [x] P-256 field arithmetic with X25519 optimizations
- [x] Solinas fast reduction (both primes)
- [x] Point operations (Jacobian coordinates)
- [x] P-384 implementation
- [x] Benchmarking suite
- [x] Lim-Lee fixed-base comb scalar multiplication on both curves (h=4 Wave 5, upgraded to h=8 Wave 7a)
- [x] Comprehensive test suite (290 tests)
- [ ] Fermat inversion (addition chain): implemented for P-256 in
      `src/inv256.asm` but 41x slower than binary GCD, retained for reference
