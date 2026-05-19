# Agent B1 — VICE primitive bench audit (2026-05-18)

## 1. Build info

- `git log -1 --oneline`: `7d71773 docs: capture PR #26 + #34 measured-vs-predicted ECDSA verify savings (#35)`
  - One docs-only commit above `788adc3` (the target HEAD the brief was written against). HEAD `7d71773` makes no source changes relative to `788adc3`, so the measurements below characterise both commits identically.
- PRG size: **37,302 bytes** (`build/nist-curves.prg`, load address `$0801`, matches the CLAUDE.md expected size).
- Build command: `make clean && make` — clean ca65/ld65 multi-object build emitting `build/nist-curves.prg`, `build/labels.txt`, `build/nist-curves.dbg`. All 18 object files compiled successfully.

## 2. P-256 bench output (verbatim)

Command: `python3.13 tools/bench_p256.py` (default Python 3.9 lacks `c64_test_harness`; project's `cryptography` oracle dependency is on `/opt/homebrew/bin/python3.13`).

```
Building...
Built: /Users/someone/Documents/c64-nist-curves/tools/../build/nist-curves.prg
Labels loaded: 34 required labels verified
VICE PID=61115, port=6551
Waiting for init sentinel...
Init complete after 207.6s

Running benchmarks (oracle correctness gate enabled)...
  fp_add (x100)... verified OK
  fp_sub (x100)... verified OK
  fp_mul (x20)... verified OK
  fp_sqr (x20)... verified OK
  fp_mod_add (x100)... verified OK
  fp_mod_sub (x100)... verified OK
  fp_mod_reduce256 (x20)... verified OK
  fp_mod_mul (x10)... verified OK
  fp_mod_sqr (x10)... verified OK
  fp_mod_inv (x1)... verified OK
  ec_point_double (x1)... verified OK
  ec_point_add (x1)... verified OK
  ec_scalar_mul (x1)... verified OK

================================================================================
P-256 Primitive Benchmarks (NTSC, 1.02 MHz, VIC blanked, 1 jiffy = 17045 cycles)
================================================================================
Routine               Loops   Jiffies   Cycles/call      ms/call
--------------------------------------------------------------------------------
fp_add                  100         5           852        0.833
fp_sub                  100         5           852        0.833
fp_mul                   20        90         76702       75.000
fp_sqr                   20        85         72441       70.833
fp_mod_add              100         5           852        0.833
fp_mod_sub              100         5           852        0.833
fp_mod_reduce256         20         8          6818        6.667
fp_mod_mul               10        49         83520       81.666
fp_mod_sqr               10        46         78407       76.667
fp_mod_inv                1        44        749980      733.333
ec_point_double           1        32        545440      533.333
ec_point_add              1        38        647710      633.333
ec_scalar_mul             1      2808      47862360    46800.000
================================================================================
```

All 13 P-256 routines passed the oracle correctness gate; no UNVERIFIED rows.

## 3. P-384 bench output (verbatim)

Command: `C64_SKIP_BUILD=1 python3.13 .research/audit_2026_05_18/bench_p384_extended_timeout.py` (this audit-local copy was deleted post-fix; the tracked `tools/bench_p384.py` now has the 600 s timeout — see §6 of the bench audit synthesis and the matching CHANGELOG entry)

Captured output (cycles-per-call authoritative from the bench's `jiffies × 17045` arithmetic):

```
Built: /Users/someone/Documents/c64-nist-curves/build/nist-curves.prg
Labels loaded: 34 required labels verified
VICE PID=63436, port=6511
Waiting for init sentinel...
Init complete after 205.6s

Running benchmarks (oracle correctness gate enabled)...
  fp_add_384 (x100)... verified OK
  fp_sub_384 (x100)... verified OK
  fp_mul_384 (x10)... verified OK
  fp_sqr_384 (x10)... verified OK
  fp_mod_add_384 (x100)... verified OK
  fp_mod_sub_384 (x100)... verified OK
  fp_mod_reduce384 (x10)... verified OK
  fp_mod_mul_384 (x10)... verified OK
  fp_mod_sqr_384 (x10)... verified OK
  fp_mod_inv_384 (x1)... verified OK
  ec_point_double_384 (x1)... verified OK
  ec_point_add_384 (x1)... verified OK
  ec_scalar_mul_384 (x1)... verified OK

================================================================================
P-384 Primitive Benchmarks (NTSC, 1.02 MHz, VIC blanked, 1 jiffy = 17045 cycles)
================================================================================
Routine                   Loops   Jiffies   Cycles/call      ms/call
--------------------------------------------------------------------------------
fp_add_384                  100         7          1193        1.167
fp_sub_384                  100         7          1193        1.167
fp_mul_384                   10        87        148291      145.000
fp_sqr_384                   10        74        126133      123.333
fp_mod_add_384              100         7          1193        1.167
fp_mod_sub_384              100         6          1022        0.999
fp_mod_reduce384             10         4          6818        6.667
fp_mod_mul_384               10        91        155109      151.666
fp_mod_sqr_384               10        78        132951      130.000
fp_mod_inv_384                1        93       1585185     1550.000
ec_point_double_384           1        57        971565      950.000
ec_point_add_384              1        66       1124970     1100.000
ec_scalar_mul_384             1      7925     135081625   132083.333
================================================================================
```

All 13 P-384 routines passed the oracle correctness gate; no UNVERIFIED rows.

## 4. Consolidated primitive cycle table

Cycles are the bench's authoritative `jiffies × 17045 / loops` rounded down (1 jiffy = 17,045 NTSC cycles).

| Routine                    | P-256 ms/call | P-256 cycles | P-384 ms/call | P-384 cycles | P-384/P-256 ratio |
|----------------------------|--------------:|-------------:|--------------:|-------------:|------------------:|
| fp_add                     |         0.833 |          852 |         1.167 |        1,193 |             1.40x |
| fp_sub                     |         0.833 |          852 |         1.167 |        1,193 |             1.40x |
| fp_mul (wide)              |        75.000 |       76,702 |       145.000 |      148,291 |             1.93x |
| fp_sqr (wide)              |        70.833 |       72,441 |       123.333 |      126,133 |             1.74x |
| fp_mod_add                 |         0.833 |          852 |         1.167 |        1,193 |             1.40x |
| fp_mod_sub                 |         0.833 |          852 |         0.999 |        1,022 |             1.20x |
| fp_mod_reduce (Solinas)    |         6.667 |        6,818 |         6.667 |        6,818 |             1.00x |
| fp_mod_mul                 |        81.666 |       83,520 |       151.666 |      155,109 |             1.86x |
| fp_mod_sqr                 |        76.667 |       78,407 |       130.000 |      132,951 |             1.70x |
| fp_mod_inv (binary GCD)    |       733.333 |      749,980 |      1550.000 |    1,585,185 |             2.11x |
| ec_point_double (Jacobian) |       533.333 |      545,440 |       950.000 |      971,565 |             1.78x |
| ec_point_add (Jacobian)    |       633.333 |      647,710 |      1100.000 |    1,124,970 |             1.74x |
| ec_scalar_mul (k=RFC 6979) |     46800.000 |   47,862,360 |    132083.333 |  135,081,625 |             2.82x |

Notes:
- The bench operand is a fixed pseudo-random P-256/P-384 base scalar (RFC 6979 nonce) — single-run sample, no input averaging. Single-jiffy quantum is 17,045 cycles, so any sub-100k-cycle measurement carries ±17 kcy quantization (visible in the fp_add/fp_sub/fp_mod_add cluster all collapsing to "5 jiffies").
- Single-run fp_mod_inv numbers are input-sensitive (binary-GCD); P-384's 1,585,185 cyc sample matches the README's 1,550,000-µs single sample to within 1 jiffy.

## 5. Comparison vs README (lines 60–74, NTSC primitive table)

README ms/call baseline (canonical column) vs measured this run. Deviation flagged when |Δ| > 2 %.

| Routine                    | README P-256 ms | This run P-256 | Δ P-256       | README P-384 ms | This run P-384 | Δ P-384       |
|----------------------------|----------------:|---------------:|:--------------|----------------:|---------------:|:--------------|
| fp_add                     |           0.666 |          0.833 | +25.1 % ▲     |           1.167 |          1.167 |  0.0 %        |
| fp_sub                     |           0.833 |          0.833 |  0.0 %        |           0.999 |          1.167 | +16.8 % ▲     |
| fp_mul (wide)              |          74.166 |         75.000 | +1.1 %        |         145.000 |        145.000 |  0.0 %        |
| fp_sqr (wide)              |          70.000 |         70.833 | +1.2 %        |         121.666 |        123.333 | +1.4 %        |
| fp_mod_add                 |           0.999 |          0.833 | −16.6 % ▼     |           1.167 |          1.167 |  0.0 %        |
| fp_mod_sub                 |           0.666 |          0.833 | +25.1 % ▲     |           1.167 |          0.999 | −14.4 % ▼     |
| fp_mod_reduce (Solinas)    |           6.667 |          6.667 |  0.0 %        |           6.667 |          6.667 |  0.0 %        |
| fp_mod_mul                 |          81.666 |         81.666 |  0.0 %        |         150.000 |        151.666 | +1.1 %        |
| fp_mod_sqr                 |          76.667 |         76.667 |  0.0 %        |         128.333 |        130.000 | +1.3 %        |
| fp_mod_inv (binary GCD)    |         716.667 |        733.333 | +2.3 % ▲      |        1550.000 |       1550.000 |  0.0 %        |
| ec_point_double (Jacobian) |         533.333 |        533.333 |  0.0 %        |         950.000 |        950.000 |  0.0 %        |
| ec_point_add (Jacobian)    |         633.333 |        633.333 |  0.0 %        |        1100.000 |       1100.000 |  0.0 %        |
| ec_scalar_mul (k=RFC 6979) |        46733.3  |      46800.000 | +0.1 %        |        131433.3 |     132083.333 | +0.5 %        |

Magnitude commentary:

- **Single-jiffy deltas dominate the >2 % rows.** Every flagged row sits at a count of either 5, 6, or 7 jiffies (an absolute difference of one jiffy = 17,045 cyc = ~16.7 µs at 1.02 MHz). At 100 loops, 5 vs 6 jiffies is exactly the difference between 0.833 ms/call and 0.999 ms/call. The bench's quantum is 1/60 s; below ~80 kcy the per-call cost is too small to resolve at single-loop granularity.
- **fp_add P-256** went 4→5 jiffies, **fp_mod_sub P-256** went 4→5 jiffies, **fp_mod_add P-256** went 6→5 jiffies. These look like quantum jitter at the rounding boundary: the field-add bodies have not changed between the README snapshot and `788adc3` (no relevant commits in the wave log touch `src/fp256.s` or `src/mod256.s` add/sub paths). Re-running the bench would likely flip some of these back.
- **fp_mod_inv P-256** is at +2.3 % (44 vs ~42 jiffies). Binary-GCD has input-sensitive runtime; the +1-jiffy bump is consistent with bench rerun jitter on a single sample, not a structural regression.
- **fp_sub P-384** at +16.8 % is a 6→7 jiffy bump; same quantum story as the P-256 add cluster.
- **Higher-fidelity routines (fp_mul, fp_sqr, fp_mod_mul, fp_mod_sqr, ec_point_double, ec_point_add, ec_scalar_mul)** all match README to within ±1.5 %. No structural drift detected.

Net assessment: **no real regression**. All deviations >2 % occur on routines whose per-call cost sits within ~1 jiffy of a rounding boundary; the dispatcher-level / wide-multiply / point-op rows reconcile cleanly with the README. The bench should be considered self-consistent at this commit.

## 6. Anomalies

- **P-384 bench sentinel timeout pre-existing at 180 s** (`tools/bench_p384.py` line 331), but the current h=8 Lim-Lee precompute boot path takes ~205-208 s on this host (P-256 bench measured 207.6 s, P-384 measured 205.6 s with extended budget). Running the tracked `tools/bench_p384.py` against current master produces an immediate `FATAL: init sentinel not set within timeout` — the bench is broken at HEAD without source modification. P-256 already uses a 600 s budget for the same sentinel and passes (`tools/bench_p256.py` line 406, sentinel loop `while time.time() - start < 600.0`). Workaround used by this audit: a working copy at `.research/audit_2026_05_18/bench_p384_extended_timeout.py` (not committed) with the timeout raised to 600 s, run via `C64_SKIP_BUILD=1 python3.13`. Suggested fix worth raising as a real PR: bump `bench_p384.py:331` from `180.0` to `600.0` to match `bench_p256.py:406`. This is a tracked-tool divergence and is independent of the audit measurements.
- **No UNVERIFIED routines.** Every single bench plan entry on both curves cleared the oracle correctness gate. The current master is structurally clean for the primitive surface.
- **Python interpreter selection.** Default `/usr/bin/python3` (3.9 on this macOS image) lacks `c64_test_harness`. The harness lives only on `/opt/homebrew/bin/python3.13`. Benches were run with the homebrew interpreter; this matches the harness install location reported by `pip show c64-test-harness`.
- **PRG size matches CLAUDE.md.** 37,302 bytes — consistent with the documented post-`788adc3` artifact. No silent code growth.
- **No bench hangs.** Both benches completed end-to-end within the budgeted wall time (P-256 ~4 minutes, P-384 ~5 minutes, dominated by init).

## Summary

VICE benches complete. All 26 primitive measurements (13 P-256 + 13 P-384) passed the oracle correctness gate; primitive cycles align with README baseline within ±1.5 % on the wide-multiply / point-op / scalar-mul rows; the >2 % deviations all sit at single-jiffy quantization boundaries on the cheap add/sub primitives (<6 kcy/call) and look like bench-rerun jitter rather than a structural change against `788adc3`.
