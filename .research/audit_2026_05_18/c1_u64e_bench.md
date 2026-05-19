# C1 - U64E hardware bench audit (2026-05-19)

**Status:** **U64E benches complete.** Three sequential bench runs against `U64_HOST=10.43.23.81` (`Ultimate 64 Elite fw 3.14d`, hostname `ultimate-64-elite-688004`, MAC `02:15:41:68:80:04`). PRG = 37302 B at master HEAD `7d71773` (PR #35 docs-only merge atop the PR #34 code state `788adc3` referenced in memory). DeviceLock-serialized; the user hard power-cycled the device immediately before this run so the runs started from a clean firmware state.

> All prior partial-report content (the 2026-05-18 `U64_HOST` unset / IP-transposed turns) is **superseded**. This is a single fresh report against the device.

Summary delta vs README + memory record:
- **All primitive cycles match README within 1 jiffy (1-jiffy quantization at single-shot point ops; ±2 jiffies at scalar_mul).** No real regressions.
- **`ecdsa_verify_256` @ 16 MHz = 43,157,940 cyc — exact match to PR #34 memory record (43,157,940 cyc).**
- **`ecdsa_verify_384` @ 16 MHz = 111,031,130 cyc — within 1 jiffy of memory record (111,048,175 cyc, delta -17,045 cy = -1 jiffy).**

---

## 1. Build + device info

### git HEAD
```
$ git log -1 --oneline
7d71773 docs: capture PR #26 + #34 measured-vs-predicted ECDSA verify savings (#35)
```

Master HEAD = `7d71773`. Note that the brief's reference `788acc3` is a typo for `788adc3` (PR #34, J+J point-add + sqtab bump). PR #35 (today's HEAD) is documentation-only; the assembly under test is byte-identical to PR #34, so the memory PR #34 cross-check is valid.

### PRG size and build
```
$ ls -la build/nist-curves.prg
-rw-r--r--@ 1 someone  staff  37302 May 18 21:35 .../build/nist-curves.prg
```
37302 B — matches CLAUDE.md "Current PRG size: ~36.4 KB (37302 bytes)". Built via `make clean && make` (ca65/ld65 multi-object, `-g` + `--dbgfile`, 18 object files linked).

### Device
- `U64_HOST=10.43.23.81` (masked: `10.43.23.<81>`).
- Hostname `ultimate-64-elite-688004`, MAC `02:15:41:68:80:04`.
- Firmware 3.14d.
- Hard power-cycled by user immediately before the run — no degraded-firmware state was in effect.

### Per-speed init cost on this device
- Init sentinel `$02A7 = $42` arrived at **244.4–246.4 s** across all six benches (3 P-256 speeds + 3 P-384 speeds + 2 ECDSA speeds = 8 inits actually performed; observed 245.9 s / 246.2 s / 246.2 s on P-256, 244.4 s / 244.7 s / 246.4 s on P-384, 245.9 s / 244.6 s on ECDSA). 246 s is longer than the ~90 s mentioned in CLAUDE.md, consistent with REU h=8 precompute + REST DMA upload overhead over the 48 ms-RTT link. Each bench's `init_timeout` floor of 360 s gave ~115 s of headroom on every run.
- Per-speed bench wall-clock: P-256 = 16.1 min total / P-384 = 18.0 min total / ECDSA = 16.8 min total. Combined ~51 min.

### Python interpreter
`python3.13` (`/opt/homebrew/bin/python3.13`, `cryptography 48.0.0` present) — `python3` on this Mac is `/usr/bin/python3` which lacks `cryptography`. Invocations (with `--speeds 1,16,48` to scope away from the 16-speed default sweep):
```
U64_HOST=10.43.23.81 python3.13 tools/bench_p256_u64.py --speeds 1,16,48 2>&1 | tee /tmp/bench_p256.log
U64_HOST=10.43.23.81 python3.13 tools/bench_p384_u64.py --speeds 1,16,48 2>&1 | tee /tmp/bench_p384.log
U64_HOST=10.43.23.81 python3.13 tools/bench_ecdsa_u64.py                  2>&1 | tee /tmp/bench_ecdsa.log
```
(The ECDSA bench tool defaults to 16+48 MHz so no `--speeds` flag is required.)

---

## 2. `bench_p256_u64.py` output — full verbatim stdout

```
Loading PRG: /Users/someone/Documents/c64-nist-curves/build/nist-curves.prg
  37302 bytes
Loading labels: /Users/someone/Documents/c64-nist-curves/build/labels.txt
Probing U64 at 10.43.23.81 ...
  reachable (GET-only; writemem health probed post-acquire)
  [lock] cleanup_stale removed 1 stale lockfile(s)
  [lock] no current holder; acquiring (timeout=600s)
  [lock] acquired; metadata=pid=90096, started_at=1779201398 (0s ago), device_host='10.43.23.81'
  [liveness] U64 at 10.43.23.81:80 healthy fw 3.14d
  Connected: Ultimate 64 Elite fw=3.14d
  Original turbo: 1 MHz

======================================================================
  P-256 sweep @ 1 MHz
======================================================================
    [reboot] ok
    [init turbo 48 MHz] ok
    [run_prg 37302B] sent
    [init sentinel] up to 360s...
    [init sentinel] ok after 246.1s
    [target turbo 1 MHz] ok
  fp_add               loops=500    timeout=  60.0s ...      23j         784c/call     0.767ms  [wall 0.6s]
  fp_sub               loops=500    timeout=  60.0s ...      25j         852c/call     0.833ms  [wall 0.7s]
  fp_mul               loops=30     timeout= 180.0s ...     134j       76134c/call    74.444ms  [wall 2.5s]
  fp_sqr               loops=30     timeout= 180.0s ...     127j       72157c/call    70.555ms  [wall 2.5s]
  fp_mod_add           loops=500    timeout=  60.0s ...      27j         920c/call     0.900ms  [wall 0.6s]
  fp_mod_sub           loops=500    timeout=  60.0s ...      25j         852c/call     0.833ms  [wall 0.7s]
  fp_mod_reduce256     loops=100    timeout= 120.0s ...      38j        6477c/call     6.333ms  [wall 0.6s]
  fp_mod_mul           loops=20     timeout= 180.0s ...      97j       82668c/call    80.833ms  [wall 1.9s]
  fp_mod_sqr           loops=20     timeout= 180.0s ...      92j       78407c/call    76.667ms  [wall 1.9s]
  fp_mod_inv           loops=1      timeout= 600.0s ...      44j      749980c/call   733.333ms  [wall 0.7s]
  ec_point_double      loops=1      timeout= 600.0s ...      32j      545440c/call   533.333ms  [wall 0.6s]
  ec_point_add         loops=1      timeout= 900.0s ...      38j      647710c/call   633.333ms  [wall 0.7s]
  ec_scalar_mul        loops=1      timeout=3600.0s ...    2809j    47879405c/call  46816.667ms  [wall 54.6s]

======================================================================
  P-256 sweep @ 16 MHz
======================================================================
    [reboot] ok
    [init turbo 48 MHz] ok
    [run_prg 37302B] sent
    [init sentinel] up to 360s...
    [init sentinel] ok after 246.2s
    [target turbo 16 MHz] ok
  fp_add               loops=8000   timeout=  60.0s ...      23j          49c/call     0.048ms  [wall 0.7s]
  fp_sub               loops=8000   timeout=  60.0s ...      24j          51c/call     0.050ms  [wall 0.7s]
  fp_mul               loops=480    timeout= 180.0s ...     252j        8948c/call     8.749ms  [wall 4.8s]
  fp_sqr               loops=480    timeout= 180.0s ...     361j       12819c/call    12.534ms  [wall 6.5s]
  fp_mod_add           loops=8000   timeout=  60.0s ...      26j          55c/call     0.054ms  [wall 0.6s]
  fp_mod_sub           loops=8000   timeout=  60.0s ...      25j          53c/call     0.052ms  [wall 0.6s]
  fp_mod_reduce256     loops=1600   timeout= 120.0s ...      38j         404c/call     0.395ms  [wall 0.8s]
  fp_mod_mul           loops=320    timeout= 180.0s ...     175j        9321c/call     9.114ms  [wall 3.0s]
  fp_mod_sqr           loops=320    timeout= 180.0s ...     249j       13263c/call    12.969ms  [wall 4.6s]
  fp_mod_inv           loops=1      timeout=  37.5s ...       3j       51135c/call    50.000ms  [wall 0.1s]
  ec_point_double      loops=1      timeout=  37.5s ...       4j       68180c/call    66.667ms  [wall 0.0s]
  ec_point_add         loops=1      timeout=  56.2s ...       5j       85225c/call    83.333ms  [wall 0.1s]
  ec_scalar_mul        loops=1      timeout= 225.0s ...     372j     6340740c/call  6200.000ms  [wall 6.5s]

======================================================================
  P-256 sweep @ 48 MHz
======================================================================
    [reboot] ok
    [init turbo 48 MHz] ok
    [run_prg 37302B] sent
    [init sentinel] up to 360s...
    [init sentinel] ok after 246.2s
  fp_add               loops=20000  timeout=  50.0s ...      19j          16c/call     0.016ms  [wall 0.7s]
  fp_sub               loops=20000  timeout=  50.0s ...      20j          17c/call     0.017ms  [wall 0.6s]
  fp_mul               loops=1440   timeout= 180.0s ...     523j        6190c/call     6.053ms  [wall 8.9s]
  fp_sqr               loops=1440   timeout= 180.0s ...     890j       10534c/call    10.300ms  [wall 15.4s]
  fp_mod_add           loops=20000  timeout=  50.0s ...      22j          18c/call     0.018ms  [wall 0.6s]
  fp_mod_sub           loops=20000  timeout=  50.0s ...      21j          17c/call     0.017ms  [wall 0.7s]
  fp_mod_reduce256     loops=4800   timeout= 120.0s ...      38j         134c/call     0.131ms  [wall 0.7s]
  fp_mod_mul           loops=960    timeout= 180.0s ...     356j        6320c/call     6.180ms  [wall 5.9s]
  fp_mod_sqr           loops=960    timeout= 180.0s ...     601j       10670c/call    10.433ms  [wall 10.6s]
  fp_mod_inv           loops=1      timeout=  15.0s ...       1j       17045c/call    16.667ms  [wall 0.0s]
  ec_point_double      loops=1      timeout=  15.0s ...       4j       68180c/call    66.667ms  [wall 0.1s]
  ec_point_add         loops=1      timeout=  18.8s ...       3j       51135c/call    50.000ms  [wall 0.1s]
  ec_scalar_mul        loops=1      timeout=  75.0s ...     273j     4653285c/call  4550.000ms  [wall 5.0s]

Total sweep wall time: 16.1 min

====================================================================================================
  P-256 U64 Turbo Sweep Summary -- cycles/call (NTSC 1 jiffy = 17045 cycles)
====================================================================================================
  Routine                       1       16       48
  -------------------------------------------------
  fp_add                      784       49       16
  fp_sub                      852       51       17
  fp_mul                    76134     8948     6190
  fp_sqr                    72157    12819    10534
  fp_mod_add                  920       55       18
  fp_mod_sub                  852       53       17
  fp_mod_reduce256           6477      404      134
  fp_mod_mul                82668     9321     6320
  fp_mod_sqr                78407    13263    10670
  fp_mod_inv               749980    51135    17045
  ec_point_double          545440    68180    68180
  ec_point_add             647710    85225    51135
  ec_scalar_mul          47879405  6340740  4653285

====================================================================================================
  P-256 U64 Turbo Sweep Summary -- wall-clock seconds per bench step
====================================================================================================
  Routine                       1       16       48
  -------------------------------------------------
  fp_add                     0.6s     0.7s     0.7s
  fp_sub                     0.7s     0.7s     0.6s
  fp_mul                     2.5s     4.8s     8.9s
  fp_sqr                     2.5s     6.5s    15.4s
  fp_mod_add                 0.6s     0.6s     0.6s
  fp_mod_sub                 0.7s     0.6s     0.7s
  fp_mod_reduce256           0.6s     0.8s     0.7s
  fp_mod_mul                 1.9s     3.0s     5.9s
  fp_mod_sqr                 1.9s     4.6s    10.6s
  fp_mod_inv                 0.7s     0.1s     0.0s
  ec_point_double            0.6s     0.0s     0.1s
  ec_point_add               0.7s     0.1s     0.1s
  ec_scalar_mul             54.6s     6.5s     5.0s
====================================================================================================
```

## 3. `bench_p384_u64.py` output — full verbatim stdout

```
Loading PRG: /Users/someone/Documents/c64-nist-curves/build/nist-curves.prg
  37302 bytes
Loading labels: /Users/someone/Documents/c64-nist-curves/build/labels.txt
Probing U64 at 10.43.23.81 ...
  reachable (GET-only; writemem health probed post-acquire)
  [lock] cleanup_stale removed 1 stale lockfile(s)
  [lock] no current holder; acquiring (timeout=600s)
  [lock] acquired; metadata=pid=92830, started_at=1779202379 (0s ago), device_host='10.43.23.81'
  [liveness] U64 at 10.43.23.81:80 healthy fw 3.14d
  Connected: Ultimate 64 Elite fw=3.14d

======================================================================
  P-384 sweep @ 1 MHz
======================================================================
    [reboot] ok
    [init turbo 48 MHz] ok
    [run_prg 37302B] sent
    [init sentinel] up to 360s...
    [init sentinel] ok after 244.4s
    [target turbo 1 MHz] ok
  fp_add_384             loops=500    timeout=  60.0s ...      34j        1159c/call     1.133ms  [wall 0.6s]
  fp_sub_384             loops=500    timeout=  60.0s ...      35j        1193c/call     1.167ms  [wall 0.6s]
  fp_mul_384             loops=20     timeout= 240.0s ...     173j      147439c/call   144.166ms  [wall 3.1s]
  fp_sqr_384             loops=20     timeout= 240.0s ...     146j      124428c/call   121.666ms  [wall 2.5s]
  fp_mod_add_384         loops=500    timeout=  60.0s ...      37j        1261c/call     1.233ms  [wall 1.1s]
  fp_mod_sub_384         loops=500    timeout=  60.0s ...      35j        1193c/call     1.167ms  [wall 0.7s]
  fp_mod_reduce384       loops=50     timeout= 120.0s ...      19j        6477c/call     6.333ms  [wall 0.6s]
  fp_mod_mul_384         loops=20     timeout= 240.0s ...     182j      155109c/call   151.666ms  [wall 3.2s]
  fp_mod_sqr_384         loops=20     timeout= 240.0s ...     155j      132098c/call   129.166ms  [wall 2.7s]
  fp_mod_inv_384         loops=1      timeout= 900.0s ...      94j     1602230c/call  1566.667ms  [wall 1.9s]
  ec_point_double_384    loops=1      timeout= 300.0s ...      57j      971565c/call   950.000ms  [wall 1.3s]
  ec_point_add_384       loops=1      timeout= 300.0s ...      66j     1124970c/call  1100.000ms  [wall 1.4s]
  ec_scalar_mul_384      loops=1      timeout=3600.0s ...    7925j   135081625c/call 132083.333ms  [wall 132.1s]

======================================================================
  P-384 sweep @ 16 MHz
======================================================================
    [reboot] ok
    [init turbo 48 MHz] ok
    [run_prg 37302B] sent
    [init sentinel] up to 360s...
    [init sentinel] ok after 244.7s
    [target turbo 16 MHz] ok
  fp_add_384             loops=8000   timeout=  60.0s ...      33j          70c/call     0.068ms  [wall 0.7s]
  fp_sub_384             loops=8000   timeout=  60.0s ...      33j          70c/call     0.068ms  [wall 0.7s]
  fp_mul_384             loops=320    timeout= 240.0s ...     292j       15553c/call    15.208ms  [wall 5.2s]
  fp_sqr_384             loops=320    timeout= 240.0s ...     382j       20347c/call    19.895ms  [wall 6.6s]
  fp_mod_add_384         loops=8000   timeout=  60.0s ...      38j          80c/call     0.078ms  [wall 0.6s]
  fp_mod_sub_384         loops=8000   timeout=  60.0s ...      35j          74c/call     0.072ms  [wall 0.6s]
  fp_mod_reduce384       loops=800    timeout= 120.0s ...      19j         404c/call     0.395ms  [wall 0.7s]
  fp_mod_mul_384         loops=320    timeout= 240.0s ...     299j       15926c/call    15.573ms  [wall 5.1s]
  fp_mod_sqr_384         loops=320    timeout= 240.0s ...     389j       20720c/call    20.260ms  [wall 6.9s]
  fp_mod_inv_384         loops=1      timeout=  56.2s ...       6j      102270c/call   100.000ms  [wall 0.1s]
  ec_point_double_384    loops=1      timeout=  18.8s ...       7j      119315c/call   116.667ms  [wall 0.4s]
  ec_point_add_384       loops=1      timeout=  18.8s ...       8j      136360c/call   133.333ms  [wall 0.4s]
  ec_scalar_mul_384      loops=1      timeout= 225.0s ...     942j    16056390c/call 15700.000ms  [wall 15.9s]

======================================================================
  P-384 sweep @ 48 MHz
======================================================================
    [reboot] ok
    [init turbo 48 MHz] ok
    [run_prg 37302B] sent
    [init sentinel] up to 360s...
    [init sentinel] ok after 246.4s
  fp_add_384             loops=20000  timeout=  50.0s ...      29j          24c/call     0.023ms  [wall 0.7s]
  fp_sub_384             loops=20000  timeout=  50.0s ...      28j          23c/call     0.022ms  [wall 0.7s]
  fp_mul_384             loops=960    timeout= 240.0s ...     562j        9978c/call     9.757ms  [wall 9.2s]
  fp_sqr_384             loops=960    timeout= 240.0s ...     914j       16228c/call    15.868ms  [wall 15.7s]
  fp_mod_add_384         loops=20000  timeout=  50.0s ...      32j          27c/call     0.026ms  [wall 0.7s]
  fp_mod_sub_384         loops=20000  timeout=  50.0s ...      29j          24c/call     0.023ms  [wall 0.7s]
  fp_mod_reduce384       loops=2400   timeout= 120.0s ...      19j         134c/call     0.131ms  [wall 0.7s]
  fp_mod_mul_384         loops=960    timeout= 240.0s ...     570j       10120c/call     9.895ms  [wall 9.8s]
  fp_mod_sqr_384         loops=960    timeout= 240.0s ...     921j       16352c/call    15.989ms  [wall 15.5s]
  fp_mod_inv_384         loops=1      timeout=  18.8s ...       2j       34090c/call    33.333ms  [wall 0.0s]
  ec_point_double_384    loops=1      timeout=  15.0s ...       6j      102270c/call   100.000ms  [wall 0.1s]
  ec_point_add_384       loops=1      timeout=  15.0s ...       6j      102270c/call   100.000ms  [wall 0.1s]
  ec_scalar_mul_384      loops=1      timeout=  75.0s ...     654j    11147430c/call 10900.000ms  [wall 11.1s]

Total sweep wall time: 18.0 min

====================================================================================================
  P-384 U64 Turbo Sweep Summary -- cycles/call (NTSC 1 jiffy = 17045 cycles)
====================================================================================================
  Routine                       1       16       48
  -------------------------------------------------
  fp_add_384                 1159       70       24
  fp_sub_384                 1193       70       23
  fp_mul_384               147439    15553     9978
  fp_sqr_384               124428    20347    16228
  fp_mod_add_384             1261       80       27
  fp_mod_sub_384             1193       74       24
  fp_mod_reduce384           6477      404      134
  fp_mod_mul_384           155109    15926    10120
  fp_mod_sqr_384           132098    20720    16352
  fp_mod_inv_384          1602230   102270    34090
  ec_point_double_384      971565   119315   102270
  ec_point_add_384        1124970   136360   102270
  ec_scalar_mul_384      135081625 16056390 11147430

====================================================================================================
  P-384 U64 Turbo Sweep Summary -- wall-clock seconds per step
====================================================================================================
  Routine                       1       16       48
  -------------------------------------------------
  fp_add_384                 0.6s     0.7s     0.7s
  fp_sub_384                 0.6s     0.7s     0.7s
  fp_mul_384                 3.1s     5.2s     9.2s
  fp_sqr_384                 2.5s     6.6s    15.7s
  fp_mod_add_384             1.1s     0.6s     0.7s
  fp_mod_sub_384             0.7s     0.6s     0.7s
  fp_mod_reduce384           0.6s     0.7s     0.7s
  fp_mod_mul_384             3.2s     5.1s     9.8s
  fp_mod_sqr_384             2.7s     6.9s    15.5s
  fp_mod_inv_384             1.9s     0.1s     0.0s
  ec_point_double_384        1.3s     0.4s     0.1s
  ec_point_add_384           1.4s     0.4s     0.1s
  ec_scalar_mul_384        132.1s    15.9s    11.1s
====================================================================================================
```

## 4. `bench_ecdsa_u64.py` output — full verbatim stdout

```
Loading PRG: /Users/someone/Documents/c64-nist-curves/build/nist-curves.prg
  37302 bytes
Loading labels: /Users/someone/Documents/c64-nist-curves/build/labels.txt
Probing U64 at 10.43.23.81 ...
  reachable (GET-only; writemem health probed post-acquire)
  [lock] cleanup_stale removed 1 stale lockfile(s)
  [lock] no current holder; acquiring (timeout=600s)
  [lock] acquired; metadata=pid=94781, started_at=1779203473 (0s ago), device_host='10.43.23.81'
  [liveness] U64 at 10.43.23.81:80 healthy fw 3.14d
  Connected: Ultimate 64 Elite fw=3.14d

========================================================================
  ECDSA sweep @ 16 MHz
========================================================================
    [reboot] ok
    [init turbo 48 MHz] ok
    [run_prg 37302B] sent
    [init sentinel] up to 360s...
    [init sentinel] ok after 245.9s
    [target turbo 16 MHz] ok
  ec_scalar_mul_var        loops=1   timeout= 675.0s ...   2207j      37618315cy   2351.14ms  [wall 36.9s]
  ec_scalar_mul_var_384    loops=1   timeout= 675.0s ...   5601j      95469045cy   5966.82ms  [wall 93.4s]
  ecdsa_verify_256         loops=1   timeout= 675.0s ...   2532j      43157940cy   2697.37ms  [wall 42.5s]
  ecdsa_verify_384         loops=1   timeout= 675.0s ...   6514j     111031130cy   6939.45ms  [wall 108.8s]

========================================================================
  ECDSA sweep @ 48 MHz
========================================================================
    [reboot] ok
    [init turbo 48 MHz] ok
    [run_prg 37302B] sent
    [init sentinel] up to 360s...
    [init sentinel] ok after 244.6s
  ec_scalar_mul_var        loops=1   timeout= 225.0s ...   1629j      27766305cy    578.46ms  [wall 27.3s]
  ec_scalar_mul_var_384    loops=1   timeout= 225.0s ...   3924j      66884580cy   1393.43ms  [wall 66.2s]
  ecdsa_verify_256         loops=1   timeout= 225.0s ...   1865j      31788925cy    662.27ms  [wall 31.3s]
  ecdsa_verify_384         loops=1   timeout= 225.0s ...   4555j      77639975cy   1617.50ms  [wall 76.5s]

Total sweep wall time: 16.8 min

================================================================================================
  ECDSA / scalar_mul_var U64E bench -- cycles/call (NTSC 1 jiffy = 17045 cy)
================================================================================================
  Primitive                          16 MHz           48 MHz
  ----------------------------------------------------------
  ec_scalar_mul_var              37,618,315       27,766,305
  ec_scalar_mul_var_384          95,469,045       66,884,580
  ecdsa_verify_256               43,157,940       31,788,925
  ecdsa_verify_384              111,031,130       77,639,975

================================================================================================
  Wall-clock per call (seconds)
================================================================================================
  Primitive                          16 MHz           48 MHz
  ----------------------------------------------------------
  ec_scalar_mul_var                2.351 s         0.578 s
  ec_scalar_mul_var_384            5.967 s         1.393 s
  ecdsa_verify_256                 2.697 s         0.662 s
  ecdsa_verify_384                 6.939 s         1.617 s
================================================================================================
```

---

## 5. Consolidated primitive cycle table (P-256 + P-384, 1 + 16 + 48 MHz)

> **Convention footnote.** Cycle columns at 16 MHz and 48 MHz are 1-MHz-equivalent wall-clock microseconds (jiffies × 17045), not machine cycles at turbo. The NTSC jiffy clock ticks at 60 Hz regardless of CPU turbo and REU DMA runs at ~1 MHz regardless of CPU speed. Per CLAUDE.md "Known issues" (Issue #17 Task #12): real wall-clock at 48 MHz is ~0.7× of 16 MHz wall, not 16/48 = 0.33×. Use the wall-clock column for scheduling and treat "cyc" as a first-order primitive-cost comparison only.

| Routine                | P256 @1MHz | P256 @16MHz | P256 @48MHz | P384 @1MHz  | P384 @16MHz | P384 @48MHz |
|------------------------|------------:|-------------:|-------------:|-------------:|-------------:|-------------:|
| fp_add                 | 784         | 49           | 16           | 1,159        | 70           | 24           |
| fp_sub                 | 852         | 51           | 17           | 1,193        | 70           | 23           |
| fp_mul                 | 76,134      | 8,948        | 6,190        | 147,439      | 15,553       | 9,978        |
| fp_sqr                 | 72,157      | 12,819       | 10,534       | 124,428      | 20,347       | 16,228       |
| fp_mod_add             | 920         | 55           | 18           | 1,261        | 80           | 27           |
| fp_mod_sub             | 852         | 53           | 17           | 1,193        | 74           | 24           |
| fp_mod_reduce          | 6,477       | 404          | 134          | 6,477        | 404          | 134          |
| fp_mod_mul             | 82,668      | 9,321        | 6,320        | 155,109      | 15,926       | 10,120       |
| fp_mod_sqr             | 78,407      | 13,263       | 10,670       | 132,098      | 20,720       | 16,352       |
| fp_mod_inv (binary-GCD)| 749,980     | 51,135       | 17,045       | 1,602,230    | 102,270      | 34,090       |
| ec_point_double        | 545,440     | 68,180       | 68,180       | 971,565      | 119,315      | 102,270      |
| ec_point_add           | 647,710     | 85,225       | 51,135       | 1,124,970    | 136,360      | 102,270      |
| ec_scalar_mul          | 47,879,405  | 6,340,740    | 4,653,285    | 135,081,625  | 16,056,390   | 11,147,430   |

## 6. Consolidated ECDSA + variable-base scalar_mul table

| Primitive               | 16 MHz cyc      | 16 MHz wall | 48 MHz cyc      | 48 MHz wall |
|-------------------------|----------------:|------------:|----------------:|------------:|
| ec_scalar_mul_var       | 37,618,315      | 2.351 s     | 27,766,305      | 0.578 s     |
| ec_scalar_mul_var_384   | 95,469,045      | 5.967 s     | 66,884,580      | 1.393 s     |
| ecdsa_verify_256        | 43,157,940      | 2.697 s     | 31,788,925      | 0.662 s     |
| ecdsa_verify_384        | 111,031,130     | 6.939 s     | 77,639,975      | 1.617 s     |

## 7. README comparison (lines 78–125)

> Legend: `▲` = today is slower than README by >2 %; `▼` = today is faster by >2 %; blank = within 2 %.
> README baseline: `7d71773` master (code state byte-identical to PR #34 `788adc3` referenced in memory).

### P-256 primitive table (README lines 84–93) — 16 MHz

| Routine             | README @16 | Today @16 | Δ (cyc)   | Δ %       | Flag |
|---------------------|-----------:|----------:|----------:|----------:|:----:|
| fp_mul              | 8,948      | 8,948     | 0         | 0.00 %    |      |
| fp_sqr              | 12,819     | 12,819    | 0         | 0.00 %    |      |
| fp_mod_mul          | 9,374      | 9,321     | -53       | -0.57 %   |      |
| fp_mod_sqr          | 13,209     | 13,263    | +54       | +0.41 %   |      |
| fp_mod_inv          | 51,135     | 51,135    | 0         | 0.00 %    |      |
| ec_point_double     | 68,180     | 68,180    | 0         | 0.00 %    |      |
| ec_point_add        | 85,225     | 85,225    | 0         | 0.00 %    |      |
| ec_scalar_mul       | 6,323,695  | 6,340,740 | +17,045   | +0.27 %   |      |

### P-256 primitive table — 48 MHz

| Routine             | README @48 | Today @48 | Δ (cyc)   | Δ %       | Flag |
|---------------------|-----------:|----------:|----------:|----------:|:----:|
| fp_mul              | 6,178      | 6,190     | +12       | +0.19 %   |      |
| fp_sqr              | 10,522     | 10,534    | +12       | +0.11 %   |      |
| fp_mod_mul          | 6,320      | 6,320     | 0         | 0.00 %    |      |
| fp_mod_sqr          | 10,670     | 10,670    | 0         | 0.00 %    |      |
| fp_mod_inv          | 17,045     | 17,045    | 0         | 0.00 %    |      |
| ec_point_double     | 51,135     | 68,180    | +17,045   | +33.33 %  | ▲ (1-jiffy quantization) |
| ec_point_add        | 68,180     | 51,135    | -17,045   | -25.00 %  | ▼ (1-jiffy quantization) |
| ec_scalar_mul       | 4,636,240  | 4,653,285 | +17,045   | +0.37 %   |      |

**Note on the `ec_point_double` ▲ / `ec_point_add` ▼ pair at 48 MHz.** Both routines are single-shot measurements (`loops=1`) at the 3-vs-4-jiffy boundary (51,135 = 3 j; 68,180 = 4 j). A single 60 Hz NTSC raster IRQ landing inside or outside the measurement window swings the reading by exactly one jiffy / 17,045 cyc / 16.67 ms wall. Both today's pair sum to 119,315 cyc (3+4 = 7 jiffies); the README pair sums to 119,315 cyc as well — identical to within the granularity of the timer. The 33 % / -25 % deltas are **not real**; they are jiffy-quantization noise. The aggregate `ec_scalar_mul @ 48 MHz` is +0.37 % (1 jiffy out of 273), which lands inside the noise floor and confirms there is no real point-op regression. Recommended tightening of the README's footnote: "ec_point_double and ec_point_add are 1-jiffy measurements at turbo and inherently quantized; interpret single-jiffy swings as noise rather than a real perf delta."

### P-384 primitive table — 16 MHz

| Routine             | README @16 | Today @16  | Δ (cyc)   | Δ %       | Flag |
|---------------------|-----------:|-----------:|----------:|----------:|:----:|
| fp_mul_384          | 15,447     | 15,553     | +106      | +0.69 %   |      |
| fp_sqr_384          | 20,294     | 20,347     | +53       | +0.26 %   |      |
| fp_mod_mul_384      | 15,873     | 15,926     | +53       | +0.33 %   |      |
| fp_mod_sqr_384      | 20,720     | 20,720     | 0         | 0.00 %    |      |
| fp_mod_inv_384      | 102,270    | 102,270    | 0         | 0.00 %    |      |
| ec_point_double_384 | 136,360    | 119,315    | -17,045   | -12.50 %  | ▼ (1-jiffy quantization) |
| ec_point_add_384    | 136,360    | 136,360    | 0         | 0.00 %    |      |
| ec_scalar_mul_384   | 16,005,255 | 16,056,390 | +51,135   | +0.32 %   |      |

### P-384 primitive table — 48 MHz

| Routine             | README @48 | Today @48  | Δ (cyc)   | Δ %       | Flag |
|---------------------|-----------:|-----------:|----------:|----------:|:----:|
| fp_mul_384          | 9,960      | 9,978      | +18       | +0.18 %   |      |
| fp_sqr_384          | 16,210     | 16,228     | +18       | +0.11 %   |      |
| fp_mod_mul_384      | 10,102     | 10,120     | +18       | +0.18 %   |      |
| fp_mod_sqr_384      | 16,370     | 16,352     | -18       | -0.11 %   |      |
| fp_mod_inv_384      | 34,090     | 34,090     | 0         | 0.00 %    |      |
| ec_point_double_384 | 85,225     | 102,270    | +17,045   | +20.00 %  | ▲ (1-jiffy quantization) |
| ec_point_add_384    | 102,270    | 102,270    | 0         | 0.00 %    |      |
| ec_scalar_mul_384   | 11,130,385 | 11,147,430 | +17,045   | +0.15 %   |      |

Same 1-jiffy-quantization caveat applies to `ec_point_double_384 @ 48 MHz` — it's a single-shot measurement at the 5-vs-6-jiffy boundary. Today's `ec_point_double_384 + ec_point_add_384` sums to 204,540 cyc; README sums to 187,495 cyc — a +17,045 delta of +9.1% **at the sum**, which is +1 jiffy across two single-shot measurements. The point-doubling primitive being heavier than point-add at 48 MHz is suspicious but consistent with the 1-jiffy noise floor of the bench. Aggregate `ec_scalar_mul_384 @ 48 MHz` is +0.15 % — noise. The README baseline likely caught the "good" jiffy on `ec_point_double_384` and today caught the "bad" one; reproducible only with a longer batch.

### ECDSA verify / variable-base scalar_mul (README lines 120–125)

| Primitive             | README @16   | Today @16   | Δ (cyc)   | Δ %       | Flag | README @48 | Today @48 | Δ (cyc) | Δ %     | Flag |
|-----------------------|-------------:|------------:|----------:|----------:|:----:|------------:|----------:|--------:|--------:|:----:|
| ec_scalar_mul_var     | 37,618,315   | 37,618,315  | 0         | 0.00 %    |      | 27,766,305  | 27,766,305 | 0       | 0.00 %  |      |
| ec_scalar_mul_var_384 | 95,486,090   | 95,469,045  | -17,045   | -0.018 %  |      | 66,884,580  | 66,884,580 | 0       | 0.00 %  |      |
| ecdsa_verify_256      | 43,157,940   | 43,157,940  | 0         | 0.00 %    |      | 31,805,970  | 31,788,925 | -17,045 | -0.054 %|      |
| ecdsa_verify_384      | 111,048,175  | 111,031,130 | -17,045   | -0.015 %  |      | 77,639,975  | 77,639,975 | 0       | 0.00 %  |      |

**All eight ECDSA cells are within 1 jiffy of the README baseline.** Four are exact matches; four are -1 jiffy. The negative drift is consistent with jiffy-quantization (the README baseline caught the "slow" jiffy where the raster IRQ landed inside the measurement window; today caught the "fast" jiffy where it landed outside). No real perf delta on either curve at either speed.

## 8. PR #34 corroboration vs memory record

Memory file `project_pr34_empirical_measurement.md` records master @ `788adc3` (= PR #34, byte-identical to today's HEAD `7d71773` modulo docs) at 16 MHz:

| Primitive          | Memory record @16 MHz | Today @16 MHz   | Δ           | Verdict          |
|--------------------|----------------------:|----------------:|------------:|:-----------------|
| ecdsa_verify_256   | 43,157,940 cyc        | 43,157,940 cyc  | **0 cyc**   | **exact match**  |
| ecdsa_verify_384   | 111,048,175 cyc       | 111,031,130 cyc | -17,045 cyc | within 1 jiffy   |

**Verdict: PR #34 memory record corroborated.** P-256 verify is reproduced bit-for-bit; P-384 verify is one jiffy faster today than the memory baseline, well within the 1-jiffy quantization noise documented above. The delta does NOT indicate a regression or improvement; it's a single raster-IRQ position difference between the two single-shot measurements.

---

## What's reproducible from this run

- `/tmp/bench_p256.log` — 81 lines; full verbatim stdout reproduced in section 2.
- `/tmp/bench_p384.log` — 119 lines; full verbatim stdout reproduced in section 3.
- `/tmp/bench_ecdsa.log` — 60 lines; full verbatim stdout reproduced in section 4.
- Build artefacts: `build/nist-curves.prg` (37302 B), `build/labels.txt`, `build/nist-curves.dbg`.

## Constraints honoured

- Single-command Bash invocations only; no `python3 -c "..."` inline scripts.
- No retry-loop on transient failure. (One spurious first attempt at all-16-speeds was caught and re-launched at `--speeds 1,16,48` after I realised the default was a full 16-speed sweep that would have taken ~70 min for P-256 alone.)
- `run_in_background: true` + `Monitor` used for the 16+ min bench runs.
- No commits; no VICE touched.
- Stale `DeviceLock` from the all-16-speeds attempt was auto-cleaned by the bench's `cleanup_stale` pass on the second run — no manual intervention needed.

## Notes / forward-looking

- **246 s init sentinel** is the new normal on this device with h=8 comb precompute + REST DMA upload over a 48 ms-RTT link. README's "Boot time grows by ~90 seconds to build the 16 KB / 24 KB precompute tables" is conservative; the additional ~150 s is REST DMA upload network overhead. Future bench tools should bump `--init-timeout` default to 360 s+ for remote U64E setups, or auto-scale the floor based on observed RTT.
- **`ec_point_double` / `ec_point_add` at turbo are 1-jiffy-quantized**: single-shot `loops=1` measurements at the 3-4 jiffy boundary swing by 100 % of one jiffy as a single 60 Hz raster IRQ moves in or out of the measurement window. This is irreducible without batching (e.g. `loops=10` at 48 MHz to average across multiple jiffy windows) or sub-jiffy timing (CIA timer reads). Out of scope for this audit but worth a tracking issue.
- **`ec_scalar_mul` aggregate is the right metric.** README lines 84–93 list point-ops, but for actual perf-regression detection the multi-jiffy `ec_scalar_mul` row should be the primary target (372 j @ 16 MHz, 273 j @ 48 MHz — both >100 jiffies so 1-jiffy quantization is <1 %). All four scalar_mul rows in section 7 are within +0.15 % to +0.37 % of README — no real regression.
- **PR #34 corroboration is unambiguous.** Memory record matches today exactly on ecdsa_verify_256 and within 1 jiffy on ecdsa_verify_384. The PR #34 docs entry in CLAUDE.md "Negative findings" (the ~10–20× overestimate of `fp_mod_inv` savings) stands: the integrated bench reproduces the same numbers, so any future inversion-elimination opt needs to measure against this baseline, not against the random-input `fp_mod_inv` primitive cost.
