#!/usr/bin/env python3
"""test_inv_fast.py - Tests for fp_mod_inv_fast (Fermat inverse, P-256).

Validates correctness against Python's pow(a, p-2, p) and measures timing
using the C64 jiffy clock, comparing to the legacy binary-GCD fp_mod_inv.

Usage:
    python3 tools/test_inv_fast.py [--seed S] [--skip-slow] [--verbose]
"""

import os
import random
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

VERBOSE = False
SKIP_SLOW = False


def int_to_le(v, n=32):
    return v.to_bytes(n, "little")


def le_to_int(b):
    return int.from_bytes(b, "little")


def set_ptr(transport, zp_addr, target):
    write_bytes(transport, zp_addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def write_fe(transport, addr, value):
    write_bytes(transport, addr, int_to_le(value))


def read_fe(transport, addr):
    return le_to_int(read_bytes(transport, addr, 32))


def read_jiffy(transport):
    """Read the 3-byte jiffy clock ($A0..$A2). MSB is at $A0."""
    b = read_bytes(transport, 0x00A0, 3)
    return (b[0] << 16) | (b[1] << 8) | b[2]


def c64_inv_fast(transport, labels, a):
    """Call fp_mod_inv_fast with a at fp_tmp1."""
    write_fe(transport, labels["fp_tmp1"], a)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    jsr(transport, labels["fp_mod_inv_fast"], timeout=600.0)
    return read_fe(transport, labels["fp_r0"])


def c64_inv_legacy(transport, labels, a):
    """Call legacy fp_mod_inv (binary GCD)."""
    write_fe(transport, labels["fp_tmp1"], a)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    # fp_misc should already point to ec_p256
    jsr(transport, labels["fp_mod_inv"], timeout=1200.0)
    return read_fe(transport, labels["fp_r0"])


def c64_mul(transport, labels, a, b):
    write_fe(transport, labels["fp_tmp2"], a)
    write_fe(transport, labels["fp_tmp3"], b)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp3"])
    jsr(transport, labels["fp_mod_mul"], timeout=120.0)
    return read_fe(transport, labels["fp_r0"])


def time_call_jiffies(transport, labels, routine_label, prep_fn, timeout=1200.0):
    """Call the routine after prep_fn; return (return_val, jiffies_elapsed)."""
    prep_fn()
    t0 = read_jiffy(transport)
    jsr(transport, labels[routine_label], timeout=timeout)
    t1 = read_jiffy(transport)
    elapsed = t1 - t0
    if elapsed < 0:
        elapsed += (1 << 24)
    return elapsed


def run_tests(transport, labels, seed):
    rng = random.Random(seed)
    passed = failed = 0

    # Make sure fp_misc = ec_p256 (needed by legacy fp_mod_inv)
    set_ptr(transport, labels["fp_misc"], labels["ec_p256"])

    # Sanity: single fp_mod_mul 3*5
    print("Sanity: fp_mod_mul(3,5)...", flush=True)
    write_fe(transport, labels["fp_tmp1"], 3)
    write_fe(transport, labels["fp_tmp2"], 5)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    jsr(transport, labels["fp_mod_mul"], timeout=120.0)
    r = read_fe(transport, labels["fp_r0"])
    print(f"  got {r} (expect 15)", flush=True)
    if r != 15:
        print("  table init is broken; aborting")
        return 0, 1

    test_vals = [1, 2, 7, 0x12345678, P256 - 1]
    for _ in range(5):
        test_vals.append(rng.randint(1, P256 - 1))

    print("\n--- fp_mod_inv_fast correctness ---")
    for v in test_vals:
        expected = pow(v, P256 - 2, P256)
        got = c64_inv_fast(transport, labels, v)
        # Verify inv * v == 1 (mod p)
        check = (got * v) % P256
        ok = (got == expected) and (check == 1)
        if ok:
            passed += 1
            status = "PASS"
        else:
            failed += 1
            status = "FAIL"
        print(f"  {status} inv({v:#x})")
        if VERBOSE or not ok:
            print(f"      got      = {got:#066x}")
            print(f"      expected = {expected:#066x}")
            print(f"      got*v mod p = {check:#x}  (should be 1)")
        if not ok:
            return passed, failed

    # --- Timing benchmark (via bench_start/bench_stop) ---
    print("\n--- Timing (jiffies = 1/60 s, NTSC) ---")
    sample = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    sample %= P256

    def read_ticks():
        raw = read_bytes(transport, labels["bench_ticks"], 3)
        return (raw[0] << 16) | (raw[1] << 8) | raw[2]

    def timeit(routine, prep, timeout):
        prep()
        jsr(transport, labels["vic_blank"], timeout=5.0)
        jsr(transport, labels["bench_start"], timeout=5.0)
        jsr(transport, labels[routine], timeout=timeout)
        jsr(transport, labels["bench_stop"], timeout=5.0)
        jsr(transport, labels["vic_unblank"], timeout=5.0)
        return read_ticks()

    def prep_fast():
        write_fe(transport, labels["fp_tmp1"], sample)
        set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])

    def prep_legacy():
        write_fe(transport, labels["fp_tmp1"], sample)
        set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
        set_ptr(transport, labels["fp_misc"], labels["ec_p256"])

    j_fast = timeit("fp_mod_inv_fast", prep_fast, 1800.0)
    print(f"  fp_mod_inv_fast : {j_fast} jiffies "
          f"({j_fast/60.0:.2f} s NTSC, {j_fast*17045} cycles)")

    if not SKIP_SLOW and labels.address("fp_mod_inv") is not None:
        j_slow = timeit("fp_mod_inv", prep_legacy, 3600.0)
        print(f"  fp_mod_inv (GCD): {j_slow} jiffies "
              f"({j_slow/60.0:.2f} s NTSC, {j_slow*17045} cycles)")
        if j_fast > 0:
            print(f"  Speedup         : {j_slow / j_fast:.2f}x")
    else:
        print("  (skipping legacy fp_mod_inv timing)")

    return passed, failed


def main():
    global VERBOSE, SKIP_SLOW
    os.chdir(PROJECT_ROOT)

    seed = random.randint(0, 2**32 - 1)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1]); i += 2
        elif args[i] == "--verbose":
            VERBOSE = True; i += 1
        elif args[i] == "--skip-slow":
            SKIP_SLOW = True; i += 1
        else:
            i += 1

    print(f"Random seed: {seed}")

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        r = subprocess.run(["make"], capture_output=True, text=True,
                           cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stdout}\n{r.stderr}")
            sys.exit(1)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    required = ["fp_mod_inv_fast", "fp_mod_mul", "fp_src1", "fp_src2",
                "fp_misc", "fp_tmp1", "fp_tmp2", "fp_tmp3", "fp_r0",
                "ec_p256", "sqtab_init", "reu_mul_init"]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: required label '{name}' missing")
            sys.exit(1)

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        grid = wait_for_text(transport, "READY.", timeout=180.0, verbose=False)
        if grid is None:
            print("FATAL: program did not reach READY")
            mgr.release(inst)
            sys.exit(1)
        print("VICE ready.")

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("Initializing sqtab_init...")
        jsr(transport, labels["sqtab_init"], timeout=30.0)
        print("Initializing reu_mul_init (~2 min in warp)...")
        jsr(transport, labels["reu_mul_init"], timeout=300.0)
        print("Tables initialized.")

        passed, failed = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
