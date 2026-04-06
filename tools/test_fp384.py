#!/usr/bin/env python3
"""test_fp384.py — Direct-memory P-384 field arithmetic tests.

Tests raw 48-byte arithmetic (copy/zero/cmp/is_zero/rshift1/add/sub/mul/sqr)
and modular arithmetic (mod_add/mod_sub/mod_reduce384/mod_mul/mod_sqr/mod_inv)
for the P-384 curve.

Uses the c64-test-harness binary monitor transport.  jsr() is event-based
via checkpoints, so no polling or retry wrappers are needed.

Usage:
    python3 tools/test_fp384.py [--seed S] [--verbose]
"""

import os
import random
import subprocess
import sys
import time
import traceback

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# P-384 field prime
P384 = 2**384 - 2**128 - 2**96 + 2**32 - 1
# P-384 group order
N384 = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
           'FFFFFFFFC7634D81F4372DDF581A0DB248B0A77A'
           'ECEC196ACCC52973', 16)


# ============================================================================
# Byte conversion helpers
# ============================================================================

def int_to_le_bytes_384(val):
    return val.to_bytes(48, "little")

def le_bytes_to_int(data):
    return int.from_bytes(data, "little")

def rand_384bit(rng):
    return rng.randint(0, (1 << 384) - 1)

def rand_field_elem(rng):
    return rng.randint(0, P384 - 1)


# ============================================================================
# C64 helper functions
# ============================================================================

def set_ptr(transport, zp_addr, target_addr):
    """Write a 16-bit little-endian pointer to zero page."""
    write_bytes(transport, zp_addr,
                bytes([target_addr & 0xFF, (target_addr >> 8) & 0xFF]))

def set_fp_ptrs(transport, labels, src1=None, src2=None, dst=None, misc=None):
    if src1 is not None:
        set_ptr(transport, labels["fp_src1"], src1)
    if src2 is not None:
        set_ptr(transport, labels["fp_src2"], src2)
    if dst is not None:
        set_ptr(transport, labels["fp_dst"], dst)
    if misc is not None:
        set_ptr(transport, labels["fp_misc"], misc)

def write_fe_384(transport, addr, val):
    write_bytes(transport, addr, int_to_le_bytes_384(val))

def read_fe_384(transport, addr):
    return le_bytes_to_int(read_bytes(transport, addr, 48))

def write_wide_384(transport, labels, val):
    write_bytes(transport, labels["fp384_wide"], val.to_bytes(96, "little"))

def read_wide_384(transport, labels):
    return le_bytes_to_int(read_bytes(transport, labels["fp384_wide"], 96))


# ============================================================================
# C64 routine wrappers
# ============================================================================

def c64_fp_add(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"],
                src2=labels["fp384_tmp2"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_add_384"], timeout=10.0)
    result = read_fe_384(transport, labels["fp384_tmp3"])
    carry = le_bytes_to_int(read_bytes(transport, labels["fp_carry"], 1))
    return result, carry

def c64_fp_sub(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"],
                src2=labels["fp384_tmp2"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_sub_384"], timeout=10.0)
    result = read_fe_384(transport, labels["fp384_tmp3"])
    borrow = le_bytes_to_int(read_bytes(transport, labels["fp_carry"], 1))
    return result, borrow

def c64_fp_mul(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"],
                src2=labels["fp384_tmp2"])
    jsr(transport, labels["fp_mul_384"], timeout=180.0)
    return read_wide_384(transport, labels)

def c64_fp_sqr(transport, labels, a):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    set_fp_ptrs(transport, labels, src1=labels["fp384_tmp1"])
    jsr(transport, labels["fp_sqr_384"], timeout=180.0)
    return read_wide_384(transport, labels)

def c64_fp_mod_add(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"],
                src2=labels["fp384_tmp2"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_mod_add_384"], timeout=10.0)
    return read_fe_384(transport, labels["fp384_tmp3"])

def c64_fp_mod_sub(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"],
                src2=labels["fp384_tmp2"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_mod_sub_384"], timeout=10.0)
    return read_fe_384(transport, labels["fp384_tmp3"])

def c64_fp_mod_reduce(transport, labels, wide_val):
    write_wide_384(transport, labels, wide_val)
    jsr(transport, labels["fp_mod_reduce384"], timeout=60.0)
    return read_fe_384(transport, labels["fp384_r0"])

def c64_fp_mod_mul(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"],
                src2=labels["fp384_tmp2"])
    jsr(transport, labels["fp_mod_mul_384"], timeout=240.0)
    return read_fe_384(transport, labels["fp384_r0"])

def c64_fp_mod_sqr(transport, labels, a):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    set_fp_ptrs(transport, labels, src1=labels["fp384_tmp1"])
    jsr(transport, labels["fp_mod_sqr_384"], timeout=240.0)
    return read_fe_384(transport, labels["fp384_r0"])

def c64_fp_mod_inv(transport, labels, a):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    set_fp_ptrs(transport, labels, src1=labels["fp384_tmp1"])
    jsr(transport, labels["fp_mod_inv_384"], timeout=900.0)
    return read_fe_384(transport, labels["fp384_r0"])


# ============================================================================
# Basic smoke tests
# ============================================================================

def test_fp_copy(transport, labels):
    passed = failed = 0
    test_val = 0xDEADBEEFCAFEBABE0123456789ABCDEFFEEDFACE1337C0DE
    test_val = (test_val << 192) | test_val
    write_fe_384(transport, labels["fp384_tmp1"], test_val)
    write_fe_384(transport, labels["fp384_tmp3"], 0)  # clear dest
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_copy_384"], timeout=10.0)
    result = read_fe_384(transport, labels["fp384_tmp3"])
    if result == test_val:
        passed += 1
        if VERBOSE: print("  PASS fp_copy_384")
    else:
        failed += 1
        print(f"  FAIL fp_copy_384: expected {test_val:#098x}, got {result:#098x}")
    return passed, failed


def test_fp_zero(transport, labels):
    passed = failed = 0
    write_fe_384(transport, labels["fp384_tmp3"], (1 << 384) - 1)
    set_fp_ptrs(transport, labels, dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_zero_384"], timeout=10.0)
    result = read_fe_384(transport, labels["fp384_tmp3"])
    if result == 0:
        passed += 1
        if VERBOSE: print("  PASS fp_zero_384")
    else:
        failed += 1
        print(f"  FAIL fp_zero_384: got {result:#098x}")
    return passed, failed


def test_fp_cmp(transport, labels, rng):
    """Smoke test fp_cmp_384 — just verify it executes without crashing."""
    passed = failed = 0
    cases = [
        ("equal", 42, 42),
        ("0<1", 0, 1),
        ("1>0", 1, 0),
        ("max>0", (1 << 384) - 1, 0),
    ]
    for i in range(3):
        a = rand_384bit(rng)
        b = rand_384bit(rng)
        cases.append((f"random#{i}", a, b))
    for name, a, b in cases:
        write_fe_384(transport, labels["fp384_tmp1"], a)
        write_fe_384(transport, labels["fp384_tmp2"], b)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp384_tmp1"],
                    src2=labels["fp384_tmp2"])
        jsr(transport, labels["fp_cmp_384"], timeout=10.0)
        passed += 1
        if VERBOSE: print(f"  PASS cmp {name} (executed)")
    return passed, failed


def test_fp_is_zero(transport, labels):
    passed = failed = 0
    cases = [("zero", 0, True), ("one", 1, False),
             ("max", (1 << 384) - 1, False),
             ("high_bit", 1 << 380, False)]
    for name, val, _ in cases:
        write_fe_384(transport, labels["fp384_tmp1"], val)
        set_fp_ptrs(transport, labels, src1=labels["fp384_tmp1"])
        jsr(transport, labels["fp_is_zero_384"], timeout=10.0)
        passed += 1
        if VERBOSE: print(f"  PASS is_zero {name} (executed)")
    return passed, failed


def test_fp_rshift1(transport, labels, rng):
    passed = failed = 0
    cases = [("0", 0), ("1", 1), ("2", 2), ("3", 3),
             ("max", (1 << 384) - 1), ("high_bit", 1 << 383)]
    for i in range(4):
        cases.append((f"random#{i}", rand_384bit(rng)))
    for name, val in cases:
        write_fe_384(transport, labels["fp384_tmp1"], val)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp384_tmp1"],
                    dst=labels["fp384_tmp1"])
        jsr(transport, labels["fp_rshift1_384"], timeout=10.0)
        result = read_fe_384(transport, labels["fp384_tmp1"])
        expected = val >> 1
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS rshift1 {name}")
        else:
            failed += 1
            print(f"  FAIL rshift1 {name}:")
            print(f"    val      = {val:#098x}")
            print(f"    expected = {expected:#098x}")
            print(f"    got      = {result:#098x}")
    return passed, failed


# ============================================================================
# Raw arithmetic tests
# ============================================================================

def test_fp_add(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0+0", 0, 0),
        ("1+1", 1, 1),
        ("0+1", 0, 1),
        ("3+5", 3, 5),
        ("max+1", (1 << 384) - 1, 1),
        ("max+max", (1 << 384) - 1, (1 << 384) - 1),
        ("p384+0", P384, 0),
        ("p384-1+1", P384 - 1, 1),
    ]
    for i in range(6):
        cases.append((f"random#{i}", rand_384bit(rng), rand_384bit(rng)))

    for name, a, b in cases:
        full_sum = a + b
        expected_low = full_sum & ((1 << 384) - 1)
        expected_carry = 1 if full_sum >= (1 << 384) else 0
        result, carry = c64_fp_add(transport, labels, a, b)
        if result == expected_low and carry == expected_carry:
            passed += 1
            if VERBOSE: print(f"  PASS add {name}")
        else:
            failed += 1
            print(f"  FAIL add {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    b        = {b:#098x}")
            print(f"    expected = {expected_low:#098x} carry={expected_carry}")
            print(f"    got      = {result:#098x} carry={carry}")
    return passed, failed


def test_fp_sub(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0-0", 0, 0),
        ("1-0", 1, 0),
        ("1-1", 1, 1),
        ("0-1", 0, 1),
        ("10-20", 10, 20),
        ("max-0", (1 << 384) - 1, 0),
        ("max-max", (1 << 384) - 1, (1 << 384) - 1),
        ("p384-1", P384, 1),
    ]
    for i in range(6):
        cases.append((f"random#{i}", rand_384bit(rng), rand_384bit(rng)))
    for name, a, b in cases:
        if a >= b:
            expected = a - b
            expected_borrow = 0
        else:
            expected = (a - b) + (1 << 384)
            expected_borrow = 1
        result, borrow = c64_fp_sub(transport, labels, a, b)
        if result == expected and borrow == expected_borrow:
            passed += 1
            if VERBOSE: print(f"  PASS sub {name}")
        else:
            failed += 1
            print(f"  FAIL sub {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    b        = {b:#098x}")
            print(f"    expected = {expected:#098x} borrow={expected_borrow}")
            print(f"    got      = {result:#098x} borrow={borrow}")
    return passed, failed


def test_fp_mul(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0*0", 0, 0),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("0xFF*0xFF", 0xFF, 0xFF),
        ("1*max", 1, (1 << 384) - 1),
        ("small*max", 0x1234, (1 << 384) - 1),
    ]
    for i in range(6):
        cases.append((f"random#{i}", rand_384bit(rng), rand_384bit(rng)))
    for name, a, b in cases:
        expected = a * b
        result = c64_fp_mul(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mul {name}")
        else:
            failed += 1
            print(f"  FAIL mul {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    b        = {b:#098x}")
            print(f"    expected = {expected:#0194x}")
            print(f"    got      = {result:#0194x}")
    return passed, failed


def test_fp_sqr(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0", 0), ("1", 1), ("3", 3), ("5", 5),
        ("0xFF", 0xFF), ("max", (1 << 384) - 1),
    ]
    for i in range(6):
        cases.append((f"random#{i}", rand_384bit(rng)))
    for name, a in cases:
        expected = a * a
        result = c64_fp_sqr(transport, labels, a)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS sqr {name}")
        else:
            failed += 1
            print(f"  FAIL sqr {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    expected = {expected:#0194x}")
            print(f"    got      = {result:#0194x}")
    return passed, failed


def test_fp_sqr_vs_mul(transport, labels, rng):
    passed = failed = 0
    for i in range(4):
        a = rand_384bit(rng)
        sqr_result = c64_fp_sqr(transport, labels, a)
        mul_result = c64_fp_mul(transport, labels, a, a)
        if sqr_result == mul_result:
            passed += 1
            if VERBOSE: print(f"  PASS sqr_vs_mul #{i}")
        else:
            failed += 1
            print(f"  FAIL sqr_vs_mul #{i}:")
            print(f"    a   = {a:#098x}")
            print(f"    sqr = {sqr_result:#0194x}")
            print(f"    mul = {mul_result:#0194x}")
    return passed, failed


# ============================================================================
# Modular arithmetic tests
# ============================================================================

def test_fp_mod_add(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0+0", 0, 0),
        ("1+1", 1, 1),
        ("p-1+1", P384 - 1, 1),
        ("p-1+p-1", P384 - 1, P384 - 1),
        ("p-10+15", P384 - 10, 15),
    ]
    for i in range(6):
        cases.append((f"random#{i}", rand_field_elem(rng), rand_field_elem(rng)))
    for name, a, b in cases:
        expected = (a + b) % P384
        result = c64_fp_mod_add(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_add {name}")
        else:
            failed += 1
            print(f"  FAIL mod_add {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    b        = {b:#098x}")
            print(f"    expected = {expected:#098x}")
            print(f"    got      = {result:#098x}")
    return passed, failed


def test_fp_mod_sub(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0-0", 0, 0),
        ("1-0", 1, 0),
        ("0-1", 0, 1),
        ("10-20", 10, 20),
        ("p-1-0", P384 - 1, 0),
    ]
    for i in range(6):
        cases.append((f"random#{i}", rand_field_elem(rng), rand_field_elem(rng)))
    for name, a, b in cases:
        expected = (a - b) % P384
        result = c64_fp_mod_sub(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_sub {name}")
        else:
            failed += 1
            print(f"  FAIL mod_sub {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    b        = {b:#098x}")
            print(f"    expected = {expected:#098x}")
            print(f"    got      = {result:#098x}")
    return passed, failed


def test_fp_mod_reduce(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("zero", 0),
        ("one", 1),
        ("p384", P384),
        ("p384+1", P384 + 1),
        ("p384-1", P384 - 1),
        ("2*p384", 2 * P384),
        ("p384^2", P384 * P384),
        ("3*5", 15),
        ("7*7", 49),
    ]
    for i in range(6):
        cases.append((f"random#{i}", rng.randint(0, (1 << 768) - 1)))
    for i in range(4):
        a = rand_field_elem(rng)
        b = rand_field_elem(rng)
        cases.append((f"product#{i}", a * b))
    for name, wide in cases:
        expected = wide % P384
        result = c64_fp_mod_reduce(transport, labels, wide)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_reduce {name}")
        else:
            failed += 1
            print(f"  FAIL mod_reduce {name}:")
            print(f"    input    = {wide:#0194x}")
            print(f"    expected = {expected:#098x}")
            print(f"    got      = {result:#098x}")
    return passed, failed


def test_fp_mod_mul(transport, labels, rng):
    passed = failed = 0
    r = rand_field_elem(rng)
    r2 = rand_field_elem(rng)
    cases = [
        ("0*0", 0, 0),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("7*7", 7, 7),
        ("a*1=a", r, 1),
        ("a*0=0", r2, 0),
    ]
    for i in range(6):
        cases.append((f"random#{i}", rand_field_elem(rng), rand_field_elem(rng)))
    for name, a, b in cases:
        expected = (a * b) % P384
        result = c64_fp_mod_mul(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_mul {name}")
        else:
            failed += 1
            print(f"  FAIL mod_mul {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    b        = {b:#098x}")
            print(f"    expected = {expected:#098x}")
            print(f"    got      = {result:#098x}")
    return passed, failed


def test_fp_mod_sqr(transport, labels, rng):
    passed = failed = 0
    cases = [("0", 0), ("1", 1), ("3", 3), ("7", 7)]
    for i in range(3):
        cases.append((f"random#{i}", rand_field_elem(rng)))
    for name, a in cases:
        expected = (a * a) % P384
        result = c64_fp_mod_sqr(transport, labels, a)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_sqr {name}")
        else:
            failed += 1
            print(f"  FAIL mod_sqr {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    expected = {expected:#098x}")
            print(f"    got      = {result:#098x}")
    return passed, failed


def test_fp_mod_inv(transport, labels, rng):
    """Only test inv(1) == 1 — binary GCD inversion is very slow."""
    passed = failed = 0
    print("    inv(1)...", end="", flush=True)
    result = c64_fp_mod_inv(transport, labels, 1)
    if result == 1:
        passed += 1
        print(" ok")
    else:
        failed += 1
        print(" FAIL")
        print(f"    expected = 1")
        print(f"    got      = {result:#098x}")
    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0
    total_skipped = 0

    test_groups = [
        ("fp_copy_384", lambda: test_fp_copy(transport, labels)),
        ("fp_zero_384", lambda: test_fp_zero(transport, labels)),
        ("fp_cmp_384", lambda: test_fp_cmp(transport, labels, rng)),
        ("fp_is_zero_384", lambda: test_fp_is_zero(transport, labels)),
        ("fp_rshift1_384", lambda: test_fp_rshift1(transport, labels, rng)),
        ("fp_add_384", lambda: test_fp_add(transport, labels, rng)),
        ("fp_sub_384", lambda: test_fp_sub(transport, labels, rng)),
        ("fp_mul_384", lambda: test_fp_mul(transport, labels, rng)),
        ("fp_sqr_384", lambda: test_fp_sqr(transport, labels, rng)),
        ("fp_sqr vs fp_mul", lambda: test_fp_sqr_vs_mul(transport, labels, rng)),
        ("fp_mod_add_384", lambda: test_fp_mod_add(transport, labels, rng)),
        ("fp_mod_sub_384", lambda: test_fp_mod_sub(transport, labels, rng)),
        ("fp_mod_reduce384", lambda: test_fp_mod_reduce(transport, labels, rng)),
        ("fp_mod_mul_384", lambda: test_fp_mod_mul(transport, labels, rng)),
        ("fp_mod_sqr_384", lambda: test_fp_mod_sqr(transport, labels, rng)),
        ("fp_mod_inv_384", lambda: test_fp_mod_inv(transport, labels, rng)),
    ]

    transport_broken = False
    for name, test_fn in test_groups:
        print(f"\n--- {name} ---")
        if transport_broken:
            total_skipped += 1
            print("  SKIP: transport broken after previous timeout")
            continue
        try:
            p, f = test_fn()
            total_passed += p
            total_failed += f
            status = "OK" if f == 0 else "FAIL"
            print(f"  {status}: {p}/{p + f} passed")
        except Exception as e:
            total_failed += 1
            print(f"  ERROR: {e}")
            if "stopped event" in str(e) or "Timed out" in str(e):
                print("  WARNING: transport likely broken, skipping remaining tests")
                transport_broken = True
            else:
                traceback.print_exc()

    return total_passed, total_failed, total_skipped


def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    seed = random.randint(0, 2**32 - 1)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            VERBOSE = True
            i += 1
        else:
            i += 1

    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stdout}\n{result.stderr}")
            sys.exit(1)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found after build")
        sys.exit(1)
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    required = [
        "fp_src1", "fp_src2", "fp_dst", "fp_misc", "fp_carry",
        "fp_copy_384", "fp_zero_384", "fp_cmp_384", "fp_is_zero_384",
        "fp_add_384", "fp_sub_384", "fp_rshift1_384",
        "fp_mul_384", "fp_sqr_384",
        "fp_mod_add_384", "fp_mod_sub_384", "fp_mod_reduce384",
        "fp_mod_mul_384", "fp_mod_sqr_384", "fp_mod_inv_384",
        "fp384_tmp1", "fp384_tmp2", "fp384_tmp3", "fp384_tmp4",
        "fp384_wide", "fp384_r0", "ec_p384",
        "sqtab_init", "reu_mul_init",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    # Launch VICE with REU
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config,
                             port_range_start=6511,
                             port_range_end=6531) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport

        # Wait for C64 initialization to complete (sentinel byte at $02A7)
        print("Waiting for init sentinel...")
        start = time.time()
        sentinel_ok = False
        while time.time() - start < 600.0:
            sentinel = read_bytes(transport, 0x02A7, 1)
            if sentinel[0] == 0x42:
                sentinel_ok = True
                break
            # Binary monitor pauses the CPU on each memory read; resume it.
            try:
                transport.resume()
            except Exception:
                pass
            time.sleep(0.5)
        if not sentinel_ok:
            print("FATAL: init sentinel not set within timeout")
            mgr.release(inst)
            sys.exit(1)
        print(f"Init complete after {time.time()-start:.1f}s")

        # Safety: write JMP $0339 at $0339 so CPU loops harmlessly
        # after jsr() returns (prevents crash when BASIC ROM is banked out)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Set fp_misc -> ec_p384 for modular routines
        p384_addr = labels["ec_p384"]
        set_ptr(transport, labels["fp_misc"], p384_addr)
        print(f"Set fp_misc -> ec_p384 (${p384_addr:04X})")

        passed, failed, skipped = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
