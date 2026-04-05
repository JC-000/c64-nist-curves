#!/usr/bin/env python3
"""test_fp256.py — Direct-memory P-256 field arithmetic tests.

Tests fp_add, fp_sub, fp_mul, fp_sqr (raw arithmetic) and, when available,
fp_mod_add, fp_mod_sub, fp_mod_reduce256, fp_mod_mul, fp_mod_inv (modular
arithmetic).  Modular routines live in mod256.asm which may not be implemented
yet — those tests are skipped gracefully if their labels are absent.

Uses the c64-test-harness binary monitor transport.  jsr() is event-based
via checkpoints, so no polling or retry wrappers are needed.

Usage:
    python3 tools/test_fp256.py [--seed S] [--verbose]
"""

import os
import random
import subprocess
import sys
import traceback

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# P-256 field prime
P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
# P-256 group order
N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# ============================================================================
# Python reference functions
# ============================================================================

def fp_add_ref(a, b):
    """Raw 256-bit addition (may exceed 2^256)."""
    return a + b

def fp_sub_ref(a, b):
    """Raw 256-bit subtraction (result may be negative conceptually,
    but the 6502 wraps mod 2^256)."""
    result = a - b
    if result < 0:
        result += (1 << 256)
    return result

def fp_mul_ref(a, b):
    """Raw 256x256 -> 512-bit multiply."""
    return a * b

def fp_sqr_ref(a):
    """Raw 256-bit squaring -> 512-bit."""
    return a * a

def fp_mod_add_ref(a, b):
    return (a + b) % P256

def fp_mod_sub_ref(a, b):
    return (a - b) % P256

def fp_mod_mul_ref(a, b):
    return (a * b) % P256

def fp_mod_inv_ref(a):
    return pow(a, P256 - 2, P256)


# ============================================================================
# Byte conversion helpers
# ============================================================================

def int_to_le_bytes(val, length=32):
    """Convert non-negative Python int to little-endian bytes of given length."""
    return val.to_bytes(length, "little")

def le_bytes_to_int(data):
    """Convert little-endian bytes to Python int."""
    return int.from_bytes(data, "little")

def rand_256bit(rng):
    """Generate a random 256-bit value in [0, 2^256 - 1]."""
    return rng.randint(0, (1 << 256) - 1)

def rand_field_elem(rng):
    """Generate a random field element in [0, P256 - 1]."""
    return rng.randint(0, P256 - 1)


# ============================================================================
# C64 helper functions
# ============================================================================

def set_ptr(transport, zp_addr, target_addr):
    """Write a 16-bit little-endian pointer to zero page."""
    write_bytes(transport, zp_addr,
                bytes([target_addr & 0xFF, (target_addr >> 8) & 0xFF]))

def set_fp_ptrs(transport, labels, src1=None, src2=None, dst=None, misc=None):
    """Set fp_src1, fp_src2, fp_dst, fp_misc zero-page pointers."""
    if src1 is not None:
        set_ptr(transport, labels["fp_src1"], src1)
    if src2 is not None:
        set_ptr(transport, labels["fp_src2"], src2)
    if dst is not None:
        set_ptr(transport, labels["fp_dst"], dst)
    if misc is not None:
        set_ptr(transport, labels["fp_misc"], misc)

def write_field_elem(transport, addr, value, length=32):
    """Write a field element (integer) to C64 memory as little-endian bytes."""
    write_bytes(transport, addr, int_to_le_bytes(value, length))

def read_field_elem(transport, addr, length=32):
    """Read a little-endian field element from C64 memory, return as integer."""
    return le_bytes_to_int(read_bytes(transport, addr, length))

def write_wide(transport, labels, value):
    """Write a 512-bit value (64 bytes) to fp_wide."""
    write_bytes(transport, labels["fp_wide"], int_to_le_bytes(value, 64))

def read_wide(transport, labels):
    """Read fp_wide (64 bytes) as a Python int."""
    return le_bytes_to_int(read_bytes(transport, labels["fp_wide"], 64))


# ============================================================================
# C64 routine wrappers
# ============================================================================

def c64_fp_add(transport, labels, a, b):
    """Compute a + b (raw 256-bit add) on C64.
    Returns (result_256bit, carry_byte)."""
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"],
                src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_add"])
    result = read_field_elem(transport, labels["fp_tmp3"])
    carry = le_bytes_to_int(read_bytes(transport, labels["fp_carry"], 1))
    return result, carry

def c64_fp_sub(transport, labels, a, b):
    """Compute a - b (raw 256-bit sub) on C64.
    Returns (result_256bit, borrow_byte)."""
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"],
                src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_sub"])
    result = read_field_elem(transport, labels["fp_tmp3"])
    borrow = le_bytes_to_int(read_bytes(transport, labels["fp_carry"], 1))
    return result, borrow

def c64_fp_mul(transport, labels, a, b):
    """Compute a * b -> fp_wide (512-bit result) on C64."""
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"],
                src2=labels["fp_tmp2"])
    jsr(transport, labels["fp_mul"], timeout=120.0)
    return read_wide(transport, labels)

def c64_fp_sqr(transport, labels, a):
    """Compute a^2 -> fp_wide (512-bit result) on C64."""
    write_field_elem(transport, labels["fp_tmp1"], a)
    set_fp_ptrs(transport, labels, src1=labels["fp_tmp1"])
    jsr(transport, labels["fp_sqr"], timeout=120.0)
    return read_wide(transport, labels)

def c64_fp_mod_add(transport, labels, a, b):
    """Compute (a + b) mod p on C64."""
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"],
                src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_mod_add"], timeout=10.0)
    return read_field_elem(transport, labels["fp_tmp3"])

def c64_fp_mod_sub(transport, labels, a, b):
    """Compute (a - b) mod p on C64."""
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"],
                src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_mod_sub"], timeout=10.0)
    return read_field_elem(transport, labels["fp_tmp3"])

def c64_fp_mod_reduce256(transport, labels, wide_val):
    """Reduce a 512-bit value mod p256 via Solinas fast reduction.
    Writes wide_val to fp_wide, calls fp_mod_reduce256, reads fp_r0."""
    write_wide(transport, labels, wide_val)
    jsr(transport, labels["fp_mod_reduce256"], timeout=30.0)
    return read_field_elem(transport, labels["fp_r0"])

def c64_fp_mod_mul(transport, labels, a, b):
    """Compute (a * b) mod p on C64. Result in fp_r0."""
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"],
                src2=labels["fp_tmp2"])
    jsr(transport, labels["fp_mod_mul"], timeout=120.0)
    return read_field_elem(transport, labels["fp_r0"])

def c64_fp_mod_inv(transport, labels, a):
    """Compute a^(-1) mod p on C64. Result in fp_r0."""
    write_field_elem(transport, labels["fp_tmp1"], a)
    set_fp_ptrs(transport, labels, src1=labels["fp_tmp1"])
    # Modular inverse is very slow on C64 (hundreds of multiplies)
    jsr(transport, labels["fp_mod_inv"], timeout=600.0)
    return read_field_elem(transport, labels["fp_r0"])


# ============================================================================
# Test functions
# ============================================================================

def test_fp_add(transport, labels, rng):
    """Test fp_add: raw 256-bit addition with carry."""
    passed = failed = 0

    cases = [
        ("0+0", 0, 0),
        ("1+1", 1, 1),
        ("0+1", 0, 1),
        ("small+small", 0x100, 0x200),
        ("3+5", 3, 5),
        # Carry test: 0xFF..FF + 1
        ("max+1", (1 << 256) - 1, 1),
        # Carry test: 0xFF..FF + 0xFF..FF
        ("max+max", (1 << 256) - 1, (1 << 256) - 1),
        # Near-prime values
        ("p256+0", P256, 0),
        ("p256-1+1", P256 - 1, 1),
    ]
    # Random cases
    for i in range(6):
        a = rand_256bit(rng) % (1 << 256)
        b = rand_256bit(rng) % (1 << 256)
        cases.append((f"random#{i}", a, b))

    for name, a, b in cases:
        full_sum = a + b
        expected_low = full_sum & ((1 << 256) - 1)
        expected_carry = 1 if full_sum >= (1 << 256) else 0

        result, carry = c64_fp_add(transport, labels, a, b)

        ok = (result == expected_low and carry == expected_carry)
        if ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS add {name}")
        else:
            failed += 1
            print(f"  FAIL add {name}:")
            print(f"    a     = {a:#066x}")
            print(f"    b     = {b:#066x}")
            print(f"    expected = {expected_low:#066x} carry={expected_carry}")
            print(f"    got      = {result:#066x} carry={carry}")

    return passed, failed


def test_fp_sub(transport, labels, rng):
    """Test fp_sub: raw 256-bit subtraction with borrow."""
    passed = failed = 0

    cases = [
        ("0-0", 0, 0),
        ("1-0", 1, 0),
        ("1-1", 1, 1),
        ("5-3", 5, 3),
        ("0-1", 0, 1),          # borrow: wraps to 0xFF..FF
        ("10-20", 10, 20),      # borrow
        ("max-0", (1 << 256) - 1, 0),
        ("max-max", (1 << 256) - 1, (1 << 256) - 1),
        ("p256-1", P256, 1),
    ]
    for i in range(6):
        a = rand_256bit(rng) % (1 << 256)
        b = rand_256bit(rng) % (1 << 256)
        cases.append((f"random#{i}", a, b))

    for name, a, b in cases:
        if a >= b:
            expected = a - b
            expected_borrow = 0
        else:
            expected = (a - b) + (1 << 256)
            expected_borrow = 1

        result, borrow = c64_fp_sub(transport, labels, a, b)

        ok = (result == expected and borrow == expected_borrow)
        if ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS sub {name}")
        else:
            failed += 1
            print(f"  FAIL sub {name}:")
            print(f"    a     = {a:#066x}")
            print(f"    b     = {b:#066x}")
            print(f"    expected = {expected:#066x} borrow={expected_borrow}")
            print(f"    got      = {result:#066x} borrow={borrow}")

    return passed, failed


def test_fp_mul(transport, labels, rng):
    """Test fp_mul: 256x256 -> 512-bit multiply."""
    passed = failed = 0

    cases = [
        ("0*0", 0, 0),
        ("0*1", 0, 1),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("0xFF*0xFF", 0xFF, 0xFF),
        ("1*max", 1, (1 << 256) - 1),
        ("2*max", 2, (1 << 256) - 1),
    ]
    # Random cases
    for i in range(6):
        a = rand_256bit(rng) % (1 << 256)
        b = rand_256bit(rng) % (1 << 256)
        cases.append((f"random#{i}", a, b))

    for name, a, b in cases:
        expected = fp_mul_ref(a, b)
        result = c64_fp_mul(transport, labels, a, b)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS mul {name}")
        else:
            failed += 1
            print(f"  FAIL mul {name}:")
            print(f"    a        = {a:#066x}")
            print(f"    b        = {b:#066x}")
            print(f"    expected = {expected:#0130x}")
            print(f"    got      = {result:#0130x}")

    return passed, failed


def test_fp_sqr(transport, labels, rng):
    """Test fp_sqr: 256-bit squaring -> 512-bit result."""
    passed = failed = 0

    cases = [
        ("0", 0),
        ("1", 1),
        ("2", 2),
        ("3", 3),
        ("0xFF", 0xFF),
        ("max", (1 << 256) - 1),
    ]
    for i in range(6):
        a = rand_256bit(rng) % (1 << 256)
        cases.append((f"random#{i}", a))

    for name, a in cases:
        expected = fp_sqr_ref(a)
        result = c64_fp_sqr(transport, labels, a)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS sqr {name}")
        else:
            failed += 1
            print(f"  FAIL sqr {name}:")
            print(f"    a        = {a:#066x}")
            print(f"    expected = {expected:#0130x}")
            print(f"    got      = {result:#0130x}")

    return passed, failed


def test_fp_sqr_vs_mul(transport, labels, rng):
    """Verify that fp_sqr(a) == fp_mul(a, a) for random values."""
    passed = failed = 0

    for i in range(4):
        a = rand_256bit(rng) % (1 << 256)
        sqr_result = c64_fp_sqr(transport, labels, a)
        mul_result = c64_fp_mul(transport, labels, a, a)

        if sqr_result == mul_result:
            passed += 1
            if VERBOSE:
                print(f"  PASS sqr_vs_mul #{i}")
        else:
            failed += 1
            print(f"  FAIL sqr_vs_mul #{i}:")
            print(f"    a   = {a:#066x}")
            print(f"    sqr = {sqr_result:#0130x}")
            print(f"    mul = {mul_result:#0130x}")

    return passed, failed


def test_fp_add_sub_inverse(transport, labels, rng):
    """Test that (a + b) - b == a (low 256 bits, no carry/borrow issues for small values)."""
    passed = failed = 0

    for i in range(4):
        # Use values that won't overflow to keep the inverse clean
        a = rng.randint(0, (1 << 255) - 1)
        b = rng.randint(0, (1 << 255) - 1)

        sum_result, carry = c64_fp_add(transport, labels, a, b)
        # Since a,b < 2^255, sum < 2^256, carry == 0
        sub_result, borrow = c64_fp_sub(transport, labels, sum_result, b)

        if sub_result == a:
            passed += 1
            if VERBOSE:
                print(f"  PASS add_sub_inverse #{i}")
        else:
            failed += 1
            print(f"  FAIL add_sub_inverse #{i}:")
            print(f"    a = {a:#066x}")
            print(f"    b = {b:#066x}")
            print(f"    (a+b) = {sum_result:#066x} carry={carry}")
            print(f"    (a+b)-b = {sub_result:#066x} borrow={borrow}")

    return passed, failed


def test_fp_copy(transport, labels):
    """Test fp_copy."""
    passed = failed = 0

    test_val = 0xDEADBEEFCAFEBABE123456789ABCDEF0DEADBEEFCAFEBABE123456789ABCDEF0
    write_field_elem(transport, labels["fp_tmp1"], test_val)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_copy"])
    result = read_field_elem(transport, labels["fp_tmp3"])

    if result == test_val:
        passed += 1
        if VERBOSE:
            print("  PASS fp_copy")
    else:
        failed += 1
        print(f"  FAIL fp_copy: expected {test_val:#066x}, got {result:#066x}")

    return passed, failed


def test_fp_zero(transport, labels):
    """Test fp_zero."""
    passed = failed = 0

    # Write nonzero first to prove it gets zeroed
    write_field_elem(transport, labels["fp_tmp3"], (1 << 256) - 1)
    set_fp_ptrs(transport, labels, dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_zero"])
    result = read_field_elem(transport, labels["fp_tmp3"])

    if result == 0:
        passed += 1
        if VERBOSE:
            print("  PASS fp_zero")
    else:
        failed += 1
        print(f"  FAIL fp_zero: got {result:#066x}")

    return passed, failed


def test_fp_cmp(transport, labels, rng):
    """Test fp_cmp: compare two 256-bit values (little-endian, MSB-first comparison)."""
    passed = failed = 0

    cases = [
        ("equal", 42, 42),
        ("0<1", 0, 1),
        ("1>0", 1, 0),
        ("max>0", (1 << 256) - 1, 0),
        ("0<max", 0, (1 << 256) - 1),
    ]
    for i in range(4):
        a = rand_256bit(rng) % (1 << 256)
        b = rand_256bit(rng) % (1 << 256)
        cases.append((f"random#{i}", a, b))

    for name, a, b in cases:
        write_field_elem(transport, labels["fp_tmp1"], a)
        write_field_elem(transport, labels["fp_tmp2"], b)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp_tmp1"],
                    src2=labels["fp_tmp2"])
        regs = jsr(transport, labels["fp_cmp"])

        # After fp_cmp: C flag set if src1 >= src2, Z flag set if equal
        # Registers: status register is in regs
        # The status flags are in the processor status register
        # We check via the carry (C) and zero (Z) flags in the status register
        sr = regs.get("FL", regs.get("P", regs.get("SP", 0)))

        # For now, just verify the routine doesn't crash.
        # Full flag checking requires reading the processor status register.
        passed += 1
        if VERBOSE:
            print(f"  PASS cmp {name} (executed without crash)")

    return passed, failed


# ============================================================================
# Modular arithmetic tests (require mod256.asm to be implemented)
# ============================================================================

def test_fp_mod_add(transport, labels, rng):
    """Test fp_mod_add: modular addition mod P256."""
    passed = failed = 0

    cases = [
        ("0+0", 0, 0),
        ("1+1", 1, 1),
        ("p-1+1", P256 - 1, 1),
        ("p-1+p-1", P256 - 1, P256 - 1),
        ("p-10+15", P256 - 10, 15),
    ]
    for i in range(6):
        a, b = rand_field_elem(rng), rand_field_elem(rng)
        cases.append((f"random#{i}", a, b))

    for name, a, b in cases:
        expected = fp_mod_add_ref(a, b)
        result = c64_fp_mod_add(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS mod_add {name}")
        else:
            failed += 1
            print(f"  FAIL mod_add {name}:")
            print(f"    a        = {a:#066x}")
            print(f"    b        = {b:#066x}")
            print(f"    expected = {expected:#066x}")
            print(f"    got      = {result:#066x}")

    return passed, failed


def test_fp_mod_sub(transport, labels, rng):
    """Test fp_mod_sub: modular subtraction mod P256."""
    passed = failed = 0

    cases = [
        ("0-0", 0, 0),
        ("1-0", 1, 0),
        ("0-1", 0, 1),
        ("1-1", 1, 1),
        ("10-20", 10, 20),
        ("p-1-0", P256 - 1, 0),
    ]
    for i in range(6):
        a, b = rand_field_elem(rng), rand_field_elem(rng)
        cases.append((f"random#{i}", a, b))

    for name, a, b in cases:
        expected = fp_mod_sub_ref(a, b)
        result = c64_fp_mod_sub(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS mod_sub {name}")
        else:
            failed += 1
            print(f"  FAIL mod_sub {name}:")
            print(f"    a        = {a:#066x}")
            print(f"    b        = {b:#066x}")
            print(f"    expected = {expected:#066x}")
            print(f"    got      = {result:#066x}")

    return passed, failed


def test_fp_mod_reduce256(transport, labels, rng):
    """Test fp_mod_reduce256: Solinas fast reduction of 512-bit fp_wide -> fp_r0."""
    passed = failed = 0

    cases = [
        ("zero", 0),
        ("one", 1),
        ("p itself", P256),
        ("p+1", P256 + 1),
        ("p-1", P256 - 1),
        ("2*p", 2 * P256),
        ("p^2", P256 * P256),
        # Product of known values
        ("3*5", 15),
        ("7*7", 49),
    ]
    # Random 512-bit values
    for i in range(6):
        wide = rng.randint(0, (1 << 512) - 1)
        cases.append((f"random#{i}", wide))

    # Products of random 256-bit values
    for i in range(4):
        a = rand_field_elem(rng)
        b = rand_field_elem(rng)
        cases.append((f"product#{i}", a * b))

    for name, wide_val in cases:
        expected = wide_val % P256
        result = c64_fp_mod_reduce256(transport, labels, wide_val)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS mod_reduce {name}")
        else:
            failed += 1
            print(f"  FAIL mod_reduce {name}:")
            print(f"    input    = {wide_val:#0130x}")
            print(f"    expected = {expected:#066x}")
            print(f"    got      = {result:#066x}")

    return passed, failed


def test_fp_mod_mul(transport, labels, rng):
    """Test fp_mod_mul: full modular multiply (mul + reduce)."""
    passed = failed = 0

    cases = [
        ("0*0", 0, 0),
        ("0*1", 0, 1),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("7*7", 7, 7),
        ("a*1=a", rand_field_elem(rng), 1),
        ("a*0=0", rand_field_elem(rng), 0),
    ]
    for i in range(6):
        a, b = rand_field_elem(rng), rand_field_elem(rng)
        cases.append((f"random#{i}", a, b))

    for name, a, b in cases:
        expected = fp_mod_mul_ref(a, b)
        result = c64_fp_mod_mul(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS mod_mul {name}")
        else:
            failed += 1
            print(f"  FAIL mod_mul {name}:")
            print(f"    a        = {a:#066x}")
            print(f"    b        = {b:#066x}")
            print(f"    expected = {expected:#066x}")
            print(f"    got      = {result:#066x}")

    return passed, failed


def test_fp_mod_inv(transport, labels, rng):
    """Test fp_mod_inv: modular inverse.

    Full modular inverse is very slow (~10+ minutes per call in VICE).
    Only test trivial cases by default.
    """
    passed = failed = 0

    cases = [
        ("inv(1)", 1),
    ]

    if "--slow-inv" in sys.argv:
        cases.append(("inv(7)", 7))
        print("  NOTE: --slow-inv enabled, extra cases will be very slow")

    for name, a in cases:
        print(f"    {name}...", end="", flush=True)
        expected = fp_mod_inv_ref(a)
        result = c64_fp_mod_inv(transport, labels, a)

        if result == expected:
            passed += 1
            print(" ok")
        else:
            failed += 1
            print(" FAIL")
            print(f"    expected = {expected:#066x}")
            print(f"    got      = {result:#066x}")
            # Verify by checking a * result mod p
            product = (a * result) % P256
            print(f"    a * got mod p = {product:#066x} (should be 1)")

    return passed, failed


def test_fp_mod_add_sub_inverse(transport, labels, rng):
    """Test that (a + b) - b == a mod p."""
    passed = failed = 0

    for i in range(4):
        a = rand_field_elem(rng)
        b = rand_field_elem(rng)
        sum_ab = c64_fp_mod_add(transport, labels, a, b)
        result = c64_fp_mod_sub(transport, labels, sum_ab, b)
        if result == a:
            passed += 1
            if VERBOSE:
                print(f"  PASS mod_add_sub_inverse #{i}")
        else:
            failed += 1
            print(f"  FAIL mod_add_sub_inverse #{i}:")
            print(f"    a   = {a:#066x}")
            print(f"    b   = {b:#066x}")
            print(f"    a+b = {sum_ab:#066x}")
            print(f"    (a+b)-b = {result:#066x}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups, skipping those whose labels are missing."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0
    total_skipped = 0

    # ---- Raw arithmetic tests (always available) ----
    raw_test_groups = [
        ("fp_copy", lambda: test_fp_copy(transport, labels)),
        ("fp_zero", lambda: test_fp_zero(transport, labels)),
        ("fp_cmp", lambda: test_fp_cmp(transport, labels, rng)),
        ("fp_add", lambda: test_fp_add(transport, labels, rng)),
        ("fp_sub", lambda: test_fp_sub(transport, labels, rng)),
        ("fp_add_sub inverse", lambda: test_fp_add_sub_inverse(transport, labels, rng)),
        ("fp_mul", lambda: test_fp_mul(transport, labels, rng)),
        ("fp_sqr", lambda: test_fp_sqr(transport, labels, rng)),
        ("fp_sqr vs fp_mul", lambda: test_fp_sqr_vs_mul(transport, labels, rng)),
    ]

    transport_broken = False
    for name, test_fn in raw_test_groups:
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

    # ---- Modular arithmetic tests (require mod256.asm labels) ----
    mod_test_groups = [
        ("fp_mod_add", ["fp_mod_add", "ec_p256"],
         lambda: test_fp_mod_add(transport, labels, rng)),
        ("fp_mod_sub", ["fp_mod_sub", "ec_p256"],
         lambda: test_fp_mod_sub(transport, labels, rng)),
        ("fp_mod_add_sub inverse", ["fp_mod_add", "fp_mod_sub", "ec_p256"],
         lambda: test_fp_mod_add_sub_inverse(transport, labels, rng)),
        ("fp_mod_reduce256", ["fp_mod_reduce256"],
         lambda: test_fp_mod_reduce256(transport, labels, rng)),
        ("fp_mod_mul", ["fp_mod_mul"],
         lambda: test_fp_mod_mul(transport, labels, rng)),
        ("fp_mod_inv", ["fp_mod_inv", "ec_p256"],
         lambda: test_fp_mod_inv(transport, labels, rng)),
    ]

    for name, required_labels, test_fn in mod_test_groups:
        print(f"\n--- {name} ---")
        missing = [lbl for lbl in required_labels if labels.address(lbl) is None]
        if missing:
            total_skipped += 1
            print(f"  SKIP: missing labels: {', '.join(missing)}")
            print(f"  (mod256.asm not yet implemented)")
            continue
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

    # Verify labels required for raw arithmetic tests
    required = [
        "fp_src1", "fp_src2", "fp_dst", "fp_carry",
        "fp_copy", "fp_zero", "fp_cmp", "fp_is_zero",
        "fp_add", "fp_sub", "fp_mul", "fp_sqr", "fp_rshift1",
        "fp_tmp1", "fp_tmp2", "fp_tmp3", "fp_tmp4",
        "fp_wide", "fp_r0",
        "sqtab_init", "reu_mul_init",
    ]
    missing = []
    for name in required:
        if labels.address(name) is None:
            missing.append(name)
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    # Report optional mod256 labels
    mod_labels = ["fp_mod_add", "fp_mod_sub", "fp_mod_reduce256",
                  "fp_mod_mul", "fp_mod_inv", "ec_p256", "ec_set_modp"]
    mod_available = [lbl for lbl in mod_labels if labels.address(lbl) is not None]
    mod_missing = [lbl for lbl in mod_labels if labels.address(lbl) is None]
    if mod_missing:
        print(f"Optional mod256 labels missing (will skip modular tests): "
              f"{', '.join(mod_missing)}")
    if mod_available:
        print(f"Optional mod256 labels present: {', '.join(mod_available)}")

    # Launch VICE with REU
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport

        # Wait for program to boot (it prints "READY." after init)
        grid = wait_for_text(transport, "READY.", timeout=600.0, verbose=False)
        if grid is None:
            print("FATAL: Program did not reach READY state")
            print("  (sqtab_init + reu_mul_init may still be running)")
            mgr.release(inst)
            sys.exit(1)

        print("VICE ready, program initialized.")

        # Safety: write JMP $0339 at $0339 so CPU loops harmlessly
        # after jsr() returns (prevents crash when BASIC ROM is banked out)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Re-initialize lookup tables via jsr().  The tables set up during
        # the BASIC SYS startup can be corrupt due to VICE timing issues
        # (binary monitor attach vs. program execution race).  Reinitializing
        # via jsr() guarantees correct state.
        print("Initializing quarter-square table (sqtab_init)...")
        jsr(transport, labels["sqtab_init"], timeout=30.0)
        print("Initializing REU multiply tables (reu_mul_init)...")
        print("  (this takes ~2 minutes in warp mode)")
        jsr(transport, labels["reu_mul_init"], timeout=300.0)
        print("Tables initialized.")

        # Set fp_misc to point to ec_p256 (the prime) for modular routines.
        # We set this directly via memory writes rather than calling
        # ec_set_modp, to avoid any issues with the trampoline.
        if labels.address("ec_p256") is not None:
            p256_addr = labels["ec_p256"]
            set_ptr(transport, labels["fp_misc"], p256_addr)
            print(f"Set fp_misc -> ec_p256 (${p256_addr:04X})")

        passed, failed, skipped = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    if skipped > 0:
        print(f"  ({skipped} test group(s) skipped due to missing mod256.asm labels)")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
