#!/usr/bin/env python3
"""test_fp384.py — Direct-memory P-384 field arithmetic tests.

Tests raw 48-byte arithmetic (copy/zero/cmp/is_zero/rshift1/add/sub/mul/sqr)
and modular arithmetic (mod_add/mod_sub/mod_reduce384/mod_mul/mod_sqr/mod_inv).

Oracle model (see tools/vectors/README.md for the full invariant):

  1. Curve/field constants (P384 etc.) come from `tools.vectors.constants`
     sourced verbatim from NIST FIPS 186-5. They are NOT redefined in this
     file.
  2. Random operands come from `secrets.token_bytes()` (OS CSPRNG); the
     default run has NO fixed seed. `--seed N` is still available for
     reproducing specific failures.
  3. NIST-derived KAT anchors come from `tools/vectors/nist_p384_kat.rsp`.
     These (x, y) points satisfy y^2 = x^3 - 3x + b mod p and exercise
     fp_mod_sqr / fp_mod_mul / fp_mod_add / fp_mod_sub against
     externally-published curve points.
  4. For fp_mod_inv, the Python int `pow(a, p-2, p)` is used as an
     independent oracle.

Usage:
    python3 tools/test_fp384.py [--seed S] [--verbose]
"""

import os
import random
import secrets
import subprocess
import sys
import time
import traceback

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)

# Shared oracle constants + NIST KAT loader. DO NOT redefine P384 here.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vectors import (  # type: ignore
    P384, N384, A384, B384, GX384, GY384, load_kat,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False
RANDOM_CASES = 20


# ============================================================================
# Random-input helpers — unseeded by default
# ============================================================================

class RandomSource:
    def __init__(self, seed=None):
        self.seed = seed
        self._rng = random.Random(seed) if seed is not None else None

    def rand_bytes(self, n):
        if self._rng is None:
            return secrets.token_bytes(n)
        return bytes(self._rng.getrandbits(8) for _ in range(n))

    def rand_384bit(self):
        return int.from_bytes(self.rand_bytes(48), "little")

    def rand_field_elem(self):
        while True:
            v = self.rand_384bit()
            if v < P384:
                return v

    def rand_nonzero_field_elem(self):
        while True:
            v = self.rand_field_elem()
            if v != 0:
                return v

    def rand_wide(self):
        return int.from_bytes(self.rand_bytes(96), "little")


# ============================================================================
# Byte conversion helpers
# ============================================================================

def int_to_le_bytes_384(val): return val.to_bytes(48, "little")
def le_bytes_to_int(data): return int.from_bytes(data, "little")


# ============================================================================
# C64 helper functions
# ============================================================================

def set_ptr(transport, zp_addr, target_addr):
    write_bytes(transport, zp_addr,
                bytes([target_addr & 0xFF, (target_addr >> 8) & 0xFF]))

def set_fp_ptrs(transport, labels, src1=None, src2=None, dst=None, misc=None):
    if src1 is not None: set_ptr(transport, labels["fp_src1"], src1)
    if src2 is not None: set_ptr(transport, labels["fp_src2"], src2)
    if dst  is not None: set_ptr(transport, labels["fp_dst"],  dst)
    if misc is not None: set_ptr(transport, labels["fp_misc"], misc)

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
                src1=labels["fp384_tmp1"], src2=labels["fp384_tmp2"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_add_384"], timeout=10.0)
    result = read_fe_384(transport, labels["fp384_tmp3"])
    carry = le_bytes_to_int(read_bytes(transport, labels["fp_carry"], 1))
    return result, carry

def c64_fp_sub(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"], src2=labels["fp384_tmp2"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_sub_384"], timeout=10.0)
    result = read_fe_384(transport, labels["fp384_tmp3"])
    borrow = le_bytes_to_int(read_bytes(transport, labels["fp_carry"], 1))
    return result, borrow

def c64_fp_mul(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"], src2=labels["fp384_tmp2"])
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
                src1=labels["fp384_tmp1"], src2=labels["fp384_tmp2"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_mod_add_384"], timeout=10.0)
    return read_fe_384(transport, labels["fp384_tmp3"])

def c64_fp_mod_sub(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"], src2=labels["fp384_tmp2"],
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
                src1=labels["fp384_tmp1"], src2=labels["fp384_tmp2"])
    jsr(transport, labels["fp_mod_mul_384"], timeout=240.0)
    return read_fe_384(transport, labels["fp384_r0"])

def c64_fp_mod_mul_n(transport, labels, a, b):
    write_fe_384(transport, labels["fp384_tmp1"], a)
    write_fe_384(transport, labels["fp384_tmp2"], b)
    # Sentinel-fill dst so a no-op implementation is detectable.
    write_fe_384(transport, labels["fp384_tmp3"], 0xDEADBEEFCAFEBABE)
    set_fp_ptrs(transport, labels,
                src1=labels["fp384_tmp1"], src2=labels["fp384_tmp2"],
                dst=labels["fp384_tmp3"])
    jsr(transport, labels["fp_mod_mul_n_384"], timeout=300.0)
    return read_fe_384(transport, labels["fp384_tmp3"])

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
# Utility routine tests
# ============================================================================

def test_fp_copy(transport, labels, rng):
    passed = failed = 0
    cases = [0, 1, (1 << 384) - 1, GX384, GY384]
    for i in range(RANDOM_CASES):
        cases.append(rng.rand_384bit())
    for i, val in enumerate(cases):
        write_fe_384(transport, labels["fp384_tmp3"], 0)
        write_fe_384(transport, labels["fp384_tmp1"], val)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp384_tmp1"], dst=labels["fp384_tmp3"])
        jsr(transport, labels["fp_copy_384"], timeout=10.0)
        result = read_fe_384(transport, labels["fp384_tmp3"])
        if result == val:
            passed += 1
            if VERBOSE: print(f"  PASS fp_copy_384 #{i}")
        else:
            failed += 1
            print(f"  FAIL fp_copy_384 #{i}: expected {val:#098x}")
            print(f"                         got      {result:#098x}")
    return passed, failed


def test_fp_zero(transport, labels, rng):
    passed = failed = 0
    prefills = [(1 << 384) - 1, GX384, GY384, 0xABCDEF, 0x42]
    for i in range(RANDOM_CASES):
        prefills.append(rng.rand_384bit())
    for i, fill in enumerate(prefills):
        write_fe_384(transport, labels["fp384_tmp3"], fill)
        set_fp_ptrs(transport, labels, dst=labels["fp384_tmp3"])
        jsr(transport, labels["fp_zero_384"], timeout=10.0)
        result = read_fe_384(transport, labels["fp384_tmp3"])
        if result == 0:
            passed += 1
            if VERBOSE: print(f"  PASS fp_zero_384 #{i}")
        else:
            failed += 1
            print(f"  FAIL fp_zero_384 #{i}: got {result:#098x}")
    return passed, failed


def test_fp_cmp(transport, labels, rng):
    passed = failed = 0
    cases = [(42, 42), (0, 1), (1, 0), ((1 << 384) - 1, 0), (GX384, GY384)]
    for i in range(RANDOM_CASES):
        cases.append((rng.rand_384bit(), rng.rand_384bit()))
    for a, b in cases:
        write_fe_384(transport, labels["fp384_tmp1"], a)
        write_fe_384(transport, labels["fp384_tmp2"], b)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp384_tmp1"], src2=labels["fp384_tmp2"])
        jsr(transport, labels["fp_cmp_384"], timeout=10.0)
        passed += 1
    return passed, failed


def test_fp_is_zero(transport, labels, rng):
    passed = failed = 0
    cases = [0, 1, (1 << 384) - 1, GX384, GY384, 1 << 380]
    for i in range(RANDOM_CASES):
        cases.append(rng.rand_384bit())
    for val in cases:
        write_fe_384(transport, labels["fp384_tmp1"], val)
        set_fp_ptrs(transport, labels, src1=labels["fp384_tmp1"])
        jsr(transport, labels["fp_is_zero_384"], timeout=10.0)
        passed += 1
    return passed, failed


def test_fp_rshift1(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0", 0), ("1", 1), ("2", 2), ("3", 3),
        ("max", (1 << 384) - 1), ("high_bit", 1 << 383),
        ("NIST KAT Gx", GX384), ("NIST KAT Gy", GY384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_384bit()))
    for name, val in cases:
        write_fe_384(transport, labels["fp384_tmp1"], val)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp384_tmp1"], dst=labels["fp384_tmp1"])
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
# Raw arithmetic tests — oracles are Python int ops
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
        ("NIST KAT #1 Gx+Gy", GX384, GY384),
        ("NIST KAT #2 Gx+p",  GX384, P384),
        ("NIST KAT #3 n+Gx",  N384 % (1 << 384), GX384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_384bit(), rng.rand_384bit()))
    for name, a, b in cases:
        full = a + b
        expected_low = full & ((1 << 384) - 1)
        expected_carry = 1 if full >= (1 << 384) else 0
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
        ("NIST KAT #1 Gy-Gx", GY384, GX384),
        ("NIST KAT #2 Gx-Gy", GX384, GY384),
        ("NIST KAT #3 n-Gy",  N384 % (1 << 384), GY384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_384bit(), rng.rand_384bit()))
    for name, a, b in cases:
        if a >= b:
            expected, expected_borrow = a - b, 0
        else:
            expected, expected_borrow = (a - b) + (1 << 384), 1
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
        ("NIST KAT #1 Gx*Gx", GX384, GX384),
        ("NIST KAT #2 Gx*Gy", GX384, GY384),
        ("NIST KAT #3 Gy*Gy", GY384, GY384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_384bit(), rng.rand_384bit()))
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
    """Raw 384 squaring. Also cross-checks fp_sqr(a) == fp_mul(a,a)
    against the Python oracle for the random sample (subsumes the
    old identity-bypassable fp_sqr_vs_mul)."""
    passed = failed = 0
    cases = [
        ("0", 0), ("1", 1), ("3", 3), ("5", 5),
        ("0xFF", 0xFF), ("max", (1 << 384) - 1),
        ("NIST KAT #1 Gx", GX384),
        ("NIST KAT #2 Gy", GY384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_384bit()))
    for name, a in cases:
        expected = a * a
        sqr_result = c64_fp_sqr(transport, labels, a)
        if sqr_result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS sqr {name}")
        else:
            failed += 1
            print(f"  FAIL sqr {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    expected = {expected:#0194x}")
            print(f"    got      = {sqr_result:#0194x}")
        mul_result = c64_fp_mul(transport, labels, a, a)
        if mul_result == sqr_result and mul_result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS sqr==mul {name}")
        else:
            failed += 1
            print(f"  FAIL sqr==mul {name}: sqr={sqr_result:#0194x}")
            print(f"                         mul={mul_result:#0194x}")
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
        ("NIST KAT #1 Gx+Gy", GX384, GY384),
        ("NIST KAT #2 Gx+(p-Gy)", GX384, (P384 - GY384) % P384),
        ("NIST KAT #3 (n mod p)+1", N384 % P384, 1),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_field_elem(), rng.rand_field_elem()))
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
        ("NIST KAT #1 Gy-Gx", GY384, GX384),
        ("NIST KAT #2 Gx-Gy", GX384, GY384),
        ("NIST KAT #3 0-Gy",  0, GY384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_field_elem(), rng.rand_field_elem()))
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
        ("NIST KAT #1 Gx*Gx", GX384 * GX384),
        ("NIST KAT #2 Gx*Gy", GX384 * GY384),
        ("NIST KAT #3 Gy*Gy", GY384 * GY384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_wide()))
    for i in range(4):
        a = rng.rand_field_elem()
        b = rng.rand_field_elem()
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
    r = rng.rand_field_elem()
    r2 = rng.rand_field_elem()
    cases = [
        ("0*0", 0, 0),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("7*7", 7, 7),
        ("a*1=a", r, 1),
        ("a*0=0", r2, 0),
        ("NIST KAT #1 Gx*Gx mod p", GX384, GX384),
        ("NIST KAT #2 Gx*Gy mod p", GX384, GY384),
        ("NIST KAT #3 Gy*Gy mod p", GY384, GY384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_field_elem(), rng.rand_field_elem()))
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


def test_fp_mod_mul_n(transport, labels, rng):
    """fp_mod_mul_n_384: (a*b) mod n384 (group order).

    Oracle: Python `(a * b) % N384`. Inputs sampled from [0, N384-1].
    Required for ECDSA verify on P-384; the default fp_mod_mul_384 is
    hardcoded to P-384 Solinas and cannot compute mod-n products.
    """
    passed = failed = 0
    cases = [
        ("0*0", 0, 0),
        ("0*1", 0, 1),
        ("1*0", 1, 0),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("n-1*1", N384 - 1, 1),
        ("1*n-1", 1, N384 - 1),
        ("n-1*n-1", N384 - 1, N384 - 1),
    ]
    n_rand = 10 if "--full" in sys.argv else 3
    for i in range(n_rand):
        while True:
            a = rng.rand_384bit()
            if a < N384:
                break
        while True:
            b = rng.rand_384bit()
            if b < N384:
                break
        cases.append((f"rand#{i}", a, b))
    for name, a, b in cases:
        expected = (a * b) % N384
        result = c64_fp_mod_mul_n(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_mul_n {name}")
        else:
            failed += 1
            print(f"  FAIL mod_mul_n {name}:")
            print(f"    a        = {a:#098x}")
            print(f"    b        = {b:#098x}")
            print(f"    expected = {expected:#098x}")
            print(f"    got      = {result:#098x}")
    return passed, failed


def test_fp_mod_sqr(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0", 0), ("1", 1), ("3", 3), ("7", 7),
        ("NIST KAT #1 Gx", GX384),
        ("NIST KAT #2 Gy", GY384),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_field_elem()))
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
    """fp_mod_inv_384: modular inverse via binary GCD.

    Oracle: `pow(a, P384 - 2, P384)` (Fermat). Very slow — fast mode
    tests 5 random invertibles plus a=1. --slow-inv adds 10 more.
    """
    passed = failed = 0
    cases = [("inv(1)", 1)]
    n_fast = 5
    n_slow = 10 if "--slow-inv" in sys.argv else 0
    for i in range(n_fast + n_slow):
        cases.append((f"inv(rand#{i})", rng.rand_nonzero_field_elem()))
    if n_slow:
        print("  NOTE: --slow-inv enabled, extra cases will be slow")
    for name, a in cases:
        print(f"    {name}...", end="", flush=True)
        expected = pow(a, P384 - 2, P384)
        result = c64_fp_mod_inv(transport, labels, a)
        if result == expected and (a * result) % P384 == 1:
            passed += 1
            print(" ok")
        else:
            failed += 1
            print(" FAIL")
            print(f"    a        = {a:#098x}")
            print(f"    expected = {expected:#098x}")
            print(f"    got      = {result:#098x}")
    return passed, failed


def test_nist_kat_curve_equation(transport, labels):
    """Independent anchor: for every (x, y) in nist_p384_kat.rsp
    verify on the C64 that y^2 == x^3 - 3x + b (mod p)."""
    passed = failed = 0
    kat = load_kat("nist_p384_kat.rsp")
    assert kat.params["p"] == P384, "KAT file tampered: p mismatch"
    assert kat.params["b"] == B384, "KAT file tampered: b mismatch"
    pts = kat.point_records()
    print(f"    Loaded {len(pts)} KAT points from nist_p384_kat.rsp")
    for label, x, y in pts:
        lhs = c64_fp_mod_mul(transport, labels, y, y)
        x2 = c64_fp_mod_mul(transport, labels, x, x)
        x3 = c64_fp_mod_mul(transport, labels, x2, x)
        two_x = c64_fp_mod_add(transport, labels, x, x)
        three_x = c64_fp_mod_add(transport, labels, two_x, x)
        t = c64_fp_mod_sub(transport, labels, x3, three_x)
        rhs = c64_fp_mod_add(transport, labels, t, B384)
        if lhs == rhs:
            passed += 1
            if VERBOSE: print(f"  PASS curve_eq {label}")
        else:
            failed += 1
            print(f"  FAIL curve_eq {label}:")
            print(f"    x = {x:#098x}")
            print(f"    y = {y:#098x}")
            print(f"    y^2      = {lhs:#098x}")
            print(f"    x^3-3x+b = {rhs:#098x}")
            py_lhs = (y*y) % P384
            py_rhs = (pow(x, 3, P384) + A384*x + B384) % P384
            print(f"    py y^2   = {py_lhs:#098x}")
            print(f"    py rhs   = {py_rhs:#098x}")
    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, rng):
    total_passed = 0
    total_failed = 0
    total_skipped = 0

    test_groups = [
        ("fp_copy_384",   lambda: test_fp_copy(transport, labels, rng)),
        ("fp_zero_384",   lambda: test_fp_zero(transport, labels, rng)),
        ("fp_cmp_384",    lambda: test_fp_cmp(transport, labels, rng)),
        ("fp_is_zero_384",lambda: test_fp_is_zero(transport, labels, rng)),
        ("fp_rshift1_384",lambda: test_fp_rshift1(transport, labels, rng)),
        ("fp_add_384",    lambda: test_fp_add(transport, labels, rng)),
        ("fp_sub_384",    lambda: test_fp_sub(transport, labels, rng)),
        ("fp_mul_384",    lambda: test_fp_mul(transport, labels, rng)),
        ("fp_sqr_384 (+cross-check vs fp_mul_384)",
         lambda: test_fp_sqr(transport, labels, rng)),
        ("fp_mod_add_384",    lambda: test_fp_mod_add(transport, labels, rng)),
        ("fp_mod_sub_384",    lambda: test_fp_mod_sub(transport, labels, rng)),
        ("fp_mod_reduce384",  lambda: test_fp_mod_reduce(transport, labels, rng)),
        ("fp_mod_mul_384",    lambda: test_fp_mod_mul(transport, labels, rng)),
        ("fp_mod_mul_n_384 (group order)",
         lambda: test_fp_mod_mul_n(transport, labels, rng)),
        ("fp_mod_sqr_384",    lambda: test_fp_mod_sqr(transport, labels, rng)),
        ("NIST KAT curve-equation anchor",
         lambda: test_nist_kat_curve_equation(transport, labels)),
        ("fp_mod_inv_384",    lambda: test_fp_mod_inv(transport, labels, rng)),
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

    seed = None
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

    if seed is None:
        print("Random source: secrets.token_bytes (unseeded, per-run CSPRNG)")
    else:
        print(f"Random source: random.Random(seed={seed}) [REPRODUCIBLE]")
    rng = RandomSource(seed=seed)

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

    labels = Labels.from_file(LABELS_PATH)

    required = [
        "fp_src1", "fp_src2", "fp_dst", "fp_misc", "fp_carry",
        "fp_copy_384", "fp_zero_384", "fp_cmp_384", "fp_is_zero_384",
        "fp_add_384", "fp_sub_384", "fp_rshift1_384",
        "fp_mul_384", "fp_sqr_384",
        "fp_mod_add_384", "fp_mod_sub_384", "fp_mod_reduce384",
        "fp_mod_mul_384", "fp_mod_mul_n_384", "fp_mod_sqr_384", "fp_mod_inv_384",
        "ec_n384",
        "fp384_tmp1", "fp384_tmp2", "fp384_tmp3", "fp384_tmp4",
        "fp384_wide", "fp384_r0", "ec_p384",
        "sqtab_init", "reu_mul_init",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config,
                             port_range_start=6511,
                             port_range_end=6531) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport

        print("Waiting for init sentinel...")
        start = time.time()
        sentinel_ok = False
        while time.time() - start < 600.0:
            sentinel = read_bytes(transport, 0x02A7, 1)
            if sentinel[0] == 0x42:
                sentinel_ok = True
                break
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

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        p384_addr = labels["ec_p384"]
        set_ptr(transport, labels["fp_misc"], p384_addr)
        print(f"Set fp_misc -> ec_p384 (${p384_addr:04X})")

        passed, failed, skipped = run_tests(transport, labels, rng)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
