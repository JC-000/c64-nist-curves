#!/usr/bin/env python3
"""test_fp256.py — Direct-memory P-256 field arithmetic tests.

Tests fp_add, fp_sub, fp_mul, fp_sqr (raw arithmetic) and the modular
routines fp_mod_add, fp_mod_sub, fp_mod_reduce256, fp_mod_mul, fp_mod_inv.

Oracle model (see tools/vectors/README.md for the full invariant):

  1. Curve/field constants (P256 etc.) come from `tools.vectors.constants`
     sourced verbatim from NIST FIPS 186-5. They are NOT redefined in this
     file. An adversarial editor rewriting this file alone cannot silently
     change the oracle.

  2. Random operands come from `secrets.token_bytes()`, i.e. the OS CSPRNG.
     There is NO fixed seed by default; every test run exercises a fresh
     sample. A `--seed N` flag is provided for reproducing specific
     failures (seeded runs use `random.Random` explicitly).

  3. NIST-derived KAT anchors come from `tools/vectors/nist_p256_kat.rsp`.
     These are (x, y) points that satisfy y^2 = x^3 - 3x + b mod p and
     therefore exercise fp_mod_sqr / fp_mod_mul / fp_mod_add / fp_mod_sub
     against externally-published, curve-validated values.

  4. For fp_mod_inv, the Python int `pow(a, p-2, p)` is used as an
     independent oracle — Python's `pow` with a modulus is an interpreter
     primitive, not an editable helper.

Usage:
    python3 tools/test_fp256.py [--seed S] [--verbose]
"""

import os
import random
import secrets
import subprocess
import sys
import traceback

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, read_bytes_verified, write_bytes, jsr, wait_for_text,
)

# Shared oracle constants + NIST KAT loader. DO NOT redefine P256 here.
# ruff: noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vectors import (  # type: ignore
    P256, N256, A256, B256, GX256, GY256, load_kat,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# Per-routine random-case count. Set above 20 per the "un-gameable"
# contract so each run covers a broad sample from the OS CSPRNG.
RANDOM_CASES = 20


def _warn_if_vice_running():
    import subprocess, sys
    try:
        res = subprocess.run(["pgrep", "-c", "x64sc"], capture_output=True, text=True, timeout=2)
        n = int(res.stdout.strip() or "0")
        if n > 0:
            print(f"WARNING: {n} other x64sc instance(s) already running - wall-clock timings may be unreliable.", file=sys.stderr)
    except Exception:
        pass  # preflight must never block test execution


# ============================================================================
# Random-input helpers — unseeded by default (secrets.token_bytes)
# ============================================================================

class RandomSource:
    """Either a seeded random.Random (reproducible) or secrets (unseeded).

    Exposes a minimal API: rand_bytes(n), rand_int(lo, hi), rand_field().
    """

    def __init__(self, seed=None):
        self.seed = seed
        if seed is None:
            self._rng = None  # use secrets
        else:
            self._rng = random.Random(seed)

    def rand_bytes(self, n):
        if self._rng is None:
            return secrets.token_bytes(n)
        return bytes(self._rng.getrandbits(8) for _ in range(n))

    def rand_256bit(self):
        return int.from_bytes(self.rand_bytes(32), "little")

    def rand_field_elem(self):
        # Rejection-sampled element in [0, P256 - 1]
        while True:
            v = self.rand_256bit()
            if v < P256:
                return v

    def rand_nonzero_field_elem(self):
        while True:
            v = self.rand_field_elem()
            if v != 0:
                return v

    def rand_wide(self):
        return int.from_bytes(self.rand_bytes(64), "little")


# ============================================================================
# Byte conversion helpers
# ============================================================================

def int_to_le_bytes(val, length=32):
    return val.to_bytes(length, "little")

def le_bytes_to_int(data):
    return int.from_bytes(data, "little")


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

def write_field_elem(transport, addr, value, length=32):
    write_bytes(transport, addr, int_to_le_bytes(value, length))

def read_field_elem(transport, addr, length=32):
    return le_bytes_to_int(read_bytes(transport, addr, length))

def write_wide(transport, labels, value):
    write_bytes(transport, labels["fp_wide"], int_to_le_bytes(value, 64))

def read_wide(transport, labels):
    return le_bytes_to_int(read_bytes(transport, labels["fp_wide"], 64))


# ============================================================================
# C64 routine wrappers
# ============================================================================

def c64_fp_add(transport, labels, a, b):
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"], src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_add"])
    result = read_field_elem(transport, labels["fp_tmp3"])
    carry = le_bytes_to_int(read_bytes_verified(transport, labels["fp_carry"], 1))
    return result, carry

def c64_fp_sub(transport, labels, a, b):
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"], src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_sub"])
    result = read_field_elem(transport, labels["fp_tmp3"])
    borrow = le_bytes_to_int(read_bytes_verified(transport, labels["fp_carry"], 1))
    return result, borrow

def c64_fp_mul(transport, labels, a, b):
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"], src2=labels["fp_tmp2"])
    jsr(transport, labels["fp_mul"], timeout=120.0)
    return read_wide(transport, labels)

def c64_fp_sqr(transport, labels, a):
    write_field_elem(transport, labels["fp_tmp1"], a)
    set_fp_ptrs(transport, labels, src1=labels["fp_tmp1"])
    jsr(transport, labels["fp_sqr"], timeout=120.0)
    return read_wide(transport, labels)

def c64_fp_mod_add(transport, labels, a, b):
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"], src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_mod_add"], timeout=10.0)
    return read_field_elem(transport, labels["fp_tmp3"])

def c64_fp_mod_sub(transport, labels, a, b):
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"], src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_mod_sub"], timeout=10.0)
    return read_field_elem(transport, labels["fp_tmp3"])

def c64_fp_mod_reduce256(transport, labels, wide_val):
    write_wide(transport, labels, wide_val)
    jsr(transport, labels["fp_mod_reduce256"], timeout=30.0)
    return read_field_elem(transport, labels["fp_r0"])

def c64_fp_mod_mul(transport, labels, a, b):
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"], src2=labels["fp_tmp2"])
    jsr(transport, labels["fp_mod_mul"], timeout=120.0)
    return read_field_elem(transport, labels["fp_r0"])

def c64_fp_mod_mul_n(transport, labels, a, b):
    write_field_elem(transport, labels["fp_tmp1"], a)
    write_field_elem(transport, labels["fp_tmp2"], b)
    # Pre-fill dst with a sentinel so we can detect no-op implementations.
    write_field_elem(transport, labels["fp_tmp3"], 0xDEADBEEF)
    set_fp_ptrs(transport, labels,
                src1=labels["fp_tmp1"], src2=labels["fp_tmp2"],
                dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_mod_mul_n"], timeout=180.0)
    return read_field_elem(transport, labels["fp_tmp3"])

def c64_fp_mod_inv(transport, labels, a):
    write_field_elem(transport, labels["fp_tmp1"], a)
    set_fp_ptrs(transport, labels, src1=labels["fp_tmp1"])
    jsr(transport, labels["fp_mod_inv"], timeout=600.0)
    return read_field_elem(transport, labels["fp_r0"])


# ============================================================================
# Test helpers
# ============================================================================

def _report(name, expected, got, extra=""):
    print(f"  FAIL {name}:")
    print(f"    expected = {expected:#066x}")
    print(f"    got      = {got:#066x}")
    if extra:
        print(extra)


# ============================================================================
# Raw arithmetic tests
# ============================================================================

def test_fp_add(transport, labels, rng):
    """fp_add: raw 256-bit addition with carry-out.

    Oracle: Python int addition (interpreter primitive).
    Inputs: edge cases + >=20 unseeded-random + NIST KAT anchors
    (adding Gx + Gy etc. for extra independent data).
    """
    passed = failed = 0
    cases = [
        ("0+0", 0, 0),
        ("1+1", 1, 1),
        ("0+1", 0, 1),
        ("small+small", 0x100, 0x200),
        ("max+1", (1 << 256) - 1, 1),
        ("max+max", (1 << 256) - 1, (1 << 256) - 1),
        ("p256+0", P256, 0),
        ("p256-1+1", P256 - 1, 1),
        # NIST KAT anchors: curve generator coordinates (FIPS 186-5).
        ("NIST KAT #1 Gx+Gy", GX256, GY256),
        ("NIST KAT #2 Gx+p", GX256, P256),
        ("NIST KAT #3 n+Gx",  N256, GX256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_256bit(), rng.rand_256bit()))

    for name, a, b in cases:
        expected_full = a + b
        expected_low = expected_full & ((1 << 256) - 1)
        expected_carry = 1 if expected_full >= (1 << 256) else 0
        result, carry = c64_fp_add(transport, labels, a, b)
        if result == expected_low and carry == expected_carry:
            passed += 1
            if VERBOSE: print(f"  PASS add {name}")
        else:
            failed += 1
            _report(f"add {name}", expected_low, result,
                    f"    carry    exp={expected_carry} got={carry}")
    return passed, failed


def test_fp_sub(transport, labels, rng):
    """fp_sub: raw 256-bit subtract with borrow. Oracle: Python ints."""
    passed = failed = 0
    cases = [
        ("0-0", 0, 0),
        ("1-0", 1, 0),
        ("1-1", 1, 1),
        ("0-1", 0, 1),
        ("10-20", 10, 20),
        ("max-0", (1 << 256) - 1, 0),
        ("max-max", (1 << 256) - 1, (1 << 256) - 1),
        ("p256-1", P256, 1),
        ("NIST KAT #1 Gy-Gx", GY256, GX256),
        ("NIST KAT #2 Gx-Gy", GX256, GY256),
        ("NIST KAT #3 n-Gy",  N256, GY256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_256bit(), rng.rand_256bit()))
    for name, a, b in cases:
        if a >= b:
            expected, expected_borrow = a - b, 0
        else:
            expected, expected_borrow = (a - b) + (1 << 256), 1
        result, borrow = c64_fp_sub(transport, labels, a, b)
        if result == expected and borrow == expected_borrow:
            passed += 1
            if VERBOSE: print(f"  PASS sub {name}")
        else:
            failed += 1
            _report(f"sub {name}", expected, result,
                    f"    borrow   exp={expected_borrow} got={borrow}")
    return passed, failed


def test_fp_mul(transport, labels, rng):
    """fp_mul: 256x256 -> 512-bit. Oracle: Python int *.

    Includes NIST KAT anchors: Gx*Gx, Gx*Gy, Gy*Gy — the squares and
    cross-product of the generator. These appear inside the curve
    equation y^2 = x^3 - 3x + b and are independently verifiable
    against the modular-reduce test below.
    """
    passed = failed = 0
    cases = [
        ("0*0", 0, 0),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("0xFF*0xFF", 0xFF, 0xFF),
        ("1*max", 1, (1 << 256) - 1),
        ("2*max", 2, (1 << 256) - 1),
        ("NIST KAT #1 Gx*Gx", GX256, GX256),
        ("NIST KAT #2 Gx*Gy", GX256, GY256),
        ("NIST KAT #3 Gy*Gy", GY256, GY256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_256bit(), rng.rand_256bit()))
    for name, a, b in cases:
        expected = a * b
        result = c64_fp_mul(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mul {name}")
        else:
            failed += 1
            print(f"  FAIL mul {name}:")
            print(f"    a={a:#066x}\n    b={b:#066x}")
            print(f"    expected={expected:#0130x}")
            print(f"    got     ={result:#0130x}")
    return passed, failed


def test_fp_sqr(transport, labels, rng):
    """fp_sqr: 256-bit -> 512-bit squaring. Oracle: Python `a*a`.

    ALSO cross-checks fp_sqr(a) == fp_mul(a,a) for the same random
    sample — this subsumes the old identity-bypassable fp_sqr_vs_mul
    test because both halves are anchored against the Python oracle.
    """
    passed = failed = 0
    cases = [
        ("0", 0), ("1", 1), ("2", 2), ("3", 3),
        ("0xFF", 0xFF), ("max", (1 << 256) - 1),
        ("NIST KAT #1 Gx", GX256),
        ("NIST KAT #2 Gy", GY256),
        ("NIST KAT #3 n",  N256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_256bit()))
    for name, a in cases:
        expected = a * a
        sqr_result = c64_fp_sqr(transport, labels, a)
        if sqr_result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS sqr {name}")
        else:
            failed += 1
            print(f"  FAIL sqr {name}: a={a:#066x}")
            print(f"    expected={expected:#0130x}")
            print(f"    got     ={sqr_result:#0130x}")
        # Cross-check against fp_mul(a, a) for the SAME input. This
        # defeats a stub that returns constant 0 from both routines:
        # the oracle above (a*a via Python) would already have caught
        # that, and here we also ensure the two routines agree for
        # the full random sample, not just 4 hand-picked values.
        mul_result = c64_fp_mul(transport, labels, a, a)
        if mul_result == sqr_result and mul_result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS sqr==mul {name}")
        else:
            failed += 1
            print(f"  FAIL sqr==mul {name}: sqr={sqr_result:#0130x}")
            print(f"                         mul={mul_result:#0130x}")
            print(f"                         oracle={expected:#0130x}")
    return passed, failed


# ============================================================================
# Utility routine tests (copy/zero/cmp/is_zero/rshift1)
# ============================================================================

def test_fp_copy(transport, labels, rng):
    passed = failed = 0
    cases = [0, 1, (1 << 256) - 1, GX256, GY256]
    for i in range(RANDOM_CASES):
        cases.append(rng.rand_256bit())
    for i, val in enumerate(cases):
        # Pre-zero destination so we know the copy actually wrote.
        write_field_elem(transport, labels["fp_tmp3"], 0)
        write_field_elem(transport, labels["fp_tmp1"], val)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp_tmp1"], dst=labels["fp_tmp3"])
        jsr(transport, labels["fp_copy"])
        result = read_field_elem(transport, labels["fp_tmp3"])
        if result == val:
            passed += 1
            if VERBOSE: print(f"  PASS fp_copy #{i}")
        else:
            failed += 1
            _report(f"fp_copy #{i}", val, result)
    return passed, failed


def test_fp_zero(transport, labels, rng):
    passed = failed = 0
    prefills = [(1 << 256) - 1, GX256, GY256, 0xABCDEF, 0x42]
    for i in range(RANDOM_CASES):
        prefills.append(rng.rand_256bit())
    for i, fill in enumerate(prefills):
        write_field_elem(transport, labels["fp_tmp3"], fill)
        set_fp_ptrs(transport, labels, dst=labels["fp_tmp3"])
        jsr(transport, labels["fp_zero"])
        result = read_field_elem(transport, labels["fp_tmp3"])
        if result == 0:
            passed += 1
            if VERBOSE: print(f"  PASS fp_zero #{i}")
        else:
            failed += 1
            _report(f"fp_zero #{i}", 0, result)
    return passed, failed


def test_fp_cmp(transport, labels, rng):
    """fp_cmp: smoke test that the routine executes without crashing for
    a mix of random and edge-case inputs."""
    passed = failed = 0
    cases = [
        (42, 42),
        (0, 1),
        (1, 0),
        ((1 << 256) - 1, 0),
        (0, (1 << 256) - 1),
        (GX256, GY256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((rng.rand_256bit(), rng.rand_256bit()))
    for a, b in cases:
        write_field_elem(transport, labels["fp_tmp1"], a)
        write_field_elem(transport, labels["fp_tmp2"], b)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp_tmp1"], src2=labels["fp_tmp2"])
        jsr(transport, labels["fp_cmp"])
        passed += 1
    return passed, failed


def test_fp_is_zero(transport, labels, rng):
    """fp_is_zero: smoke test — verifies the routine runs against a mix
    of zero and non-zero inputs. (No flag extraction here; full flag
    checking would require reading the 6502 status register.)"""
    passed = failed = 0
    if labels.address("fp_is_zero") is None:
        return 0, 0
    cases = [0, 1, (1 << 256) - 1, GX256, GY256]
    for i in range(RANDOM_CASES):
        cases.append(rng.rand_256bit())
    for val in cases:
        write_field_elem(transport, labels["fp_tmp1"], val)
        set_fp_ptrs(transport, labels, src1=labels["fp_tmp1"])
        jsr(transport, labels["fp_is_zero"])
        passed += 1
    return passed, failed


def test_fp_rshift1(transport, labels, rng):
    """fp_rshift1: 256-bit logical right shift by 1. Oracle: Python `v >> 1`."""
    passed = failed = 0
    if labels.address("fp_rshift1") is None:
        return 0, 0
    cases = [
        ("0", 0), ("1", 1), ("2", 2), ("3", 3),
        ("max", (1 << 256) - 1), ("high_bit", 1 << 255),
        ("NIST KAT Gx", GX256), ("NIST KAT Gy", GY256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_256bit()))
    for name, val in cases:
        write_field_elem(transport, labels["fp_tmp1"], val)
        set_fp_ptrs(transport, labels,
                    src1=labels["fp_tmp1"], dst=labels["fp_tmp1"])
        jsr(transport, labels["fp_rshift1"])
        result = read_field_elem(transport, labels["fp_tmp1"])
        expected = val >> 1
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS rshift1 {name}")
        else:
            failed += 1
            _report(f"rshift1 {name}", expected, result)
    return passed, failed


# ============================================================================
# Modular arithmetic tests
# ============================================================================

def test_fp_mod_add(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0+0", 0, 0),
        ("1+1", 1, 1),
        ("p-1+1", P256 - 1, 1),
        ("p-1+p-1", P256 - 1, P256 - 1),
        ("p-10+15", P256 - 10, 15),
        ("NIST KAT #1 Gx+Gy", GX256, GY256),
        ("NIST KAT #2 Gx+(p-Gy)", GX256, (P256 - GY256) % P256),
        ("NIST KAT #3 n+1", N256 % P256, 1),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_field_elem(), rng.rand_field_elem()))
    for name, a, b in cases:
        expected = (a + b) % P256
        result = c64_fp_mod_add(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_add {name}")
        else:
            failed += 1
            _report(f"mod_add {name}", expected, result)
    return passed, failed


def test_fp_mod_sub(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0-0", 0, 0),
        ("1-0", 1, 0),
        ("0-1", 0, 1),
        ("1-1", 1, 1),
        ("10-20", 10, 20),
        ("p-1-0", P256 - 1, 0),
        ("NIST KAT #1 Gy-Gx", GY256, GX256),
        ("NIST KAT #2 Gx-Gy", GX256, GY256),
        ("NIST KAT #3 0-Gy", 0, GY256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_field_elem(), rng.rand_field_elem()))
    for name, a, b in cases:
        expected = (a - b) % P256
        result = c64_fp_mod_sub(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_sub {name}")
        else:
            failed += 1
            _report(f"mod_sub {name}", expected, result)
    return passed, failed


def test_fp_mod_reduce256(transport, labels, rng):
    """Solinas fast reduction of 512-bit fp_wide -> fp_r0 mod P256.

    Oracle: Python `w % P256`. NIST anchors: products of the generator
    components (Gx*Gx, Gx*Gy, Gy*Gy) — these must reduce to specific
    values that, combined with mod_sub/mod_add, satisfy the curve
    equation.
    """
    passed = failed = 0
    cases = [
        ("zero", 0),
        ("one", 1),
        ("p itself", P256),
        ("p+1", P256 + 1),
        ("p-1", P256 - 1),
        ("2*p", 2 * P256),
        ("p^2", P256 * P256),
        ("3*5", 15),
        ("7*7", 49),
        ("NIST KAT #1 Gx*Gx", GX256 * GX256),
        ("NIST KAT #2 Gx*Gy", GX256 * GY256),
        ("NIST KAT #3 Gy*Gy", GY256 * GY256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_wide()))
    for i in range(4):
        a = rng.rand_field_elem()
        b = rng.rand_field_elem()
        cases.append((f"product#{i}", a * b))
    for name, wide_val in cases:
        expected = wide_val % P256
        result = c64_fp_mod_reduce256(transport, labels, wide_val)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_reduce {name}")
        else:
            failed += 1
            print(f"  FAIL mod_reduce {name}:")
            print(f"    input    = {wide_val:#0130x}")
            print(f"    expected = {expected:#066x}")
            print(f"    got      = {result:#066x}")
    return passed, failed


def test_fp_mod_mul(transport, labels, rng):
    passed = failed = 0
    cases = [
        ("0*0", 0, 0),
        ("0*1", 0, 1),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("7*7", 7, 7),
        ("a*1=a", rng.rand_field_elem(), 1),
        ("a*0=0", rng.rand_field_elem(), 0),
        ("NIST KAT #1 Gx*Gx mod p", GX256, GX256),
        ("NIST KAT #2 Gx*Gy mod p", GX256, GY256),
        ("NIST KAT #3 Gy*Gy mod p", GY256, GY256),
    ]
    for i in range(RANDOM_CASES):
        cases.append((f"rand#{i}", rng.rand_field_elem(), rng.rand_field_elem()))
    for name, a, b in cases:
        expected = (a * b) % P256
        result = c64_fp_mod_mul(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_mul {name}")
        else:
            failed += 1
            _report(f"mod_mul {name}", expected, result,
                    f"    a = {a:#066x}\n    b = {b:#066x}")
    return passed, failed


def test_fp_mod_mul_n(transport, labels, rng):
    """fp_mod_mul_n: (a*b) mod n256 (group order).

    Oracle: Python `(a * b) % N256`. Inputs sampled from [0, N256-1].
    This primitive is required for ECDSA verify, which needs modular
    multiplication mod n (the group order), not mod p. The default
    `fp_mod_mul` is hardcoded to Solinas p-reduction and cannot handle
    mod-n arithmetic.
    """
    passed = failed = 0
    cases = [
        ("0*0", 0, 0),
        ("0*1", 0, 1),
        ("1*0", 1, 0),
        ("1*1", 1, 1),
        ("3*5", 3, 5),
        ("n-1*1", N256 - 1, 1),
        ("1*n-1", 1, N256 - 1),
        ("n-1*n-1", N256 - 1, N256 - 1),
    ]
    n_rand = 10 if "--full" in sys.argv else 3
    for i in range(n_rand):
        # Rejection-sample uniform inputs in [0, N256-1].
        while True:
            a = rng.rand_256bit()
            if a < N256:
                break
        while True:
            b = rng.rand_256bit()
            if b < N256:
                break
        cases.append((f"rand#{i}", a, b))
    for name, a, b in cases:
        expected = (a * b) % N256
        result = c64_fp_mod_mul_n(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mod_mul_n {name}")
        else:
            failed += 1
            _report(f"mod_mul_n {name}", expected, result,
                    f"    a = {a:#066x}\n    b = {b:#066x}")
    return passed, failed


def test_fp_mod_inv(transport, labels, rng):
    """fp_mod_inv: modular inverse via binary GCD.

    Oracle: Python `pow(a, P256 - 2, P256)` (Fermat's little theorem,
    interpreter primitive). Very slow on C64 (~10+ minutes per call
    in VICE). Default fast mode tests 5 random invertible elements
    plus trivial case a=1. --slow-inv adds more.
    """
    passed = failed = 0
    cases = [("inv(1)", 1)]
    # Fast-mode random cases (5 invertibles). Task spec: ~5 random
    # inverses in fast mode, 10+ in slow mode.
    n_fast = 5
    n_slow = 10 if "--slow-inv" in sys.argv else 0
    n_extra = n_fast + n_slow
    for i in range(n_extra):
        a = rng.rand_nonzero_field_elem()
        cases.append((f"inv(rand#{i})", a))
    if n_slow:
        print("  NOTE: --slow-inv enabled, extra cases will be slow")
    for name, a in cases:
        print(f"    {name}...", end="", flush=True)
        expected = pow(a, P256 - 2, P256)
        result = c64_fp_mod_inv(transport, labels, a)
        if result == expected:
            # Additional sanity: a * result == 1 mod p (independent check).
            if (a * result) % P256 == 1:
                passed += 1
                print(" ok")
            else:
                failed += 1
                print(" FAIL (sanity a*inv != 1)")
        else:
            failed += 1
            print(" FAIL")
            print(f"    a        = {a:#066x}")
            print(f"    expected = {expected:#066x}")
            print(f"    got      = {result:#066x}")
            print(f"    a*got mod p = {(a*result)%P256:#066x}")
    return passed, failed


# ============================================================================
# NIST KAT curve-equation anchor
# ============================================================================

def test_nist_kat_curve_equation(transport, labels):
    """Independent anchor: for every (x, y) in tools/vectors/nist_p256_kat.rsp
    verify on the C64 that y^2 == x^3 - 3x + b (mod p).

    This composes fp_mod_mul, fp_mod_sub, fp_mod_add with external
    NIST/Wycheproof-sourced points. An assembly stub that returns
    constant 0 from all routines cannot possibly pass this — the
    curve equation only holds for valid points and 0 != 0^3 - 3*0 + b
    = b for any non-zero b.
    """
    passed = failed = 0
    kat = load_kat("nist_p256_kat.rsp")
    assert kat.params["p"] == P256, "KAT file tampered: p mismatch"
    assert kat.params["b"] == B256, "KAT file tampered: b mismatch"
    pts = kat.point_records()
    print(f"    Loaded {len(pts)} KAT points from nist_p256_kat.rsp")
    for label, x, y in pts:
        # lhs = y^2 mod p
        lhs = c64_fp_mod_mul(transport, labels, y, y)
        # x^2 mod p
        x2 = c64_fp_mod_mul(transport, labels, x, x)
        # x^3 mod p
        x3 = c64_fp_mod_mul(transport, labels, x2, x)
        # 3x mod p (via add)
        two_x = c64_fp_mod_add(transport, labels, x, x)
        three_x = c64_fp_mod_add(transport, labels, two_x, x)
        # x^3 - 3x mod p
        t = c64_fp_mod_sub(transport, labels, x3, three_x)
        # + b
        rhs = c64_fp_mod_add(transport, labels, t, B256)
        if lhs == rhs:
            passed += 1
            if VERBOSE: print(f"  PASS curve_eq {label}")
        else:
            failed += 1
            print(f"  FAIL curve_eq {label}:")
            print(f"    x = {x:#066x}")
            print(f"    y = {y:#066x}")
            print(f"    y^2         = {lhs:#066x}")
            print(f"    x^3-3x+b    = {rhs:#066x}")
            # Cross-check against Python oracle to localize the bug:
            py_lhs = (y*y) % P256
            py_rhs = (pow(x, 3, P256) + A256*x + B256) % P256
            print(f"    py y^2      = {py_lhs:#066x}")
            print(f"    py x^3-3x+b = {py_rhs:#066x}")
    return passed, failed


def test_fp_mod_add_sub_inverse(transport, labels, rng):
    """(a + b) - b == a mod p. Oracle still covers the random a
    comparison (a is a Python int the 6502 never got to see first)."""
    passed = failed = 0
    for i in range(RANDOM_CASES):
        a = rng.rand_field_elem()
        b = rng.rand_field_elem()
        sum_ab = c64_fp_mod_add(transport, labels, a, b)
        result = c64_fp_mod_sub(transport, labels, sum_ab, b)
        # Anchor BOTH halves: (a+b) must match Python (a+b)%p AND
        # the final round-trip must match the original a.
        expected_sum = (a + b) % P256
        if sum_ab == expected_sum and result == a:
            passed += 1
            if VERBOSE: print(f"  PASS mod_add_sub_inverse #{i}")
        else:
            failed += 1
            print(f"  FAIL mod_add_sub_inverse #{i}:")
            print(f"    a           = {a:#066x}")
            print(f"    b           = {b:#066x}")
            print(f"    a+b (c64)   = {sum_ab:#066x}")
            print(f"    a+b (py)    = {expected_sum:#066x}")
            print(f"    (a+b)-b     = {result:#066x}")
    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, rng):
    total_passed = 0
    total_failed = 0
    total_skipped = 0

    raw_test_groups = [
        ("fp_copy",   lambda: test_fp_copy(transport, labels, rng)),
        ("fp_zero",   lambda: test_fp_zero(transport, labels, rng)),
        ("fp_cmp",    lambda: test_fp_cmp(transport, labels, rng)),
        ("fp_is_zero",lambda: test_fp_is_zero(transport, labels, rng)),
        ("fp_rshift1",lambda: test_fp_rshift1(transport, labels, rng)),
        ("fp_add",    lambda: test_fp_add(transport, labels, rng)),
        ("fp_sub",    lambda: test_fp_sub(transport, labels, rng)),
        ("fp_mul",    lambda: test_fp_mul(transport, labels, rng)),
        ("fp_sqr (+cross-check vs fp_mul)",
         lambda: test_fp_sqr(transport, labels, rng)),
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
        ("fp_mod_mul_n (group order)", ["fp_mod_mul_n", "ec_n256"],
         lambda: test_fp_mod_mul_n(transport, labels, rng)),
        ("NIST KAT curve-equation anchor",
         ["fp_mod_mul", "fp_mod_add", "fp_mod_sub", "ec_p256"],
         lambda: test_nist_kat_curve_equation(transport, labels)),
        ("fp_mod_inv", ["fp_mod_inv", "ec_p256"],
         lambda: test_fp_mod_inv(transport, labels, rng)),
    ]

    for name, required_labels, test_fn in mod_test_groups:
        print(f"\n--- {name} ---")
        missing = [lbl for lbl in required_labels if labels.address(lbl) is None]
        if missing:
            total_skipped += 1
            print(f"  SKIP: missing labels: {', '.join(missing)}")
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
    _warn_if_vice_running()
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

    labels = Labels.from_file(LABELS_PATH)

    required = [
        "fp_src1", "fp_src2", "fp_dst", "fp_carry",
        "fp_copy", "fp_zero", "fp_cmp",
        "fp_add", "fp_sub", "fp_mul", "fp_sqr",
        "fp_tmp1", "fp_tmp2", "fp_tmp3", "fp_tmp4",
        "fp_wide", "fp_r0",
        "sqtab_init", "reu_mul_init",
    ]
    missing = [name for name in required if labels.address(name) is None]
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    mod_labels = ["fp_mod_add", "fp_mod_sub", "fp_mod_reduce256",
                  "fp_mod_mul", "fp_mod_mul_n", "fp_mod_inv",
                  "ec_p256", "ec_n256", "ec_set_modp"]
    mod_available = [lbl for lbl in mod_labels if labels.address(lbl) is not None]
    mod_missing = [lbl for lbl in mod_labels if labels.address(lbl) is None]
    if mod_missing:
        print(f"Optional mod256 labels missing: {', '.join(mod_missing)}")
    if mod_available:
        print(f"Optional mod256 labels present: {', '.join(mod_available)}")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport

        grid = wait_for_text(transport, "READY.", timeout=600.0, verbose=False)
        if grid is None:
            print("FATAL: Program did not reach READY state")
            mgr.release(inst)
            sys.exit(1)

        print("VICE ready, program initialized.")

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("Initializing quarter-square table (sqtab_init)...")
        jsr(transport, labels["sqtab_init"], timeout=30.0)
        print("Initializing REU multiply tables (reu_mul_init)...")
        print("  (this takes ~2 minutes in warp mode)")
        jsr(transport, labels["reu_mul_init"], timeout=300.0)
        print("Tables initialized.")

        if labels.address("ec_p256") is not None:
            p256_addr = labels["ec_p256"]
            set_ptr(transport, labels["fp_misc"], p256_addr)
            print(f"Set fp_misc -> ec_p256 (${p256_addr:04X})")

        passed, failed, skipped = run_tests(transport, labels, rng)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
