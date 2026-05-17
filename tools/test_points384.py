#!/usr/bin/env python3
"""test_points384.py -- Direct-memory P-384 point operation tests.

Tests ec_point_double_384, ec_point_add_384, ec_scalar_mul_384.
All field elements are LITTLE-ENDIAN (byte 0 = LSB).
Point layout: X = offset 0..47, Y = offset 48..95, Z = offset 96..143.

Gameability defense (see tools/vectors/README.md): external
`cryptography` oracle for scalar multiplication, NIST CAVP KATs as
fixed anchors, and unseeded random scalars per run.

Usage:
    python3 tools/test_points384.py [--seed S] [--verbose] [--full]
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
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

sys.path.insert(0, PROJECT_ROOT)

from tools.vectors import (  # noqa: E402
    P384_GX, P384_GY, P384_N, P384_P,
    affine_add, affine_double,
    jacobian_to_affine,
    load_nist_scalar_mul_kats,
    scalar_mul_oracle,
    self_check,
)
from tools.vectors.loader import INFINITY, is_infinity  # noqa: E402

VERBOSE = False

G_X = P384_GX
G_Y = P384_GY
P384 = P384_P
N384 = P384_N


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
# Byte conversion helpers
# ============================================================================

def int_to_le_bytes(val, length=48):
    return val.to_bytes(length, "little")

def le_bytes_to_int(data):
    return int.from_bytes(data, "little")

def int_to_be_bytes(val, length=48):
    return val.to_bytes(length, "big")

def set_ptr(transport, zp_addr, target_addr):
    write_bytes(transport, zp_addr,
                bytes([target_addr & 0xFF, (target_addr >> 8) & 0xFF]))


def write_field_elem(transport, addr, value):
    write_bytes(transport, addr, int_to_le_bytes(value, 48))

def read_field_elem(transport, addr):
    return le_bytes_to_int(read_bytes(transport, addr, 48))

def write_jacobian_point(transport, base_addr, x, y, z):
    write_field_elem(transport, base_addr, x)
    write_field_elem(transport, base_addr + 48, y)
    write_field_elem(transport, base_addr + 96, z)

def write_affine_point(transport, base_addr, x, y):
    write_field_elem(transport, base_addr, x)
    write_field_elem(transport, base_addr + 48, y)

def read_jacobian_point(transport, base_addr):
    x = read_field_elem(transport, base_addr)
    y = read_field_elem(transport, base_addr + 48)
    z = read_field_elem(transport, base_addr + 96)
    return x, y, z


# ============================================================================
# Oracle helpers
# ============================================================================

def random_affine_point(rng):
    k = rng.randrange(1, N384 - 1)
    return scalar_mul_oracle(k, "p384")


def c64_double(transport, labels, px, py):
    write_jacobian_point(transport, labels["ec384_p1"], px, py, 1)
    jsr(transport, labels["ec_point_double_384"], timeout=600.0)
    jx, jy, jz = read_jacobian_point(transport, labels["ec384_p3"])
    return jacobian_to_affine(jx, jy, jz, "p384")


def c64_add(transport, labels, p1x, p1y, p1z, p2x, p2y):
    write_jacobian_point(transport, labels["ec384_p1"], p1x, p1y, p1z)
    write_affine_point(transport, labels["ec384_p2"], p2x, p2y)
    jsr(transport, labels["ec_point_add_384"], timeout=1200.0)
    jx, jy, jz = read_jacobian_point(transport, labels["ec384_p3"])
    return jacobian_to_affine(jx, jy, jz, "p384")


def c64_scalar_mul(transport, labels, k):
    SCALAR_BUF = 0x033C
    write_bytes(transport, SCALAR_BUF, int_to_be_bytes(k, 48))
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_BUF)
    jsr(transport, labels["ec_scalar_mul_384"], timeout=3600.0)
    jx, jy, jz = read_jacobian_point(transport, labels["ec384_p3"])
    return jacobian_to_affine(jx, jy, jz, "p384")


def c64_scalar_mul_var(transport, labels, k, bx, by):
    """Drive ec_scalar_mul_var_384 (variable-base double-and-add, P-384).

    BE scalar into scratch buffer, ec_scalar_ptr wired, base point
    staged into ec_base384_x / ec_base384_y, Jacobian result read from
    ec384_p3 and Python-side j2a handles Z=0/infinity cleanly.
    """
    SCALAR_BUF = 0x033C
    write_bytes(transport, SCALAR_BUF, int_to_be_bytes(k, 48))
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_BUF)
    write_field_elem(transport, labels["ec_base384_x"], bx)
    write_field_elem(transport, labels["ec_base384_y"], by)
    jsr(transport, labels["ec_scalar_mul_var_384"], timeout=10800.0)
    jx, jy, jz = read_jacobian_point(transport, labels["ec384_p3"])
    return jacobian_to_affine(jx, jy, jz, "p384")


# ============================================================================
# Test functions
# ============================================================================

def test_ec_mulp_384(transport, labels):
    passed = failed = 0

    write_field_elem(transport, labels["fp384_tmp1"], 1)
    write_field_elem(transport, labels["fp384_tmp2"], 1)
    set_ptr(transport, labels["fp_src1"], labels["fp384_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp384_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp384_tmp3"])
    jsr(transport, labels["ec_mulp_384"], timeout=120.0)
    result = read_field_elem(transport, labels["fp384_tmp3"])
    if result == 1:
        passed += 1
        print("  PASS: ec_mulp_384(1, 1) = 1")
    else:
        failed += 1
        print(f"  FAIL: ec_mulp_384(1, 1) = {result:#098x}")

    write_field_elem(transport, labels["fp384_tmp1"], G_X)
    write_field_elem(transport, labels["fp384_tmp2"], G_X)
    set_ptr(transport, labels["fp_src1"], labels["fp384_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp384_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp384_tmp3"])
    jsr(transport, labels["ec_mulp_384"], timeout=120.0)
    result = read_field_elem(transport, labels["fp384_tmp3"])
    expected = (G_X * G_X) % P384
    if result == expected:
        passed += 1
        print("  PASS: ec_mulp_384(Gx, Gx) matches Python reference")
    else:
        failed += 1
        print(f"  FAIL: ec_mulp_384(Gx, Gx) = {result:#098x}")
        print(f"    expected = {expected:#098x}")

    return passed, failed


def test_point_double_384(transport, labels, rng, n_random):
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p384")
    anchor = kats[0]
    cases = [(anchor["qx"], anchor["qy"], f"NIST KAT[0]")]
    for i in range(n_random):
        x, y = random_affine_point(rng)
        cases.append((x, y, f"random[{i}]"))

    for px, py, label in cases:
        print(f"  Doubling {label}...")
        t0 = time.time()
        ax, ay = c64_double(transport, labels, px, py)
        dt = time.time() - t0
        expected = affine_double((px, py), "p384")
        if (ax, ay) == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): {label}")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): {label}")
            print(f"    expected x={expected[0]:#098x}")
            print(f"    got      x={ax:#098x}")
            print(f"    expected y={expected[1]:#098x}")
            print(f"    got      y={ay:#098x}")

    return passed, failed


def test_point_add_384(transport, labels, rng, n_random):
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p384")
    anchor = kats[0]
    cases = [
        (anchor["qx"], anchor["qy"], G_X, G_Y, "NIST KAT[0] + G"),
    ]
    for i in range(n_random):
        for _ in range(5):
            p1 = random_affine_point(rng)
            p2 = random_affine_point(rng)
            if p1[0] != p2[0]:
                break
        else:
            continue
        cases.append((p1[0], p1[1], p2[0], p2[1], f"random[{i}]"))

    for p1x, p1y, p2x, p2y, label in cases:
        print(f"  Adding {label}...")
        t0 = time.time()
        ax, ay = c64_add(transport, labels, p1x, p1y, 1, p2x, p2y)
        dt = time.time() - t0
        expected = affine_add((p1x, p1y), (p2x, p2y), "p384")
        if (ax, ay) == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): {label}")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): {label}")
            print(f"    expected x={expected[0]:#098x}")
            print(f"    got      x={ax:#098x}")
            print(f"    expected y={expected[1]:#098x}")
            print(f"    got      y={ay:#098x}")

    return passed, failed


def c64_add_jj_384(transport, labels, p1x, p1y, p1z, p2x, p2y, p2z):
    """Drive ec_point_add_jj_384 (full Jacobian+Jacobian add)."""
    write_jacobian_point(transport, labels["ec384_p1"], p1x, p1y, p1z)
    write_jacobian_point(transport, labels["ec384_p2"], p2x, p2y, p2z)
    write_bytes(transport, labels["ec384_p3"], b"\x5A" * 144)
    jsr(transport, labels["ec_point_add_jj_384"], timeout=1800.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    return jacobian_to_affine(p3x, p3y, p3z, "p384")


def _random_z_lift_384(x, y, z, p):
    return (x * z * z) % p, (y * z * z * z) % p, z


def test_point_add_jj_384(transport, labels, rng, n_random):
    """ec_point_add_jj_384 - edge cases + random pairs with random Z lifts.

    Mirror of test_point_add_jj from test_points256.py; covers the same five
    edge cases plus n_random random pairs each with independent Z lifts."""
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p384")
    Px, Py = kats[0]["qx"], kats[0]["qy"]
    Qx, Qy = G_X, G_Y

    # Edge 1: P1 = infinity
    print("  Edge: P1 = infinity, P2 = random Jacobian")
    z2 = rng.randrange(2, P384 - 1)
    P2x, P2y, P2z = _random_z_lift_384(Qx, Qy, z2, P384)
    write_jacobian_point(transport, labels["ec384_p1"], 0, 0, 0)
    write_jacobian_point(transport, labels["ec384_p2"], P2x, P2y, P2z)
    write_bytes(transport, labels["ec384_p3"], b"\xA5" * 144)
    jsr(transport, labels["ec_point_add_jj_384"], timeout=600.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    if (p3x, p3y, p3z) == (P2x, P2y, P2z):
        passed += 1
        print("  PASS: infinity + P2 verbatim copy")
    else:
        failed += 1
        print(f"  FAIL: infinity + P2 mismatch")

    # Edge 2: P2 = infinity
    print("  Edge: P1 = random Jacobian, P2 = infinity")
    z1 = rng.randrange(2, P384 - 1)
    P1x, P1y, P1z = _random_z_lift_384(Px, Py, z1, P384)
    write_jacobian_point(transport, labels["ec384_p1"], P1x, P1y, P1z)
    write_jacobian_point(transport, labels["ec384_p2"], 0, 0, 0)
    write_bytes(transport, labels["ec384_p3"], b"\xA5" * 144)
    jsr(transport, labels["ec_point_add_jj_384"], timeout=600.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    if (p3x, p3y, p3z) == (P1x, P1y, P1z):
        passed += 1
        print("  PASS: P1 + infinity verbatim copy")
    else:
        failed += 1
        print(f"  FAIL: P1 + infinity mismatch")

    # Edge 3: both infinity
    print("  Edge: both infinity")
    write_jacobian_point(transport, labels["ec384_p1"], 0, 0, 0)
    write_jacobian_point(transport, labels["ec384_p2"], 0, 0, 0)
    write_bytes(transport, labels["ec384_p3"], b"\xA5" * 144)
    jsr(transport, labels["ec_point_add_jj_384"], timeout=600.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    if (p3x, p3y, p3z) == (0, 0, 0):
        passed += 1
        print("  PASS: inf + inf -> inf")
    else:
        failed += 1
        print(f"  FAIL: inf + inf gave non-zero point")

    # Edge 4: same point, different Z lifts -> 2*P
    print("  Edge: P + P (different Z lifts) -> 2*P")
    z1 = rng.randrange(2, P384 - 1)
    z2 = rng.randrange(2, P384 - 1)
    P1x, P1y, P1z = _random_z_lift_384(Px, Py, z1, P384)
    P2x, P2y, P2z = _random_z_lift_384(Px, Py, z2, P384)
    got = c64_add_jj_384(transport, labels, P1x, P1y, P1z, P2x, P2y, P2z)
    expected = affine_double((Px, Py), "p384")
    if got == expected:
        passed += 1
        print("  PASS: P + P (different Z) = 2*P")
    else:
        failed += 1
        print(f"  FAIL: P + P (different Z) mismatch; got={got} expected={expected}")

    # Edge 5: P + (-P) -> infinity
    print("  Edge: P + (-P) -> infinity")
    z1 = rng.randrange(2, P384 - 1)
    z2 = rng.randrange(2, P384 - 1)
    P1x, P1y, P1z = _random_z_lift_384(Px, Py, z1, P384)
    P2x, P2y, P2z = _random_z_lift_384(Px, (-Py) % P384, z2, P384)
    write_jacobian_point(transport, labels["ec384_p1"], P1x, P1y, P1z)
    write_jacobian_point(transport, labels["ec384_p2"], P2x, P2y, P2z)
    write_bytes(transport, labels["ec384_p3"], b"\xA5" * 144)
    jsr(transport, labels["ec_point_add_jj_384"], timeout=600.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    if (p3x, p3y, p3z) == (0, 0, 0):
        passed += 1
        print("  PASS: P + (-P) -> infinity")
    else:
        failed += 1
        print(f"  FAIL: P + (-P) -> non-zero")

    # Random pairs with random Z lifts
    for i in range(n_random):
        for _ in range(5):
            ax, ay = random_affine_point(rng)
            bx, by = random_affine_point(rng)
            if ax != bx:
                break
        else:
            continue
        z1 = rng.randrange(2, P384 - 1)
        z2 = rng.randrange(2, P384 - 1)
        P1x, P1y, P1z = _random_z_lift_384(ax, ay, z1, P384)
        P2x, P2y, P2z = _random_z_lift_384(bx, by, z2, P384)
        print(f"  Random pair[{i}] with Z lifts...")
        t0 = time.time()
        got = c64_add_jj_384(transport, labels, P1x, P1y, P1z, P2x, P2y, P2z)
        dt = time.time() - t0
        expected = affine_add((ax, ay), (bx, by), "p384")
        if got == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): random[{i}]")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): random[{i}] got={got} expected={expected}")

    return passed, failed


def test_jacobian_double_random_z_384(transport, labels, rng, n_random):
    passed = failed = 0
    for i in range(n_random):
        x, y = random_affine_point(rng)
        z = rng.randrange(2, P384 - 1)
        jx = (x * z * z) % P384
        jy = (y * z * z * z) % P384
        if jacobian_to_affine(jx, jy, z, "p384") != (x, y):
            failed += 1
            print(f"  FAIL: Python j2a self-test failed on random[{i}]")
            continue

        write_jacobian_point(transport, labels["ec384_p1"], jx, jy, z)
        t0 = time.time()
        jsr(transport, labels["ec_point_double_384"], timeout=600.0)
        dt = time.time() - t0
        p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
        ax, ay = jacobian_to_affine(p3x, p3y, p3z, "p384")
        expected = affine_double((x, y), "p384")
        if (ax, ay) == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): random Z random[{i}]")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): random Z random[{i}]")
    return passed, failed


def test_point_at_infinity_384(transport, labels):
    """Doubling infinity -> infinity, pre-filled non-zero buffer.

    Wave 5b fixed the BPL-fill bug family, so the routine must itself
    zero all 144 bytes."""
    passed = failed = 0

    write_jacobian_point(transport, labels["ec384_p1"], 42, 99, 0)
    write_bytes(transport, labels["ec384_p3"], b"\xAA" * 144)
    write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

    print("  Calling ec_point_double_384 (infinity)...")
    jsr(transport, labels["ec_point_double_384"], timeout=60.0)

    p3_data = read_bytes(transport, labels["ec384_p3"], 144)
    if all(b == 0 for b in p3_data):
        passed += 1
        print("  PASS: doubling infinity leaves ec384_p3 all zeros")
    else:
        failed += 1
        nonzero = [(i, b) for i, b in enumerate(p3_data) if b != 0]
        print(f"  FAIL: {len(nonzero)} non-zero bytes; first: {nonzero[:8]}")

    return passed, failed


def test_add_infinity_plus_random_384(transport, labels, rng, n_random):
    passed = failed = 0
    for i in range(n_random):
        rx, ry = random_affine_point(rng)
        write_jacobian_point(transport, labels["ec384_p1"], 0, 0, 0)
        write_affine_point(transport, labels["ec384_p2"], rx, ry)
        write_bytes(transport, labels["ec384_p3"], b"\x5A" * 144)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
        jsr(transport, labels["ec_point_add_384"], timeout=120.0)
        p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
        if p3x == rx and p3y == ry and p3z == 1:
            passed += 1
            print(f"  PASS: infinity + random[{i}] = R (Z=1)")
        else:
            failed += 1
            print(f"  FAIL: infinity + random[{i}]")
            print(f"    expected X = {rx:#098x}")
            print(f"    got      X = {p3x:#098x}")
    return passed, failed


def test_scalar_mul_var_384(transport, labels, rng, n_random):
    """ec_scalar_mul_var_384 (variable-base double-and-add) vs oracle.

    Random (n_P, k) pairs: P = n_P*G via oracle, expected = (k*n_P mod n)*G.
    Edge cases: k=1, k=2, k=n-1, k=0, k=n.
    """
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p384")
    anchor = kats[0]
    Px, Py = anchor["qx"], anchor["qy"]

    edge_cases = [
        (1,           "k=1"),
        (2,           "k=2"),
        (N384 - 1,    "k=n-1"),
        (0,           "k=0 (infinity)"),
        (N384,        "k=n (infinity)"),
    ]

    def run_case(k, Px_, Py_, label):
        nonlocal passed, failed
        print(f"  scalar_mul_var_384 {label}...")
        t0 = time.time()
        got = c64_scalar_mul_var(transport, labels, k, Px_, Py_)
        dt = time.time() - t0
        k_mod = k % N384
        if k_mod == 0:
            expected = INFINITY
        else:
            R = INFINITY
            for i in range(k_mod.bit_length() - 1, -1, -1):
                R = affine_add(R, R, "p384")
                if (k_mod >> i) & 1:
                    R = affine_add(R, (Px_, Py_), "p384")
            expected = R
        if got == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): {label}")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): {label} k={k:#x}")
            print(f"    Px={Px_:#098x}")
            print(f"    Py={Py_:#098x}")
            print(f"    expected={expected}")
            print(f"    got     ={got}")

    for k, label in edge_cases:
        run_case(k, Px, Py, label + " on NIST KAT[0]")

    got1 = c64_scalar_mul_var(transport, labels, 1, Px, Py)
    if got1 == (Px, Py):
        passed += 1
        print("  PASS: k=1 returns (Px, Py) verbatim")
    else:
        failed += 1
        print(f"  FAIL: k=1 identity: got {got1}")

    neg_y = (-Py) % P384
    got_neg = c64_scalar_mul_var(transport, labels, N384 - 1, Px, Py)
    if got_neg == (Px, neg_y):
        passed += 1
        print("  PASS: k=n-1 returns (Px, -Py mod p)")
    else:
        failed += 1
        print(f"  FAIL: k=n-1 identity: got {got_neg}")

    for i in range(n_random):
        nP = rng.randrange(2, N384 - 1)
        Px_, Py_ = scalar_mul_oracle(nP, "p384")
        k = rng.randrange(1, N384 - 1)
        kP_scalar = (k * nP) % N384
        if kP_scalar == 0:
            expected = INFINITY
        else:
            expected = scalar_mul_oracle(kP_scalar, "p384")
        print(f"  scalar_mul_var_384 random[{i}] k={k:#x} nP={nP:#x}...")
        t0 = time.time()
        got = c64_scalar_mul_var(transport, labels, k, Px_, Py_)
        dt = time.time() - t0
        if got == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): random[{i}]")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): random[{i}] k={k:#x} nP={nP:#x}")
            print(f"    Px={Px_:#098x}")
            print(f"    Py={Py_:#098x}")
            print(f"    expected={expected}")
            print(f"    got     ={got}")

    return passed, failed


def test_scalar_mul_random_384(transport, labels, rng, n_random, n_kat_fast):
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p384")
    kat_subset = kats if n_kat_fast is None else kats[:n_kat_fast]

    scalars = [(k["d"], f"NIST KAT[{i}]") for i, k in enumerate(kat_subset)]
    for i in range(n_random):
        scalars.append((rng.randrange(1, N384 - 1), f"random[{i}]"))
    scalars.append((1, "k=1"))

    for k, label in scalars:
        print(f"  scalar_mul_384 {label}...")
        t0 = time.time()
        ax, ay = c64_scalar_mul(transport, labels, k)
        dt = time.time() - t0
        expected = scalar_mul_oracle(k, "p384")
        if (ax, ay) == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): {label}")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): {label} k={k:#x}")
            print(f"    expected x={expected[0]:#098x}")
            print(f"    got      x={ax:#098x}")
            print(f"    expected y={expected[1]:#098x}")
            print(f"    got      y={ay:#098x}")
    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, rng, run_full):
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    transport_broken = False

    if run_full:
        n_dbl = 10
        n_add = 10
        n_j2a = 10
        n_inf = 5
        n_sca = 10
        n_var = 10
        n_kat = None
    else:
        n_dbl = 3
        n_add = 3
        n_j2a = 3
        n_inf = 2
        n_sca = 3
        n_var = 3
        n_kat = 3

    kat_count = len(load_nist_scalar_mul_kats("p384")) if n_kat is None else n_kat

    test_groups = [
        ("ec_mulp_384 smoke test",
         lambda: test_ec_mulp_384(transport, labels)),
        (f"Point doubling ({n_dbl} random + 1 NIST)",
         lambda: test_point_double_384(transport, labels, rng, n_dbl)),
        (f"Point addition ({n_add} random + 1 NIST)",
         lambda: test_point_add_384(transport, labels, rng, n_add)),
        (f"Point add J+J ({n_add} random pairs + 5 edge cases)",
         lambda: test_point_add_jj_384(transport, labels, rng, n_add)),
        (f"Jacobian doubling with random Z ({n_j2a})",
         lambda: test_jacobian_double_random_z_384(transport, labels, rng, n_j2a)),
        ("Point at infinity (double)",
         lambda: test_point_at_infinity_384(transport, labels)),
        (f"Infinity + R = R ({n_inf} random)",
         lambda: test_add_infinity_plus_random_384(transport, labels, rng, n_inf)),
        (f"Scalar mul ({n_sca} random + {kat_count} NIST KATs + k=1)",
         lambda: test_scalar_mul_random_384(transport, labels, rng, n_sca, n_kat)),
        (f"Variable-base scalar mul ({n_var} random + 5 edge cases)",
         lambda: test_scalar_mul_var_384(transport, labels, rng, n_var)),
    ]

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
    _warn_if_vice_running()
    os.chdir(PROJECT_ROOT)

    seed = None
    run_full = False
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            VERBOSE = True
            i += 1
        elif args[i] == "--full":
            run_full = True
            i += 1
        else:
            i += 1

    if seed is None:
        seed = secrets.randbits(64)
    rng = random.Random(seed)
    mode = "full" if run_full else "fast"
    print(f"Mode: {mode}")
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    print("Validating NIST KATs against cryptography oracle...")
    kats = load_nist_scalar_mul_kats("p384")
    for kat in kats:
        x, y = scalar_mul_oracle(kat["d"], "p384")
        if (x, y) != (kat["qx"], kat["qy"]):
            print(f"FATAL: NIST KAT mismatch d={kat['d']:#x}")
            sys.exit(2)
    print(f"  p384: {len(kats)} KATs verified")
    self_check(rng, "p384", 3)
    print("  affine_add self-check OK")

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
        "ec384_p1", "ec384_p2", "ec384_p3",
        "ec_gx384", "ec_gy384", "ec_p384",
        "ec_point_double_384", "ec_point_add_384", "ec_scalar_mul_384",
        "ec_scalar_mul_var_384", "ec_base384_x", "ec_base384_y",
        "ec_set_modp_384", "ec_mulp_384",
        "fp_copy_384", "fp_zero_384",
        "sqtab_init", "reu_mul_init",
        "ec_scalar_ptr",
        "fp_src1", "fp_src2", "fp_dst", "fp_misc",
        "fp384_tmp1", "fp384_tmp2", "fp384_tmp3",
    ]
    missing = [name for name in required if labels.address(name) is None]
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

        passed, failed, skipped = run_tests(transport, labels, rng, run_full)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    print(f"Mode: {mode}  Seed: {seed}")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
