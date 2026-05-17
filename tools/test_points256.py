#!/usr/bin/env python3
"""test_points256.py -- Direct-memory P-256 point operation tests.

Tests ec_point_double, ec_point_add, ec_scalar_mul, ec_jacobian_to_affine.
All field elements are LITTLE-ENDIAN (byte 0 = LSB).
Point layout: X = offset 0..31, Y = offset 32..63, Z = offset 64..95.

Gameability defense (see tools/vectors/README.md):

    * The `cryptography` Python package is the external oracle for
      scalar multiplication. Every expected output is produced by an
      independent process, so a 4-entry lookup-table implementation
      cannot pass.
    * NIST CAVP KATs (loaded from tools/vectors/nist_p256_ecdh.rsp) are
      a fixed anchor. They run on every boot and are cross-checked
      against `cryptography` before any C64 test begins.
    * Random scalars are drawn from `secrets.randbits()` (OS entropy)
      unless --seed is passed for reproducing a specific failure.

Usage:
    python3 tools/test_points256.py [--seed S] [--verbose] [--full]

    --full   Run an expanded random-scalar set (default: fast mode).
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

# Make `tools.vectors` importable regardless of cwd.
sys.path.insert(0, PROJECT_ROOT)

from tools.vectors import (  # noqa: E402
    P256_GX, P256_GY, P256_N, P256_P,
    affine_add, affine_double, affine_neg,
    jacobian_to_affine,
    load_nist_scalar_mul_kats,
    scalar_mul_oracle,
    self_check,
)
from tools.vectors.loader import INFINITY, is_infinity  # noqa: E402

VERBOSE = False

# Convenience aliases
G_X = P256_GX
G_Y = P256_GY
P256 = P256_P
N256 = P256_N

# RFC 6979 A.2.5 sample-message private key (kept as one extra anchor).
TEST_PRIVKEY = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721


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

def int_to_le_bytes(val, length=32):
    return val.to_bytes(length, "little")

def le_bytes_to_int(data):
    return int.from_bytes(data, "little")

def int_to_be_bytes(val, length=32):
    return val.to_bytes(length, "big")

def set_ptr(transport, zp_addr, target_addr):
    write_bytes(transport, zp_addr,
                bytes([target_addr & 0xFF, (target_addr >> 8) & 0xFF]))


# ============================================================================
# C64 helper functions
# ============================================================================

def write_field_elem(transport, addr, value, length=32):
    write_bytes(transport, addr, int_to_le_bytes(value, length))

def read_field_elem(transport, addr, length=32):
    return le_bytes_to_int(read_bytes(transport, addr, length))

def write_jacobian_point(transport, base_addr, x, y, z):
    write_field_elem(transport, base_addr, x)
    write_field_elem(transport, base_addr + 32, y)
    write_field_elem(transport, base_addr + 64, z)

def write_affine_point(transport, base_addr, x, y):
    write_field_elem(transport, base_addr, x)
    write_field_elem(transport, base_addr + 32, y)

def read_jacobian_point(transport, base_addr):
    x = read_field_elem(transport, base_addr)
    y = read_field_elem(transport, base_addr + 32)
    z = read_field_elem(transport, base_addr + 64)
    return x, y, z


# ============================================================================
# Helpers: obtain a random affine P-256 point via the oracle
# ============================================================================

def random_affine_point(rng):
    """Return a random affine (x, y) on P-256 by computing k*G via the oracle."""
    k = rng.randrange(1, N256 - 1)
    return scalar_mul_oracle(k, "p256")


# ============================================================================
# C64 invocation wrappers
# ============================================================================

def c64_double(transport, labels, px, py):
    write_jacobian_point(transport, labels["ec_p1"], px, py, 1)
    jsr(transport, labels["ec_point_double"], timeout=600.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    return jacobian_to_affine(p3x, p3y, p3z, "p256")


def c64_add(transport, labels, p1x, p1y, p1z, p2x, p2y):
    write_jacobian_point(transport, labels["ec_p1"], p1x, p1y, p1z)
    write_affine_point(transport, labels["ec_p2"], p2x, p2y)
    jsr(transport, labels["ec_point_add"], timeout=1200.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    return jacobian_to_affine(p3x, p3y, p3z, "p256")


def c64_scalar_mul(transport, labels, k):
    SCALAR_BUF = 0x033C
    write_bytes(transport, SCALAR_BUF, int_to_be_bytes(k, 32))
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_BUF)
    jsr(transport, labels["ec_scalar_mul"], timeout=3600.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    return jacobian_to_affine(p3x, p3y, p3z, "p256")


def c64_scalar_mul_var(transport, labels, k, bx, by):
    """Drive ec_scalar_mul_var (variable-base double-and-add).

    Pokes the 32-byte BE scalar into a scratch buffer, wires
    ec_scalar_ptr to it, stages the LE base point into ec_base_x /
    ec_base_y, and jsr's ec_scalar_mul_var. The Jacobian output at
    ec_p3 is read back and converted to affine via the Python oracle
    (handles the Z=0/infinity case naturally, same pattern as
    c64_scalar_mul).
    """
    SCALAR_BUF = 0x033C
    write_bytes(transport, SCALAR_BUF, int_to_be_bytes(k, 32))
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_BUF)
    write_field_elem(transport, labels["ec_base_x"], bx)
    write_field_elem(transport, labels["ec_base_y"], by)
    jsr(transport, labels["ec_scalar_mul_var"], timeout=7200.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    return jacobian_to_affine(p3x, p3y, p3z, "p256")


# ============================================================================
# Test functions
# ============================================================================

def test_ec_mulp(transport, labels):
    """Smoke test: field multiply plumbing works."""
    passed = failed = 0

    write_field_elem(transport, labels["fp_tmp1"], 1)
    write_field_elem(transport, labels["fp_tmp2"], 1)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])
    jsr(transport, labels["ec_mulp"], timeout=300.0)
    result = read_field_elem(transport, labels["fp_tmp3"])
    if result == 1:
        passed += 1
        print("  PASS: ec_mulp(1, 1) = 1")
    else:
        failed += 1
        print(f"  FAIL: ec_mulp(1, 1) = {result:#066x}")

    write_field_elem(transport, labels["fp_tmp1"], G_X)
    write_field_elem(transport, labels["fp_tmp2"], G_X)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])
    jsr(transport, labels["ec_mulp"], timeout=300.0)
    result = read_field_elem(transport, labels["fp_tmp3"])
    expected = (G_X * G_X) % P256
    if result == expected:
        passed += 1
        print("  PASS: ec_mulp(Gx, Gx) matches Python reference")
    else:
        failed += 1
        print(f"  FAIL: ec_mulp(Gx, Gx)")
        print(f"    expected = {expected:#066x}")
        print(f"    got      = {result:#066x}")

    return passed, failed


def test_point_double(transport, labels, rng, n_random):
    """Double n_random random affine points + 1 NIST-derived KAT."""
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p256")
    anchor = kats[0]
    cases = [(anchor["qx"], anchor["qy"], f"NIST KAT[0] d={anchor['d']:#x}")]
    for i in range(n_random):
        x, y = random_affine_point(rng)
        cases.append((x, y, f"random[{i}]"))

    for px, py, label in cases:
        print(f"  Doubling {label}...")
        t0 = time.time()
        ax, ay = c64_double(transport, labels, px, py)
        dt = time.time() - t0
        expected = affine_double((px, py), "p256")
        if (ax, ay) == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): {label}")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): {label}")
            print(f"    expected x={expected[0]:#066x}")
            print(f"    got      x={ax:#066x}")
            print(f"    expected y={expected[1]:#066x}")
            print(f"    got      y={ay:#066x}")

    return passed, failed


def test_point_add(transport, labels, rng, n_random):
    """Add n_random random point pairs + 1 NIST-derived KAT."""
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p256")
    anchor = kats[0]
    cases = [
        (anchor["qx"], anchor["qy"], G_X, G_Y, "NIST KAT[0] + G"),
    ]
    for i in range(n_random):
        # Draw two distinct random points. If P1.x == P2.x (extreme
        # coincidence) the mixed-add formula would hit the doubling /
        # inverse-point branch, so redraw.
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
        expected = affine_add((p1x, p1y), (p2x, p2y), "p256")
        if (ax, ay) == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): {label}")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): {label}")
            print(f"    expected x={expected[0]:#066x}")
            print(f"    got      x={ax:#066x}")
            print(f"    expected y={expected[1]:#066x}")
            print(f"    got      y={ay:#066x}")

    return passed, failed


def c64_add_jj(transport, labels, p1x, p1y, p1z, p2x, p2y, p2z):
    """Drive ec_point_add_jj (full Jacobian+Jacobian add)."""
    write_jacobian_point(transport, labels["ec_p1"], p1x, p1y, p1z)
    write_jacobian_point(transport, labels["ec_p2"], p2x, p2y, p2z)
    write_bytes(transport, labels["ec_p3"], b"\x5A" * 96)
    jsr(transport, labels["ec_point_add_jj"], timeout=1200.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    return jacobian_to_affine(p3x, p3y, p3z, "p256")


def _random_z_lift(x, y, z, p):
    """Project an affine (x, y) onto Jacobian (X, Y, Z) with X = x*Z^2, Y = y*Z^3."""
    return (x * z * z) % p, (y * z * z * z) % p, z


def test_point_add_jj(transport, labels, rng, n_random):
    """ec_point_add_jj (full J+J add) - edge cases + random pairs with random Z lifts.

    Edge cases:
      1. P1 = infinity (Z1=0)     -> ec_p3 := P2
      2. P2 = infinity (Z2=0)     -> ec_p3 := P1
      3. Both infinity            -> ec_p3 := infinity
      4. P1 == P2 (same point with different Z lifts) -> 2*P1
      5. P1 == -P2 (same x, neg y, with different Z lifts) -> infinity

    Then n_random pairs of distinct random points each lifted to random Z's.
    """
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p256")
    Px, Py = kats[0]["qx"], kats[0]["qy"]
    Qx, Qy = G_X, G_Y

    # Edge 1: P1 infinity (Z1 = 0). Expect ec_p3 == P2 verbatim (lifted Z2).
    print("  Edge: P1 = infinity, P2 = random Jacobian")
    z2 = rng.randrange(2, P256 - 1)
    P2x, P2y, P2z = _random_z_lift(Qx, Qy, z2, P256)
    write_jacobian_point(transport, labels["ec_p1"], 0, 0, 0)
    write_jacobian_point(transport, labels["ec_p2"], P2x, P2y, P2z)
    write_bytes(transport, labels["ec_p3"], b"\xA5" * 96)
    jsr(transport, labels["ec_point_add_jj"], timeout=300.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    if (p3x, p3y, p3z) == (P2x, P2y, P2z):
        passed += 1
        print("  PASS: infinity + P2 yielded P2 verbatim")
    else:
        failed += 1
        print(f"  FAIL: infinity + P2 mismatch; X={p3x:#x} Y={p3y:#x} Z={p3z:#x}")

    # Edge 2: P2 infinity (Z2 = 0). Expect ec_p3 == P1 verbatim.
    print("  Edge: P1 = random Jacobian, P2 = infinity")
    z1 = rng.randrange(2, P256 - 1)
    P1x, P1y, P1z = _random_z_lift(Px, Py, z1, P256)
    write_jacobian_point(transport, labels["ec_p1"], P1x, P1y, P1z)
    write_jacobian_point(transport, labels["ec_p2"], 0, 0, 0)
    write_bytes(transport, labels["ec_p3"], b"\xA5" * 96)
    jsr(transport, labels["ec_point_add_jj"], timeout=300.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    if (p3x, p3y, p3z) == (P1x, P1y, P1z):
        passed += 1
        print("  PASS: P1 + infinity yielded P1 verbatim")
    else:
        failed += 1
        print(f"  FAIL: P1 + infinity mismatch; X={p3x:#x} Y={p3y:#x} Z={p3z:#x}")

    # Edge 3: both infinity
    print("  Edge: both infinity")
    write_jacobian_point(transport, labels["ec_p1"], 0, 0, 0)
    write_jacobian_point(transport, labels["ec_p2"], 0, 0, 0)
    write_bytes(transport, labels["ec_p3"], b"\xA5" * 96)
    jsr(transport, labels["ec_point_add_jj"], timeout=300.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    if (p3x, p3y, p3z) == (0, 0, 0):
        passed += 1
        print("  PASS: inf + inf -> inf")
    else:
        failed += 1
        print(f"  FAIL: inf + inf gave non-zero; X={p3x:#x} Y={p3y:#x} Z={p3z:#x}")

    # Edge 4: same projective point, different Z lifts -> 2*P
    print("  Edge: P + P (different Z lifts) -> 2*P")
    z1 = rng.randrange(2, P256 - 1)
    z2 = rng.randrange(2, P256 - 1)
    P1x, P1y, P1z = _random_z_lift(Px, Py, z1, P256)
    P2x, P2y, P2z = _random_z_lift(Px, Py, z2, P256)
    got = c64_add_jj(transport, labels, P1x, P1y, P1z, P2x, P2y, P2z)
    expected = affine_double((Px, Py), "p256")
    if got == expected:
        passed += 1
        print("  PASS: P + P (different Z) = 2*P")
    else:
        failed += 1
        print(f"  FAIL: P + P (different Z) mismatch; got={got} expected={expected}")

    # Edge 5: P + (-P) -> infinity
    print("  Edge: P + (-P) -> infinity")
    z1 = rng.randrange(2, P256 - 1)
    z2 = rng.randrange(2, P256 - 1)
    P1x, P1y, P1z = _random_z_lift(Px, Py, z1, P256)
    P2x, P2y, P2z = _random_z_lift(Px, (-Py) % P256, z2, P256)
    write_jacobian_point(transport, labels["ec_p1"], P1x, P1y, P1z)
    write_jacobian_point(transport, labels["ec_p2"], P2x, P2y, P2z)
    write_bytes(transport, labels["ec_p3"], b"\xA5" * 96)
    jsr(transport, labels["ec_point_add_jj"], timeout=300.0)
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    if (p3x, p3y, p3z) == (0, 0, 0):
        passed += 1
        print("  PASS: P + (-P) -> infinity (all-zero Jacobian)")
    else:
        failed += 1
        print(f"  FAIL: P + (-P) gave non-zero; X={p3x:#x} Y={p3y:#x} Z={p3z:#x}")

    # Random pairs with random Z lifts
    for i in range(n_random):
        for _ in range(5):
            ax, ay = random_affine_point(rng)
            bx, by = random_affine_point(rng)
            if ax != bx:
                break
        else:
            continue
        z1 = rng.randrange(2, P256 - 1)
        z2 = rng.randrange(2, P256 - 1)
        P1x, P1y, P1z = _random_z_lift(ax, ay, z1, P256)
        P2x, P2y, P2z = _random_z_lift(bx, by, z2, P256)
        print(f"  Random pair[{i}] with Z lifts...")
        t0 = time.time()
        got = c64_add_jj(transport, labels, P1x, P1y, P1z, P2x, P2y, P2z)
        dt = time.time() - t0
        expected = affine_add((ax, ay), (bx, by), "p256")
        if got == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): random[{i}]")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): random[{i}]")
            print(f"    expected={expected}")
            print(f"    got     ={got}")

    return passed, failed


def test_jacobian_to_affine(transport, labels, rng, n_random):
    """Feed ec_point_double random Jacobian points with Z != 1.

    For each trial we pick a random affine (x, y) via the oracle, lift
    to Jacobian as (x*Z^2, y*Z^3, Z) for random Z, and double on the
    C64. The expected affine output is 2*(x, y) from the oracle.

    This exercises the assembly's Jacobian->Jacobian math with a
    non-trivial Z value (the default Z=1 path is much less interesting,
    and is already covered by test_point_double).
    """
    passed = failed = 0

    for i in range(n_random):
        x, y = random_affine_point(rng)
        z = rng.randrange(2, P256 - 1)
        jx = (x * z * z) % P256
        jy = (y * z * z * z) % P256
        # Self-check: our Python j2a must round-trip to (x, y).
        if jacobian_to_affine(jx, jy, z, "p256") != (x, y):
            failed += 1
            print(f"  FAIL: Python j2a self-test failed on random[{i}]")
            continue

        write_jacobian_point(transport, labels["ec_p1"], jx, jy, z)
        t0 = time.time()
        jsr(transport, labels["ec_point_double"], timeout=600.0)
        dt = time.time() - t0
        p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
        ax, ay = jacobian_to_affine(p3x, p3y, p3z, "p256")
        expected = affine_double((x, y), "p256")
        if (ax, ay) == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): random Z random[{i}]")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): random Z random[{i}]")
            print(f"    z       = {z:#066x}")
            print(f"    expected x={expected[0]:#066x}")
            print(f"    got      x={ax:#066x}")
            print(f"    expected y={expected[1]:#066x}")
            print(f"    got      y={ay:#066x}")

    return passed, failed


def test_point_at_infinity(transport, labels):
    """Doubling infinity -> infinity, on a pre-filled non-zero buffer.

    Pre-fills ec_p3 with $A5 so a no-op cannot pass (the previous test
    in this suite might have left ec_p3 all-zero; $A5 ensures the
    check is positive)."""
    passed = failed = 0

    write_jacobian_point(transport, labels["ec_p1"], 42, 99, 0)
    write_bytes(transport, labels["ec_p3"], b"\xA5" * 96)
    write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

    print("  Calling ec_point_double (infinity)...")
    jsr(transport, labels["ec_point_double"], timeout=60.0)

    p3_data = read_bytes(transport, labels["ec_p3"], 96)
    if all(b == 0 for b in p3_data):
        passed += 1
        print("  PASS: doubling infinity overwrote ec_p3 with zeros")
    else:
        failed += 1
        print("  FAIL: doubling infinity did not zero ec_p3")
        nonzero = [(i, b) for i, b in enumerate(p3_data) if b != 0]
        print(f"    nonzero bytes: {nonzero[:8]}...")

    return passed, failed


def test_add_infinity_plus_random(transport, labels, rng, n_random):
    """infinity + R = R for several random R."""
    passed = failed = 0
    for i in range(n_random):
        rx, ry = random_affine_point(rng)
        write_jacobian_point(transport, labels["ec_p1"], 0, 0, 0)
        write_affine_point(transport, labels["ec_p2"], rx, ry)
        # Pre-scribble ec_p3 so a no-op cannot pass.
        write_bytes(transport, labels["ec_p3"], b"\x5A" * 96)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
        jsr(transport, labels["ec_point_add"], timeout=120.0)
        p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
        if p3x == rx and p3y == ry and p3z == 1:
            passed += 1
            print(f"  PASS: infinity + random[{i}] = R (Z=1)")
        else:
            failed += 1
            print(f"  FAIL: infinity + random[{i}] did not give R")
            print(f"    expected X = {rx:#066x}")
            print(f"    got      X = {p3x:#066x}")
            print(f"    expected Y = {ry:#066x}")
            print(f"    got      Y = {p3y:#066x}")
            print(f"    expected Z = 1")
            print(f"    got      Z = {p3z:#066x}")
    return passed, failed


def test_scalar_mul_var(transport, labels, rng, n_random):
    """ec_scalar_mul_var (variable-base double-and-add) vs oracle.

    For each random sample we pick a random public point P = n_P * G
    (so P is a valid curve point but distinct from G) and a random
    scalar k, then assert harness(k, P) == oracle(k * P).

    Edge cases: k=1 -> P, k=2 -> 2P, k=n-1 -> -P, k=0 -> infinity,
    k=n -> infinity. The infinity cases exercise the routine's
    "R remained ∞ across all bits" zero-fill branch at @v_loop_done.
    """
    passed = failed = 0

    # --- Structured edge cases on a single pinned P (KAT[0]) so a
    # failure is reproducible without chasing a random seed. ---
    kats = load_nist_scalar_mul_kats("p256")
    anchor = kats[0]
    Px, Py = anchor["qx"], anchor["qy"]

    def point_mul_oracle(k_):
        """k*P in the affine group, reducing k mod n first."""
        k_mod = k_ % N256
        if k_mod == 0:
            return INFINITY
        # cryptography only exposes k*G, so reach the affine oracle via
        # scalar_mul with the base rebinding trick -- not available, so
        # fall back to repeated affine_add against the hand-rolled
        # group law (self-check already validated it against
        # cryptography at startup).
        # Double-and-add from MSB.
        R = INFINITY
        bits = k_mod.bit_length()
        for i in range(bits - 1, -1, -1):
            R = affine_add(R, R, "p256")
            if (k_mod >> i) & 1:
                R = affine_add(R, (Px, Py), "p256")
        return R

    edge_cases = [
        (1,           "k=1"),
        (2,           "k=2"),
        (N256 - 1,    "k=n-1"),
        (0,           "k=0 (infinity)"),
        (N256,        "k=n (infinity)"),
    ]

    def run_case(k, Px_, Py_, label):
        nonlocal passed, failed
        print(f"  scalar_mul_var {label}...")
        t0 = time.time()
        got = c64_scalar_mul_var(transport, labels, k, Px_, Py_)
        dt = time.time() - t0
        # Compute expected via affine double-and-add on top of
        # (Px, Py). Correctness of affine_add itself is ensured by
        # the self_check() run against `cryptography` at startup.
        k_mod = k % N256
        if k_mod == 0:
            expected = INFINITY
        else:
            R = INFINITY
            for i in range(k_mod.bit_length() - 1, -1, -1):
                R = affine_add(R, R, "p256")
                if (k_mod >> i) & 1:
                    R = affine_add(R, (Px_, Py_), "p256")
            expected = R
        if got == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): {label}")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): {label} k={k:#x}")
            print(f"    Px={Px_:#066x}")
            print(f"    Py={Py_:#066x}")
            print(f"    expected={expected}")
            print(f"    got     ={got}")

    for k, label in edge_cases:
        run_case(k, Px, Py, label + f" on NIST KAT[0]")

    # --- k=1 / k=n-1 sanity cross-checks (affine identities) ---
    # k=1 -> expect (Px, Py); already covered by edge_cases but we
    # pattern-match the tuple shape to catch any coercion drift.
    got1 = c64_scalar_mul_var(transport, labels, 1, Px, Py)
    if got1 == (Px, Py):
        passed += 1
        print("  PASS: k=1 returns (Px, Py) verbatim")
    else:
        failed += 1
        print(f"  FAIL: k=1 identity: got {got1}, want ({Px:#x}, {Py:#x})")

    neg_y = (-Py) % P256
    got_neg = c64_scalar_mul_var(transport, labels, N256 - 1, Px, Py)
    if got_neg == (Px, neg_y):
        passed += 1
        print("  PASS: k=n-1 returns (Px, -Py mod p)")
    else:
        failed += 1
        print(f"  FAIL: k=n-1 identity: got {got_neg}")

    # --- Random (n_P, k) pairs on a fresh P each time ---
    for i in range(n_random):
        # Random n_P gives a random valid public P distinct from G
        # (with overwhelming probability).
        nP = rng.randrange(2, N256 - 1)
        Px_, Py_ = scalar_mul_oracle(nP, "p256")
        k = rng.randrange(1, N256 - 1)
        # Oracle: k * P = (k * nP mod n) * G via the library.
        kP_scalar = (k * nP) % N256
        if kP_scalar == 0:
            expected = INFINITY
        else:
            expected = scalar_mul_oracle(kP_scalar, "p256")
        print(f"  scalar_mul_var random[{i}] k={k:#x} nP={nP:#x}...")
        t0 = time.time()
        got = c64_scalar_mul_var(transport, labels, k, Px_, Py_)
        dt = time.time() - t0
        if got == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): random[{i}]")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): random[{i}] k={k:#x} nP={nP:#x}")
            print(f"    Px={Px_:#066x}")
            print(f"    Py={Py_:#066x}")
            print(f"    expected={expected}")
            print(f"    got     ={got}")

    return passed, failed


def test_scalar_mul_random(transport, labels, rng, n_random,
                           n_kat_fast):
    """n_random random scalars + NIST KATs + RFC 6979 sample."""
    passed = failed = 0

    kats = load_nist_scalar_mul_kats("p256")
    # In fast mode we subsample KATs to keep runtime bounded; in full
    # mode we run them all. The call site decides how many.
    kat_subset = kats if n_kat_fast is None else kats[:n_kat_fast]

    scalars = [(k["d"], f"NIST KAT[{i}]") for i, k in enumerate(kat_subset)]
    for i in range(n_random):
        scalars.append((rng.randrange(1, N256 - 1), f"random[{i}]"))
    scalars.append((TEST_PRIVKEY, "RFC 6979 sample"))

    for k, label in scalars:
        print(f"  scalar_mul {label}...")
        t0 = time.time()
        ax, ay = c64_scalar_mul(transport, labels, k)
        dt = time.time() - t0
        expected = scalar_mul_oracle(k, "p256")
        if (ax, ay) == expected:
            passed += 1
            print(f"  PASS ({dt:.1f}s): {label}")
        else:
            failed += 1
            print(f"  FAIL ({dt:.1f}s): {label} k={k:#x}")
            print(f"    expected x={expected[0]:#066x}")
            print(f"    got      x={ax:#066x}")
            print(f"    expected y={expected[1]:#066x}")
            print(f"    got      y={ay:#066x}")
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
        n_kat = None   # run all 25 NIST KATs
    else:
        n_dbl = 3
        n_add = 3
        n_j2a = 3
        n_inf = 2
        n_sca = 3
        n_var = 3
        n_kat = 3

    kat_count = len(load_nist_scalar_mul_kats("p256")) if n_kat is None else n_kat

    test_groups = [
        ("ec_mulp smoke test",
         lambda: test_ec_mulp(transport, labels)),
        (f"Point doubling ({n_dbl} random + 1 NIST)",
         lambda: test_point_double(transport, labels, rng, n_dbl)),
        (f"Point addition ({n_add} random + 1 NIST)",
         lambda: test_point_add(transport, labels, rng, n_add)),
        (f"Point add J+J ({n_add} random pairs + 5 edge cases)",
         lambda: test_point_add_jj(transport, labels, rng, n_add)),
        (f"Jacobian doubling with random Z ({n_j2a})",
         lambda: test_jacobian_to_affine(transport, labels, rng, n_j2a)),
        ("Point at infinity (double)",
         lambda: test_point_at_infinity(transport, labels)),
        (f"Infinity + R = R ({n_inf} random)",
         lambda: test_add_infinity_plus_random(transport, labels, rng, n_inf)),
        (f"Scalar mul ({n_sca} random + {kat_count} NIST KATs + RFC 6979)",
         lambda: test_scalar_mul_random(transport, labels, rng, n_sca, n_kat)),
        (f"Variable-base scalar mul ({n_var} random + 5 edge cases)",
         lambda: test_scalar_mul_var(transport, labels, rng, n_var)),
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

    # Oracle sanity: every NIST KAT must match `cryptography` before
    # we spend any C64 time. A failure here means the test environment
    # itself is broken (NIST file edited, library mismatch, ...).
    print("Validating NIST KATs against cryptography oracle...")
    kats = load_nist_scalar_mul_kats("p256")
    for kat in kats:
        x, y = scalar_mul_oracle(kat["d"], "p256")
        if (x, y) != (kat["qx"], kat["qy"]):
            print(f"FATAL: NIST KAT mismatch d={kat['d']:#x}")
            sys.exit(2)
    print(f"  p256: {len(kats)} KATs verified")
    self_check(rng, "p256", 3)
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
        "ec_p1", "ec_p2", "ec_p3",
        "ec_t1", "ec_t2", "ec_t3",
        "ec_gx256", "ec_gy256",
        "ec_point_double", "ec_point_add", "ec_scalar_mul",
        "ec_scalar_mul_var", "ec_base_x", "ec_base_y",
        "ec_set_modp", "ec_mulp",
        "ec_scalar_ptr",
        "sqtab_init", "reu_mul_init",
        "fp_src1", "fp_src2", "fp_dst", "fp_misc",
        "fp_tmp1", "fp_tmp2", "fp_tmp3",
        "ec_p256", "fp_mod_mul",
    ]
    missing = [name for name in required if labels.address(name) is None]
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config) as mgr:
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

        p256_addr = labels["ec_p256"]
        set_ptr(transport, labels["fp_misc"], p256_addr)
        print(f"Set fp_misc -> ec_p256 (${p256_addr:04X})")

        passed, failed, skipped = run_tests(transport, labels, rng, run_full)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    if skipped > 0:
        print(f"  ({skipped} test group(s) skipped)")
    print(f"Mode: {mode}  Seed: {seed}")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
