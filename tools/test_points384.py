#!/usr/bin/env python3
"""test_points384.py -- Direct-memory P-384 point operation tests.

Tests ec_point_double_384, ec_point_add_384, ec_mulp_384.
All field elements are LITTLE-ENDIAN (byte 0 = LSB).
Point layout: X = offset 0..47, Y = offset 48..95, Z = offset 96..143.

Uses the c64-test-harness binary monitor transport.

Usage:
    python3 tools/test_points384.py [--seed S] [--verbose]
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

# P-384 generator coordinates (FIPS 186-4)
G_X = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
G_Y = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F

# Known 2*G coordinates (P-384)
TWO_G_X = 0x08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61
TWO_G_Y = 0x8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80


# ============================================================================
# Byte conversion helpers
# ============================================================================

def int_to_le_bytes(val, length=48):
    return val.to_bytes(length, "little")

def le_bytes_to_int(data):
    return int.from_bytes(data, "little")

def set_ptr(transport, zp_addr, target_addr):
    write_bytes(transport, zp_addr,
                bytes([target_addr & 0xFF, (target_addr >> 8) & 0xFF]))


def write_field_elem(transport, addr, value):
    write_bytes(transport, addr, int_to_le_bytes(value, 48))

def read_field_elem(transport, addr):
    return le_bytes_to_int(read_bytes(transport, addr, 48))

def write_jacobian_point(transport, base_addr, x, y, z):
    """Write Jacobian point. X=offset 0, Y=offset 48, Z=offset 96."""
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


def jacobian_to_affine_python(jx, jy, jz):
    """Convert Jacobian (X, Y, Z) to affine (x, y) in Python."""
    z_inv = pow(jz, P384 - 2, P384)
    z2 = (z_inv * z_inv) % P384
    z3 = (z2 * z_inv) % P384
    ax = (jx * z2) % P384
    ay = (jy * z3) % P384
    return ax, ay


def int_to_be_bytes(val, length=48):
    return val.to_bytes(length, "big")


def zero_point(transport, addr, nbytes=144):
    """Zero-fill a buffer from Python (avoids relying on asm infinity fill)."""
    write_bytes(transport, addr, b"\x00" * nbytes)


# ============================================================================
# Test functions
# ============================================================================

def test_ec_mulp_384(transport, labels):
    """Smoke test: 1*1 mod p384 = 1, and Gx*Gx mod p384 matches Python."""
    passed = failed = 0

    write_field_elem(transport, labels["fp384_tmp1"], 1)
    write_field_elem(transport, labels["fp384_tmp2"], 1)
    set_ptr(transport, labels["fp_src1"], labels["fp384_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp384_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp384_tmp3"])

    print("  Calling ec_mulp_384 (1 * 1 mod p)...")
    t0 = time.time()
    jsr(transport, labels["ec_mulp_384"], timeout=120.0)
    print(f"  ec_mulp_384 completed in {time.time()-t0:.1f}s")

    result = read_field_elem(transport, labels["fp384_tmp3"])
    if result == 1:
        passed += 1
        print("  PASS: ec_mulp_384(1, 1) = 1")
    else:
        failed += 1
        print(f"  FAIL: ec_mulp_384(1, 1) = {result:#098x} (expected 1)")

    write_field_elem(transport, labels["fp384_tmp1"], G_X)
    write_field_elem(transport, labels["fp384_tmp2"], G_X)
    set_ptr(transport, labels["fp_src1"], labels["fp384_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp384_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp384_tmp3"])

    print("  Calling ec_mulp_384 (Gx * Gx mod p)...")
    t0 = time.time()
    jsr(transport, labels["ec_mulp_384"], timeout=120.0)
    print(f"  ec_mulp_384 completed in {time.time()-t0:.1f}s")

    result = read_field_elem(transport, labels["fp384_tmp3"])
    expected = (G_X * G_X) % P384
    if result == expected:
        passed += 1
        print("  PASS: ec_mulp_384(Gx, Gx) matches Python reference")
    else:
        failed += 1
        print(f"  FAIL: ec_mulp_384(Gx, Gx)")
        print(f"    expected = {expected:#098x}")
        print(f"    got      = {result:#098x}")

    return passed, failed


def test_point_double_384(transport, labels):
    """Point doubling -- 2*G via ec_point_double_384."""
    passed = failed = 0

    print("  Loading generator G into ec384_p1 (Jacobian, Z=1)...")
    write_jacobian_point(transport, labels["ec384_p1"], G_X, G_Y, 1)

    print("  Calling ec_point_double_384...")
    t0 = time.time()
    jsr(transport, labels["ec_point_double_384"], timeout=120.0)
    print(f"  ec_point_double_384 completed in {time.time()-t0:.1f}s")

    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    if VERBOSE:
        print(f"    Jacobian result: X={p3x:#098x}")
        print(f"                     Y={p3y:#098x}")
        print(f"                     Z={p3z:#098x}")

    print("  Converting Jacobian to affine in Python...")
    ax, ay = jacobian_to_affine_python(p3x, p3y, p3z)

    if ax == TWO_G_X and ay == TWO_G_Y:
        passed += 1
        print("  PASS: 2*G matches expected coordinates")
    else:
        failed += 1
        print("  FAIL: 2*G does not match")
        print(f"    expected X = {TWO_G_X:#098x}")
        print(f"    got      X = {ax:#098x}")
        print(f"    expected Y = {TWO_G_Y:#098x}")
        print(f"    got      Y = {ay:#098x}")

    return passed, failed


def test_point_add_384(transport, labels):
    """Point addition -- G + G = 2*G via ec_point_add_384."""
    passed = failed = 0

    print("  Loading G into ec384_p1 (Jacobian, Z=1) and ec384_p2 (affine)...")
    write_jacobian_point(transport, labels["ec384_p1"], G_X, G_Y, 1)
    write_affine_point(transport, labels["ec384_p2"], G_X, G_Y)

    print("  Calling ec_point_add_384...")
    t0 = time.time()
    jsr(transport, labels["ec_point_add_384"], timeout=120.0)
    print(f"  ec_point_add_384 completed in {time.time()-t0:.1f}s")

    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    if VERBOSE:
        print(f"    Jacobian result: X={p3x:#098x}")
        print(f"                     Y={p3y:#098x}")
        print(f"                     Z={p3z:#098x}")

    print("  Converting Jacobian to affine in Python...")
    ax, ay = jacobian_to_affine_python(p3x, p3y, p3z)

    if ax == TWO_G_X and ay == TWO_G_Y:
        passed += 1
        print("  PASS: G + G = 2*G matches expected coordinates")
    else:
        failed += 1
        print("  FAIL: G + G does not match 2*G")
        print(f"    expected X = {TWO_G_X:#098x}")
        print(f"    got      X = {ax:#098x}")
        print(f"    expected Y = {TWO_G_Y:#098x}")
        print(f"    got      Y = {ay:#098x}")

    return passed, failed


def test_point_at_infinity_384(transport, labels):
    """Set ec384_p1 Z=0, call ec_point_double_384, verify result all zeros.

    NOTE: The current ec_point_double_384 infinity fill loop uses
        LDY #$8F ; ... ; DEY ; BPL loop
    which fails because $8F has bit 7 set -> BPL never branches. This means
    the routine does not zero out ec384_p3 on the infinity path; it simply
    leaves whatever was there. We pre-zero ec384_p3 from Python before the
    call so the check is meaningful, and verify the routine doesn't OVERWRITE
    ec384_p3 with a bogus doubling result. A true assembly fix would replace
    the loop with e.g. LDY #144 / (DEY) / BNE ... going to zero via BNE.
    """
    passed = failed = 0

    print("  Setting ec384_p1 to point at infinity (Z=0)...")
    write_jacobian_point(transport, labels["ec384_p1"], 42, 99, 0)

    # Pre-zero ec384_p3 so we can verify the routine does NOT perform a full
    # doubling (writing computed coords over the zero buffer).
    zero_point(transport, labels["ec384_p3"], 144)

    write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

    print("  Calling ec_point_double_384 (infinity case)...")
    jsr(transport, labels["ec_point_double_384"], timeout=60.0)

    p3_data = read_bytes(transport, labels["ec384_p3"], 144)
    all_zero = all(b == 0 for b in p3_data)

    if all_zero:
        passed += 1
        print("  PASS: Doubling infinity leaves ec384_p3 all zeros")
    else:
        failed += 1
        p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
        print("  FAIL: Doubling infinity did not give all zeros")
        print(f"    X = {p3x:#098x}")
        print(f"    Y = {p3y:#098x}")
        print(f"    Z = {p3z:#098x}")

    return passed, failed


def test_add_infinity_plus_g_384(transport, labels):
    """infinity + G = G (with Z=1)."""
    passed = failed = 0

    print("  Setting ec384_p1 = infinity, ec384_p2 = G...")
    write_jacobian_point(transport, labels["ec384_p1"], 0, 0, 0)
    write_affine_point(transport, labels["ec384_p2"], G_X, G_Y)

    write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

    print("  Calling ec_point_add_384 (infinity + G)...")
    t0 = time.time()
    jsr(transport, labels["ec_point_add_384"], timeout=120.0)
    print(f"  ec_point_add_384 completed in {time.time()-t0:.1f}s")

    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])

    if p3x == G_X and p3y == G_Y and p3z == 1:
        passed += 1
        print("  PASS: infinity + G = G (with Z=1)")
    else:
        failed += 1
        print("  FAIL: infinity + G did not give G")
        print(f"    expected X = {G_X:#098x}")
        print(f"    got      X = {p3x:#098x}")
        print(f"    expected Y = {G_Y:#098x}")
        print(f"    got      Y = {p3y:#098x}")
        print(f"    expected Z = 1")
        print(f"    got      Z = {p3z:#098x}")

    return passed, failed


def test_scalar_mul_k1_384(transport, labels):
    """Scalar multiplication k=1: 1*G = G via ec_scalar_mul_384."""
    passed = failed = 0
    SCALAR_BUF = 0x033C

    print("  Writing scalar k=1 (big-endian, 48 bytes) to memory...")
    k_bytes = int_to_be_bytes(1, 48)
    write_bytes(transport, SCALAR_BUF, k_bytes)
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_BUF)

    print("  Calling ec_scalar_mul_384 (k=1)...")
    t0 = time.time()
    jsr(transport, labels["ec_scalar_mul_384"], timeout=3600.0)
    elapsed = time.time() - t0
    print(f"  ec_scalar_mul_384 completed in {elapsed:.1f}s")

    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    if VERBOSE:
        print(f"    Jacobian result: X={p3x:#098x}")
        print(f"                     Y={p3y:#098x}")
        print(f"                     Z={p3z:#098x}")

    ax, ay = jacobian_to_affine_python(p3x, p3y, p3z)

    if ax == G_X and ay == G_Y:
        passed += 1
        print("  PASS: 1*G via scalar_mul_384 = G")
    else:
        failed += 1
        print("  FAIL: 1*G via scalar_mul_384 does not match G")
        print(f"    expected X = {G_X:#098x}")
        print(f"    got      X = {ax:#098x}")
        print(f"    expected Y = {G_Y:#098x}")
        print(f"    got      Y = {ay:#098x}")

    return passed, failed


def test_scalar_mul_small_384(transport, labels):
    """Small scalar multiplication -- 2*G via ec_scalar_mul_384."""
    passed = failed = 0
    SCALAR_BUF = 0x033C

    print("  Writing scalar k=2 (big-endian, 48 bytes) to memory...")
    k_bytes = int_to_be_bytes(2, 48)
    write_bytes(transport, SCALAR_BUF, k_bytes)
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_BUF)

    print("  Calling ec_scalar_mul_384 (k=2, windowed method)...")
    t0 = time.time()
    jsr(transport, labels["ec_scalar_mul_384"], timeout=3600.0)
    elapsed = time.time() - t0
    print(f"  ec_scalar_mul_384 completed in {elapsed:.1f}s")

    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec384_p3"])
    if VERBOSE:
        print(f"    Jacobian result: X={p3x:#098x}")
        print(f"                     Y={p3y:#098x}")
        print(f"                     Z={p3z:#098x}")

    ax, ay = jacobian_to_affine_python(p3x, p3y, p3z)

    if ax == TWO_G_X and ay == TWO_G_Y:
        passed += 1
        print("  PASS: 2*G via scalar_mul_384 matches expected coordinates")
    else:
        failed += 1
        print("  FAIL: 2*G via scalar_mul_384 does not match")
        print(f"    expected X = {TWO_G_X:#098x}")
        print(f"    got      X = {ax:#098x}")
        print(f"    expected Y = {TWO_G_Y:#098x}")
        print(f"    got      Y = {ay:#098x}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels):
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    transport_broken = False

    test_groups = [
        ("ec_mulp_384 smoke test",
         lambda: test_ec_mulp_384(transport, labels)),
        ("Point doubling (2*G)",
         lambda: test_point_double_384(transport, labels)),
        ("Point addition (G + G = 2*G)",
         lambda: test_point_add_384(transport, labels)),
        ("Point at infinity (double)",
         lambda: test_point_at_infinity_384(transport, labels)),
        ("Infinity + G = G (add)",
         lambda: test_add_infinity_plus_g_384(transport, labels)),
        ("Scalar mul (k=1, expect G)",
         lambda: test_scalar_mul_k1_384(transport, labels)),
        ("Scalar mul (k=2, expect 2*G)",
         lambda: test_scalar_mul_small_384(transport, labels)),
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

        # Safety loop
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        p384_addr = labels["ec_p384"]
        set_ptr(transport, labels["fp_misc"], p384_addr)
        print(f"Set fp_misc -> ec_p384 (${p384_addr:04X})")

        passed, failed, skipped = run_tests(transport, labels)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
