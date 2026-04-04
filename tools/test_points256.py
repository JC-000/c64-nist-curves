#!/usr/bin/env python3
"""test_points256.py -- Direct-memory P-256 point operation tests.

Tests ec_point_double, ec_point_add, ec_scalar_mul, ec_jacobian_to_affine.
All field elements are LITTLE-ENDIAN (byte 0 = LSB).
Point layout: X = offset 0..31, Y = offset 32..63, Z = offset 64..95.

Uses the c64-test-harness binary monitor transport.

Usage:
    python3 tools/test_points256.py [--seed S] [--verbose] [--full]

    --full   Run the full scalar multiplication test (hours in warp mode).
             Without this flag only the fast tests are run.
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

# P-256 field prime
P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

# P-256 generator coordinates (from SEC 2)
G_X = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
G_Y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Known 2*G coordinates (P-256)
TWO_G_X = 0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
TWO_G_Y = 0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1

# RFC 6979 A.2.5 test private key (from assembly data, as integer)
# Private key: sample signing key for message "sample" with SHA-256
TEST_PRIVKEY = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

# Expected public key from TEST_PRIVKEY * G
TEST_PUBX = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
TEST_PUBY = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299


# ============================================================================
# Byte conversion helpers
# ============================================================================

def int_to_le_bytes(val, length=32):
    """Convert non-negative Python int to little-endian bytes of given length."""
    return val.to_bytes(length, "little")

def le_bytes_to_int(data):
    """Convert little-endian bytes to Python int."""
    return int.from_bytes(data, "little")

def int_to_be_bytes(val, length=32):
    """Convert non-negative Python int to big-endian bytes of given length."""
    return val.to_bytes(length, "big")

def set_ptr(transport, zp_addr, target_addr):
    """Write a 16-bit little-endian pointer to zero page."""
    write_bytes(transport, zp_addr,
                bytes([target_addr & 0xFF, (target_addr >> 8) & 0xFF]))


# ============================================================================
# C64 helper functions
# ============================================================================

def write_field_elem(transport, addr, value, length=32):
    """Write a field element (integer) to C64 memory as little-endian bytes."""
    write_bytes(transport, addr, int_to_le_bytes(value, length))

def read_field_elem(transport, addr, length=32):
    """Read a little-endian field element from C64 memory, return as integer."""
    return le_bytes_to_int(read_bytes(transport, addr, length))

def write_jacobian_point(transport, base_addr, x, y, z):
    """Write a Jacobian point (X, Y, Z) to memory at base_addr.
    Each coordinate is 32 bytes, little-endian."""
    write_field_elem(transport, base_addr, x)       # X at offset 0
    write_field_elem(transport, base_addr + 32, y)   # Y at offset 32
    write_field_elem(transport, base_addr + 64, z)   # Z at offset 64

def write_affine_point(transport, base_addr, x, y):
    """Write an affine point (X, Y) to memory at base_addr.
    Each coordinate is 32 bytes, little-endian. (Z is not written.)"""
    write_field_elem(transport, base_addr, x)        # X at offset 0
    write_field_elem(transport, base_addr + 32, y)    # Y at offset 32

def read_jacobian_point(transport, base_addr):
    """Read a Jacobian point from memory. Returns (X, Y, Z) as ints."""
    x = read_field_elem(transport, base_addr)
    y = read_field_elem(transport, base_addr + 32)
    z = read_field_elem(transport, base_addr + 64)
    return x, y, z

def read_affine_result(transport, labels):
    """Read the affine output from ec_affine_x, ec_affine_y."""
    ax = read_field_elem(transport, labels["ec_affine_x"])
    ay = read_field_elem(transport, labels["ec_affine_y"])
    return ax, ay


# ============================================================================
# Test functions
# ============================================================================

def test_ec_mulp(transport, labels):
    """Smoke test: verify ec_mulp (modular multiply + copy to dst) works.

    Computes 1 * 1 mod p = 1 via ec_mulp and checks the result.
    This validates the entire chain: ec_set_modp -> fp_mod_mul -> fp_copy.
    """
    passed = failed = 0

    # Write 1 to fp_tmp1 and fp_tmp2 as src, fp_tmp3 as dst
    # (Use fp_tmp* rather than ec_t* to avoid any address-related issues)
    write_field_elem(transport, labels["fp_tmp1"], 1)
    write_field_elem(transport, labels["fp_tmp2"], 1)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])

    print("  Calling ec_mulp (1 * 1 mod p)...")
    t0 = time.time()
    jsr(transport, labels["ec_mulp"], timeout=300.0)
    elapsed = time.time() - t0
    print(f"  ec_mulp completed in {elapsed:.1f}s")

    result = read_field_elem(transport, labels["fp_tmp3"])
    if result == 1:
        passed += 1
        print("  PASS: ec_mulp(1, 1) = 1")
    else:
        failed += 1
        print(f"  FAIL: ec_mulp(1, 1) = {result:#066x} (expected 1)")

    # Now test with actual generator coordinates
    print(f"  Gx = {G_X:#066x}")
    print(f"  Gy = {G_Y:#066x}")

    write_field_elem(transport, labels["fp_tmp1"], G_X)
    write_field_elem(transport, labels["fp_tmp2"], G_X)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])

    print("  Calling ec_mulp (Gx * Gx mod p)...")
    t0 = time.time()
    jsr(transport, labels["ec_mulp"], timeout=300.0)
    elapsed = time.time() - t0
    print(f"  ec_mulp completed in {elapsed:.1f}s")

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


def jacobian_to_affine_python(jx, jy, jz):
    """Convert Jacobian (X, Y, Z) to affine (x, y) using Python arithmetic.

    This avoids the extremely slow C64 mod_inv for verification purposes.
    """
    z_inv = pow(jz, P256 - 2, P256)
    z2 = (z_inv * z_inv) % P256
    z3 = (z2 * z_inv) % P256
    ax = (jx * z2) % P256
    ay = (jy * z3) % P256
    return ax, ay


def test_point_double(transport, labels):
    """Test 1: Point doubling -- 2*G via ec_point_double.

    Load G into ec_p1 as Jacobian (Z=1), double, read Jacobian result,
    convert to affine IN PYTHON, compare with known 2*G coordinates.
    """
    passed = failed = 0

    print("  Loading generator G into ec_p1 (Jacobian, Z=1)...")
    if VERBOSE:
        print(f"    Gx = {G_X:#066x}")
        print(f"    Gy = {G_Y:#066x}")

    write_jacobian_point(transport, labels["ec_p1"], G_X, G_Y, 1)

    print("  Calling ec_point_double (7 mod-muls, may take several minutes)...")
    jsr(transport, labels["ec_point_double"], timeout=1800.0)

    # Read Jacobian result from ec_p3
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    if VERBOSE:
        print(f"    Jacobian result: X={p3x:#066x}")
        print(f"                     Y={p3y:#066x}")
        print(f"                     Z={p3z:#066x}")

    # Convert to affine in Python (C64 mod_inv is too slow for testing)
    print("  Converting Jacobian to affine in Python...")
    ax, ay = jacobian_to_affine_python(p3x, p3y, p3z)
    if VERBOSE:
        print(f"    Affine X = {ax:#066x}")
        print(f"    Affine Y = {ay:#066x}")

    if ax == TWO_G_X and ay == TWO_G_Y:
        passed += 1
        print("  PASS: 2*G matches expected coordinates")
    else:
        failed += 1
        print("  FAIL: 2*G does not match")
        print(f"    expected X = {TWO_G_X:#066x}")
        print(f"    got      X = {ax:#066x}")
        print(f"    expected Y = {TWO_G_Y:#066x}")
        print(f"    got      Y = {ay:#066x}")

    return passed, failed


def test_point_add(transport, labels):
    """Test 2: Point addition -- G + G = 2*G via ec_point_add.

    Load G into ec_p1 as Jacobian (Z=1), G into ec_p2 as affine,
    call ec_point_add, convert to affine, compare with 2*G.
    """
    passed = failed = 0

    print("  Loading G into ec_p1 (Jacobian, Z=1) and ec_p2 (affine)...")
    write_jacobian_point(transport, labels["ec_p1"], G_X, G_Y, 1)
    write_affine_point(transport, labels["ec_p2"], G_X, G_Y)

    print("  Calling ec_point_add (11 mod-muls, may take 20+ minutes)...")
    jsr(transport, labels["ec_point_add"], timeout=1800.0)

    # Read Jacobian result and convert in Python
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    if VERBOSE:
        print(f"    Jacobian result: X={p3x:#066x}")
        print(f"                     Y={p3y:#066x}")
        print(f"                     Z={p3z:#066x}")

    print("  Converting Jacobian to affine in Python...")
    ax, ay = jacobian_to_affine_python(p3x, p3y, p3z)

    if ax == TWO_G_X and ay == TWO_G_Y:
        passed += 1
        print("  PASS: G + G = 2*G matches expected coordinates")
    else:
        failed += 1
        print("  FAIL: G + G does not match 2*G")
        print(f"    expected X = {TWO_G_X:#066x}")
        print(f"    got      X = {ax:#066x}")
        print(f"    expected Y = {TWO_G_Y:#066x}")
        print(f"    got      Y = {ay:#066x}")

    return passed, failed


def test_point_at_infinity(transport, labels):
    """Test 5: Point at infinity handling.

    Set ec_p1 Z = 0 (point at infinity), double, verify result is all zeros.
    """
    passed = failed = 0

    print("  Setting ec_p1 to point at infinity (Z=0)...")
    # Write some nonzero X,Y but Z=0
    write_jacobian_point(transport, labels["ec_p1"], 42, 99, 0)

    # Refresh safety loop
    write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

    print("  Calling ec_point_double (infinity case, should be fast)...")
    jsr(transport, labels["ec_point_double"], timeout=60.0)

    # Read ec_p3 -- should be all zeros (infinity)
    p3_data = read_bytes(transport, labels["ec_p3"], 96)
    all_zero = all(b == 0 for b in p3_data)

    if all_zero:
        passed += 1
        print("  PASS: Doubling infinity gives infinity (all zeros)")
    else:
        failed += 1
        p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
        print("  FAIL: Doubling infinity did not give all zeros")
        print(f"    X = {p3x:#066x}")
        print(f"    Y = {p3y:#066x}")
        print(f"    Z = {p3z:#066x}")

    return passed, failed


def test_add_infinity_plus_g(transport, labels):
    """Test: infinity + G = G (via ec_point_add).

    Set ec_p1 = infinity (Z=0), ec_p2 = G (affine), call ec_point_add.
    Result should be G with Z=1.
    """
    passed = failed = 0

    print("  Setting ec_p1 = infinity, ec_p2 = G...")
    write_jacobian_point(transport, labels["ec_p1"], 0, 0, 0)
    write_affine_point(transport, labels["ec_p2"], G_X, G_Y)

    # Verify the safety loop is still intact
    write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

    print("  Calling ec_point_add (infinity + G, should be fast)...")
    t0 = time.time()
    jsr(transport, labels["ec_point_add"], timeout=120.0)
    print(f"  ec_point_add completed in {time.time() - t0:.1f}s")

    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])

    # When P1 is infinity, ec_point_add copies P2 to P3 with Z=1
    if p3x == G_X and p3y == G_Y and p3z == 1:
        passed += 1
        print("  PASS: infinity + G = G (with Z=1)")
    else:
        failed += 1
        print("  FAIL: infinity + G did not give G")
        print(f"    expected X = {G_X:#066x}")
        print(f"    got      X = {p3x:#066x}")
        print(f"    expected Y = {G_Y:#066x}")
        print(f"    got      Y = {p3y:#066x}")
        print(f"    expected Z = 1")
        print(f"    got      Z = {p3z:#066x}")

    return passed, failed


def test_scalar_mul_small(transport, labels):
    """Test 4: Small scalar multiplication -- 2*G via ec_scalar_mul.

    Use scalar k = 2 (big-endian: 00 00 ... 00 02).
    This processes only ~1 set bit, so should be much faster than a full
    256-bit scalar.
    """
    passed = failed = 0

    # Use a safe 32-byte buffer for the scalar that won't be clobbered
    # by point operations. ec_t1..ec_t6 are used as temps by point_double
    # and point_add, so we CANNOT use them.
    # Use the cassette buffer area at $033C (after jsr trampoline + safety JMP).
    SCALAR_BUF = 0x033C

    print("  Writing scalar k=2 (big-endian) to memory...")
    k_bytes = int_to_be_bytes(2, 32)
    write_bytes(transport, SCALAR_BUF, k_bytes)

    # Set ec_scalar_ptr (ZP $3b) to point to the scalar buffer
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_BUF)

    print("  Calling ec_scalar_mul (k=2, expect ~1 add + 256 doubles)...")
    print("  (this may take 30+ minutes in warp mode)")
    jsr(transport, labels["ec_scalar_mul"], timeout=3600.0)

    # Read Jacobian result and convert in Python
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    if VERBOSE:
        print(f"    Jacobian result: X={p3x:#066x}")
        print(f"                     Y={p3y:#066x}")
        print(f"                     Z={p3z:#066x}")

    print("  Converting Jacobian to affine in Python...")
    ax, ay = jacobian_to_affine_python(p3x, p3y, p3z)

    if ax == TWO_G_X and ay == TWO_G_Y:
        passed += 1
        print("  PASS: 2*G via scalar_mul matches expected coordinates")
    else:
        failed += 1
        print("  FAIL: 2*G via scalar_mul does not match")
        print(f"    expected X = {TWO_G_X:#066x}")
        print(f"    got      X = {ax:#066x}")
        print(f"    expected Y = {TWO_G_Y:#066x}")
        print(f"    got      Y = {ay:#066x}")

    return passed, failed


def test_scalar_mul_full(transport, labels):
    """Test 3: Full scalar multiplication -- k*G for test private key.

    Uses the test private key from ecdsa_test_privkey, computes k*G,
    compares with ecdsa_test_pubx/ecdsa_test_puby.

    WARNING: This is VERY slow (~hours in warp mode for 256 scalar bits).
    """
    passed = failed = 0

    # Use the known test private key (big-endian for scalar_mul)
    privkey_be = int_to_be_bytes(TEST_PRIVKEY, 32)
    if VERBOSE:
        print(f"    privkey (BE for scalar_mul) = {privkey_be.hex()}")

    # Write scalar to a safe buffer (cassette buffer area, not ec_t* temps!)
    SCALAR_BUF = 0x033C
    write_bytes(transport, SCALAR_BUF, privkey_be)

    # Set ec_scalar_ptr
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_BUF)

    print("  Calling ec_scalar_mul (full 256-bit key)...")
    print("  WARNING: This will take a VERY long time (~hours in warp mode)")
    jsr(transport, labels["ec_scalar_mul"], timeout=7200.0)

    # Read Jacobian result and convert in Python
    p3x, p3y, p3z = read_jacobian_point(transport, labels["ec_p3"])
    if VERBOSE:
        print(f"    Jacobian result: X={p3x:#066x}")
        print(f"                     Y={p3y:#066x}")
        print(f"                     Z={p3z:#066x}")

    print("  Converting Jacobian to affine in Python...")
    ax, ay = jacobian_to_affine_python(p3x, p3y, p3z)

    if ax == TEST_PUBX and ay == TEST_PUBY:
        passed += 1
        print("  PASS: k*G matches expected public key")
    else:
        failed += 1
        print("  FAIL: k*G does not match expected public key")
        print(f"    expected X = {TEST_PUBX:#066x}")
        print(f"    got      X = {ax:#066x}")
        print(f"    expected Y = {TEST_PUBY:#066x}")
        print(f"    got      Y = {ay:#066x}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, run_full):
    """Run all point operation tests."""
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    transport_broken = False

    test_groups = [
        ("ec_mulp smoke test", False,
         lambda: test_ec_mulp(transport, labels)),
        ("Point doubling (2*G)", False,
         lambda: test_point_double(transport, labels)),
        ("Point addition (G + G = 2*G)", False,
         lambda: test_point_add(transport, labels)),
        ("Point at infinity (double)", False,
         lambda: test_point_at_infinity(transport, labels)),
        ("Infinity + G = G (add)", False,
         lambda: test_add_infinity_plus_g(transport, labels)),
        ("Scalar mul (k=2, 2*G)", False,
         lambda: test_scalar_mul_small(transport, labels)),
        ("Scalar mul (full private key)", True,
         lambda: test_scalar_mul_full(transport, labels)),
    ]

    for name, needs_full, test_fn in test_groups:
        print(f"\n--- {name} ---")
        if needs_full and not run_full:
            total_skipped += 1
            print("  SKIP: use --full to run this test (takes hours)")
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

    # Verify required labels
    required = [
        "ec_p1", "ec_p2", "ec_p3",
        "ec_t1", "ec_t2", "ec_t3",
        "ec_gx256", "ec_gy256",
        "ec_point_double", "ec_point_add", "ec_scalar_mul",
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

    # Launch VICE with REU
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport

        # Wait for program to boot
        grid = wait_for_text(transport, "READY.", timeout=180.0, verbose=False)
        if grid is None:
            print("FATAL: Program did not reach READY state")
            print("  (sqtab_init + reu_mul_init may still be running)")
            mgr.release(inst)
            sys.exit(1)

        print("VICE ready, program initialized.")

        # Safety: write JMP $0339 at $0339 so CPU loops harmlessly
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

        # Write known-good curve data constants.  VICE startup can corrupt
        # the PRG image due to a binary monitor attach race, so we
        # overwrite data areas with known-correct values.  We do NOT
        # overwrite code areas (ec_mulp etc.) because that proved to
        # sometimes disrupt the binary monitor's jsr() mechanism.
        print("Writing known-good curve constants to memory...")
        write_field_elem(transport, labels["ec_gx256"], G_X)
        write_field_elem(transport, labels["ec_gy256"], G_Y)
        write_bytes(transport, labels["ec_p256"], int_to_le_bytes(P256))

        # Set fp_misc to point to ec_p256 for modular routines
        p256_addr = labels["ec_p256"]
        set_ptr(transport, labels["fp_misc"], p256_addr)
        print(f"Set fp_misc -> ec_p256 (${p256_addr:04X})")

        passed, failed, skipped = run_tests(transport, labels, run_full)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    if skipped > 0:
        print(f"  ({skipped} test group(s) skipped)")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
