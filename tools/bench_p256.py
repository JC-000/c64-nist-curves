#!/usr/bin/env python3
"""bench_p256.py — Performance benchmarks for P-256 primitives on C64/VICE.

Measures jiffy clock cycles (NTSC, VIC blanked) for each field and curve
primitive by installing a small 6502 trampoline loop at $C000 that calls
the target routine N times between bench_start/bench_stop.

Usage:
    python3 tools/bench_p256.py
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# Oracle imports: bench refuses to record cycles for a routine whose
# single-call output does not match the external reference.
sys.path.insert(0, PROJECT_ROOT)
from tools.vectors import (  # noqa: E402
    P256_P, affine_add, affine_double,
    jacobian_to_affine, scalar_mul_oracle,
)

# NTSC C64: ~1.022727 MHz, 17045 cycles per jiffy (1/60 sec).
NTSC_CYCLES_PER_JIFFY = 17045
NTSC_CPU_HZ = NTSC_CYCLES_PER_JIFFY * 60  # ~1,022,700 Hz


def _warn_if_vice_running():
    import subprocess, sys
    try:
        res = subprocess.run(["pgrep", "-c", "x64sc"], capture_output=True, text=True, timeout=2)
        n = int(res.stdout.strip() or "0")
        if n > 0:
            print(f"WARNING: {n} other x64sc instance(s) already running - wall-clock timings may be unreliable.", file=sys.stderr)
    except Exception:
        pass  # preflight must never block test execution

# Trampoline install address (unused RAM under BASIC ROM is fine here; $C000
# is the standard free 4 KB block that is always RAM).
TRAMPOLINE_ADDR = 0xC000

# P-256 prime, just for constructing realistic-looking operands.
P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

# Fixed "random-looking" operands — reproducible across runs.
OPERAND_A = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
OPERAND_B = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
# A Jacobian point on P-256 for the curve ops (the base-point G affine coords,
# Z=1 gives a valid Jacobian point).  Used for doubling input.
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
# For add, second (affine) operand = 2G (precomputed).  Using G itself as
# p2 would double through the add path which is a degenerate case; use a
# different affine point to benchmark the normal add path.  We use 2G.
# 2*G computed off-line:
G2X = 0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978
G2Y = 0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1


def int_to_le_bytes(val, length=32):
    return (val & ((1 << (8 * length)) - 1)).to_bytes(length, "little")

def le_bytes_to_int(data):
    return int.from_bytes(data, "little")

def set_ptr(transport, zp_addr, target):
    write_bytes(transport, zp_addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def build_loop_trampoline(routine_addr, count):
    """Build an inline loop trampoline at $C000:

        LDA #count
        STA $C020           ; counter in memory (routines clobber X/Y)
    loop:
        JSR routine
        DEC $C020
        BNE loop
        RTS

    `count` must be in 1..255.  We use an absolute-address counter at
    $C020 rather than the X register, because most of the benchmarked
    routines clobber X (e.g. fp_add uses `LDX #32`).
    """
    assert 1 <= count <= 255, f"loop count {count} out of range 1..255"
    return bytes([
        0xA9, count & 0xFF,                                     # LDA #count
        0x8D, 0x20, 0xC0,                                       # STA $C020
        0x20, routine_addr & 0xFF, (routine_addr >> 8) & 0xFF,  # JSR routine
        0xCE, 0x20, 0xC0,                                       # DEC $C020
        0xD0, 0xF8,                                             # BNE loop
        0x60,                                                   # RTS
    ])


def read_bench_ticks(transport, labels):
    """Read the jiffy count from bench_ticks.

    bench_stop copies $A0, $A1, $A2 into bench_ticks+0/+1/+2.  The KERNAL
    jiffy clock at $A0-$A2 is stored big-endian (MSB first), so the
    in-memory layout is [MSB, mid, LSB].
    """
    raw = read_bytes(transport, labels["bench_ticks"], 3)
    return (raw[0] << 16) | (raw[1] << 8) | raw[2]


def bench_routine(transport, labels, routine_label, loops, setup_fn=None,
                  verify_fn=None, timeout=60.0):
    """Benchmark a single routine `loops` times.

    Returns (jiffies, cycles_per_call, ms_per_call).
    `setup_fn(transport, labels)` runs once before each timed batch to
    re-prime inputs that may have been mutated by the previous call.
    `verify_fn(transport, labels)`, if provided, is called after a
    single untimed invocation of the routine and must return True when
    the routine's output matches the external oracle. Any failure
    raises RuntimeError -- bench refuses to record cycles for an
    unverified routine.
    """
    routine_addr = labels[routine_label]
    trampoline = build_loop_trampoline(routine_addr, loops)

    # --- correctness gate -------------------------------------------------
    # Re-prime inputs, call the routine once directly (not in the loop),
    # and compare against the oracle. Only if this passes do we proceed
    # to the timed loop.
    if verify_fn is not None:
        if setup_fn is not None:
            setup_fn(transport, labels)
        jsr(transport, routine_addr, timeout=max(timeout, 10.0))
        if not verify_fn(transport, labels):
            raise RuntimeError(
                f"correctness gate FAILED for {routine_label}: "
                f"output does not match oracle"
            )

    if setup_fn is not None:
        setup_fn(transport, labels)

    # Install the trampoline fresh each time (cheap, and ensures no stale code).
    write_bytes(transport, TRAMPOLINE_ADDR, trampoline)

    # VIC blanking gives +20-25% CPU back to the 6510.
    jsr(transport, labels["vic_blank"], timeout=5.0)
    jsr(transport, labels["bench_start"], timeout=5.0)
    jsr(transport, TRAMPOLINE_ADDR, timeout=timeout)
    jsr(transport, labels["bench_stop"], timeout=5.0)
    jsr(transport, labels["vic_unblank"], timeout=5.0)

    jiffies = read_bench_ticks(transport, labels)
    total_cycles = jiffies * NTSC_CYCLES_PER_JIFFY
    cycles_per_call = total_cycles // loops
    ms_per_call = (cycles_per_call / NTSC_CPU_HZ) * 1000.0
    return jiffies, cycles_per_call, ms_per_call


# ----------------------------------------------------------------------------
# Per-routine setup functions
# ----------------------------------------------------------------------------

def setup_field_ab(transport, labels):
    """Load fp_tmp1 = A, fp_tmp2 = B, set src1/src2/dst to tmp1/tmp2/tmp3."""
    write_bytes(transport, labels["fp_tmp1"], int_to_le_bytes(OPERAND_A, 32))
    write_bytes(transport, labels["fp_tmp2"], int_to_le_bytes(OPERAND_B, 32))
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])


def setup_field_a(transport, labels):
    """Load fp_tmp1 = A; set src1 -> fp_tmp1 (for sqr and inv)."""
    write_bytes(transport, labels["fp_tmp1"], int_to_le_bytes(OPERAND_A, 32))
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])


def setup_reduce(transport, labels):
    """Load fp_wide with a 512-bit value that will exercise Solinas reduction."""
    wide = (OPERAND_A * OPERAND_B) & ((1 << 512) - 1)
    write_bytes(transport, labels["fp_wide"], int_to_le_bytes(wide, 64))


def setup_point_double(transport, labels):
    """Load ec_p1 with a valid Jacobian point (G, Z=1).
    ec_p1 layout: X (32 bytes), Y (32 bytes), Z (32 bytes), all little-endian.
    """
    ec_p1 = labels["ec_p1"]
    write_bytes(transport, ec_p1 + 0,  int_to_le_bytes(GX, 32))
    write_bytes(transport, ec_p1 + 32, int_to_le_bytes(GY, 32))
    write_bytes(transport, ec_p1 + 64, int_to_le_bytes(1,  32))  # Z = 1


def setup_point_add(transport, labels):
    """Load ec_p1 (Jacobian, = G) and ec_p2 (affine, = 2G).
    ec_p2 layout: X (32), Y (32); Z unused.
    """
    setup_point_double(transport, labels)
    ec_p2 = labels["ec_p2"]
    write_bytes(transport, ec_p2 + 0,  int_to_le_bytes(G2X, 32))
    write_bytes(transport, ec_p2 + 32, int_to_le_bytes(G2Y, 32))


# --- J+J operands: lifts of (3G, 5G) to Jacobian with non-trivial Z values.
# Both inputs are full Jacobian (X, Y, Z != 1) so the J+J formula must
# execute the Z1*Z2/Z2^2/Z1^2 multiplies it would otherwise skip in the
# mixed (affine-Z2) add. Chosen here as deterministic Python int constants;
# the verify oracle composes affine(jj_p1) + affine(jj_p2) via the
# library helpers.
JJ_K1 = 3
JJ_K2 = 5
# Non-trivial Z lifts. For any affine (x, y) and any Z in F_p*, the
# Jacobian (x*Z^2 mod p, y*Z^3 mod p, Z) represents the same affine point.
JJ_Z1 = 0xA13F50C2B9D7E68417593E4F2B0CDA1567F801932E47B5C61D9A0F8E27634519
JJ_Z2 = 0x55ED7B4029164CFA8B72190E63D80F47A98C25361EF7B0A8429D6E10B5C8347F

def _lift_to_jacobian_p256(k, z):
    ax, ay = scalar_mul_oracle(k, "p256")
    z2 = (z * z) % P256_P
    z3 = (z2 * z) % P256_P
    jx = (ax * z2) % P256_P
    jy = (ay * z3) % P256_P
    return jx, jy, z


def setup_point_add_jj(transport, labels):
    """Both ec_p1 and ec_p2 as full Jacobian with non-trivial Z."""
    jx1, jy1, jz1 = _lift_to_jacobian_p256(JJ_K1, JJ_Z1)
    jx2, jy2, jz2 = _lift_to_jacobian_p256(JJ_K2, JJ_Z2)
    ec_p1 = labels["ec_p1"]
    ec_p2 = labels["ec_p2"]
    write_bytes(transport, ec_p1 + 0,  int_to_le_bytes(jx1, 32))
    write_bytes(transport, ec_p1 + 32, int_to_le_bytes(jy1, 32))
    write_bytes(transport, ec_p1 + 64, int_to_le_bytes(jz1, 32))
    write_bytes(transport, ec_p2 + 0,  int_to_le_bytes(jx2, 32))
    write_bytes(transport, ec_p2 + 32, int_to_le_bytes(jy2, 32))
    write_bytes(transport, ec_p2 + 64, int_to_le_bytes(jz2, 32))


# --- mod-n multiply operands: ecdsa_h * ecdsa_w shape (post-w-stash).
# fp_mod_mul_n hardcodes the ec_n256 pointer at the source-text level
# (see src/mod256.s:651, 663) so the caller does NOT need to issue
# ec_set_modn. Operand layout is fp_src1 (a) * fp_src2 (b) -> fp_dst (LE).
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
MODN_A = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
MODN_B = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
# Both operands must be in [0, n-1] per fp_mod_mul_n's caller contract.
MODN_A %= P256_N
MODN_B %= P256_N


def setup_fp_mod_mul_n(transport, labels):
    """Stage fp_src1 = MODN_A, fp_src2 = MODN_B, fp_dst = fp_tmp3."""
    write_bytes(transport, labels["fp_tmp1"], int_to_le_bytes(MODN_A, 32))
    write_bytes(transport, labels["fp_tmp2"], int_to_le_bytes(MODN_B, 32))
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])


# Representative 256-bit scalar: RFC 6979 sample-message private key.
# (Same constant as TEST_PRIVKEY in test_points256.py.)
SCALAR_MUL_K = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

# Scratch buffer in cassette area (free RAM, won't be touched by point ops).
SCALAR_MUL_BUF = 0x033C


# ----------------------------------------------------------------------------
# Correctness verifiers (oracle gates)
# ----------------------------------------------------------------------------

def _read_le(transport, addr, length):
    return int.from_bytes(read_bytes(transport, addr, length), "little")


def verify_fp_add(transport, labels):
    # fp_add writes 32 bytes; carry is dropped (caller's responsibility).
    got = _read_le(transport, labels["fp_tmp3"], 32)
    return got == ((OPERAND_A + OPERAND_B) & ((1 << 256) - 1))


def verify_fp_sub(transport, labels):
    got = _read_le(transport, labels["fp_tmp3"], 32)
    return got == ((OPERAND_A - OPERAND_B) & ((1 << 256) - 1))


def verify_fp_mul(transport, labels):
    # fp_mul writes the 64-byte product to fp_wide, NOT fp_dst.
    got = _read_le(transport, labels["fp_wide"], 64)
    return got == OPERAND_A * OPERAND_B


def verify_fp_sqr(transport, labels):
    got = _read_le(transport, labels["fp_wide"], 64)
    return got == OPERAND_A * OPERAND_A


def verify_fp_mod_add(transport, labels):
    got = _read_le(transport, labels["fp_tmp3"], 32)
    return got == (OPERAND_A + OPERAND_B) % P256


def verify_fp_mod_sub(transport, labels):
    got = _read_le(transport, labels["fp_tmp3"], 32)
    return got == (OPERAND_A - OPERAND_B) % P256


def verify_fp_mod_reduce(transport, labels):
    # fp_mod_reduce256 reads fp_wide; writes fp_r0 (32 bytes).
    got = _read_le(transport, labels["fp_r0"], 32)
    wide = (OPERAND_A * OPERAND_B) & ((1 << 512) - 1)
    return got == wide % P256


def verify_fp_mod_mul(transport, labels):
    # fp_mod_mul writes fp_r0 (via fp_mod_reduce256), NOT fp_dst.
    got = _read_le(transport, labels["fp_r0"], 32)
    return got == (OPERAND_A * OPERAND_B) % P256


def verify_fp_mod_sqr(transport, labels):
    got = _read_le(transport, labels["fp_r0"], 32)
    return got == (OPERAND_A * OPERAND_A) % P256


def verify_fp_mod_inv(transport, labels):
    got = _read_le(transport, labels["fp_r0"], 32)
    return got == pow(OPERAND_A, -1, P256)


def verify_point_double(transport, labels):
    jx = _read_le(transport, labels["ec_p3"], 32)
    jy = _read_le(transport, labels["ec_p3"] + 32, 32)
    jz = _read_le(transport, labels["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    expected = affine_double((GX, GY), "p256")
    return (ax, ay) == expected


def verify_point_add(transport, labels):
    jx = _read_le(transport, labels["ec_p3"], 32)
    jy = _read_le(transport, labels["ec_p3"] + 32, 32)
    jz = _read_le(transport, labels["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    expected = affine_add((GX, GY), (G2X, G2Y), "p256")
    return (ax, ay) == expected


def verify_point_add_jj(transport, labels):
    jx = _read_le(transport, labels["ec_p3"], 32)
    jy = _read_le(transport, labels["ec_p3"] + 32, 32)
    jz = _read_le(transport, labels["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    expected = affine_add(scalar_mul_oracle(JJ_K1, "p256"),
                          scalar_mul_oracle(JJ_K2, "p256"), "p256")
    return (ax, ay) == expected


def verify_fp_mod_mul_n(transport, labels):
    got = _read_le(transport, labels["fp_tmp3"], 32)
    return got == (MODN_A * MODN_B) % P256_N


def verify_scalar_mul(transport, labels):
    jx = _read_le(transport, labels["ec_p3"], 32)
    jy = _read_le(transport, labels["ec_p3"] + 32, 32)
    jz = _read_le(transport, labels["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    expected = scalar_mul_oracle(SCALAR_MUL_K, "p256")
    return (ax, ay) == expected


def setup_scalar_mul(transport, labels):
    """Write a representative 256-bit scalar (BE) and point ec_scalar_ptr at it.

    The Lim-Lee precompute table built at boot lives in REU bank 2 and is
    not disturbed by reu_mul_init (which only writes bank 0), so it remains
    valid here.
    """
    k_be = SCALAR_MUL_K.to_bytes(32, "big")
    write_bytes(transport, SCALAR_MUL_BUF, k_be)
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_MUL_BUF)


# ----------------------------------------------------------------------------
# Benchmark plan
# ----------------------------------------------------------------------------

# (routine_label, loops, setup_fn, verify_fn, timeout_seconds)
BENCH_PLAN = [
    ("fp_add",           100, setup_field_ab,     verify_fp_add,         30.0),
    ("fp_sub",           100, setup_field_ab,     verify_fp_sub,         30.0),
    ("fp_mul",            20, setup_field_ab,     verify_fp_mul,        120.0),
    ("fp_sqr",            20, setup_field_a,      verify_fp_sqr,        120.0),
    ("fp_mod_add",       100, setup_field_ab,     verify_fp_mod_add,     30.0),
    ("fp_mod_sub",       100, setup_field_ab,     verify_fp_mod_sub,     30.0),
    ("fp_mod_reduce256",  20, setup_reduce,       verify_fp_mod_reduce,  60.0),
    ("fp_mod_mul",        10, setup_field_ab,     verify_fp_mod_mul,    120.0),
    ("fp_mod_sqr",        10, setup_field_a,      verify_fp_mod_sqr,    120.0),
    ("fp_mod_inv",         1, setup_field_a,      verify_fp_mod_inv,    600.0),
    ("bench_fp_mod_mul_n_tramp",      5, setup_fp_mod_mul_n,
        verify_fp_mod_mul_n,  300.0),
    ("ec_point_double",    1, setup_point_double, verify_point_double,  600.0),
    ("ec_point_add",       1, setup_point_add,    verify_point_add,     900.0),
    ("bench_ec_point_add_jj_tramp",   1, setup_point_add_jj,
        verify_point_add_jj,   900.0),
    ("ec_scalar_mul",      1, setup_scalar_mul,   verify_scalar_mul,   3600.0),
]


def main():
    _warn_if_vice_running()
    os.chdir(PROJECT_ROOT)

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
        "fp_src1", "fp_src2", "fp_dst", "fp_misc",
        "fp_tmp1", "fp_tmp2", "fp_tmp3", "fp_wide", "fp_r0",
        "sqtab_init", "reu_mul_init",
        "bench_start", "bench_stop", "bench_ticks",
        "vic_blank", "vic_unblank",
        "ec_p256", "ec_p1", "ec_p2", "ec_p3",
        "ec_scalar_ptr",
    ]
    # Routines to be benchmarked must exist.
    required += [name for (name, _l, _s, _v, _t) in BENCH_PLAN]

    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    # Launch VICE with REU enabled (reu_mul_init uses it).
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config,
                             port_range_start=6551,
                             port_range_end=6571) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        # Wait for boot-time init to complete via $02A7 sentinel (sqtab +
        # reu_mul_init + ec_precompute_256 + ec_precompute_384). This is
        # the canonical pattern per CLAUDE.md; previously this file used
        # wait_for_text("READY.", timeout=180.0) which became flaky after
        # the ct_mul_8x8 port (issue #14) extended boot time past the 180 s
        # budget and is fundamentally race-prone against the text grid.
        # No post-sentinel jsr-reinit is needed — the sentinel is written
        # after every table is built, so state is known-good.
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
        print(f"Init complete after {time.time() - start:.1f}s")

        # Safety loop for jsr() return.
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Point fp_misc at ec_p256 for modular routines.
        set_ptr(transport, labels["fp_misc"], labels["ec_p256"])

        # Run benchmarks
        print()
        print("Running benchmarks (oracle correctness gate enabled)...")
        results = []
        unverified = []
        for name, loops, setup_fn, verify_fn, timeout in BENCH_PLAN:
            print(f"  {name} (x{loops})...", flush=True, end=" ")
            try:
                jiffies, cycles, ms = bench_routine(
                    transport, labels, name, loops,
                    setup_fn=setup_fn, verify_fn=verify_fn, timeout=timeout)
            except RuntimeError as e:
                print("UNVERIFIED")
                print(f"    {e}")
                unverified.append(name)
                continue
            print("verified OK")
            results.append((name, loops, jiffies, cycles, ms))

        mgr.release(inst)

    # Report
    print()
    title = (f"P-256 Primitive Benchmarks "
             f"(NTSC, 1.02 MHz, VIC blanked, 1 jiffy = "
             f"{NTSC_CYCLES_PER_JIFFY} cycles)")
    bar = "=" * len(title)
    print(bar)
    print(title)
    print(bar)
    hdr = f"{'Routine':<20} {'Loops':>6} {'Jiffies':>9} {'Cycles/call':>13} {'ms/call':>12}"
    print(hdr)
    print("-" * len(bar))
    for name, loops, jiffies, cycles, ms in results:
        print(f"{name:<20} {loops:>6} {jiffies:>9} {cycles:>13} {ms:>12.3f}")
    print(bar)
    if unverified:
        print()
        print(f"UNVERIFIED ROUTINES ({len(unverified)}): {', '.join(unverified)}")
        print("These routines failed the oracle correctness gate and")
        print("their cycle counts were NOT recorded.")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
