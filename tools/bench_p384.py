#!/usr/bin/env python3
"""bench_p384.py -- Performance benchmarks for P-384 primitives on C64/VICE.

Measures jiffy clock cycles (NTSC, VIC blanked) for each field and curve
primitive by installing a small 6502 trampoline loop at $C000 that calls
the target routine N times between bench_start/bench_stop.

Usage:
    python3 tools/bench_p384.py
"""

import os
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

# Oracle imports: bench refuses to record cycles for routines that fail
# the single-call correctness gate.
sys.path.insert(0, PROJECT_ROOT)
from tools.vectors import (  # noqa: E402
    P384_P, affine_add, affine_double,
    jacobian_to_affine, scalar_mul_oracle,
)

# NTSC C64: ~1.022727 MHz, 17045 cycles per jiffy (1/60 sec).
NTSC_CYCLES_PER_JIFFY = 17045
NTSC_CPU_HZ = NTSC_CYCLES_PER_JIFFY * 60


def _warn_if_vice_running():
    import subprocess, sys
    try:
        res = subprocess.run(["pgrep", "-c", "x64sc"], capture_output=True, text=True, timeout=2)
        n = int(res.stdout.strip() or "0")
        if n > 0:
            print(f"WARNING: {n} other x64sc instance(s) already running - wall-clock timings may be unreliable.", file=sys.stderr)
    except Exception:
        pass  # preflight must never block test execution

TRAMPOLINE_ADDR = 0xC000

# P-384 operands: generator G and 2G (known values).
OPERAND_A = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
OPERAND_B = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
GX = OPERAND_A
GY = OPERAND_B
G2X = 0x08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61
G2Y = 0x8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80


def int_to_le_bytes(val, length=48):
    return (val & ((1 << (8 * length)) - 1)).to_bytes(length, "little")

def set_ptr(transport, zp_addr, target):
    write_bytes(transport, zp_addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def build_loop_trampoline(routine_addr, count):
    """Build inline loop trampoline at $C000 (counter at $C020)."""
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
    raw = read_bytes(transport, labels["bench_ticks"], 3)
    return (raw[0] << 16) | (raw[1] << 8) | raw[2]


def bench_routine(transport, labels, routine_label, loops, setup_fn=None,
                  verify_fn=None, timeout=60.0):
    """Benchmark a routine with a one-shot correctness gate against the oracle."""
    routine_addr = labels[routine_label]
    trampoline = build_loop_trampoline(routine_addr, loops)

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

    write_bytes(transport, TRAMPOLINE_ADDR, trampoline)

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
    write_bytes(transport, labels["fp384_tmp1"], int_to_le_bytes(OPERAND_A, 48))
    write_bytes(transport, labels["fp384_tmp2"], int_to_le_bytes(OPERAND_B, 48))
    set_ptr(transport, labels["fp_src1"], labels["fp384_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp384_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp384_tmp3"])


def setup_field_a(transport, labels):
    write_bytes(transport, labels["fp384_tmp1"], int_to_le_bytes(OPERAND_A, 48))
    set_ptr(transport, labels["fp_src1"], labels["fp384_tmp1"])
    set_ptr(transport, labels["fp_dst"], labels["fp384_tmp3"])


def setup_reduce(transport, labels):
    wide = (OPERAND_A * OPERAND_B) & ((1 << 768) - 1)
    write_bytes(transport, labels["fp384_wide"], int_to_le_bytes(wide, 96))


def setup_point_double(transport, labels):
    """Load ec384_p1 with a valid Jacobian point (G, Z=1).
    Layout: X (48), Y (48), Z (48) -- 144 bytes."""
    ec_p1 = labels["ec384_p1"]
    write_bytes(transport, ec_p1 + 0,  int_to_le_bytes(GX, 48))
    write_bytes(transport, ec_p1 + 48, int_to_le_bytes(GY, 48))
    write_bytes(transport, ec_p1 + 96, int_to_le_bytes(1,  48))  # Z=1


def setup_point_add(transport, labels):
    """ec384_p1 = Jacobian G, ec384_p2 = affine 2G."""
    setup_point_double(transport, labels)
    ec_p2 = labels["ec384_p2"]
    write_bytes(transport, ec_p2 + 0,  int_to_le_bytes(G2X, 48))
    write_bytes(transport, ec_p2 + 48, int_to_le_bytes(G2Y, 48))


# --- J+J operands: lifts of (3G, 5G) to Jacobian with non-trivial Z values.
# Both inputs are full Jacobian (X, Y, Z != 1) so the J+J formula must
# execute the Z1*Z2/Z2^2/Z1^2 multiplies it would otherwise skip in the
# mixed (affine-Z2) add. Verify oracle composes affine(jj_p1) +
# affine(jj_p2) via the library helpers.
JJ_K1_384 = 3
JJ_K2_384 = 5
JJ_Z1_384 = 0x4C2A19F8DDB36C150E97F3A24B81C5E067D094EAB173C58F19A0276EBC3D4915F8E0235B1C8047A6D9E5037F12BCA0E4
JJ_Z2_384 = 0x7B9FA0E2154C638DEF09572630CBA48F176C9D053AE21084F7B0C8D5697A4123E5D810ABCB72FC9034E18605F7CD2491

def _lift_to_jacobian_p384(k, z):
    ax, ay = scalar_mul_oracle(k, "p384")
    z2 = (z * z) % P384_P
    z3 = (z2 * z) % P384_P
    jx = (ax * z2) % P384_P
    jy = (ay * z3) % P384_P
    return jx, jy, z


def setup_point_add_jj_384(transport, labels):
    """Both ec384_p1 and ec384_p2 as full Jacobian with non-trivial Z."""
    jx1, jy1, jz1 = _lift_to_jacobian_p384(JJ_K1_384, JJ_Z1_384)
    jx2, jy2, jz2 = _lift_to_jacobian_p384(JJ_K2_384, JJ_Z2_384)
    ec_p1 = labels["ec384_p1"]
    ec_p2 = labels["ec384_p2"]
    write_bytes(transport, ec_p1 + 0,  int_to_le_bytes(jx1, 48))
    write_bytes(transport, ec_p1 + 48, int_to_le_bytes(jy1, 48))
    write_bytes(transport, ec_p1 + 96, int_to_le_bytes(jz1, 48))
    write_bytes(transport, ec_p2 + 0,  int_to_le_bytes(jx2, 48))
    write_bytes(transport, ec_p2 + 48, int_to_le_bytes(jy2, 48))
    write_bytes(transport, ec_p2 + 96, int_to_le_bytes(jz2, 48))


# --- mod-n multiply operands. fp_mod_mul_n_384 hardcodes ec_n384 at the
# source-text level (src/mod384.s:783, 795). Operand layout is
# fp_src1 (a) * fp_src2 (b) -> fp_dst (LE).
P384_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
MODN_A_384 = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
MODN_B_384 = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
MODN_A_384 %= P384_N
MODN_B_384 %= P384_N


def setup_fp_mod_mul_n_384(transport, labels):
    """Stage fp_src1 = MODN_A_384, fp_src2 = MODN_B_384, fp_dst = fp384_tmp3."""
    write_bytes(transport, labels["fp384_tmp1"], int_to_le_bytes(MODN_A_384, 48))
    write_bytes(transport, labels["fp384_tmp2"], int_to_le_bytes(MODN_B_384, 48))
    set_ptr(transport, labels["fp_src1"], labels["fp384_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp384_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp384_tmp3"])


# Representative 384-bit scalar: P-384 group order minus a small constant.
# Order n = 2**384 - 2**128 - ... (standard P-384 order). Using n - 7 gives a
# near-full-length scalar exercising essentially all 96 comb iterations.
P384_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
SCALAR_MUL_K_384 = P384_ORDER - 7

# Scratch buffer in cassette area (free RAM, won't be touched by point ops).
SCALAR_MUL_BUF_384 = 0x033C


# ----------------------------------------------------------------------------
# Correctness verifiers (oracle gates)
# ----------------------------------------------------------------------------

def _read_le(transport, addr, length):
    return int.from_bytes(read_bytes(transport, addr, length), "little")


def verify_fp_add_384(transport, labels):
    got = _read_le(transport, labels["fp384_tmp3"], 48)
    return got == ((OPERAND_A + OPERAND_B) & ((1 << 384) - 1))


def verify_fp_sub_384(transport, labels):
    got = _read_le(transport, labels["fp384_tmp3"], 48)
    return got == ((OPERAND_A - OPERAND_B) & ((1 << 384) - 1))


def verify_fp_mul_384(transport, labels):
    # fp_mul_384 writes the 96-byte product to fp384_wide, NOT fp_dst.
    got = _read_le(transport, labels["fp384_wide"], 96)
    return got == OPERAND_A * OPERAND_B


def verify_fp_sqr_384(transport, labels):
    got = _read_le(transport, labels["fp384_wide"], 96)
    return got == OPERAND_A * OPERAND_A


def verify_fp_mod_add_384(transport, labels):
    got = _read_le(transport, labels["fp384_tmp3"], 48)
    return got == (OPERAND_A + OPERAND_B) % P384_P


def verify_fp_mod_sub_384(transport, labels):
    got = _read_le(transport, labels["fp384_tmp3"], 48)
    return got == (OPERAND_A - OPERAND_B) % P384_P


def verify_fp_mod_reduce_384(transport, labels):
    got = _read_le(transport, labels["fp384_r0"], 48)
    wide = (OPERAND_A * OPERAND_B) & ((1 << 768) - 1)
    return got == wide % P384_P


def verify_fp_mod_mul_384(transport, labels):
    got = _read_le(transport, labels["fp384_r0"], 48)
    return got == (OPERAND_A * OPERAND_B) % P384_P


def verify_fp_mod_sqr_384(transport, labels):
    got = _read_le(transport, labels["fp384_r0"], 48)
    return got == (OPERAND_A * OPERAND_A) % P384_P


def verify_fp_mod_inv_384(transport, labels):
    got = _read_le(transport, labels["fp384_r0"], 48)
    return got == pow(OPERAND_A, -1, P384_P)


def verify_point_double_384(transport, labels):
    jx = _read_le(transport, labels["ec384_p3"], 48)
    jy = _read_le(transport, labels["ec384_p3"] + 48, 48)
    jz = _read_le(transport, labels["ec384_p3"] + 96, 48)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p384")
    return (ax, ay) == affine_double((GX, GY), "p384")


def verify_point_add_384(transport, labels):
    jx = _read_le(transport, labels["ec384_p3"], 48)
    jy = _read_le(transport, labels["ec384_p3"] + 48, 48)
    jz = _read_le(transport, labels["ec384_p3"] + 96, 48)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p384")
    return (ax, ay) == affine_add((GX, GY), (G2X, G2Y), "p384")


def verify_point_add_jj_384(transport, labels):
    jx = _read_le(transport, labels["ec384_p3"], 48)
    jy = _read_le(transport, labels["ec384_p3"] + 48, 48)
    jz = _read_le(transport, labels["ec384_p3"] + 96, 48)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p384")
    expected = affine_add(scalar_mul_oracle(JJ_K1_384, "p384"),
                          scalar_mul_oracle(JJ_K2_384, "p384"), "p384")
    return (ax, ay) == expected


def verify_fp_mod_mul_n_384(transport, labels):
    got = _read_le(transport, labels["fp384_tmp3"], 48)
    return got == (MODN_A_384 * MODN_B_384) % P384_N


def verify_scalar_mul_384(transport, labels):
    jx = _read_le(transport, labels["ec384_p3"], 48)
    jy = _read_le(transport, labels["ec384_p3"] + 48, 48)
    jz = _read_le(transport, labels["ec384_p3"] + 96, 48)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p384")
    return (ax, ay) == scalar_mul_oracle(SCALAR_MUL_K_384, "p384")


def setup_scalar_mul_384(transport, labels):
    """Write a representative 384-bit scalar (BE) and point ec_scalar_ptr at it."""
    k_be = SCALAR_MUL_K_384.to_bytes(48, "big")
    write_bytes(transport, SCALAR_MUL_BUF_384, k_be)
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_MUL_BUF_384)


# ----------------------------------------------------------------------------
# Benchmark plan
# ----------------------------------------------------------------------------

BENCH_PLAN = [
    ("fp_add_384",           100, setup_field_ab,      verify_fp_add_384,        30.0),
    ("fp_sub_384",           100, setup_field_ab,      verify_fp_sub_384,        30.0),
    ("fp_mul_384",            10, setup_field_ab,      verify_fp_mul_384,       180.0),
    ("fp_sqr_384",            10, setup_field_a,       verify_fp_sqr_384,       180.0),
    ("fp_mod_add_384",       100, setup_field_ab,      verify_fp_mod_add_384,    30.0),
    ("fp_mod_sub_384",       100, setup_field_ab,      verify_fp_mod_sub_384,    30.0),
    ("fp_mod_reduce384",      10, setup_reduce,        verify_fp_mod_reduce_384, 60.0),
    ("fp_mod_mul_384",        10, setup_field_ab,      verify_fp_mod_mul_384,   240.0),
    ("fp_mod_sqr_384",        10, setup_field_a,       verify_fp_mod_sqr_384,   240.0),
    ("fp_mod_inv_384",         1, setup_field_a,       verify_fp_mod_inv_384,   900.0),
    ("bench_fp_mod_mul_n_384_tramp",  5, setup_fp_mod_mul_n_384,
        verify_fp_mod_mul_n_384, 600.0),
    ("ec_point_double_384",    1, setup_point_double,  verify_point_double_384, 300.0),
    ("ec_point_add_384",       1, setup_point_add,     verify_point_add_384,    300.0),
    ("bench_ec_point_add_jj_384_tramp", 1, setup_point_add_jj_384,
        verify_point_add_jj_384, 900.0),
    ("ec_scalar_mul_384",      1, setup_scalar_mul_384, verify_scalar_mul_384, 3600.0),
]


def main():
    _warn_if_vice_running()
    os.chdir(PROJECT_ROOT)

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
        "fp384_tmp1", "fp384_tmp2", "fp384_tmp3", "fp384_wide", "fp384_r0",
        "sqtab_init", "reu_mul_init",
        "bench_start", "bench_stop", "bench_ticks",
        "vic_blank", "vic_unblank",
        "ec_p384", "ec384_p1", "ec384_p2", "ec384_p3",
        "ec_scalar_ptr",
    ]
    required += [name for (name, _l, _s, _v, _t) in BENCH_PLAN]

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

        set_ptr(transport, labels["fp_misc"], labels["ec_p384"])

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

    print()
    title = (f"P-384 Primitive Benchmarks "
             f"(NTSC, 1.02 MHz, VIC blanked, 1 jiffy = "
             f"{NTSC_CYCLES_PER_JIFFY} cycles)")
    bar = "=" * len(title)
    print(bar)
    print(title)
    print(bar)
    hdr = f"{'Routine':<24} {'Loops':>6} {'Jiffies':>9} {'Cycles/call':>13} {'ms/call':>12}"
    print(hdr)
    print("-" * len(bar))
    for name, loops, jiffies, cycles, ms in results:
        print(f"{name:<24} {loops:>6} {jiffies:>9} {cycles:>13} {ms:>12.3f}")
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
