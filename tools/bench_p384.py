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

# NTSC C64: ~1.022727 MHz, 17045 cycles per jiffy (1/60 sec).
NTSC_CYCLES_PER_JIFFY = 17045
NTSC_CPU_HZ = NTSC_CYCLES_PER_JIFFY * 60

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
                  timeout=60.0):
    routine_addr = labels[routine_label]
    trampoline = build_loop_trampoline(routine_addr, loops)

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


# ----------------------------------------------------------------------------
# Benchmark plan
# ----------------------------------------------------------------------------

BENCH_PLAN = [
    ("fp_add_384",           100, setup_field_ab,      30.0),
    ("fp_sub_384",           100, setup_field_ab,      30.0),
    ("fp_mul_384",            10, setup_field_ab,     180.0),
    ("fp_sqr_384",            10, setup_field_a,      180.0),
    ("fp_mod_add_384",       100, setup_field_ab,      30.0),
    ("fp_mod_sub_384",       100, setup_field_ab,      30.0),
    ("fp_mod_reduce384",      10, setup_reduce,        60.0),
    ("fp_mod_mul_384",        10, setup_field_ab,     240.0),
    ("fp_mod_sqr_384",        10, setup_field_a,      240.0),
    ("fp_mod_inv_384",         1, setup_field_a,      900.0),
    ("ec_point_double_384",    1, setup_point_double, 300.0),
    ("ec_point_add_384",       1, setup_point_add,    300.0),
]


def main():
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
    ]
    required += [name for (name, _l, _s, _t) in BENCH_PLAN]

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
        while time.time() - start < 180.0:
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
        print("Running benchmarks...")
        results = []
        for name, loops, setup_fn, timeout in BENCH_PLAN:
            print(f"  {name} (x{loops})...", flush=True)
            jiffies, cycles, ms = bench_routine(
                transport, labels, name, loops, setup_fn=setup_fn,
                timeout=timeout)
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
    sys.exit(0)


if __name__ == "__main__":
    main()
