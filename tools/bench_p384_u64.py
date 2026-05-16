#!/usr/bin/env python3
"""bench_p384_u64.py -- P-384 primitive benchmarks on Ultimate 64 hardware
across all 16 turbo speeds. Mirrors tools/bench_p384.py but targets U64.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))

from tools.vectors import (  # noqa: E402
    P384_P, affine_add, affine_double,
    jacobian_to_affine, scalar_mul_oracle,
)

from bench_u64_common import (  # noqa: E402
    ALL_SPEEDS, NTSC_CYCLES_PER_JIFFY, NTSC_CPU_HZ,
    Ultimate64Client, Ultimate64Transport, DeviceLock, probe_u64,
    get_turbo_mhz, set_turbo_mhz, set_reu, snapshot_state, restore_state,
    Labels,
    reboot_and_prepare, run_one_routine, park_main_loop,
    set_ptr, write_le, read_le,
    acquire_device_lock_or_exit, writemem_health_probe,
)

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")


# ---------------------------------------------------------------------------
# Operands / scalars
# ---------------------------------------------------------------------------

OPERAND_A = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
OPERAND_B = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
GX = OPERAND_A
GY = OPERAND_B
G2X = 0x08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61
G2Y = 0x8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80

P384_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
SCALAR_MUL_K = P384_ORDER - 7
SCALAR_MUL_BUF = 0x033C


def setup_field_ab(t, l):
    write_le(t, l["fp384_tmp1"], OPERAND_A, 48)
    write_le(t, l["fp384_tmp2"], OPERAND_B, 48)
    set_ptr(t, l["fp_src1"], l["fp384_tmp1"])
    set_ptr(t, l["fp_src2"], l["fp384_tmp2"])
    set_ptr(t, l["fp_dst"], l["fp384_tmp3"])


def setup_field_a(t, l):
    write_le(t, l["fp384_tmp1"], OPERAND_A, 48)
    set_ptr(t, l["fp_src1"], l["fp384_tmp1"])
    set_ptr(t, l["fp_dst"], l["fp384_tmp3"])


def setup_reduce(t, l):
    wide = (OPERAND_A * OPERAND_B) & ((1 << 768) - 1)
    write_le(t, l["fp384_wide"], wide, 96)


def setup_point_double(t, l):
    ec = l["ec384_p1"]
    write_le(t, ec + 0, GX, 48)
    write_le(t, ec + 48, GY, 48)
    write_le(t, ec + 96, 1, 48)


def setup_point_add(t, l):
    setup_point_double(t, l)
    ec = l["ec384_p2"]
    write_le(t, ec + 0, G2X, 48)
    write_le(t, ec + 48, G2Y, 48)


def setup_scalar_mul(t, l):
    k_be = SCALAR_MUL_K.to_bytes(48, "big")
    t.write_memory(SCALAR_MUL_BUF, k_be)
    set_ptr(t, l["ec_scalar_ptr"], SCALAR_MUL_BUF)


def verify_fp_add(t, l):
    return read_le(t, l["fp384_tmp3"], 48) == ((OPERAND_A + OPERAND_B) & ((1 << 384) - 1))

def verify_fp_sub(t, l):
    return read_le(t, l["fp384_tmp3"], 48) == ((OPERAND_A - OPERAND_B) & ((1 << 384) - 1))

def verify_fp_mul(t, l):
    return read_le(t, l["fp384_wide"], 96) == OPERAND_A * OPERAND_B

def verify_fp_sqr(t, l):
    return read_le(t, l["fp384_wide"], 96) == OPERAND_A * OPERAND_A

def verify_fp_mod_add(t, l):
    return read_le(t, l["fp384_tmp3"], 48) == (OPERAND_A + OPERAND_B) % P384_P

def verify_fp_mod_sub(t, l):
    return read_le(t, l["fp384_tmp3"], 48) == (OPERAND_A - OPERAND_B) % P384_P

def verify_fp_mod_reduce(t, l):
    wide = (OPERAND_A * OPERAND_B) & ((1 << 768) - 1)
    return read_le(t, l["fp384_r0"], 48) == wide % P384_P

def verify_fp_mod_mul(t, l):
    return read_le(t, l["fp384_r0"], 48) == (OPERAND_A * OPERAND_B) % P384_P

def verify_fp_mod_sqr(t, l):
    return read_le(t, l["fp384_r0"], 48) == (OPERAND_A * OPERAND_A) % P384_P

def verify_fp_mod_inv(t, l):
    return read_le(t, l["fp384_r0"], 48) == pow(OPERAND_A, -1, P384_P)

def verify_point_double(t, l):
    jx = read_le(t, l["ec384_p3"], 48)
    jy = read_le(t, l["ec384_p3"] + 48, 48)
    jz = read_le(t, l["ec384_p3"] + 96, 48)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p384")
    return (ax, ay) == affine_double((GX, GY), "p384")

def verify_point_add(t, l):
    jx = read_le(t, l["ec384_p3"], 48)
    jy = read_le(t, l["ec384_p3"] + 48, 48)
    jz = read_le(t, l["ec384_p3"] + 96, 48)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p384")
    return (ax, ay) == affine_add((GX, GY), (G2X, G2Y), "p384")

def verify_scalar_mul(t, l):
    jx = read_le(t, l["ec384_p3"], 48)
    jy = read_le(t, l["ec384_p3"] + 48, 48)
    jz = read_le(t, l["ec384_p3"] + 96, 48)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p384")
    return (ax, ay) == scalar_mul_oracle(SCALAR_MUL_K, "p384")


BENCH_PLAN = [
    ("fp_add_384",           500, setup_field_ab,      verify_fp_add,         60.0),
    ("fp_sub_384",           500, setup_field_ab,      verify_fp_sub,         60.0),
    ("fp_mul_384",            20, setup_field_ab,      verify_fp_mul,        240.0),
    ("fp_sqr_384",            20, setup_field_a,       verify_fp_sqr,        240.0),
    ("fp_mod_add_384",       500, setup_field_ab,      verify_fp_mod_add,     60.0),
    ("fp_mod_sub_384",       500, setup_field_ab,      verify_fp_mod_sub,     60.0),
    ("fp_mod_reduce384",      50, setup_reduce,        verify_fp_mod_reduce, 120.0),
    ("fp_mod_mul_384",        20, setup_field_ab,      verify_fp_mod_mul,    240.0),
    ("fp_mod_sqr_384",        20, setup_field_a,       verify_fp_mod_sqr,    240.0),
    ("fp_mod_inv_384",         1, setup_field_a,       verify_fp_mod_inv,    900.0),
    ("ec_point_double_384",    1, setup_point_double,  verify_point_double,  300.0),
    ("ec_point_add_384",       1, setup_point_add,     verify_point_add,     300.0),
    ("ec_scalar_mul_384",      1, setup_scalar_mul,    verify_scalar_mul,  3600.0),
]

LOOP_CAP = 20000


def scaled_loops(base, mhz):
    # Long routines (base==1) keep loops=1 across all speeds; even at
    # 48 MHz they run for many jiffies. Short routines scale linearly
    # with mhz so the per-call timing stays well above the jiffy floor.
    if base <= 1:
        return 1
    return max(1, min(LOOP_CAP, base * mhz))


def run_sweep_for_speed(client, transport, prg_data, labels, mhz, args):
    main_loop = labels["main_loop"]

    print(f"\n{'='*70}\n  P-384 sweep @ {mhz} MHz\n{'='*70}", flush=True)

    ok = reboot_and_prepare(client, transport, prg_data, mhz,
                            init_timeout=args.init_timeout)
    if not ok:
        return {name: {"ok": False, "jiffies": 0, "cycles": None,
                       "ms": None, "wall": 0.0, "reason": "INIT_TIMEOUT"}
                for (name, *_rest) in BENCH_PLAN}

    set_ptr(transport, labels["fp_misc"], labels["ec_p384"])
    park_main_loop(transport, main_loop)

    speed_results = {}
    for name, base_loops, setup_fn, verify_fn, base_timeout in BENCH_PLAN:
        loops = scaled_loops(base_loops, mhz)
        timeout = max(15.0, base_timeout * loops / max(1, base_loops) / mhz)
        timeout = max(15.0, timeout)
        print(f"  {name:<22} loops={loops:<6d} timeout={timeout:6.1f}s ...",
              flush=True, end=" ")
        res = run_one_routine(
            transport, labels, main_loop,
            name, loops, setup_fn, verify_fn, timeout)
        speed_results[name] = res
        if res["ok"]:
            print(f"{res['jiffies']:>7d}j  {res['cycles']:>10d}c/call  "
                  f"{res['ms']:>8.3f}ms  [wall {res['wall']:.1f}s]")
        else:
            print(f"{res['reason']:<22}  [wall {res['wall']:.1f}s]")

    return speed_results


def print_summary(all_results, speeds):
    print()
    print("=" * 100)
    print("  P-384 U64 Turbo Sweep Summary -- cycles/call (NTSC 1 jiffy = "
          f"{NTSC_CYCLES_PER_JIFFY} cycles)")
    print("=" * 100)
    names = [name for (name, *_r) in BENCH_PLAN]
    hdr = f"  {'Routine':<22}"
    for mhz in speeds:
        hdr += f" {mhz:>8d}"
    print(hdr)
    print("  " + "-" * (22 + 9 * len(speeds)))
    for name in names:
        row = f"  {name:<22}"
        for mhz in speeds:
            res = all_results.get(mhz, {}).get(name)
            if res is None or not res["ok"]:
                reason = res["reason"] if res else "-"
                short = {"UNVERIFIED": "UNVRF", "SKIP(0 jiffies)": "SKIP0",
                         "TIMEOUT": "T/O", "INIT_TIMEOUT": "INIT"}.get(reason, "-")
                row += f" {short:>8}"
            else:
                row += f" {res['cycles']:>8d}"
        print(row)

    print()
    print("=" * 100)
    print("  P-384 U64 Turbo Sweep Summary -- wall-clock seconds per step")
    print("=" * 100)
    hdr = f"  {'Routine':<22}"
    for mhz in speeds:
        hdr += f" {mhz:>8d}"
    print(hdr)
    print("  " + "-" * (22 + 9 * len(speeds)))
    for name in names:
        row = f"  {name:<22}"
        for mhz in speeds:
            res = all_results.get(mhz, {}).get(name)
            if res is None:
                row += f" {'-':>8}"
            else:
                row += f" {res['wall']:>7.1f}s"
        print(row)
    print("=" * 100)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--speeds", type=str, default=None)
    p.add_argument("--init-timeout", type=float, default=360.0)
    p.add_argument("--prg", type=str, default=PRG_PATH)
    p.add_argument("--labels", type=str, default=LABELS_PATH)
    return p.parse_args()


def main():
    args = parse_args()

    host = os.environ.get("U64_HOST")
    if not host:
        print("ERROR: set U64_HOST=<ip>")
        sys.exit(2)
    password = os.environ.get("U64_PASSWORD")

    speeds = ([int(s.strip()) for s in args.speeds.split(",")]
              if args.speeds else list(ALL_SPEEDS))

    print(f"Loading PRG: {args.prg}")
    with open(args.prg, "rb") as f:
        prg_data = f.read()
    print(f"  {len(prg_data)} bytes")

    print(f"Loading labels: {args.labels}")
    labels = Labels.from_file(args.labels)

    required = [
        "main_loop",
        "fp_src1", "fp_src2", "fp_dst", "fp_misc",
        "fp384_tmp1", "fp384_tmp2", "fp384_tmp3", "fp384_wide", "fp384_r0",
        "bench_ticks", "vic_blank", "vic_unblank",
        "ec_p384", "ec384_p1", "ec384_p2", "ec384_p3", "ec_scalar_ptr",
    ]
    required += [n for (n, *_r) in BENCH_PLAN]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: missing labels: {missing}")
        sys.exit(1)

    print(f"Probing U64 at {host} ...")
    pr = probe_u64(host, password=password)
    if not pr.reachable:
        print(f"FATAL: {pr}")
        sys.exit(2)
    print("  reachable (GET-only; writemem health probed post-acquire)")

    lock = acquire_device_lock_or_exit(host)
    try:
        ok, reason = writemem_health_probe(host, password=password)
        if not ok:
            print(f"FATAL: writemem health probe failed: {reason}")
            sys.exit(3)
        print(f"  [writemem] {reason}")

        client = Ultimate64Client(host=host, password=password, timeout=60.0)
        transport = Ultimate64Transport(host=host, password=password, client=client)
        info = client.get_info()
        print(f"  Connected: {info.get('product','?')} fw={info.get('firmware_version','?')}")

        orig_state = snapshot_state(client)

        all_results = {}
        t_start = time.monotonic()
        try:
            for mhz in speeds:
                all_results[mhz] = run_sweep_for_speed(
                    client, transport, prg_data, labels, mhz, args)
        except KeyboardInterrupt:
            print("\n[interrupted]")
        finally:
            try:
                restore_state(client, orig_state)
            except Exception as e:
                print(f"WARN: restore_state failed: {e}")
            try:
                transport.close()
            except Exception:
                pass

        print(f"\nTotal sweep wall time: {(time.monotonic()-t_start)/60:.1f} min")
    finally:
        lock.release()

    print_summary(all_results, speeds)


if __name__ == "__main__":
    main()
