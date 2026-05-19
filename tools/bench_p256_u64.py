#!/usr/bin/env python3
"""bench_p256_u64.py -- P-256 primitive benchmarks on Ultimate 64 hardware
across all 16 turbo speeds.

Mirrors `tools/bench_p256.py` (same BENCH_PLAN, same oracle gate) but:

  * Targets Ultimate 64 instead of VICE
  * Installs a monolithic trampoline at $C000 and hijacks `main_loop`
    to drive it (U64 binary monitor has no JSR facility)
  * Full reboot + REU + turbo + run_prg + init-sentinel wait between
    each of the 16 speeds
  * Per-speed oracle correctness gate; mismatch -> UNVERIFIED (cycles
    dropped); 0 jiffies -> SKIP

Usage:
    U64_HOST=192.168.1.81 python3 tools/bench_p256_u64.py
    U64_HOST=192.168.1.81 python3 tools/bench_p256_u64.py --speeds 8
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
    P256_P, affine_add, affine_double,
    jacobian_to_affine, scalar_mul_oracle,
)

from bench_u64_common import (  # noqa: E402
    ALL_SPEEDS, NTSC_CYCLES_PER_JIFFY, NTSC_CPU_HZ,
    Ultimate64Client, Ultimate64Transport, DeviceLock, probe_u64,
    get_turbo_mhz, set_turbo_mhz, set_reu, snapshot_state, restore_state,
    Labels,
    reboot_and_prepare, run_one_routine, park_main_loop,
    set_ptr, write_le, read_le,
    acquire_device_lock_or_exit, liveness_probe,
)

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")


# ---------------------------------------------------------------------------
# Operands / scalars (identical to tools/bench_p256.py)
# ---------------------------------------------------------------------------

OPERAND_A = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
OPERAND_B = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
GX = OPERAND_A
GY = OPERAND_B
G2X = 0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978
G2Y = 0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1

SCALAR_MUL_K = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
SCALAR_MUL_BUF = 0x033C


# ---------------------------------------------------------------------------
# Setup functions (DMA-equivalent versions of the VICE bench setups)
# ---------------------------------------------------------------------------

def setup_field_ab(transport, labels):
    write_le(transport, labels["fp_tmp1"], OPERAND_A, 32)
    write_le(transport, labels["fp_tmp2"], OPERAND_B, 32)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])


def setup_field_a(transport, labels):
    write_le(transport, labels["fp_tmp1"], OPERAND_A, 32)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])


def setup_reduce(transport, labels):
    wide = (OPERAND_A * OPERAND_B) & ((1 << 512) - 1)
    write_le(transport, labels["fp_wide"], wide, 64)


def setup_point_double(transport, labels):
    ec_p1 = labels["ec_p1"]
    write_le(transport, ec_p1 + 0, GX, 32)
    write_le(transport, ec_p1 + 32, GY, 32)
    write_le(transport, ec_p1 + 64, 1, 32)


def setup_point_add(transport, labels):
    setup_point_double(transport, labels)
    ec_p2 = labels["ec_p2"]
    write_le(transport, ec_p2 + 0, G2X, 32)
    write_le(transport, ec_p2 + 32, G2Y, 32)


# --- J+J operands: lifts of (3G, 5G) to Jacobian with non-trivial Z values
# so the J+J formula must execute the Z1*Z2/Z2^2/Z1^2 multiplies it would
# otherwise skip in the mixed (affine-Z2) add path.
JJ_K1 = 3
JJ_K2 = 5
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
    jx1, jy1, jz1 = _lift_to_jacobian_p256(JJ_K1, JJ_Z1)
    jx2, jy2, jz2 = _lift_to_jacobian_p256(JJ_K2, JJ_Z2)
    ec_p1 = labels["ec_p1"]
    ec_p2 = labels["ec_p2"]
    write_le(transport, ec_p1 + 0,  jx1, 32)
    write_le(transport, ec_p1 + 32, jy1, 32)
    write_le(transport, ec_p1 + 64, jz1, 32)
    write_le(transport, ec_p2 + 0,  jx2, 32)
    write_le(transport, ec_p2 + 32, jy2, 32)
    write_le(transport, ec_p2 + 64, jz2, 32)


# --- mod-n multiply operands. fp_mod_mul_n hardcodes ec_n256 at the source
# level; caller only needs to stage fp_src1/fp_src2/fp_dst.
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
MODN_A = OPERAND_A % P256_N
MODN_B = OPERAND_B % P256_N


def setup_fp_mod_mul_n(transport, labels):
    write_le(transport, labels["fp_tmp1"], MODN_A, 32)
    write_le(transport, labels["fp_tmp2"], MODN_B, 32)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])


def setup_scalar_mul(transport, labels):
    k_be = SCALAR_MUL_K.to_bytes(32, "big")
    transport.write_memory(SCALAR_MUL_BUF, k_be)
    set_ptr(transport, labels["ec_scalar_ptr"], SCALAR_MUL_BUF)


# ---------------------------------------------------------------------------
# Verifiers
# ---------------------------------------------------------------------------

def verify_fp_add(t, l):
    return read_le(t, l["fp_tmp3"], 32) == ((OPERAND_A + OPERAND_B) & ((1 << 256) - 1))

def verify_fp_sub(t, l):
    return read_le(t, l["fp_tmp3"], 32) == ((OPERAND_A - OPERAND_B) & ((1 << 256) - 1))

def verify_fp_mul(t, l):
    return read_le(t, l["fp_wide"], 64) == OPERAND_A * OPERAND_B

def verify_fp_sqr(t, l):
    return read_le(t, l["fp_wide"], 64) == OPERAND_A * OPERAND_A

def verify_fp_mod_add(t, l):
    return read_le(t, l["fp_tmp3"], 32) == (OPERAND_A + OPERAND_B) % P256_P

def verify_fp_mod_sub(t, l):
    return read_le(t, l["fp_tmp3"], 32) == (OPERAND_A - OPERAND_B) % P256_P

def verify_fp_mod_reduce(t, l):
    wide = (OPERAND_A * OPERAND_B) & ((1 << 512) - 1)
    return read_le(t, l["fp_r0"], 32) == wide % P256_P

def verify_fp_mod_mul(t, l):
    return read_le(t, l["fp_r0"], 32) == (OPERAND_A * OPERAND_B) % P256_P

def verify_fp_mod_sqr(t, l):
    return read_le(t, l["fp_r0"], 32) == (OPERAND_A * OPERAND_A) % P256_P

def verify_fp_mod_inv(t, l):
    return read_le(t, l["fp_r0"], 32) == pow(OPERAND_A, -1, P256_P)

def verify_point_double(t, l):
    jx = read_le(t, l["ec_p3"], 32)
    jy = read_le(t, l["ec_p3"] + 32, 32)
    jz = read_le(t, l["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    return (ax, ay) == affine_double((GX, GY), "p256")

def verify_point_add(t, l):
    jx = read_le(t, l["ec_p3"], 32)
    jy = read_le(t, l["ec_p3"] + 32, 32)
    jz = read_le(t, l["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    return (ax, ay) == affine_add((GX, GY), (G2X, G2Y), "p256")

def verify_point_add_jj(t, l):
    jx = read_le(t, l["ec_p3"], 32)
    jy = read_le(t, l["ec_p3"] + 32, 32)
    jz = read_le(t, l["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    expected = affine_add(scalar_mul_oracle(JJ_K1, "p256"),
                          scalar_mul_oracle(JJ_K2, "p256"), "p256")
    return (ax, ay) == expected

def verify_fp_mod_mul_n(t, l):
    return read_le(t, l["fp_tmp3"], 32) == (MODN_A * MODN_B) % P256_N

def verify_scalar_mul(t, l):
    jx = read_le(t, l["ec_p3"], 32)
    jy = read_le(t, l["ec_p3"] + 32, 32)
    jz = read_le(t, l["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    return (ax, ay) == scalar_mul_oracle(SCALAR_MUL_K, "p256")


# ---------------------------------------------------------------------------
# Bench plan (base loops at 1 MHz; scaled by mhz per-speed)
# ---------------------------------------------------------------------------

# (name, base_loops_1MHz, setup, verify, per-call_timeout_seconds_at_1MHz)
BENCH_PLAN = [
    ("fp_add",           500, setup_field_ab,     verify_fp_add,         60.0),
    ("fp_sub",           500, setup_field_ab,     verify_fp_sub,         60.0),
    ("fp_mul",            30, setup_field_ab,     verify_fp_mul,        180.0),
    ("fp_sqr",            30, setup_field_a,      verify_fp_sqr,        180.0),
    ("fp_mod_add",       500, setup_field_ab,     verify_fp_mod_add,     60.0),
    ("fp_mod_sub",       500, setup_field_ab,     verify_fp_mod_sub,     60.0),
    ("fp_mod_reduce256", 100, setup_reduce,       verify_fp_mod_reduce, 120.0),
    ("fp_mod_mul",        20, setup_field_ab,     verify_fp_mod_mul,    180.0),
    ("fp_mod_sqr",        20, setup_field_a,      verify_fp_mod_sqr,    180.0),
    ("fp_mod_inv",         1, setup_field_a,      verify_fp_mod_inv,    600.0),
    ("bench_fp_mod_mul_n_tramp",     10, setup_fp_mod_mul_n,
        verify_fp_mod_mul_n,  600.0),
    ("ec_point_double",    1, setup_point_double, verify_point_double,  600.0),
    ("ec_point_add",       1, setup_point_add,    verify_point_add,     900.0),
    ("bench_ec_point_add_jj_tramp",   5, setup_point_add_jj,
        verify_point_add_jj,  900.0),
    ("ec_scalar_mul",      1, setup_scalar_mul,   verify_scalar_mul,   3600.0),
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

    print(f"\n{'='*70}\n  P-256 sweep @ {mhz} MHz\n{'='*70}", flush=True)

    ok = reboot_and_prepare(client, transport, prg_data, mhz,
                            init_timeout=args.init_timeout)
    if not ok:
        return {name: {"ok": False, "jiffies": 0, "cycles": None,
                       "ms": None, "wall": 0.0, "reason": "INIT_TIMEOUT"}
                for (name, *_rest) in BENCH_PLAN}

    # Point fp_misc at the P-256 curve params so modular ops use P.
    set_ptr(transport, labels["fp_misc"], labels["ec_p256"])

    # Park main_loop for a known idle.
    park_main_loop(transport, main_loop)

    speed_results = {}
    for name, base_loops, setup_fn, verify_fn, base_timeout in BENCH_PLAN:
        loops = scaled_loops(base_loops, mhz)
        # timeout scales inversely with mhz (but at least 15 s floor).
        timeout = max(15.0, base_timeout * loops / max(1, base_loops))
        timeout = timeout / mhz   # real wall time shrinks with speed
        timeout = max(15.0, timeout)
        print(f"  {name:<20} loops={loops:<6d} timeout={timeout:6.1f}s ...",
              flush=True, end=" ")
        res = run_one_routine(
            transport, labels, main_loop,
            name, loops, setup_fn, verify_fn, timeout)
        speed_results[name] = res
        tag = res["reason"]
        if res["ok"]:
            print(f"{res['jiffies']:>7d}j  {res['cycles']:>10d}c/call  "
                  f"{res['ms']:>8.3f}ms  [wall {res['wall']:.1f}s]")
        else:
            print(f"{tag:<22}  [wall {res['wall']:.1f}s]")

    return speed_results


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(all_results, speeds):
    print()
    print("=" * 100)
    print("  P-256 U64 Turbo Sweep Summary -- cycles/call (NTSC 1 jiffy = "
          f"{NTSC_CYCLES_PER_JIFFY} cycles)")
    print("=" * 100)

    names = [name for (name, *_rest) in BENCH_PLAN]
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
    print("  P-256 U64 Turbo Sweep Summary -- wall-clock seconds per bench step")
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
    p.add_argument("--speeds", type=str, default=None,
                   help="Comma-separated speeds in MHz. Default: all 16.")
    p.add_argument("--init-timeout", type=float, default=360.0,
                   help="Init sentinel timeout per speed (default 240).")
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

    if args.speeds:
        speeds = [int(s.strip()) for s in args.speeds.split(",")]
    else:
        speeds = list(ALL_SPEEDS)

    print(f"Loading PRG: {args.prg}")
    with open(args.prg, "rb") as f:
        prg_data = f.read()
    print(f"  {len(prg_data)} bytes")

    print(f"Loading labels: {args.labels}")
    labels = Labels.from_file(args.labels)

    required = [
        "main_loop",
        "fp_src1", "fp_src2", "fp_dst", "fp_misc",
        "fp_tmp1", "fp_tmp2", "fp_tmp3", "fp_wide", "fp_r0",
        "bench_ticks", "vic_blank", "vic_unblank",
        "ec_p256", "ec_p1", "ec_p2", "ec_p3", "ec_scalar_ptr",
    ]
    required += [n for (n, *_r) in BENCH_PLAN]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: missing labels: {missing}")
        sys.exit(1)

    print(f"Probing U64 at {host} ...")
    pr = probe_u64(host, password=password)
    if not pr.reachable:
        print(f"FATAL: U64 not reachable: {pr}")
        sys.exit(2)
    print("  reachable (GET-only; writemem health probed post-acquire)")

    lock = acquire_device_lock_or_exit(host)
    try:
        live = liveness_probe(host, password=password)
        if not live.healthy:
            print(f"FATAL: liveness probe failed: {live.summary}")
            if live.recommendation:
                print(f"  recommendation: {live.recommendation}")
            sys.exit(3)
        print(f"  [liveness] {live.summary}")

        client = Ultimate64Client(host=host, password=password, timeout=60.0)
        transport = Ultimate64Transport(host=host, password=password, client=client)
        info = client.get_info()
        print(f"  Connected: {info.get('product', '?')} fw={info.get('firmware_version', '?')}")

        orig_state = snapshot_state(client)
        orig_mhz = get_turbo_mhz(client)
        print(f"  Original turbo: {orig_mhz} MHz" if orig_mhz else "  Original turbo: Off")

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

        elapsed = time.monotonic() - t_start
        print(f"\nTotal sweep wall time: {elapsed/60:.1f} min")
    finally:
        lock.release()

    print_summary(all_results, speeds)


if __name__ == "__main__":
    main()
