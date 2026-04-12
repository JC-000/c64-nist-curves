#!/usr/bin/env python3
"""debug_u64_hang.py -- diagnose hangs in U64 monolithic trampoline benching."""
from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from collections import Counter

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))

from bench_u64_common import (
    Ultimate64Client, Ultimate64Transport, DeviceLock, probe_u64,
    set_turbo_mhz, set_reu, snapshot_state, restore_state,
    Labels,
    reboot_and_prepare, park_main_loop, hijack_main_loop,
    build_sweep_trampoline, TRAMPOLINE_ADDR, DONE_SENTINEL_ADDR,
    set_ptr, write_le,
)

from c64_test_harness.backends.u64_debug_capture import DebugCapture
from c64_test_harness.backends.ultimate64_helpers import (
    set_debug_stream_mode, DEBUG_MODE_6510,
)

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

OPERAND_A = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
OPERAND_B = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def _local_ip(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def setup_field_ab(transport, labels):
    write_le(transport, labels["fp_tmp1"], OPERAND_A, 32)
    write_le(transport, labels["fp_tmp2"], OPERAND_B, 32)
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])


def load_symbol_map(labels_path):
    syms = []
    with open(labels_path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "al":
                try:
                    addr = int(parts[1].split(":")[1], 16)
                except Exception:
                    continue
                name = parts[2].lstrip(".")
                syms.append((addr, name))
    syms.sort()
    return syms


def nearest_symbol(syms, addr):
    import bisect
    idx = bisect.bisect_right(syms, (addr, "\xff\xff")) - 1
    if idx < 0:
        return None, 0
    sym_addr, sym_name = syms[idx]
    return sym_name, addr - sym_addr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("routine")
    ap.add_argument("--loops", type=int, default=100)
    ap.add_argument("--capture-seconds", type=float, default=2.0)
    ap.add_argument("--mhz", type=int, default=8)
    ap.add_argument("--init-timeout", type=float, default=360.0)
    ap.add_argument("--skip-reboot", action="store_true",
                    help="Skip reboot (assume PRG already initialized)")
    args = ap.parse_args()

    host = os.environ.get("U64_HOST", "192.168.1.81")
    password = os.environ.get("U64_PASSWORD")

    print(f"Loading PRG: {PRG_PATH}")
    with open(PRG_PATH, "rb") as f:
        prg_data = f.read()

    labels = Labels.from_file(LABELS_PATH)
    syms = load_symbol_map(LABELS_PATH)

    pr = probe_u64(host, password=password)
    if not pr.reachable:
        print(f"FATAL: U64 unreachable: {pr}")
        sys.exit(2)

    local = _local_ip(host)
    print(f"  local IP: {local}")

    lock = DeviceLock(host)
    with lock:
        client = Ultimate64Client(host=host, password=password, timeout=60.0)
        transport = Ultimate64Transport(host=host, password=password, client=client)

        orig_state = snapshot_state(client)
        try:
            if not args.skip_reboot:
                ok = reboot_and_prepare(client, transport, prg_data, args.mhz,
                                        init_timeout=args.init_timeout)
                if not ok:
                    print("FATAL: init sentinel not observed")
                    sys.exit(2)
            else:
                set_turbo_mhz(client, args.mhz)
                time.sleep(0.5)

            set_ptr(transport, labels["fp_misc"], labels["ec_p256"])
            main_loop = labels["main_loop"]
            park_main_loop(transport, main_loop)

            setup_field_ab(transport, labels)

            routine_addr = labels[args.routine]
            print(f"  routine {args.routine} @ ${routine_addr:04x}")

            code = build_sweep_trampoline(
                routine_addr, args.loops,
                bench_ticks_addr=labels["bench_ticks"],
                vic_blank_addr=labels["vic_blank"],
                vic_unblank_addr=labels["vic_unblank"],
                main_loop_addr=main_loop,
                bench_start_addr=labels["bench_start"],
                bench_stop_addr=labels["bench_stop"])
            transport.write_memory(TRAMPOLINE_ADDR, code)
            transport.write_memory(DONE_SENTINEL_ADDR, bytes([0x00]))

            set_debug_stream_mode(client, DEBUG_MODE_6510)

            cap = DebugCapture(port=11002)
            cap.start()
            try:
                client.stream_debug_start(f"{local}:11002")
                time.sleep(0.05)
                hijack_main_loop(transport, main_loop, TRAMPOLINE_ADDR)
                try:
                    transport.resume()
                except Exception:
                    pass
                time.sleep(args.capture_seconds)
            finally:
                try:
                    client.stream_debug_stop()
                except Exception:
                    pass
                time.sleep(0.2)
                result = cap.stop()

            park_main_loop(transport, main_loop)

            done = transport.read_memory(DONE_SENTINEL_ADDR, 1)[0]
            print(f"  done sentinel = ${done:02x}")
            print(f"  capture: cycles={result.total_cycles} "
                  f"packets={result.packets_received} "
                  f"dropped={result.packets_dropped} "
                  f"dur={result.duration_seconds:.2f}s")

            cpu_trace = [c for c in result.trace if c.is_cpu]
            print(f"  CPU cycles: {len(cpu_trace)}")
            if not cpu_trace:
                print("NO CPU CYCLES CAPTURED")
                return

            pc_counter = Counter()
            irq_asserted = 0
            for c in cpu_trace:
                pc_counter[c.address] += 1
                if c.irq:
                    irq_asserted += 1

            total_cpu = max(1, len(cpu_trace))
            print(f"\n  IRQ# asserted: {irq_asserted} / {total_cpu} "
                  f"({100.0 * irq_asserted / total_cpu:.2f}%)")

            print("\n  Top 30 PC addresses:")
            print(f"    {'addr':>6}  {'count':>8}  symbol+offset")
            for addr, cnt in pc_counter.most_common(30):
                name, off = nearest_symbol(syms, addr)
                label = f"{name}+{off}" if name else "?"
                print(f"    ${addr:04x}  {cnt:>8d}  {label}")

            def in_range(lo, hi):
                return sum(v for a, v in pc_counter.items() if lo <= a <= hi)

            print("\n  Region distribution (CPU fetches):")
            print(f"    trampoline  $C000-$C0FF : {in_range(0xC000, 0xC0FF)}")
            print(f"    zero page   $0000-$00FF : {in_range(0x0000, 0x00FF)}")
            print(f"    stack       $0100-$01FF : {in_range(0x0100, 0x01FF)}")
            print(f"    prg area    $0800-$7FFF : {in_range(0x0800, 0x7FFF)}")
            print(f"    BASIC ROM   $A000-$BFFF : {in_range(0xA000, 0xBFFF)}")
            print(f"    KERNAL ROM  $E000-$FFFF : {in_range(0xE000, 0xFFFF)}")

            sym_counter = Counter()
            for addr, cnt in pc_counter.items():
                name, _off = nearest_symbol(syms, addr)
                sym_counter[name or "?"] += cnt
            print("\n  Top 10 symbols by total PC hits:")
            for name, cnt in sym_counter.most_common(10):
                print(f"    {cnt:>8d}  {name}")

        finally:
            try:
                restore_state(client, orig_state)
            except Exception:
                pass
            try:
                transport.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
