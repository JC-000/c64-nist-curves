#!/usr/bin/env python3
"""diag_fp_mul.py -- isolation timing for fp_mul under VICE.

Boots the standalone PRG, initializes sqtab + reu tables, then JSRs
fp_mul N times with fixed inputs, recording per-call wall-clock between
JSR and the breakpoint hitting back. If timing is uniformly fast the
"timeouts" we see in test_fp256 are not from fp_mul itself; if bimodal
(fast + occasional hang/long), it's a state-residue bug.

Also captures the VICE pid so the parent can spot-check whether VICE is
still alive after a timeout (read_memory still works -> harness lost an
event; VICE dead -> C64-side hang).
"""
from __future__ import annotations

import argparse
import os
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

OPERAND_A = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
OPERAND_B = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def set_ptr(transport, zp_addr, target):
    write_bytes(transport, zp_addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=20,
                    help="number of fp_mul JSRs to time")
    ap.add_argument("--per-call-timeout", type=float, default=10.0,
                    help="per-call timeout (s)")
    args = ap.parse_args()

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: missing {PRG_PATH}")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    print(f"Loaded labels.")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    t_start = time.monotonic()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE pid={inst.pid} port={inst.port}")

        transport = inst.transport

        grid = wait_for_text(transport, "READY.", timeout=600.0, verbose=False)
        if grid is None:
            print("FATAL: VICE did not reach READY")
            mgr.release(inst)
            sys.exit(1)
        print(f"READY at t={time.monotonic()-t_start:.1f}s")

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        t_init0 = time.monotonic()
        jsr(transport, labels["sqtab_init"], timeout=30.0)
        print(f"sqtab_init done: {time.monotonic()-t_init0:.1f}s")

        t_init1 = time.monotonic()
        jsr(transport, labels["reu_mul_init"], timeout=300.0)
        print(f"reu_mul_init done: {time.monotonic()-t_init1:.1f}s")

        # Stage operands
        a_bytes = OPERAND_A.to_bytes(32, "little")
        b_bytes = OPERAND_B.to_bytes(32, "little")
        write_bytes(transport, labels["fp_tmp1"], a_bytes)
        write_bytes(transport, labels["fp_tmp2"], b_bytes)
        set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
        set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])

        timings = []
        first_result = None
        any_failure = False

        for i in range(args.iters):
            t0 = time.monotonic()
            try:
                jsr(transport, labels["fp_mul"], timeout=args.per_call_timeout)
                dt = time.monotonic() - t0
                timings.append(dt)
                if first_result is None:
                    first_result = bytes(read_bytes(transport, labels["fp_wide"], 64))
                    print(f"  iter#{i:02d} dt={dt*1000:.1f}ms first_result_hash="
                          f"{hash(first_result) & 0xffffffff:08x}")
                else:
                    cur = bytes(read_bytes(transport, labels["fp_wide"], 64))
                    same = (cur == first_result)
                    print(f"  iter#{i:02d} dt={dt*1000:.1f}ms same_result={same}")
                    if not same:
                        any_failure = True
            except Exception as e:
                dt = time.monotonic() - t0
                timings.append(dt)
                any_failure = True
                print(f"  iter#{i:02d} FAILED after {dt*1000:.1f}ms: {e!r}")
                # Try to spot-check: is VICE still alive? read a tiny mem region.
                try:
                    sniff = read_bytes(transport, 0x0400, 16)
                    print(f"    POST-FAIL read_bytes($0400, 16)={sniff.hex()} "
                          "(harness still talking to VICE)")
                except Exception as e2:
                    print(f"    POST-FAIL read_bytes RAISED: {e2!r} "
                          "(transport hard-broken)")
                break

        print(f"\nSummary: {len(timings)} iters, "
              f"min={min(timings)*1000:.1f}ms "
              f"max={max(timings)*1000:.1f}ms "
              f"any_failure={any_failure}")

        mgr.release(inst)
    sys.exit(1 if any_failure else 0)


if __name__ == "__main__":
    main()
