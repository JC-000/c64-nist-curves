#!/usr/bin/env python3
"""Diagnostic: does fp_mod_add fail after running fp_mul/fp_sqr first?

The user-facing test_fp_mod_add_sub_inverse only fails some samples, and
re-running with --seed 1 gives different failures, suggesting non-determinism.
But isolated fp_mod_add (diag_fp_mod_add.py) is deterministic + correct.

Theory: the failure is induced by REU state from prior fp_mul/fp_sqr — when
fp_mod_add runs after fp_mul, fp_wide bytes 32..63 may still hold REU residue
(see team task #1: REU register-residue defence). But fp_mod_add doesn't read
fp_wide. So this would not directly cause the issue.

Alternative theory: the failure pattern (~12-20% per run, not deterministic
for a given seed) is environmental — VICE focus-steal corrupting RAM via the
keyboard ISR while the test is running. The keyboard ISR runs at IRQ time
~60Hz and writes into the keyboard buffer at $0277-$0280 and a few zero-page
locations.

This diag exercises the same call-sequence pattern as the failing test:
  for i in range(N):
      sum_ab = fp_mod_add(a, b)         # writes to fp_tmp3, READS BACK
      result = fp_mod_sub(sum_ab, b)    # writes sum_ab back to fp_tmp1
      verify sum_ab == (a+b)%p
      verify result == a
"""

import os
import sys
import random

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))

from c64_test_harness import (  # noqa: E402
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)
from vectors import P256  # noqa: E402

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")


def int_to_le(v, n=32):
    return v.to_bytes(n, "little")


def le_to_int(b):
    return int.from_bytes(b, "little")


def set_ptr(transport, zp, addr):
    write_bytes(transport, zp, bytes([addr & 0xFF, (addr >> 8) & 0xFF]))


def setup_ptrs(transport, labels, src1=None, src2=None, dst=None, misc=None):
    if src1 is not None: set_ptr(transport, labels["fp_src1"], src1)
    if src2 is not None: set_ptr(transport, labels["fp_src2"], src2)
    if dst is not None:  set_ptr(transport, labels["fp_dst"], dst)
    if misc is not None: set_ptr(transport, labels["fp_misc"], misc)


def fp_mod_add(transport, labels, a, b):
    write_bytes(transport, labels["fp_tmp1"], int_to_le(a))
    write_bytes(transport, labels["fp_tmp2"], int_to_le(b))
    setup_ptrs(transport, labels,
               src1=labels["fp_tmp1"], src2=labels["fp_tmp2"], dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_mod_add"], timeout=10.0)
    return le_to_int(read_bytes(transport, labels["fp_tmp3"], 32))


def fp_mod_sub(transport, labels, a, b):
    write_bytes(transport, labels["fp_tmp1"], int_to_le(a))
    write_bytes(transport, labels["fp_tmp2"], int_to_le(b))
    setup_ptrs(transport, labels,
               src1=labels["fp_tmp1"], src2=labels["fp_tmp2"], dst=labels["fp_tmp3"])
    jsr(transport, labels["fp_mod_sub"], timeout=10.0)
    return le_to_int(read_bytes(transport, labels["fp_tmp3"], 32))


def fp_mul(transport, labels, a, b):
    write_bytes(transport, labels["fp_tmp1"], int_to_le(a))
    write_bytes(transport, labels["fp_tmp2"], int_to_le(b))
    setup_ptrs(transport, labels, src1=labels["fp_tmp1"], src2=labels["fp_tmp2"])
    jsr(transport, labels["fp_mul"], timeout=120.0)
    return le_to_int(read_bytes(transport, labels["fp_wide"], 64))


def fp_sqr(transport, labels, a):
    write_bytes(transport, labels["fp_tmp1"], int_to_le(a))
    setup_ptrs(transport, labels, src1=labels["fp_tmp1"])
    jsr(transport, labels["fp_sqr"], timeout=120.0)
    return le_to_int(read_bytes(transport, labels["fp_wide"], 64))


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    n_cases = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    rng = random.Random(seed)

    labels = Labels.from_file(LABELS_PATH)
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        wait_for_text(transport, "READY.", timeout=600.0, verbose=False)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
        print("Init tables...")
        jsr(transport, labels["sqtab_init"], timeout=30.0)
        jsr(transport, labels["reu_mul_init"], timeout=300.0)
        print("Tables ready.")

        set_ptr(transport, labels["fp_misc"], labels["ec_p256"])

        # Run an fp_mul and fp_sqr first to dirty REU/fp_wide -- mirrors the
        # test order where fp_sqr runs immediately before fp_mod_add tests.
        print("\nDirtying REU state via fp_mul/fp_sqr (5 random ops)...")
        for _ in range(5):
            x = int.from_bytes(bytes(rng.getrandbits(8) for _ in range(32)), "little")
            y = int.from_bytes(bytes(rng.getrandbits(8) for _ in range(32)), "little")
            fp_mul(transport, labels, x, y)
            fp_sqr(transport, labels, x)
        print("REU dirty.\n")

        failures = 0
        for i in range(n_cases):
            while True:
                a = int.from_bytes(bytes(rng.getrandbits(8) for _ in range(32)), "little")
                if a < P256:
                    break
            while True:
                b = int.from_bytes(bytes(rng.getrandbits(8) for _ in range(32)), "little")
                if b < P256:
                    break

            sum_c64 = fp_mod_add(transport, labels, a, b)
            sum_py = (a + b) % P256
            roundtrip = fp_mod_sub(transport, labels, sum_c64, b)

            sum_match = (sum_c64 == sum_py)
            rt_match = (roundtrip == a)

            if sum_match and rt_match:
                print(f"  #{i:2d}: ok")
            else:
                failures += 1
                print(f"  #{i:2d}: FAIL  sum_match={sum_match}  rt_match={rt_match}")
                print(f"        a       = {a:#066x}")
                print(f"        b       = {b:#066x}")
                print(f"        sum_c64 = {sum_c64:#066x}")
                print(f"        sum_py  = {sum_py:#066x}")
                print(f"        rt      = {roundtrip:#066x}")

        mgr.release(inst)

    print(f"\n{failures}/{n_cases} cases failed")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
