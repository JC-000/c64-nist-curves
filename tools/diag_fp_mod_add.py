#!/usr/bin/env python3
"""Deterministic reproducer for fp_mod_add byte-mismatch.

Investigates whether (a + b) % p computed by fp_mod_add deterministically
agrees with Python's oracle, by running the SAME (a, b) pair multiple times
with reads in between.

Strategy:
  * Pick a pair (a, b) drawn once from a fixed seed.
  * Run c64_fp_mod_add(a, b) N times in a row, no other ops between.
  * Compare each result to the Python oracle.
  * If any disagree, dump the underlying fp_add (unreduced) result too.
  * Print which bytes differ.
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


def fp_mod_add_once(transport, labels, a, b):
    write_bytes(transport, labels["fp_tmp1"], int_to_le(a))
    write_bytes(transport, labels["fp_tmp2"], int_to_le(b))
    # Pre-fill destination with sentinel so we can detect lingering bytes.
    write_bytes(transport, labels["fp_tmp3"], bytes([0xCC] * 32))
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])
    set_ptr(transport, labels["fp_misc"], labels["ec_p256"])
    jsr(transport, labels["fp_mod_add"], timeout=10.0)
    raw = read_bytes(transport, labels["fp_tmp3"], 32)
    return raw


def fp_add_once(transport, labels, a, b):
    """Run only the unreduced fp_add and read back the carry+result."""
    write_bytes(transport, labels["fp_tmp1"], int_to_le(a))
    write_bytes(transport, labels["fp_tmp2"], int_to_le(b))
    write_bytes(transport, labels["fp_tmp3"], bytes([0xCC] * 32))
    set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
    set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
    set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])
    jsr(transport, labels["fp_add"], timeout=10.0)
    raw = read_bytes(transport, labels["fp_tmp3"], 32)
    carry = read_bytes(transport, labels["fp_carry"], 1)[0]
    return raw, carry


def diff_report(label, c64_bytes, expected_int):
    got = le_to_int(c64_bytes)
    exp = expected_int
    if got == exp:
        print(f"  {label}: MATCH ({got:#066x})")
        return True
    eb = exp.to_bytes(32, "little")
    diffs = [(i, c64_bytes[i], eb[i]) for i in range(32) if c64_bytes[i] != eb[i]]
    print(f"  {label}: MISMATCH")
    print(f"    got = {got:#066x}")
    print(f"    exp = {exp:#066x}")
    print(f"    {len(diffs)} differing bytes (LE pos | c64 | py | diff):")
    for i, c, e in diffs:
        print(f"      LE[{i:2d}] {c:02x} {e:02x} {c-e:+4d}")
    return False


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 12345
    n_runs = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    n_pairs = int(sys.argv[3]) if len(sys.argv) > 3 else 3

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
        print("Initialising tables (sqtab_init + reu_mul_init, ~2 min)...")
        jsr(transport, labels["sqtab_init"], timeout=30.0)
        jsr(transport, labels["reu_mul_init"], timeout=300.0)
        print("Tables initialised.")

        # Set fp_misc once to ec_p256
        set_ptr(transport, labels["fp_misc"], labels["ec_p256"])

        all_pass = True
        for pair_idx in range(n_pairs):
            # Sample (a, b) in [0, P256)
            while True:
                a = int.from_bytes(bytes(rng.getrandbits(8) for _ in range(32)), "little")
                if a < P256:
                    break
            while True:
                b = int.from_bytes(bytes(rng.getrandbits(8) for _ in range(32)), "little")
                if b < P256:
                    break
            expected = (a + b) % P256
            print(f"\n=== Pair #{pair_idx}: a={a:#066x}\n             b={b:#066x}")
            print(f"     expected (a+b)%p = {expected:#066x}")

            # Run mod_add N times deterministically
            for run in range(n_runs):
                raw = fp_mod_add_once(transport, labels, a, b)
                ok = diff_report(f"mod_add run {run}", raw, expected)
                all_pass &= ok

            # Also run unreduced fp_add and report
            raw_add, carry = fp_add_once(transport, labels, a, b)
            unreduced = (a + b)
            unreduced_low = unreduced & ((1 << 256) - 1)
            unreduced_carry = 1 if unreduced >= (1 << 256) else 0
            ok = diff_report("fp_add (unreduced)", raw_add, unreduced_low)
            print(f"    carry: c64={carry} expected={unreduced_carry}")
            all_pass &= ok and (carry == unreduced_carry)

        mgr.release(inst)

    print("\n" + ("ALL OK" if all_pass else "SOME FAILED"))
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
