#!/usr/bin/env python3
"""Hammer read_bytes() to look for transient read corruption.

If the byte-mismatch in fp_mod_add is actually a flaky binary-monitor read
(rather than a real arithmetic bug), repeatedly reading the same memory
without changing it should occasionally return wrong bytes.

Procedure:
  1. Init VICE.
  2. Compute fp_mod_add once to put a known value in fp_tmp3.
  3. Read fp_tmp3 N times in a tight loop.
  4. Report any read that disagrees with the first read.
"""

import os
import sys

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


def set_ptr(transport, zp, addr):
    write_bytes(transport, zp, bytes([addr & 0xFF, (addr >> 8) & 0xFF]))


def main():
    n_reads = int(sys.argv[1]) if len(sys.argv) > 1 else 1000

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

        # Write a fixed pattern to fp_tmp3
        pattern = bytes([0xA5, 0x5A] * 16)
        write_bytes(transport, labels["fp_tmp3"], pattern)
        # Verify initial write matches
        first = read_bytes(transport, labels["fp_tmp3"], 32)
        if first != pattern:
            print(f"FAIL: first read != pattern\n  pattern={pattern.hex()}\n  first  ={first.hex()}")

        mismatches = 0
        for i in range(n_reads):
            cur = read_bytes(transport, labels["fp_tmp3"], 32)
            if cur != pattern:
                mismatches += 1
                if mismatches <= 5:
                    diffs = [(j, cur[j], pattern[j]) for j in range(32)
                             if cur[j] != pattern[j]]
                    print(f"  read #{i}: MISMATCH ({len(diffs)} bytes differ)")
                    for j, c, p in diffs[:6]:
                        print(f"    LE[{j}] got={c:02x} expected={p:02x}")

        print(f"\n{mismatches}/{n_reads} reads disagreed with the original pattern.")

        # Now hammer with a MIX of writes + reads of an unrelated address,
        # interleaved with reads of fp_tmp3. This simulates the chaotic
        # request/response pattern in the actual test.
        print("\nNow hammering with mixed write+read pattern...")
        mismatches2 = 0
        for i in range(n_reads):
            # Write a different address (also 32 bytes)
            write_bytes(transport, labels["fp_tmp1"],
                        int_to_le(i & ((1 << 256) - 1)))
            # Read fp_tmp1 to drain
            _ = read_bytes(transport, labels["fp_tmp1"], 32)
            # Now read fp_tmp3 -- should still match pattern
            cur = read_bytes(transport, labels["fp_tmp3"], 32)
            if cur != pattern:
                mismatches2 += 1
                if mismatches2 <= 5:
                    diffs = [(j, cur[j], pattern[j]) for j in range(32)
                             if cur[j] != pattern[j]]
                    print(f"  iter #{i}: MISMATCH ({len(diffs)} bytes differ)")
                    for j, c, p in diffs[:6]:
                        print(f"    LE[{j}] got={c:02x} expected={p:02x}")

        print(f"\n{mismatches2}/{n_reads} interleaved reads disagreed.")

        mgr.release(inst)

    sys.exit(0 if (mismatches + mismatches2) == 0 else 1)


if __name__ == "__main__":
    main()
