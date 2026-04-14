#!/usr/bin/env python3
"""Brute-force correctness check for the constant-time ``mul_8x8``.

Tests all 65 536 ``(a, b)`` pairs in ``[0,255]^2`` against the Python
reference ``a * b`` and asserts byte-equality of the 16-bit result in
``poly_prod_lo`` / ``poly_prod_hi``.

Background: issue #14 (Option B) replaced the old `mul_8x8` body with a
constant-time implementation ported from c64-ChaCha20-Poly1305 v0.3.0's
``ct_mul_8x8``. The old body had two secret-dependent branches; the new
body uses a sign-mask trick for ``|a-b|`` and SMC-patched ``abs,x`` loads
for the sum-page dispatch. This script exercises every ``(a, b)`` pair
and proves functional correctness.

It does NOT assert timing — that's a separate CT contract established by
code inspection (the routine has no conditional branches; all table loads
use page-aligned bases with X, Y in ``[0, 255]``). See the header comment
in ``src/mul_8x8.s`` for the CT analysis.

Usage::

    python3 tools/ct_mul_brute_check.py

Expects ``build/nist-curves.prg`` to exist (run ``make`` first). Uses a
256-byte batch shim at ``$C000`` that loops ``b = 0..255`` calling
``mul_8x8`` once per ``b`` with the current ``a`` SMC-baked into an
``lda #imm`` inside the shim. Results stream to ``$C200`` (lo) and
``$C300`` (hi). The whole sweep is 256 VICE round-trips (one per ``a``)
instead of 65 536.
"""

from __future__ import annotations

import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

from c64_test_harness import (  # noqa: E402
    Labels,
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
)

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

SHIM_ADDR = 0xC000
RESULTS_LO = 0xC200
RESULTS_HI = 0xC300


def build_shim(mul_addr: int, prod_lo: int, prod_hi: int) -> bytes:
    """Assemble the 256-``b`` tight loop at ``$C000``.

    Layout (byte offsets from $C000)::

        00: A9 00          lda #$00       <- a_imm, SMC-patched per outer a
        02: A2 00          ldx #$00       <- b_val
        04: 20 lo hi       jsr mul_8x8
        07: AE 22 C0       ldx b_val
        0A: AD lo hi       lda poly_prod_lo
        0D: 9D 00 C2       sta $C200,x
        10: AD lo hi       lda poly_prod_hi
        13: 9D 00 C3       sta $C300,x
        16: EE 22 C0       inc b_val
        19: AD 22 C0       lda b_val
        1C: D0 E2          bne -$1E       -> back to $C000 (SMC a_imm preserved)
        1E: 60             rts
        1F: 00             padding
        20: (unused, aligned to 0x22 below)
        22: 00             b_val (data slot)

    The outer Python loop pokes the desired ``a`` into offset 0x01 (the
    immediate byte of the leading ``lda #$00``) and b_val at 0x22 back
    to zero before each ``jsr SHIM_ADDR``. The shim exits when b_val
    wraps back to 0 after 256 iterations.
    """
    def addr2(a: int) -> bytes:
        return bytes([a & 0xFF, (a >> 8) & 0xFF])

    b_val_addr = SHIM_ADDR + 0x22
    code = bytearray(0x23)

    # 00: lda #$00  ; a immediate (SMC-patched)
    code[0x00:0x02] = b"\xA9\x00"
    # 02: ldx b_val ; X = current b
    code[0x02:0x05] = b"\xAE" + addr2(b_val_addr)
    # 05: jsr mul_8x8
    code[0x05:0x08] = b"\x20" + addr2(mul_addr)
    # 08: ldx b_val   (mul_8x8 clobbered X)
    code[0x08:0x0B] = b"\xAE" + addr2(b_val_addr)
    # 0B: lda poly_prod_lo
    code[0x0B:0x0E] = b"\xAD" + addr2(prod_lo)
    # 0E: sta $C200,x
    code[0x0E:0x11] = b"\x9D" + addr2(RESULTS_LO)
    # 11: lda poly_prod_hi
    code[0x11:0x14] = b"\xAD" + addr2(prod_hi)
    # 14: sta $C300,x
    code[0x14:0x17] = b"\x9D" + addr2(RESULTS_HI)
    # 17: inc b_val
    code[0x17:0x1A] = b"\xEE" + addr2(b_val_addr)
    # 1A: lda b_val
    code[0x1A:0x1D] = b"\xAD" + addr2(b_val_addr)
    # 1D: bne back
    #    After the bne (PC = SHIM_ADDR+0x1F), branching to $C000 (SHIM_ADDR+0x00)
    #    needs offset 0x00 - 0x1F = -0x1F = 0xE1.
    code[0x1D:0x1F] = b"\xD0\xE1"
    # 1F: rts
    code[0x1F:0x20] = b"\x60"
    # 22: b_val
    code[0x22:0x23] = b"\x00"
    return bytes(code)


def main() -> int:
    labels = Labels.from_file(LABELS_PATH)
    mul_addr = labels["mul_8x8"]
    prod_lo = labels["poly_prod_lo"]
    prod_hi = labels["poly_prod_hi"]

    print(f"mul_8x8       = ${mul_addr:04x}")
    print(f"poly_prod_lo  = ${prod_lo:04x}")
    print(f"poly_prod_hi  = ${prod_hi:04x}")

    shim = build_shim(mul_addr, prod_lo, prod_hi)

    cfg = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
        extra_args=["-reu", "-reusize", "512"],
    )

    t_start = time.time()
    with ViceInstanceManager(
        config=cfg,
        port_range_start=6591,
        port_range_end=6611,
    ) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        # Wait for init sentinel (sqtab + REU mul table + precompute tables done).
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
            return 1
        print(f"Init complete after {time.time() - start:.1f}s")

        # Plant shim at $C000.
        write_bytes(transport, SHIM_ADDR, shim)

        mismatches = 0
        max_report = 8
        total = 0
        for a in range(256):
            # SMC-bake `a` into the shim's leading lda-immediate (offset 0x01).
            write_bytes(transport, SHIM_ADDR + 0x01, bytes([a]))
            # Reset b_val = 0.
            write_bytes(transport, SHIM_ADDR + 0x22, bytes([0]))

            # Run the 256-b inner sweep.
            jsr(transport, SHIM_ADDR, timeout=10.0)

            lo = read_bytes(transport, RESULTS_LO, 256)
            hi = read_bytes(transport, RESULTS_HI, 256)

            for b in range(256):
                expected = a * b
                got = lo[b] | (hi[b] << 8)
                total += 1
                if got != expected:
                    mismatches += 1
                    if mismatches <= max_report:
                        print(
                            f"MISMATCH a={a:3d} b={b:3d}: "
                            f"expected ${expected:04x}, got ${got:04x}"
                        )
            if (a + 1) % 32 == 0:
                elapsed = time.time() - t_start
                print(f"  a={a + 1:3d}/256 ({elapsed:.1f}s, {mismatches} mismatches)")

        mgr.release(inst)

    elapsed = time.time() - t_start
    print("=" * 60)
    print(f"Total pairs checked: {total}")
    print(f"Mismatches: {mismatches}")
    print(f"Elapsed: {elapsed:.1f}s")
    if mismatches == 0:
        print("RESULT: mul_8x8 PASS (65536/65536)")
        return 0
    print("RESULT: mul_8x8 FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
