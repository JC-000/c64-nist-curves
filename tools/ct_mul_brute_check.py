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

    Layout (byte offsets from $C000), canonical §8.3 convention::

        00: AC 22 C0       ldy b_val      <- Y = b (canonical entry)
        03: 20 lo hi       jsr mul_8x8
        06: AE 22 C0       ldx b_val      (mul_8x8 clobbers X and Y)
        09: AD lo hi       lda poly_prod_lo
        0C: 9D 00 C2       sta $C200,x
        0F: AD lo hi       lda poly_prod_hi
        12: 9D 00 C3       sta $C300,x
        15: EE 22 C0       inc b_val
        18: AD 22 C0       lda b_val
        1B: D0 E3          bne -$1D       -> back to $C000
        1D: 60             rts
        1E: (padding to 0x22 below)
        22: 00             b_val (data slot)

    The outer Python loop SMC-bakes the desired ``a`` at the library's
    canonical caller-contract sites (``smc_sum_a_imm+1`` /
    ``smc_diff_a_imm+1``, from labels) and resets b_val at 0x22 before
    each ``jsr SHIM_ADDR``. The shim exits when b_val wraps back to 0
    after 256 iterations.
    """
    def addr2(a: int) -> bytes:
        return bytes([a & 0xFF, (a >> 8) & 0xFF])

    b_val_addr = SHIM_ADDR + 0x22
    code = bytearray(0x23)

    # Canonical ct_mul_8x8 convention (§8.3, adopted 2026-06-19): b in Y,
    # `a` SMC-baked by the CALLER into smc_sum_a_imm+1 / smc_diff_a_imm+1
    # — the Python outer loop pokes those two library addresses per a.
    # (The previous shim used the pre-§8.3 register entry A=a / X=b; with
    # the canonical body that computed stale-bake garbage — issue #71
    # collateral fix. mul_8x8 itself was correct all along.)
    # 00: ldy b_val ; Y = current b
    code[0x00:0x03] = b"\xAC" + addr2(b_val_addr)
    # 03: jsr mul_8x8
    code[0x03:0x06] = b"\x20" + addr2(mul_addr)
    # 06: ldx b_val   (mul_8x8 clobbers X and Y)
    code[0x06:0x09] = b"\xAE" + addr2(b_val_addr)
    # 09: lda poly_prod_lo
    code[0x09:0x0C] = b"\xAD" + addr2(prod_lo)
    # 0C: sta $C200,x
    code[0x0C:0x0F] = b"\x9D" + addr2(RESULTS_LO)
    # 0F: lda poly_prod_hi
    code[0x0F:0x12] = b"\xAD" + addr2(prod_hi)
    # 12: sta $C300,x
    code[0x12:0x15] = b"\x9D" + addr2(RESULTS_HI)
    # 15: inc b_val
    code[0x15:0x18] = b"\xEE" + addr2(b_val_addr)
    # 18: lda b_val
    code[0x18:0x1B] = b"\xAD" + addr2(b_val_addr)
    # 1B: bne back
    #    After the bne (PC = SHIM_ADDR+0x1D), branching to $C000 (SHIM_ADDR+0x00)
    #    needs offset 0x00 - 0x1D = -0x1D = 0xE3.
    code[0x1B:0x1D] = b"\xD0\xE3"
    # 1D: rts
    code[0x1D:0x1E] = b"\x60"
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
        smc_sum = labels["smc_sum_a_imm"]
        smc_diff = labels["smc_diff_a_imm"]
        for a in range(256):
            # SMC-bake `a` at the canonical library sites (caller contract).
            write_bytes(transport, smc_sum + 1, bytes([a]))
            write_bytes(transport, smc_diff + 1, bytes([a]))
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
