#!/usr/bin/env python3
"""bench_reu_mult.py — Isolate the cost of the 128 KB REU multiply table.

Measures, in true 6502 cycles (NTSC, VIC blanked, VICE warp = simulated cycles
are deterministic):

  1. `reu_fetch_mul_row` — pure DMA + setup cost per fetched row (512 B).
  2. `mul_8x8`           — the constant-time quarter-square primitive.
  3. `fp_mul` / `fp_sqr` (P-256) and `fp_mul_384` / `fp_sqr_384` (P-384) —
     full field multiplies, for context (cross-check against bench_p256.py).

From these three, we can compute:

  - DMA cost per row, broken down into setup vs cycle-stolen DMA stall.
  - Per-fp_mul DMA fraction (~32 rows × per-row).
  - Cost of the *alternative* (no-table) implementation that would do
    1024 inline `mul_8x8` calls per fp_mul (32×32 byte products).
  - Speedup ratio of REU table vs naive inline-mul_8x8 alternative.

Loop trampoline uses a nested 8-bit×8-bit counter at $C020/$C021, giving
up to 65 280 iterations per jsr() call. Both micro-benched routines are
constant-time (input-independent), so we do not need to vary operands.

Usage:
    python3 tools/bench_reu_mult.py
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

NTSC_CYCLES_PER_JIFFY = 17045

TRAMPOLINE_ADDR = 0xC000

OPERAND_A_256 = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
OPERAND_B_256 = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
OPERAND_A_384 = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
OPERAND_B_384 = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f


def int_to_le_bytes(val, length):
    return (val & ((1 << (8 * length)) - 1)).to_bytes(length, "little")


def set_ptr(transport, zp_addr, target):
    write_bytes(transport, zp_addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def build_single_loop_trampoline(routine_addr, count):
    """8-bit count, 1..255 iterations. Matches bench_p256.py."""
    assert 1 <= count <= 255
    return bytes([
        0xA9, count & 0xFF,
        0x8D, 0x20, 0xC0,
        0x20, routine_addr & 0xFF, (routine_addr >> 8) & 0xFF,
        0xCE, 0x20, 0xC0,
        0xD0, 0xF8,
        0x60,
    ])


def build_nested_trampoline(routine_addr, outer):
    """Nested 8-bit×8-bit counter: routine is called 256 × outer times.

    Layout (verified offsets):
        00 A9 outer    ; LDA #outer
        02 8D 21 C0    ; STA $C021         (outer counter)
        05 A9 FF       ; LDA #$FF          (outer_top:)
        07 8D 20 C0    ; STA $C020         (reset inner counter)
        0A 20 lo hi    ; JSR routine       (inner_loop:)
        0D CE 20 C0    ; DEC $C020
        10 D0 F8       ; BNE inner_loop    (back 8 bytes to $0A)
        12 CE 21 C0    ; DEC $C021
        15 D0 EE       ; BNE outer_top     (back 18 bytes to $05)
        17 60          ; RTS

    Inner runs 256 iterations (LDA #$FF=255 stores, DEC, BNE), the
    iteration on which DEC produces $00 falls through. So per outer-lap
    the routine is JSR'd exactly 256 times (the $FF→$FE→...→$00 path).
    """
    assert 1 <= outer <= 255
    return bytes([
        0xA9, outer,
        0x8D, 0x21, 0xC0,
        0xA9, 0xFF,
        0x8D, 0x20, 0xC0,
        0x20, routine_addr & 0xFF, (routine_addr >> 8) & 0xFF,
        0xCE, 0x20, 0xC0,
        0xD0, 0xF8,
        0xCE, 0x21, 0xC0,
        0xD0, 0xEE,
        0x60,
    ])


def read_bench_ticks(transport, labels):
    raw = read_bytes(transport, labels["bench_ticks"], 3)
    return (raw[0] << 16) | (raw[1] << 8) | raw[2]


def bench_loop(transport, labels, routine_addr, trampoline, iters_per_call,
               trampoline_calls=1, timeout=120.0):
    """Run `trampoline_calls` invocations of the supplied trampoline
    between bench_start/bench_stop, return (jiffies, cycles_per_iter).
    """
    write_bytes(transport, TRAMPOLINE_ADDR, trampoline)
    jsr(transport, labels["vic_blank"], timeout=5.0)
    jsr(transport, labels["bench_start"], timeout=5.0)
    for _ in range(trampoline_calls):
        jsr(transport, TRAMPOLINE_ADDR, timeout=timeout)
    jsr(transport, labels["bench_stop"], timeout=5.0)
    jsr(transport, labels["vic_unblank"], timeout=5.0)
    jiffies = read_bench_ticks(transport, labels)
    total_cycles = jiffies * NTSC_CYCLES_PER_JIFFY
    total_iters = iters_per_call * trampoline_calls
    return jiffies, total_cycles, total_cycles / total_iters


def main():
    os.chdir(PROJECT_ROOT)

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stdout}\n{result.stderr}")
            sys.exit(1)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)

    required = [
        "reu_fetch_mul_row", "mul_8x8", "mul_cached_a",
        "fp_mul", "fp_sqr", "fp_mul_384", "fp_sqr_384",
        "fp_src1", "fp_src2", "fp_dst",
        "fp_tmp1", "fp_tmp2", "fp_tmp3",
        "bench_start", "bench_stop", "bench_ticks",
        "vic_blank", "vic_unblank",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config,
                             port_range_start=6571,
                             port_range_end=6591) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        # Wait for $02A7 = $42 init sentinel
        print("Waiting for init sentinel...")
        t0 = time.time()
        ok = False
        while time.time() - t0 < 600.0:
            if read_bytes(transport, 0x02A7, 1)[0] == 0x42:
                ok = True
                break
            try:
                transport.resume()
            except Exception:
                pass
            time.sleep(0.5)
        if not ok:
            print("FATAL: init sentinel not set in 600s")
            mgr.release(inst)
            sys.exit(1)
        print(f"Init complete in {time.time() - t0:.1f}s")

        # Safety loop for jsr() return
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # --- 1. reu_fetch_mul_row ---
        # Setup: mul_cached_a = arbitrary nonzero value (cycle count is
        # input-independent, but we want a representative DMA target).
        write_bytes(transport, labels["mul_cached_a"], bytes([0x42]))
        # outer=20 → 5120 iters. Per iter ≈ JSR(6)+body(20)+RTS(6)+DEC(6)+BNE(3)
        # + DMA stall (~512 cy for the 512-byte REU→C64 transfer) ≈ 553 cy.
        # Total ≈ 2.83 M cy ≈ 166 jiffies.
        tramp_reu = build_nested_trampoline(labels["reu_fetch_mul_row"], 20)
        j, total, per_iter = bench_loop(
            transport, labels, labels["reu_fetch_mul_row"],
            tramp_reu, iters_per_call=20 * 256, timeout=60.0)
        reu_per_iter = per_iter
        print(f"reu_fetch_mul_row: {j:5d} jiffies, {total:>9.0f} cy total, "
              f"{per_iter:>7.2f} cy/iter  (5120 calls)")

        # --- 2. mul_8x8 ---
        # Body 86 cy + JSR/RTS 12 + DEC/BNE 9 = 107 cy/iter. outer=20 → 5120
        # iters → ~548 k cy ≈ 32 jiffies.
        tramp_mul = build_nested_trampoline(labels["mul_8x8"], 20)
        j, total, per_iter = bench_loop(
            transport, labels, labels["mul_8x8"],
            tramp_mul, iters_per_call=20 * 256, timeout=60.0)
        mul_per_iter = per_iter
        print(f"mul_8x8          : {j:5d} jiffies, {total:>9.0f} cy total, "
              f"{per_iter:>7.2f} cy/iter  (5120 calls)")

        # --- 3. Noop trampoline overhead baseline ---
        # Time a routine that is "RTS only". We use bench_stop's first
        # instruction-byte trick — wait, we don't have a labelled RTS-only
        # routine. Inject one: write a single $60 (RTS) at trampoline+$40
        # and JSR that.
        noop_addr = TRAMPOLINE_ADDR + 0x40
        write_bytes(transport, noop_addr, bytes([0x60]))
        tramp_noop = build_nested_trampoline(noop_addr, 20)
        j, total, per_iter = bench_loop(
            transport, labels, noop_addr,
            tramp_noop, iters_per_call=20 * 256, timeout=60.0)
        noop_per_iter = per_iter
        print(f"noop (RTS only)  : {j:5d} jiffies, {total:>9.0f} cy total, "
              f"{per_iter:>7.2f} cy/iter  (5120 calls)")

        # Loop overhead = JSR(6)+RTS(6)+DEC(6)+BNE(3) ≈ 21 cy. The measured
        # noop_per_iter should be close to 21 cy + a tiny outer-loop fraction.
        loop_overhead = noop_per_iter

        # --- 4. fp_mul / fp_sqr (P-256) ---
        write_bytes(transport, labels["fp_tmp1"], int_to_le_bytes(OPERAND_A_256, 32))
        write_bytes(transport, labels["fp_tmp2"], int_to_le_bytes(OPERAND_B_256, 32))
        set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
        set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
        set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])
        tramp_fpmul = build_single_loop_trampoline(labels["fp_mul"], 20)
        j, total, per_iter = bench_loop(
            transport, labels, labels["fp_mul"],
            tramp_fpmul, iters_per_call=20, timeout=120.0)
        fp_mul_256 = per_iter
        print(f"fp_mul   (P-256) : {j:5d} jiffies, {total:>9.0f} cy total, "
              f"{per_iter:>8.0f} cy/call (20 calls)")

        # fp_sqr — same operand A.
        set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
        set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])
        tramp_fpsqr = build_single_loop_trampoline(labels["fp_sqr"], 20)
        j, total, per_iter = bench_loop(
            transport, labels, labels["fp_sqr"],
            tramp_fpsqr, iters_per_call=20, timeout=120.0)
        fp_sqr_256 = per_iter
        print(f"fp_sqr   (P-256) : {j:5d} jiffies, {total:>9.0f} cy total, "
              f"{per_iter:>8.0f} cy/call (20 calls)")

        # --- 5. fp_mul_384 / fp_sqr_384 ---
        write_bytes(transport, labels["fp_tmp1"], int_to_le_bytes(OPERAND_A_384, 48))
        write_bytes(transport, labels["fp_tmp2"], int_to_le_bytes(OPERAND_B_384, 48))
        set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
        set_ptr(transport, labels["fp_src2"], labels["fp_tmp2"])
        set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])
        tramp_fpmul384 = build_single_loop_trampoline(labels["fp_mul_384"], 10)
        j, total, per_iter = bench_loop(
            transport, labels, labels["fp_mul_384"],
            tramp_fpmul384, iters_per_call=10, timeout=180.0)
        fp_mul_384 = per_iter
        print(f"fp_mul_384       : {j:5d} jiffies, {total:>9.0f} cy total, "
              f"{per_iter:>8.0f} cy/call (10 calls)")

        set_ptr(transport, labels["fp_src1"], labels["fp_tmp1"])
        set_ptr(transport, labels["fp_dst"], labels["fp_tmp3"])
        tramp_fpsqr384 = build_single_loop_trampoline(labels["fp_sqr_384"], 10)
        j, total, per_iter = bench_loop(
            transport, labels, labels["fp_sqr_384"],
            tramp_fpsqr384, iters_per_call=10, timeout=180.0)
        fp_sqr_384 = per_iter
        print(f"fp_sqr_384       : {j:5d} jiffies, {total:>9.0f} cy total, "
              f"{per_iter:>8.0f} cy/call (10 calls)")

        mgr.release(inst)

    # ------------------------------------------------------------------
    # Derived quantities
    # ------------------------------------------------------------------
    reu_body = reu_per_iter - loop_overhead
    mul_body = mul_per_iter - loop_overhead

    n256 = 32  # bytes per P-256 field element
    n384 = 48

    # If we replaced the REU table with inline mul_8x8 calls:
    #   - DMA cost (32 × reu_body for fp_mul 256) goes away.
    #   - But every byte product (N × N = N^2 lookups, currently ~5 cy each
    #     after the row is in C64 RAM) must instead come from a fresh mul_8x8
    #     call, costing mul_body cy.
    # Rough alternative cost: current fp_mul - (N × reu_body) + (N^2 × (mul_body - 5)).
    # This treats the lookup-vs-mul_8x8 swap as the only delta and ignores
    # second-order effects (accumulator register pressure, etc.).
    LOOKUP_COST_PER_BYTE = 5  # 2 × `lda mul_dma_*,y` ≈ 4 cy + neighbouring overhead

    def naive_alt(measured, n):
        dma_now = n * reu_body
        lookups_now = n * n * LOOKUP_COST_PER_BYTE
        mul8_calls = n * n * mul_body
        return measured - dma_now - lookups_now + mul8_calls

    naive_256 = naive_alt(fp_mul_256, n256)
    naive_384 = naive_alt(fp_mul_384, n384)

    bar = "=" * 78
    print()
    print(bar)
    print("REU multiply table — cost decomposition (measured cycles)")
    print(bar)
    print(f"  reu_fetch_mul_row body (DMA setup + 512-cy stall): {reu_body:7.1f} cy")
    print(f"  mul_8x8           body (constant-time)           : {mul_body:7.1f} cy")
    print(f"  Loop overhead per iter (JSR+RTS+DEC+BNE)         : {loop_overhead:7.1f} cy")
    print()
    print(f"  P-256 fp_mul measured                            : {fp_mul_256:7.0f} cy/call")
    print(f"  P-256 fp_sqr measured                            : {fp_sqr_256:7.0f} cy/call")
    print(f"  P-384 fp_mul measured                            : {fp_mul_384:7.0f} cy/call")
    print(f"  P-384 fp_sqr measured                            : {fp_sqr_384:7.0f} cy/call")
    print()
    print(f"  DMA cost embedded in fp_mul (P-256, 32 rows)     : {32 * reu_body:7.0f} cy "
          f"({100.0 * 32 * reu_body / fp_mul_256:4.1f}% of fp_mul)")
    print(f"  DMA cost embedded in fp_mul (P-384, 48 rows)     : {48 * reu_body:7.0f} cy "
          f"({100.0 * 48 * reu_body / fp_mul_384:4.1f}% of fp_mul)")
    print()
    print(f"  Naïve alt: P-256 fp_mul with 32² inline mul_8x8  : ~{naive_256:7.0f} cy/call")
    print(f"  → REU table speedup vs naïve P-256               : {naive_256 / fp_mul_256:4.2f}×")
    print(f"  Naïve alt: P-384 fp_mul with 48² inline mul_8x8  : ~{naive_384:7.0f} cy/call")
    print(f"  → REU table speedup vs naïve P-384               : {naive_384 / fp_mul_384:4.2f}×")
    print(bar)


if __name__ == "__main__":
    main()
