#!/usr/bin/env python3
"""bench_ecdsa_u64.py -- Per-primitive cycle benchmarks for ECDSA verify and
variable-base scalar multiplication on Ultimate 64 Elite hardware.

Measures four primitives at 16 MHz and 48 MHz:

  1. ec_scalar_mul_var        (P-256 variable-base scalar multiplication,
                                 non-constant-time, ECDSA verify step)
  2. ec_scalar_mul_var_384    (P-384 variable-base scalar multiplication)
  3. ecdsa_verify_256         (full ECDSA-P256 verify; exercises one
                                 ec_scalar_mul AND one ec_scalar_mul_var)
  4. ecdsa_verify_384         (full ECDSA-P384 verify)

Timing source:

  * Primary: the existing jiffy-clock pattern used by tools/bench_p256_u64.py
    and tools/bench_p384_u64.py (CIA1 TOD via bench_start / bench_stop).
    Jiffy granularity is 17045 cycles per tick; the targets take millions
    of cycles so sub-jiffy precision is not meaningful.

  * Secondary (optional, cross-check): the Ultimate 64 Elite cycle-accurate
    debug bus-stream over UDP:11002.  The bench trampolines in src/main.s
    write a marker byte to $BFFF immediately before and after the measured
    routine (see src/main.s `bench_*_tramp`).  DebugCapture filters those
    writes out of the bus trace and reports the exact cycle delta between
    start-marker and stop-marker.  The jiffy count is still reported as
    the primary number; the debug-stream number is reported next to it
    for sanity-check.  Set BENCH_DEBUG_STREAM=1 to enable the debug-stream
    capture (it's opt-in because it allocates ~32 Mbps of UDP traffic for
    the duration of the capture).

Usage:
    U64_HOST=192.168.1.81 python3 tools/bench_ecdsa_u64.py
    U64_HOST=192.168.1.81 BENCH_DEBUG_STREAM=1 python3 tools/bench_ecdsa_u64.py
    U64_HOST=192.168.1.81 python3 tools/bench_ecdsa_u64.py --speeds 16,48

If U64_HOST is unset or the device is not reachable the tool exits with a
clear message and leaves no artifacts on the network.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))

from tools.vectors import (  # noqa: E402
    jacobian_to_affine, scalar_mul_oracle,
)

from bench_u64_common import (  # noqa: E402
    ALL_SPEEDS, NTSC_CYCLES_PER_JIFFY, NTSC_CPU_HZ,
    Ultimate64Client, Ultimate64Transport, DeviceLock, probe_u64,
    get_turbo_mhz, set_turbo_mhz, set_reu, snapshot_state, restore_state,
    Labels,
    reboot_and_prepare, run_one_routine, park_main_loop,
    set_ptr, write_le, read_le,
)

try:
    from c64_test_harness.backends.u64_debug_capture import (
        DebugCapture, DEFAULT_DEBUG_PORT,
    )
    from c64_test_harness.backends.ultimate64_helpers import (
        set_debug_stream_mode, set_stream_destination, DEBUG_MODE_6510,
    )
    _DEBUG_CAPTURE_OK = True
except Exception:
    _DEBUG_CAPTURE_OK = False


PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")


# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------

# RFC 6979 A.2.5 -- P-256, SHA-256, message "sample"
RFC6979_P256 = {
    "msg": b"sample",
    "d":  0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
    "Ux": 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
    "Uy": 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299,
    "r":  0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
    "s":  0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8,
}

# RFC 6979 A.3.1 -- P-384, SHA-384, message "sample"
RFC6979_P384 = {
    "msg": b"sample",
    "d":  0x6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5,
    "Ux": 0xEC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13,
    "Uy": 0x8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720,
    "r":  0x94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46,
    "s":  0x99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8,
}

# A non-trivial scalar used for the variable-base scalar_mul_var benches.
# We use the RFC 6979 A.2.5 (resp. A.3.1) signer's private key `d` so that
# the oracle gate compares against `scalar_mul_oracle(d, curve)`.
SCALAR_MUL_VAR_256_K = RFC6979_P256["d"]
SCALAR_MUL_VAR_384_K = RFC6979_P384["d"]

# Base points for scalar_mul_var: use the P-256 / P-384 generator G.
from tools.vectors.constants import GX256, GY256, GX384, GY384  # noqa: E402
SCALAR_MUL_VAR_256_BX = GX256
SCALAR_MUL_VAR_256_BY = GY256
SCALAR_MUL_VAR_384_BX = GX384
SCALAR_MUL_VAR_384_BY = GY384

# Scratch buffer in BASIC input-buffer area for BE scalars.
SCALAR_BUF_256 = 0x033C   # 32 BE bytes
SCALAR_BUF_384 = 0x035C   # 48 BE bytes


# ---------------------------------------------------------------------------
# Setup functions
# ---------------------------------------------------------------------------

def _pack_verify_struct_256(r, s, h_bytes, qx, qy):
    """Pack r|s|h|Qx|Qy as 5x32 BE bytes."""
    payload = (r.to_bytes(32, "big") + s.to_bytes(32, "big")
               + int.from_bytes(h_bytes, "big").to_bytes(32, "big")
               + qx.to_bytes(32, "big") + qy.to_bytes(32, "big"))
    assert len(payload) == 160
    return payload


def _pack_verify_struct_384(r, s, h_bytes, qx, qy):
    """Pack r|s|h|Qx|Qy as 5x48 BE bytes."""
    payload = (r.to_bytes(48, "big") + s.to_bytes(48, "big")
               + int.from_bytes(h_bytes, "big").to_bytes(48, "big")
               + qx.to_bytes(48, "big") + qy.to_bytes(48, "big"))
    assert len(payload) == 240
    return payload


def setup_scalar_mul_var_256(t, l):
    """Stage k and point ec_base_{x,y} at G for the P-256 scalar_mul_var."""
    k_be = SCALAR_MUL_VAR_256_K.to_bytes(32, "big")
    t.write_memory(SCALAR_BUF_256, k_be)
    set_ptr(t, l["ec_scalar_ptr"], SCALAR_BUF_256)
    write_le(t, l["ec_base_x"], SCALAR_MUL_VAR_256_BX, 32)
    write_le(t, l["ec_base_y"], SCALAR_MUL_VAR_256_BY, 32)


def setup_scalar_mul_var_384(t, l):
    """Stage k and point ec_base384_{x,y} at G for the P-384 scalar_mul_var."""
    k_be = SCALAR_MUL_VAR_384_K.to_bytes(48, "big")
    t.write_memory(SCALAR_BUF_384, k_be)
    set_ptr(t, l["ec_scalar_ptr"], SCALAR_BUF_384)
    write_le(t, l["ec_base384_x"], SCALAR_MUL_VAR_384_BX, 48)
    write_le(t, l["ec_base384_y"], SCALAR_MUL_VAR_384_BY, 48)


def setup_ecdsa_verify_256(t, l):
    """Stage the 160 B verify struct from RFC 6979 A.2.5."""
    v = RFC6979_P256
    h = hashlib.sha256(v["msg"]).digest()
    payload = _pack_verify_struct_256(v["r"], v["s"], h, v["Ux"], v["Uy"])
    t.write_memory(l["ecdsa_inputs_256"], payload)
    # Zero the result byte so a stale 0/1 can't pass the gate.
    t.write_memory(l["ecdsa_result_256"], b"\xFF")


def setup_ecdsa_verify_384(t, l):
    """Stage the 240 B verify struct from RFC 6979 A.3.1."""
    v = RFC6979_P384
    h = hashlib.sha384(v["msg"]).digest()
    payload = _pack_verify_struct_384(v["r"], v["s"], h, v["Ux"], v["Uy"])
    t.write_memory(l["ecdsa_inputs_384"], payload)
    t.write_memory(l["ecdsa_result_384"], b"\xFF")


# ---------------------------------------------------------------------------
# Verifiers (oracle gates)
# ---------------------------------------------------------------------------

def verify_scalar_mul_var_256(t, l):
    """Expect ec_p3 to be k*G in Jacobian form."""
    jx = read_le(t, l["ec_p3"], 32)
    jy = read_le(t, l["ec_p3"] + 32, 32)
    jz = read_le(t, l["ec_p3"] + 64, 32)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p256")
    return (ax, ay) == scalar_mul_oracle(SCALAR_MUL_VAR_256_K, "p256")


def verify_scalar_mul_var_384(t, l):
    """Expect ec384_p3 to be k*G in Jacobian form."""
    jx = read_le(t, l["ec384_p3"], 48)
    jy = read_le(t, l["ec384_p3"] + 48, 48)
    jz = read_le(t, l["ec384_p3"] + 96, 48)
    ax, ay = jacobian_to_affine(jx, jy, jz, "p384")
    return (ax, ay) == scalar_mul_oracle(SCALAR_MUL_VAR_384_K, "p384")


def verify_ecdsa_verify_256(t, l):
    """Expect result byte 0 (valid) for the RFC 6979 A.2.5 positive vector."""
    return t.read_memory(l["ecdsa_result_256"], 1)[0] == 0


def verify_ecdsa_verify_384(t, l):
    """Expect result byte 0 (valid) for the RFC 6979 A.3.1 positive vector."""
    return t.read_memory(l["ecdsa_result_384"], 1)[0] == 0


# ---------------------------------------------------------------------------
# Bench plan
# ---------------------------------------------------------------------------

# (bench_tramp_label,          display_name,              loops,
#  setup_fn,                    verify_fn,                 timeout_at_1MHz,
#  marker_start, marker_stop)
#
# loops=1 for all four: each call is multi-second at 1 MHz and multi-hundred-
# millisecond even at 48 MHz. Jiffy precision (17045 cy/jiffy) is fine.
BENCH_PLAN = [
    ("bench_ec_scalar_mul_var_256_tramp", "ec_scalar_mul_var",       1,
     setup_scalar_mul_var_256,   verify_scalar_mul_var_256,  3600.0,
     0x82, 0x83),
    ("bench_ec_scalar_mul_var_384_tramp", "ec_scalar_mul_var_384",   1,
     setup_scalar_mul_var_384,   verify_scalar_mul_var_384,  3600.0,
     0x84, 0x85),
    ("bench_ecdsa_verify_256_tramp",      "ecdsa_verify_256",        1,
     setup_ecdsa_verify_256,     verify_ecdsa_verify_256,    3600.0,
     0x80, 0x81),
    ("bench_ecdsa_verify_384_tramp",      "ecdsa_verify_384",        1,
     setup_ecdsa_verify_384,     verify_ecdsa_verify_384,    3600.0,
     0x86, 0x87),
]


# ---------------------------------------------------------------------------
# Debug-stream cross-check (optional)
# ---------------------------------------------------------------------------

def _make_bfff_write_filter():
    """Return a filter function for DebugCapture keyed on 6510 writes to $BFFF."""
    def keep(word: int) -> bool:
        # bit 31 = phi2 (1=CPU), bit 24 = R/W (1=read, 0=write)
        is_cpu = bool(word & (1 << 31))
        is_write = not bool(word & (1 << 24))
        addr = word & 0xFFFF
        return is_cpu and is_write and addr == 0xBFFF
    return keep


def debug_stream_cycle_delta(trace, start_tok, stop_tok):
    """Parse a filtered BusCycle trace to find the last (start, stop) pair
    and return the cycle count between them (= index delta when the trace
    is unfiltered bus cycles).

    Because our filter only retains writes-to-$BFFF, the trace is small
    (one entry per marker emission).  We need a different approach to
    compute cycle deltas: we have to *not* filter, and keep every bus
    cycle, then count cycles between the two markers.
    """
    # Find all writes with data == start_tok and data == stop_tok
    n_start = n_stop = 0
    last_start_idx = last_stop_idx = None
    for i, bc in enumerate(trace):
        if not bc.is_cpu or not bc.is_write or bc.address != 0xBFFF:
            continue
        if bc.data == start_tok:
            last_start_idx = i
            n_start += 1
        elif bc.data == stop_tok:
            last_stop_idx = i
            n_stop += 1
    if last_start_idx is None or last_stop_idx is None:
        return None, n_start, n_stop
    if last_stop_idx <= last_start_idx:
        return None, n_start, n_stop
    # Bus cycle count between markers = index delta (each entry is one cycle
    # of the PHI2 clock). The `sta $BFFF` instruction is 4 cycles; the stop
    # marker is *at* the write cycle (cycle 4 of the stop `sta`), so the
    # interval start_idx..stop_idx includes the 4-cy start `sta`'s write
    # cycle and ends on the stop `sta`'s write cycle.
    return last_stop_idx - last_start_idx, n_start, n_stop


# ---------------------------------------------------------------------------
# Per-speed driver
# ---------------------------------------------------------------------------

def run_sweep_for_speed(client, transport, prg_data, labels, mhz, args):
    main_loop = labels["main_loop"]

    print(f"\n{'='*72}\n  ECDSA sweep @ {mhz} MHz\n{'='*72}", flush=True)

    ok = reboot_and_prepare(client, transport, prg_data, mhz,
                            init_timeout=args.init_timeout)
    if not ok:
        return {name: {"ok": False, "reason": "INIT_TIMEOUT"}
                for (_t, name, *_r) in BENCH_PLAN}

    # Neither the verify nor scalar_mul_var entry points require a specific
    # `fp_misc` pointer on entry -- the ECDSA routines install the curve
    # prime via ec_set_modp / ec_set_modp_384 internally. But set it for
    # sanity (mirrors the primitive bench tools).
    set_ptr(transport, labels["fp_misc"], labels["ec_p256"])
    park_main_loop(transport, main_loop)

    speed_results = {}
    for tramp_name, disp_name, loops, setup_fn, verify_fn, base_timeout, \
            mk_start, mk_stop in BENCH_PLAN:
        # Per-primitive wall-time at turbo does NOT scale linearly with MHz:
        # jiffy clock (CIA raster IRQ) ticks at real-time NTSC 60 Hz regardless
        # of turbo speed, and REU DMA runs at 1 MHz regardless of CPU turbo.
        # Empirically, 48 MHz wall time is ~70-75% of 16 MHz wall for these
        # primitives. Timeout must leave ample headroom for that and for
        # benign HTTP polling stalls. Use max(180s, 3*base_timeout/mhz).
        timeout = max(180.0, 3.0 * base_timeout / mhz)
        print(f"  {disp_name:<24} loops={loops:<3d} timeout={timeout:6.1f}s ...",
              flush=True, end=" ")

        # Optional debug-stream capture for this primitive.
        dbg_cap = None
        if args.debug_stream and _DEBUG_CAPTURE_OK:
            try:
                dbg_cap = DebugCapture(port=DEFAULT_DEBUG_PORT)
                dbg_cap.start()
                # Configure and start the stream (fire-and-forget).
                set_debug_stream_mode(client, DEBUG_MODE_6510)
                # NB: stream destination is typically pre-configured in the
                # U64E Web UI. We ask the device to start the stream to
                # whatever destination is currently configured. If the user
                # hasn't configured it this is a no-op and dbg_cap will
                # receive no packets.
                try:
                    client.stream_debug_start(args.debug_destination or "")
                except Exception as e:
                    print(f"[dbg stream_start failed: {e}]", end=" ")
            except Exception as e:
                print(f"[dbg init failed: {e}]", end=" ")
                dbg_cap = None

        res = run_one_routine(
            transport, labels, main_loop,
            tramp_name, loops, setup_fn, verify_fn, timeout)

        # Stop & parse the debug-stream capture.
        dbg_cycles = None
        dbg_start_count = dbg_stop_count = 0
        if dbg_cap is not None:
            try:
                client.stream_debug_stop()
            except Exception:
                pass
            try:
                result = dbg_cap.stop()
                dbg_cycles, dbg_start_count, dbg_stop_count = \
                    debug_stream_cycle_delta(result.trace, mk_start, mk_stop)
            except Exception as e:
                print(f"[dbg stop failed: {e}]", end=" ")

        res["dbg_cycles"] = dbg_cycles
        res["dbg_start_count"] = dbg_start_count
        res["dbg_stop_count"] = dbg_stop_count
        speed_results[disp_name] = res

        if res["ok"]:
            # Primary: jiffies × NTSC_CYCLES_PER_JIFFY = measured cycles
            # (bench_start / bench_stop measures jiffy elapsed inside the
            # trampoline body).
            cyc = res["cycles"]
            ms = cyc / (mhz * 1_000_000.0) * 1000.0
            extra = ""
            if dbg_cycles is not None:
                diff = dbg_cycles - cyc
                pct = (100.0 * diff / cyc) if cyc else 0.0
                extra = (f"  [dbg={dbg_cycles} Δ={diff:+d} ({pct:+.2f}%)]")
            print(f"{res['jiffies']:>6d}j  {cyc:>12d}cy  "
                  f"{ms:>8.2f}ms  [wall {res['wall']:.1f}s]{extra}")
        else:
            print(f"{res['reason']:<22}  [wall {res['wall']:.1f}s]")

    return speed_results


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _fmt_cy(c):
    if c is None:
        return "-"
    # commas for readability
    return f"{c:,}"


def print_summary(all_results, speeds):
    print()
    print("=" * 96)
    print("  ECDSA / scalar_mul_var U64E bench -- cycles/call (NTSC 1 jiffy = "
          f"{NTSC_CYCLES_PER_JIFFY} cy)")
    print("=" * 96)
    names = [disp for (_t, disp, *_r) in BENCH_PLAN]
    hdr = f"  {'Primitive':<24}"
    for mhz in speeds:
        hdr += f" {str(mhz)+' MHz':>16}"
    print(hdr)
    print("  " + "-" * (24 + 17 * len(speeds)))
    for name in names:
        row = f"  {name:<24}"
        for mhz in speeds:
            res = all_results.get(mhz, {}).get(name)
            if res is None or not res.get("ok"):
                reason = res["reason"] if res else "-"
                short = {"UNVERIFIED": "UNVRF", "SKIP(0 jiffies)": "SKIP0",
                         "TIMEOUT": "T/O", "INIT_TIMEOUT": "INIT"}.get(
                    reason, "-")
                row += f" {short:>16}"
            else:
                row += f" {_fmt_cy(res['cycles']):>16}"
        print(row)

    print()
    print("=" * 96)
    print("  Wall-clock per call (seconds)")
    print("=" * 96)
    hdr = f"  {'Primitive':<24}"
    for mhz in speeds:
        hdr += f" {str(mhz)+' MHz':>16}"
    print(hdr)
    print("  " + "-" * (24 + 17 * len(speeds)))
    for name in names:
        row = f"  {name:<24}"
        for mhz in speeds:
            res = all_results.get(mhz, {}).get(name)
            if res is None or not res.get("ok"):
                row += f" {'-':>16}"
            else:
                s = res["cycles"] / (mhz * 1_000_000.0)
                row += f" {s:>13.3f} s"
        print(row)
    print("=" * 96)

    # Debug-stream cross-check block
    has_dbg = any(
        (all_results.get(mhz, {}).get(n) or {}).get("dbg_cycles") is not None
        for n in names for mhz in speeds)
    if has_dbg:
        print()
        print("=" * 96)
        print("  Debug-stream cross-check (bus-cycle delta between markers)")
        print("=" * 96)
        hdr = f"  {'Primitive':<24}"
        for mhz in speeds:
            hdr += f" {str(mhz)+' MHz':>16}"
        print(hdr)
        print("  " + "-" * (24 + 17 * len(speeds)))
        for name in names:
            row = f"  {name:<24}"
            for mhz in speeds:
                res = all_results.get(mhz, {}).get(name) or {}
                dbg = res.get("dbg_cycles")
                if dbg is None:
                    row += f" {'-':>16}"
                else:
                    row += f" {_fmt_cy(dbg):>16}"
            print(row)
        print("=" * 96)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--speeds", type=str, default="16,48",
                   help="Comma-separated speeds in MHz (default: 16,48).")
    p.add_argument("--init-timeout", type=float, default=360.0)
    p.add_argument("--prg", type=str, default=PRG_PATH)
    p.add_argument("--labels", type=str, default=LABELS_PATH)
    p.add_argument("--debug-stream", action="store_true",
                   default=bool(os.environ.get("BENCH_DEBUG_STREAM")),
                   help="Enable U64E debug-stream cycle cross-check "
                        "(requires stream destination configured on device).")
    p.add_argument("--debug-destination", type=str,
                   default=os.environ.get("BENCH_DEBUG_DEST", ""),
                   help="IP:port destination for the debug stream. If empty, "
                        "uses the U64E's pre-configured destination.")
    return p.parse_args()


def main():
    args = parse_args()

    host = os.environ.get("U64_HOST")
    if not host:
        print("ERROR: U64_HOST not set")
        print("  Set U64_HOST=<ip> (and optionally U64_PASSWORD) to run the "
              "bench.")
        print("  Skipping bench; the PRG still builds and the code paths "
              "still link.")
        sys.exit(2)
    password = os.environ.get("U64_PASSWORD")

    speeds = [int(s.strip()) for s in args.speeds.split(",")]
    for m in speeds:
        if m not in ALL_SPEEDS:
            print(f"ERROR: unsupported turbo speed {m} MHz; must be one of "
                  f"{ALL_SPEEDS}")
            sys.exit(2)

    print(f"Loading PRG: {args.prg}")
    with open(args.prg, "rb") as f:
        prg_data = f.read()
    print(f"  {len(prg_data)} bytes")

    print(f"Loading labels: {args.labels}")
    labels = Labels.from_file(args.labels)

    required = [
        "main_loop",
        "fp_misc",
        "bench_ticks", "vic_blank", "vic_unblank",
        "bench_start", "bench_stop",
        "ec_p256", "ec_p384",
        "ec_scalar_ptr",
        "ec_base_x", "ec_base_y", "ec_base384_x", "ec_base384_y",
        "ec_p3", "ec384_p3",
        "ecdsa_inputs_256", "ecdsa_inputs_384",
        "ecdsa_result_256", "ecdsa_result_384",
    ]
    required += [t for (t, *_r) in BENCH_PLAN]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: missing labels: {missing}")
        sys.exit(1)

    print(f"Probing U64 at {host} ...")
    pr = probe_u64(host, password=password)
    if not pr.reachable:
        print(f"FATAL: U64 not reachable: {pr}")
        print("  The bench requires live Ultimate 64 Elite hardware. Exiting.")
        sys.exit(2)
    print("  reachable")

    if args.debug_stream:
        if not _DEBUG_CAPTURE_OK:
            print("WARNING: --debug-stream requested but DebugCapture import "
                  "failed; proceeding without cross-check.")
            args.debug_stream = False
        else:
            print(f"Debug-stream cross-check ENABLED (UDP "
                  f"{DEFAULT_DEBUG_PORT})")

    lock = DeviceLock(host)
    with lock:
        client = Ultimate64Client(host=host, password=password, timeout=60.0)
        transport = Ultimate64Transport(host=host, password=password,
                                        client=client)
        info = client.get_info()
        print(f"  Connected: {info.get('product','?')} "
              f"fw={info.get('firmware_version','?')}")

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

        print(f"\nTotal sweep wall time: "
              f"{(time.monotonic()-t_start)/60:.1f} min")

    print_summary(all_results, speeds)


if __name__ == "__main__":
    main()
