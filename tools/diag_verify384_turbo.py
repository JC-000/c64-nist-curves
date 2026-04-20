#!/usr/bin/env python3
"""diag_verify384_turbo.py -- Round 1 isolation for the 48 MHz
ecdsa_verify_384 timeout.

Boots at 48 MHz, polls init sentinel, runs ONLY ecdsa_verify_384
at 48 MHz with a long per-call timeout (300 s) and no retries
so the total test cycle is at most ~310 s. Captures a small debug
stream of writes to $02A8 (done sentinel) and $BFFF (marker bytes
$86/$87) between start and expected completion.

Hypothesis under test: the 48 MHz verify_384 T/O in Task #11 was
caused by cumulative state left by the three prior primitives in
the same session (scalar_mul_var / scalar_mul_var_384 / verify_256).
If an isolated run completes, this is confirmed.

Usage:
    U64_HOST=192.168.1.81 python3 tools/diag_verify384_turbo.py
    U64_HOST=192.168.1.81 python3 tools/diag_verify384_turbo.py \
        --timeout 300 --debug-stream
"""
from __future__ import annotations

import argparse
import hashlib
import os
import socket
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))

from bench_u64_common import (  # noqa: E402
    Ultimate64Client, Ultimate64Transport, DeviceLock, probe_u64,
    set_turbo_mhz, set_reu, snapshot_state, restore_state,
    Labels,
    reboot_and_prepare, park_main_loop, hijack_main_loop,
    build_sweep_trampoline, TRAMPOLINE_ADDR, DONE_SENTINEL_ADDR,
    INIT_SENTINEL_ADDR,
    set_ptr, write_le, read_le,
    poll_done_sentinel,
    NTSC_CYCLES_PER_JIFFY,
)

try:
    from c64_test_harness.backends.u64_debug_capture import (
        DebugCapture, DEFAULT_DEBUG_PORT,
    )
    from c64_test_harness.backends.ultimate64_helpers import (
        set_debug_stream_mode, DEBUG_MODE_6510,
    )
    _DEBUG_CAPTURE_OK = True
except Exception as _e:
    _DEBUG_CAPTURE_OK = False

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")


# --- RFC 6979 A.3.1 ---
RFC6979_P384 = {
    "msg": b"sample",
    "Ux": 0xEC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13,
    "Uy": 0x8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720,
    "r":  0x94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46,
    "s":  0x99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8,
}


def _pack_verify_struct_384(r, s, h_bytes, qx, qy):
    payload = (r.to_bytes(48, "big") + s.to_bytes(48, "big")
               + int.from_bytes(h_bytes, "big").to_bytes(48, "big")
               + qx.to_bytes(48, "big") + qy.to_bytes(48, "big"))
    assert len(payload) == 240
    return payload


def setup_ecdsa_verify_384(t, l):
    v = RFC6979_P384
    h = hashlib.sha384(v["msg"]).digest()
    payload = _pack_verify_struct_384(v["r"], v["s"], h, v["Ux"], v["Uy"])
    t.write_memory(l["ecdsa_inputs_384"], payload)
    t.write_memory(l["ecdsa_result_384"], b"\xFF")


def verify_ecdsa_verify_384(t, l):
    return t.read_memory(l["ecdsa_result_384"], 1)[0] == 0


def _local_ip(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def run_isolated_verify384(client, transport, labels, timeout,
                           enable_debug_stream=False, local_ip=None,
                           target_mhz=48):
    main_loop = labels["main_loop"]
    routine_addr = labels["bench_ecdsa_verify_384_tramp"]
    bench_ticks = labels["bench_ticks"]
    vic_blank = labels["vic_blank"]
    vic_unblank = labels["vic_unblank"]

    # Mirror the bench's fp_misc preset.
    set_ptr(transport, labels["fp_misc"], labels["ec_p256"])

    park_main_loop(transport, main_loop)

    # Stage verify inputs.
    setup_ecdsa_verify_384(transport, labels)

    code = build_sweep_trampoline(
        routine_addr, 1, bench_ticks, vic_blank, vic_unblank,
        main_loop_addr=main_loop,
        bench_start_addr=labels["bench_start"],
        bench_stop_addr=labels["bench_stop"])
    transport.write_memory(TRAMPOLINE_ADDR, code)

    transport.write_memory(DONE_SENTINEL_ADDR, bytes([0x00]))
    time.sleep(0.02)
    transport.write_memory(DONE_SENTINEL_ADDR, bytes([0x00]))
    for _ in range(20):
        if transport.read_memory(DONE_SENTINEL_ADDR, 1)[0] == 0x00:
            break
        transport.write_memory(DONE_SENTINEL_ADDR, bytes([0x00]))
        time.sleep(0.02)

    transport.write_memory(bench_ticks, bytes([0x00, 0x00, 0x00]))

    dbg_cap = None
    if enable_debug_stream and _DEBUG_CAPTURE_OK:
        print(f"  [debug-stream] starting capture UDP:{DEFAULT_DEBUG_PORT}"
              f" -> {local_ip}", flush=True)
        try:
            dbg_cap = DebugCapture(port=DEFAULT_DEBUG_PORT)
            dbg_cap.start()
            set_debug_stream_mode(client, DEBUG_MODE_6510)
            client.stream_debug_start(f"{local_ip}:{DEFAULT_DEBUG_PORT}"
                                      if local_ip else "")
        except Exception as e:
            print(f"  [debug-stream] init failed: {e}", flush=True)
            dbg_cap = None

    hijack_main_loop(transport, main_loop, TRAMPOLINE_ADDR)
    try:
        transport.resume()
    except Exception:
        pass

    wall_start = time.monotonic()
    print(f"  [run] hijacked, polling done sentinel (timeout {timeout:.0f}s)...",
          flush=True)
    ok = poll_done_sentinel(transport, timeout, poll_interval=1.0)
    wall = time.monotonic() - wall_start

    if dbg_cap is not None:
        try:
            client.stream_debug_stop()
        except Exception:
            pass
        time.sleep(0.2)
        try:
            result = dbg_cap.stop()
        except Exception as e:
            print(f"  [debug-stream] stop failed: {e}", flush=True)
            result = None
    else:
        result = None

    park_main_loop(transport, main_loop)
    try:
        transport.resume()
    except Exception:
        pass
    time.sleep(0.1)

    res = {"ok": ok, "wall": wall}
    if ok:
        raw = transport.read_memory(bench_ticks, 3)
        jiffies = (raw[0] << 16) | (raw[1] << 8) | raw[2]
        res["jiffies"] = jiffies
        res["cycles"] = jiffies * NTSC_CYCLES_PER_JIFFY
        res["verify_ok"] = verify_ecdsa_verify_384(transport, labels)
    else:
        res["jiffies"] = None
        res["cycles"] = None
        res["verify_ok"] = None

    res["debug_result"] = result
    res["target_mhz"] = target_mhz
    return res


def summarize_debug_trace(result, log=print):
    if result is None:
        log("  [debug-stream] no trace")
        return
    log(f"  [debug-stream] total_cycles={result.total_cycles} "
        f"packets={result.packets_received} "
        f"dropped={result.packets_dropped} "
        f"dur={result.duration_seconds:.2f}s")
    # Filter CPU writes to $BFFF and $02A8.
    marker_writes = []
    done_writes = []
    for i, bc in enumerate(result.trace):
        if not bc.is_cpu or not bc.is_write:
            continue
        if bc.address == 0xBFFF:
            marker_writes.append((i, bc.data))
        elif bc.address == DONE_SENTINEL_ADDR:
            done_writes.append((i, bc.data))
    log(f"  marker writes to $BFFF: {len(marker_writes)}")
    for i, d in marker_writes[:40]:
        log(f"    idx={i:>10d}  val=${d:02x}")
    log(f"  done sentinel writes to $02A8: {len(done_writes)}")
    for i, d in done_writes[:10]:
        log(f"    idx={i:>10d}  val=${d:02x}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=300.0,
                    help="Per-call timeout in seconds (default 300).")
    ap.add_argument("--init-timeout", type=float, default=360.0)
    ap.add_argument("--debug-stream", action="store_true",
                    help="Capture U64E debug stream during the call.")
    ap.add_argument("--target-mhz", type=int, default=48)
    ap.add_argument("--no-reboot", action="store_true",
                    help="Skip reboot (assume PRG already initialized)")
    args = ap.parse_args()

    host = os.environ.get("U64_HOST", "192.168.1.81")
    password = os.environ.get("U64_PASSWORD")

    print(f"Loading PRG: {PRG_PATH}")
    with open(PRG_PATH, "rb") as f:
        prg_data = f.read()
    print(f"  {len(prg_data)} bytes")
    labels = Labels.from_file(LABELS_PATH)

    required = [
        "main_loop", "fp_misc", "bench_ticks",
        "vic_blank", "vic_unblank", "bench_start", "bench_stop",
        "ec_p256",
        "bench_ecdsa_verify_384_tramp",
        "ecdsa_inputs_384", "ecdsa_result_384",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: missing labels: {missing}")
        sys.exit(1)

    pr = probe_u64(host, password=password)
    if not pr.reachable:
        print(f"FATAL: U64 unreachable: {pr}")
        sys.exit(2)
    print(f"  reachable: {pr}")

    local = _local_ip(host)
    print(f"  local IP: {local}")

    lock = DeviceLock(host)
    with lock:
        client = Ultimate64Client(host=host, password=password, timeout=60.0)
        transport = Ultimate64Transport(host=host, password=password,
                                        client=client)
        info = client.get_info()
        print(f"  Connected: {info.get('product','?')} "
              f"fw={info.get('firmware_version','?')}")

        orig_state = snapshot_state(client)
        try:
            if not args.no_reboot:
                ok = reboot_and_prepare(
                    client, transport, prg_data, args.target_mhz,
                    init_timeout=args.init_timeout)
                if not ok:
                    print("FATAL: init sentinel never set")
                    sys.exit(2)
            else:
                set_turbo_mhz(client, args.target_mhz)
                time.sleep(0.3)

            print(f"\n[ROUND 1] ecdsa_verify_384 isolated @ {args.target_mhz} MHz")
            print(f"          timeout={args.timeout:.0f}s  retries=0")

            res = run_isolated_verify384(
                client, transport, labels,
                timeout=args.timeout,
                enable_debug_stream=args.debug_stream,
                local_ip=local,
                target_mhz=args.target_mhz,
            )

            if res["ok"]:
                mhz = res["target_mhz"]
                cyc = res["cycles"]
                ms = cyc / (mhz * 1_000_000.0) * 1000.0
                print(f"  RESULT: COMPLETED in wall {res['wall']:.1f}s  "
                      f"jiffies={res['jiffies']}  cycles={cyc}  "
                      f"time={ms:.1f}ms @ {mhz}MHz  "
                      f"verify_ok={res['verify_ok']}")
            else:
                print(f"  RESULT: TIMEOUT after wall {res['wall']:.1f}s")

            if args.debug_stream:
                summarize_debug_trace(res["debug_result"])

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
