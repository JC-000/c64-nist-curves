"""Shared helpers for U64 turbo-sweep benchmarking of P-256 / P-384 primitives.

Installs a monolithic ~60-byte 6502 trampoline at $C000 that:

  1. SEI + zero jiffy clock ($A0/$A1/$A2) + CLI
  2. JSR vic_blank
  3. Loops a 16-bit counter calling the target routine
  4. JSR vic_unblank
  5. SEI + snapshots jiffies into `bench_ticks` + CLI
  6. Writes $42 to DONE_SENTINEL ($0350)
  7. JMP * (park)

Hijack is atomic: a 3-byte shim at $0800 (JMP $C000) is written once
after init.  `hijack_main_loop` flips a single byte at $0836 from $35
to $00, turning `JMP $0835` into `JMP $0800` -> shim -> trampoline.
`park_main_loop` restores the byte to $35.  Single-byte writes are
atomic from the CPU's perspective.
"""
from __future__ import annotations

import os
import sys
import time

_HARNESS_SRC = "/home/someone/c64-test-harness/src"
if os.path.isdir(_HARNESS_SRC) and _HARNESS_SRC not in sys.path:
    sys.path.insert(0, _HARNESS_SRC)

from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (  # noqa: E402
    Ultimate64Client,
    Ultimate64Error,
)
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    get_turbo_mhz,
    set_turbo_mhz,
    set_reu,
    snapshot_state,
    restore_state,
)
from c64_test_harness.backends.device_lock import (  # noqa: E402
    DeviceLock,
    DeviceLockTimeout,
)
from c64_test_harness.backends.ultimate64_probe import probe_u64  # noqa: E402
from c64_test_harness.labels import Labels  # noqa: E402


ALL_SPEEDS = [1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 20, 24, 32, 40, 48]

NTSC_CYCLES_PER_JIFFY = 17045
NTSC_CPU_HZ = NTSC_CYCLES_PER_JIFFY * 60

INIT_SENTINEL_ADDR = 0x02A7
INIT_SENTINEL_VAL = 0x42
DONE_SENTINEL_ADDR = 0x02A8
DONE_SENTINEL_VAL = 0x42

TRAMPOLINE_ADDR = 0xC000
LOOP_COUNTER_ADDR = 0xC0F0  # 2 bytes, little-endian
SHIM_ADDR = 0x0800  # JMP $C000 shim written once after init


def build_sweep_trampoline(
    routine_addr: int,
    loops: int,
    bench_ticks_addr: int,
    vic_blank_addr: int,
    vic_unblank_addr: int,
    main_loop_addr: int = 0x0835,
    bench_start_addr: int | None = None,
    bench_stop_addr: int | None = None,
) -> bytes:
    """Build the monolithic benchmark program starting at TRAMPOLINE_ADDR.

    Calls the program's existing bench_start / bench_stop helpers (which
    do SEI ; reset jiffy ; CLI and SEI ; snapshot bench_ticks ; CLI
    respectively). After the snapshot it restores main_loop via a
    single-byte write to $0836 (atomic), sets the done sentinel ($42
    at $0350), and JMPs back to main_loop.
    """
    assert 1 <= loops <= 65535, f"loops {loops} out of 1..65535"
    assert bench_start_addr is not None and bench_stop_addr is not None
    code = bytearray()

    def emit(*bs):
        code.extend(bs)

    def lda_imm(v): emit(0xA9, v & 0xFF)
    def sta_abs(a): emit(0x8D, a & 0xFF, (a >> 8) & 0xFF)
    def lda_abs(a): emit(0xAD, a & 0xFF, (a >> 8) & 0xFF)
    def ora_abs(a): emit(0x0D, a & 0xFF, (a >> 8) & 0xFF)
    def dec_abs(a): emit(0xCE, a & 0xFF, (a >> 8) & 0xFF)
    def jsr(a): emit(0x20, a & 0xFF, (a >> 8) & 0xFF)

    lo = LOOP_COUNTER_ADDR
    hi = LOOP_COUNTER_ADDR + 1

    # Blank VIC and reset jiffy clock via the program's helpers.
    jsr(vic_blank_addr)
    jsr(bench_start_addr)

    # Prime 16-bit loop counter.
    lda_imm(loops & 0xFF)
    sta_abs(lo)
    lda_imm((loops >> 8) & 0xFF)
    sta_abs(hi)

    loop_top = TRAMPOLINE_ADDR + len(code)
    jsr(routine_addr)
    lda_abs(lo)
    emit(0xD0, 0x03)                 # BNE +3
    dec_abs(hi)
    dec_abs(lo)
    lda_abs(lo)
    ora_abs(hi)
    branch_pc = TRAMPOLINE_ADDR + len(code) + 2
    offset = (loop_top - branch_pc) & 0xFF
    emit(0xD0, offset)               # BNE loop_top

    # Snapshot jiffies to bench_ticks via the program's helper.
    jsr(bench_stop_addr)
    jsr(vic_unblank_addr)

    # Restore main_loop atomically: write ONE byte at main_loop+1 ($0836)
    # changing $00 back to $35, so JMP $0800 becomes JMP $0835 again.
    lda_imm(main_loop_addr & 0xFF)       # $35
    sta_abs(main_loop_addr + 1)          # -> $0836

    lda_imm(DONE_SENTINEL_VAL)
    sta_abs(DONE_SENTINEL_ADDR)

    emit(0x4C, main_loop_addr & 0xFF, (main_loop_addr >> 8) & 0xFF)

    return bytes(code)


def poll_done_sentinel(transport, timeout, poll_interval=0.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = transport.read_memory(DONE_SENTINEL_ADDR, 1)
        if data and data[0] == DONE_SENTINEL_VAL:
            return True
        try:
            transport.resume()
        except Exception:
            pass
        time.sleep(poll_interval)
    return False


def poll_init_sentinel(transport, timeout, poll_interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = transport.read_memory(INIT_SENTINEL_ADDR, 1)
        if data and data[0] == INIT_SENTINEL_VAL:
            return True
        try:
            transport.resume()
        except Exception:
            pass
        time.sleep(poll_interval)
    return False


def install_shim(transport):
    """Write JMP $C000 at $0800 (dead BASIC stub area). Called once after
    init sentinel is detected."""
    transport.write_memory(SHIM_ADDR, bytes([
        0x4C, TRAMPOLINE_ADDR & 0xFF, (TRAMPOLINE_ADDR >> 8) & 0xFF]))


def reboot_and_prepare(client, transport, prg_data, mhz,
                       init_timeout=360.0, reu_size="512 KB",
                       init_mhz=48):
    """Full reboot; always run init (sqtab + REU mul tables +
    ec_precompute_256/384) at `init_mhz` (default 48 MHz) so boot takes
    ~4 min even when the benchmark target is 1 MHz; then switch turbo to
    the target speed once the init sentinel ($42 at $02A7) is seen.
    """
    print(f"    [reboot]", flush=True, end="")
    client.reboot()
    time.sleep(8.0)
    print(" ok")

    set_reu(client, enabled=True, size=reu_size)
    print(f"    [init turbo {init_mhz} MHz]", flush=True, end="")
    set_turbo_mhz(client, init_mhz)
    time.sleep(0.5)
    print(" ok")

    print(f"    [run_prg {len(prg_data)}B]", flush=True, end="")
    client.run_prg(prg_data)
    print(" sent")

    print(f"    [init sentinel] up to {init_timeout:.0f}s...", flush=True)
    t0 = time.monotonic()
    ok = poll_init_sentinel(transport, init_timeout, poll_interval=2.0)
    if not ok:
        print(f"    [init sentinel] TIMEOUT after {time.monotonic()-t0:.1f}s")
        return False
    print(f"    [init sentinel] ok after {time.monotonic()-t0:.1f}s")

    # Install the shim at $0800 (JMP $C000) once, now that init is done
    # and the BASIC stub area is safe to overwrite.
    install_shim(transport)

    if mhz != init_mhz:
        print(f"    [target turbo {mhz} MHz]", flush=True, end="")
        set_turbo_mhz(client, mhz)
        time.sleep(0.5)
        print(" ok")
    return True


def park_main_loop(transport, main_loop_addr):
    """Atomic restore: write ONE byte at main_loop_addr+1, setting the
    low byte of the JMP operand back to main_loop_addr & 0xFF ($35),
    so the instruction reads JMP $0835 (self-loop)."""
    transport.write_memory(
        main_loop_addr + 1,
        bytes([main_loop_addr & 0xFF]))


def hijack_main_loop(transport, main_loop_addr, target):
    """Atomic hijack: write ONE byte at main_loop_addr+1, changing the
    low byte of the JMP operand from $35 to $00.  This turns
    JMP $0835 into JMP $0800, which hits the shim (JMP $C000)."""
    transport.write_memory(
        main_loop_addr + 1,
        bytes([SHIM_ADDR & 0xFF]))  # $00


def _run_one_routine_once(transport, labels, main_loop_addr,
                          routine_name, loops, setup_fn, verify_fn, timeout):
    routine_addr = labels[routine_name]
    bench_ticks = labels["bench_ticks"]
    vic_blank = labels["vic_blank"]
    vic_unblank = labels["vic_unblank"]

    park_main_loop(transport, main_loop_addr)

    if setup_fn is not None:
        setup_fn(transport, labels)

    code = build_sweep_trampoline(
        routine_addr, loops, bench_ticks, vic_blank, vic_unblank,
        main_loop_addr=main_loop_addr,
        bench_start_addr=labels["bench_start"],
        bench_stop_addr=labels["bench_stop"])
    transport.write_memory(TRAMPOLINE_ADDR, code)
    # Belt-and-braces: zero done sentinel twice with a brief settle, in
    # case the U64 REST API reorders or buffers writes around fast bursts.
    transport.write_memory(DONE_SENTINEL_ADDR, bytes([0x00]))
    time.sleep(0.02)
    transport.write_memory(DONE_SENTINEL_ADDR, bytes([0x00]))
    # Read-back guard: spin until the device confirms the zero landed.
    for _ in range(20):
        if transport.read_memory(DONE_SENTINEL_ADDR, 1)[0] == 0x00:
            break
        transport.write_memory(DONE_SENTINEL_ADDR, bytes([0x00]))
        time.sleep(0.02)

    # Zero bench_ticks too so a stale read from a missed trampoline
    # produces an obvious 0-jiffy (SKIP) rather than stale nonsense.
    transport.write_memory(bench_ticks, bytes([0x00, 0x00, 0x00]))
    hijack_main_loop(transport, main_loop_addr, TRAMPOLINE_ADDR)
    try:
        transport.resume()
    except Exception:
        pass

    wall_start = time.monotonic()
    poll_iv = 0.2 if timeout < 30 else 0.5
    ok = poll_done_sentinel(transport, timeout, poll_interval=poll_iv)
    wall = time.monotonic() - wall_start

    park_main_loop(transport, main_loop_addr)
    try:
        transport.resume()
    except Exception:
        pass
    time.sleep(0.1)

    if not ok:
        return {"ok": False, "jiffies": 0, "cycles": None, "ms": None,
                "wall": wall, "reason": "TIMEOUT"}

    raw = transport.read_memory(bench_ticks, 3)
    jiffies = (raw[0] << 16) | (raw[1] << 8) | raw[2]

    if verify_fn is not None and not verify_fn(transport, labels):
        return {"ok": False, "jiffies": jiffies, "cycles": None, "ms": None,
                "wall": wall, "reason": "UNVERIFIED"}

    if jiffies == 0:
        return {"ok": False, "jiffies": 0, "cycles": None, "ms": None,
                "wall": wall, "reason": "SKIP(0 jiffies)"}

    total_cycles = jiffies * NTSC_CYCLES_PER_JIFFY
    cycles_per_call = total_cycles // loops
    ms_per_call = (cycles_per_call / NTSC_CPU_HZ) * 1000.0
    return {"ok": True, "jiffies": jiffies, "cycles": cycles_per_call,
            "ms": ms_per_call, "wall": wall, "reason": "OK"}


def set_ptr(transport, zp_addr, target):
    transport.write_memory(
        zp_addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def write_le(transport, addr, value, length):
    data = (value & ((1 << (8 * length)) - 1)).to_bytes(length, "little")
    transport.write_memory(addr, data)


def read_le(transport, addr, length):
    return int.from_bytes(transport.read_memory(addr, length), "little")


# ---------------------------------------------------------------------------
# Device-lock acquire helpers
# ---------------------------------------------------------------------------

#: Bench-tool default for the bounded acquire timeout.  10 minutes matches
#: the longest expected serialized bench wait while keeping a stuck queue
#: from blocking another agent's run indefinitely.
DEFAULT_LOCK_ACQUIRE_TIMEOUT = 600.0


def _fmt_lock_holder(info):
    """Render a DeviceLock.read_info() dict into a one-line human string.

    Returns ``"<no metadata>"`` on falsy / non-dict input rather than ``None``
    so the call site can always print something useful.
    """
    if not isinstance(info, dict):
        return "<no metadata>"
    pid = info.get("pid")
    ts = info.get("ts")
    host = info.get("device_host")
    bits = []
    if pid is not None:
        bits.append(f"pid={pid}")
    if isinstance(ts, (int, float)):
        age = max(0.0, time.time() - ts)
        bits.append(f"started_at={ts:.0f} ({age:.0f}s ago)")
    if host:
        bits.append(f"device_host={host!r}")
    return ", ".join(bits) if bits else "<no metadata>"


def acquire_device_lock_or_exit(host, *,
                                timeout=DEFAULT_LOCK_ACQUIRE_TIMEOUT):
    """Stale-clean, surface existing holder, then bounded-acquire.

    Bench-tool entry-point helper that replaces the legacy
    ``with DeviceLock(host):`` pattern.  Performs, in order:

      1. ``DeviceLock.cleanup_stale()`` to drop lockfiles belonging to
         dead PIDs (e.g. previous holder ``kill -9``ed without releasing).
      2. ``lock.read_info()`` to surface the metadata of any current
         holder BEFORE we block.  Printed as a single line so the user
         can see they'd be queueing behind a specific other run.
      3. ``lock.acquire_or_raise(timeout=...)`` to block at most
         *timeout* seconds.  On :class:`DeviceLockTimeout` the structured
         message (holder pid, liveness, lockfile age, REST reachability)
         is printed and the process exits 2.

    Returns the acquired :class:`DeviceLock` instance.  Callers are
    responsible for ``lock.release()`` in their cleanup path.

    NOTE: this function will ``sys.exit(2)`` on timeout — it is intended
    for top-level bench tools, not library code.
    """
    try:
        removed = DeviceLock.cleanup_stale()
    except Exception as e:  # pragma: no cover - defensive
        removed = 0
        print(f"  [lock] cleanup_stale: WARN {type(e).__name__}: {e}",
              flush=True)
    if removed:
        print(f"  [lock] cleanup_stale removed {removed} stale lockfile(s)",
              flush=True)

    lock = DeviceLock(host)

    pre_info = lock.read_info()
    if pre_info is not None:
        print(
            f"  [lock] device currently held by another run: "
            f"{_fmt_lock_holder(pre_info)}",
            flush=True,
        )
        print(
            f"  [lock] will block up to {timeout:.0f}s for acquire "
            f"(queue-aware; live progressing holders extend the deadline)",
            flush=True,
        )
    else:
        print(f"  [lock] no current holder; acquiring (timeout={timeout:.0f}s)",
              flush=True)

    try:
        lock.acquire_or_raise(timeout=timeout)
    except DeviceLockTimeout as e:
        print(f"FATAL: DeviceLock acquire failed: {e}", flush=True)
        # Re-surface the holder metadata in case the structured message
        # didn't carry it (e.g. cleanup_stale dropped it mid-wait).
        late_info = lock.read_info()
        if late_info is not None:
            print(f"  current holder: {_fmt_lock_holder(late_info)}",
                  flush=True)
        sys.exit(2)
    held_info = lock.read_info()
    if held_info is not None:
        print(f"  [lock] acquired; metadata={_fmt_lock_holder(held_info)}",
              flush=True)
    else:
        print("  [lock] acquired", flush=True)
    return lock


# ---------------------------------------------------------------------------
# Writemem health probe (POST 404 detection)
# ---------------------------------------------------------------------------

#: Scratch address used by :func:`writemem_health_probe`.  Adjacent to the
#: existing $02A7 init sentinel and $02A8 done sentinel but DISTINCT —
#: deliberately avoids those bytes so the probe never collides with a
#: post-init poll.  Within the BASIC RS-232 stash area which the C64
#: KERNAL never touches without explicit I/O.
WRITEMEM_PROBE_ADDR = 0x02A9

#: Distinctive payload (avoids 0x00 / 0xFF so a stuck readback can't masquerade
#: as success).  Length 64 forces the POST raw-byte path when paired with
#: ``write_mem_query_threshold=0`` — see :func:`writemem_health_probe`.
_WRITEMEM_PROBE_PAYLOAD = bytes(((0xA5 ^ i) & 0xFF) for i in range(64))


def writemem_health_probe(host, *, password=None,
                          addr=WRITEMEM_PROBE_ADDR,
                          timeout=10.0):
    """Detect the U64E 3.14d POST /v1/machine:writemem 404 degradation.

    The firmware bug surfaces as **HTTP 404 "Could not read data from
    attachment"** on the POST raw-byte form of ``write_mem``; the PUT
    ``?data=<hex>`` form keeps working through it.  ``probe_u64(...).reachable``
    only exercises GET endpoints and so cannot see this state.  The bug
    clears only via physical power-cycle; ``reset`` / ``reboot`` over REST
    may NOT recover it, and repeated POST hits against the degraded endpoint
    can wedge the entire TCP stack.

    This probe builds a one-shot :class:`Ultimate64Client` with
    ``write_mem_query_threshold=0`` to FORCE the POST path regardless of
    detected firmware version, writes a 64-byte distinctive payload to
    *addr*, reads it back, and verifies the round-trip.  On a healthy
    device this is a few hundred ms.

    Returns ``(ok: bool, reason: str)``.  ``ok=True`` only when the
    round-trip matches byte-for-byte.  On HTTP 404 the *reason* names
    the bug explicitly so the operator knows a power-cycle is needed.
    """
    try:
        # write_mem_query_threshold=0 forces POST for any non-empty
        # payload, bypassing the autodetected 128-byte cutoff that
        # would otherwise route this through the safe PUT path.
        probe_client = Ultimate64Client(
            host=host, password=password, timeout=timeout,
            write_mem_query_threshold=0,
        )
    except Exception as e:
        return False, f"client construct failed: {type(e).__name__}: {e}"
    try:
        probe_client.write_mem(addr, _WRITEMEM_PROBE_PAYLOAD)
    except Ultimate64Error as e:
        status = getattr(e, "status", None)
        body = getattr(e, "body", "") or ""
        if status == 404 and "attachment" in body.lower():
            return False, (
                "POST /v1/machine:writemem returned HTTP 404 "
                "'Could not read data from attachment' — device is in "
                "writemem-degraded state, physical power-cycle required "
                "(reset/reboot over REST does NOT clear this)"
            )
        return False, (
            f"write_mem failed: HTTP {status} {type(e).__name__}: "
            f"{str(e)[:200]}"
        )
    except Exception as e:
        return False, f"write_mem raised {type(e).__name__}: {e}"
    try:
        got = probe_client.read_mem(addr, len(_WRITEMEM_PROBE_PAYLOAD))
    except Exception as e:
        return False, f"read_mem raised {type(e).__name__}: {e}"
    if got != _WRITEMEM_PROBE_PAYLOAD:
        return False, (
            f"readback mismatch (wrote {len(_WRITEMEM_PROBE_PAYLOAD)} bytes, "
            f"got {len(got)} bytes; first 8 wrote="
            f"{_WRITEMEM_PROBE_PAYLOAD[:8].hex()} got={got[:8].hex()})"
        )
    return True, "writemem POST round-trip OK"


def run_one_routine(transport, labels, main_loop_addr,
                    routine_name, loops, setup_fn, verify_fn, timeout,
                    retries: int = 2):
    """Run a routine with up to `retries` attempts on UNVERIFIED/TIMEOUT.

    On each retry the main_loop is parked and a brief settle delay is
    inserted before re-attempting. The first OK result wins; otherwise
    the last attempt's result is returned.
    """
    last = None
    for attempt in range(retries + 1):
        if attempt > 0:
            try:
                park_main_loop(transport, main_loop_addr)
            except Exception:
                pass
            time.sleep(0.3)
        try:
            res = _run_one_routine_once(
                transport, labels, main_loop_addr,
                routine_name, loops, setup_fn, verify_fn, timeout)
        except Exception as e:
            res = {"ok": False, "jiffies": 0, "cycles": None, "ms": None,
                   "wall": 0.0, "reason": f"EXC:{type(e).__name__}"}
        last = res
        if res["ok"]:
            if attempt > 0:
                res["reason"] = f"OK(retry{attempt})"
            return res
    return last
