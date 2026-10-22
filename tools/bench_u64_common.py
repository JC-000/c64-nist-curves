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

import logging
import os
import sys
import time

# One harness, resolved one way.  A sys.path shim used to sit here naming
# an absolute Linux checkout and inserting it at position 0 — inert on a
# Mac, but wherever that directory existed it silently decided which
# c64_test_harness (and therefore which device-capability table, which is
# what picks PUT over the leaking POST) the whole run loaded.  Deleted:
# the editable install resolves on its own, and a second copy is a hazard,
# not a convenience.  `print_harness_provenance` below makes the resolved
# path visible instead of assumed.

# /Temp hygiene is deliberately NOT forced here.  The harness arms it from
# device capability -- `runner_wedge_possible is not False`, so leak-prone
# and unknown firmware arm, and a device carrying the upstream collector
# (U64E 3.15+) disarms -- and it accounts for attachments at the request
# layer, so every POST-with-body is covered, not just uploads.  Setting
# `U64_AUTO_TEMP_GC=1` would *force* the pass on for ANY device and
# override that decision from our side, which is the call-site policy
# ownership this repo is trying not to take.  An operator can still force
# it either way through the environment for a one-off.

# Hard-fail a device call that is not under the DeviceLock, rather than
# trusting every entry point to remember.  Matches test_reu_mul_u64.py.
os.environ.setdefault("U64_REQUIRE_DEVICE_LOCK", "1")

from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (  # noqa: E402
    Ultimate64Client,
)
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    get_turbo_mhz,
    set_turbo_mhz,
    set_reu,
    snapshot_state,
    restore_state,
)
# Not guarded: public schema names that set_turbo_mhz (imported
# unconditionally above) depends on -- ultimate64_helpers imports
# CPU_SPEED_VALUES and cpu_speed_mhz from this module itself, and its
# cpu_speed_enum reads CPU_SPEED_BY_MHZ -- so a harness without them could
# not run set_turbo_mhz either; a guard would only defer the failure.
from c64_test_harness.backends.ultimate64_schema import (  # noqa: E402
    CPU_SPEED_BY_MHZ,
    CPU_SPEED_VALUES,
    cpu_speed_mhz,
)
try:
    # Private, but it is the probe set_turbo_mhz itself validates with.
    from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
        _cpu_speed_presets,
    )
except ImportError:  # harness without it: every probe is inconclusive
    print("WARN: c64_test_harness has no _cpu_speed_presets; every probe is "
          "inconclusive, so resolve_sweep_speeds refuses every sweep until "
          "this tool is ported to the harness's replacement", file=sys.stderr)

    def _cpu_speed_presets(client):
        return None
from c64_test_harness.backends.device_lock import (  # noqa: E402
    DeviceLock,
    DeviceLockTimeout,
)
from c64_test_harness.backends.ultimate64_probe import (  # noqa: E402
    probe_u64,
    liveness_probe,
)
from c64_test_harness.labels import Labels  # noqa: E402


ALL_SPEEDS = sorted(CPU_SPEED_BY_MHZ)
# The harness schema's cross-generation SUPERSET -- no single device has
# all of these (C64U lacks 5, U64E lacks 64).  Only an offline typo check;
# the sweep itself comes from resolve_sweep_speeds(), which asks the
# connected device.

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


PROBE_ATTEMPTS = 3
REFUSAL_PREFIX = "refusing before any reboot or upload: "


def resolve_sweep_speeds(client, requested):
    """Return the speeds to sweep, validated BEFORE any reboot or upload.

    The CPU Speed presets differ per device generation (C64U fw 1.1.0 has
    64 and no 5, U64E the reverse) and the harness owns that knowledge:
    `set_turbo_mhz` validates against the device's own preset list, read by
    the harness's `_cpu_speed_presets` (one bodyless GET, cached per
    client; no public accessor exists).  We ask the same probe, so the
    up-front verdict here is exactly the one set_turbo_mhz would reach
    mid-sweep after a reboot and a run_prg had already been spent.

    requested=None (no --speeds) -> every speed the device reports.
    An explicit list containing a speed the device rejects -> ValueError.

    Inconclusive probe (GET failed / unexpected shape / no schema speed in
    it / harness without the helper): retried PROBE_ATTEMPTS times, then
    REFUSED -- for an explicit --speeds as well as a bare run.  Fail-closed
    on purpose: the harness does not cache an inconclusive answer, so a
    transient failure here followed by a good GET inside set_turbo_mhz
    would reject a foreign speed mid-sweep, after reboots and uploads --
    the crash-late behaviour this function exists to prevent.  The only
    list we could fall back to is the schema superset, which is known to
    contain a speed each generation rejects.  The operator re-runs once
    the device answers.
    """
    supported = None
    for attempt in range(PROBE_ATTEMPTS):
        if attempt:
            time.sleep(1.0)
        try:
            presets = _cpu_speed_presets(client)
        except Exception:
            presets = None
        if presets is not None:
            supported = sorted(cpu_speed_mhz(p) for p in presets
                               if p in CPU_SPEED_VALUES) or None
        if supported is not None:
            break
    bad = [m for m in (requested or []) if m not in ALL_SPEEDS
           or (supported is not None and m not in supported)]
    if bad:
        raise ValueError(
            f"{REFUSAL_PREFIX}speed(s) {bad} not supported by this device; "
            f"supported: "
            f"{supported if supported is not None else ALL_SPEEDS}")
    if supported is None:
        raise ValueError(
            f"{REFUSAL_PREFIX}could not read this device's CPU Speed presets "
            f"after {PROBE_ATTEMPTS} attempts, so the speeds cannot be checked "
            f"before the sweep reboots it; re-run once the device answers")
    return list(requested) if requested else supported


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


def print_harness_provenance():
    """Print which c64_test_harness was loaded, and its hygiene switches.

    The harness is the single choke point for device traffic: it owns the
    PUT/POST decision, the ``/Temp`` budget and hygiene pass, and whether
    hygiene arms at all (from the device's firmware capability).  All of
    that is a property of *the copy that got imported*, so which copy that
    is belongs in the run log rather than in an assumption.  The env
    overrides are printed because they are the one way a run can differ
    from what the harness would have decided on its own -- ``<unset>`` is
    the expected and preferred state for the hygiene one.
    Cheap: no network, no device.
    """
    # Install the handler first: the harness logs its device grading from
    # inside Ultimate64Client.__init__, and every caller constructs the
    # client after taking the lock, so arming the handler here is what
    # makes that grading visible at all.
    enable_harness_logging()
    import c64_test_harness
    print(f"  harness: {c64_test_harness.__file__}")
    print(f"  overrides: U64_AUTO_TEMP_GC="
          f"{os.environ.get('U64_AUTO_TEMP_GC', '<unset>')} "
          f"U64_REQUIRE_DEVICE_LOCK="
          f"{os.environ.get('U64_REQUIRE_DEVICE_LOCK', '<unset>')}")


def enable_harness_logging(level=logging.INFO):
    """Surface the harness's own device-grading and hygiene messages.

    Without a handler, ``log_device_grading()`` (INFO) is dropped, so the
    run log shows the *override* we asked for and never the decision the
    harness actually reached — which is the more useful of the two. The
    disarmed-hygiene message is a WARNING and would reach stderr through
    ``logging.lastResort`` anyway, but only as a bare line with no level
    or logger name; routing both through one handler keeps them legible
    and in order with our own output.

    Idempotent: repeated calls do not stack handlers.
    """
    log = logging.getLogger("c64_test_harness")
    if any(getattr(h, "_nistcurves_bench", False) for h in log.handlers):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("  [harness] %(levelname)s %(message)s"))
    handler._nistcurves_bench = True
    log.addHandler(handler)
    log.setLevel(level)


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
        print_harness_provenance()
    except Exception as e:  # pragma: no cover - defensive
        print(f"  harness: WARN could not report provenance "
              f"({type(e).__name__}: {e})", flush=True)
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


# --------------------------------------------------------------------------
# Offline self-test (no device, no VICE):
#   make check-bench-tools   (= python3 tools/bench_u64_common.py --self-test)
# Drives resolve_sweep_speeds + reboot_and_prepare, then the REAL main() of
# bench_p256/p384/ecdsa_u64 and test_reu_mul_u64, against fake clients that
# answer the harness's CPU Speed probe the way each device generation does
# (or fail it), so the harness's own set_turbo_mhz validation runs for real.
# --------------------------------------------------------------------------

# Preset strings as the devices report them (harness docstring,
# _cpu_speed_presets: C64U fw 1.1.0 has "64" and no " 5"; U64E fw 3.14
# the reverse).  Test fixtures only -- the tools never read these.
_FAKE_C64U_PRESETS = [" 1", " 2", " 3", " 4", " 6", " 8", "10", "12", "14",
                      "16", "20", "24", "32", "40", "48", "64"]
_FAKE_U64E_PRESETS = [" 1", " 2", " 3", " 4", " 5", " 6", " 8", "10", "12",
                      "14", "16", "20", "24", "32", "40", "48"]


class _FakeClient:
    """Records every device-mutating call; answers config GETs."""

    def __init__(self, cpu_presets, fail_first=0):
        self.cpu_presets = cpu_presets    # None -> probe always fails
        self.fail_first = fail_first      # first N CPU Speed GETs fail
        self.probe_calls = 0
        self.events = []

    def get_info(self):
        return {"product": "fake", "firmware_version": "1.1.0",
                "unique_id": "fake0"}

    def get_config_item(self, category, item):
        if item == "CPU Speed":
            self.probe_calls += 1
            if (self.cpu_presets is None
                    or self.probe_calls <= self.fail_first):
                from c64_test_harness.backends.ultimate64_client import (
                    Ultimate64Error)
                raise Ultimate64Error("simulated probe failure")
            return {"current": "48", "values": list(self.cpu_presets),
                    "default": " 1"}
        return {"current": "", "presets": [""], "default": ""}

    def set_config_items(self, category, updates):
        self.events.append(("set", category, dict(updates)))

    def reboot(self):
        self.events.append(("reboot",))

    def run_prg(self, data):
        self.events.append(("run_prg", len(data)))


class _FakeTransport:
    def __init__(self, client=None):
        self.client = client

    def close(self):
        if self.client is not None:
            self.client.events.append(("close",))

    def read_memory(self, addr, length):
        return bytes([INIT_SENTINEL_VAL]) * length

    def write_memory(self, addr, data):
        pass

    def resume(self):
        pass


def _simulate_main(client, requested):
    """resolve, then sweep -- what bench_p256/p384/ecdsa_u64 main() does.

    Returns (speeds or None, exception or None, events before it).
    """
    import contextlib
    import io
    speeds = None
    try:
        speeds = resolve_sweep_speeds(client, requested)
        with contextlib.redirect_stdout(io.StringIO()):
            for mhz in speeds:
                reboot_and_prepare(client, _FakeTransport(), b"\x01\x08", mhz)
    except (ValueError, SystemExit) as e:
        return speeds, e, list(client.events)
    return speeds, None, list(client.events)


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _FakeLabels:
    @classmethod
    def from_file(cls, path):
        return cls()

    def address(self, name):
        return 0x1000

    def __getitem__(self, name):
        return 0x1000


def _drive_bench_main(modname, argv, client, prg_path):
    """Run a bench tool's REAL main() against `client`.

    Only the device seams are replaced (probe, lock, liveness, client and
    transport constructors, snapshot/restore, labels, summary).  The
    per-speed body is replaced by a stub that records the speed and then
    calls the tool's real reboot_and_prepare, so the harness's
    set_turbo_mhz validation runs where the sweep would run it.  Whatever
    order main() puts resolve_sweep_speeds in is what gets tested.

    Returns (exit code or exception, client.events).
    """
    import contextlib
    import importlib
    import io
    m = importlib.import_module(modname)
    transport = _FakeTransport(client)

    def sweep(client_, transport_, prg_data, labels, mhz, args):
        client_.events.append(("sweep", mhz))
        m.reboot_and_prepare(client_, transport_, prg_data, mhz)
        return {}

    patches = {
        "probe_u64": lambda host, **kw: _Obj(reachable=True),
        "acquire_device_lock_or_exit":
            lambda host, **kw: _Obj(release=lambda: None),
        "liveness_probe": lambda host, **kw: _Obj(
            healthy=True, summary="fake", recommendation=None),
        "Ultimate64Client": lambda **kw: client,
        "Ultimate64Transport": lambda **kw: transport,
        "snapshot_state": lambda c: None,
        "restore_state": lambda c, s: None,
        "get_turbo_mhz": lambda c: None,
        "Labels": _FakeLabels,
        "run_sweep_for_speed": sweep,
        "print_summary": lambda *a, **k: None,
    }
    saved = {k: getattr(m, k) for k in patches if hasattr(m, k)}
    saved_argv = sys.argv
    saved_host = os.environ.get("U64_HOST")
    for k, v in patches.items():
        setattr(m, k, v)
    sys.argv = [modname + ".py", "--prg", prg_path,
                "--labels", prg_path] + list(argv)
    os.environ["U64_HOST"] = "fake.invalid"
    result = 0
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            m.main()
    except SystemExit as e:
        result = e.code
    except Exception as e:
        result = e
    finally:
        for k, v in saved.items():
            setattr(m, k, v)
        sys.argv = saved_argv
        if saved_host is None:
            os.environ.pop("U64_HOST", None)
        else:
            os.environ["U64_HOST"] = saved_host
    return result, list(client.events)


class _ReachedSnapshot(Exception):
    pass


def _drive_reu_probe_main(argv, client, prg_path):
    """Run test_reu_mul_u64.main(argv) up to its snapshot_state call.

    Its harness imports are function-local, so the seams are patched on
    the harness modules themselves.  snapshot_state raises
    _ReachedSnapshot: reaching it means the speed check let the run on.
    Returns (rc or exception, client.events).
    """
    import contextlib
    import importlib
    import io
    from c64_test_harness.backends import device_lock as dl_mod
    from c64_test_harness.backends import ultimate64 as u64_mod
    from c64_test_harness.backends import ultimate64_helpers as hl_mod
    from c64_test_harness.backends import ultimate64_probe as pr_mod
    m = importlib.import_module("test_reu_mul_u64")

    class _Lock:
        def __init__(self, host):
            pass

        @staticmethod
        def cleanup_stale():
            pass

        def release(self):
            pass

    def snap(c):
        raise _ReachedSnapshot()

    transport = _FakeTransport(client)
    seams = [(dl_mod, "DeviceLock", _Lock),
             (u64_mod, "Ultimate64Transport", lambda **kw: transport),
             (pr_mod, "probe_u64", lambda host, **kw: _Obj(reachable=True)),
             (hl_mod, "snapshot_state", snap),
             (m, "acquire_device_lock", lambda lock, wait, t: 0)]
    saved = [(mod, name, getattr(mod, name)) for mod, name, _ in seams]
    saved_host = os.environ.get("U64_HOST")
    for mod, name, val in seams:
        setattr(mod, name, val)
    os.environ["U64_HOST"] = "fake.invalid"
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            result = m.main(["--prg", prg_path, "--labels", prg_path]
                            + list(argv))
    except Exception as e:
        result = e
    finally:
        for mod, name, val in saved:
            setattr(mod, name, val)
        if saved_host is None:
            os.environ.pop("U64_HOST", None)
        else:
            os.environ["U64_HOST"] = saved_host
    return result, list(client.events)


def self_test() -> int:
    fails = []

    def check(name, cond, detail=""):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}"
              + (f"  {detail}" if detail and not cond else ""))
        if not cond:
            fails.append(name)

    def mutations(events):
        return sum(1 for e in events if e[0] in ("reboot", "run_prg"))

    real_sleep = time.sleep
    time.sleep = lambda s: None
    try:
        for dev, presets, foreign in (("C64U", _FAKE_C64U_PRESETS, 5),
                                      ("U64E", _FAKE_U64E_PRESETS, 64)):
            want = [int(p) for p in presets]
            speeds, exc, ev = _simulate_main(_FakeClient(presets), None)
            check(f"{dev}: default sweep == device presets", speeds == want,
                  f"got {speeds}")
            check(f"{dev}: default sweep completes", exc is None,
                  f"{type(exc).__name__}: {exc} after "
                  f"{mutations(ev)} reboot/run_prg calls")
            speeds, exc, ev = _simulate_main(_FakeClient(presets),
                                             [16, foreign])
            check(f"{dev}: --speeds 16,{foreign} rejected before any "
                  f"reboot/upload", exc is not None and mutations(ev) == 0,
                  f"exc={exc!r} after {mutations(ev)} reboot/run_prg calls")
            check(f"{dev}: rejection is the up-front one and names the "
                  f"speed",
                  exc is not None and mutations(ev) == 0
                  and str(exc).startswith(REFUSAL_PREFIX)
                  and str(foreign) in str(exc),
                  f"exc={exc!r} after {mutations(ev)} reboot/run_prg calls")
            speeds, exc, ev = _simulate_main(_FakeClient(presets), [48, 16])
            check(f"{dev}: supported --speeds 48,16 kept in order",
                  exc is None and speeds == [48, 16],
                  f"speeds={speeds} exc={exc!r}")

        speeds, exc, ev = _simulate_main(_FakeClient(None), None)
        check("inconclusive probe: default sweep refused up front",
              exc is not None and mutations(ev) == 0,
              f"speeds={speeds} exc={exc!r} after {mutations(ev)} "
              f"reboot/run_prg calls")
        c = _FakeClient(None)
        speeds, exc, ev = _simulate_main(c, [16, 48])
        check("inconclusive probe: explicit --speeds refused up front too",
              exc is not None and mutations(ev) == 0
              and str(exc).startswith(REFUSAL_PREFIX),
              f"speeds={speeds} exc={exc!r} after {mutations(ev)} "
              f"reboot/run_prg calls")
        check(f"inconclusive probe: retried {PROBE_ATTEMPTS} times before "
              f"refusing", c.probe_calls == PROBE_ATTEMPTS,
              f"probe_calls={c.probe_calls}")
        speeds, exc, ev = _simulate_main(_FakeClient(None), [16, 7])
        check("inconclusive probe: non-schema speed 7 still rejected",
              exc is not None and mutations(ev) == 0,
              f"speeds={speeds} exc={exc!r}")

        # Flaky probe: the harness does not cache an inconclusive answer,
        # so a first GET that fails and a later one that succeeds would
        # let a foreign speed through resolve and crash in set_turbo_mhz.
        speeds, exc, ev = _simulate_main(
            _FakeClient(_FAKE_U64E_PRESETS, fail_first=1), [16, 64])
        check("flaky probe (1st GET fails): U64E --speeds 16,64 rejected "
              "before any reboot/upload",
              exc is not None and mutations(ev) == 0,
              f"speeds={speeds} exc={exc!r} after {mutations(ev)} "
              f"reboot/run_prg calls")
        speeds, exc, ev = _simulate_main(
            _FakeClient(_FAKE_C64U_PRESETS, fail_first=2), None)
        check("flaky probe (2 GETs fail): C64U default sweep recovers",
              exc is None and speeds == [int(p) for p in _FAKE_C64U_PRESETS],
              f"speeds={speeds} exc={exc!r}")

        # The real tools' main(): resolve must run before the first
        # reboot, and a refusal must close the transport.
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".prg", delete=False) as f:
            f.write(b"\x01\x08\x00\x00")
            prg_path = f.name
        try:
            c64u = [int(p) for p in _FAKE_C64U_PRESETS]
            for tool, bare in (("bench_p256_u64", c64u),
                               ("bench_p384_u64", c64u),
                               ("bench_ecdsa_u64", [16, 48])):
                rc, ev = _drive_bench_main(
                    tool, ["--speeds", "16,5"],
                    _FakeClient(_FAKE_C64U_PRESETS), prg_path)
                check(f"{tool}.main(): C64U --speeds 16,5 exits 2 before "
                      f"any reboot/upload",
                      rc == 2 and mutations(ev) == 0,
                      f"rc={rc!r} after {mutations(ev)} reboot/run_prg "
                      f"calls")
                check(f"{tool}.main(): refusal closes the transport",
                      rc == 2 and ("close",) in ev,
                      f"rc={rc!r} close={('close',) in ev}")
                rc, ev = _drive_bench_main(
                    tool, [], _FakeClient(_FAKE_C64U_PRESETS), prg_path)
                swept = [e[1] for e in ev if e[0] == "sweep"]
                check(f"{tool}.main(): C64U bare run sweeps {bare}",
                      rc in (0, None) and swept == bare,
                      f"rc={rc!r} swept={swept}")

            reu = "test_reu_mul_u64"
            for argv, what in ((["--speeds", "48,5"], "--speeds 48,5"),
                               (["--boot-mhz", "5"], "--boot-mhz 5")):
                rc, ev = _drive_reu_probe_main(
                    argv, _FakeClient(_FAKE_C64U_PRESETS), prg_path)
                check(f"{reu}.main(): C64U {what} refused (rc 2) before "
                      f"snapshot/reboot/upload",
                      rc == 2 and mutations(ev) == 0,
                      f"rc={rc!r} after {mutations(ev)} reboot/run_prg "
                      f"calls")
            rc, ev = _drive_reu_probe_main(
                ["--speeds", "48,16"], _FakeClient(_FAKE_C64U_PRESETS),
                prg_path)
            check(f"{reu}.main(): C64U --speeds 48,16 gets past the check",
                  isinstance(rc, _ReachedSnapshot), f"rc={rc!r}")
        finally:
            os.unlink(prg_path)
    finally:
        time.sleep = real_sleep

    print(f"\nself-test: {'ALL PASS' if not fails else f'{len(fails)} FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    print("usage: bench_u64_common.py --self-test")
    sys.exit(2)
