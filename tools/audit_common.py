"""audit_common.py -- shared helpers for the adversarial test entrypoints.

Used by tools/test_ecdsa_adversarial.py and tools/test_prims_adversarial.py
(ported from the 2026-08-28 hazmat audit, .research/adversarial_audit_2026_08_28).

What lives here:

  * Boot: the canonical ViceInstanceManager + $02A7-sentinel pattern from
    tools/test_points384.py (transport.resume() after EVERY poll --
    binmon reads pause emulation), C64_INIT_TIMEOUT default 900 s.
    Never launches x64sc directly. ONE boot per entrypoint.
  * Suite: the RED/GREEN case recorder. Every case records expected and
    got; a case whose verdict is FAIL but which carries an
    `expect_fixed_by` tag (a finding id such as "F-1") is reported as
    RED(known) instead of FAIL, is counted separately, and does NOT fail
    the run -- unless `--strict` is given, in which case it does. INFO
    rows record documented-but-uncontracted behaviour and never fail.
  * Per-case timeout: `Suite.timed()` runs one C64 call under the jsr()
    timeout; a c64_test_harness TimeoutError becomes a FAIL (or
    RED(known)) row with got="HANG/timeout", and the transport is then
    recovered (restore SP, re-arm the trampoline) so the remaining cases
    still run. A hang is a row, not a wedged run.
  * Byte helpers (LE field elements, BE structs, ZP pointer pokes) and
    the 6502 flag decoder for the register dict jsr() returns.
  * Optional JSONL record of every row (`--record PATH`).

Oracle discipline (tools/vectors/README.md): nothing in this module or
its callers takes an expected value from a C64 run. Expected values come
from cryptography.hazmat, hashlib, Python int arithmetic, and the
self-checked affine group law in tools/vectors/loader.py.
"""

import json
import os
import secrets
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, read_bytes, write_bytes, jsr,
)
from c64_test_harness.transport import TimeoutError as HarnessTimeout

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PRG_PATH = os.path.join(PROJECT_ROOT, "build",
                        os.environ.get("C64_PRG_NAME", "nist-curves.prg"))
LABELS_PATH = os.path.join(PROJECT_ROOT, "build",
                           os.environ.get("C64_LABELS_NAME", "labels.txt"))

# Cassette-buffer scratch: the harness jsr() trampoline is $0334-$0338, the
# suites' JMP-self guard is $0339-$033B, and the BE scalar staging buffer
# starts at $033C (48 B -> $036B). None overlap.
GUARD_ADDR = 0x0339
SCALAR_BUF = 0x033C

# 6502 status-register bit positions.
FLAG_C = 0x01
FLAG_Z = 0x02
FLAG_N = 0x80


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv, usage):
    """Common flags: --seed N, --full, --verbose, --strict, --record PATH."""
    opts = {"seed": None, "full": False, "verbose": False, "strict": False,
            "record": None, "extra": []}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--seed" and i + 1 < len(argv):
            opts["seed"] = int(argv[i + 1])
            i += 2
        elif a == "--record" and i + 1 < len(argv):
            opts["record"] = argv[i + 1]
            i += 2
        elif a == "--full":
            opts["full"] = True
            i += 1
        elif a == "--verbose":
            opts["verbose"] = True
            i += 1
        elif a == "--strict":
            opts["strict"] = True
            i += 1
        elif a in ("-h", "--help"):
            print(usage)
            sys.exit(0)
        else:
            opts["extra"].append(a)
            i += 1
    if opts["seed"] is None:
        opts["seed"] = secrets.randbits(64)
    return opts


def warn_if_vice_running():
    try:
        res = subprocess.run(["pgrep", "-c", "x64sc"], capture_output=True,
                             text=True, timeout=2)
        n = int(res.stdout.strip() or "0")
        if n > 0:
            print(f"WARNING: {n} other x64sc instance(s) already running - "
                  f"wall-clock timings may be unreliable.", file=sys.stderr)
    except Exception:
        pass


def build_prg():
    """`make clean && make` unless C64_SKIP_BUILD is set (same as the other
    entrypoints). Exits on failure."""
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True,
                       cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stdout}\n{result.stderr}")
            sys.exit(1)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found after build")
        sys.exit(1)
    print(f"Built: {PRG_PATH}")


def load_labels(required=()):
    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: required labels missing: {', '.join(missing)}")
        sys.exit(1)
    return labels


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

class Machine:
    """One booted VICE. Use as a context manager; yields itself with
    `.transport` ready (init sentinel seen, $0339 guard planted)."""

    def __init__(self, init_timeout=None):
        if init_timeout is None:
            init_timeout = float(os.environ.get("C64_INIT_TIMEOUT", "900"))
        self.init_timeout = init_timeout
        if os.environ.get("C64_NO_REU"):
            reu_args = ["+reu"]
        else:
            reu_args = ["-reu", "-reusize", "512"]
        self.config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False, extra_args=reu_args)
        self.mgr = None
        self.inst = None
        self.transport = None

    def __enter__(self):
        self.mgr = ViceInstanceManager(config=self.config)
        self.mgr.__enter__()
        try:
            self.inst = self.mgr.acquire()
            self.transport = self.inst.transport
            print(f"VICE PID={self.inst.pid}, port={self.inst.port}")
            print("Waiting for init sentinel...")
            start = time.time()
            ok = False
            while time.time() - start < self.init_timeout:
                sentinel = read_bytes(self.transport, 0x02A7, 1)
                if sentinel[0] == 0x42:
                    ok = True
                    break
                try:
                    self.transport.resume()
                except Exception:
                    pass
                time.sleep(0.5)
            if not ok:
                raise RuntimeError(
                    f"init sentinel not set within {self.init_timeout:.0f}s")
            print(f"Init complete after {time.time() - start:.1f}s")
            write_bytes(self.transport, GUARD_ADDR, bytes([0x4C, 0x39, 0x03]))
        except Exception:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *exc):
        try:
            if self.inst is not None:
                self.mgr.release(self.inst)
        finally:
            self.mgr.__exit__(None, None, None)
        return False


def recover_after_hang(transport, saved_sp):
    """After a jsr() timeout the CPU is still spinning inside the hung
    routine. Binmon commands still work (they pause the machine), so we
    restore the stack pointer captured before the call and re-arm the
    trampoline with a known RTS. Returns True on success."""
    rts_addr = SCALAR_BUF          # scratch; every scalar case rewrites it
    try:
        transport.read_registers()
        if saved_sp is not None:
            transport.set_registers({"SP": saved_sp})
        write_bytes(transport, rts_addr, bytes([0x60]))
        regs = jsr(transport, rts_addr, timeout=10.0)
        return regs.get("PC") == 0x0337
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Byte helpers
# ---------------------------------------------------------------------------

def le(v, n):
    return v.to_bytes(n, "little")


def be(v, n):
    return v.to_bytes(n, "big")


def from_le(b):
    return int.from_bytes(b, "little")


def set_ptr(transport, zp_addr, target):
    write_bytes(transport, zp_addr,
                bytes([target & 0xFF, (target >> 8) & 0xFF]))


def build_be_struct(r, s, h, qx, qy, nbytes):
    """Pack the ecdsa_verify_* input struct: r|s|h|Qx|Qy, all BE."""
    return be(r, nbytes) + be(s, nbytes) + be(h, nbytes) + be(qx, nbytes) \
        + be(qy, nbytes)


def flags_of(regs):
    """(C, Z) from the register dict jsr() returns (key 'FL')."""
    fl = regs.get("FL")
    if fl is None:
        fl = regs.get("FLAGS", regs.get("SR"))
    if fl is None:
        return None, None
    return fl & FLAG_C, 1 if (fl & FLAG_Z) else 0


# ---------------------------------------------------------------------------
# Suite: RED/GREEN recorder with per-case timeout
# ---------------------------------------------------------------------------

class Suite:
    VERDICTS = ("PASS", "FAIL", "RED", "INFO")

    def __init__(self, name, strict=False, record=None, verbose=False):
        self.name = name
        self.strict = strict
        self.verbose = verbose
        self.n_pass = self.n_fail = self.n_red = self.n_info = 0
        self.red_rows = []
        self.fail_rows = []
        self.fp = open(record, "a") if record else None
        self.t_start = time.time()
        self._emit({"event": "start", "suite": name, "time": self.t_start})

    def _emit(self, rec):
        if self.fp:
            self.fp.write(json.dumps(rec, default=str) + "\n")
            self.fp.flush()

    def note(self, msg):
        print(msg, flush=True)
        self._emit({"event": "note", "msg": msg})

    def case(self, section, label, expected, got, *, verdict=None,
             expect_fixed_by=None, detail=None, dt=None):
        """Record one row.

        verdict None  -> PASS if expected == got else FAIL
        verdict INFO  -> documented/uncontracted behaviour, never fails
        expect_fixed_by="F-n" -> a FAIL becomes RED(known F-n) unless the
                                 suite runs --strict.
        """
        if verdict is None:
            verdict = "PASS" if expected == got else "FAIL"
        known = None
        if verdict == "FAIL" and expect_fixed_by and not self.strict:
            verdict = "RED"
            known = expect_fixed_by
        if verdict == "PASS":
            self.n_pass += 1
        elif verdict == "FAIL":
            self.n_fail += 1
            self.fail_rows.append(f"{section} :: {label}")
        elif verdict == "RED":
            self.n_red += 1
            self.red_rows.append(f"{section} :: {label} [{known}]")
        else:
            self.n_info += 1
        rec = {"section": section, "label": label, "verdict": verdict,
               "expected": expected, "got": got, "dt": dt,
               "expect_fixed_by": expect_fixed_by}
        if detail:
            rec["detail"] = detail
        self._emit(rec)
        tag = verdict if verdict != "RED" else f"RED(known {known})"
        if verdict == "PASS" and expect_fixed_by:
            tag = f"PASS (was expected red under {expect_fixed_by})"
        line = f"  {tag} [{section}] {label}"
        if dt is not None:
            line += f" ({dt:.1f}s)"
        if verdict != "PASS" or self.verbose:
            line += f"\n      expected={_short(expected)}\n      got     ={_short(got)}"
            if detail:
                line += f"\n      detail  ={_short(detail)}"
        print(line, flush=True)

    def timed(self, section, label, fn, expected, *, transport,
              expect_fixed_by=None, detail=None, post=None):
        """Run fn() (one or more C64 calls) under the harness jsr timeout.

        A TimeoutError (or any transport exception) becomes a row with
        got='HANG/timeout ...'; the transport is then recovered so the
        next case can run. `post` maps the raw return of fn() to the value
        compared against `expected` (identity when None)."""
        saved_sp = None
        try:
            saved_sp = transport.read_registers().get("SP")
        except Exception:
            pass
        t0 = time.time()
        try:
            raw = fn()
        except HarnessTimeout as e:
            dt = time.time() - t0
            ok = recover_after_hang(transport, saved_sp)
            d = dict(detail or {})
            d["recovered"] = ok
            self.case(section, label, expected, f"HANG/timeout: {e}",
                      expect_fixed_by=expect_fixed_by, detail=d, dt=dt)
            if not ok:
                raise RuntimeError(
                    "transport not recoverable after hang") from e
            return None
        except Exception as e:
            dt = time.time() - t0
            self.case(section, label, expected, f"EXC: {e!r}",
                      expect_fixed_by=expect_fixed_by, detail=detail, dt=dt)
            return None
        dt = time.time() - t0
        got = post(raw) if post else raw
        self.case(section, label, expected, got,
                  expect_fixed_by=expect_fixed_by, detail=detail, dt=dt)
        return raw

    def summary(self, seed=None, mode=None):
        dt = time.time() - self.t_start
        print(f"\n{'=' * 60}")
        if self.red_rows:
            print("Red-known rows:")
            for r in self.red_rows:
                print(f"  RED  {r}")
        if self.fail_rows:
            print("Failed rows:")
            for r in self.fail_rows:
                print(f"  FAIL {r}")
        known = sorted({r.rsplit("[", 1)[1].rstrip("]")
                        for r in self.red_rows}) or ["F-1"]
        print(f"Results: {self.n_pass} passed, {self.n_fail} failed, "
              f"{self.n_red} red-known ({', '.join(known)})"
              + (f", {self.n_info} info" if self.n_info else ""))
        if mode is not None:
            print(f"Mode: {mode}  Seed: {seed}  Strict: {self.strict}  "
                  f"Wall: {dt / 60:.1f} min")
        print(f"{'=' * 60}")
        self._emit({"event": "end", "pass": self.n_pass, "fail": self.n_fail,
                    "red": self.n_red, "info": self.n_info, "time": time.time()})
        if self.fp:
            self.fp.close()
        return self.n_fail == 0


def _short(v):
    s = repr(v)
    if isinstance(v, int) and v > 0xFFFF:
        s = hex(v)
    return s if len(s) <= 200 else s[:197] + "..."
