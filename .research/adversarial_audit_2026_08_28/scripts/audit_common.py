"""Shared boot / logging helpers for the adversarial audit scripts.

Boots VICE exactly the way tools/test_points384.py does (ViceInstanceManager,
$02A7 sentinel poll with transport.resume() after every poll). Never launches
x64sc directly. Read-only with respect to the repository.
"""
import json
import os
import sys
import time

PROJECT_ROOT = "/Users/someone/Documents/c64-nist-curves"
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))

from c64_test_harness import (  # noqa: E402
    Labels, ViceConfig, ViceInstanceManager, read_bytes, write_bytes, jsr,
)

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
SCALAR_BUF = 0x033C          # cassette buffer, same slot the point tests use

AUDIT_DIR = os.path.dirname(os.path.abspath(__file__))


class Log:
    """Append-only JSONL + human log. Every case records expected/actual."""

    def __init__(self, name):
        self.path = os.path.join(AUDIT_DIR, name + ".jsonl")
        self.txt = os.path.join(AUDIT_DIR, name + ".log")
        self.n_pass = self.n_fail = self.n_info = 0
        self.fp = open(self.path, "a")
        self.tp = open(self.txt, "a")
        self.emit({"event": "start", "time": time.time()})

    def emit(self, rec):
        self.fp.write(json.dumps(rec, default=str) + "\n")
        self.fp.flush()

    def case(self, section, label, expected, got, detail=None, dt=None,
             verdict=None):
        """verdict: None -> derived from expected==got; 'INFO' records only."""
        if verdict is None:
            verdict = "PASS" if expected == got else "FAIL"
        if verdict == "PASS":
            self.n_pass += 1
        elif verdict == "FAIL":
            self.n_fail += 1
        else:
            self.n_info += 1
        rec = {"section": section, "label": label, "verdict": verdict,
               "expected": expected, "got": got, "dt": dt}
        if detail:
            rec["detail"] = detail
        self.emit(rec)
        line = f"[{verdict}] {section} :: {label}"
        if dt is not None:
            line += f" ({dt:.1f}s)"
        if verdict != "PASS":
            line += f"\n    expected={expected!r}\n    got     ={got!r}"
            if detail:
                line += f"\n    detail  ={detail!r}"
        print(line, flush=True)
        self.tp.write(line + "\n")
        self.tp.flush()

    def note(self, msg):
        print(msg, flush=True)
        self.tp.write(msg + "\n")
        self.tp.flush()
        self.emit({"event": "note", "msg": msg})

    def summary(self):
        s = (f"SUMMARY pass={self.n_pass} fail={self.n_fail} "
             f"info={self.n_info}")
        self.note(s)
        self.emit({"event": "end", "time": time.time(),
                   "pass": self.n_pass, "fail": self.n_fail,
                   "info": self.n_info})


def load_labels():
    return Labels.from_file(LABELS_PATH)


def boot(log, init_timeout=None, extra_args=None):
    """Context-manager-like generator: yields (mgr, inst, transport)."""
    if init_timeout is None:
        init_timeout = float(os.environ.get("C64_INIT_TIMEOUT", "900"))
    if extra_args is None:
        extra_args = ["-reu", "-reusize", "512"]
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=extra_args)
    mgr = ViceInstanceManager(config=config)
    mgr.__enter__()
    inst = mgr.acquire()
    transport = inst.transport
    log.note(f"VICE PID={inst.pid}, port={inst.port}; waiting for $02A7")
    start = time.time()
    ok = False
    while time.time() - start < init_timeout:
        sentinel = read_bytes(transport, 0x02A7, 1)
        if sentinel[0] == 0x42:
            ok = True
            break
        try:
            transport.resume()
        except Exception:
            pass
        time.sleep(0.5)
    if not ok:
        mgr.release(inst)
        mgr.__exit__(None, None, None)
        raise RuntimeError("init sentinel not set within timeout")
    log.note(f"Init complete after {time.time() - start:.1f}s")
    # Same RTS/JMP guard every suite plants at $0339.
    write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
    return mgr, inst, transport


def shutdown(mgr, inst):
    try:
        mgr.release(inst)
    finally:
        mgr.__exit__(None, None, None)


# ---- byte helpers -----------------------------------------------------------

def le(v, n):
    return v.to_bytes(n, "little")


def be(v, n):
    return v.to_bytes(n, "big")


def from_le(b):
    return int.from_bytes(b, "little")


def set_ptr(transport, zp_addr, target):
    write_bytes(transport, zp_addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def flags_of(regs):
    """Return (C, Z) from the register dict jsr() returns, or (None, None)."""
    fl = None
    for k in ("FL", "FLAGS", "SR", "P"):
        if k in regs:
            fl = regs[k]
            break
    if fl is None:
        return None, None
    return fl & 1, (fl >> 1) & 1
