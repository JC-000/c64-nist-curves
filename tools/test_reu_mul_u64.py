#!/usr/bin/env python3
"""test_reu_mul_u64.py — Ultimate 64 hardware probe for the SPEC v0.13.0 §8.2
REU DMA completion-confirm (a) + post-execute settle (b) obligations
(c64-lib-contract#144 / #146, this repo's issue #130).

Built to the adversarial review's §G minimum experiment.  The shape below is
not arbitrary; each choice answers a specific way this run could post a
confident wrong row.

THE ARBITER RUNS FIRST
----------------------
Leg 2 is a bare-metal minimal-shape probe that calls NO library code: it
writes the eight REU registers itself, issues the execute, and reads
`nistcurves_mul_dma_lo` at **+4 cycles**.  That is strictly more aggressive
than c64-x25519's *failing* unfixed shape (~+10 cy) and than anything our
library can be poked into (a bare-`rts` poke still pays jsr+rts = +20 cy
before the caller's read).  It converts "did the defect reproduce?" from a
property of our software into a property of the device today:

  * probe dirty, library clean  -> rig sound, defect present, the fix works;
  * probe clean at 48 MHz       -> the defect is not observable on this
                                   device in this configuration.  STOP
                                   TUNING.  Any reproduction obtained after
                                   this is a logged DEVIATION, not a result;
  * probe clean, pre-fix library dirty -> the rig's model of the hazard is
                                   wrong; investigate before reporting.

TWO SURFACES, TWO COLUMNS, NEVER ONE NUMBER
-------------------------------------------
  * FETCH path (512 B REU->C64, `reu_fetch_mul_row`): the ONLY surface where
    the defect has ever actually been seen (x25519's stale mul_dma_lo[0..1] /
    mul_dma_hi[0]).  It carries the prior positive and is never dropped.
  * STASH path (256 B C64->REU, the two `reu_mul_init` sites): corruption
    there is a hypothesis floated in #144 and never observed.
Direction and length differ, so their floors need not be equal.

POISON BEFORE EVERY REBUILD — REQUIRED, NOT OPTIONAL
-----------------------------------------------------
Boot writes the table; a cell rewriting it means a row reads corrupt only if
BOTH passes corrupted it, so a true per-row rate p is observed as p_boot *
p_cell.  The error is ONE-DIRECTIONAL: it can only ever hide the defect,
which is the worst possible direction for a run whose headline may be a null
result.  Every stash-path cell therefore poisons all 256 rows first (with a
long settle poked in so the poisoning itself is reliable), and a
poison-without-rebuild self-check proves the poison reaches the REU.

SETTLE CONTROL IS A POKE, NOT A REBUILD
----------------------------------------
The library has 13 REU execute sites: 6 hot ones in fp_mul / fp_sqr whose
settle is met STRUCTURALLY (no poke reaches them) and 7 tight ones that
`jsr nistcurves_reu_dma_wait`.  Only the latter are reachable here, and that
limit is a property of the library, not of this tool.

`nistcurves_reu_dma_wait` is 39 bytes of RAM at an exported label.
Overwriting it with `nop*k / rts` gives 12 + 2k cycles and with
`bit $DF00 / nop*k / rts` gives 16 + 2k — one write_memory, constant PRG
sha256.  The build knob cannot go below 43 cycles (34 + 9*ITER; the source
comment's 35 + 9*ITER is off by one, the final `bne` falls through), and the
only datum in existence upstream is a PASS at ~49 cycles, so the knob may
never straddle the floor at all.

EVERY NUMBER CARRIES N AND k
-----------------------------
A verdict word with no N is not a result.  Bytes within one fetch are
near-perfectly correlated (x25519 saw the same 2-3 bytes stale in every
affected fetch), so the trial unit is ONE FETCH.  N clean fetches bound the
per-fetch rate at 95% by p <= 1 - 0.05**(1/N): N=29 -> 10%, N=59 -> 5%,
N=99 -> 3%, N=299 -> 1%.  Cells that were declared but never run are printed
as `verdict=NOT_RUN` so a later reader can tell 0/5 from not-tested.

WHAT THIS RUN IS NOT ENTITLED TO CLAIM
---------------------------------------
  * that the defect is fixed or gone in fw 3.15 + patch #814 — a
    non-reproduction is an upper bound on a rate at a stated N, nothing more;
  * a stash floor and a fetch floor as one number;
  * anything about 64 MHz (this device stops at 48) or about the six
    structural hot fp_mul/fp_sqr sites (no poke reaches them);
  * a bounded-spin / poll-iteration statistic — the settle loop reuses
    `nistcurves_reu_wait_cnt`, so it is destroyed on every call;
  * a fw "3.15" row: /v1/info cannot distinguish stock from this device's
    local patch GideonZ/1541ultimate#814;
  * a REU-size effect without the byte-index histogram that discriminates the
    candidate mechanisms;
  * agreement or disagreement with the incidental x25519 handshake pass — a
    handshake cannot separate "tables correct" from "tables wrong but the
    protocol survived", so it is not commensurable with a row check.

This tool never prints a recommendation for LIB_NISTCURVES_REU_SETTLE_ITER.
A threshold measured on one device generation is not a fleet margin
(c64-lib-contract §13.6: the C64 Ultimate needed materially more settle than
the U64 Elite, and the landed constant carried ~35% margin).

Usage:
    python3 tools/test_reu_mul_u64.py --self-test        # no device
    python3 tools/test_reu_mul_u64.py --verify-builds    # no device
    U64_HOST=<ip> python3 tools/test_reu_mul_u64.py --dry-run
    U64_HOST=<ip> python3 tools/test_reu_mul_u64.py
    U64_HOST=<ip> python3 tools/test_reu_mul_u64.py --only arbiter,fetch
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import re
import shutil
import subprocess
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

# Hard-enforce the harness's advisory device-lock check: this tool reboots the
# device and rewrites its config, so a lockless run corrupts a sibling
# session's run as well as its own.  Set before the harness is imported.
os.environ.setdefault("U64_REQUIRE_DEVICE_LOCK", "1")

BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
DEFAULT_PRG = os.path.join(BUILD_DIR, "nist-curves.prg")
DEFAULT_LABELS = os.path.join(BUILD_DIR, "labels.txt")
ITER_BUILD_DIR = os.path.join(BUILD_DIR, "reu-settle")

# /v1/info reports a bare "3.15" and CANNOT distinguish stock firmware from a
# locally patched build.  This device carries GideonZ/1541ultimate#814
# (bounded UCI socket table + close-all on C64 reset).  If that patch touches
# REU/DMA arbitration at all, a pre-fix build that PASSES here means "the
# patch fixed it", not "the defect is absent on 3.15" — the wrong conclusion
# this experiment is most at risk of publishing to a fleet-wide issue.  So the
# note rides on EVERY row, and nobody downstream has to assume a socket patch
# is irrelevant to DMA timing.
DEFAULT_FIRMWARE_NOTE = "3.15+patch814(unverified_by_/v1/info)"

# --------------------------------------------------------------------------- #
# Memory map (CLAUDE.md "U64 bench architecture")                              #
# --------------------------------------------------------------------------- #
# $C000..$CFFF is free RAM in this image (the PRG ends well below $9C00's
# sqtab window). The trampoline is ~530 bytes, so the snapshot pages and the
# argument block sit above it rather than in the old $C0Fx slot.
TRAMPOLINE_ADDR = 0xC000
TRAMPOLINE_LIMIT = 0xC400
SNAP_LO, SNAP_HI = 0xC400, 0xC500  # 6502-side copy of a fetched row
ARG_ADDR = 0xC600                 # 8 argument bytes
OP_ADDR = 0xC60F
SHIM_ADDR = 0x0800                # dead BASIC-stub bytes; JMP $C000 lives here
INIT_SENTINEL_ADDR = 0x02A7
INIT_SENTINEL_VAL = 0x42
DONE_SENTINEL_ADDR = 0x02A8
DONE_SENTINEL_VAL = 0x42

(OP_INIT, OP_FETCH_HOST, OP_FETCH_SNAP, OP_NOFETCH, OP_CLOCK, OP_DMA,
 OP_FP_SQR, OP_PROBE_MIN, OP_POISON_TABLE, OP_DRAIN) = range(10)

REU_STATUS, REU_COMMAND = 0xDF00, 0xDF01
REU_C64_LO, REU_C64_HI = 0xDF02, 0xDF03
REU_REU_LO, REU_REU_HI, REU_REU_BANK = 0xDF04, 0xDF05, 0xDF06
REU_LEN_LO, REU_LEN_HI, REU_ADDR_CTRL = 0xDF07, 0xDF08, 0xDF0A
CMD_STASH, CMD_FETCH = 0xB0, 0xB1   # execute + autoload + direction

# Bank $02 $A000..$FFFF is documented free consumer scratch (CLAUDE.md "REU
# precompute table layout"), so the presence probe cannot disturb the multiply
# table (banks $00/$01) or the comb anchors (bank $02 below $A000).
PROBE_BANK, PROBE_OFF = 0x02, 0xA000

# Table poison written by OP_POISON_TABLE.  It is row-INDEPENDENT by
# construction (one buffer stashed to all 256 rows), so — unlike the
# landing-buffer poison, which is `~expected_row(a)` and cannot alias anywhere
# — it necessarily coincides with the correct product byte at some
# (row, index) pairs: 440 of the 131 072 cells, 0.34%.  Those cells cannot be
# classified as "the rebuild never wrote this byte", so `stale_bytes` on a
# stash-path cell is a slight UNDER-count.  It never causes a false PASS: a
# byte that aliases the poison is a byte that already holds the correct value,
# so it is not a mismatch in the first place.  The mismatch count and the
# index histogram are unaffected.
TABLE_POISON_LO = bytes(i ^ 0x5A for i in range(256))
TABLE_POISON_HI = bytes((i ^ 0x5A) ^ 0xFF for i in range(256))

REQUIRED_LABELS = [
    "main_loop", "reu_mul_init", "reu_fetch_mul_row",
    "nistcurves_mul_cached_a", "nistcurves_mul_dma_lo", "nistcurves_mul_dma_hi",
    "nistcurves_reu_dma_wait", "nistcurves_reu_wait_cnt",
    "nistcurves_reu_dma_timeout",
    "bench_start", "bench_stop", "bench_ticks",
]

# If the mechanism is "the CPU resumes before the transfer has landed",
# staleness is index-dependent and concentrated at LOW destination indices —
# exactly what x25519 measured (mul_dma_lo[0..1], mul_dma_hi[0]).  The fp_sqr
# diagonal site reads index `a` of row `a`, so the exposed rows are precisely
# the small ones.  A purely random sample can miss that region, so 1..8 are
# forced in; 0 is the row the `beq` fast path skips; 127/128/254/255 are the
# bank-boundary and top-of-range rows.
FIXED_ROWS = [1, 2, 3, 4, 5, 6, 7, 8, 0, 127, 128, 254, 255]

# The tuning budget, pre-registered.  Anything the run varies that is NOT in
# this list is emitted as a DEVIATION line.  The value is not enforcement; it
# is that the post-hoc story has to survive a written record of what was
# tried, in what order.
TUNING_BUDGET = ("clock", "settle_length", "reu_size", "row_set",
                 "read_immediacy", "trial_count")


# --------------------------------------------------------------------------- #
# Settle stubs poked into nistcurves_reu_dma_wait                              #
# --------------------------------------------------------------------------- #
# Cycles are execute -> `rts` return, i.e. from completion of the call site's
# `sta reu_command` to the instruction after its `jsr`:
#     jsr 6 + [bit abs 4] + 2k (nop) + rts 6
# The call site adds 2-6 more before its own next REU register write, and more
# before its first read of the landing buffer, so these are floors.
WAIT_ROUTINE_BYTES = 39           # from src/mul_8x8.s; asserted live on device


def stub_bytes(form: str, k: int) -> bytes:
    if form == "nop":
        return bytes([0xEA] * k + [0x60])
    if form == "bit":
        return bytes([0x2C, REU_STATUS & 0xFF, REU_STATUS >> 8]
                     + [0xEA] * k + [0x60])
    raise ValueError(f"unknown stub form {form!r}")


def stub_cycles(form: str, k: int) -> int:
    if form == "nop":
        return 12 + 2 * k
    if form == "bit":
        return 16 + 2 * k
    if form == "orig":
        return ORIG_CYCLES
    raise ValueError(f"unknown stub form {form!r}")


def stub_max_k(form: str) -> int:
    return WAIT_ROUTINE_BYTES - len(stub_bytes(form, 0))


ORIG_CYCLES = 106                 # the shipped ITER=8 body: 34 + 9*8


# --------------------------------------------------------------------------- #
# Pure-Python model of the reu_mul table                                       #
# --------------------------------------------------------------------------- #

def expected_row(a: int) -> bytes:
    """The 512 bytes reu_mul_init stashes for multiplier `a`: 256 low bytes of
    a*b for b=0..255, then 256 high bytes (src/reu_mul_init.s)."""
    if not 0 <= a <= 255:
        raise ValueError(f"row {a} out of 0..255")
    return (bytes((a * b) & 0xFF for b in range(256))
            + bytes(((a * b) >> 8) & 0xFF for b in range(256)))


def poison_row(a: int) -> bytes:
    """Row-dependent scrub for the C64 landing buffers.

    A constant poison (x25519 uses $EE) scores a stale byte as correct
    whenever the true product byte equals the poison, and `a*b` hits any given
    low byte for many (a, b).  Complementing the expected row makes poison !=
    expected at every index, so "byte == poison" is an unambiguous "never
    written" and is counted apart from "wrong but not poison", which means
    wrong row / bank aliasing.
    """
    return bytes(x ^ 0xFF for x in expected_row(a))


def row_reu_address(a: int, base_bank: int = 0) -> tuple[int, int]:
    """(bank, within-bank offset) of row `a`'s low half.

    reu_mul_init stashes with reu_reu_lo = 0, reu_reu_hi = (a*2) & $FF and
    bank = base + carry-out of that shift: rows 0..127 land in `base_bank`,
    128..255 in `base_bank + 1`, each at (a % 128) * 512; the high half at
    +256.
    """
    if not 0 <= a <= 255:
        raise ValueError(f"row {a} out of 0..255")
    return base_bank + (a >> 7), ((a * 2) & 0xFF) << 8


def row_linear_address(a: int, base_bank: int = 0) -> int:
    bank, off = row_reu_address(a, base_bank)
    return bank * 0x10000 + off


def compare_row(a: int, lo: bytes, hi: bytes, poison: bytes | None = None):
    """Compare a fetched row against CPU-computed a*b.

    Returns (mismatch_indices, stale_indices, samples).  Indices are 0..255
    for the low half and 256..511 for the high half.  `stale` is the subset
    equal to `poison` (default: the row-dependent landing-buffer poison) —
    i.e. bytes the DMA never wrote, as opposed to bytes written from the wrong
    place.
    """
    want = expected_row(a)
    pois = poison if poison is not None else poison_row(a)
    got = bytes(lo) + bytes(hi)
    mism, stale, samples = [], [], []
    for i in range(512):
        if got[i] != want[i]:
            mism.append(i)
            if got[i] == pois[i]:
                stale.append(i)
            if len(samples) < 8:
                samples.append((a, i & 0xFF, "lo" if i < 256 else "hi",
                                got[i], want[i]))
    return mism, stale, samples


def sample_rows(count: int, seed: int) -> list[int]:
    rows = list(FIXED_ROWS)[:max(count, len(FIXED_ROWS))]
    rng = random.Random(seed)
    while len(rows) < count:
        r = rng.randrange(256)
        if r not in rows:
            rows.append(r)
    return rows


def index_histogram(indices: list[int]) -> str:
    """Compact byte-index histogram.

    The histogram — not the mismatch count — separates a settle effect (a
    short prefix of the landing buffer stale, low indices only) from
    wrong-row / bank aliasing (mismatches spread across the whole row).  It is
    also what discriminates the candidate mechanisms behind any apparent
    REU-size effect, so a size effect must never be reported without it.
    """
    if not indices:
        return "{}"
    lo = [i for i in indices if i < 256]
    hi = [i - 256 for i in indices if i >= 256]
    b = {"lo0-7": sum(1 for i in lo if i < 8),
         "lo8-63": sum(1 for i in lo if 8 <= i < 64),
         "lo64+": sum(1 for i in lo if i >= 64),
         "hi0-7": sum(1 for i in hi if i < 8),
         "hi8-63": sum(1 for i in hi if 8 <= i < 64),
         "hi64+": sum(1 for i in hi if i >= 64)}
    head = ",".join(str(i) for i in sorted(set(indices))[:12])
    return "{" + ";".join(f"{k}={v}" for k, v in b.items() if v) + f";first={head}" + "}"


def rate_bound(n_clean: int) -> float | None:
    """95% upper bound on the per-fetch failure rate given N clean fetches."""
    if n_clean <= 0:
        return None
    return 1.0 - 0.05 ** (1.0 / n_clean)


# --------------------------------------------------------------------------- #
# Settle-immediate location (used by --verify-builds only)                     #
# --------------------------------------------------------------------------- #

def _prg_offset(addr: int, load_addr: int) -> int:
    return 2 + (addr - load_addr)


def find_settle_immediate(prg: bytes, wait_addr: int, cnt_addr: int) -> int:
    """File offset of the `lda #<LIB_NISTCURVES_REU_SETTLE_ITER` operand.

    Matches the exact tail of nistcurves_reu_dma_wait, anchored at the
    routine's exported entry.  Zero or multiple matches is a hard error:
    patching the wrong byte would produce a settle value the tool misreports.
    """
    load_addr = int.from_bytes(prg[:2], "little")
    lo, hi = cnt_addr & 0xFF, (cnt_addr >> 8) & 0xFF
    tail = bytes([0x8D, lo, hi, 0xCE, lo, hi, 0xD0, 0xFB, 0x60])
    start = _prg_offset(wait_addr, load_addr)
    if start < 2 or start >= len(prg):
        raise ValueError(f"nistcurves_reu_dma_wait ${wait_addr:04X} outside PRG")
    window = prg[start:start + 64]
    hits = [m.start() for m in re.finditer(
        re.escape(b"\xA9") + b"." + re.escape(tail), window, re.DOTALL)]
    if len(hits) != 1:
        raise ValueError(
            f"settle immediate: expected exactly 1 match in the 64 bytes at "
            f"nistcurves_reu_dma_wait, found {len(hits)}")
    return start + hits[0] + 1


def patch_settle_immediate(prg: bytes, offset: int, iters: int) -> bytes:
    if not 1 <= iters <= 255:
        raise ValueError("LIB_NISTCURVES_REU_SETTLE_ITER must be 1..255")
    out = bytearray(prg)
    out[offset] = iters
    return bytes(out)


# --------------------------------------------------------------------------- #
# Building (device-free integrity check; NOT on the measurement path)          #
# --------------------------------------------------------------------------- #

def run_make(defines: str = "") -> None:
    """`make` with CONTRACT_DEFINES.

    The Makefile's knob stamp invalidates every OBJECT when the flattened knob
    string changes (SPEC v0.10.5 / v0.11.1), but on GNU make 3.81 (the macOS
    system make) the final link is INTERMITTENTLY skipped even though all 32
    objects were just reassembled — measured 2026-08-30: for
    `-D LIB_NISTCURVES_REU_SETTLE_ITER=n`, n in {2,3,4,6}, ca65 ran 32 times
    and ld65 never did, leaving build/nist-curves.prg carrying the PREVIOUS
    knob value with exit status 0.  That is exactly the v0.11.1 property the
    stamp exists to guarantee ("assert the artifact flipped, not that
    something rebuilt").  Reported as a defect; worked around by deleting the
    PRG and labels first (forcing the link) and asserting the artifact after.

    Also: CONTRACT_DEFINES values must use `0x` hex, never `$`; and CA65FLAGS
    — which the c64-x25519 template scrubs — is not used by this Makefile at
    all, so setting it would silently change nothing.
    """
    env = dict(os.environ)
    env.pop("CA65FLAGS", None)
    for stale in (DEFAULT_PRG, DEFAULT_LABELS):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
    cmd = ["make"] + ([f"CONTRACT_DEFINES={defines}"] if defines else [])
    r = subprocess.run(cmd, capture_output=True, text=True,
                       cwd=PROJECT_ROOT, env=env)
    if r.returncode != 0:
        blob = r.stdout + r.stderr
        if "is already defined" in blob:
            sys.stderr.write(blob[-2000:] + "\n")
            raise SystemExit(
                "build failed: the documented consumer override does not "
                "assemble. Every `.ifndef`-guarded equate that a SECOND TU "
                "`.import`s collides with its own `-D` definition, because "
                "CONTRACT_DEFINES reaches every TU (SPEC §6.2). Confirmed for "
                "LIB_NISTCURVES_REU_SETTLE_ITER (src/mul_8x8.s), "
                "LIB_NISTCURVES_REU_BANK_MUL (src/mul_8x8.s), "
                "LIB_NISTCURVES_REU_BANK_COMB (src/points256_comb.s) and "
                "LIB_NISTCURVES_REU_OFFSET_COMB_P384 (src/points384_comb.s) — "
                "i.e. the whole SPEC §3 consumer-relocation path. The fix is "
                "to guard each import with `.ifndef`, the shape "
                "src/sqtab_base.inc already documents as 'included, not "
                "imported'; it is being handled in its own PR and is "
                "deliberately NOT on this branch, so --verify-builds cannot "
                "run here. The MEASUREMENT path does not need it: the settle "
                "is poked into RAM, not rebuilt.")
        sys.stderr.write(r.stdout[-4000:] + "\n" + r.stderr[-4000:] + "\n")
        raise SystemExit(f"build failed: make {' '.join(cmd[1:])!r}")


def sha256_of(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build_variant(tag: str, defines: str,
                  expect_iter: int | None = None) -> tuple[str, str, str]:
    from c64_test_harness.labels import Labels
    os.makedirs(ITER_BUILD_DIR, exist_ok=True)
    run_make(defines)
    prg = os.path.join(ITER_BUILD_DIR, f"{tag}.prg")
    labels = os.path.join(ITER_BUILD_DIR, f"{tag}.labels.txt")
    shutil.copyfile(DEFAULT_PRG, prg)
    shutil.copyfile(DEFAULT_LABELS, labels)
    if expect_iter is not None:
        lb = Labels.from_file(labels)
        with open(prg, "rb") as f:
            img = f.read()
        off = find_settle_immediate(img, lb["nistcurves_reu_dma_wait"],
                                    lb["nistcurves_reu_wait_cnt"])
        if img[off] != expect_iter:
            raise SystemExit(
                f"build of {tag} did not flip the artifact: settle immediate "
                f"is {img[off]}, expected {expect_iter} (make 3.81 skipped "
                f"the link — see run_make())")
    return prg, labels, sha256_of(prg)


# --------------------------------------------------------------------------- #
# Timeouts                                                                     #
# --------------------------------------------------------------------------- #
# CLAUDE.md "Jiffy-clock / REU-DMA wall-clock non-linearity at U64E turbo":
# real wall at 48 MHz is ~0.7x of the 16 MHz wall, not 16/48 = 0.33x, because
# REU DMA runs at ~1 MHz regardless of CPU speed.  A pure 1/mhz extrapolation
# under-budgets turbo by ~3x — how the old bench formula misfired.
_TIMEOUT_BASE_1MHZ = {"init": 120.0, "fetch": 4.0, "dma": 4.0, "clock": 10.0,
                      "sqr": 10.0, "poison": 30.0}
_TIMEOUT_FLOOR = {"init": 90.0, "fetch": 30.0, "dma": 30.0, "clock": 60.0,
                  "sqr": 30.0, "poison": 60.0}


def timeout_for(kind: str, mhz: int) -> float:
    return max(_TIMEOUT_FLOOR[kind],
               3.0 * _TIMEOUT_BASE_1MHZ[kind] / max(1, mhz))


BOOT_SENTINEL_TIMEOUT = 900.0   # boot = sqtab + reu_mul + both ec_precompute_*


# --------------------------------------------------------------------------- #
# Tiny 6502 assembler for the trampoline                                       #
# --------------------------------------------------------------------------- #

class Asm:
    def __init__(self, org):
        self.org = org
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.fix: list[tuple[int, str, str]] = []   # (offset, label, kind)

    def here(self):
        return self.org + len(self.code)

    def label(self, name):
        self.labels[name] = len(self.code)

    def b(self, *vals):
        self.code.extend(vals)

    def imm(self, opc, v):
        self.b(opc, v & 0xFF)

    def abs(self, opc, a):
        self.b(opc, a & 0xFF, (a >> 8) & 0xFF)

    def absl(self, opc, name):
        self.fix.append((len(self.code) + 1, name, "abs"))
        self.b(opc, 0, 0)

    def rel(self, opc, name):
        self.fix.append((len(self.code) + 1, name, "rel"))
        self.b(opc, 0)

    def link(self):
        for off, name, kind in self.fix:
            if name not in self.labels:
                raise KeyError(f"undefined trampoline label {name!r}")
            t = self.labels[name]
            if kind == "rel":
                d = t - (off + 1)
                if not -128 <= d <= 127:
                    raise ValueError(f"branch to {name} out of range ({d})")
                self.code[off] = d & 0xFF
            else:
                a = self.org + t
                self.code[off] = a & 0xFF
                self.code[off + 1] = (a >> 8) & 0xFF
        return bytes(self.code)


LDA_IMM, LDA_ABS, LDA_ABSY = 0xA9, 0xAD, 0xB9
STA_ABS, STA_ABSY = 0x8D, 0x99
LDY_IMM, LDX_IMM = 0xA0, 0xA2
INY, DEX, DEY, CLI, SEI, RTS = 0xC8, 0xCA, 0x88, 0x58, 0x78, 0x60
BNE, BEQ, JMP, JSR = 0xD0, 0xF0, 0x4C, 0x20
CMP_IMM, ORA_ABS, EOR_ABSY, DEC_ABS, INC_ABS = 0xC9, 0x0D, 0x59, 0xCE, 0xEE


def build_trampoline(labels) -> bytes:
    """Op dispatcher at $C000.  See the ops' comments for what each proves."""
    main_loop = labels["main_loop"]
    if (main_loop >> 8) != (SHIM_ADDR >> 8):
        raise SystemExit(
            f"main_loop ${main_loop:04X} is not in the shim page "
            f"${SHIM_ADDR >> 8:02X}xx — the single-byte hijack at "
            f"${main_loop + 1:04X} assumes it is")
    mdl, mdh = labels["nistcurves_mul_dma_lo"], labels["nistcurves_mul_dma_hi"]
    a = Asm(TRAMPOLINE_ADDR)

    def latch():
        """Re-establish the persistent DMA descriptor the library's caller
        contract assumes (CLAUDE.md "Persistent REU DMA descriptor state")."""
        a.imm(LDA_IMM, mdl & 0xFF);        a.abs(STA_ABS, REU_C64_LO)
        a.imm(LDA_IMM, (mdl >> 8) & 0xFF); a.abs(STA_ABS, REU_C64_HI)
        a.imm(LDA_IMM, 0)
        a.abs(STA_ABS, REU_REU_LO)
        a.abs(STA_ABS, REU_LEN_LO)
        a.abs(STA_ABS, REU_ADDR_CTRL)
        a.imm(LDA_IMM, 2); a.abs(STA_ABS, REU_LEN_HI)      # length = 512

    def snapshot(tag):
        """6502-side copy of both landing pages into SNAP_LO/SNAP_HI, as tight
        after the fetch as possible: the first `lda mul_dma_lo,y` is the read
        that has to land inside the settle window for the hazard to be visible
        at all.  Host-read rows are clean at every clock upstream; only this
        column has ever gone red."""
        a.imm(LDY_IMM, 0)
        a.label(tag)
        a.abs(LDA_ABSY, mdl); a.abs(STA_ABSY, SNAP_LO)
        a.abs(LDA_ABSY, mdh); a.abs(STA_ABSY, SNAP_HI)
        a.b(INY)
        a.rel(BNE, tag)

    def long_delay(tag):
        """~1280 cycles, so an op cannot leave the controller busy for the
        next one."""
        a.imm(LDX_IMM, 0)
        a.label(tag)
        a.b(DEX)
        a.rel(BNE, tag)

    a.abs(LDA_ABS, OP_ADDR)
    # cmp / bne-over / jmp rather than cmp / beq: several op bodies sit more
    # than 127 bytes away, so a direct BEQ is out of branch range.
    for opv, tgt in ((OP_FETCH_HOST, "fhost"), (OP_FETCH_SNAP, "fsnap"),
                     (OP_NOFETCH, "nofetch"), (OP_CLOCK, "clock"),
                     (OP_DMA, "dma"), (OP_FP_SQR, "fpsqr"),
                     (OP_PROBE_MIN, "probemin"),
                     (OP_POISON_TABLE, "poison"), (OP_DRAIN, "drain")):
        a.imm(CMP_IMM, opv)
        a.rel(BNE, f"next_{tgt}")
        a.absl(JMP, tgt)
        a.label(f"next_{tgt}")
    a.absl(JSR, "_reu_mul_init")                    # OP_INIT falls through
    a.absl(JMP, "done")

    # -- OP_FETCH_HOST: host reads the landing buffers afterwards, CPU idle --
    a.label("fhost")
    a.b(SEI); latch(); a.absl(JSR, "_fetch"); a.b(CLI)
    a.absl(JMP, "done")

    # -- OP_FETCH_SNAP: the read-after-DMA shape the library itself executes --
    a.label("fsnap")
    a.b(SEI); latch(); a.absl(JSR, "_fetch"); snapshot("cp1"); a.b(CLI)
    a.absl(JMP, "done")

    # -- OP_NOFETCH: detector positive control — the snapshot with NO DMA at
    #    all.  If the read-back is not exactly the poison the host wrote, the
    #    detector cannot see a corruption we injected ourselves and every
    #    later PASS is vacuous.
    a.label("nofetch")
    a.b(SEI); snapshot("cp2"); a.b(CLI)
    a.absl(JMP, "done")

    # -- OP_CLOCK: in-band clock verification.  Never record a clock that was
    #    merely SET: Turbo Control is Manual here and run_prg may reset it,
    #    and a leg silently at the wrong clock makes anchoring meaningless.
    #    Uses the CIA Timer A jiffy clock via the program's own bench_start /
    #    bench_stop, NOT the CIA1 TOD clock (their TOD confounder must not
    #    carry into our instrument).
    a.label("clock")
    a.absl(JSR, "_bench_start")
    a.abs(LDA_ABS, ARG_ADDR);     a.abs(STA_ABS, ARG_ADDR + 4)
    a.abs(LDA_ABS, ARG_ADDR + 1); a.abs(STA_ABS, ARG_ADDR + 5)
    a.label("couter")
    a.imm(LDX_IMM, 0)
    a.label("cinner")
    a.b(DEX); a.rel(BNE, "cinner")
    a.abs(LDA_ABS, ARG_ADDR + 4); a.rel(BNE, "cskip")
    a.abs(DEC_ABS, ARG_ADDR + 5)
    a.label("cskip")
    a.abs(DEC_ABS, ARG_ADDR + 4)
    a.abs(LDA_ABS, ARG_ADDR + 4); a.abs(ORA_ABS, ARG_ADDR + 5)
    a.rel(BNE, "couter")
    a.absl(JSR, "_bench_stop")
    a.absl(JMP, "done")

    # -- OP_DMA: one arbitrary transfer from the 8 argument bytes (REU
    #    presence probe).
    a.label("dma")
    a.b(SEI)
    for i, reg in enumerate((REU_C64_LO, REU_C64_HI, REU_REU_LO, REU_REU_HI,
                             REU_REU_BANK, REU_LEN_LO, REU_LEN_HI)):
        a.abs(LDA_ABS, ARG_ADDR + i); a.abs(STA_ABS, reg)
    a.imm(LDA_IMM, 0); a.abs(STA_ABS, REU_ADDR_CTRL)
    a.abs(LDA_ABS, ARG_ADDR + 7); a.abs(STA_ABS, REU_COMMAND)
    a.absl(JSR, "_dma_wait")
    a.b(CLI)
    a.absl(JMP, "done")

    # -- OP_FP_SQR: the exposed diagonal-squaring site.  src/reu_dma_done.inc
    #    frames obligation (b) as "the next REU REGISTER WRITE lands on a busy
    #    controller", and every structural assert measures bytes to the next
    #    `sta reu_reu_hi`.  But the only hardware observation anyone has is a
    #    DATA-landing hazard, governed by execute -> first read of
    #    nistcurves_mul_dma_lo — which the asserts do not measure.  At the
    #    fp_sqr diagonal site that distance is +15 cycles; x25519's failing
    #    shape was ~+10.
    a.label("fpsqr")
    a.absl(JSR, "_fp_sqr")
    a.absl(JMP, "done")

    # -- OP_PROBE_MIN: THE ARBITER.  Calls no library code: writes the eight
    #    REU registers itself, issues the execute, and reads the landing
    #    buffer at +4 cycles (one `lda abs`).  Strictly more aggressive than
    #    x25519's FAILING unfixed shape (~+10 cy) and than any poke of our
    #    library (bare-rts still costs jsr+rts = +20 cy).  Its result is a
    #    property of the DEVICE, not of our build.
    #    args: [3] = reu_hi (a*2), [4] = reu bank
    a.label("probemin")
    a.b(SEI)
    a.imm(LDA_IMM, mdl & 0xFF);        a.abs(STA_ABS, REU_C64_LO)
    a.imm(LDA_IMM, (mdl >> 8) & 0xFF); a.abs(STA_ABS, REU_C64_HI)
    a.imm(LDA_IMM, 0);                 a.abs(STA_ABS, REU_REU_LO)
    a.abs(LDA_ABS, ARG_ADDR + 3);      a.abs(STA_ABS, REU_REU_HI)
    a.abs(LDA_ABS, ARG_ADDR + 4);      a.abs(STA_ABS, REU_REU_BANK)
    a.imm(LDA_IMM, 0);                 a.abs(STA_ABS, REU_LEN_LO)
    a.imm(LDA_IMM, 2);                 a.abs(STA_ABS, REU_LEN_HI)
    a.imm(LDA_IMM, 0);                 a.abs(STA_ABS, REU_ADDR_CTRL)
    a.imm(LDA_IMM, CMD_FETCH);         a.abs(STA_ABS, REU_COMMAND)
    for i in range(4):                                   # +4, +8, +12, +16 cy
        a.abs(LDA_ABS, mdl + i); a.abs(STA_ABS, SNAP_LO + i)
    for i in range(4):
        a.abs(LDA_ABS, mdh + i); a.abs(STA_ABS, SNAP_HI + i)
    long_delay("pmdelay")
    a.b(CLI)
    a.absl(JMP, "done")

    # -- OP_POISON_TABLE: fill both landing pages with a non-aliasing pattern
    #    the host has written, then stash it to all 256 row offsets.  Required
    #    before every stash-path cell: without it, boot's table write and the
    #    cell's rewrite are two independent chances to get each row right, so
    #    a true per-row rate p is observed as p_boot * p_cell.  That error is
    #    ONE-DIRECTIONAL — it can only hide the defect.
    #    Run with a long settle poked in so the poisoning itself is reliable.
    a.label("poison")
    a.b(SEI)
    a.imm(LDA_IMM, 0); a.abs(STA_ABS, ARG_ADDR + 6)      # row counter
    a.label("prow")
    a.imm(LDA_IMM, mdl & 0xFF);        a.abs(STA_ABS, REU_C64_LO)
    a.imm(LDA_IMM, (mdl >> 8) & 0xFF); a.abs(STA_ABS, REU_C64_HI)
    a.imm(LDA_IMM, 0);                 a.abs(STA_ABS, REU_REU_LO)
    a.imm(LDA_IMM, 0);                 a.abs(STA_ABS, REU_LEN_LO)
    a.imm(LDA_IMM, 1);                 a.abs(STA_ABS, REU_LEN_HI)   # 256
    a.imm(LDA_IMM, 0);                 a.abs(STA_ABS, REU_ADDR_CTRL)
    a.abs(LDA_ABS, ARG_ADDR + 6)
    a.b(0x0A)                                            # ASL -> a*2, C = a>>7
    a.abs(STA_ABS, REU_REU_HI)
    a.abs(LDA_ABS, ARG_ADDR + 5)                         # base bank
    a.b(0x69, 0x00)                                      # ADC #0 -> +carry
    a.abs(STA_ABS, REU_REU_BANK)
    a.imm(LDA_IMM, CMD_STASH); a.abs(STA_ABS, REU_COMMAND)
    a.absl(JSR, "_dma_wait")
    # high half at offset +256
    a.imm(LDA_IMM, mdh & 0xFF);        a.abs(STA_ABS, REU_C64_LO)
    a.imm(LDA_IMM, (mdh >> 8) & 0xFF); a.abs(STA_ABS, REU_C64_HI)
    a.imm(LDA_IMM, 0);                 a.abs(STA_ABS, REU_REU_LO)
    a.imm(LDA_IMM, 0);                 a.abs(STA_ABS, REU_LEN_LO)
    a.imm(LDA_IMM, 1);                 a.abs(STA_ABS, REU_LEN_HI)
    a.abs(LDA_ABS, ARG_ADDR + 6)
    a.b(0x0A)                                            # ASL, C = a>>7
    a.b(0x09, 0x01)                                      # ORA #1 -> +256
    a.abs(STA_ABS, REU_REU_HI)
    a.abs(LDA_ABS, ARG_ADDR + 5)
    a.b(0x69, 0x00)
    a.abs(STA_ABS, REU_REU_BANK)
    a.imm(LDA_IMM, CMD_STASH); a.abs(STA_ABS, REU_COMMAND)
    a.absl(JSR, "_dma_wait")
    a.abs(INC_ABS, ARG_ADDR + 6)
    a.rel(BNE, "prow")
    a.b(CLI)
    a.absl(JMP, "done")

    # -- OP_DRAIN: one `lda $DF00` to clear a stale END OF BLOCK.  A pre-fix
    #    build never reads $DF00, so bit 6 can sit SET; the first
    #    `bit $DF00 / bvs` of a later build would then have obligation (a)
    #    satisfied by history rather than by its own transfer.  Run at the
    #    start of every cell and after every PRG reload.
    a.label("drain")
    a.abs(LDA_ABS, REU_STATUS)

    a.label("done")
    a.b(CLI)
    a.imm(LDA_IMM, main_loop & 0xFF); a.abs(STA_ABS, main_loop + 1)
    a.imm(LDA_IMM, DONE_SENTINEL_VAL); a.abs(STA_ABS, DONE_SENTINEL_ADDR)
    a.abs(JMP, main_loop)

    # resolve library entry points as absolute targets
    for name, sym in (("_reu_mul_init", "reu_mul_init"),
                      ("_fetch", "reu_fetch_mul_row"),
                      ("_dma_wait", "nistcurves_reu_dma_wait"),
                      ("_bench_start", "bench_start"),
                      ("_bench_stop", "bench_stop"),
                      ("_fp_sqr", "fp_sqr")):
        addr = labels.address(sym)
        if addr is None:
            addr = TRAMPOLINE_ADDR      # unused op; patched to a harmless nop
        for i, (off, lname, kind) in enumerate(a.fix):
            if lname == name:
                a.code[off] = addr & 0xFF
                a.code[off + 1] = (addr >> 8) & 0xFF
    a.fix = [f for f in a.fix if not f[1].startswith("_")]

    code = a.link()
    if len(code) > TRAMPOLINE_LIMIT - TRAMPOLINE_ADDR:
        raise SystemExit(f"trampoline {len(code)} B overruns "
                         f"${TRAMPOLINE_LIMIT:04X}")
    return code


# --------------------------------------------------------------------------- #
# Device driver                                                                #
# --------------------------------------------------------------------------- #

CLOCK_INNER_CYCLES = 1279          # ldx #0 / dex / bne, 256 iterations


class Device:
    def __init__(self, transport, client, verbose=False):
        self.t = transport
        self.c = client
        self.verbose = verbose
        self.labels = None
        self.prg = None
        self.wait_orig = None
        self.zp: dict[str, int] = {}

    def _resume(self):
        try:
            self.t.resume()
        except Exception:
            pass

    def read(self, addr, n):
        return bytes(self.t.read_memory(addr, n))

    def write(self, addr, data):
        self.t.write_memory(addr, bytes(data))

    def poll(self, addr, val, timeout, interval=0.05):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            d = self.t.read_memory(addr, 1)
            if d and d[0] == val:
                return True
            self._resume()
            time.sleep(interval)
        return False

    # -- boot ---------------------------------------------------------------
    def boot(self, prg_path, labels, boot_mhz, reu_size):
        from c64_test_harness.backends.ultimate64_helpers import (
            get_reu_config, set_reu, set_turbo_mhz)
        self.labels = labels
        print("    [reboot]", flush=True)
        self.c.reboot()
        time.sleep(8.0)
        # Set and VERIFY enable + size; never inherit what a sibling session
        # left behind.
        set_reu(self.c, enabled=True, size=reu_size)
        enabled, size = get_reu_config(self.c)
        if not enabled:
            raise SystemExit(
                "ABORT: REU still reports Disabled after set_reu(enabled=True). "
                "With no REU mapped, $DF00-$DF0A are open bus: every row is "
                "wrong at every clock and nothing measured afterwards means "
                "anything.")
        print(f"    [reu] enabled, size={size!r}")
        set_turbo_mhz(self.c, boot_mhz)
        time.sleep(0.5)
        with open(prg_path, "rb") as f:
            self.prg = f.read()
        print(f"    [run_prg {len(self.prg)} B @ {boot_mhz} MHz boot]",
              flush=True)
        self.c.run_prg(self.prg)
        t0 = time.monotonic()
        print(f"    [init sentinel $02A7] up to {BOOT_SENTINEL_TIMEOUT:.0f}s "
              f"(boot runs sqtab + reu_mul + both ec_precompute_*)", flush=True)
        if not self.poll(INIT_SENTINEL_ADDR, INIT_SENTINEL_VAL,
                         BOOT_SENTINEL_TIMEOUT, interval=2.0):
            raise SystemExit("ABORT: $02A7 init sentinel never appeared")
        print(f"    [init sentinel] ok after {time.monotonic() - t0:.0f}s")
        # The trampoline, the poked settle bytes and the hijacked main_loop
        # operand all survive cells but NOT a run_prg, so they are reinstalled
        # after every reload.
        self.write(SHIM_ADDR, bytes([0x4C, TRAMPOLINE_ADDR & 0xFF,
                                     (TRAMPOLINE_ADDR >> 8) & 0xFF]))
        self.write(TRAMPOLINE_ADDR, build_trampoline(labels))
        self.wait_orig = self.read(labels["nistcurves_reu_dma_wait"],
                                   WAIT_ROUTINE_BYTES)
        self._check_wait_shape()
        self.drain_status()
        return size

    def _check_wait_shape(self):
        """Confirm the 39-byte routine really is what we think before
        overwriting it, so a source change fails loudly here instead of
        silently corrupting the library in RAM."""
        cnt = self.labels["nistcurves_reu_wait_cnt"]
        want = bytes([0xA9, 0x00, 0x8D, cnt & 0xFF, cnt >> 8,
                      0x8D, (cnt + 1) & 0xFF, (cnt + 1) >> 8])
        if self.wait_orig[:len(want)] != want:
            raise SystemExit(
                f"ABORT: nistcurves_reu_dma_wait prologue is "
                f"{self.wait_orig[:len(want)].hex()}, expected {want.hex()}; "
                f"update WAIT_ROUTINE_BYTES / the poke shape to match "
                f"src/mul_8x8.s")
        if self.wait_orig[WAIT_ROUTINE_BYTES - 1] != 0x60:
            raise SystemExit("ABORT: byte 38 of nistcurves_reu_dma_wait is not "
                             "`rts`; the routine length changed.")

    # -- settle control -----------------------------------------------------
    def set_settle(self, form: str, k: int = 0):
        addr = self.labels["nistcurves_reu_dma_wait"]
        payload = self.wait_orig if form == "orig" else stub_bytes(form, k)
        if form != "orig" and k > stub_max_k(form):
            raise ValueError(f"{form} stub k={k} does not fit "
                             f"{WAIT_ROUTINE_BYTES} bytes")
        self.write(addr, payload)
        got = self.read(addr, len(payload))
        if got != payload:
            raise SystemExit(
                f"ABORT: settle poke did not land at ${addr:04X}: wrote "
                f"{payload[:8].hex()}… read {got[:8].hex()}…")

    def restore_settle(self):
        if self.wait_orig is not None and self.labels is not None:
            try:
                self.set_settle("orig")
            except Exception as e:
                print(f"  WARNING: could not restore the settle routine: {e}")

    # -- calls --------------------------------------------------------------
    def call(self, op, timeout, poll_interval=0.02):
        main_loop = self.labels["main_loop"]
        self.write(OP_ADDR, bytes([op]))
        self.write(DONE_SENTINEL_ADDR, b"\x00")
        t0 = time.monotonic()
        self.write(main_loop + 1, bytes([SHIM_ADDR & 0xFF]))   # atomic hijack
        self._resume()
        ok = self.poll(DONE_SENTINEL_ADDR, DONE_SENTINEL_VAL, timeout,
                       interval=poll_interval)
        wall = time.monotonic() - t0
        # Repair on every path: a timed-out op leaves the operand pointing at
        # the shim and the next call would double-enter.
        self.write(main_loop + 1, bytes([main_loop & 0xFF]))
        self._resume()
        return wall if ok else None

    def drain_status(self):
        """Discard one $DF00 read (see OP_DRAIN)."""
        return self.call(OP_DRAIN, 30.0) is not None

    def clear_dma_timeout(self):
        """`nistcurves_reu_dma_timeout` is sticky by design and re-init does
        not reset it, so a timeout in one cell would make every later cell
        look timed-out.  Host clears it per cell and reports it per cell."""
        self.write(self.labels["nistcurves_reu_dma_timeout"], b"\x00")

    def dma_timeout_flag(self):
        return self.read(self.labels["nistcurves_reu_dma_timeout"], 1)[0]

    # -- in-band clock verification ----------------------------------------
    def measure_mhz(self, expect_mhz: int) -> float | None:
        outer = max(1, min(65535,
                           int(expect_mhz * 1e6 * 0.5 / CLOCK_INNER_CYCLES)))
        self.write(ARG_ADDR, bytes([outer & 0xFF, (outer >> 8) & 0xFF]))
        self.write(self.labels["bench_ticks"], b"\x00\x00\x00")
        if self.call(OP_CLOCK, timeout_for("clock", expect_mhz),
                     poll_interval=0.05) is None:
            return None
        raw = self.read(self.labels["bench_ticks"], 3)
        jiffies = (raw[0] << 16) | (raw[1] << 8) | raw[2]
        if jiffies == 0:
            return None
        return outer * CLOCK_INNER_CYCLES / (jiffies / 60.0) / 1e6


# --------------------------------------------------------------------------- #
# Instrument checks                                                            #
# --------------------------------------------------------------------------- #

def reu_presence_probe(dev: Device) -> bool:
    """Stash a host pattern to free REU scratch, scrub, fetch it back.

    Run at 1 MHz, where no timing hazard exists, so a failure means the REU is
    absent or unmapped — not a settle effect.  With no REU mapped the $DFxx
    registers are open bus, `sta $DF01` does nothing and every row is wrong at
    every clock; that must abort the run, not be attributed to the settle.
    """
    mdl = dev.labels["nistcurves_mul_dma_lo"]
    pattern = bytes((i * 7 + 13) & 0xFF for i in range(256))
    dev.write(mdl, pattern)
    args = bytes([mdl & 0xFF, (mdl >> 8) & 0xFF,
                  PROBE_OFF & 0xFF, (PROBE_OFF >> 8) & 0xFF, PROBE_BANK,
                  0x00, 0x01, CMD_STASH])
    dev.write(ARG_ADDR, args)
    if dev.call(OP_DMA, timeout_for("dma", 1)) is None:
        print("    REU presence probe: TIMEOUT on stash")
        return False
    dev.write(mdl, bytes(256))
    dev.write(ARG_ADDR, args[:7] + bytes([CMD_FETCH]))
    if dev.call(OP_DMA, timeout_for("dma", 1)) is None:
        print("    REU presence probe: TIMEOUT on fetch")
        return False
    got = dev.read(mdl, 256)
    ok = got == pattern
    wrong = sum(1 for i in range(256) if got[i] != pattern[i])
    print(f"    REU presence probe (bank ${PROBE_BANK:02X}:${PROBE_OFF:04X}, "
          f"256 B round trip @ 1 MHz): {'OK' if ok else 'FAILED'}"
          + ("" if ok else f" — {wrong}/256 bytes wrong"))
    return ok


def detector_positive_control(dev: Device) -> bool:
    """Scrub the landing buffers, run the snapshot with NO DMA, require the
    read-back to be exactly the poison."""
    mdl, mdh = (dev.labels["nistcurves_mul_dma_lo"],
                dev.labels["nistcurves_mul_dma_hi"])
    pois = poison_row(37)
    dev.write(mdl, pois[:256])
    dev.write(mdh, pois[256:])
    dev.write(SNAP_LO, bytes(256))
    dev.write(SNAP_HI, bytes(256))
    if dev.call(OP_NOFETCH, timeout_for("fetch", 1)) is None:
        print("    detector positive control: TIMEOUT")
        return False
    got = dev.read(SNAP_LO, 256) + dev.read(SNAP_HI, 256)
    ok = got == pois
    print(f"    detector positive control (no DMA issued; all 512 bytes must "
          f"read back as the poison we wrote): {'OK' if ok else 'FAILED'}")
    if not ok:
        print("      the snapshot path did not return what the host wrote; "
              "every later PASS would be vacuous")
    return ok


def poison_table(dev: Device, mhz: int) -> bool:
    """Write the non-aliasing poison to all 256 REU rows, with a long settle
    poked in so the poisoning itself is reliable."""
    mdl, mdh = (dev.labels["nistcurves_mul_dma_lo"],
                dev.labels["nistcurves_mul_dma_hi"])
    dev.set_settle("orig")
    dev.write(mdl, TABLE_POISON_LO)
    dev.write(mdh, TABLE_POISON_HI)
    dev.write(ARG_ADDR + 5, bytes([0x00]))      # base bank of the mul table
    w = dev.call(OP_POISON_TABLE, timeout_for("poison", mhz),
                 poll_interval=0.05)
    if w is None:
        print("    poison_table: TIMEOUT")
        return False
    return True


def poison_self_check(dev: Device, mhz: int, rows: list[int]) -> bool:
    """Poison, then verify WITHOUT rebuilding: every row must read back as the
    poison.  If it does not, the poison op is not reaching the REU and every
    subsequent 'the rebuild wrote it correctly' is meaningless."""
    if not poison_table(dev, mhz):
        return False
    mdl, mdh = (dev.labels["nistcurves_mul_dma_lo"],
                dev.labels["nistcurves_mul_dma_hi"])
    bad = 0
    for a in rows[:4]:
        dev.write(mdl, poison_row(a)[:256])
        dev.write(mdh, poison_row(a)[256:])
        dev.write(dev.labels["nistcurves_mul_cached_a"], bytes([a]))
        if dev.call(OP_FETCH_HOST, timeout_for("fetch", mhz)) is None:
            print("    poison self-check: TIMEOUT")
            return False
        lo, hi = dev.read(mdl, 256), dev.read(mdh, 256)
        if lo != TABLE_POISON_LO or hi != TABLE_POISON_HI:
            bad += 1
    ok = bad == 0
    print(f"    poison-without-rebuild self-check ({len(rows[:4])} rows read "
          f"back after poisoning, no OP_INIT): {'OK' if ok else 'FAILED'}"
          + ("" if ok else f" — {bad} rows were not the poison"))
    return ok


# --------------------------------------------------------------------------- #
# Cells                                                                        #
# --------------------------------------------------------------------------- #

class CellResult:
    """One matrix cell.  Every field the verdict line needs, so a verdict word
    can never be printed without its N and k."""

    def __init__(self, name, clock, settle_cy, reu_size, read_kind, surface):
        self.name = name
        self.clock = clock
        self.settle_cy = settle_cy
        self.reu_size = reu_size
        self.read_kind = read_kind
        self.surface = surface
        self.n = 0                 # fetches attempted (the trial unit)
        self.k = 0                 # fetches with >= 1 wrong byte
        self.host_n = 0
        self.host_k = 0
        self.stale_bytes = 0
        self.wrong_bytes = 0
        self.indices: list[int] = []
        self.samples: list[tuple] = []
        self.dma_timeout = 0
        self.error = None
        self.not_run = False

    @property
    def verdict(self):
        if self.not_run:
            return "NOT_RUN"
        if self.error:
            return "ERROR"
        if self.n == 0:
            return "NOT_RUN"
        return "PASS" if self.k == 0 else "FAIL"

    def line(self, devstr, measured_mhz, prg_sha):
        bound = rate_bound(self.n) if self.k == 0 else None
        bits = [
            f"CELL {self.name}",
            f"surface={self.surface}",
            f"clock={self.clock}",
            f"clock_measured={'%.1f' % measured_mhz if measured_mhz else 'UNVERIFIED'}",
            f"settle_cy={self.settle_cy}",
            f"reu={self.reu_size.replace(' ', '')}",
            f"read={self.read_kind}",
            f"N={self.n}", f"k={self.k}",
            f"host_N={self.host_n}", f"host_k={self.host_k}",
            f"wrong_bytes={self.wrong_bytes}", f"stale_bytes={self.stale_bytes}",
            f"idx_hist={index_histogram(self.indices)}",
            f"p95_upper={'%.3f' % bound if bound is not None else 'n/a'}",
            f"verdict={self.verdict}",
            f"device={devstr}",
            f"prg=sha256:{prg_sha[:16]}",
        ]
        if self.dma_timeout:
            bits.append("dma_timeout_flag=1")
        if self.error:
            bits.append(f"error={self.error}")
        return " ".join(bits)


def fetch_cell(dev, mhz, reu_size, rows, n_fetches, settle, name,
               host_read=True, table_poison=None) -> CellResult:
    """FETCH-path cell: scrub -> fetch -> cpu-read.

    This is the surface where the defect has actually been observed
    (x25519's stale mul_dma_lo[0..1] / mul_dma_hi[0]), so it carries the prior
    positive and is never dropped for time.
    """
    form, k = settle
    cell = CellResult(name, mhz, stub_cycles(form, k), reu_size,
                      "cpu" + ("+host" if host_read else ""), "fetch")
    mdl, mdh = (dev.labels["nistcurves_mul_dma_lo"],
                dev.labels["nistcurves_mul_dma_hi"])
    cached_a = dev.labels["nistcurves_mul_cached_a"]
    dev.clear_dma_timeout()
    dev.drain_status()
    dev.set_settle(form, k)
    i = 0
    while cell.n < n_fetches:
        a = rows[i % len(rows)]
        i += 1
        pois = poison_row(a)
        dev.write(mdl, pois[:256]); dev.write(mdh, pois[256:])
        dev.write(SNAP_LO, pois[:256]); dev.write(SNAP_HI, pois[256:])
        dev.write(cached_a, bytes([a]))
        if dev.call(OP_FETCH_SNAP, timeout_for("fetch", mhz)) is None:
            cell.error = f"TIMEOUT_in_reu_fetch_mul_row_row{a}"
            break
        lo, hi = dev.read(SNAP_LO, 256), dev.read(SNAP_HI, 256)
        mism, stale, samples = compare_row(a, lo, hi, pois)
        cell.n += 1
        if mism:
            cell.k += 1
            cell.wrong_bytes += len(mism)
            cell.stale_bytes += len(stale)
            cell.indices.extend(mism)
            for s in samples[:max(0, 8 - len(cell.samples))]:
                cell.samples.append(s)
        if host_read and cell.host_n < max(1, n_fetches // 10):
            dev.write(mdl, pois[:256]); dev.write(mdh, pois[256:])
            dev.write(cached_a, bytes([a]))
            if dev.call(OP_FETCH_HOST, timeout_for("fetch", mhz)) is None:
                cell.error = f"TIMEOUT_in_host_read_row{a}"
                break
            hlo, hhi = dev.read(mdl, 256), dev.read(mdh, 256)
            hm, _, _ = compare_row(a, hlo, hhi, pois)
            cell.host_n += 1
            if hm:
                cell.host_k += 1
    cell.dma_timeout = dev.dma_timeout_flag()
    return cell


def stash_cell(dev, mhz, reu_size, rows, n_fetches, settle, name) -> CellResult:
    """STASH-path cell: poison every row -> poke the settle -> OP_INIT ->
    verify with a LONG settle on the fetch.

    Poisoning first is what makes "the table is correct" assert *this rebuild
    wrote it correctly* rather than *the table is correct after two or more
    attempts*.  The fetch settle is deliberately the shipped body so this cell
    measures the stash path only.  Corruption here is a hypothesis floated in
    #144 and never observed by anyone, which is exactly why it must not be
    reported as one number with the fetch floor.
    """
    form, k = settle
    cell = CellResult(name, mhz, stub_cycles(form, k), reu_size, "host",
                      "stash")
    if not poison_table(dev, mhz):
        cell.error = "poison_table_failed"
        return cell
    dev.clear_dma_timeout()
    dev.drain_status()
    dev.set_settle(form, k)
    w = dev.call(OP_INIT, timeout_for("init", mhz), poll_interval=0.2)
    if w is None:
        cell.error = "TIMEOUT_in_reu_mul_init"
        return cell
    # A reu_mul_init that took 0.2 s on a "1 MHz" leg proves the clock was not
    # applied: 65 536 ct_mul_8x8 calls at 92 cy is ~6.0 Mcy, ~7 s at 1 MHz.
    expect = 6.0e6 / (max(1, mhz) * 1e6)
    if w < 0.4 * expect:
        print(f"      WARNING: reu_mul_init took {w:.2f}s at a nominal "
              f"{mhz} MHz (expected >= {0.4 * expect:.2f}s) — clock suspect")
    dev.set_settle("orig")
    mdl, mdh = (dev.labels["nistcurves_mul_dma_lo"],
                dev.labels["nistcurves_mul_dma_hi"])
    cached_a = dev.labels["nistcurves_mul_cached_a"]
    tp = TABLE_POISON_LO + TABLE_POISON_HI
    i = 0
    while cell.n < n_fetches:
        a = rows[i % len(rows)]
        i += 1
        dev.write(mdl, poison_row(a)[:256]); dev.write(mdh, poison_row(a)[256:])
        dev.write(cached_a, bytes([a]))
        if dev.call(OP_FETCH_HOST, timeout_for("fetch", mhz)) is None:
            cell.error = f"TIMEOUT_in_reu_fetch_mul_row_row{a}"
            break
        lo, hi = dev.read(mdl, 256), dev.read(mdh, 256)
        mism, stale, samples = compare_row(a, lo, hi, tp)
        cell.n += 1
        if mism:
            cell.k += 1
            cell.wrong_bytes += len(mism)
            cell.stale_bytes += len(stale)   # still the table poison = unwritten
            cell.indices.extend(mism)
            for s in samples[:max(0, 8 - len(cell.samples))]:
                cell.samples.append(s)
    cell.dma_timeout = dev.dma_timeout_flag()
    return cell


def arbiter_cell(dev, mhz, reu_size, rows, n_fetches) -> CellResult:
    """THE ARBITER: bare-metal minimal-shape probe at +4 cycles.

    Calls no library code, so its result is a property of the device today,
    not of our build.  Only the first four bytes of each half are checked —
    that is where the hazard has ever been seen, and reading further would
    move the read further from the execute.
    """
    cell = CellResult("arbiter_minimal_shape", mhz, 4, reu_size, "cpu+4cy",
                      "fetch")
    mdl, mdh = (dev.labels["nistcurves_mul_dma_lo"],
                dev.labels["nistcurves_mul_dma_hi"])
    dev.clear_dma_timeout()
    dev.drain_status()
    i = 0
    while cell.n < n_fetches:
        a = rows[i % len(rows)]
        i += 1
        if a == 0:
            continue                 # row 0 is all zeros: no stale signal
        bank, off = row_reu_address(a, 0)
        pois = poison_row(a)
        dev.write(mdl, pois[:256]); dev.write(mdh, pois[256:])
        dev.write(SNAP_LO, pois[:4]); dev.write(SNAP_HI, pois[256:260])
        dev.write(ARG_ADDR + 3, bytes([(off >> 8) & 0xFF, bank]))
        if dev.call(OP_PROBE_MIN, timeout_for("fetch", mhz)) is None:
            cell.error = f"TIMEOUT_in_probe_min_row{a}"
            break
        got_lo, got_hi = dev.read(SNAP_LO, 4), dev.read(SNAP_HI, 4)
        want = expected_row(a)
        cell.n += 1
        bad = []
        for j in range(4):
            if got_lo[j] != want[j]:
                bad.append(j)
                if got_lo[j] == pois[j]:
                    cell.stale_bytes += 1
                if len(cell.samples) < 8:
                    cell.samples.append((a, j, "lo", got_lo[j], want[j]))
            if got_hi[j] != want[256 + j]:
                bad.append(256 + j)
                if got_hi[j] == pois[256 + j]:
                    cell.stale_bytes += 1
                if len(cell.samples) < 8:
                    cell.samples.append((a, j, "hi", got_hi[j], want[256 + j]))
        if bad:
            cell.k += 1
            cell.wrong_bytes += len(bad)
            cell.indices.extend(bad)
    cell.dma_timeout = dev.dma_timeout_flag()
    return cell


def print_cell_detail(cell: CellResult):
    if cell.indices:
        print(f"      byte-index histogram: {index_histogram(cell.indices)}")
        print("      (a short low-index prefix = settle/staleness; mismatches "
              "spread across the row = wrong row or bank aliasing)")
    for a, b, half, got, want in cell.samples:
        print(f"      a={a:3d} b={b:3d} {half} got {got:02x} want {want:02x}")


# --------------------------------------------------------------------------- #
# Self-test (no device)                                                        #
# --------------------------------------------------------------------------- #

def self_test() -> int:
    fails = []

    def check(name, cond, detail=""):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}"
              + (f"  {detail}" if detail and not cond else ""))
        if not cond:
            fails.append(name)

    image = bytearray(2 * 0x10000)
    for a in range(256):
        base = a * 512
        for b in range(256):
            p = a * b
            image[base + b] = p & 0xFF
            image[base + 256 + b] = (p >> 8) & 0xFF
    ok = True
    for a in range(256):
        lin = row_linear_address(a, 0)
        if lin != a * 512 or expected_row(a) != bytes(image[lin:lin + 512]):
            ok = False
            break
    check("expected_row == independent flat-image model, all 256 rows", ok)

    check("row 0   -> bank+0 offset $0000", row_reu_address(0) == (0, 0x0000))
    check("row 127 -> bank+0 offset $FE00", row_reu_address(127) == (0, 0xFE00))
    check("row 128 -> bank+1 offset $0000", row_reu_address(128) == (1, 0x0000))
    check("row 255 -> bank+1 offset $FE00", row_reu_address(255) == (1, 0xFE00))
    check("row 127 low half ends exactly at its bank's top",
          row_reu_address(127)[1] + 512 == 0x10000)
    check("base_bank override shifts both halves",
          row_reu_address(200, base_bank=3) == (4, ((200 * 2) & 0xFF) << 8))

    r0, r1, r16, r255 = (expected_row(x) for x in (0, 1, 16, 255))
    check("a=0 row is all zero", r0 == bytes(512))
    check("a=1 lo[b]==b, hi all zero",
          r1[:256] == bytes(range(256)) and r1[256:] == bytes(256))
    check("a=16 b=16 -> 256 -> lo $00 hi $01",
          r16[16] == 0x00 and r16[256 + 16] == 0x01)
    check("a=255 b=255 -> 65025 -> lo $01 hi $FE",
          r255[255] == 0x01 and r255[256 + 255] == 0xFE)

    check("landing-buffer poison never aliases a correct byte, all 256 rows",
          all(all(p != e for p, e in zip(poison_row(a), expected_row(a)))
              for a in range(256)))
    tp = TABLE_POISON_LO + TABLE_POISON_HI
    alias = sum(1 for a in range(256)
                for p_, e_ in zip(tp, expected_row(a)) if p_ == e_)
    check(f"table poison coincides with a correct byte in only "
          f"{alias}/131072 cells ({alias / 131072:.2%}) — an under-count of "
          f"stale bytes, never a false PASS",
          alias == 440, f"{alias} cells")

    good = expected_row(77)
    mism, stale, _ = compare_row(77, good[:256], good[256:])
    check("compare_row clean row -> no mismatches", mism == [] and stale == [])
    clo = bytearray(good[:256]); clo[3] ^= 0x01
    chi = bytearray(good[256:]); chi[200] ^= 0x80
    mism, stale, _ = compare_row(77, bytes(clo), bytes(chi))
    check("compare_row finds exactly the 2 injected mismatches",
          mism == [3, 456], str(mism))
    check("neither injected mismatch is classed as stale", stale == [])
    p = poison_row(77)
    mism, stale, _ = compare_row(77, p[:256], p[256:])
    check("an all-poison row is 512 mismatches, all classed stale",
          len(mism) == 512 and len(stale) == 512)
    check("index_histogram separates low-index staleness",
          "lo0-7=3" in index_histogram([0, 1, 2, 256]),
          index_histogram([0, 1, 2, 256]))
    check("index_histogram of nothing is {}", index_histogram([]) == "{}")

    check("rows 1..8 are always in the sample",
          all(a in sample_rows(24, 1) for a in range(1, 9)))

    check("bare rts stub is 12 cycles", stub_cycles("nop", 0) == 12)
    check("nop*k stub is 12+2k", stub_cycles("nop", 34) == 80)
    check("bit stub is 16+2k",
          stub_cycles("bit", 0) == 16 and stub_cycles("bit", 34) == 84)
    check("bare rts stub encodes as $60", stub_bytes("nop", 0) == b"\x60")
    check("bit stub encodes as bit $DF00 / nops / rts",
          stub_bytes("bit", 2) == bytes([0x2C, 0x00, 0xDF, 0xEA, 0xEA, 0x60]))
    check("stubs fit the 39-byte routine",
          stub_max_k("nop") == 38 and stub_max_k("bit") == 35)
    check("shipped body is 34 + 9*8 = 106 cycles", ORIG_CYCLES == 106)
    check("the poke reaches below the build knob's 43-cycle floor",
          stub_cycles("nop", 0) < 43)

    # 95% rate bounds (the table the report gives)
    check("N=29 clean fetches bound p at ~10%",
          abs(rate_bound(29) - 0.0995) < 0.002, f"{rate_bound(29):.4f}")
    check("N=99 clean fetches bound p at ~3%",
          abs(rate_bound(99) - 0.0296) < 0.002, f"{rate_bound(99):.4f}")
    check("rate_bound(0) is None (no N, no bound)", rate_bound(0) is None)

    # verdict discipline: no N, no verdict word
    c = CellResult("x", 48, 12, "512 KB", "cpu", "fetch")
    check("a cell with N=0 reports NOT_RUN, never PASS", c.verdict == "NOT_RUN")
    c.n = 5
    check("a cell with N=5, k=0 reports PASS", c.verdict == "PASS")
    c.k = 1
    check("a cell with k>0 reports FAIL", c.verdict == "FAIL")
    check("the cell line always carries N and k",
          "N=5" in c.line("d", 48.0, "0" * 64)
          and "k=1" in c.line("d", 48.0, "0" * 64))

    # trampoline assembles and links for a synthetic label set
    class _L(dict):
        def address(self, n):
            return self.get(n)
    fake = _L({"main_loop": 0x0835, "reu_mul_init": 0x0A91,
               "reu_fetch_mul_row": 0x0A53,
               "nistcurves_reu_dma_wait": 0x0A74,
               "nistcurves_mul_dma_lo": 0x7A00,
               "nistcurves_mul_dma_hi": 0x7B00,
               "bench_start": 0x087C, "bench_stop": 0x0887,
               "fp_sqr": 0x1234})
    try:
        code = build_trampoline(fake)
        check(f"trampoline assembles and links ({len(code)} B, fits under "
              f"${TRAMPOLINE_LIMIT:04X})",
              len(code) <= TRAMPOLINE_LIMIT - TRAMPOLINE_ADDR)
    except Exception as e:
        check("trampoline assembles and links", False, f"{type(e).__name__}: {e}")

    if os.path.exists(DEFAULT_PRG) and os.path.exists(DEFAULT_LABELS):
        from c64_test_harness.labels import Labels
        labels = Labels.from_file(DEFAULT_LABELS)
        with open(DEFAULT_PRG, "rb") as f:
            prg = f.read()
        try:
            off = find_settle_immediate(prg, labels["nistcurves_reu_dma_wait"],
                                        labels["nistcurves_reu_wait_cnt"])
            check(f"settle immediate located at file offset {off} "
                  f"(${int.from_bytes(prg[:2], 'little') + off - 2:04X}), "
                  f"value {prg[off]}", prg[off] == 8, f"value {prg[off]}")
            wa = labels["nistcurves_reu_dma_wait"]
            body = prg[_prg_offset(wa, int.from_bytes(prg[:2], "little")):]
            check("nistcurves_reu_dma_wait is 39 bytes ending in rts",
                  body[WAIT_ROUTINE_BYTES - 1] == 0x60,
                  f"byte 38 = {body[WAIT_ROUTINE_BYTES - 1]:#04x}")
        except ValueError as e:
            check("settle immediate locator", False, str(e))
        try:
            code = build_trampoline(labels)
            check(f"trampoline assembles against the real labels "
                  f"({len(code)} B)",
                  len(code) <= TRAMPOLINE_LIMIT - TRAMPOLINE_ADDR)
        except Exception as e:
            check("trampoline against real labels", False,
                  f"{type(e).__name__}: {e}")
    else:
        print("  SKIP  PRG-backed checks (build/nist-curves.prg absent; "
              "run `make` first)")

    print(f"\nself-test: {'ALL PASS' if not fails else f'{len(fails)} FAILED'}")
    return 0 if not fails else 1


# --------------------------------------------------------------------------- #
# Build verification (no device; not on the measurement path)                  #
# --------------------------------------------------------------------------- #

def verify_builds(iters: list[int]) -> int:
    from c64_test_harness.labels import Labels
    print("Building variants (each `make CONTRACT_DEFINES=...`)\n")
    rows = []
    print("  default (no CONTRACT_DEFINES)...", flush=True)
    dflt_prg, dflt_labels, dflt_sha = build_variant("default", "")
    labels = Labels.from_file(dflt_labels)
    with open(dflt_prg, "rb") as f:
        base_image = f.read()
    off = find_settle_immediate(base_image, labels["nistcurves_reu_dma_wait"],
                                labels["nistcurves_reu_wait_cnt"])
    rows.append(("default", "(none)", dflt_sha, len(base_image),
                 base_image[off], ""))
    fails = []
    for n in iters:
        d = f"-D LIB_NISTCURVES_REU_SETTLE_ITER={n}"
        print(f"  ITER={n}...", flush=True)
        p, _l, sha = build_variant(f"iter{n}", d, expect_iter=n)
        with open(p, "rb") as f:
            img = f.read()
        note = []
        if patch_settle_immediate(base_image, off, n) != img:
            note.append("POKE != REBUILD")
            fails.append(f"iter{n}: poke-equivalence")
        rows.append((f"iter{n}", d, sha, len(img), img[off], " ".join(note)))
    print("  bank $03...", flush=True)
    bp, _bl, bsha = build_variant("bank03", "-D LIB_SHARED_REU_MUL_BANK=0x03")
    with open(bp, "rb") as f:
        bimg = f.read()
    rows.append(("bank03", "-D LIB_SHARED_REU_MUL_BANK=0x03", bsha, len(bimg),
                 bimg[off], "" if bsha != dflt_sha else "SAME AS DEFAULT"))
    if bsha == dflt_sha:
        fails.append("bank03: identical to default")
    print("\n  restoring the default build...", flush=True)
    run_make("")

    print(f"\nSettle immediate lives at PRG file offset {off} "
          f"(${int.from_bytes(base_image[:2], 'little') + off - 2:04X})\n")
    print(f"  {'variant':9} {'CONTRACT_DEFINES':44} {'bytes':>6} {'ITER':>4}  sha256")
    print("  " + "-" * 118)
    for tag, d, sha, size, imm, note in rows:
        print(f"  {tag:9} {d:44} {size:6d} {imm:4d}  {sha}"
              + (f"  <-- {note}" if note else ""))
    n_iters = [r for r in rows if r[0].startswith("iter")]
    print(f"\n  distinct sha256 across {len(n_iters)} ITER builds: "
          f"{len({r[2] for r in n_iters})}")
    d8 = [r[2] for r in n_iters if r[0] == "iter8"]
    if d8:
        same = d8[0] == dflt_sha
        print(f"  ITER=8 build == default build: {same}")
        if not same:
            fails.append("iter8 != default")
    print(f"  poke(default, n) == build(ITER=n) for every n: "
          f"{'yes' if not [f for f in fails if 'poke' in f] else 'NO'}")
    print("\n  NOTE: the measurement path does NOT use these builds — the "
          "settle is poked into RAM, because the knob's 43..106 cy range "
          "cannot reach below the only known-passing point (~49 cy). This "
          "target remains a build-integrity check of the documented consumer "
          "override.")
    print(f"\nverify-builds: {'ALL PASS' if not fails else f'FAILED: {fails}'}")
    return 0 if not fails else 1


# --------------------------------------------------------------------------- #
# Ladder parsing / verdicts                                                    #
# --------------------------------------------------------------------------- #

def parse_ladder(spec: str) -> list[tuple[str, int]]:
    """'nop0,nop2,orig' -> [("nop",0), ("nop",2), ("orig",0)]"""
    out = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if tok == "orig":
            out.append(("orig", 0))
            continue
        m = re.fullmatch(r"(nop|bit)(\d+)", tok)
        if not m:
            raise ValueError(f"bad ladder point {tok!r}; use nop0 / bit12 / orig")
        form, k = m.group(1), int(m.group(2))
        if k > stub_max_k(form):
            raise ValueError(f"{tok}: k>{stub_max_k(form)} does not fit the "
                             f"{WAIT_ROUTINE_BYTES}-byte routine")
        out.append((form, k))
    return out


def arbiter_verdict(cell: CellResult) -> list[str]:
    """Pre-declared, written before the run — not chosen after it."""
    L = []
    if cell.error or cell.n == 0:
        L.append("ARBITER: NOT MEASURED — the minimal-shape probe did not "
                 "complete. Nothing downstream can be attributed to the "
                 "device rather than to our build.")
        return L
    if cell.k > 0:
        L.append(f"ARBITER: DIRTY — {cell.k}/{cell.n} minimal-shape fetches "
                 f"returned stale/wrong bytes at +4 cycles. The defect IS "
                 f"observable on this device today, and the rig is sound. If "
                 f"the library cells below are clean, the fix is validated.")
        L.append(f"  index histogram: {index_histogram(cell.indices)} "
                 f"({cell.stale_bytes} of {cell.wrong_bytes} wrong bytes were "
                 f"still the poison, i.e. never written)")
    else:
        b = rate_bound(cell.n)
        L.append(f"ARBITER: CLEAN — 0/{cell.n} minimal-shape fetches at "
                 f"+4 cycles returned a wrong byte (95% upper bound on the "
                 f"per-fetch rate: {b:.1%}). The defect is NOT observable on "
                 f"this device in this configuration.")
        L.append("  STOP TUNING. No library-side adjustment can be justified "
                 "after this result, and any subsequent reproduction is a "
                 "DEVIATION that must be logged as such, not a result.")
        L.append("  This is NOT 'the fix was unnecessary', and NOT 'the "
                 "defect is fixed in fw 3.15 + patch #814'. It is an upper "
                 "bound on a rate at a stated N, on one device, on one day.")
    return L


def anchoring_verdict(th_hi, th_lo, hi_mhz, lo_mhz, ladder_min_cy):
    L = []
    if th_hi is None and th_lo is None:
        L.append(f"ANCHORING: INCONCLUSIVE — every ladder point down to "
                 f"{ladder_min_cy} cy passed at both clocks. No reachable "
                 f"settle reproduces the defect, so no floor was measured. "
                 f"This is NOT 'cycle-anchored'.")
        return L
    if th_hi is None:
        L.append(f"ANCHORING: INCONCLUSIVE at {hi_mhz} MHz — every ladder "
                 f"point down to {ladder_min_cy} cy passed, so the floor is "
                 f"below what this instrument reaches.")
        return L
    if th_lo is None:
        L.append(f"ANCHORING: {hi_mhz} MHz floor >= {th_hi} cy; {lo_mhz} MHz "
                 f"passed at every point down to {ladder_min_cy} cy (lower "
                 f"bound only).")
        L.append(f"  A cycle-anchored floor of {th_hi} cy would have failed at "
                 f"{lo_mhz} MHz too, so CYCLE-ANCHORING IS REJECTED on this "
                 f"device. The ratio is unbounded below, so this does not "
                 f"measure how time-anchored it is.")
        return L
    ratio = th_hi / th_lo
    L.append(f"ANCHORING: {hi_mhz} MHz floor >= {th_hi} cy; {lo_mhz} MHz floor "
             f">= {th_lo} cy; ratio {ratio:.2f}x")
    if ratio >= 2.0:
        L.append("  CYCLE-ANCHORING REJECTED; consistent with a wall-clock "
                 "floor (3x the clock needing ~3x the cycles).")
    elif ratio <= 1.25:
        L.append("  Both clocks need about the same cycles: CYCLE-ANCHORING "
                 "NOT REJECTED.")
    else:
        L.append("  Between the wall-clock (~3x) and cycle (~1x) predictions; "
                 "the ladder is too coarse to separate them. Report as "
                 "neither.")
    L.append("  Scope: ONE device generation, ONE firmware (3.15 + local "
             "patch #814), and a floor for the FETCH path only — the stash "
             "path's floor is a separate number and must not be merged with "
             "it. Fleet experience (c64-lib-contract §13.6) is that the C64 "
             "Ultimate needed materially more settle than the U64 Elite and "
             "that the landed constant carried ~35% margin over the measured "
             "floor. This tool prints no recommendation for "
             "LIB_NISTCURVES_REU_SETTLE_ITER — that is a human call.")
    return L


# --------------------------------------------------------------------------- #
# Plan (dry run)                                                               #
# --------------------------------------------------------------------------- #

STAGES = ["arbiter", "fetch", "stash", "crosscheck", "sqr"]


def describe_plan(opts, rows) -> None:
    host = os.environ.get("U64_HOST") or "<U64_HOST unset>"
    lad = parse_ladder(opts.ladder)
    print("DRY RUN — no device operation is performed.\n")
    print(f"Device            : {host}")
    print(f"Lock              : DeviceLock({host}); "
          + (f"blocking acquire, timeout {opts.lock_timeout:.0f}s" if opts.wait
             else "NON-BLOCKING acquire (use --wait to queue)")
          + f"; U64_REQUIRE_DEVICE_LOCK="
            f"{os.environ.get('U64_REQUIRE_DEVICE_LOCK')}")
    print(f"Stages            : {', '.join(opts.only)}")
    print(f"Drop order        : bank -> size -> stash -> the {opts.speeds[-1]}"
          f" MHz ladder (keep its shortest settle: that is the whole "
          f"anchoring bit) -> everything but the arbiter and the instrument "
          f"checks. The FETCH column carries the prior positive and is never "
          f"dropped.")
    print(f"Tuning budget     : {', '.join(TUNING_BUDGET)} — anything else "
          f"that moves is emitted as a DEVIATION line")
    print()
    print("Legs, in order:")
    print("  1. lock; record product/serial/fw/fpga/core + REU and turbo "
          "config; set REU explicitly and VERIFY by presence probe at 1 MHz")
    print("  2. THE ARBITER: bare-metal minimal-shape probe, +4 cycles, "
          f"{opts.speeds[0]} MHz, N={opts.arbiter_n}. Calls no library code. "
          "Decides whether the rest of the run is about the device or about "
          "our fix. Never dropped.")
    print("  3. detector positive control (skip-the-fetch -> all-poison) and "
          "poison-without-rebuild self-check")
    print("  4. in-band clock verification at every clock used (CIA Timer A "
          "jiffies, NOT the CIA1 TOD clock)")
    print(f"  5. FETCH-path cells (the observed surface): settle "
          f"{opts.ladder} = {[stub_cycles(f, k) for f, k in lad]} cy, at "
          f"{opts.speeds} MHz, cpu-read, N={opts.n} each, index histogram "
          f"every time")
    print(f"  6. STASH-path cells (the hypothesised surface): poison all 256 "
          f"rows -> poke settle -> OP_INIT -> verify, same settles and clocks,"
          f" N={opts.n}")
    print(f"  7. reboot-per-cell cross-check on 3 cells chosen to span the "
          f"risk (most-likely-to-fail, first-after-a-clock-change, a clean "
          f"one), compared as RATES not verdicts")
    print(f"  8. optional: fp_sqr diagonal site; REU size; bank")
    print()
    print(f"Settle control    : POKE nistcurves_reu_dma_wait "
          f"({WAIT_ROUTINE_BYTES} B) in place — no rebuild, no reload, no "
          f"reboot, constant PRG sha256. Reaches {stub_cycles('nop', 0)} cy; "
          f"the build knob's floor is 43 cy and the only datum in existence "
          f"is a PASS at ~49 cy.")
    print(f"Shipped body      : {ORIG_CYCLES} cy (34 + 9*8; the source "
          f"comment's 35 + 9*ITER is off by one — the final bne falls through)")
    print(f"REU size          : {opts.reu_sizes} (demoted from the default "
          f"matrix: the x25519 tool has used 512 KB since its first commit, "
          f"which is the size of BOTH the recorded reproduction and the "
          f"passing handshake, so size separates nothing — still recorded on "
          f"every line)")
    print(f"Rows              : {len(rows)} (seed {opts.seed}); 1..8 forced in "
          f"because staleness at low destination indices predicts exposure "
          f"exactly there -> {rows}")
    print(f"Trial unit        : ONE FETCH. Bytes within a fetch are "
          f"near-perfectly correlated, so counting 512 of them as independent "
          f"would inflate N by ~500x. N={opts.n} bounds the per-fetch rate at "
          f"95% by {rate_bound(opts.n):.1%}.")
    print(f"Poison            : landing buffers get ~expected_row(a) "
          f"(row-dependent, cannot alias); the REU table gets index^$5A / its "
          f"complement before EVERY stash-path rebuild — without it a true "
          f"rate p is observed as p_boot*p_cell, an error that can only ever "
          f"HIDE the defect")
    print(f"Stale bit 6       : one `lda $DF00` is issued and discarded at the "
          f"start of every cell and after every PRG reload — a pre-fix build "
          f"never reads $DF00, so it can leave END OF BLOCK set and satisfy "
          f"obligation (a) on a later build by history")
    print(f"dma_timeout flag  : sticky by design and not reset by re-init, so "
          f"the host clears it per cell and reports it per cell")
    print(f"Firmware note     : fw {opts.firmware_note} — on EVERY row")
    print(f"Restore config    : "
          + ("NO (--no-restore)" if opts.no_restore else
             "yes, in a finally block, to the values OBSERVED AT STARTUP (the "
             "REU size is read from the device, never hard-coded); the settle "
             "routine's original 39 bytes are restored too"))
    print()
    print("Timeouts (3x headroom at turbo; wall at 48 MHz is ~0.7x of 16 MHz, "
          "not 0.33x):")
    print(f"  {'op':10} " + " ".join(f"{m:>9d} MHz" for m in (48, 16, 1)))
    for kind in sorted(_TIMEOUT_BASE_1MHZ):
        print(f"  {kind:10} " + " ".join(
            f"{timeout_for(kind, m):9.0f} s  " for m in (48, 16, 1)))
    print(f"  {'boot $02A7':10} {BOOT_SENTINEL_TIMEOUT:9.0f} s")
    print()
    n_fetch_cells = len(lad) * len(opts.speeds) * len(opts.reu_sizes)
    n_stash_cells = n_fetch_cells if "stash" in opts.only else 0
    per = opts.n * 0.35
    print(f"Estimated device time: {len(opts.reu_sizes)} boots x ~4 min "
          f"= {len(opts.reu_sizes) * 4} min; arbiter "
          f"{opts.arbiter_n * 0.35 / 60:.1f} min; "
          f"{n_fetch_cells} fetch cells x {per / 60:.1f} min = "
          f"{n_fetch_cells * per / 60:.0f} min; "
          f"{n_stash_cells} stash cells x {(per + 5) / 60:.1f} min = "
          f"{n_stash_cells * (per + 5) / 60:.0f} min.")
    print("Nothing above was executed.")


# --------------------------------------------------------------------------- #
# Args                                                                         #
# --------------------------------------------------------------------------- #

REU_SIZE_ALIASES = {
    "128K": "128 KB", "256K": "256 KB", "512K": "512 KB",
    "1M": "1 MB", "2M": "2 MB", "4M": "4 MB", "8M": "8 MB", "16M": "16 MB",
}


def normalise_size(spec: str) -> str:
    s = spec.strip()
    key = s.upper().replace(" ", "").replace("B", "")
    if key in REU_SIZE_ALIASES:
        return REU_SIZE_ALIASES[key]
    if s in REU_SIZE_ALIASES.values():
        return s
    raise ValueError(f"unknown REU size {spec!r}; try one of "
                     f"{sorted(REU_SIZE_ALIASES)}")


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="test_reu_mul_u64.py",
        description="U64 hardware probe for the SPEC §8.2 REU DMA settle.")
    p.add_argument("--only", default="arbiter,fetch,stash",
                   help=f"stages, in order: {','.join(STAGES)} "
                        f"(default arbiter,fetch,stash)")
    p.add_argument("--speeds", default="48,16",
                   help="clocks to measure, highest first (default 48,16)")
    p.add_argument("--ladder", default="nop0,nop2,nop6,nop16,orig",
                   help="settle points (default -> 12,16,24,44,106 cycles; "
                        "44 is the nearest even step to the build knob's "
                        "43-cycle floor)")
    p.add_argument("--n", type=int, default=100,
                   help="fetches per cell — the trial unit (default 100, "
                        "which bounds the per-fetch rate at 95%% by ~3%%)")
    p.add_argument("--arbiter-n", type=int, default=100,
                   help="fetches for the minimal-shape probe (default 100)")
    p.add_argument("--reu-size", default="512K",
                   help="REU size(s) (default 512K — the size of both the "
                        "recorded reproduction and the passing handshake)")
    p.add_argument("--rows", type=int, default=20,
                   help="distinct rows cycled through (1..8 always forced in)")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--no-host-read", dest="host_read", action="store_false",
                   help="skip the host-read column (cpu-read is never skipped)")
    p.add_argument("--boot-mhz", type=int, default=48)
    p.add_argument("--prg", default=None,
                   help="run against an already-built PRG instead of building")
    p.add_argument("--labels", default=None)
    p.add_argument("--wait", action="store_true")
    p.add_argument("--lock-timeout", type=float, default=1800.0)
    p.add_argument("--no-restore", action="store_true")
    p.add_argument("--firmware-note", default=DEFAULT_FIRMWARE_NOTE)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--verify-builds", action="store_true")
    p.add_argument("--iters", default="1,2,3,4,6,8",
                   help="--verify-builds only: knob values to build")
    p.add_argument("--verbose", action="store_true")
    o = p.parse_args(argv)
    o.only = [s.strip() for s in o.only.split(",") if s.strip()]
    bad = [s for s in o.only if s not in STAGES]
    if bad:
        p.error(f"unknown stage(s) {bad}; valid: {STAGES}")
    o.only = [s for s in STAGES if s in o.only]
    o.speeds = [int(x) for x in o.speeds.split(",") if x.strip()]
    o.iters = sorted({int(x) for x in o.iters.split(",") if x.strip()})
    try:
        parse_ladder(o.ladder)
        o.reu_sizes = [normalise_size(x) for x in o.reu_size.split(",")
                       if x.strip()]
    except ValueError as e:
        p.error(str(e))
    if not o.reu_sizes:
        p.error("--reu-size needs at least one size")
    if o.n < 1 or o.arbiter_n < 1:
        p.error("--n / --arbiter-n must be >= 1")
    if o.seed is None:
        o.seed = int.from_bytes(os.urandom(4), "big")
    return o


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #

def main(argv=None):
    opts = parse_args(sys.argv[1:] if argv is None else argv)

    if opts.self_test:
        return self_test()
    if opts.verify_builds:
        return verify_builds(opts.iters)

    rows = sample_rows(opts.rows, opts.seed)
    if opts.dry_run:
        describe_plan(opts, rows)
        return 0

    host = os.environ.get("U64_HOST")
    if not host:
        print("U64_HOST not set — refusing to guess a device address.")
        return 1

    from c64_test_harness.backends.device_lock import DeviceLock
    from c64_test_harness.backends.ultimate64 import Ultimate64Transport
    from c64_test_harness.backends.ultimate64_probe import probe_u64
    from c64_test_harness.backends.ultimate64_helpers import (
        set_turbo_mhz, snapshot_state, restore_state)
    from c64_test_harness.labels import Labels

    probe = probe_u64(host)
    if not getattr(probe, "reachable", False):
        print(f"U64 at {host} not reachable: {probe}")
        return 1

    try:
        DeviceLock.cleanup_stale()
    except Exception as e:
        print(f"  [lock] cleanup_stale: WARN {type(e).__name__}: {e}")
    lock = DeviceLock(host)
    holder = lock.read_info()
    if holder is not None:
        print(f"  [lock] currently held: {holder}")
    acquired = (lock.acquire(timeout=opts.lock_timeout) if opts.wait
                else lock.acquire(timeout=0.0, progress_window=None))
    if not acquired:
        print("FATAL: device lock not acquired"
              + ("" if opts.wait else " and --wait was not given")
              + f"; holder {lock.read_info()}")
        return 2
    print("  [lock] acquired")

    transport = client = snapshot = dev = None
    lines: list[str] = []
    prose: list[str] = []
    stage_times: list[tuple[str, float]] = []
    rc = 0
    ladder = parse_ladder(opts.ladder)
    ladder_min_cy = min(stub_cycles(f, k) for f, k in ladder)
    declared: list[tuple] = []      # every cell we intend to run
    for size in opts.reu_sizes:
        declared.append(("arbiter", opts.speeds[0], 4, size))
        for mhz in opts.speeds:
            for f, k in ladder:
                declared.append(("fetch", mhz, stub_cycles(f, k), size))
                declared.append(("stash", mhz, stub_cycles(f, k), size))
    ran: set[tuple] = set()

    try:
        transport = Ultimate64Transport(
            host=host, password=os.environ.get("U64_PASSWORD"), timeout=8.0)
        client = transport.client
        info = client.get_info()
        product = info.get("product", "?")
        serial = info.get("unique_id") or info.get("serial") or "?"
        fw = info.get("firmware_version", "?")
        fpga = info.get("fpga_version", "?")
        core = info.get("core_version", "?")
        devstr = (f"{product}/{serial}/fw{opts.firmware_note}/fpga{fpga}"
                  f"/core{core}")
        print(f"\nDevice: {product} serial {serial}")
        print(f"        fw {fw} (reported) -> recorded as "
              f"{opts.firmware_note}; fpga {fpga}, core {core}")
        print("        /v1/info cannot distinguish stock 3.15 from this "
              "device's local patch, so the row says so explicitly.")

        snapshot = snapshot_state(client)
        print("\nPre-run config OBSERVED AT STARTUP (the restore target — "
              "nothing here is hard-coded):")
        for k_, v_ in (("Turbo Control", snapshot.turbo_control),
                       ("CPU Speed", snapshot.cpu_speed),
                       ("RAM Expansion Unit", snapshot.reu_enabled),
                       ("REU Size", snapshot.reu_size),
                       ("Cartridge", snapshot.cartridge)):
            print(f"  {k_:19}: {v_!r}")

        dev = Device(transport, client, verbose=opts.verbose)

        prg = opts.prg or DEFAULT_PRG
        lbl_path = opts.labels or (
            os.path.join(os.path.dirname(os.path.abspath(prg)), "labels.txt")
            if opts.prg else DEFAULT_LABELS)
        if not opts.prg:
            print("\nBuilding the default profile...")
            run_make("")
        for p_ in (prg, lbl_path):
            if not os.path.exists(p_):
                raise SystemExit(f"missing {p_}")
        labels = Labels.from_file(lbl_path)
        missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
        if missing:
            raise SystemExit(f"labels missing from {lbl_path}: {missing}")
        prg_sha = sha256_of(prg)
        print(f"  PRG sha256 {prg_sha}")
        print(f"  nistcurves_reu_dma_wait @ "
              f"${labels['nistcurves_reu_dma_wait']:04X}, reu_mul_init @ "
              f"${labels['reu_mul_init']:04X}, reu_fetch_mul_row @ "
              f"${labels['reu_fetch_mul_row']:04X}")
        print(f"\nTuning budget (pre-registered): {', '.join(TUNING_BUDGET)}. "
              f"Anything else that moves during this run prints a DEVIATION "
              f"line.")

        def emit(line):
            lines.append(line)
            print(line, flush=True)

        for size in opts.reu_sizes:
            print(f"\n{'=' * 78}\n=== REU size {size} ===")
            t_size = time.monotonic()
            dev.boot(prg, labels, opts.boot_mhz, reu_size=size)

            # ---- LEG 1b: REU presence ---------------------------------
            print("\n  [leg 1] REU presence probe @ 1 MHz")
            set_turbo_mhz(client, 1); time.sleep(0.5)
            if not reu_presence_probe(dev):
                raise SystemExit(
                    "ABORT: the REU did not round-trip a pattern at 1 MHz. "
                    "Without a mapped REU every row is wrong at every clock.")

            # ---- LEG 2: THE ARBITER -----------------------------------
            arb = None
            if "arbiter" in opts.only:
                t0 = time.monotonic()
                mhz = opts.speeds[0]
                set_turbo_mhz(client, mhz); time.sleep(0.5)
                m = dev.measure_mhz(mhz)
                print(f"\n  [leg 2] THE ARBITER: bare-metal minimal-shape "
                      f"probe, +4 cycles, {mhz} MHz (measured "
                      f"{'%.1f' % m if m else 'UNVERIFIED'}), "
                      f"N={opts.arbiter_n}")
                print("    Calls no library code. Strictly more aggressive "
                      "than x25519's FAILING unfixed shape (~+10 cy) and than "
                      "any poke of our library (bare-rts is +20 cy).")
                arb = arbiter_cell(dev, mhz, size, rows, opts.arbiter_n)
                print_cell_detail(arb)
                emit(arb.line(devstr, m, prg_sha))
                ran.add(("arbiter", mhz, 4, size))
                for ln in arbiter_verdict(arb):
                    print(ln); prose.append(ln)
                stage_times.append((f"arbiter/{size}", time.monotonic() - t0))

            # ---- LEG 3: instrument controls ---------------------------
            print("\n  [leg 3] detector positive control + poison self-check")
            set_turbo_mhz(client, 1); time.sleep(0.5)
            if not detector_positive_control(dev):
                raise SystemExit(
                    "ABORT: the detector could not see a corruption we "
                    "injected ourselves; every later PASS would be vacuous.")
            if "stash" in opts.only and not poison_self_check(dev, 1, rows):
                raise SystemExit(
                    "ABORT: the table poison is not reaching the REU, so no "
                    "stash-path cell could assert that ITS rebuild wrote the "
                    "table correctly.")

            # ---- LEG 4: clock verification ----------------------------
            print("\n  [leg 4] in-band clock verification (CIA Timer A "
                  "jiffies, not TOD)")
            measured: dict[int, float | None] = {}
            for mhz in opts.speeds:
                set_turbo_mhz(client, mhz); time.sleep(0.5)
                m = dev.measure_mhz(mhz)
                measured[mhz] = m
                if m is None:
                    print(f"    {mhz} MHz: MEASUREMENT FAILED — clock "
                          f"discarded")
                else:
                    off = abs(m - mhz) / mhz
                    print(f"    set {mhz} MHz -> measured {m:.1f} MHz "
                          f"({off * 100:.0f}% off)"
                          + ("  <-- DISCARDED (>20%)" if off > 0.20 else ""))
                    if off > 0.20:
                        measured[mhz] = None
            usable = [m for m in opts.speeds if measured.get(m) is not None]
            if not usable:
                raise SystemExit("ABORT: no clock verified in-band.")

            # ---- LEG 5: FETCH path ------------------------------------
            thresholds: dict[int, int | None] = {}
            if "fetch" in opts.only:
                t0 = time.monotonic()
                print(f"\n  [leg 5] FETCH-path cells (the observed surface) "
                      f"— settle {opts.ladder}")
                for mhz in usable:
                    set_turbo_mhz(client, mhz); time.sleep(0.5)
                    th = None
                    for form, k in ladder:
                        cy = stub_cycles(form, k)
                        name = f"fetch_{mhz}MHz_{cy}cy"
                        c = fetch_cell(dev, mhz, size, rows, opts.n,
                                       (form, k), name,
                                       host_read=opts.host_read)
                        print_cell_detail(c)
                        emit(c.line(devstr, measured[mhz], prg_sha))
                        ran.add(("fetch", mhz, cy, size))
                        if c.verdict == "PASS" and th is None:
                            th = cy
                        if c.verdict == "FAIL":
                            th = None
                    thresholds[mhz] = th
                    print(f"    {mhz} MHz: "
                          + (f"smallest clean settle {th} cy" if th
                             else "no ladder point was clean"))
                stage_times.append((f"fetch/{size}", time.monotonic() - t0))

            # ---- LEG 6: STASH path ------------------------------------
            if "stash" in opts.only:
                t0 = time.monotonic()
                print(f"\n  [leg 6] STASH-path cells (the hypothesised "
                      f"surface; poisoned before every rebuild)")
                for mhz in usable:
                    set_turbo_mhz(client, mhz); time.sleep(0.5)
                    for form, k in ladder:
                        cy = stub_cycles(form, k)
                        name = f"stash_{mhz}MHz_{cy}cy"
                        c = stash_cell(dev, mhz, size, rows, opts.n,
                                       (form, k), name)
                        print_cell_detail(c)
                        emit(c.line(devstr, measured[mhz], prg_sha))
                        ran.add(("stash", mhz, cy, size))
                stage_times.append((f"stash/{size}", time.monotonic() - t0))

            # ---- LEG 7: reboot-per-cell cross-check -------------------
            if "crosscheck" in opts.only and "fetch" in opts.only:
                t0 = time.monotonic()
                print("\n  [leg 7] reboot-per-cell cross-check, compared as "
                      "RATES not verdicts")
                print("    Three cells span the risk: the one most likely to "
                      "FAIL (shortest settle, fastest clock), one immediately "
                      "after a clock change, and one clean cell (to catch a "
                      "cheap path that MANUFACTURES failures).")
                print("    If they disagree, believe the reboot path: cheap "
                      "FAILs + reboot PASS = carry-over artifact; cheap PASS "
                      "+ reboot FAIL = HALT, something a reboot clears is "
                      "masking the defect.")
                short = ladder[0]
                for tag, mhz, settle in (
                        ("most_likely_fail", usable[0], short),
                        ("after_clock_change", usable[-1], short),
                        ("clean", usable[0], ("orig", 0))):
                    dev.boot(prg, labels, opts.boot_mhz, reu_size=size)
                    set_turbo_mhz(client, mhz); time.sleep(0.5)
                    c = fetch_cell(dev, mhz, size, rows, opts.n, settle,
                                   f"crosscheck_{tag}_{mhz}MHz",
                                   host_read=opts.host_read)
                    emit(c.line(devstr, measured.get(mhz), prg_sha))
                stage_times.append((f"crosscheck/{size}",
                                    time.monotonic() - t0))

            # ---- optional: fp_sqr diagonal ----------------------------
            if "sqr" in opts.only:
                print("\n  [sqr] fp_sqr diagonal-site leg is declared but not "
                      "implemented in this revision — the +15 cy data-read "
                      "distance it would probe is recorded in the report "
                      "instead. NOT RUN.")

            dev.restore_settle()
            stage_times.append((f"size {size} total", time.monotonic() - t_size))

            # ---- anchoring ---------------------------------------------
            if "fetch" in opts.only and len(usable) >= 2:
                for ln in anchoring_verdict(thresholds.get(usable[0]),
                                            thresholds.get(usable[-1]),
                                            usable[0], usable[-1],
                                            ladder_min_cy):
                    print(ln); prose.append(f"[{size}] {ln}")

        # cells declared but never run, so a reader can tell 0/N from untested
        for d in declared:
            if d not in ran:
                surf, mhz, cy, size = d
                lines.append(
                    f"CELL {surf}_{mhz}MHz_{cy}cy surface={surf} clock={mhz} "
                    f"settle_cy={cy} reu={size.replace(' ', '')} N=0 k=0 "
                    f"verdict=NOT_RUN device={devstr} "
                    f"prg=sha256:{prg_sha[:16]}")

        try:
            set_turbo_mhz(client, 1)
        except Exception:
            pass

    except KeyboardInterrupt:
        print("\nINTERRUPTED — restoring device state before exit.")
        rc = 130
    finally:
        if dev is not None:
            dev.restore_settle()
        if snapshot is not None and client is not None and not opts.no_restore:
            try:
                restore_state(client, snapshot)
                print("\nDevice config restored to what was OBSERVED AT "
                      "STARTUP:")
                print(f"  Turbo Control      : {snapshot.turbo_control!r}")
                print(f"  CPU Speed          : {snapshot.cpu_speed!r}")
                print(f"  RAM Expansion Unit : {snapshot.reu_enabled!r}")
                print(f"  REU Size           : observed {snapshot.reu_size!r} "
                      f"-> restored {snapshot.reu_size!r}")
                print(f"  Cartridge          : {snapshot.cartridge!r}")
            except Exception as e:
                print(f"\nWARNING: config restore FAILED ({type(e).__name__}: "
                      f"{e}). The device may be left with the REU enabled at "
                      f"size {opts.reu_sizes[-1]!r}; the startup values were "
                      f"REU={snapshot.reu_enabled!r} "
                      f"size={snapshot.reu_size!r} "
                      f"turbo={snapshot.turbo_control!r} "
                      f"speed={snapshot.cpu_speed!r}.")
        elif opts.no_restore:
            print("\n--no-restore: device left with the REU enabled.")
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        try:
            lock.release()
        except Exception:
            pass

    print("\n" + "=" * 78)
    for ln in lines:
        print(ln)
    if prose:
        print()
        for ln in prose:
            print(ln)
    if stage_times:
        print("\nElapsed per stage:")
        for name, secs in stage_times:
            print(f"  {name:22} {secs:7.0f} s")
    return rc


if __name__ == "__main__":
    sys.exit(main())
