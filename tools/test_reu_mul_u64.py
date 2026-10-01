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
  * that the defect is fixed or gone in the firmware under test — a
    non-reproduction is an upper bound on a rate at a stated N, nothing more;
  * a stash floor and a fetch floor as one number;
  * anything about a clock the device was not measured at, or about the six
    structural hot fp_mul/fp_sqr sites (no poke reaches them);
  * a bounded-spin / poll-iteration statistic — the settle loop reuses
    `nistcurves_reu_wait_cnt`, so it is destroyed on every call;
  * a firmware it did not observe: the row's fw field is the version the
    device's own /v1/info reported, optionally annotated by --firmware-note
    (which must begin with that version, issue #172) — /v1/info cannot
    distinguish stock from a local patch such as GideonZ/1541ultimate#814;
  * a REU-size effect without the byte-index histogram that discriminates the
    candidate mechanisms;
  * agreement or disagreement with the incidental x25519 handshake pass — a
    handshake cannot separate "tables correct" from "tables wrong but the
    protocol survived", so it is not commensurable with a row check.

WHAT clock_measured IS
----------------------
The effective CPU rate with the display on, as the cells themselves run:
leg 4 times a loop with DEN=1 and the KERNAL IRQ live, so the reading
includes badlines (~5.85% of PHI2 cycles on NTSC, ~5.09% on PAL), the
one-PHI2-multiple shortfall at the top two speed indices that
GideonZ/1541ultimate#874 documents, and the small KERNAL jiffy-IRQ cost.
It is not a delivered clock. That would need $D011=$0B, $D015=0, SEI and a
free-running CIA timer, which this tool does not set up. OP_CLOCK reads
$D011 and $D015 on the C64 side, and every row records them as `vic_den=`
and `sprites=`.

EXIT STATUS
-----------
A wrapper that reads only the exit status must never mistake a run that did
not happen, or did not finish, for a measurement.
  0    complete run: every declared cell reached PASS or FAIL, and no FAIL
       at the shipped settle (sub-floor FAILs are expected bracket data)
  1    aborted (ABORT / missing build / exception), or --self-test /
       --verify-builds failed, or U64_HOST unset / device unreachable
  2    refused to start: device lock not acquired (no --wait, or --wait
       timed out), or --firmware-note rejected against /v1/info; also
       argparse's own status for a command-line usage error, including an
       unimplemented --only stage (sqr) or crosscheck without fetch
  3    no real verdict: every cell NOT_RUN / ERROR / CONTAMINATED, or none
  4    partial: some declared cells NOT_RUN / ERROR / CONTAMINATED (e.g.
       a clock leg 4 discarded), the rest PASS / FAIL
  5    a FAIL at the shipped settle (106 cy body) on a mitigated build:
       the library as shipped returned wrong rows -- a regression signal
  130  interrupted (^C); device config restored before exit
Precedence when several apply: 130 > 3 > 5 > 4 > 0.

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
import contextlib
import hashlib
import io
import os
import random
import pathlib
import re
import shutil
import tempfile
import subprocess
import sys
import time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

# Hard-enforce the harness's advisory device-lock check: this tool reboots the
# device and rewrites its config, so a lockless run corrupts a sibling
# session's run as well as its own.  Set before the harness is imported.
os.environ.setdefault("U64_REQUIRE_DEVICE_LOCK", "1")

# /Temp hygiene is deliberately NOT forced here -- the harness arms it from
# device capability and accounts for attachments at the request layer, so
# this tool's oversize writes (each a POST above the 128 B threshold) are
# already counted against the budget, not just its single boot upload.
# Forcing `U64_AUTO_TEMP_GC=1` would override that decision from the call
# site; see CLAUDE.md "Device traffic: the harness is the only route".

# Exit status contract -- see EXIT STATUS in the module docstring.
EXIT_OK = 0             # complete run: every declared cell PASS or FAIL
EXIT_ABORT = 1          # aborted / self-test or verify-builds failed
EXIT_REFUSED = 2        # refused to start: lock not acquired, bad fw note
EXIT_NO_VERDICT = 3     # no cell reached PASS or FAIL
EXIT_PARTIAL = 4        # some declared cells NOT_RUN / ERROR / CONTAMINATED
EXIT_ORIG_FAIL = 5      # a FAIL at the shipped settle on a mitigated build
EXIT_INTERRUPTED = 130  # ^C (device state restored first)

BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
DEFAULT_PRG = os.path.join(BUILD_DIR, "nist-curves.prg")
DEFAULT_LABELS = os.path.join(BUILD_DIR, "labels.txt")

# /v1/info reports a bare version (e.g. "3.15") and CANNOT distinguish stock
# firmware from a locally patched build.  The U64E this tool was written
# against carries GideonZ/1541ultimate#814 (bounded UCI socket table +
# close-all on C64 reset); if that patch touches REU/DMA arbitration at all, a
# pre-fix build that PASSES there means "the patch fixed it", not "the defect
# is absent on 3.15".  So the operator may annotate the reported version with
# --firmware-note (e.g. "3.15+patch814"), and the note rides on EVERY row.
#
# Issue #172: that annotation used to be a hardcoded DEFAULT
# ("3.15+patch814(unverified_by_/v1/info)") applied silently to ANY device,
# so a C64U reporting fw 1.1.0 would have stamped fw3.15 on every CELL row --
# a wrong field beside four live ones (product/serial/fpga/core), which
# inherits credibility it has not earned.  Now the firmware field is always
# derived from the /v1/info reply of the device actually observed: with no
# note it IS the reported version (marked unverified for patch level), and an
# explicit note must begin with the reported version verbatim or the run
# refuses before touching anything.
FIRMWARE_UNVERIFIED_SUFFIX = "(patch_level_unverified_by_v1_info)"


def firmware_note_for_row(reported_fw, note):
    """-> (firmware field recorded on every row, refusal reason or None).

    Pure; the reported string is whatever `/v1/info`'s firmware_version said
    for the device in hand.  Exactly one of the two results is None.
    """
    rep = (str(reported_fw).strip() if reported_fw is not None else "")
    # A leading V/v is part of how /v1/info spells versions ("V3.14d"); the
    # harness's u64_capabilities strips it the same way.  It is ignored for
    # the version check and the prefix compare, never for what is recorded.
    rep_core = rep.lstrip("Vv")
    rep_ok = bool(re.match(r"\d+\.\d+", rep_core))
    if note is None:
        if not rep_ok:
            return (f"{rep or '?'}(firmware_version_not_reported_by_v1_info)",
                    None)
        return f"{rep}{FIRMWARE_UNVERIFIED_SUFFIX}", None
    note = str(note)
    # The note is embedded in space-delimited key=value CELL rows, inside the
    # '/'-delimited device field: whitespace, '=' or '/' would let it forge
    # or split fields ("1.1.0 verdict=PASS" adds a second verdict).  A strict
    # charset rather than a blacklist.
    if not re.fullmatch(r"[A-Za-z0-9._+()~-]+", note):
        return None, (f"--firmware-note {note!r} may contain only letters, "
                      f"digits and . _ + ( ) ~ - (no whitespace, '=' or "
                      f"'/'): it is written into space-delimited key=value "
                      f"CELL rows and the '/'-delimited device field.")
    if not rep_ok:
        return None, (f"--firmware-note {note!r} cannot be checked: /v1/info "
                      f"reported firmware_version {reported_fw!r}, which is "
                      f"not a version. Omit --firmware-note to record what "
                      f"the device reported.")
    # The note is an annotation ON the reported version, so it must begin with
    # it verbatim and not continue it (3.15 vs 3.150, 1.1.0 vs 1.1.05).
    note_core = note.lstrip("Vv")
    if not (note_core.lower().startswith(rep_core.lower())
            and not re.match(r"[0-9A-Za-z]|\.\d",
                             note_core[len(rep_core):])):
        return None, (f"--firmware-note {note!r} does not begin with the "
                      f"firmware this device reports ({rep!r} via /v1/info). "
                      f"Refusing to stamp a firmware this device is not "
                      f"running onto every row; pass a note that starts with "
                      f"{rep!r}, or omit it.")
    return note, None


_IDENTITY_FIELDS = ("product", "unique_id", "serial", "firmware_version",
                    "fpga_version", "core_version")


def device_identity_changed(before: dict, after: dict) -> list[str]:
    """Fields of /v1/info that differ between two observations.

    Every row is stamped with the identity read at startup, so the tool
    re-reads /v1/info after each reboot and refuses to keep stamping if the
    box answering is no longer the one the rows name.
    """
    return [k for k in _IDENTITY_FIELDS if before.get(k) != after.get(k)]


def _row_token(value) -> str:
    """One CELL-row token: no whitespace (the row is space-delimited), no
    '=' (key=value) and no '/' (the device field's own separator).  The
    product name is "Ultimate 64 Elite" / "C64 Ultimate", which used to
    split `device=` into three row tokens."""
    return re.sub(r"[\s=/]+", "_", str(value)) or "?"


def device_string(info: dict, note: str) -> str:
    product = info.get("product", "?")
    serial = info.get("unique_id") or info.get("serial") or "?"
    fpga = info.get("fpga_version", "?")
    core = info.get("core_version", "?")
    return "/".join(_row_token(x) for x in
                    (product, serial, f"fw{note}", f"fpga{fpga}",
                     f"core{core}"))


def acquire_device_lock(lock, wait: bool, lock_timeout: float) -> int:
    """Take the DeviceLock. -> 0 when held, else the process exit status."""
    holder = lock.read_info()
    if holder is not None:
        print(f"  [lock] currently held: {holder}")
    acquired = (lock.acquire(timeout=lock_timeout) if wait
                else lock.acquire(timeout=0.0, progress_window=None))
    if not acquired:
        print("FATAL: device lock not acquired"
              + ("" if wait else " and --wait was not given")
              + f"; holder {lock.read_info()}")
        return EXIT_REFUSED
    print("  [lock] acquired")
    return 0

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
VIC_CTRL1, VIC_SPRITE_EN = 0xD011, 0xD015
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
    "bench_start", "bench_stop", "bench_ticks",
]

# Present only in a MITIGATED build (v0.12.0+). The unmitigated control -- the
# only configuration that can discriminate "the settle fixed it" from "the core
# removed it" -- has none of them, so requiring them made the control
# unrunnable. Absence is the signal, not an error.
MITIGATION_LABELS = [
    "nistcurves_reu_dma_wait", "nistcurves_reu_wait_cnt",
    "nistcurves_reu_dma_timeout",
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

def run_make(defines: str = "", build_dir: str | None = None) -> None:
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
    bdir = build_dir or BUILD_DIR
    for stale in (os.path.join(bdir, "nist-curves.prg"),
                  os.path.join(bdir, "labels.txt")):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
    # `BUILD_DIR` is a plain `=` in the Makefile, so a command-line value
    # overrides it everywhere -- objects, stamp, knob wipe and all.
    cmd = (["make"] + ([f"BUILD_DIR={build_dir}"] if build_dir else [])
           + ([f"CONTRACT_DEFINES={defines}"] if defines else []))
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


def build_variant(tag: str, defines: str, build_dir: str,
                  expect_iter: int | None = None) -> tuple[str, str, str]:
    """Build one knob variant in `build_dir` (never the user's build/: a
    knob change makes the Makefile wipe every object, archive and PRG in its
    BUILD_DIR) and keep a copy under build_dir/reu-settle/."""
    from c64_test_harness.labels import Labels
    keep = os.path.join(build_dir, "reu-settle")
    os.makedirs(keep, exist_ok=True)
    run_make(defines, build_dir=build_dir)
    prg = os.path.join(keep, f"{tag}.prg")
    labels = os.path.join(keep, f"{tag}.labels.txt")
    shutil.copyfile(os.path.join(build_dir, "nist-curves.prg"), prg)
    shutil.copyfile(os.path.join(build_dir, "labels.txt"), labels)
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


def build_trampoline(labels, symbols: bool = False):
    """Op dispatcher at $C000.  See the ops' comments for what each proves."""
    main_loop = labels["main_loop"]
    if (main_loop >> 8) != (SHIM_ADDR >> 8):
        raise SystemExit(
            f"main_loop ${main_loop:04X} is not in the shim page "
            f"${SHIM_ADDR >> 8:02X}xx — the single-byte hijack at "
            f"${main_loop + 1:04X} assumes it is")
    mdl, mdh = labels["nistcurves_mul_dma_lo"], labels["nistcurves_mul_dma_hi"]
    cached_a = labels["nistcurves_mul_cached_a"]
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
        # SPEC §8.2 / issue #153: reu_fetch_mul_row takes the row index in A.
        # It used to ignore A and read nistcurves_mul_cached_a itself, so this
        # trampoline reached the jsr with whatever latch() left in A -- which
        # is 2, from the store above. After #153 that would have fetched row 2
        # for every cell, and because the probe compares each fetch against
        # expected_row(a), EVERY settle length would report ~100% corruption:
        # an instrument with no discrimination, failing in the direction that
        # looks like a finding. The host still selects the row by writing
        # nistcurves_mul_cached_a, so load A from it here, last, immediately
        # before the call.
        a.abs(LDA_ABS, cached_a)

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
    # 24-bit pass counter (issue #173): a 16-bit one caps the window at
    # 65535 passes = 1.3 s at 64 MHz, too short to quantise below ~1%.
    a.abs(LDA_ABS, ARG_ADDR + 2); a.abs(STA_ABS, ARG_ADDR + 6)
    a.label("couter")
    a.imm(LDX_IMM, 0)
    a.label("cinner")
    a.b(DEX); a.rel(BNE, "cinner")
    a.abs(LDA_ABS, ARG_ADDR + 4); a.rel(BNE, "cskip0")
    a.abs(LDA_ABS, ARG_ADDR + 5); a.rel(BNE, "cskip1")
    a.abs(DEC_ABS, ARG_ADDR + 6)
    a.label("cskip1")
    a.abs(DEC_ABS, ARG_ADDR + 5)
    a.label("cskip0")
    a.abs(DEC_ABS, ARG_ADDR + 4)
    a.abs(LDA_ABS, ARG_ADDR + 4); a.abs(ORA_ABS, ARG_ADDR + 5)
    a.abs(ORA_ABS, ARG_ADDR + 6)
    a.rel(BNE, "couter")
    a.label("cdone")
    a.absl(JSR, "_bench_stop")
    # Display state the window ran under, captured on the C64 side (outside
    # the timed window): $D011 (DEN = bit 4 -> badlines) to ARG+3, $D015
    # (sprite enable -> sprite DMA) to ARG+7.  clock_measured is the
    # effective CPU rate UNDER these conditions, so they ride on every row.
    a.label("cvic")
    a.abs(LDA_ABS, VIC_CTRL1); a.abs(STA_ABS, ARG_ADDR + 3)
    a.abs(LDA_ABS, VIC_SPRITE_EN); a.abs(STA_ABS, ARG_ADDR + 7)
    a.label("cvicend")
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

    # A missing library entry point must resolve to something that RETURNS.
    # It previously resolved to TRAMPOLINE_ADDR, so on an unmitigated control
    # build (no nistcurves_reu_dma_wait) the three `jsr _dma_wait` sites became
    # `jsr $C000` -- a jump back into the trampoline's own entry. That hangs the
    # machine, and it presented as "REU presence probe: TIMEOUT on stash", which
    # reads like a dead REU rather than a tool bug. Emit a real `rts` and point
    # missing symbols at it.
    a.label("_missing_rts")
    a.b(RTS)

    # resolve library entry points as absolute targets
    for name, sym in (("_reu_mul_init", "reu_mul_init"),
                      ("_fetch", "reu_fetch_mul_row"),
                      ("_dma_wait", "nistcurves_reu_dma_wait"),
                      ("_bench_start", "bench_start"),
                      ("_bench_stop", "bench_stop"),
                      ("_fp_sqr", "fp_sqr")):
        addr = labels.address(sym)
        if addr is None:
            addr = TRAMPOLINE_ADDR + a.labels["_missing_rts"]
        for i, (off, lname, kind) in enumerate(a.fix):
            if lname == name:
                a.code[off] = addr & 0xFF
                a.code[off + 1] = (addr >> 8) & 0xFF
    a.fix = [f for f in a.fix if not f[1].startswith("_")]

    code = a.link()
    if len(code) > TRAMPOLINE_LIMIT - TRAMPOLINE_ADDR:
        raise SystemExit(f"trampoline {len(code)} B overruns "
                         f"${TRAMPOLINE_LIMIT:04X}")
    if symbols:
        return code, {k: TRAMPOLINE_ADDR + v for k, v in a.labels.items()}
    return code


def simulate_6502(code: bytes, org: int, pc: int, stop: set[int],
                  mem: dict[int, int], max_steps: int = 5_000_000):
    """Cycle-count the trampoline's clock loop from its ASSEMBLED BYTES.

    Implements only the opcodes the OP_CLOCK loop uses, with NMOS 6502
    timings (branch: 2, +1 taken, +1 more if the target is on another page).
    Anything else raises, so a loop edit cannot be silently mis-timed.
    -> (cycles, pc at stop).  `mem` holds the counter bytes and is updated.
    """
    x = 0
    a = 0
    z = False
    cyc = 0
    for step in range(max_steps):
        if step and pc in stop:     # never stops before the first opcode
            return cyc, pc
        i = pc - org
        op = code[i]
        if op == LDX_IMM:
            x = code[i + 1]; z = x == 0; pc += 2; cyc += 2
        elif op == DEX:
            x = (x - 1) & 0xFF; z = x == 0; pc += 1; cyc += 2
        elif op in (LDA_ABS, STA_ABS, ORA_ABS, DEC_ABS):
            ad = code[i + 1] | (code[i + 2] << 8)
            if op == LDA_ABS:
                a = mem.get(ad, 0); z = a == 0; cyc += 4
            elif op == STA_ABS:
                mem[ad] = a; cyc += 4
            elif op == ORA_ABS:
                a |= mem.get(ad, 0); z = a == 0; cyc += 4
            else:
                v = (mem.get(ad, 0) - 1) & 0xFF
                mem[ad] = v; z = v == 0; cyc += 6
            pc += 3
        elif op == BNE:
            d = code[i + 1]
            nxt = pc + 2
            if not z:
                tgt = (nxt + (d - 256 if d & 0x80 else d)) & 0xFFFF
                cyc += 3 + (1 if (tgt >> 8) != (nxt >> 8) else 0)
                pc = tgt
            else:
                cyc += 2; pc = nxt
        else:
            raise ValueError(f"simulate_6502: opcode ${op:02X} at "
                             f"${pc:04X} is not modelled")
    raise RuntimeError("simulate_6502: step limit hit")


def clock_loop_cycles_simulated(code: bytes, syms: dict, n: int) -> int:
    """Cycles from `couter` to `cdone` for an outer count of n."""
    mem = {ARG_ADDR + 4 + k: (n >> (8 * k)) & 0xFF
           for k in range(CLOCK_COUNTER_BYTES)}
    cyc, _ = simulate_6502(code, TRAMPOLINE_ADDR, syms["couter"],
                           {syms["cdone"]}, mem)
    return cyc


# --------------------------------------------------------------------------- #
# Device driver                                                                #
# --------------------------------------------------------------------------- #

# OP_CLOCK's loop, per outer pass (NMOS timings; no branch crosses a page,
# which the self-test proves by simulating the assembled bytes):
#   ldx #0 2 | dex/bne x256: 255*5 + 4 = 1279 | lda lo 4 | bne 3 (taken)
#   | dec lo 6 | lda 4 | ora 4 | ora 4 | bne 3                  = 1309
# A pass entered with the low byte 0 takes the borrow path (bne 2, lda mid 4,
# bne 3, dec mid 6) = +12; with the mid byte 0 too (bne 2, dec hi 6) = +5
# more; the last pass falls out of `bne couter` = -1.  (Before issue #173's
# 24-bit counter the pass was 1305; before that it was modelled as 1279 --
# the inner loop alone, 2.0% short.)
CLOCK_INNER_CYCLES = 1279          # dex / bne, 256 iterations
CLOCK_PASS_CYCLES = 1309
CLOCK_BORROW_MID = 12
CLOCK_BORROW_HI = 5
CLOCK_COUNTER_BYTES = 3
CLOCK_MAX_PASSES = (1 << (8 * CLOCK_COUNTER_BYTES)) - 1

# Issue #173.  The old check ran ONE window sized to ~0.5 s at the expected
# clock and divided by its jiffy count.  Two properties of that shape made it
# unfit as evidence, whatever the device was doing:
#   * IF any fixed overhead O sat inside the window, it would read as a clock
#     deficit of 0.5/(0.5+O) -- the same percentage at every setting, because
#     the window was rescaled to 0.5 s each time;
#   * a ~30-jiffy window quantises at +-3.3%.
# Whether such an overhead exists is NOT established: bench_start /
# bench_stop zero and read the jiffy clock on the C64 itself, around the
# loop, so no host latency enters the window, and the real overhead may be
# ~0.  The reported constant 0.9375 also contained the 2.0% cycle-model
# shortfall fixed separately; what remains is not attributed here.  So the
# clock is now the SLOPE of two windows,
# f = (cycles2 - cycles1) / (jiffies2 - jiffies1) * 60: any fixed overhead is
# the intercept and cancels, and the intercept is printed as MEASURED, with
# its bound, rather than assumed in either direction.
# The long window (~10 s, sized from the short one's crude reading so a clock
# far from the expected one cannot run into the call timeout) puts ~570
# jiffies between the two; each count is off by under one jiffy at its own
# start phase, so the difference is within +-2 and the estimate within
# ~+-0.35% (wider if a large overhead shortened the long window), and that
# bound is carried on every row as clock_pm.
#
# NOT removed, and not removable by any fit: the KERNAL jiffy IRQ runs inside
# the window and takes H cycles per tick, so the loop sees f - 60*H cycles
# per second.  That is time-proportional, ~60H/f of the reading -- material
# at 1 MHz (a few hundred cycles per tick is a ~1-2% low reading),
# negligible at turbo.  Sizing it needs hardware.
#
# WHAT IS MEASURED (hardware run at 1e17794, U64E fw 3.15 / core 1.4F, NTSC:
# 48 set -> 45.00 +-0.15, intercept 0.0 +-18.4 ms; 16 set -> 15.30 +-0.05,
# intercept -6.0 +-18.4 ms).  clock_measured is the EFFECTIVE CPU rate under
# the conditions OP_CLOCK runs in -- display on, KERNAL IRQ on -- which are
# also the conditions every fetch/stash cell runs in, so the measurement is
# deliberately left as is and labelled instead.  Its known biases:
#   * badlines: with DEN=1 the VIC steals 40 cycles on each of 25 badlines
#     per frame: 1000/(263*65) = 5.85% of PHI2 cycles on NTSC,
#     1000/(312*63) = 5.09% on PAL;
#   * GideonZ/1541ultimate#874: with the VIC blanked, speed indices 0-13
#     deliver exactly label x PHI2, but the top two indices are one PHI2
#     multiple short (U64E 40 -> 38.99, 48 -> 47.00), because the VIC always
#     keeps one slot;
#   * the KERNAL jiffy IRQ (small; see below).
# Prediction 47 x 1.0227 x 0.9415 = 45.25 (measured 45.00) and
# 16 x 1.0227 x 0.9415 = 15.41 (15.30); the remaining ~1% is loop alignment
# against badline rows.  A DELIVERED-clock reading needs $D011=$0B (display
# off), $D015=0 (no sprites), SEI and a free-running CIA timer; this tool
# does none of that.  $D011/$D015 are read by OP_CLOCK on the C64 side and
# carried on every row (vic_den=, sprites=).
BADLINE_STEAL_NTSC = 25 * 40 / (263 * 65)
BADLINE_STEAL_PAL = 25 * 40 / (312 * 63)
CLOCK_SHORT_S = 0.5
CLOCK_LONG_S = 10.0


def clock_cycles(n: int) -> int:
    """CPU cycles from `couter` to `cdone` for an outer count of n >= 1."""
    return (n * CLOCK_PASS_CYCLES + (n // 256) * CLOCK_BORROW_MID
            + (n // 65536) * CLOCK_BORROW_HI - 1)


def _clock_passes(mhz: float, seconds: float) -> int:
    return max(1, min(CLOCK_MAX_PASSES,
                      int(mhz * 1e6 * seconds / CLOCK_PASS_CYCLES)))


class ClockEstimate(float):
    """The measured MHz (a float, so every existing consumer still works),
    plus the evidence: the bounds the jiffy quantisation allows, the fixed
    overhead the fit removed, and the two raw windows."""

    def __new__(cls, mhz, lo, hi, overhead_s, windows):
        self = super().__new__(cls, mhz)
        self.lo, self.hi = lo, hi
        self.overhead_s = overhead_s
        self.windows = windows
        return self

    @property
    def mhz(self) -> float:
        return float(self)

    @property
    def pm(self) -> float:
        return (self.hi - self.lo) / 2.0


def clock_fit(n1: int, j1: int, n2: int, j2: int) -> ClockEstimate | None:
    """Two-point fit. Each jiffy count is floor(60*(t + O) + phase) with its
    own phase in [0,1), so each is within (-1,+1) of 60*(t + O) and their
    difference within (-2,+2) of the true 60*(t2 - t1)."""
    dc = clock_cycles(n2) - clock_cycles(n1)
    dj = j2 - j1
    if dc <= 0 or dj < 3:
        return None
    f = dc / (dj / 60.0)
    lo = dc / ((dj + 2) / 60.0)
    hi = dc / ((dj - 2) / 60.0)
    # Intercept, extrapolated back from the SHORT window: j1's own (-1,+1)
    # jiffy plus the slope's relative error times the short window's length
    # (~0.1 jiffy when the short window is the planned 0.5 s; more when the
    # clock was far below the expected one and it ran long).
    t1 = clock_cycles(n1) / f
    over = j1 / 60.0 - t1
    over_pm = 1.0 / 60.0 + t1 * (hi - lo) / 2.0 / f
    est = ClockEstimate(f / 1e6, lo / 1e6, hi / 1e6, over,
                        ((n1, j1), (n2, j2)))
    est.overhead_pm_s = over_pm
    return est


def run_clock_measurement(expect_mhz: int, window):
    """Pure decision logic of the in-band clock check.

    `window(outer) -> jiffies | None` is the only device-coupled step (one
    OP_CLOCK call); the self-test drives this with synthetic jiffy counts.
    """
    n1 = _clock_passes(expect_mhz, CLOCK_SHORT_S)
    j1 = window(n1)
    if not j1:
        return None
    crude = clock_cycles(n1) / (j1 / 60.0) / 1e6   # overhead-biased; sizing only
    # Sized as an EXTENSION of the short window, so the difference is ~10 s
    # even when the short one ran long (turbo not applied: 48 expected, 1 real).
    n2 = min(CLOCK_MAX_PASSES, n1 + _clock_passes(crude, CLOCK_LONG_S))
    j2 = window(n2)
    if not j2:
        return None
    est = clock_fit(n1, j1, n2, j2)
    # The crude reading carries the very overhead the fit removes, so a large
    # one shortens the extension.  If it came up well short, re-size it once
    # from the fitted (overhead-free) slope.
    if est is not None and (j2 - j1) < 0.8 * 60.0 * CLOCK_LONG_S:
        n3 = min(CLOCK_MAX_PASSES,
                 n1 + _clock_passes(est.mhz, CLOCK_LONG_S))
        if n3 > n2:
            j3 = window(n3)
            if not j3:
                return None
            est = clock_fit(n1, j1, n3, j3)
    return est


class Device:
    def __init__(self, transport, client, verbose=False):
        self.t = transport
        self.c = client
        self.verbose = verbose
        self.labels = None
        self.prg = None
        self.wait_orig = None
        self.zp: dict[str, int] = {}
        self.clock_vic: tuple[int, int] | None = None   # ($D011, $D015)

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
        # An unmitigated control build has no wait routine to capture or
        # restore -- absence is the signal, not an error (see MITIGATION_LABELS).
        if self.mitigated:
            self.wait_orig = self.read(labels["nistcurves_reu_dma_wait"],
                                       WAIT_ROUTINE_BYTES)
            self._check_wait_shape()
        else:
            self.wait_orig = None
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
    @property
    def mitigated(self) -> bool:
        """False for a genuine pre-fix build: it has no settle routine at all.

        The UNMITIGATED CONTROL is the discriminating experiment (see the
        header): on a core that may have removed the hazard in hardware
        (1.4E -> 1.4F, GideonZ/1541ultimate 59594060), a MITIGATED build
        passes either way, so it cannot tell "the settle fixed it" from "the
        core removed it". Only an unmitigated build can. Such a build has no
        `nistcurves_reu_dma_wait` to poke -- its settle is whatever the
        instruction stream inherently provides -- so every poke is a no-op
        and the ladder collapses to a single native-settle cell.
        """
        return "nistcurves_reu_dma_wait" in self.labels

    def set_settle(self, form: str, k: int = 0):
        if not self.mitigated:
            return          # unmitigated control: nothing to poke, by design
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
        if not self.mitigated:
            return      # unmitigated control: the sticky flag does not exist
        self.write(self.labels["nistcurves_reu_dma_timeout"], b"\x00")

    def dma_timeout_flag(self):
        if not self.mitigated:
            return 0    # unmitigated control: no sticky flag exists
        return self.read(self.labels["nistcurves_reu_dma_timeout"], 1)[0]

    # -- in-band clock verification ----------------------------------------
    def measure_mhz(self, expect_mhz: int):
        self.clock_vic = None
        est = run_clock_measurement(
            expect_mhz, lambda outer: self._clock_window(outer, expect_mhz))
        if est is not None and self.clock_vic is not None:
            d011, d015 = self.clock_vic
            est.vic_den = (d011 >> 4) & 1
            est.sprites = d015
        return est

    def _clock_window(self, outer: int, expect_mhz: int) -> int | None:
        """One OP_CLOCK call: run `outer` loop passes, return jiffies."""
        self.write(ARG_ADDR, bytes((outer >> (8 * k)) & 0xFF
                                   for k in range(CLOCK_COUNTER_BYTES)))
        self.write(self.labels["bench_ticks"], b"\x00\x00\x00")
        if self.call(OP_CLOCK, timeout_for("clock", expect_mhz),
                     poll_interval=0.05) is None:
            return None
        raw = self.read(self.labels["bench_ticks"], 3)
        # $D011 / $D015 as OP_CLOCK read them on the C64 side (ARG+3/+7);
        # the host reads plain RAM here, never I/O.
        vic = self.read(ARG_ADDR + 3, 5)
        self.clock_vic = (vic[0], vic[4])
        return (raw[0] << 16) | (raw[1] << 8) | raw[2]


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
        self.contaminated = False   # precondition failed: table was not correct

    @property
    def verdict(self):
        if self.contaminated:
            # NOT "FAIL". A cell whose precondition failed measured something
            # other than the device, and a FAIL word here would be read as a
            # result. 2026-08-30: five such cells were reported as FAIL and
            # relayed to another lane before the identical numbers gave it
            # away.
            return "CONTAMINATED"
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
            # issue #173: the jiffy-quantisation bound travels with the value,
            # so a reader cannot take a 1-decimal figure for a 1% claim.
            f"clock_pm={'%.2f' % measured_mhz.pm if hasattr(measured_mhz, 'pm') else 'n/a'}",
            # the display state the clock was measured under: it is the
            # effective CPU rate with these on (badlines / sprite DMA)
            f"vic_den={getattr(measured_mhz, 'vic_den', 'n/a')}",
            f"sprites={'0x%02X' % measured_mhz.sprites if hasattr(measured_mhz, 'sprites') else 'n/a'}",
            f"settle_cy={'native(unmitigated)' if self.settle_cy < 0 else self.settle_cy}",
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


def assert_table_correct(dev, mhz, rows, where: str) -> bool:
    """PRECONDITION for every measured cell: the REU multiply table must
    already hold correct products before we measure anything.

    Why this exists (2026-08-30): leg 3's poison-without-rebuild self-check
    left the table poisoned and nothing re-ran reu_mul_init, so the whole
    fetch ladder measured a poisoned table and reported 100/100 FAIL at every
    settle length. The tell was that five cells returned BIT-IDENTICAL
    numbers -- a timing hazard cannot do that -- and the mismatches were
    exactly `want ^ 0x5A`, our own documented poison.

    Asserting the precondition beats inspecting the corruption afterwards:
    it fires on the first cell rather than the second, it does not depend on
    the corruption carrying a recognisable pattern, and it also catches a
    FOREIGN writer -- REU contents survive reboots, PRG loads and lane
    changes, and this device is shared with lanes whose traffic is invisible
    to our lock.

    Uses a long settle so that a genuine settle hazard cannot make a correct
    table look wrong here; this checks the TABLE, not the timing.
    """
    mdl, mdh = (dev.labels["nistcurves_mul_dma_lo"],
                dev.labels["nistcurves_mul_dma_hi"])
    dev.set_settle("orig", 0)
    bad = []
    for a in rows[:4]:
        want = expected_row(a)
        pois = poison_row(a)
        dev.write(mdl, pois[:256]); dev.write(mdh, pois[256:])
        dev.write(dev.labels["nistcurves_mul_cached_a"], bytes([a]))
        if dev.call(OP_FETCH_HOST, timeout_for("fetch", mhz)) is None:
            print(f"    PRECONDITION [{where}]: TIMEOUT fetching row {a}")
            return False
        got = dev.read(mdl, 256) + dev.read(mdh, 256)
        if got != want:
            n_pois = sum(1 for g, w in zip(got, want)
                         if g == (w ^ 0x5A) or g == ((w ^ 0x5A) ^ 0xFF))
            bad.append((a, sum(1 for g, w in zip(got, want) if g != w), n_pois))
    if bad:
        print(f"    PRECONDITION FAIL [{where}]: the REU table is NOT correct "
              f"before measuring. Rows {[b[0] for b in bad]}; "
              f"wrong/poison-matching bytes {[(b[1], b[2]) for b in bad]}.")
        print("      A high poison-matching count means WE contaminated it "
              "(a poison step with no rebuild). Otherwise something outside "
              "this run wrote the REU.")
        return False
    return True


def fetch_cell(dev, mhz, reu_size, rows, n_fetches, settle, name,
               host_read=True, table_poison=None) -> CellResult:
    """FETCH-path cell: scrub -> fetch -> cpu-read.

    This is the surface where the defect has actually been observed
    (x25519's stale mul_dma_lo[0..1] / mul_dma_hi[0]), so it carries the prior
    positive and is never dropped for time.
    """
    form, k = settle
    # An unmitigated build has no pokeable settle; report it as native rather
    # than as the cycle count of a stub that was never written.
    settle_cy = cell_settle_cy(form, k, dev.mitigated)
    cell = CellResult(name, mhz, settle_cy, reu_size,
                      "cpu" + ("+host" if host_read else ""), "fetch")
    mdl, mdh = (dev.labels["nistcurves_mul_dma_lo"],
                dev.labels["nistcurves_mul_dma_hi"])
    cached_a = dev.labels["nistcurves_mul_cached_a"]
    dev.clear_dma_timeout()
    dev.drain_status()
    # PRECONDITION: the table must already be correct. A cell that measures a
    # contaminated table reports a 100% failure that says nothing about the
    # device -- and it is indistinguishable from a real result unless you
    # happen to run a second cell and notice the numbers are identical.
    if not assert_table_correct(dev, mhz, rows, name):
        cell.error = "PRECONDITION_table_not_correct_before_cell"
        cell.contaminated = True
        return cell
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


def cell_settle_cy(form: str, k: int, mitigated: bool) -> int:
    """settle_cy a CELL row may claim for a POKED settle.

    An unmitigated control has no `nistcurves_reu_dma_wait`, so every poke is
    a no-op (Device.set_settle returns early) and the cell runs at the
    build's native settle.  -1 renders as `settle_cy=native(unmitigated)` --
    the convention fetch_cell always followed and stash_cell did not.
    """
    return stub_cycles(form, k) if mitigated else -1


def cell_name(surface: str, mhz: int, cy: int, mitigated: bool) -> str:
    """Name of a cell whose settle is a POKE (fetch / stash ladder).  On a
    control the requested ladder point is kept only to keep names unique,
    and spelled so it cannot be read as a delivered settle."""
    if mitigated:
        return f"{surface}_{mhz}MHz_{cy}cy"
    return f"{surface}_{mhz}MHz_native_unpoked-req{cy}"


def not_run_line(surface: str, mhz: int, cy: int, size: str, poked: bool,
                 mitigated: bool, devstr: str, prg_sha: str) -> str:
    """CELL row for a declared cell that never ran.  `poked`: its settle
    would have come from the settle poke (false for the bare-metal arbiter,
    whose +4 cy read distance is its own code)."""
    if mhz is None:                 # crosscheck: clock picked after leg 4
        settle = cy if mitigated else "native(unmitigated)"
        return (f"CELL {surface} surface=fetch clock=n/a "
                f"settle_cy={settle} reu={size.replace(' ', '')} N=0 k=0 "
                f"verdict=NOT_RUN device={devstr} "
                f"prg=sha256:{prg_sha[:16]}")
    if poked:
        name = cell_name(surface, mhz, cy, mitigated)
        settle = cy if mitigated else "native(unmitigated)"
    else:
        name, settle = f"{surface}_{mhz}MHz_{cy}cy", cy
    return (f"CELL {name} surface={surface} clock={mhz} "
            f"settle_cy={settle} reu={size.replace(' ', '')} N=0 k=0 "
            f"verdict=NOT_RUN device={devstr} "
            f"prg=sha256:{prg_sha[:16]}")


def leg4_line(mhz: int, m) -> str:
    """Leg 4's per-clock line for a ClockEstimate `m`."""
    off = abs(m - mhz) / mhz
    den = getattr(m, "vic_den", None)
    spr = getattr(m, "sprites", None)
    state = (f"vic_den={den if den is not None else 'n/a'} sprites="
             + (f"0x{spr:02X}" if spr is not None else "n/a"))
    if den == 1:
        cond = ("effective CPU rate with the display on: includes badlines "
                f"(~{BADLINE_STEAL_NTSC:.2%} NTSC / {BADLINE_STEAL_PAL:.2%} "
                "PAL of PHI2 cycles) and, at the top two speed indices, "
                "GideonZ/1541ultimate#874's one-PHI2-multiple shortfall")
    elif den == 0:
        cond = ("effective CPU rate with the display blanked (no badlines); "
                "#874's top-index shortfall still applies")
    else:
        cond = "display state not captured"
    return (f"    set {mhz} MHz -> measured {m:.2f} "
            f"+-{m.pm:.2f} MHz ({off * 100:.1f}% off) [{state}; {cond}; "
            f"not a delivered-clock reading]; fixed "
            f"overhead (fit intercept, as measured; may be "
            f"~0) "
            f"{m.overhead_s * 1000:.1f} +-"
            f"{m.overhead_pm_s * 1000:.1f} ms; windows "
            f"(passes, jiffies) {m.windows}"
            + ("  <-- DISCARDED (>20%)" if off > 0.20 else ""))


def leg5_summary(mhz: int, th: int | None, mitigated: bool) -> str:
    """Leg 5's per-clock summary line.

    On an unmitigated control every ladder point ran at the same native
    settle (the poke is a no-op), so `th` is just the nominal label of the
    first clean cell and names no settle that was applied.  Say what was
    measured instead: whether the native settle was clean.
    """
    if not mitigated:
        return (f"    {mhz} MHz: native settle (unmitigated control; the "
                f"ladder collapsed to one point) — "
                + ("a clean cell followed the last failing one" if th
                   else "no clean cell after the last failing one; see the "
                        "CELL rows for N and k"))
    return (f"    {mhz} MHz: "
            + (f"smallest clean settle {th} cy" if th
               else "no ladder point was clean"))


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
    cell = CellResult(name, mhz, cell_settle_cy(form, k, dev.mitigated),
                      reu_size, "host",
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
               "nistcurves_mul_cached_a": 0x7D00,
               "bench_start": 0x087C, "bench_stop": 0x0887,
               "fp_sqr": 0x1234})
    try:
        code = build_trampoline(fake)
        check(f"trampoline assembles and links ({len(code)} B, fits under "
              f"${TRAMPOLINE_LIMIT:04X})",
              len(code) <= TRAMPOLINE_LIMIT - TRAMPOLINE_ADDR)
    except Exception as e:
        check("trampoline assembles and links", False, f"{type(e).__name__}: {e}")

    # -- the clock loop's cycle model, against the ASSEMBLED bytes ----------
    # Oracle sanity first: `ldx #0 / dex / bne` is the textbook
    # 2 + 256*5 - 1 = 1281 cycles, and 255 more when the bne crosses a page.
    tiny = bytes([LDX_IMM, 0, DEX, BNE, 0xFD])
    for org_, want in ((0xC000, 1281), (0xC0FD, 1281 + 255)):
        try:
            got, _ = simulate_6502(tiny, org_, org_, {org_ + len(tiny)}, {})
        except Exception as e:
            got = f"{type(e).__name__}: {e}"
        check(f"simulator: ldx#0/dex/bne at ${org_:04X} is {want} cycles",
              got == want, f"got {got}")
    try:
        code_, syms_ = build_trampoline(fake, symbols=True)
        bad = {n_: (clock_cycles(n_),
                    clock_loop_cycles_simulated(code_, syms_, n_))
               for n_ in (1, 2, 255, 256, 257, 513, 600)}
        bad = {k_: v_ for k_, v_ in bad.items() if v_[0] != v_[1]}
        check("clock_cycles(n) == cycles simulated from the trampoline's "
              "bytes, n in {1,2,255,256,257,513,600} (borrow cases incl.)",
              not bad, "n: (model, simulated) " + str(bad))
        # One pass entered at counter value v costs clock_cycles(v) -
        # clock_cycles(v-1); simulate exactly that pass, incl. the 24-bit
        # high-byte borrow a full run could not reach in reasonable time.
        bad = {}
        for v in (2, 5, 256, 512, 65536, 131072, 65536 * 3 + 256):
            mem_ = {ARG_ADDR + 4 + k: (v >> (8 * k)) & 0xFF
                    for k in range(CLOCK_COUNTER_BYTES)}
            got, _ = simulate_6502(code_, TRAMPOLINE_ADDR, syms_["couter"],
                                   {syms_["couter"], syms_["cdone"]}, mem_)
            want = clock_cycles(v) - clock_cycles(v - 1)
            left = sum(mem_[ARG_ADDR + 4 + k] << (8 * k)
                       for k in range(CLOCK_COUNTER_BYTES))
            if got != want or left != v - 1:
                bad[v] = (want, got, left)
        check("each single pass (incl. 24-bit high-byte borrow) costs what "
              "clock_cycles() says and decrements the counter by exactly 1",
              not bad, "v: (model, simulated, counter after) " + str(bad))
    except Exception as e:
        check("clock loop simulates", False, f"{type(e).__name__}: {e}")

    # -- issue #173: a fixed overhead must not read as a clock deficit ------
    # Synthetic device: the window is clock_cycles(outer) at the TRUE clock
    # plus a fixed overhead, counted by a 60 Hz jiffy clock started at an
    # arbitrary phase (floor), exactly what bench_start/bench_stop observe.
    # The phase rotates per call, as it does on hardware.
    def synth(f_mhz, over_s, phases, log):
        it = iter(phases * 64)

        def window(outer):
            t = clock_cycles(outer) / (f_mhz * 1e6) + over_s
            log.append(t)
            return int(t * 60.0 + next(it))
        return window

    worst = []
    for f_true, expect in ((1, 1), (16, 16), (48, 48), (64, 64),
                           (47.0, 48), (60.0, 64), (1, 48), (64, 16)):
        for over_j in (0.0, 2.0, 3.0, 15.0):
            for phases in ((0.0, 0.0), (0.999, 0.0), (0.0, 0.999),
                           (0.5, 0.25)):
                log: list[float] = []
                est = run_clock_measurement(
                    expect, synth(f_true, over_j / 60.0, list(phases), log))
                mhz = getattr(est, "mhz", est)
                err = (abs(mhz - f_true) / f_true if mhz else float("inf"))
                over = getattr(est, "overhead_s", None)
                lo_, hi_ = (getattr(est, "lo", None), getattr(est, "hi", None))
                o_pm = getattr(est, "overhead_pm_s", None)
                ok = (err <= 0.006
                      and over is not None and o_pm is not None
                      and abs(over - over_j / 60.0) <= o_pm
                      and (o_pm <= 1.2 / 60.0 if f_true == expect else True)
                      and lo_ is not None and lo_ <= f_true <= hi_
                      and (hi_ - lo_) / 2 / f_true <= 0.006
                      and max(log) <= 40.0)
                if not ok:
                    worst.append(f"f={f_true} expect={expect} "
                                 f"O={over_j:g}j ph={phases}: "
                                 f"mhz={mhz if mhz is None else round(mhz, 3)}"
                                 f" err={err:.2%} O_rec={over} "
                                 f"bounds=({lo_},{hi_}) "
                                 f"longest={max(log) if log else 0:.1f}s")
    check("two-point clock: within 0.6% of truth, its +-bounds contain the "
          "truth and are <= 0.6%, and the "
          "injected overhead is recovered within its stated bound (<= 1.2 "
          "jiffy when the clock is the expected one) at 1/16/48/64 MHz, "
          "0/2/3/15-jiffy overhead, any phase; no window over 40 s",
          not worst, f"{len(worst)} cases, e.g. " + "; ".join(worst[:3]))
    # The issue's reported artifact, reproduced on the OLD estimator's shape
    # (one 0.5 s window), is what the new one must be immune to: the same
    # 2-jiffy overhead at every clock must leave the estimate unmoved.
    moved = []
    for f_true in (1, 16, 48, 64):
        a0 = run_clock_measurement(f_true, synth(f_true, 0.0, [0.5], []))
        a2 = run_clock_measurement(f_true, synth(f_true, 2 / 60, [0.5], []))
        m0, m2 = getattr(a0, "mhz", a0), getattr(a2, "mhz", a2)
        if not (m0 and m2 and abs(m2 - m0) / f_true <= 0.005):
            moved.append(f"{f_true} MHz: {m0} -> {m2}")
    check("injecting a 2-jiffy fixed overhead does not move the estimate",
          not moved, "; ".join(moved))
    est48 = run_clock_measurement(48, synth(48, 2 / 60, [0.5], []))
    ln48 = CellResult("x", 48, 12, "512 KB", "cpu", "fetch").line(
        "d", est48, "0" * 64)
    # -- OP_CLOCK end to end: host encoding -> trampoline copy -> counter ----
    # The loop checks above start at `couter` with the counter pre-seeded, so
    # the ARG->counter copy and the host's encode/decode were never run.
    # Here the ARGs are written by Device._clock_window itself, the copy runs
    # on the assembled bytes, and the fake answers the way bench_stop does:
    # jiffy_clock $A0 (MSB), $A1, $A2 (LSB) copied in order to bench_ticks.
    class _FakeClockDev(Device):
        def __init__(self, f_mhz, d011=0x1B, d015=0x00):
            super().__init__(None, None)
            self.labels = fake
            self.mem: dict[int, int] = {}
            self.f = f_mhz
            self.d011, self.d015 = d011, d015
            self.code, self.syms = build_trampoline(fake, symbols=True)
            self.counters: list[int] = []

        def write(self, addr, data):
            for i_, b_ in enumerate(bytes(data)):
                self.mem[addr + i_] = b_

        def read(self, addr, n):
            return bytes(self.mem.get(addr + i_, 0) for i_ in range(n))

        def call(self, op, timeout, poll_interval=0.02):
            if op != OP_CLOCK:
                raise AssertionError(f"unexpected op {op}")
            start = self.syms["clock"]
            if self.code[start - TRAMPOLINE_ADDR] != JSR:
                raise AssertionError("OP_CLOCK no longer opens with jsr")
            simulate_6502(self.code, TRAMPOLINE_ADDR, start + 3,
                          {self.syms["couter"]}, self.mem)
            n_ = sum(self.mem.get(ARG_ADDR + 4 + k, 0) << (8 * k)
                     for k in range(CLOCK_COUNTER_BYTES))
            self.counters.append(n_)
            j_ = int(clock_cycles(n_) / (self.f * 1e6) * 60.0 + 0.5)
            self.write(fake["bench_ticks"],
                       bytes([(j_ >> 16) & 0xFF, (j_ >> 8) & 0xFF, j_ & 0xFF]))
            # The VIC registers as the C64 side would see them; whatever the
            # trampoline does with them after bench_stop runs on its bytes.
            self.mem[0xD011], self.mem[0xD015] = self.d011, self.d015
            if "cvic" in self.syms:
                simulate_6502(self.code, TRAMPOLINE_ADDR, self.syms["cvic"],
                              {self.syms["cvicend"]}, self.mem)
            return 0.1
    fake["bench_ticks"] = 0x0890
    # -- what clock_measured IS: the effective rate with the display on -----
    vic_bad = []
    try:
        for d011_, d015_, den_, spr_ in ((0x1B, 0x00, 1, "0x00"),
                                         (0x0B, 0x00, 0, "0x00"),
                                         (0x9B, 0x05, 1, "0x05")):
            fdv = _FakeClockDev(48, d011=d011_, d015=d015_)
            est_v = fdv.measure_mhz(48)
            ln_v = CellResult("x", 48, 12, "512 KB", "cpu", "fetch").line(
                "d", est_v, "0" * 64)
            l4_v = leg4_line(48, est_v) if est_v is not None else ""
            for what_, s_ in (("CELL", ln_v), ("leg 4", l4_v)):
                if (f"vic_den={den_}" not in s_
                        or f"sprites={spr_}" not in s_):
                    vic_bad.append(f"$D011=${d011_:02X} $D015=${d015_:02X}: "
                                   f"{what_} lacks vic_den={den_} / "
                                   f"sprites={spr_}: {s_.strip()[:100]!r}")
            if "vic_den=" in ln_v and (ln_v.index("vic_den=")
                                        < ln_v.index("clock_pm=")):
                vic_bad.append("vic_den precedes the clock it qualifies")
    except Exception as e:
        vic_bad.append(f"{type(e).__name__}: {e}")
    check("the clock reading carries the display state it was taken under "
          "(vic_den from $D011 bit 4, sprites=$D015) on every CELL row and "
          "the leg-4 line, read on the C64 side by OP_CLOCK",
          not vic_bad, "; ".join(vic_bad[:3]))
    txt_bad = []
    try:
        buf_ = io.StringIO()
        with contextlib.redirect_stdout(buf_):
            describe_plan(parse_args(["--seed", "1"]), sample_rows(20, 1))
        plan_ = buf_.getvalue()
        l4_ = leg4_line(48, _FakeClockDev(48).measure_mhz(48))
        for name_, t_ in (("dry-run plan", plan_), ("leg-4 line", l4_),
                          ("module docstring", __doc__ or "")):
            low_ = t_.lower()
            for need_ in ("badline", "#874", "display on"):
                if need_ not in low_:
                    txt_bad.append(f"{name_} does not name {need_!r}")
            if re.search(r"(?<!not )(?<!not a )delivered clock", low_):
                txt_bad.append(f"{name_} calls the reading a delivered clock")
    except Exception as e:
        txt_bad.append(f"{type(e).__name__}: {e}")
    check("clock_measured is labelled the effective CPU rate with the display "
          "on: dry-run, leg 4 and docstring name badlines and #874 and never "
          "call it a delivered clock", not txt_bad, "; ".join(txt_bad[:4]))
    try:
        bad = []
        for f_, n_ in ((0.05, 0x012345), (0.2, 0x00FF01), (48, 0x0A0B0C),
                       (1, 0x000102)):
            fd = _FakeClockDev(f_)
            j_got = fd._clock_window(n_, 48)
            j_want = int(clock_cycles(n_) / (f_ * 1e6) * 60.0 + 0.5)
            if fd.counters != [n_] or j_got != j_want:
                bad.append(f"n=${n_:06X} f={f_}: counter "
                           f"{[hex(c) for c in fd.counters]} jiffies "
                           f"{j_got} want {j_want}")
        check("_clock_window end to end: ARG encode -> trampoline copy -> "
              "24-bit counter -> bench_ticks decode (3-byte jiffy counts "
              "included)", not bad, "; ".join(bad))
        bad = []
        for f_ in (1, 16, 48, 64):
            est_ = _FakeClockDev(f_).measure_mhz(f_)
            if est_ is None or not est_.lo <= f_ <= est_.hi:
                bad.append(f"{f_} MHz -> {est_ and (est_.lo, est_.hi)}")
        check("measure_mhz end to end through the fake device brackets the "
              "true clock at 1/16/48/64 MHz", not bad, "; ".join(bad))
    except Exception as e:
        check("OP_CLOCK end-to-end fake device", False,
              f"{type(e).__name__}: {e}")
    finally:
        fake.pop("bench_ticks", None)

    check("a CELL row carries clock_measured AND its clock_pm bound",
          est48 is not None and "clock_measured=48.0" in ln48
          and re.search(r"clock_pm=0\.\d\d ", ln48) is not None, ln48)

    # -- issue #172: firmware provenance comes from the device observed ------
    # /v1/info strings as reported by the two devices this tool has met.
    u64e = {"product": "Ultimate 64 Elite", "unique_id": "601A96",
            "firmware_version": "3.15", "fpga_version": "11F",
            "core_version": "1.4F"}
    c64u = {"product": "C64 Ultimate", "unique_id": "5D2518",
            "firmware_version": "1.1.0", "fpga_version": "122",
            "core_version": "1.49"}
    for dev_info in (u64e, c64u):
        rep = dev_info["firmware_version"]
        note, why = firmware_note_for_row(rep, None)
        row = device_string(dev_info, note) if note else ""
        m_ = re.search(r"/fw([0-9.]+)", row)
        check(f"no --firmware-note: the row's fw is the reported {rep}, not a "
              f"constant", why is None and m_ is not None
              and m_.group(1) == rep, f"row {row!r} refusal {why!r}")
    note, why = firmware_note_for_row("1.1.0", "3.15+patch814")
    check("an explicit note naming fw 3.15 on a device reporting 1.1.0 is "
          "REFUSED", note is None and bool(why), f"recorded {note!r}")
    note, why = firmware_note_for_row("1.1.0", "1.15+x")
    check("major matches but minor does not (1.15 vs 1.1.0) -> REFUSED",
          note is None and bool(why), f"recorded {note!r}")
    # V-prefixed versions are real /v1/info output (the harness's
    # u64_capabilities strips "Vv" and its fixtures use these strings).
    for rep in ("V3.14d", "V3.16", "V3.15", "V3.13"):
        note, why = firmware_note_for_row(rep, None)
        check(f"no note, reported {rep!r}: recorded as reported, not "
              f"'not_reported'", why is None and note is not None
              and note.startswith(rep) and "not_reported" not in note,
              f"{note!r} {why!r}")
    for rep, nt, ok_want in (("V3.14d", "V3.14d+patch", True),
                             ("V3.14d", "3.14d+patch", True),
                             ("3.14d", "V3.14d+patch", True),
                             ("V3.15", "v3.15", True),
                             ("V3.16", "3.15+patch814", False),
                             ("V3.14d", "V3.14+patch", False),
                             ("V3.15", "V3.150", False)):
        note, why = firmware_note_for_row(rep, nt)
        check(f"reported {rep!r}, note {nt!r} -> "
              f"{'accepted' if ok_want else 'REFUSED'}",
              (note == nt and why is None) if ok_want
              else (note is None and bool(why)), f"{note!r} {why!r}")
    # The note lands inside space-delimited key=value CELL rows.
    for nt in ("1.1.0 verdict=PASS clock_measured=64.0", "1.1.0 + patch814",
               "1.1.0+k=v", "1.1.0\tx", "1.1.0+patch\n",
               "1.1.0/fpga999"):
        note, why = firmware_note_for_row("1.1.0", nt)
        check(f"note {nt!r} (whitespace, '=' or '/') -> REFUSED",
              note is None and bool(why), f"recorded {note!r}")
    for dev_info in (u64e, c64u, dict(c64u, firmware_version="?")):
        nt_, _w = firmware_note_for_row(dev_info["firmware_version"], None)
        ds_ = device_string(dev_info, nt_)
        check(f"device field for {dev_info['product']!r} is one token "
              f"with exactly 5 '/'-fields (no whitespace or '=')",
              not re.search(r"[\s=]", ds_) and len(ds_.split("/")) == 5,
              repr(ds_))
    note, why = firmware_note_for_row("1.1.0", "1.1.5")
    check("a note claiming a different patch release (1.1.5 vs 1.1.0) -> "
          "REFUSED", note is None and bool(why), f"recorded {note!r}")
    note, why = firmware_note_for_row("3.15", "3.150")
    check("a note that CONTINUES the reported version (3.150) -> REFUSED",
          note is None and bool(why), f"recorded {note!r}")
    check("identity unchanged across a reboot -> no fields",
          device_identity_changed(u64e, dict(u64e)) == [])
    check("a different box answering after reboot is detected",
          device_identity_changed(u64e, c64u) != [])
    for fld, newv in (("firmware_version", "3.16"), ("fpga_version", "120"),
                      ("core_version", "1.4E"), ("product", "C64 Ultimate"),
                      ("unique_id", "000000")):
        ch_ = device_identity_changed(u64e, dict(u64e, **{fld: newv}))
        check(f"only {fld} changes across a reboot -> refused, naming it",
              ch_ == [fld], f"changed fields reported: {ch_}")
    note, why = firmware_note_for_row("3.15", "3.15+patch814")
    check("an explicit note agreeing with /v1/info is recorded verbatim",
          note == "3.15+patch814" and why is None, f"{note!r} {why!r}")
    note, why = firmware_note_for_row("3.14d", "3.14d")
    check("a lettered build (3.14d) agrees with its own note",
          note == "3.14d" and why is None, f"{note!r} {why!r}")
    note, why = firmware_note_for_row("?", "3.15+patch814")
    check("an explicit note cannot be verified against a missing "
          "firmware_version -> REFUSED", note is None and bool(why),
          f"recorded {note!r}")
    note, why = firmware_note_for_row("3.15", "patched")
    check("a note that does not lead with a version -> REFUSED",
          note is None and bool(why), f"recorded {note!r}")

    # The verdict PROSE is a firmware attribution too, emitted beside rows.
    clean = CellResult("arb", 64, 4, "512 KB", "cpu", "arbiter"); clean.n = 100
    prose_ = " ".join(arbiter_verdict(clean, fw_label="1.1.0")
                      + anchoring_verdict(40, 12, 64, 16, 12,
                                          fw_label="1.1.0"))
    check("verdict prose names the OBSERVED firmware, never a hardcoded 3.15",
          "3.15" not in prose_ and "#814" not in prose_ and "1.1.0" in prose_,
          prose_[:0] + str([s_ for s_ in ("3.15", "#814") if s_ in prose_]))

    # -- issue #172 defect 2: a refused or unavailable lock never exits 0 ----
    class _Lock:
        def __init__(self, result):
            self.result, self.calls = result, []

        def read_info(self):
            return {"pid": 72223}

        def acquire(self, timeout=None, progress_window=60.0):
            self.calls.append((timeout, progress_window))
            if isinstance(self.result, BaseException):
                raise self.result
            return self.result
    _out = sys.stdout
    try:
        sys.stdout = open(os.devnull, "w")
        rc_refused = acquire_device_lock(_Lock(False), False, 1800.0)
        rc_waited = acquire_device_lock(_Lock(False), True, 5.0)
        rc_held = acquire_device_lock(_Lock(True), False, 1800.0)
        try:
            rc_broken = acquire_device_lock(_Lock(OSError("EACCES")),
                                            False, 1800.0)
        except Exception as e:
            rc_broken = f"raised {type(e).__name__}"
    finally:
        sys.stdout.close()
        sys.stdout = _out
    check("refused lock (no --wait) -> non-zero exit", rc_refused != 0,
          f"rc={rc_refused}")
    check("lock --wait timed out -> non-zero exit", rc_waited != 0,
          f"rc={rc_waited}")
    # An exception escaping main() is exit status 1 from the interpreter, so
    # propagating is an acceptable non-zero outcome; returning 0 is not.
    check("unavailable lock (acquire raises) -> non-zero exit",
          rc_broken != 0, f"rc={rc_broken}")
    check("acquired lock -> 0 (the run proceeds)", rc_held == 0,
          f"rc={rc_held}")

    # -- a run that produced no real verdict must not exit 0 ----------------
    def _cells(*verdicts, settle=12):
        out = []
        for i, v in enumerate(verdicts):
            c_ = CellResult(f"c{i}", 48, settle, "512 KB", "cpu", "fetch")
            if v in ("PASS", "FAIL"):
                c_.n, c_.k = 10, (0 if v == "PASS" else 1)
            elif v == "ERROR":
                c_.n, c_.error = 3, "timeout"
            elif v == "CONTAMINATED":
                c_.n, c_.contaminated = 10, True
            out.append(c_.line("d", 48.0, "0" * 64))
        return out
    _fx = ("NOT_RUN", "ERROR", "CONTAMINATED", "PASS", "FAIL")
    _got = [re.search(r" verdict=(\S+)", l_).group(1) for l_ in _cells(*_fx)]
    check("exit-status fixtures really carry the verdicts they name",
          tuple(_got) == _fx, str(_got))
    orig_pass = _cells("PASS", settle=ORIG_CYCLES)
    orig_fail = _cells("FAIL", settle=ORIG_CYCLES)
    # (name, lines, rc in, mitigated build, exit status wanted) -- the codes
    # are the documented contract, so they are literals here, not constants.
    exit_cases = [
        ("every cell NOT_RUN", _cells("NOT_RUN", "NOT_RUN"), 0, True, 3),
        ("every cell ERROR", _cells("ERROR", "ERROR"), 0, True, 3),
        ("every cell CONTAMINATED", _cells("CONTAMINATED"), 0, True, 3),
        ("NOT_RUN + ERROR + CONTAMINATED only",
         _cells("NOT_RUN", "ERROR", "CONTAMINATED"), 0, True, 3),
        ("no CELL line at all", [], 0, True, 3),
        ("one PASS among NOT_RUNs is PARTIAL", _cells("NOT_RUN", "PASS"),
         0, True, 4),
        ("1 PASS + 21 ERROR is PARTIAL", _cells("PASS", *["ERROR"] * 21),
         0, True, 4),
        ("1 PASS + 21 NOT_RUN is PARTIAL", _cells("PASS", *["NOT_RUN"] * 21),
         0, True, 4),
        ("1 FAIL + 21 CONTAMINATED is PARTIAL",
         _cells("FAIL", *["CONTAMINATED"] * 21), 0, True, 4),
        ("complete run, all PASS", _cells("PASS", "PASS") + orig_pass,
         0, True, 0),
        ("complete run, sub-floor FAILs are bracket data",
         _cells("FAIL", "PASS") + orig_pass, 0, True, 0),
        ("a FAIL at the shipped orig settle is a regression signal",
         _cells("PASS") + orig_fail, 0, True, 5),
        ("orig FAIL outranks partial", _cells("NOT_RUN") + orig_fail,
         0, True, 5),
        ("orig FAIL on an UNMITIGATED control is expected, not 5",
         _cells("PASS") + orig_fail, 0, False, 0),
        ("^C keeps 130 even with verdicts", _cells("PASS"), 130, True, 130),
    ]
    _eh = exit_status_help()
    _codes = (EXIT_OK, EXIT_ABORT, EXIT_REFUSED, EXIT_NO_VERDICT,
              EXIT_PARTIAL, EXIT_ORIG_FAIL, EXIT_INTERRUPTED)
    _undoc = [c_ for c_ in _codes
              if not re.search(rf"^  {c_}\s", _eh, re.M)]
    check("every EXIT_* code is documented in the docstring / --help",
          not _undoc and len(set(_codes)) == len(_codes), f"undocumented {_undoc}")
    for name_, cl_, rc_in, mit_, want in exit_cases:
        _out = sys.stdout
        try:
            sys.stdout = open(os.devnull, "w")
            got = run_exit_status(cl_, rc_in, mitigated=mit_)
        finally:
            sys.stdout.close()
            sys.stdout = _out
        check(f"exit status: {name_} -> {want}", got == want, f"got {got}")

    # -- a control build cannot claim a poked settle in ANY CELL field ------
    # stash_cell is driven for real: the fake's call() times out, so it
    # returns right after building its CellResult (poison_table_failed).
    class _FakeStashDev(Device):
        def __init__(self, labels_):
            super().__init__(None, None)
            self.labels = labels_
            self.wait_orig = bytes(WAIT_ROUTINE_BYTES - 1) + b"\x60"
            self.mem: dict[int, int] = {}

        def write(self, addr, data):
            for i_, b_ in enumerate(bytes(data)):
                self.mem[addr + i_] = b_

        def read(self, addr, n):
            return bytes(self.mem.get(addr + i_, 0) for i_ in range(n))

        def call(self, op, timeout, poll_interval=0.02):
            return None
    unmit_labels = _L({k_: v_ for k_, v_ in fake.items()
                       if k_ not in MITIGATION_LABELS})
    lbl_bad = []
    for mit_, labels_ in ((True, fake), (False, unmit_labels)):
        fd_ = _FakeStashDev(labels_)
        if fd_.mitigated != mit_:
            lbl_bad.append(f"fixture mitigated={fd_.mitigated}, want {mit_}")
            continue
        for form_, k_ in (("nop", 0), ("nop", 16), ("orig", 0)):
            cy_ = stub_cycles(form_, k_)
            _out = sys.stdout
            try:
                sys.stdout = open(os.devnull, "w")
                c_ = stash_cell(fd_, 48, "512 KB", [1], 5, (form_, k_),
                                cell_name("stash", 48, cy_, mit_))
            finally:
                sys.stdout.close()
                sys.stdout = _out
            rows_ = {"stash_cell": c_.line("d", 48.0, "0" * 64),
                     "not_run(stash)": not_run_line(
                         "stash", 48, cy_, "512 KB", True, mit_, "d", "0" * 64),
                     "not_run(fetch)": not_run_line(
                         "fetch", 48, cy_, "512 KB", True, mit_, "d", "0" * 64)}
            for what_, ln_ in rows_.items():
                claims = re.findall(rf"(?<![0-9]){cy_}cy|settle_cy={cy_}\b", ln_)
                if mit_ and f"settle_cy={cy_}" not in ln_:
                    lbl_bad.append(f"mitigated {what_} {form_}{k_}: lost "
                                   f"settle_cy={cy_}: {ln_[:90]}")
                if not mit_ and (claims or
                                 "settle_cy=native(unmitigated)" not in ln_):
                    lbl_bad.append(f"UNMITIGATED {what_} {form_}{k_} claims "
                                   f"{claims}: {ln_[:90]}")
    arb_ = not_run_line("arbiter", 48, 4, "512 KB", False, False, "d", "0" * 64)
    if "settle_cy=4 " not in arb_:
        lbl_bad.append(f"arbiter's own +4 cy lost on a control: {arb_[:80]}")
    check("CELL rows on a control build never claim a poked settle (name or "
          "settle_cy; stash_cell driven, NOT_RUN rows too); mitigated rows "
          "keep it; the arbiter keeps its own +4 cy",
          not lbl_bad, "; ".join(lbl_bad[:4]))

    # -- declared cells follow --only; the exit status follows declared ------
    def _run(argv_, ran_if, extra_emitted=0, discard=()):
        """A synthetic run: every declared cell for which ran_if(d) holds
        PASSes, plus `extra_emitted` undeclared PASS rows (e.g. a stage whose
        cells are not declared); the rest get main()'s NOT_RUN rows."""
        o_ = parse_args(argv_ + ["--seed", "1"])
        dec_ = declared_cells(o_)
        # The keys main() records come from stage_cells(), the same function
        # main() iterates -- not from the declared set and not from a copy
        # of main()'s stage gates.  `discard` models leg 4 dropping clocks;
        # the arbiter runs before leg 4, on the full speed list, as in main().
        usable_ = [m_ for m_ in o_.speeds if m_ not in discard]
        ran_ = set()
        for size_ in o_.reu_sizes:
            for stage_ in STAGES:
                for rc_ in stage_cells(o_, stage_, size_,
                                       o_.speeds if stage_ == "arbiter"
                                       else usable_):
                    if ran_if(rc_.key):
                        ran_.add(rc_.key)
        lines_ = []
        for i_, d_ in enumerate(sorted(ran_, key=str)):
            c_ = CellResult(f"{d_[0]}_{i_}", 48, 12, "512 KB", "cpu", "fetch")
            c_.n = 10
            lines_.append(c_.line("d", 48.0, "0" * 64))
        for i_ in range(extra_emitted):
            c_ = CellResult(f"extra_{i_}", 48, 12, "512 KB", "cpu", "fetch")
            c_.n = 10
            lines_.append(c_.line("d", 48.0, "0" * 64))
        lines_ += not_run_lines(dec_, ran_, True, "d", "0" * 64)
        buf_ = io.StringIO()
        with contextlib.redirect_stdout(buf_):
            rc_ = run_exit_status(lines_, 0, mitigated=True,
                                  declared_n=len(dec_))
        return rc_, dec_, buf_.getvalue()
    dc_bad = []
    rc_, dec_, _o = _run(["--only", "fetch"], lambda d: True)
    if rc_ != 0:
        dc_bad.append(f"--only fetch, all ran -> {rc_} (declared surfaces "
                      f"{sorted({d[0] for d in dec_})})")
    rc_, dec_, _o = _run(["--only", "arbiter,fetch"], lambda d: True)
    if rc_ != 0:
        dc_bad.append(f"--only arbiter,fetch, all ran -> {rc_} (declared "
                      f"{sorted({d[0] for d in dec_})})")
    rc_, dec_, _o = _run(["--only", "fetch", "--speeds", "64,16"],
                         lambda d: True, discard=(64,))
    if rc_ != 4:
        dc_bad.append(f"--only fetch, 64 MHz discarded -> {rc_}, want 4")
    rc_, dec_, _o = _run([], lambda d: d[0] != "stash")
    if rc_ != 4:
        dc_bad.append(f"default stages, stash never ran -> {rc_}, want 4")
    rc_, dec_, _o = _run(["--only", "fetch,crosscheck"], lambda d: True)
    if rc_ != 0 or not any(d[0].startswith("crosscheck") for d in dec_):
        dc_bad.append(f"--only fetch,crosscheck all ran -> {rc_}; "
                      f"crosscheck declared: "
                      f"{any(d[0].startswith('crosscheck') for d in dec_)}")
    rc_, dec_, _o = _run(["--only", "fetch,crosscheck"],
                         lambda d: not d[0].startswith("crosscheck"))
    if rc_ != 4:
        dc_bad.append(f"--only fetch,crosscheck, crosscheck never ran -> "
                      f"{rc_}, want 4")
    check("declared cells follow --only (narrowed complete run -> 0; a "
          "selected clock discarded -> 4; crosscheck declared when selected)",
          not dc_bad, "; ".join(dc_bad))
    rc_, dec_, out_ = _run(["--only", "fetch"], lambda d: True,
                           extra_emitted=3)
    check("RUN COMPLETENESS prints the true declared count, not the number "
          "of CELL lines", f"declared {len(dec_)} cell(s)" in out_,
          f"declared={len(dec_)}; printed: "
          f"{out_.strip().splitlines()[0] if out_.strip() else ''!r}")

    # -- an unimplemented stage is a usage error, alone or combined ---------
    st_bad = []
    for spec_ in ("sqr", "fetch,sqr", "arbiter,fetch,stash,crosscheck,sqr"):
        st_, err_ = parse_stages(spec_)
        if not err_ or "sqr" not in err_ or "fetch" not in err_:
            st_bad.append(f"--only {spec_} accepted as {st_} (error {err_!r})")
    for spec_, want_ in (("fetch", ["fetch"]),
                         ("stash,arbiter", ["arbiter", "stash"]),
                         ("fetch,crosscheck", ["fetch", "crosscheck"])):
        st_, err_ = parse_stages(spec_)
        if err_ or st_ != want_:
            st_bad.append(f"--only {spec_} -> {st_} {err_!r}, want {want_}")
    if not parse_stages("bogus")[1]:
        st_bad.append("--only bogus accepted")
    for spec_ in ("crosscheck", "arbiter,crosscheck", "stash,crosscheck"):
        st_, err_ = parse_stages(spec_)
        if not err_ or "crosscheck" not in err_ or "fetch" not in err_:
            st_bad.append(f"--only {spec_} (crosscheck without fetch) "
                          f"accepted as {st_}")
    # Process level: argparse's usage error is exit 2.  --dry-run touches
    # no device (U64_HOST is not needed and not set here).
    env_ = {k_: v_ for k_, v_ in os.environ.items() if k_ != "U64_HOST"}
    for spec_, word_ in (("sqr", "sqr"), ("fetch,sqr", "sqr"),
                         ("crosscheck", "crosscheck")):
        r_ = subprocess.run([sys.executable, os.path.abspath(__file__),
                             "--dry-run", "--only", spec_],
                            capture_output=True, text=True, env=env_)
        if r_.returncode != 2 or word_ not in r_.stderr:
            st_bad.append(f"process --only {spec_}: exit {r_.returncode}, "
                          f"stderr {r_.stderr.strip()[-80:]!r}")
    check("--only: an unimplemented stage (sqr), or crosscheck without "
          "fetch, is refused with exit 2, alone or combined, naming it and "
          "listing the implemented stages",
          not st_bad, "; ".join(st_bad))

    # -- leg 5 prose: a control build cannot report a settle floor ----------
    l5_bad = []
    for th_ in (12, 44, ORIG_CYCLES, None):
        s_ = leg5_summary(48, th_, mitigated=False)
        if re.search(r"\d+\s*cy\b", s_) or "native" not in s_:
            l5_bad.append(f"UNMITIGATED th={th_}: {s_.strip()!r}")
        s_ = leg5_summary(48, th_, mitigated=True)
        want_ = (f"smallest clean settle {th_} cy" if th_
                 else "no ladder point was clean")
        if want_ not in s_:
            l5_bad.append(f"mitigated th={th_}: {s_.strip()!r}")
    check("leg 5 summary: a control build names its native settle, never a "
          "'smallest clean settle N cy'; a mitigated build keeps it",
          not l5_bad, "; ".join(l5_bad))

    # -- verify-builds: the build/ guard reports even when a build raises ---
    vb_bad = []
    with tempfile.TemporaryDirectory() as ub:
        open(os.path.join(ub, "keep.o"), "w").write("x")
        kept: list[str] = []

        def _raising_inner(iters_, bdir_):
            kept.append(bdir_)
            os.remove(os.path.join(ub, "keep.o"))       # the damage
            raise SystemExit("build failed: simulated")
        buf = io.StringIO()
        raised = None
        try:
            with contextlib.redirect_stdout(buf):
                verify_builds([1], user_build=ub, inner=_raising_inner)
        except SystemExit as e:
            raised = e
        out_ = buf.getvalue()
        if raised is None:
            vb_bad.append("the inner failure was swallowed")
        if "was modified" not in out_ or "deleted keep.o" not in out_:
            vb_bad.append(f"no build/ diagnostic printed: {out_.strip()!r}")
        for k_ in kept:
            shutil.rmtree(k_, ignore_errors=True)
    check("verify-builds: when a build RAISES, the modified-build/ "
          "diagnostic is still printed and the failure still propagates",
          not vb_bad, "; ".join(vb_bad))

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

def snapshot_tree(root: str) -> dict[str, tuple[int, int]]:
    """{relpath: (size, mtime_ns)} for every file under root ({} if absent)."""
    snap = {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            st = os.stat(p)
            snap[os.path.relpath(p, root)] = (st.st_size, st.st_mtime_ns)
    return snap


def tree_changes(before: dict, after: dict) -> list[str]:
    out = [f"deleted {k}" for k in sorted(before.keys() - after.keys())]
    out += [f"created {k}" for k in sorted(after.keys() - before.keys())]
    out += [f"changed {k}" for k in sorted(before.keys() & after.keys())
            if before[k] != after[k]]
    return out


def verify_builds(iters: list[int], user_build: str = BUILD_DIR,
                  inner=None) -> int:
    # The user's build/ is not this mode's to touch: snapshot it and assert
    # it is byte-for-byte (names, sizes, mtimes) where it was afterwards.
    # `user_build` / `inner` exist so the self-test can drive this wrapper
    # without running a single build.
    inner = inner or _verify_builds
    user_build_before = snapshot_tree(user_build)
    tmp = tempfile.mkdtemp(prefix="nistcurves-verify-builds-")
    rc = 1
    try:
        rc = inner(iters, tmp)
    finally:
        # Reported here, on EVERY path: a build that raises (SystemExit from
        # run_make / build_variant) must still say what it did to build/.
        changes = tree_changes(user_build_before, snapshot_tree(user_build))
        if rc == 0 and not changes:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print(f"  variant builds kept for inspection in {tmp}")
        if changes:
            print(f"\nverify-builds: FAILED — the user's {user_build} was "
                  f"modified ({len(changes)} entries): "
                  + "; ".join(changes[:8])
                  + (" ..." if len(changes) > 8 else ""))
    if changes:
        return EXIT_ABORT
    print(f"  user's build/ untouched: {len(user_build_before)} files, same "
          f"names, sizes and mtimes")
    return rc


def _verify_builds(iters: list[int], bdir: str) -> int:
    from c64_test_harness.labels import Labels
    print(f"Building variants (each `make BUILD_DIR={bdir} "
          f"CONTRACT_DEFINES=...`; the user's build/ is never touched)\n")
    rows = []
    print("  default (no CONTRACT_DEFINES)...", flush=True)
    dflt_prg, dflt_labels, dflt_sha = build_variant("default", "", bdir)
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
        p, _l, sha = build_variant(f"iter{n}", d, bdir, expect_iter=n)
        with open(p, "rb") as f:
            img = f.read()
        note = []
        if patch_settle_immediate(base_image, off, n) != img:
            note.append("POKE != REBUILD")
            fails.append(f"iter{n}: poke-equivalence")
        rows.append((f"iter{n}", d, sha, len(img), img[off], " ".join(note)))
    print("  bank $03...", flush=True)
    bp, _bl, bsha = build_variant("bank03", "-D LIB_SHARED_REU_MUL_BANK=0x03",
                                  bdir)
    with open(bp, "rb") as f:
        bimg = f.read()
    rows.append(("bank03", "-D LIB_SHARED_REU_MUL_BANK=0x03", bsha, len(bimg),
                 bimg[off], "" if bsha != dflt_sha else "SAME AS DEFAULT"))
    if bsha == dflt_sha:
        fails.append("bank03: identical to default")
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


def arbiter_verdict(cell: CellResult, fw_label: str | None = None) -> list[str]:
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
        L.append(f"  This is NOT 'the fix was unnecessary', and NOT 'the "
                 f"defect is fixed in fw {fw_label or '<unrecorded>'}'. It is "
                 f"an upper bound on a rate at a stated N, on one device, on "
                 f"one day.")
    return L


def anchoring_verdict(th_hi, th_lo, hi_mhz, lo_mhz, ladder_min_cy,
                      settle_was_varied=True, fw_label: str | None = None):
    """Emit an anchoring verdict ONLY if a settle was actually varied.

    HARD PRECONDITION ON THE CONCLUSION (2026-08-30). On an unmitigated
    control build the settle poke is a no-op by design, so every cell runs at
    the same native settle and the ladder collapses to one point. This
    function was still handed the ladder's *nominal* labels and duly printed

        48 MHz floor >= 12 cy; 16 MHz floor >= 12 cy; ratio 1.00x
        Both clocks need about the same cycles: CYCLE-ANCHORING NOT REJECTED

    from two thresholds that could not have differed. That was the only one
    of the day's four instrument over-claims the tool would have PUBLISHED
    rather than merely reported to a human who could push back -- a formatted
    verdict string, heading for a row, heading for a contract issue, and
    shaped like an answer so it would survive review.

    The rule it violates: a null result is only evidence if the null could not
    have been there anyway. Identical thresholds were guaranteed by
    construction, so their identity carried no information. A verdict that
    cannot be computed should not be computable.
    """
    L = []
    if not settle_was_varied:
        L.append("ANCHORING: NOT COMPUTED — no settle was varied in this run "
                 "(unmitigated control: the poke is a no-op, so every cell ran "
                 "at the same native settle). A ladder that collapsed to one "
                 "point cannot support an anchoring verdict in EITHER "
                 "direction, and identical thresholds here are guaranteed by "
                 "construction rather than measured.")
        return L
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
    L.append(f"  Scope: ONE device generation, ONE firmware (fw "
             f"{fw_label or '<unrecorded>'}, as observed via /v1/info), and "
             "a floor for the FETCH path only — the stash "
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

STAGES = ["arbiter", "fetch", "stash", "crosscheck"]      # implemented, in order

# Named in the design but NOT implemented.  Asking for one is a usage error
# (exit 2): it used to be accepted, printed "NOT RUN" in prose, declared no
# cell, and so exited 3 alone or was silently dropped beside other stages.
UNIMPLEMENTED_STAGES = {
    "sqr": "the fp_sqr diagonal-site leg (+15 cy data-read distance) is not "
           "implemented in this revision",
}


def parse_stages(spec: str) -> tuple[list[str], str | None]:
    """--only value -> (stages in canonical order, usage error or None)."""
    only = [s.strip() for s in spec.split(",") if s.strip()]
    unimpl = [s for s in only if s in UNIMPLEMENTED_STAGES]
    if unimpl:
        why = "; ".join(f"{s}: {UNIMPLEMENTED_STAGES[s]}" for s in unimpl)
        return [], (f"stage(s) {unimpl} not implemented ({why}). "
                    f"Implemented stages: {','.join(STAGES)}")
    bad = [s for s in only if s not in STAGES]
    if bad:
        return [], (f"unknown stage(s) {bad}; implemented stages: "
                    f"{','.join(STAGES)}")
    if not only:
        return [], f"--only is empty; implemented stages: {','.join(STAGES)}"
    if "crosscheck" in only and "fetch" not in only:
        # crosscheck re-runs FETCH cells after a reboot and compares them
        # with leg 5's; without fetch it can never run, so it would only
        # ever be declared and come out NOT_RUN (exit 4).
        return [], ("stage 'crosscheck' requires 'fetch' (it re-runs fetch "
                    "cells after a reboot and compares them with leg 5); add "
                    f"fetch to --only. Implemented stages: {','.join(STAGES)}")
    return [s for s in STAGES if s in only], None


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
    print(f"  4. in-band clock check at every clock used (CIA Timer A "
          f"jiffies, NOT the CIA1 TOD clock): a {CLOCK_SHORT_S:g} s window "
          f"plus a ~{CLOCK_LONG_S:g} s extension, clock = slope, so a fixed "
          f"overhead cancels and is reported; +- bound on every row "
          f"(issue #173). The reading is the EFFECTIVE CPU rate with the "
          f"display on, the conditions the cells run in: it includes "
          f"badlines (~{BADLINE_STEAL_NTSC:.2%} NTSC / "
          f"{BADLINE_STEAL_PAL:.2%} PAL), GideonZ/1541ultimate#874's "
          f"one-PHI2-multiple shortfall at the top two speed indices, and "
          f"the KERNAL jiffy IRQ (~1-2% at 1 MHz, negligible at turbo). It "
          f"is not a delivered-clock reading ($D011=$0B, $D015=0, SEI, "
          f"free-running CIA timer are not set up). $D011/$D015 are read "
          f"on the C64 side and carried as vic_den= / sprites=")
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
    print(f"  8. optional: REU size; bank. (The fp_sqr diagonal-site stage "
          f"'sqr' is NOT implemented; --only sqr is refused with exit 2.)")
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
    print("Firmware field    : "
          + (f"fw {opts.firmware_note!r} — on EVERY row, but ONLY if it "
             f"begins with the version /v1/info reports at startup; "
             f"otherwise the run refuses (exit 2) before any reboot or write "
             f"(issue #172)" if opts.firmware_note is not None else
             f"fw <the version /v1/info reports at startup>"
             f"{FIRMWARE_UNVERIFIED_SUFFIX} — on EVERY row; never a "
             f"constant (issue #172). Pass --firmware-note to annotate a "
             f"locally patched build"))
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


def exit_status_help() -> str:
    """The EXIT STATUS section of the module docstring, verbatim, so --help
    and the docstring cannot drift apart."""
    doc = __doc__ or ""
    start = doc.find("EXIT STATUS\n")
    end = doc.find("\n\n", doc.find("Precedence", start))
    return doc[start:end].rstrip() if start >= 0 else ""


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="test_reu_mul_u64.py",
        description="U64 hardware probe for the SPEC §8.2 REU DMA settle.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=exit_status_help())
    p.add_argument("--only", default="arbiter,fetch,stash",
                   help=f"stages, in order: {','.join(STAGES)} "
                        f"(default arbiter,fetch,stash). 'sqr' (fp_sqr "
                        f"diagonal site) is NOT implemented and is refused "
                        f"with exit 2; so is crosscheck without fetch")
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
    p.add_argument("--firmware-note", default=None,
                   help="annotation recorded as the row's fw field, e.g. "
                        "'3.15+patch814'. MUST begin with the version "
                        "/v1/info reports or the run refuses (issue #172). "
                        "Default: the reported version, marked unverified "
                        "for patch level. The guard pins ONLY the base "
                        "version; everything after it is the operator's "
                        "unverified claim. Allowed characters: letters, "
                        "digits, . _ + ( ) ~ -")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--verify-builds", action="store_true")
    p.add_argument("--iters", default="1,2,3,4,6,8",
                   help="--verify-builds only: knob values to build")
    p.add_argument("--verbose", action="store_true")
    o = p.parse_args(argv)
    o.only, stage_err = parse_stages(o.only)
    if stage_err:
        p.error(stage_err)
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

CROSSCHECK_TAGS = ("most_likely_fail", "after_clock_change", "clean")


def crosscheck_key(tag: str, settle: tuple[str, int], size: str) -> tuple:
    """Crosscheck cells' clock is chosen from the clocks leg 4 kept, so it
    is not known when the run is declared: key on tag + settle instead."""
    return (f"crosscheck_{tag}", None, stub_cycles(*settle), size)


class RunCell(tuple):
    """One cell main() executes: (tag, mhz, settle, key).  `key` is what
    main() records in `ran` -- it must match a declared_cells() entry."""
    __slots__ = ()

    def __new__(cls, tag, mhz, settle, key):
        return super().__new__(cls, (tag, mhz, settle, key))

    tag = property(lambda s: s[0])
    mhz = property(lambda s: s[1])
    settle = property(lambda s: s[2])
    key = property(lambda s: s[3])


def stage_cells(opts, stage: str, size: str, usable: list[int]) -> list:
    """The cells main() runs for one stage at one REU size, in execution
    order, given the clocks leg 4 kept.  main() iterates exactly this list
    and records each entry's `key`, so the self-test's view of "what ran"
    comes from the code under test rather than from a copy of it."""
    ladder = parse_ladder(opts.ladder)
    if stage not in opts.only or not usable:
        return []
    if stage == "arbiter":
        mhz = opts.speeds[0]
        return [RunCell("arbiter", mhz, None, ("arbiter", mhz, 4, size))]
    if stage in ("fetch", "stash"):
        return [RunCell(stage, mhz, (f, k),
                        (stage, mhz, stub_cycles(f, k), size))
                for mhz in usable for f, k in ladder]
    if stage == "crosscheck":
        if "fetch" not in opts.only:
            return []
        short = ladder[0]
        return [RunCell(tag, mhz, settle, crosscheck_key(tag, settle, size))
                for tag, mhz, settle in (
                    ("most_likely_fail", usable[0], short),
                    ("after_clock_change", usable[-1], short),
                    ("clean", usable[0], ("orig", 0)))]
    return []


def declared_cells(opts) -> list[tuple]:
    """Every cell the run intends to produce, for the SELECTED stages only:
    (surface, mhz, cy, size).  A deselected stage is not a cell that failed
    to run, so it must not become a NOT_RUN row (that made every narrowed
    run exit 4 and taught wrappers to ignore 4)."""
    ladder = parse_ladder(opts.ladder)
    only = set(opts.only)
    declared: list[tuple] = []
    for size in opts.reu_sizes:
        if "arbiter" in only:
            declared.append(("arbiter", opts.speeds[0], 4, size))
        for mhz in opts.speeds:
            for f, k in ladder:
                if "fetch" in only:
                    declared.append(("fetch", mhz, stub_cycles(f, k), size))
                if "stash" in only:
                    declared.append(("stash", mhz, stub_cycles(f, k), size))
        if "crosscheck" in only:
            # parse_stages() refuses crosscheck without fetch, so a declared
            # crosscheck cell is always one main() can run.
            for tag in CROSSCHECK_TAGS:
                settle = ("orig", 0) if tag == "clean" else ladder[0]
                declared.append(crosscheck_key(tag, settle, size))
    return declared


def not_run_lines(declared, ran, mitigated: bool, devstr: str,
                  prg_sha: str) -> list[str]:
    """NOT_RUN rows for every declared cell that never ran."""
    out = []
    for d in declared:
        if d not in ran:
            surf, mhz, cy, size = d
            out.append(not_run_line(surf, mhz, cy, size, surf != "arbiter",
                                    mitigated, devstr, prg_sha))
    return out


def run_exit_status(cell_lines: list[str], rc: int,
                    mitigated: bool = True,
                    declared_n: int | None = None) -> int:
    """Process exit status from the CELL lines the run actually emitted
    (every declared cell has one, run or NOT_RUN).  See EXIT STATUS in the
    module docstring.  Precedence: an rc already decided (130) > 3 (no real
    verdict) > 5 (FAIL at the shipped settle) > 4 (partial) > 0.

    A FAIL below the shipped settle is expected bracket data, not a tool
    failure.  A FAIL at the shipped body (settle_cy == ORIG_CYCLES) on a
    MITIGATED build means the library as shipped returned wrong rows: a
    regression signal, distinct from everything else.  On the unmitigated
    control a FAIL is the expected outcome, so it never yields 5.
    """
    if rc:
        return rc
    cells = []
    for ln in cell_lines:
        if not ln.startswith("CELL "):
            continue
        v = re.search(r" verdict=(\S+)", ln)
        s = re.search(r" settle_cy=(\S+)", ln)
        cells.append((v.group(1) if v else "?", s.group(1) if s else "?"))
    verdicts = [v for v, _ in cells]
    real = [v for v in verdicts if v in ("PASS", "FAIL")]
    counts = {v: verdicts.count(v) for v in sorted(set(verdicts))}
    n_decl = declared_n if declared_n is not None else len(cells)
    print(f"\nRUN COMPLETENESS: declared {n_decl} cell(s), emitted "
          f"{len(cells)} CELL row(s), ran "
          f"{len(cells) - counts.get('NOT_RUN', 0)}, real verdicts "
          f"{len(real)}; verdict counts {counts or '{}'}")
    if not real:
        print("  NO REAL VERDICT: the measurement did not happen; exit 3.")
        return EXIT_NO_VERDICT
    orig_fails = [1 for v, s in cells
                  if v == "FAIL" and s == str(ORIG_CYCLES)] if mitigated else []
    if orig_fails:
        print(f"  {len(orig_fails)} FAIL(s) AT THE SHIPPED SETTLE "
              f"({ORIG_CYCLES} cy): the library as shipped returned wrong "
              f"rows -- a regression signal, not bracket data; exit 5.")
        return EXIT_ORIG_FAIL
    if len(real) < len(cells):
        print(f"  PARTIAL: {len(cells) - len(real)} declared cell(s) ended "
              f"NOT_RUN / ERROR / CONTAMINATED; exit 4.")
        return EXIT_PARTIAL
    return EXIT_OK


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
        return EXIT_ABORT

    from c64_test_harness.backends.device_lock import DeviceLock
    from c64_test_harness.backends.ultimate64 import Ultimate64Transport
    from c64_test_harness.backends.ultimate64_probe import probe_u64
    from c64_test_harness.backends.ultimate64_helpers import (
        set_turbo_mhz, snapshot_state, restore_state)
    from c64_test_harness.labels import Labels

    probe = probe_u64(host)
    if not getattr(probe, "reachable", False):
        print(f"U64 at {host} not reachable: {probe}")
        return EXIT_ABORT

    try:
        DeviceLock.cleanup_stale()
    except Exception as e:
        print(f"  [lock] cleanup_stale: WARN {type(e).__name__}: {e}")
    lock = DeviceLock(host)
    lock_rc = acquire_device_lock(lock, opts.wait, opts.lock_timeout)
    if lock_rc:
        return lock_rc

    transport = client = snapshot = dev = None
    lines: list[str] = []
    prose: list[str] = []
    stage_times: list[tuple[str, float]] = []
    rc = 0
    mitigated_build = True      # set from the labels once the build is known
    ladder = parse_ladder(opts.ladder)
    ladder_min_cy = min(stub_cycles(f, k) for f, k in ladder)
    declared = declared_cells(opts)     # every cell we intend to run
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
        fw_note, refusal = firmware_note_for_row(fw, opts.firmware_note)
        print(f"\nDevice: {product} serial {serial}")
        if refusal:
            # Nothing has been written, rebooted or snapshotted yet.
            print(f"FATAL: {refusal}")
            rc = EXIT_REFUSED
            return rc
        devstr = device_string(info, fw_note)
        print(f"        fw {fw} (reported) -> recorded as "
              f"{fw_note}; fpga {fpga}, core {core}")
        print("        /v1/info cannot distinguish a stock build from a "
              "locally patched one, so the row says what was observed and "
              "who asserted the rest.")

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
        # Artifact-level provenance for the control, printed rather than
        # merely asserted, so a reader can see the build really is unmitigated
        # without taking anyone's word (requested by the c64-wireguard lane).
        # These are properties of the ARTIFACT, not of the build recipe.
        try:
            _img = pathlib.Path(prg).read_bytes()
            _n_bit = _img.count(b"\x2c\x00\xdf")   # bit $DF00
            print(f"  artifact provenance: `bit $DF00` occurrences in image: "
                  f"{_n_bit}  (0 => no REU status read anywhere => unmitigated)")
        except Exception as _e:
            print(f"  artifact provenance: could not scan image ({_e})")
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
        _mit = [n for n in MITIGATION_LABELS if labels.address(n) is not None]
        mitigated_build = bool(_mit)
        if len(_mit) == len(MITIGATION_LABELS):
            print(f"  nistcurves_reu_dma_wait @ "
                  f"${labels['nistcurves_reu_dma_wait']:04X}, reu_mul_init @ "
                  f"${labels['reu_mul_init']:04X}, reu_fetch_mul_row @ "
                  f"${labels['reu_fetch_mul_row']:04X}")
        elif not _mit:
            print(f"  UNMITIGATED CONTROL BUILD: none of "
                  f"{MITIGATION_LABELS} are present, so there is no settle to "
                  f"poke and no confirm anywhere in the image. reu_mul_init @ "
                  f"${labels['reu_mul_init']:04X}, reu_fetch_mul_row @ "
                  f"${labels['reu_fetch_mul_row']:04X}")
        else:
            raise SystemExit(
                f"ABORT: build is neither mitigated nor unmitigated -- only "
                f"{_mit} of {MITIGATION_LABELS} present. Refusing to guess "
                f"which surface is under test.")
        print(f"\nTuning budget (pre-registered): {', '.join(TUNING_BUDGET)}. "
              f"Anything else that moves during this run prints a DEVIATION "
              f"line.")

        def boot_and_reconfirm(size_):
            # Rows carry the identity observed at startup (issue #172); after
            # every reboot, confirm the box answering is still that one.
            dev.boot(prg, labels, opts.boot_mhz, reu_size=size_)
            changed = device_identity_changed(info, client.get_info())
            if changed:
                raise SystemExit(
                    f"ABORT: /v1/info after reboot differs from startup in "
                    f"{changed}; the rows' device field would no longer name "
                    f"the device that produced them.")

        def emit(line):
            lines.append(line)
            print(line, flush=True)

        for size in opts.reu_sizes:
            print(f"\n{'=' * 78}\n=== REU size {size} ===")
            t_size = time.monotonic()
            boot_and_reconfirm(size)

            # ---- LEG 1b: REU presence ---------------------------------
            print("\n  [leg 1] REU presence probe @ 1 MHz")
            set_turbo_mhz(client, 1); time.sleep(0.5)
            if not reu_presence_probe(dev):
                raise SystemExit(
                    "ABORT: the REU did not round-trip a pattern at 1 MHz. "
                    "Without a mapped REU every row is wrong at every clock.")

            # ---- LEG 2: THE ARBITER -----------------------------------
            arb = None
            for arb_cell in stage_cells(opts, "arbiter", size, opts.speeds):
                t0 = time.monotonic()
                mhz = arb_cell.mhz
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
                ran.add(arb_cell.key)
                for ln in arbiter_verdict(arb, fw_label=fw_note):
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
            # The self-check leaves the table POISONED. Rebuild it before
            # anything measures, or every later cell reads our own poison
            # and reports a 100% failure that has nothing to do with the
            # device (measured 2026-08-30: five bit-identical FAIL cells).
            print("    rebuilding the table after the poison self-check "
                  "(OP_INIT)...", flush=True)
            if dev.call(OP_INIT, timeout_for("init", 1),
                        poll_interval=0.2) is None:
                raise SystemExit(
                    "ABORT: could not rebuild the multiply table after the "
                    "poison self-check; the table is left poisoned and no "
                    "measurement would mean anything.")

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
                    print(leg4_line(mhz, m))
                    if off > 0.20:
                        measured[mhz] = None
            usable = [m for m in opts.speeds if measured.get(m) is not None]
            if not usable:
                raise SystemExit("ABORT: no clock verified in-band.")

            # ---- LEG 5: FETCH path ------------------------------------
            thresholds: dict[int, int | None] = {}
            fetch_cells = stage_cells(opts, "fetch", size, usable)
            if fetch_cells:
                t0 = time.monotonic()
                print(f"\n  [leg 5] FETCH-path cells (the observed surface) "
                      f"— settle {opts.ladder}")
                for mhz in dict.fromkeys(c_.mhz for c_ in fetch_cells):
                    set_turbo_mhz(client, mhz); time.sleep(0.5)
                    th = None
                    for run_cell in [c_ for c_ in fetch_cells
                                     if c_.mhz == mhz]:
                        form, k = run_cell.settle
                        cy = stub_cycles(form, k)
                        name = cell_name("fetch", mhz, cy, dev.mitigated)
                        c = fetch_cell(dev, mhz, size, rows, opts.n,
                                       (form, k), name,
                                       host_read=opts.host_read)
                        print_cell_detail(c)
                        emit(c.line(devstr, measured[mhz], prg_sha))
                        ran.add(run_cell.key)
                        if c.verdict == "PASS" and th is None:
                            th = cy
                        if c.verdict == "FAIL":
                            th = None
                    thresholds[mhz] = th
                    print(leg5_summary(mhz, th, dev.mitigated))
                stage_times.append((f"fetch/{size}", time.monotonic() - t0))

            # ---- LEG 6: STASH path ------------------------------------
            stash_cells = stage_cells(opts, "stash", size, usable)
            if stash_cells:
                t0 = time.monotonic()
                print(f"\n  [leg 6] STASH-path cells (the hypothesised "
                      f"surface; poisoned before every rebuild)")
                for mhz in dict.fromkeys(c_.mhz for c_ in stash_cells):
                    set_turbo_mhz(client, mhz); time.sleep(0.5)
                    for run_cell in [c_ for c_ in stash_cells
                                     if c_.mhz == mhz]:
                        form, k = run_cell.settle
                        cy = stub_cycles(form, k)
                        name = cell_name("stash", mhz, cy, dev.mitigated)
                        c = stash_cell(dev, mhz, size, rows, opts.n,
                                       (form, k), name)
                        print_cell_detail(c)
                        emit(c.line(devstr, measured[mhz], prg_sha))
                        ran.add(run_cell.key)
                stage_times.append((f"stash/{size}", time.monotonic() - t0))

            # ---- LEG 7: reboot-per-cell cross-check -------------------
            cross_cells = stage_cells(opts, "crosscheck", size, usable)
            if cross_cells:
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
                for run_cell in cross_cells:
                    tag, mhz, settle = (run_cell.tag, run_cell.mhz,
                                        run_cell.settle)
                    boot_and_reconfirm(size)
                    set_turbo_mhz(client, mhz); time.sleep(0.5)
                    c = fetch_cell(dev, mhz, size, rows, opts.n, settle,
                                   f"crosscheck_{tag}_{mhz}MHz",
                                   host_read=opts.host_read)
                    emit(c.line(devstr, measured.get(mhz), prg_sha))
                    ran.add(run_cell.key)
                stage_times.append((f"crosscheck/{size}",
                                    time.monotonic() - t0))

            dev.restore_settle()
            stage_times.append((f"size {size} total", time.monotonic() - t_size))

            # ---- anchoring ---------------------------------------------
            if "fetch" in opts.only and len(usable) >= 2:
                for ln in anchoring_verdict(thresholds.get(usable[0]),
                                            thresholds.get(usable[-1]),
                                            usable[0], usable[-1],
                                            ladder_min_cy,
                                            settle_was_varied=dev.mitigated,
                                            fw_label=fw_note):
                    print(ln); prose.append(f"[{size}] {ln}")

        # cells declared but never run, so a reader can tell 0/N from untested
        lines.extend(not_run_lines(declared, ran, mitigated_build, devstr,
                                   prg_sha))

        try:
            set_turbo_mhz(client, 1)
        except Exception:
            pass

    except KeyboardInterrupt:
        print("\nINTERRUPTED — restoring device state before exit.")
        rc = EXIT_INTERRUPTED
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
    return run_exit_status(lines, rc, mitigated=mitigated_build,
                           declared_n=len(declared))


if __name__ == "__main__":
    sys.exit(main())
