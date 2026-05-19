#!/usr/bin/env python3
"""bench_sha384.py — SHA-384 per-block compression benchmarks on C64/VICE.

Resolves the per-block ``sha_compress`` cost that the U64E turbo bench
(`tools/bench_ecdsa_u64.py`) can only bound from above at 17,045
1-MHz-equivalent cycles (one jiffy) for short messages. At VICE 1 MHz
each compression should land at several jiffies, so a length sweep can
isolate the per-block cost by differencing two adjacent block counts.

Methodology
-----------
For each length L in the sweep:

1. Oracle gate — stage the message in ``sha384_msg_buf`` (chunked to
   1 KB if L > 1024 B), drive ``sha384_init`` / ``sha384_update`` /
   ``sha384_final`` via ``jsr()``, read 48 B of ``sha384_digest`` back,
   and compare to ``hashlib.sha384`` over the same bytes. Any mismatch
   marks the length UNVERIFIED and drops its cycle count.

2. Timed loop — install a $C000 trampoline that calls
   ``init / update*N_chunks / final`` ``loops`` times against the
   already-staged buffer (SHA-2 compress timing is data-oblivious so
   the per-iter timed work matches what the gate verified). Read
   bench_ticks, divide by ``loops`` to amortise jiffy quantisation.

Per-block cost is then derived as
``(cycles(L=128) - cycles(L=0)) = 1 block of compress + small overhead``.

Usage
-----
    python3 tools/bench_sha384.py [--loops N]

    --loops N    Override per-length iteration count (default: 5)
"""

import argparse
import hashlib
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

# NTSC C64: ~1.022727 MHz, 17045 cycles per jiffy (1/60 sec).
NTSC_CYCLES_PER_JIFFY = 17045
NTSC_CPU_HZ = NTSC_CYCLES_PER_JIFFY * 60  # ~1,022,700 Hz

# Trampoline install address (free 4 KB RAM block, same as bench_p256.py).
TRAMPOLINE_ADDR = 0xC000
# Iteration counter lives just past the largest plausible trampoline body
# (≤ ~32 B for L=4096). $C100 keeps it page-aligned and well clear.
TRAMPOLINE_COUNTER = 0xC100

# sha384_msg_buf is 1024 B (data.s); per-call sha_len caps at 16 bits but
# the staging buffer is the real limit. Larger messages must be split into
# 1 KB chunks fed via repeat ``sha384_update`` calls.
MSG_BUF_SIZE = 1024

# Canonical SHA-2 padding-boundary length sweep:
#   * 0           — empty message, exercises the pad-only final block
#   * 55, 56      — one-block / two-block padding boundary
#                   (length tail = 16 B, so 128 - 16 = 112 max payload;
#                    but SHA-512 word boundaries give 55/56 the same
#                    role as SHA-256's 55/56 in published padding tests)
#   * 111, 112    — single-block-padded vs spill-to-two-blocks boundary
#                   for the 128 B / 16 B tail layout
#   * 127, 128, 129 — block-boundary transitions (128 B = exactly one
#                     full SHA-512 block)
#   * 200         — span across two blocks with arbitrary tail
#   * 1024        — fills the staging buffer exactly; 8 compress blocks
#   * 4096        — four staging-buffer fills; 32 compress blocks. Lets
#                   per-block cost be amortised against the L=1024 row.
LENGTH_SWEEP = [0, 55, 56, 111, 112, 127, 128, 129, 200, 1024, 4096]


def _warn_if_vice_running():
    try:
        res = subprocess.run(
            ["pgrep", "-c", "x64sc"],
            capture_output=True, text=True, timeout=2,
        )
        n = int(res.stdout.strip() or "0")
        if n > 0:
            print(
                f"WARNING: {n} other x64sc instance(s) already running — "
                "wall-clock timings may be unreliable.",
                file=sys.stderr,
            )
    except Exception:
        pass


def sha_block_count(length: int) -> int:
    """FIPS 180-4 SHA-512 compression block count for a message of len bytes.

    Padding rule: append 0x80, then zero-pad, then 16 B (128-bit) length.
    A message of ``length`` bytes fits in ``ceil((length + 1 + 16) / 128)``
    blocks, since the minimum padding is 1 B (0x80) + 16 B length.
    """
    return (length + 1 + 16 + 127) // 128


def make_chunk_lengths(length: int) -> list[int]:
    """Split a message length into 1 KB chunks (last chunk may be short)."""
    if length == 0:
        return []
    full, rem = divmod(length, MSG_BUF_SIZE)
    chunks = [MSG_BUF_SIZE] * full
    if rem:
        chunks.append(rem)
    return chunks


def build_bench_trampoline(labels, msg_len: int, loops: int) -> bytes:
    """Build a $C000 trampoline that runs `loops` full SHA-384 hashes.

    Each iteration:
        JSR sha384_init
        (optional, per 1 KB chunk:) JSR sha384_update
        JSR sha384_final

    sha_src and sha_len must be pre-loaded by the caller. For multi-chunk
    messages the chunk-size is always 1024 B (and the residual chunk is
    handled separately when len % 1024 != 0). To keep the bench simple,
    all timed iterations reuse the same 1 KB staging window — SHA-512
    compression is data-oblivious in cycle count, so the timing matches
    what the oracle gate verified over the real message.

    Layout (one iter shown):
        JSR sha384_init            ; 3 B
        ; for each chunk of size 1024:
        LDA #<1024 / STA sha_len   ; 2+2 B
        LDA #>1024 / STA sha_len+1 ; 2+2 B
        JSR sha384_update          ; 3 B
        ; for the optional residual chunk of size R:
        LDA #<R / STA sha_len      ; 2+2 B
        LDA #>R / STA sha_len+1    ; 2+2 B
        JSR sha384_update          ; 3 B
        JSR sha384_final           ; 3 B

    For L=0 the update sequence is empty (init → final is the entire
    body and exercises the pad-only final block).
    """
    assert 1 <= loops <= 255, f"loops {loops} out of 1..255"
    sha_init = labels["sha384_init"]
    sha_update = labels["sha384_update"]
    sha_final = labels["sha384_final"]
    sha_len = labels["sha_len"]
    assert sha_len <= 0xFF, "sha_len expected to be zero-page"

    chunks = make_chunk_lengths(msg_len)

    body = []
    # JSR sha384_init
    body += [0x20, sha_init & 0xFF, (sha_init >> 8) & 0xFF]
    # For each chunk: load sha_len = chunk_size, JSR sha384_update.
    # In the common single-chunk case sha_len could be set once before
    # the loop and not re-set per iter, but the cost of two ZP stores
    # per iter is sub-jiffy and the symmetric trampoline keeps later
    # auditing simple.
    for ck in chunks:
        body += [0xA9, ck & 0xFF, 0x85, sha_len & 0xFF]
        body += [0xA9, (ck >> 8) & 0xFF, 0x85, (sha_len + 1) & 0xFF]
        body += [0x20, sha_update & 0xFF, (sha_update >> 8) & 0xFF]
    # JSR sha384_final
    body += [0x20, sha_final & 0xFF, (sha_final >> 8) & 0xFF]

    counter_lo = TRAMPOLINE_COUNTER & 0xFF
    counter_hi = (TRAMPOLINE_COUNTER >> 8) & 0xFF
    header = [
        0xA9, loops & 0xFF,                   # LDA #loops
        0x8D, counter_lo, counter_hi,         # STA TRAMPOLINE_COUNTER
    ]
    # body bytes occupy `len(body)`; loop branch must skip backwards over
    # body + DEC abs(3) + BNE(2) so BNE offset = -(len(body) + 3 + 2)
    dec_bne_rts = [
        0xCE, counter_lo, counter_hi,         # DEC TRAMPOLINE_COUNTER
        0xD0, (256 - (len(body) + 5)) & 0xFF, # BNE -(body+DEC) = back to start of body
        0x60,                                 # RTS
    ]
    return bytes(header + body + dec_bne_rts)


def stage_message(transport, labels, message: bytes) -> None:
    """Write up to 1 KB of message content into sha384_msg_buf.

    For oracle-gate runs this primes the buffer with the first 1 KB of
    the actual message; subsequent chunks are streamed in by the gate
    driver. For the timed loop the same primed bytes are reused for
    every chunk of every iteration (data-oblivious cost).
    """
    msg_buf = labels["sha384_msg_buf"]
    prime = message[:MSG_BUF_SIZE]
    if not prime:
        # Empty message: still stage zeros so msg_buf has known content
        # (the loop never calls update for L=0, but defensive).
        prime = b"\x00" * MSG_BUF_SIZE
    elif len(prime) < MSG_BUF_SIZE:
        prime = prime + b"\x00" * (MSG_BUF_SIZE - len(prime))
    write_bytes(transport, msg_buf, prime)
    # Set sha_src = LE 16-bit pointer to msg_buf
    write_bytes(
        transport, labels["sha_src"],
        bytes([msg_buf & 0xFF, (msg_buf >> 8) & 0xFF]),
    )


def c64_sha384_once(transport, labels, message: bytes, *, timeout=300.0) -> bytes:
    """Run one full SHA-384 hash on the C64 and return the 48 B BE digest.

    Streams ``message`` through ``sha384_msg_buf`` in 1 KB chunks. Used
    only by the oracle gate; timed iterations reuse a pre-staged buffer
    via the trampoline.
    """
    msg_buf = labels["sha384_msg_buf"]
    sha_src = labels["sha_src"]
    sha_len = labels["sha_len"]

    jsr(transport, labels["sha384_init"], timeout=5.0)
    offset = 0
    while offset < len(message):
        chunk = message[offset : offset + MSG_BUF_SIZE]
        write_bytes(transport, msg_buf, chunk)
        write_bytes(transport, sha_src,
                    bytes([msg_buf & 0xFF, (msg_buf >> 8) & 0xFF]))
        clen = len(chunk)
        write_bytes(transport, sha_len,
                    bytes([clen & 0xFF, (clen >> 8) & 0xFF]))
        jsr(transport, labels["sha384_update"], timeout=timeout)
        offset += MSG_BUF_SIZE
    jsr(transport, labels["sha384_final"], timeout=60.0)
    return read_bytes(transport, labels["sha384_digest"], 48)


def read_bench_ticks(transport, labels):
    raw = read_bytes(transport, labels["bench_ticks"], 3)
    return (raw[0] << 16) | (raw[1] << 8) | raw[2]


def bench_one_length(transport, labels, length: int, loops: int):
    """Bench SHA-384 for a single message length.

    Returns dict with: length, blocks, loops, jiffies, total_cycles,
    cycles_per_call, ms_per_call, cycles_per_block, verified (bool).
    """
    blocks = sha_block_count(length)

    # --- oracle gate ----------------------------------------------------
    # Use a length-derived deterministic pattern (no randomness needed:
    # SHA-2 cycle cost is data-oblivious; only the gate cares about bit
    # values). Pattern = bytes((i ^ (length & 0xFF)) & 0xFF for i in 0..L)
    # so each length yields a distinct payload.
    message = bytes(((i ^ (length & 0xFF)) & 0xFF) for i in range(length))
    expected = hashlib.sha384(message).digest()

    # Gate timeout: each update call is ≤1 KB ≈ 8 SHA-512 blocks; at VICE
    # warp mode each block lands at ~10 s real time worst case. Allow
    # 200 s per update chunk plus a 60 s buffer.
    gate_chunk_timeout = 200.0
    got = c64_sha384_once(
        transport, labels, message, timeout=gate_chunk_timeout
    )
    verified = (got == expected)
    if not verified:
        return {
            "length": length, "blocks": blocks, "loops": loops,
            "jiffies": None, "total_cycles": None,
            "cycles_per_call": None, "ms_per_call": None,
            "cycles_per_block": None, "verified": False,
            "expected": expected, "got": got,
        }

    # --- timed loop -----------------------------------------------------
    # Re-stage msg_buf with the first chunk so every iter sees consistent
    # bytes. (Oracle gate left msg_buf holding the LAST chunk of the
    # message — for L=4096 that's bytes [3072..4095]. Restage to put the
    # first 1 KB back.)
    stage_message(transport, labels, message)

    trampoline = build_bench_trampoline(labels, length, loops)
    write_bytes(transport, TRAMPOLINE_ADDR, trampoline)

    # Timeout budget: at VICE 1 MHz warp, a 4096 B hash is ≤ ~32 blocks
    # × estimated ~80-280 kcy/block ≈ ~2.5-9 Mcy = 2.5-9 s real-time per
    # iter (warp scales). Give ample headroom: 60 s for short messages,
    # bump for longer ones. Real wall clock in warp mode is typically
    # 10-100× faster than 1 MHz nominal.
    base = 60.0
    if length >= 1024:
        base = 180.0
    per_call_estimate = max(0.5, blocks * 0.05)  # generous
    timeout = base + loops * per_call_estimate

    jsr(transport, labels["vic_blank"], timeout=5.0)
    jsr(transport, labels["bench_start"], timeout=5.0)
    jsr(transport, TRAMPOLINE_ADDR, timeout=timeout)
    jsr(transport, labels["bench_stop"], timeout=5.0)
    jsr(transport, labels["vic_unblank"], timeout=5.0)

    jiffies = read_bench_ticks(transport, labels)
    total_cycles = jiffies * NTSC_CYCLES_PER_JIFFY
    cycles_per_call = total_cycles // loops
    cycles_per_block = cycles_per_call // blocks if blocks > 0 else None
    ms_per_call = (cycles_per_call / NTSC_CPU_HZ) * 1000.0
    return {
        "length": length, "blocks": blocks, "loops": loops,
        "jiffies": jiffies, "total_cycles": total_cycles,
        "cycles_per_call": cycles_per_call, "ms_per_call": ms_per_call,
        "cycles_per_block": cycles_per_block, "verified": True,
    }


def main():
    parser = argparse.ArgumentParser(
        description=("Oracle-gated SHA-384 per-block benchmarks "
                     "(VICE 1 MHz NTSC)."),
    )
    parser.add_argument(
        "--loops", type=int, default=5,
        help="Iterations per length (default: 5)",
    )
    args = parser.parse_args()

    if not (1 <= args.loops <= 255):
        print(f"FATAL: --loops {args.loops} out of 1..255")
        sys.exit(2)

    _warn_if_vice_running()
    os.chdir(PROJECT_ROOT)

    # Build (unless skipped)
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(
            ["make"], capture_output=True, text=True, cwd=PROJECT_ROOT,
        )
        if result.returncode != 0:
            print(f"Build failed:\n{result.stdout}\n{result.stderr}")
            sys.exit(1)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found after build")
        sys.exit(1)
    print(f"Built: {PRG_PATH}")

    labels = Labels.from_file(LABELS_PATH)
    required = [
        "sha384_init", "sha384_update", "sha384_final",
        "sha384_digest", "sha384_msg_buf",
        "sha_src", "sha_len",
        "bench_start", "bench_stop", "bench_ticks",
        "vic_blank", "vic_unblank",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    config = ViceConfig(
        prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
        extra_args=["-reu", "-reusize", "512"],
    )

    with ViceInstanceManager(
        config=config,
        port_range_start=6571,
        port_range_end=6591,
    ) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        print("Waiting for init sentinel ($02A7 = $42)...")
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
            sys.exit(1)
        print(f"Init complete after {time.time() - start:.1f}s")

        # Standard RTS-guard at $0339 used by all benches.
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print()
        print(f"Running SHA-384 benchmarks (loops={args.loops}, "
              f"oracle gate enabled)...")
        results = []
        unverified = []
        for length in LENGTH_SWEEP:
            blocks = sha_block_count(length)
            print(f"  L={length:>4} B ({blocks} block{'s' if blocks != 1 else ''})...",
                  flush=True, end=" ")
            try:
                r = bench_one_length(transport, labels, length, args.loops)
            except Exception as e:
                print(f"ERROR: {e!r}")
                unverified.append((length, str(e)))
                continue
            if not r["verified"]:
                print("UNVERIFIED")
                print(f"    expected: {r['expected'].hex()}")
                print(f"    got:      {r['got'].hex()}")
                unverified.append((length, "oracle mismatch"))
                continue
            print(f"OK  {r['jiffies']:>6} jiffies / "
                  f"{r['cycles_per_call']:>9} cy/call / "
                  f"{r['cycles_per_block']:>7} cy/block")
            results.append(r)

        mgr.release(inst)

    # ----- report ---------------------------------------------------------
    print()
    title = (f"SHA-384 Per-Block Benchmarks "
             f"(VICE NTSC, 1.02 MHz, VIC blanked, "
             f"1 jiffy = {NTSC_CYCLES_PER_JIFFY} cycles)")
    bar = "=" * len(title)
    print(bar)
    print(title)
    print(bar)
    hdr = (f"{'Length':>7} {'Blocks':>6} {'Loops':>5} "
           f"{'Jiffies':>8} {'Cycles/call':>13} {'Cycles/block':>13} "
           f"{'ms/call':>10}")
    print(hdr)
    print("-" * len(bar))
    for r in results:
        print(f"{r['length']:>7} {r['blocks']:>6} {r['loops']:>5} "
              f"{r['jiffies']:>8} {r['cycles_per_call']:>13} "
              f"{r['cycles_per_block']:>13} {r['ms_per_call']:>10.2f}")
    print(bar)

    # ----- per-block cost extraction -------------------------------------
    # Best per-block estimate: difference between two same-prefix-padding
    # rows that differ by N blocks. The 1024 B vs 4096 B pair differs by
    # exactly 24 compression blocks (32 - 8), and both use the same
    # init/final padding shape (≥111 B threshold + multi-block tail),
    # so subtracting amortises the init/final cost away.
    by_len = {r["length"]: r for r in results}
    print()
    if 1024 in by_len and 4096 in by_len:
        r1, r4 = by_len[1024], by_len[4096]
        delta_blocks = r4["blocks"] - r1["blocks"]
        delta_cy = r4["cycles_per_call"] - r1["cycles_per_call"]
        if delta_blocks > 0:
            per_block = delta_cy // delta_blocks
            print(f"Per-block compress cost (Δ between L=4096 and L=1024, "
                  f"{delta_blocks} blocks): {per_block:,} cy/block "
                  f"({per_block / NTSC_CYCLES_PER_JIFFY:.2f} jiffies)")
    if 0 in by_len and 1024 in by_len:
        r0, r1 = by_len[0], by_len[1024]
        delta_blocks = r1["blocks"] - r0["blocks"]
        delta_cy = r1["cycles_per_call"] - r0["cycles_per_call"]
        if delta_blocks > 0:
            per_block = delta_cy // delta_blocks
            print(f"Per-block compress cost (Δ between L=1024 and L=0, "
                  f"{delta_blocks} blocks): {per_block:,} cy/block "
                  f"({per_block / NTSC_CYCLES_PER_JIFFY:.2f} jiffies)")

    if unverified:
        print()
        print(f"UNVERIFIED LENGTHS ({len(unverified)}): "
              f"{', '.join(f'L={l}' for l, _ in unverified)}")
        print("These lengths failed the oracle correctness gate and "
              "their cycle counts were NOT recorded.")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
