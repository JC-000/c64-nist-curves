#!/usr/bin/env python3
"""test_sha384.py — Oracle-gated SHA-384 tests for the c64-nist-curves library.

Exercises the sha384_init / sha384_update / sha384_final ABI by poking
message bytes into sha384_msg_buf (1024-byte scratch in DATA segment),
setting the sha_src / sha_len ZP slots, and calling the assembly routines
via jsr(). The 48-byte BE digest is read back from sha384_digest and
compared to hashlib.sha384.

Oracle model:
  All expected digests come from hashlib.sha384 (Python standard library),
  which is independent of the C64 implementation. No expected values are
  hard-coded from a prior implementation run (FIPS 180-4 mandatory anchors
  are cross-checked against hashlib at startup).

Usage:
    python3 tools/test_sha384.py [--seed N] [--verbose] [--full]

    --seed N    Reproduce a specific failure (default: OS CSPRNG, unseeded)
    --verbose   Print PASS lines in addition to FAILs
    --full      Run stress battery (1023, 1024, 1025, 4096 bytes)
"""

import hashlib
import os
import random
import secrets
import subprocess
import sys
import time
import traceback

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, read_bytes_verified, write_bytes, jsr,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "nist-curves.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# Maximum bytes per sha384_update call — limited by sha384_msg_buf size.
MSG_BUF_SIZE = 1024

# ---------------------------------------------------------------------------
# FIPS 180-4 mandatory anchors (cross-checked against hashlib at startup)
# ---------------------------------------------------------------------------

# Section 6.3 / B.1: SHA-384("abc")
FIPS_ABC = b"abc"
FIPS_ABC_DIGEST = bytes.fromhex(
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
    "8086072ba1e7cc2358baeca134c825a7"
)

# Section B.2 sample one: empty input
FIPS_EMPTY_DIGEST = bytes.fromhex(
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
    "274edebfe76f65fbd51ad2f14898b95b"
)

# FIPS 180-4 / SHA-2 sample two-block message (56 bytes, same as SHA-256 sample)
FIPS_TWO_BLOCK = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

# FIPS 180-4 / SHA-2 sample three-block-ish message (112 bytes)
FIPS_THREE_BLOCK = (
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
    b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
)

# Random battery: lengths exercising boundary conditions around block size
# SHA-384 block = 128 bytes, so 127/128/129 are block-boundary cases.
# SHA-384 padding threshold: a message of length 112 bytes fits in one block
# (128 - 16 bytes for length encoding), 113+ spills to two blocks.
RANDOM_BATTERY_LENGTHS = [
    0, 1, 17, 55, 56, 57, 63, 64, 111, 112, 113, 127, 128, 129, 200, 255, 256,
]

# Stress battery lengths (only when --full)
STRESS_BATTERY_LENGTHS = [1023, 1024, 1025, 4096]


# ---------------------------------------------------------------------------
# Random source (seeded or OS CSPRNG)
# ---------------------------------------------------------------------------

class RandomSource:
    def __init__(self, seed=None):
        self.seed = seed
        self._rng = random.Random(seed) if seed is not None else None

    def rand_bytes(self, n):
        if self._rng is None:
            return secrets.token_bytes(n)
        return bytes(self._rng.randrange(256) for _ in range(n))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
        pass  # preflight must never block test execution


# ---------------------------------------------------------------------------
# Core C64 driver
# ---------------------------------------------------------------------------

def c64_sha384(transport, labels, message: bytes) -> bytes:
    """Hash `message` on the C64 and return the 48-byte BE digest.

    Calls sha384_init once, then sha384_update in 1024-byte chunks (the size
    of sha384_msg_buf), then sha384_final. For an empty message, sha384_update
    is skipped entirely and sha384_final is called directly after init.
    """
    msg_buf = labels["sha384_msg_buf"]
    sha_src = labels["sha_src"]
    sha_len = labels["sha_len"]

    # Reset state and load IV
    jsr(transport, labels["sha384_init"], timeout=2.0)

    # Absorb message in chunks (skip update entirely for empty message)
    offset = 0
    while offset < len(message):
        chunk = message[offset : offset + MSG_BUF_SIZE]
        # Poke chunk bytes into sha384_msg_buf
        write_bytes(transport, msg_buf, chunk)
        # Set sha_src = LE 16-bit pointer to sha384_msg_buf
        write_bytes(transport, sha_src,
                    bytes([msg_buf & 0xFF, (msg_buf >> 8) & 0xFF]))
        # Set sha_len = LE 16-bit byte count for this chunk
        clen = len(chunk)
        write_bytes(transport, sha_len,
                    bytes([clen & 0xFF, (clen >> 8) & 0xFF]))
        # sha384_update absorbs [sha_src, sha_src+sha_len)
        # Timeout: 1024 B = 8 SHA-512 blocks; ~10-20s per block in warp ⇒ 160s max
        jsr(transport, labels["sha384_update"], timeout=160.0)
        offset += MSG_BUF_SIZE

    # Finalize: padding + length block(s) + write 48 BE bytes to sha384_digest
    jsr(transport, labels["sha384_final"], timeout=60.0)

    # Read back 48-byte BE digest
    return read_bytes_verified(transport, labels["sha384_digest"], 48)


# ---------------------------------------------------------------------------
# Individual test runners
# ---------------------------------------------------------------------------

def run_one(transport, labels, name, message):
    """Run a single test vector. Returns (passed, failed)."""
    expected = hashlib.sha384(message).digest()
    try:
        got = c64_sha384(transport, labels, message)
    except Exception as e:
        print(f"  FAIL {name}: exception {e!r}")
        return 0, 1
    if got == expected:
        if VERBOSE:
            print(f"  PASS {name}: {got.hex()}")
        return 1, 0
    print(f"  FAIL {name}:")
    print(f"    input (hex, first 64B): {message[:64].hex()!r}")
    print(f"    expected: {expected.hex()}")
    print(f"    got:      {got.hex()}")
    return 0, 1


def run_mandatory_kats(transport, labels):
    """Four mandatory FIPS 180-4 / standard KAT vectors."""
    passed = failed = 0
    cases = [
        ("empty (FIPS 180-4)", b""),
        ("abc (FIPS 180-4)", FIPS_ABC),
        ("two-block (FIPS 180-4, 56 B)", FIPS_TWO_BLOCK),
        ("three-block-ish (FIPS 180-4, 112 B)", FIPS_THREE_BLOCK),
    ]
    for name, msg in cases:
        p, f = run_one(transport, labels, name, msg)
        passed += p
        failed += f
    return passed, failed


def run_random_battery(transport, labels, rng):
    """Random inputs at boundary-condition lengths (always run)."""
    passed = failed = 0
    for n in RANDOM_BATTERY_LENGTHS:
        msg = rng.rand_bytes(n)
        p, f = run_one(transport, labels, f"random len={n}", msg)
        passed += p
        failed += f
    return passed, failed


def run_stress_battery(transport, labels, rng):
    """Longer random inputs including multi-update paths (--full only)."""
    passed = failed = 0
    for n in STRESS_BATTERY_LENGTHS:
        msg = rng.rand_bytes(n)
        p, f = run_one(transport, labels, f"stress len={n}", msg)
        passed += p
        failed += f
    return passed, failed


# ---------------------------------------------------------------------------
# Test orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels, rng, run_full):
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    transport_broken = False

    groups = [
        ("Mandatory KAT (FIPS 180-4)",
         lambda: run_mandatory_kats(transport, labels)),
        ("Random battery (boundary lengths)",
         lambda: run_random_battery(transport, labels, rng)),
    ]
    if run_full:
        groups.append(
            ("Stress battery (long messages, multi-update, --full)",
             lambda: run_stress_battery(transport, labels, rng))
        )

    for name, fn in groups:
        print(f"\n--- {name} ---")
        if transport_broken:
            total_skipped += 1
            print("  SKIP: transport broken after previous timeout")
            continue
        try:
            p, f = fn()
            total_passed += p
            total_failed += f
            status = "OK" if f == 0 else "FAIL"
            print(f"  {status}: {p}/{p + f} passed")
        except Exception as e:
            total_failed += 1
            print(f"  ERROR: {e}")
            if "stopped event" in str(e) or "Timed out" in str(e):
                print("  WARNING: transport likely broken, skipping remaining tests")
                transport_broken = True
            else:
                traceback.print_exc()

    return total_passed, total_failed, total_skipped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global VERBOSE

    import argparse

    parser = argparse.ArgumentParser(
        description="Oracle-gated SHA-384 tests for the c64-nist-curves library."
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Fix random seed for reproducible failures (default: OS CSPRNG)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print PASS lines as well as FAILs",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Run stress battery (1023, 1024, 1025, 4096-byte inputs)",
    )
    args = parser.parse_args()

    VERBOSE = args.verbose
    seed = args.seed
    run_full = args.full

    _warn_if_vice_running()
    os.chdir(PROJECT_ROOT)

    if seed is None:
        print("Random source: secrets.token_bytes (unseeded, per-run CSPRNG)")
    else:
        print(f"Random source: random.Random(seed={seed}) [REPRODUCIBLE]")
    rng = RandomSource(seed=seed)

    # Oracle sanity check: FIPS anchors must match hashlib before we touch C64.
    print("Oracle sanity: verifying FIPS 180-4 anchors against hashlib...")
    if hashlib.sha384(b"").digest() != FIPS_EMPTY_DIGEST:
        print("FATAL: hashlib SHA-384(empty) disagrees with FIPS 180-4 constant")
        sys.exit(2)
    if hashlib.sha384(FIPS_ABC).digest() != FIPS_ABC_DIGEST:
        print("FATAL: hashlib SHA-384('abc') disagrees with FIPS 180-4 constant")
        sys.exit(2)
    print("  OK: FIPS 180-4 anchors match hashlib")

    # Build (unless skipped via env var)
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(
            ["make"], capture_output=True, text=True, cwd=PROJECT_ROOT
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
        "sha384_init",
        "sha384_update",
        "sha384_final",
        "sha384_digest",
        "sha384_msg_buf",
        "sha_src",
        "sha_len",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: required labels not found: {', '.join(missing)}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
        extra_args=["-reu", "-reusize", "512"],
    )

    with ViceInstanceManager(
        config=config,
        port_range_start=6511,
        port_range_end=6531,
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

        # Plant the standard RTS-at-$0339 guard used by all test files.
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        passed, failed, skipped = run_tests(transport, labels, rng, run_full)
        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
    print(f"Mode: {'full' if run_full else 'fast'}")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
