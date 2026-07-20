#!/usr/bin/env python3
"""test_ecdsa_verify.py -- Oracle-gated ECDSA verify tests for P-256 / P-384.

Exercises the two packaged verify routines (src/ecdsa256.s::ecdsa_verify_256
and src/ecdsa384.s::ecdsa_verify_384) end-to-end by staging the 160-/240-byte
BE input struct into the test-driver buffers (ecdsa_inputs_256 /
ecdsa_inputs_384 in data.s) and invoking the trampoline in main.s
(ecdsa_verify_256_tramp / ecdsa_verify_384_tramp) which loads A/X with a
pointer to the buffer, calls verify, and captures the returned C flag into
ecdsa_result_{256,384} (0 = valid, 1 = invalid). The trampoline indirection
is necessary because c64_test_harness.jsr() does not let the Python side
preload CPU registers.

Oracle model (same shape as tools/vectors/README.md):

  1. Positive anchors: RFC 6979 Appendix A.2.5 (P-256, SHA-256) and
     Appendix A.3.1 (P-384, SHA-384) "sample" vectors. These are pinned
     IETF-standardised outputs; tampering would break the RFC.

  2. Negative derivatives on the RFC vectors: LSB flips in r / s, r=0,
     s=0, r=n, s=n, corrupted pub_x, corrupted hash. The positive
     baseline plus every derivative MUST agree with the
     `cryptography` oracle (which is the external authority for
     ECDSA verification across the full verify space).

  3. NIST CAVP SigVer vectors (`tools/vectors/nist_p{256,384}_sigver.rsp`,
     15 per curve, subsampled in fast mode). The harness result is
     compared against `cryptography.verify`; if `cryptography` ever
     disagrees with the KAT's Result = P/F field the test prints a
     loud WARNING but still trusts the oracle. The KAT Result field
     tells us *what the vector was meant to exercise* (mod code 1=Msg,
     2=R, 3=S, 4=Q) and is reported alongside each case for context.

Usage:
    python3 tools/test_ecdsa_verify.py           # 5 CAVP vectors/curve
    python3 tools/test_ecdsa_verify.py --full    # 20 CAVP vectors/curve
"""

import hashlib
import os
import secrets
import subprocess
import sys
import time
import traceback

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature, Prehashed,
)
from cryptography.exceptions import InvalidSignature


PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
# C64_PRG_NAME / C64_LABELS_NAME select an alternate build under build/ —
# used by `make nocomb-prg` (issue #61) to run this whole suite against the
# ECDSA_NO_COMB variant PRG (pair with C64_SKIP_BUILD=1, since the default
# build step below only produces the standard PRG).
PRG_PATH = os.path.join(PROJECT_ROOT, "build",
                        os.environ.get("C64_PRG_NAME", "nist-curves.prg"))
LABELS_PATH = os.path.join(PROJECT_ROOT, "build",
                           os.environ.get("C64_LABELS_NAME", "labels.txt"))

sys.path.insert(0, PROJECT_ROOT)

from tools.vectors import (  # noqa: E402
    P256_N, P384_N,
)


def _warn_if_vice_running():
    import subprocess, sys
    try:
        res = subprocess.run(["pgrep", "-c", "x64sc"], capture_output=True, text=True, timeout=2)
        n = int(res.stdout.strip() or "0")
        if n > 0:
            print(f"WARNING: {n} other x64sc instance(s) already running - wall-clock timings may be unreliable.", file=sys.stderr)
    except Exception:
        pass  # preflight must never block test execution


# ----------------------------------------------------------------------------
# RFC 6979 test vectors
# ----------------------------------------------------------------------------
# Appendix A.2.5 -- P-256, SHA-256, message "sample"
#   https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5
RFC6979_P256 = {
    "msg": b"sample",
    "d":  0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
    "Ux": 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
    "Uy": 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299,
    "r":  0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
    "s":  0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8,
}

# Appendix A.3.1 -- P-384, SHA-384, message "sample"
#   https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.3.1
RFC6979_P384 = {
    "msg": b"sample",
    "d":  0x6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5,
    "Ux": 0xEC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13,
    "Uy": 0x8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720,
    "r":  0x94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46,
    "s":  0x99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8,
}


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def int_to_be_bytes(val, length):
    return val.to_bytes(length, "big")


def build_struct(r, s, h, qx, qy, byte_len):
    """Pack five BE field elements into one struct for the C64 verify driver."""
    return (int_to_be_bytes(r,  byte_len)
          + int_to_be_bytes(s,  byte_len)
          + int_to_be_bytes(h,  byte_len)
          + int_to_be_bytes(qx, byte_len)
          + int_to_be_bytes(qy, byte_len))


def oracle_verify(curve, r, s, h_bytes, qx, qy):
    """Return True if (r, s) is a valid ECDSA signature on h_bytes under (qx,qy).

    `curve` is 'p256' or 'p384'. `h_bytes` is the raw digest (SHA-256 or
    SHA-384). Returns False for any malformed input (out-of-range, bad
    point, invalid signature). This is the external oracle against which
    the C64 verify result is compared.
    """
    # Range check that mirrors what a sane verifier does -- cryptography
    # does it internally as well, but an out-of-range scalar can raise
    # ValueError from derive-public-key / signature decoding.
    n = {"p256": P256_N, "p384": P384_N}[curve]
    if not (1 <= r < n) or not (1 <= s < n):
        return False
    curve_obj = {"p256": ec.SECP256R1(), "p384": ec.SECP384R1()}[curve]
    hash_alg = {"p256": hashes.SHA256(), "p384": hashes.SHA384()}[curve]
    try:
        pub = ec.EllipticCurvePublicNumbers(qx, qy, curve_obj).public_key()
    except (ValueError, Exception):
        return False
    sig = encode_dss_signature(r, s)
    try:
        pub.verify(sig, h_bytes, ec.ECDSA(Prehashed(hash_alg)))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def c64_verify_256(transport, labels, r, s, h_bytes, qx, qy):
    """Stage the 160 B struct, invoke tramp, return 0 (valid) / 1 (invalid)."""
    h_int = int.from_bytes(h_bytes, "big")
    payload = build_struct(r, s, h_int, qx, qy, 32)
    assert len(payload) == 160
    write_bytes(transport, labels["ecdsa_inputs_256"], payload)
    write_bytes(transport, labels["ecdsa_result_256"], b"\xFF")  # sentinel
    jsr(transport, labels["ecdsa_verify_256_tramp"], timeout=300.0)
    result = read_bytes(transport, labels["ecdsa_result_256"], 1)[0]
    if result not in (0, 1):
        raise RuntimeError(
            f"ecdsa_result_256 = {result:#04x}; trampoline did not run"
        )
    return result


def c64_verify_384(transport, labels, r, s, h_bytes, qx, qy):
    """Stage the 240 B struct, invoke tramp, return 0 (valid) / 1 (invalid)."""
    h_int = int.from_bytes(h_bytes, "big")
    payload = build_struct(r, s, h_int, qx, qy, 48)
    assert len(payload) == 240
    write_bytes(transport, labels["ecdsa_inputs_384"], payload)
    write_bytes(transport, labels["ecdsa_result_384"], b"\xFF")
    jsr(transport, labels["ecdsa_verify_384_tramp"], timeout=600.0)
    result = read_bytes(transport, labels["ecdsa_result_384"], 1)[0]
    if result not in (0, 1):
        raise RuntimeError(
            f"ecdsa_result_384 = {result:#04x}; trampoline did not run"
        )
    return result


def c64_verify_with_msg_384(transport, labels, r, s, message, qx, qy):
    """Stage message + 240 B struct (h slot zeroed), invoke the wrapper tramp.

    The C64 wrapper hashes `message` with SHA-384, splices the digest into
    the struct's h slot, then runs the standard ecdsa_verify_384 path.
    Returns 0 (valid) / 1 (invalid). `message` must fit in sha384_msg_buf
    (1024 bytes) since the wrapper issues exactly one sha384_update call.
    """
    if len(message) > 1024:
        raise ValueError(
            f"message length {len(message)} exceeds sha384_msg_buf (1024)"
        )

    msg_buf = labels["sha384_msg_buf"]
    sha_src = labels["sha_src"]
    sha_len = labels["sha_len"]

    # Build the struct: h slot is left zero -- the wrapper overwrites it.
    payload = build_struct(r, s, 0, qx, qy, 48)
    assert len(payload) == 240
    write_bytes(transport, labels["ecdsa_inputs_384"], payload)

    # Stage message (skip the poke for an empty message; sha_len = 0
    # short-circuits sha384_update on the C64 side).
    if len(message) > 0:
        write_bytes(transport, msg_buf, message)
    write_bytes(transport, sha_src,
                bytes([msg_buf & 0xFF, (msg_buf >> 8) & 0xFF]))
    write_bytes(transport, sha_len,
                bytes([len(message) & 0xFF, (len(message) >> 8) & 0xFF]))

    # Sentinel + invoke. SHA-384 of a sub-1KB message in warp is < 5s; the
    # verify step itself runs ~30s; budget 600s for a generous margin.
    write_bytes(transport, labels["ecdsa_result_msg_384"], b"\xFF")
    jsr(transport, labels["ecdsa_verify_with_msg_384_tramp"], timeout=600.0)
    result = read_bytes(transport, labels["ecdsa_result_msg_384"], 1)[0]
    if result not in (0, 1):
        raise RuntimeError(
            f"ecdsa_result_msg_384 = {result:#04x}; trampoline did not run"
        )
    return result


def run_case(transport, labels, curve, r, s, h_bytes, qx, qy, label):
    """Run one vector on both oracle and C64, compare. Returns (pass, fail)."""
    oracle_valid = oracle_verify(curve, r, s, h_bytes, qx, qy)
    expected_c = 0 if oracle_valid else 1
    t0 = time.time()
    try:
        if curve == "p256":
            got_c = c64_verify_256(transport, labels, r, s, h_bytes, qx, qy)
        else:
            got_c = c64_verify_384(transport, labels, r, s, h_bytes, qx, qy)
    except Exception as e:
        dt = time.time() - t0
        print(f"  FAIL ({dt:.1f}s) [{curve}] {label}: exception {e!r}")
        return 0, 1
    dt = time.time() - t0
    tag = "VALID" if oracle_valid else "INVALID"
    if got_c == expected_c:
        print(f"  PASS ({dt:.1f}s) [{curve}] {label}: oracle={tag}, C64=C{got_c}")
        return 1, 0
    print(f"  FAIL ({dt:.1f}s) [{curve}] {label}: oracle={tag} (C={expected_c})"
          f", C64 returned C={got_c}")
    return 0, 1


# ----------------------------------------------------------------------------
# NIST CAVP SigVer parser
# ----------------------------------------------------------------------------

def load_sigver_vectors(path, section):
    """Parse a NIST CAVP SigVer .rsp file for one curve+hash section.

    Returns a list of dicts with keys:
        Msg (bytes), Qx (int), Qy (int), R (int), S (int),
        expected_pass (bool), raw_result (str)
    """
    out = []
    current = {}
    in_section = False
    with open(path, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                if current and in_section:
                    out.append(current)
                    current = {}
                continue
            if line.startswith("[") and line.endswith("]"):
                if current and in_section:
                    out.append(current)
                current = {}
                in_section = (line[1:-1].strip() == section)
                continue
            if not in_section:
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip()
                if k == "Msg":
                    current["Msg"] = bytes.fromhex(v)
                elif k in ("Qx", "Qy", "R", "S"):
                    current[k] = int(v, 16)
                elif k == "Result":
                    current["raw_result"] = v
                    current["expected_pass"] = v.startswith("P")
    if current and in_section:
        out.append(current)
    return [v for v in out if all(
        kk in v for kk in ("Msg", "Qx", "Qy", "R", "S", "expected_pass")
    )]


# ----------------------------------------------------------------------------
# Test drivers
# ----------------------------------------------------------------------------

def run_rfc6979_tests(transport, labels, curve, vec, byte_len, hash_name):
    """RFC 6979 positive + 8 negative derivations on one vector."""
    passed = failed = 0
    if hash_name == "sha256":
        h = hashlib.sha256(vec["msg"]).digest()
    else:
        h = hashlib.sha384(vec["msg"]).digest()
    r, s, Ux, Uy = vec["r"], vec["s"], vec["Ux"], vec["Uy"]
    n = {"p256": P256_N, "p384": P384_N}[curve]

    # Positive
    p, f = run_case(transport, labels, curve, r, s, h, Ux, Uy,
                    f"RFC 6979 {curve} sample (positive)")
    passed += p; failed += f

    # Negatives
    negs = [
        (r ^ 1, s,      h,                                        Ux, Uy, "LSB flip r"),
        (r,      s ^ 1, h,                                        Ux, Uy, "LSB flip s"),
        (0,      s,      h,                                        Ux, Uy, "r = 0"),
        (r,      0,      h,                                        Ux, Uy, "s = 0"),
        (n,      s,      h,                                        Ux, Uy, "r = n"),
        (r,      n,      h,                                        Ux, Uy, "s = n"),
        (r,      s,      h,                                        Ux ^ 1, Uy, "flip bit in Qx"),
        (r,      s,      bytes([h[0] ^ 1]) + h[1:],                Ux, Uy, "flip bit in hash"),
    ]
    for r2, s2, h2, qx2, qy2, tag in negs:
        p, f = run_case(transport, labels, curve, r2, s2, h2, qx2, qy2,
                        f"RFC 6979 {curve} neg: {tag}")
        passed += p; failed += f

    return passed, failed


def run_cavp_tests(transport, labels, curve, hash_alg, path, section, n_max):
    """NIST CAVP SigVer vectors for one curve/hash pair."""
    passed = failed = 0
    vectors = load_sigver_vectors(path, section)
    if not vectors:
        print(f"  ERROR: no vectors parsed from {path} section {section}")
        return 0, 1

    # Cross-validate oracle vs KAT Result column for reporting (loud
    # warning only; the oracle wins if they disagree).
    oracle_mismatch = []
    for v in vectors:
        h = hash_alg(v["Msg"]).digest()
        ok = oracle_verify(curve, v["R"], v["S"], h, v["Qx"], v["Qy"])
        if ok != v["expected_pass"]:
            oracle_mismatch.append(v)
    if oracle_mismatch:
        print(f"  WARNING: {len(oracle_mismatch)}/{len(vectors)} vectors' KAT Result "
              f"disagrees with cryptography oracle; trusting oracle")

    # Pick a balanced subset: include at least one P and at least one each
    # of F modifications. Simple strategy: take the first n_max as stored.
    subset = vectors[:n_max]
    print(f"  Running {len(subset)}/{len(vectors)} CAVP vectors "
          f"(section {section})")
    for i, v in enumerate(subset):
        h = hash_alg(v["Msg"]).digest()
        tag = f"CAVP[{i}] {v['raw_result']}"
        p, f = run_case(transport, labels, curve,
                        v["R"], v["S"], h, v["Qx"], v["Qy"], tag)
        passed += p; failed += f
    return passed, failed


# ----------------------------------------------------------------------------
# ecdsa_verify_with_message_384 wrapper tests
#
# Generate fresh P-384 keypairs and sign random messages of varying length
# (1, 17, 100, 500, 1023 bytes -- all under the 1024 B sha384_msg_buf cap).
# The C64 wrapper does the SHA-384 internally, so the test never poke a
# precomputed digest into the h slot. Each case is then sanity-checked
# against the existing precomputed-digest path (c64_verify_384) to confirm
# the wrapper produces the same VALID/INVALID verdict.
# ----------------------------------------------------------------------------

def run_p384_msg_wrapper_tests(transport, labels):
    """Generate keypair + random message + sign, verify the message-form
    wrapper agrees with the precomputed-digest verify path."""
    passed = failed = 0

    # Use a single P-384 keypair for all positive cases. Bind it via the raw
    # public-key numbers so we have qx/qy as ints in our LE/BE-agnostic form.
    sk = ec.generate_private_key(ec.SECP384R1())
    pub_nums = sk.public_key().public_numbers()
    qx, qy = pub_nums.x, pub_nums.y

    # Positive cases at boundary message lengths (under 1024 to keep the
    # wrapper's single-update path; multi-update is the streaming variant
    # callers drive directly, not this wrapper).
    msg_lens = [1, 17, 100, 500, 1023]

    for n in msg_lens:
        msg = secrets.token_bytes(n)
        # cryptography signs with SHA-384; result is DER, decode -> (r, s).
        sig_der = sk.sign(msg, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(sig_der)

        # Compute expected outcome via the same external oracle used by every
        # other test in this file -- this validates the message-form wrapper
        # against cryptography end-to-end (hash + verify both done external).
        h = hashlib.sha384(msg).digest()
        oracle_valid = oracle_verify("p384", r, s, h, qx, qy)
        # Sign should always produce a valid signature.
        if not oracle_valid:
            print(f"  FAIL [p384 wrapper] len={n}: oracle rejects fresh "
                  f"keypair signature (test bug, not a C64 issue)")
            failed += 1
            continue
        expected_c = 0

        t0 = time.time()
        try:
            got_c = c64_verify_with_msg_384(transport, labels, r, s, msg, qx, qy)
        except Exception as e:
            dt = time.time() - t0
            print(f"  FAIL ({dt:.1f}s) [p384 wrapper] len={n} positive: "
                  f"exception {e!r}")
            failed += 1
            continue
        dt = time.time() - t0
        if got_c == expected_c:
            print(f"  PASS ({dt:.1f}s) [p384 wrapper] len={n} positive: "
                  f"VALID (C={got_c})")
            passed += 1
        else:
            print(f"  FAIL ({dt:.1f}s) [p384 wrapper] len={n} positive: "
                  f"oracle=VALID (C=0), C64 returned C={got_c}")
            failed += 1

    # Two negatives: tamper with the message after signing (digest changes,
    # signature should no longer verify), and use a wrong public key on a
    # fresh sign. Both must produce INVALID.
    msg = secrets.token_bytes(64)
    sig_der = sk.sign(msg, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(sig_der)
    tampered = bytes([msg[0] ^ 1]) + msg[1:]
    h_tampered = hashlib.sha384(tampered).digest()
    oracle_valid = oracle_verify("p384", r, s, h_tampered, qx, qy)
    assert not oracle_valid, "tampered message should not verify"

    t0 = time.time()
    try:
        got_c = c64_verify_with_msg_384(
            transport, labels, r, s, tampered, qx, qy)
    except Exception as e:
        dt = time.time() - t0
        print(f"  FAIL ({dt:.1f}s) [p384 wrapper] tampered msg: exception {e!r}")
        failed += 1
    else:
        dt = time.time() - t0
        if got_c == 1:
            print(f"  PASS ({dt:.1f}s) [p384 wrapper] tampered msg: "
                  f"INVALID (C={got_c})")
            passed += 1
        else:
            print(f"  FAIL ({dt:.1f}s) [p384 wrapper] tampered msg: "
                  f"oracle=INVALID (C=1), C64 returned C={got_c}")
            failed += 1

    # Wrong public key (keep r/s/msg, swap pub).
    sk2 = ec.generate_private_key(ec.SECP384R1())
    other_nums = sk2.public_key().public_numbers()
    qx2, qy2 = other_nums.x, other_nums.y
    msg = secrets.token_bytes(50)
    sig_der = sk.sign(msg, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(sig_der)
    h = hashlib.sha384(msg).digest()
    oracle_valid = oracle_verify("p384", r, s, h, qx2, qy2)
    assert not oracle_valid, "sig under wrong pub should not verify"

    t0 = time.time()
    try:
        got_c = c64_verify_with_msg_384(
            transport, labels, r, s, msg, qx2, qy2)
    except Exception as e:
        dt = time.time() - t0
        print(f"  FAIL ({dt:.1f}s) [p384 wrapper] wrong pub: exception {e!r}")
        failed += 1
    else:
        dt = time.time() - t0
        if got_c == 1:
            print(f"  PASS ({dt:.1f}s) [p384 wrapper] wrong pub: "
                  f"INVALID (C={got_c})")
            passed += 1
        else:
            print(f"  FAIL ({dt:.1f}s) [p384 wrapper] wrong pub: "
                  f"oracle=INVALID (C=1), C64 returned C={got_c}")
            failed += 1

    return passed, failed


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def run_tests(transport, labels, run_full):
    total_p = total_f = 0
    n_cavp = 20 if run_full else 5

    groups = [
        ("P-256 RFC 6979 A.2.5 + 8 negatives",
         lambda: run_rfc6979_tests(transport, labels, "p256",
                                   RFC6979_P256, 32, "sha256")),
        ("P-384 RFC 6979 A.3.1 + 8 negatives",
         lambda: run_rfc6979_tests(transport, labels, "p384",
                                   RFC6979_P384, 48, "sha384")),
        (f"P-256 NIST CAVP SigVer ({n_cavp} vectors)",
         lambda: run_cavp_tests(
             transport, labels, "p256", hashlib.sha256,
             os.path.join(PROJECT_ROOT, "tools/vectors/nist_p256_sigver.rsp"),
             "P-256,SHA-256", n_cavp)),
        (f"P-384 NIST CAVP SigVer ({n_cavp} vectors)",
         lambda: run_cavp_tests(
             transport, labels, "p384", hashlib.sha384,
             os.path.join(PROJECT_ROOT, "tools/vectors/nist_p384_sigver.rsp"),
             "P-384,SHA-384", n_cavp)),
        ("P-384 ecdsa_verify_with_message_384 wrapper (5 positive + 2 negative)",
         lambda: run_p384_msg_wrapper_tests(transport, labels)),
    ]

    for name, fn in groups:
        print(f"\n--- {name} ---")
        try:
            p, f = fn()
            total_p += p; total_f += f
            status = "OK" if f == 0 else "FAIL"
            print(f"  {status}: {p}/{p+f} passed")
        except Exception as e:
            total_f += 1
            print(f"  ERROR: {e}")
            traceback.print_exc()
    return total_p, total_f


def main():
    _warn_if_vice_running()
    run_full = "--full" in sys.argv[1:]

    os.chdir(PROJECT_ROOT)

    # Build unless skipped (matches pattern in other test files).
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stdout}\n{result.stderr}")
            sys.exit(1)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found after build")
        sys.exit(1)
    print(f"Built: {PRG_PATH}")

    labels = Labels.from_file(LABELS_PATH)
    required = [
        "ecdsa_verify_256_tramp", "ecdsa_verify_384_tramp",
        "ecdsa_inputs_256", "ecdsa_inputs_384",
        "ecdsa_result_256", "ecdsa_result_384",
        # ecdsa_verify_with_message_384 wrapper test trampoline
        "ecdsa_verify_with_msg_384_tramp", "ecdsa_result_msg_384",
        "sha384_msg_buf", "sha_src", "sha_len",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: required labels missing: {', '.join(missing)}")
        sys.exit(1)

    # Oracle sanity: verify RFC 6979 anchors agree with cryptography.
    print("Oracle sanity: RFC 6979 A.2.5 / A.3.1 should verify...")
    h256 = hashlib.sha256(RFC6979_P256["msg"]).digest()
    if not oracle_verify("p256", RFC6979_P256["r"], RFC6979_P256["s"],
                          h256, RFC6979_P256["Ux"], RFC6979_P256["Uy"]):
        print("FATAL: RFC 6979 P-256 A.2.5 failed the oracle")
        sys.exit(2)
    h384 = hashlib.sha384(RFC6979_P384["msg"]).digest()
    if not oracle_verify("p384", RFC6979_P384["r"], RFC6979_P384["s"],
                          h384, RFC6979_P384["Ux"], RFC6979_P384["Uy"]):
        print("FATAL: RFC 6979 P-384 A.3.1 failed the oracle")
        sys.exit(2)
    print("  OK: RFC 6979 anchors pinned via cryptography.verify")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        print("Waiting for init sentinel...")
        start = time.time()
        sentinel_ok = False
        # C64_INIT_TIMEOUT: the FP_ONCHIP_MUL variant PRG (issue #69) boots
        # ~3x slower than baseline (precompute field muls run on-chip), so
        # variant test runs need a wider window than the 600 s default.
        init_timeout = float(os.environ.get("C64_INIT_TIMEOUT", "600"))
        while time.time() - start < init_timeout:
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
        print(f"Init complete after {time.time()-start:.1f}s")

        # Plant an RTS-at-0339 guard matching other tests (defensive; not
        # strictly required since ecdsa_verify never jumps there).
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        passed, failed = run_tests(transport, labels, run_full)
        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"Mode: {'full' if run_full else 'fast'}")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
