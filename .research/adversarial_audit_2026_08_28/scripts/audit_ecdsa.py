#!/usr/bin/env python3.13
"""Adversarial ECDSA-verify sweep: C64 ecdsa_verify_256/384 vs cryptography.hazmat.

One VICE boot, many cases. Every expected value comes from hazmat (OpenSSL)
or from Python-int ECDSA math whose result hazmat re-confirms; nothing is
taken from a previous C64 run.

Usage: python3.13 audit_ecdsa.py [--p384-only] [--p256-only]
"""
import hashlib
import secrets
import sys
import time

from audit_common import (Log, boot, shutdown, load_labels, be,
                          read_bytes, write_bytes, jsr, PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, Prehashed)
from cryptography.exceptions import InvalidSignature

from tools.vectors import (P256_P, P256_N, P256_B, P256_GX, P256_GY,
                           P384_P, P384_N, P384_B, P384_GX, P384_GY)
from tools.vectors.loader import scalar_mul_oracle, affine_add, INFINITY

CURVE = {
    "p256": dict(p=P256_P, n=P256_N, b=P256_B, gx=P256_GX, gy=P256_GY,
                 nbytes=32, obj=ec.SECP256R1(), hash=hashes.SHA256(),
                 hfn=hashlib.sha256, struct="ecdsa_inputs_256",
                 result="ecdsa_result_256", tramp="ecdsa_verify_256_tramp",
                 timeout=900.0),
    "p384": dict(p=P384_P, n=P384_N, b=P384_B, gx=P384_GX, gy=P384_GY,
                 nbytes=48, obj=ec.SECP384R1(), hash=hashes.SHA384(),
                 hfn=hashlib.sha384, struct="ecdsa_inputs_384",
                 result="ecdsa_result_384", tramp="ecdsa_verify_384_tramp",
                 timeout=1800.0),
}


# --------------------------------------------------------------------------
# Oracles
# --------------------------------------------------------------------------

def hazmat_verify(curve, r, s, h_bytes, qx, qy):
    """Raw hazmat verdict with NO Python-side pre-range check.

    Returns True / False / 'ERR:<reason>' (ERR is treated as INVALID by a
    verifier but recorded so we can see whether OpenSSL even accepted the
    encoding).
    """
    c = CURVE[curve]
    try:
        pub = ec.EllipticCurvePublicNumbers(qx, qy, c["obj"]).public_key()
    except Exception as e:
        return f"ERR:pubkey:{type(e).__name__}"
    try:
        sig = encode_dss_signature(r, s)
    except Exception as e:
        return f"ERR:sigenc:{type(e).__name__}"
    try:
        pub.verify(sig, h_bytes, ec.ECDSA(Prehashed(c["hash"])))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        return f"ERR:verify:{type(e).__name__}"


def oracle_c(curve, r, s, h_bytes, qx, qy):
    v = hazmat_verify(curve, r, s, h_bytes, qx, qy)
    return (0 if v is True else 1), v


def py_verify(curve, r, s, e, qx, qy):
    """Independent pure-int ECDSA verify (FIPS 186-5 6.4.2) for cross-check.

    Uses the loader's affine group law (self-checked vs hazmat) and hazmat
    for k*G. e is the integer hash value (already truncated to n bits)."""
    c = CURVE[curve]
    n, p = c["n"], c["p"]
    if not (1 <= r < n and 1 <= s < n):
        return False
    if not (0 <= qx < p and 0 <= qy < p):
        return False
    if (qy * qy - (qx ** 3 - 3 * qx + c["b"])) % p != 0:
        return False
    w = pow(s, -1, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    R = INFINITY if u1 == 0 else scalar_mul_oracle(u1, curve)
    # u2*Q by affine double-and-add (Q generic, hazmat only exposes k*G)
    T = INFINITY
    for i in range(u2.bit_length() - 1, -1, -1):
        T = affine_add(T, T, curve)
        if (u2 >> i) & 1:
            T = affine_add(T, (qx, qy), curve)
    R = affine_add(R, T, curve)
    if R == INFINITY:
        return False
    return (R[0] % n) == r


# --------------------------------------------------------------------------
# Signature construction helpers (Python ints + hazmat for k*G)
# --------------------------------------------------------------------------

def sign_with_k(curve, d, e, k):
    """Textbook ECDSA sign with explicit nonce k. e = integer message rep."""
    n = CURVE[curve]["n"]
    x, _ = scalar_mul_oracle(k, curve)
    r = x % n
    s = (pow(k, -1, n) * (e + r * d)) % n
    return r, s


def keygen(curve, d=None):
    n = CURVE[curve]["n"]
    if d is None:
        d = 1 + secrets.randbelow(n - 1)
    qx, qy = scalar_mul_oracle(d, curve)
    return d, qx, qy


def point_mul(curve, k, P):
    """k*P via affine double-and-add (for arbitrary base P)."""
    n = CURVE[curve]["n"]
    k %= n
    T = INFINITY
    for i in range(k.bit_length() - 1, -1, -1):
        T = affine_add(T, T, curve)
        if (k >> i) & 1:
            T = affine_add(T, P, curve)
    return T


def find_point_with_x_in(curve, lo, hi):
    """Random on-curve point whose x lies in [lo, hi). p%4==3 sqrt."""
    c = CURVE[curve]
    p, b = c["p"], c["b"]
    assert p % 4 == 3
    while True:
        x = lo + secrets.randbelow(hi - lo)
        rhs = (pow(x, 3, p) - 3 * x + b) % p
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p == rhs:
            return x, y


def find_small_x_point(curve):
    c = CURVE[curve]
    p, b = c["p"], c["b"]
    x = 0
    while True:
        rhs = (pow(x, 3, p) - 3 * x + b) % p
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p == rhs:
            return x, y
        x += 1


# --------------------------------------------------------------------------
# C64 driver
# --------------------------------------------------------------------------

def c64_verify(transport, labels, curve, r, s, h_bytes, qx, qy):
    c = CURVE[curve]
    nb = c["nbytes"]
    assert len(h_bytes) == nb
    payload = be(r, nb) + be(s, nb) + h_bytes + be(qx, nb) + be(qy, nb)
    write_bytes(transport, labels[c["struct"]], payload)
    write_bytes(transport, labels[c["result"]], b"\xFF")
    t0 = time.time()
    jsr(transport, labels[c["tramp"]], timeout=c["timeout"])
    dt = time.time() - t0
    res = read_bytes(transport, labels[c["result"]], 1)[0]
    if res not in (0, 1):
        raise RuntimeError(f"result byte {res:#x}: trampoline did not run")
    return res, dt


def run_case(log, transport, labels, curve, label, r, s, h_bytes, qx, qy,
             e_for_py=None):
    exp_c, hz = oracle_c(curve, r, s, h_bytes, qx, qy)
    spec_override = None
    if "must REJECT" in label:
        # FIPS 186-5 / issue #66 contract: non-canonical encodings are
        # rejected by the library even though OpenSSL reduces them mod p.
        spec_override = 1
    if spec_override is not None and spec_override != exp_c:
        hz = f"{hz} (hazmat differs from spec; spec expects C={spec_override})"
        exp_c = spec_override
    py = None
    if e_for_py is not None:
        try:
            py = py_verify(curve, r, s, e_for_py, qx, qy)
        except Exception as ex:
            py = f"ERR:{ex!r}"
    try:
        got, dt = c64_verify(transport, labels, curve, r, s, h_bytes, qx, qy)
    except Exception as ex:
        log.case("ecdsa-" + curve, label, exp_c, f"EXC:{ex!r}",
                 detail={"hazmat": hz, "py": py, "r": hex(r), "s": hex(s),
                         "h": h_bytes.hex(), "qx": hex(qx), "qy": hex(qy)})
        return
    detail = {"hazmat": hz, "py_verify": py, "r": hex(r), "s": hex(s),
              "h": h_bytes.hex(), "qx": hex(qx), "qy": hex(qy)}
    if py is not None and (py is True) != (exp_c == 0):
        detail["NOTE"] = "hazmat and pure-int verify DISAGREE"
    log.case("ecdsa-" + curve, label, exp_c, got, detail=detail, dt=dt)


# --------------------------------------------------------------------------
# Case generators
# --------------------------------------------------------------------------

def cases_for(curve, quick=False):
    """Yield (label, r, s, h_bytes, qx, qy, e_int_or_None)."""
    c = CURVE[curve]
    n, p, nb = c["n"], c["p"], c["nbytes"]
    nbits = nb * 8
    hfn = c["hfn"]
    H = lambda v: be(v % (1 << nbits), nb)  # noqa: E731

    d, qx, qy = keygen(curve)
    msg = secrets.token_bytes(40)
    h = hfn(msg).digest()
    e = int.from_bytes(h, "big")
    k = 1 + secrets.randbelow(n - 1)
    r, s = sign_with_k(curve, d, e, k)

    # --- baseline + malleability + range gate ---------------------------
    yield ("baseline valid (hazmat key, manual k)", r, s, h, qx, qy, e)
    yield ("malleable (r, n-s) must VERIFY", r, n - s, h, qx, qy, e)
    yield ("r = n-1 (random)", n - 1, s, h, qx, qy, e)
    yield ("s = n-1 (random)", r, n - 1, h, qx, qy, e)
    yield ("r = n", n, s, h, qx, qy, e)
    yield ("s = n", r, n, h, qx, qy, e)
    yield ("r = n+1", n + 1, s, h, qx, qy, e)
    yield ("s = n+1", r, n + 1, h, qx, qy, e)
    yield ("r = 2^bits-1", (1 << nbits) - 1, s, h, qx, qy, e)
    yield ("s = 2^bits-1", r, (1 << nbits) - 1, h, qx, qy, e)
    if r + n < (1 << nbits):
        yield ("r = r_valid + n (fits width; must NOT reduce)",
               r + n, s, h, qx, qy, e)
    if s + n < (1 << nbits):
        yield ("s = s_valid + n (fits width)", r, s + n, h, qx, qy, e)
    yield ("r = 0", 0, s, h, qx, qy, e)
    yield ("s = 0", r, 0, h, qx, qy, e)
    yield ("r = 1 (random sig)", 1, s, h, qx, qy, e)
    yield ("s = 1 (random sig)", r, 1, h, qx, qy, e)

    # --- hash-value edge cases, each with a signature built FOR that e ---
    for label, e2 in [("h = 0 via signing (u1 = 0 path)", 0),
                      ("h = n (≡0 mod n, unreduced input)", n),
                      ("h = n+1", n + 1),
                      ("h = 2^bits-1 (>= n, unreduced)", (1 << nbits) - 1),
                      ("h = n-1", n - 1),
                      ("h = 1", 1),
                      ("h = 2^(bits-1) (top bit only)", 1 << (nbits - 1)),
                      ("h = p (field prime as hash)", p),
                      ("h = 2^bits - (2^bits - n) - 1 + ... random >= n",
                       n + secrets.randbelow((1 << nbits) - n))]:
        k2 = 1 + secrets.randbelow(n - 1)
        r2, s2 = sign_with_k(curve, d, e2 % n, k2)
        # Note: signer uses e2 mod n; verifier receives raw e2 bytes.
        yield (label, r2, s2, H(e2), qx, qy, e2)
    # wrong-h negatives for the same edge encodings
    yield ("h = 0 with baseline sig (must reject)", r, s, H(0), qx, qy, 0)
    yield ("h = 2^bits-1 with baseline sig (must reject)", r, s,
           H((1 << nbits) - 1), qx, qy, (1 << nbits) - 1)
    # h vs h+n: same residue, both must give same verdict as oracle
    if e + n < (1 << nbits):
        yield ("h + n (same residue as valid h)", r, s, H(e + n), qx, qy,
               e + n)

    # --- u1 = 0 forgery-shape (h=0): works for ANY Q, no d needed ------
    for qlabel, Q in [("random Q", (qx, qy)),
                      ("Q = G", (c["gx"], c["gy"])),
                      ("Q = -G", (c["gx"], (-c["gy"]) % p)),
                      ("Q = 2G", affine_add((c["gx"], c["gy"]),
                                            (c["gx"], c["gy"]), curve))]:
        kk = 2 + secrets.randbelow(n - 2)
        R = point_mul(curve, kk, Q)
        rr = R[0] % n
        ss = (rr * pow(kk, -1, n)) % n
        yield (f"h=0 constructed sig, {qlabel}", rr, ss, H(0), Q[0], Q[1], 0)

    # --- Qx ≡ r trick: (r,s)=(Qx,Qx), h=0, u2=1 -> R = Q ----------------
    if qx < n:
        yield ("h=0, (r,s)=(Qx,Qx): u2=1, R=Q, x(R)=r", qx, qx, H(0),
               qx, qy, 0)

    # --- cofactor fallback path: x(R) in [n, p) ---------------------------
    # Q := R with n <= x < p; h=0, u2=1 -> R = Q; r = x - n. Both C64
    # compare branches (r*Z^2 == X fails, (r+n)*Z^2 == X hits) exercised.
    xr, yr = find_point_with_x_in(curve, n, p)
    rr = xr - n
    assert 1 <= rr < n
    yield ("cofactor fallback: Q.x in [n,p), r = Qx-n, s = r, h=0",
           rr, rr, H(0), xr, yr, 0)
    yield ("cofactor fallback negative: r = Qx-n+1", rr + 1, rr, H(0),
           xr, yr, 0)
    # also with u2 = 2: Q' = R/2 ... needs inverse of 2 times R: Q' = (2^-1 mod n) * R
    half = pow(2, -1, n)
    Qh = point_mul(curve, half, (xr, yr))
    yield ("cofactor fallback via u2=2: Q=(1/2)R, r=Qx(R)-n, s=r/2, h=0",
           rr, (rr * half) % n, H(0), Qh[0], Qh[1], 0)

    # --- R = infinity construction: h ≡ -r*d (mod n) --------------------
    r3 = 1 + secrets.randbelow(n - 1)
    s3 = 1 + secrets.randbelow(n - 1)
    e3 = (-r3 * d) % n
    yield ("u1*G + u2*Q = infinity (h = -r*d mod n) must REJECT",
           r3, s3, H(e3), qx, qy, e3)

    # --- u1*G == u2*Q (J+J same-point path): h ≡ r*d -------------------
    u1 = 2 + secrets.randbelow(n - 2)
    R2 = scalar_mul_oracle((2 * u1) % n, curve)
    r4 = R2[0] % n
    s4 = (r4 * d * pow(u1, -1, n)) % n
    e4 = (r4 * d) % n
    yield ("u1*G == u2*Q (J+J doubling path), valid", r4, s4, H(e4),
           qx, qy, e4)
    # negation variant: u1*G == -(u2*Q) is the infinity case above.

    # --- public key edge cases -----------------------------------------
    x0, y0 = find_small_x_point(curve)
    # h=0 construction so no private key is needed for these Q
    for qlabel, Q in [(f"Q with smallest x={x0}", (x0, y0)),
                      ("Q = (x0, -y0)", (x0, (-y0) % p))]:
        kk = 2 + secrets.randbelow(n - 2)
        R = point_mul(curve, kk, Q)
        rr = R[0] % n
        ss = (rr * pow(kk, -1, n)) % n
        yield (f"h=0 constructed sig, {qlabel}", rr, ss, H(0), Q[0], Q[1], 0)
        if Q[0] + p < (1 << nbits):
            yield (f"same but Qx+p (non-canonical) must REJECT", rr, ss,
                   H(0), Q[0] + p, Q[1], 0)
        if Q[1] + p < (1 << nbits):
            yield (f"same but Qy+p (non-canonical) must REJECT", rr, ss,
                   H(0), Q[0], Q[1] + p, 0)
    yield ("Q = (0,0) infinity-ish encoding", r, s, h, 0, 0, e)
    yield ("Q = (p, p)", r, s, h, p, p, e)
    yield ("Q = (2^bits-1, 2^bits-1)", r, s, h, (1 << nbits) - 1,
           (1 << nbits) - 1, e)
    yield ("Q off-curve (qy+1)", r, s, h, qx, (qy + 1) % p, e)
    yield ("Q = (qx, -qy) i.e. -Q with Q's sig", r, s, h, qx, (-qy) % p, e)
    if qy + p < (1 << nbits):
        yield ("Q = (qx, qy + p) non-canonical Q must REJECT", r, s, h, qx,
               qy + p, e)
    # twist / off-curve point that satisfies y^2 = x^3 - 3x + b' (b' != b)
    yield ("Q on wrong curve (b+1)", r, s, h, *find_point_with_x_in_b(
        curve, c["b"] + 1), e)

    # --- keys d = 1, 2, n-1, n-2 with real signatures ----------------------
    for dd, dl in [(1, "d=1 (Q=G)"), (2, "d=2"), (n - 1, "d=n-1 (Q=-G)"),
                   (n - 2, "d=n-2")]:
        qx2, qy2 = scalar_mul_oracle(dd, curve)
        k2 = 1 + secrets.randbelow(n - 1)
        r2, s2 = sign_with_k(curve, dd, e, k2)
        yield (f"valid sig, {dl}", r2, s2, h, qx2, qy2, e)

    # --- short r / short s (leading zero bytes) ---------------------------
    for want in ("r", "s"):
        for _ in range(4000):
            k2 = 1 + secrets.randbelow(n - 1)
            r2, s2 = sign_with_k(curve, d, e, k2)
            v = r2 if want == "r" else s2
            if v < (1 << (nbits - 8)):
                yield (f"valid sig with {want} top byte 0 ({want}={v:#x})",
                       r2, s2, h, qx, qy, e)
                break
    # r with top TWO bytes zero (rarer; try harder, still cheap)
    for _ in range(200000):
        k2 = 1 + secrets.randbelow(n - 1)
        r2, s2 = sign_with_k(curve, d, e, k2)
        if r2 < (1 << (nbits - 16)):
            yield (f"valid sig with r top 2 bytes 0 (r={r2:#x})",
                   r2, s2, h, qx, qy, e)
            break
    # nonce k = 1 -> r = Gx mod n
    r2, s2 = sign_with_k(curve, d, e, 1)
    yield ("valid sig with k=1 (r = Gx mod n)", r2, s2, h, qx, qy, e)
    r2, s2 = sign_with_k(curve, d, e, n - 1)
    yield ("valid sig with k=n-1", r2, s2, h, qx, qy, e)

    # --- random hazmat-signed positives + tampered negatives -----------
    nrand = 2 if quick else 4
    for i in range(nrand):
        sk = ec.generate_private_key(c["obj"])
        pn = sk.public_key().public_numbers()
        m = secrets.token_bytes(secrets.randbelow(200))
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature)
        rr, ss = decode_dss_signature(sk.sign(m, ec.ECDSA(c["hash"])))
        hh = hfn(m).digest()
        ee = int.from_bytes(hh, "big")
        yield (f"hazmat random valid #{i}", rr, ss, hh, pn.x, pn.y, ee)
        bit = 1 << secrets.randbelow(nbits)
        which = i % 3
        if which == 0:
            yield (f"hazmat random #{i}, r bit flipped", rr ^ bit, ss, hh,
                   pn.x, pn.y, ee)
        elif which == 1:
            yield (f"hazmat random #{i}, h bit flipped", rr, ss,
                   be(ee ^ bit, nb), pn.x, pn.y, ee ^ bit)
        else:
            yield (f"hazmat random #{i}, s bit flipped", rr, ss ^ bit, hh,
                   pn.x, pn.y, ee)


def find_point_with_x_in_b(curve, bprime):
    c = CURVE[curve]
    p = c["p"]
    while True:
        x = secrets.randbelow(p)
        rhs = (pow(x, 3, p) - 3 * x + bprime) % p
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p == rhs:
            return x, y


# --------------------------------------------------------------------------
# Mutation testing of the shipped suite (no source edits: PRG bytes are
# patched in the running VICE via write_bytes and restored afterwards).
# --------------------------------------------------------------------------

def _find_qx_gate_jmp(transport, labels):
    """Locate the `jmp @ev_fail` that follows the Qx >= p fp_cmp in
    ecdsa_verify_256. Pattern: JSR fp_cmp ; BCC +3 ; JMP @ev_fail. The
    r/s/Qx/Qy compares are occurrences 1..4 after the entry point."""
    base = labels["ecdsa_verify_256"]
    code = read_bytes(transport, base, 0x400)
    fc = labels["fp_cmp"]
    pat = bytes([0x20, fc & 0xFF, fc >> 8, 0x90, 0x03, 0x4C])
    hits = []
    i = 0
    while True:
        j = code.find(pat, i)
        if j < 0:
            break
        hits.append(base + j + 5)      # address of the JMP opcode
        i = j + 1
    return hits


def mutation_phase(log, transport, labels):
    import tools.test_ecdsa_verify as T
    sec = "mutation"

    def run_suite_group(name, fn):
        p, f = fn()
        log.note(f"    suite group '{name}': {p} passed, {f} failed")
        return p, f

    entry = labels["ecdsa_verify_256"]
    orig = read_bytes(transport, entry, 2)

    # (1) verify always says VALID (clc ; rts)
    write_bytes(transport, entry, bytes([0x18, 0x60]))
    p, f = run_suite_group("p256 RFC6979 under clc;rts mutant",
                           lambda: T.run_rfc6979_tests(
                               transport, labels, "p256", T.RFC6979_P256,
                               32, "sha256"))
    log.case(sec, "suite detects verify_256 := always-VALID (clc;rts)",
             "fails>0", f"fails={f}", verdict="PASS" if f > 0 else "FAIL",
             detail={"passed": p, "failed": f})
    # (2) verify always says INVALID (sec ; rts)
    write_bytes(transport, entry, bytes([0x38, 0x60]))
    p, f = run_suite_group("p256 RFC6979 under sec;rts mutant",
                           lambda: T.run_rfc6979_tests(
                               transport, labels, "p256", T.RFC6979_P256,
                               32, "sha256"))
    log.case(sec, "suite detects verify_256 := always-INVALID (sec;rts)",
             "fails>0", f"fails={f}", verdict="PASS" if f > 0 else "FAIL",
             detail={"passed": p, "failed": f})
    write_bytes(transport, entry, orig)
    assert read_bytes(transport, entry, 2) == orig

    # (3) remove the Qx >= p range gate: does the suite's issue-#66 group
    #     notice? Then does a signature that is valid under the REDUCED
    #     key get accepted (i.e. the gate really was load-bearing)?
    hits = _find_qx_gate_jmp(transport, labels)
    log.note(f"    fp_cmp/bcc/jmp gate sites in ecdsa_verify_256: "
             f"{[hex(h) for h in hits]}")
    if len(hits) >= 4:
        qx_jmp = hits[2]
        saved = read_bytes(transport, qx_jmp, 3)
        write_bytes(transport, qx_jmp, bytes([0xEA, 0xEA, 0xEA]))
        p, f = run_suite_group("p256 issue#66 group under Qx-gate-removed",
                               lambda: T.run_q_validation_tests(
                                   transport, labels, "p256",
                                   T.RFC6979_P256, 32, "sha256"))
        log.case(sec, "suite issue#66 group detects Qx range gate removal",
                 "fails>0", f"fails={f}",
                 verdict="PASS" if f > 0 else "FAIL",
                 detail={"passed": p, "failed": f,
                         "note": "FAIL here = the suite's Q-gate cases are "
                                 "vacuous (they'd reject anyway because the "
                                 "RFC signature is invalid under the "
                                 "modified key)"})
        # constructed h=0 signature valid under reduced key
        curve = "p256"
        c = CURVE[curve]
        p_, n = c["p"], c["n"]
        x0, y0 = find_small_x_point(curve)
        kk = 2 + secrets.randbelow(n - 2)
        R = point_mul(curve, kk, (x0, y0))
        rr = R[0] % n
        ss = (rr * pow(kk, -1, n)) % n
        got, dt = c64_verify(transport, labels, curve, rr, ss, bytes(32),
                             x0 + p_, y0)
        log.case(sec, "gate-removed mutant ACCEPTS Qx+p with h=0 sig "
                 "(shows constructed case is load-bearing)",
                 0, got, dt=dt,
                 detail={"qx": hex(x0 + p_), "r": hex(rr), "s": hex(ss)})
        write_bytes(transport, qx_jmp, saved)
        got, dt = c64_verify(transport, labels, curve, rr, ss, bytes(32),
                             x0 + p_, y0)
        log.case(sec, "restored build rejects the same Qx+p case", 1, got,
                 dt=dt)
    else:
        log.note("    could not locate Qx gate; skipping mutation (3)")


TRIM_KEYS = ["baseline", "malleable", "r = n+1", "s = 2^bits-1", "r = 0",
             "s = n", "h = 0 via", "h = n (", "h = 2^bits-1 (>=",
             "h = 0 with baseline", "h=0 constructed sig, random Q",
             "Q = -G", "(Qx,Qx)", "cofactor fallback: Q.x",
             "cofactor fallback negative", "= infinity", "J+J doubling",
             "smallest x", "Qx+p", "Q = (0,0)", "Q = (p, p)", "off-curve",
             "wrong curve", "d=n-1", "r top byte 0", "k=1", "random valid #0",
             "h bit flipped", "r = n-1"]


def main():
    args = sys.argv[1:]
    curves = ["p256", "p384"]
    if "--p384-only" in args:
        curves = ["p384"]
    if "--p256-only" in args:
        curves = ["p256"]
    quick = "--quick" in args
    log = Log("ecdsa_" + "_".join(curves))
    labels = load_labels()
    mgr, inst, transport = boot(log)
    try:
        for curve in curves:
            log.note(f"=== {curve} ===")
            for tup in cases_for(curve, quick=quick):
                label, r, s, hb, qx, qy, e = tup
                if "--trim" in args and not any(k in label for k in TRIM_KEYS):
                    continue
                run_case(log, transport, labels, curve, label, r, s, hb,
                         qx, qy, e_for_py=e)
        if "--mutate" in args:
            log.note("=== mutation phase (P-256) ===")
            mutation_phase(log, transport, labels)
    finally:
        log.summary()
        shutdown(mgr, inst)


if __name__ == "__main__":
    main()
