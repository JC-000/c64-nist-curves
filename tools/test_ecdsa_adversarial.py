#!/usr/bin/env python3
"""test_ecdsa_adversarial.py -- adversarial ECDSA-verify sweep, both curves.

Ported from the 2026-08-28 hazmat audit
(.research/adversarial_audit_2026_08_28/report.md, section 4 items 1-8 and
15). Every case class there is a group here:

  1. Q gate, h=0 construction (issue #66 / audit F-2): pick k, R = k*Q0,
     r = x(R) mod n, s = r*k^-1, h = 0 -- (r, s) verifies under Q0 for ANY
     Q0 without a private key. Feed Q' = (Qx+p, y) and (Qx, Qy+p): the
     library must REJECT the non-canonical encoding. This is the one
     shape that goes RED when the Qx/Qy >= p gate is removed (the
     shipped issue-#66 group reuses an RFC signature that is invalid
     under the substituted key anyway, so it passes with the gate gone).
  2. Range-gate strictness: r, s in {n-1 (random sig), n, n+1, 2^bits-1,
     r+n (fits width; must NOT reduce), 0, 1}.
  3. h >= n end-to-end: sign with e = h mod n, feed raw h in {n, n+1,
     2^bits-1, p, random >= n}; expect VALID. Pins the fp_mod_mul_n
     precondition. Plus h and h+n (same residue) with the same signature.
  4. u1 = 0 / h = 0 constructed signature under random Q, G, -G, 2G:
     VALID; comb with a zero scalar + ec_point_add_jj with P2 = infinity.
  5. R = infinity: h = -r*d mod n -> INVALID.
  6. u1*G == u2*Q (J+J same-point -> ec_point_double tail): VALID.
  7. Cofactor fallback (@ev_cof_fallback): Q with x in [n, p), h = 0,
     (r, s) = (x-n, x-n) [u2 = 1] and the u2 = 2 lift Q' = (1/2)*Q:
     VALID; r = x-n+1: INVALID.
  8. Malleability: (r, n-s) must VERIFY (stated so nobody "fixes" it).
  15. NIST CAVP SigVer with the Result reason code ASSERTED: P -> C=0,
     F (k - ...) -> C=1, k parsed and cross-checked structurally; hazmat
     must agree with the Result column (a disagreement is a FAIL, not a
     warning). --full runs all 15/15; fast mode runs a balanced subset
     that includes one vector of every reason class present (so the
     P-384 subset always carries a "Message changed" vector).

Plus: random hazmat-signed positives with bit-flipped negatives, key
edge cases (d = 1, 2, n-1, n-2; Q = (0,0), (p,p), (W,W), off-curve, -Q,
wrong-curve b+1), short r/s (leading zero bytes), k = 1 / k = n-1.

Oracle: cryptography.hazmat (OpenSSL) plus an independent pure-int
FIPS 186-5 verifier (`py_verify`) that must agree with hazmat on every
case. The only place they are allowed to differ is the non-canonical Q
encoding, where OpenSSL reduces mod p and the library's documented
contract (FIPS 186-5 / issue #66) is REJECT; those cases carry an
explicit spec override. No expected value comes from a C64 run.

One VICE boot; all cases batched. Boot pattern = tools/test_points384.py.

Usage:
    python3 tools/test_ecdsa_adversarial.py [--seed N] [--full] [--verbose]
                                            [--strict] [--record out.jsonl]
                                            [--p256-only | --p384-only]

Exit status is non-zero on unexpected failures only; RED(known) rows are
reported but do not fail the run unless --strict is given. (No ECDSA row
is expected red today; the tag machinery is shared with the prims suite.)
"""

import hashlib
import os
import random
import sys

from c64_test_harness import read_bytes, write_bytes, jsr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit_common import (  # noqa: E402
    PROJECT_ROOT, Machine, Suite, be, build_be_struct, build_prg,
    load_labels, parse_args, warn_if_vice_running,
)

sys.path.insert(0, PROJECT_ROOT)
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: E402
    encode_dss_signature, decode_dss_signature, Prehashed)
from cryptography.exceptions import InvalidSignature  # noqa: E402

from tools.vectors import (  # noqa: E402
    P256_P, P256_N, P256_B, P256_GX, P256_GY,
    P384_P, P384_N, P384_B, P384_GX, P384_GY)
from tools.vectors.loader import (  # noqa: E402
    scalar_mul_oracle, affine_add, INFINITY, self_check)
from tools.test_ecdsa_verify import (  # noqa: E402
    load_sigver_vectors, select_cavp_subset, parse_cavp_result)

CURVE = {
    "p256": dict(p=P256_P, n=P256_N, b=P256_B, gx=P256_GX, gy=P256_GY,
                 nbytes=32, obj=ec.SECP256R1(), hash=hashes.SHA256(),
                 hfn=hashlib.sha256, struct="ecdsa_inputs_256",
                 result="ecdsa_result_256", tramp="ecdsa_verify_256_tramp",
                 timeout=900.0, sigver="tools/vectors/nist_p256_sigver.rsp",
                 section="P-256,SHA-256"),
    "p384": dict(p=P384_P, n=P384_N, b=P384_B, gx=P384_GX, gy=P384_GY,
                 nbytes=48, obj=ec.SECP384R1(), hash=hashes.SHA384(),
                 hfn=hashlib.sha384, struct="ecdsa_inputs_384",
                 result="ecdsa_result_384", tramp="ecdsa_verify_384_tramp",
                 timeout=1800.0, sigver="tools/vectors/nist_p384_sigver.rsp",
                 section="P-384,SHA-384"),
}

USAGE = __doc__


# ---------------------------------------------------------------------------
# Oracles
# ---------------------------------------------------------------------------

def hazmat_verify(curve, r, s, h_bytes, qx, qy):
    """Raw hazmat verdict with NO Python-side pre-range check.
    True / False / 'ERR:<where>:<type>' (ERR == the encoding was refused,
    which a verifier reports as INVALID)."""
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


def point_mul(curve, k, P):
    """k*P by affine double-and-add on the self-checked group law
    (hazmat only exposes k*G)."""
    n = CURVE[curve]["n"]
    k %= n
    T = INFINITY
    for i in range(k.bit_length() - 1, -1, -1):
        T = affine_add(T, T, curve)
        if (k >> i) & 1:
            T = affine_add(T, P, curve)
    return T


def py_verify(curve, r, s, e, qx, qy):
    """Independent pure-int ECDSA verify (FIPS 186-5 6.4.2). e = integer
    hash value as the verifier receives it (NOT pre-reduced)."""
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
    R = affine_add(R, point_mul(curve, u2, (qx, qy)), curve)
    if R == INFINITY:
        return False
    return (R[0] % n) == r


# ---------------------------------------------------------------------------
# Signature construction (Python ints + hazmat k*G)
# ---------------------------------------------------------------------------

def sign_with_k(curve, d, e, k):
    n = CURVE[curve]["n"]
    x, _ = scalar_mul_oracle(k, curve)
    r = x % n
    s = (pow(k, -1, n) * (e + r * d)) % n
    return r, s


def keygen(curve, rng, d=None):
    n = CURVE[curve]["n"]
    if d is None:
        d = rng.randrange(1, n)
    qx, qy = scalar_mul_oracle(d, curve)
    return d, qx, qy


def h0_signature(curve, rng, Q):
    """u1 = 0 forgery shape: (r, s) that verifies under Q with h = 0."""
    n = CURVE[curve]["n"]
    k = rng.randrange(2, n)
    R = point_mul(curve, k, Q)
    r = R[0] % n
    s = (r * pow(k, -1, n)) % n
    return r, s


def sqrt_point(curve, x, bprime=None):
    c = CURVE[curve]
    p = c["p"]
    b = c["b"] if bprime is None else bprime
    rhs = (pow(x, 3, p) - 3 * x + b) % p
    y = pow(rhs, (p + 1) // 4, p)          # p % 4 == 3 on both curves
    return y if y * y % p == rhs else None


def find_point_with_x_in(curve, rng, lo, hi, bprime=None):
    while True:
        x = rng.randrange(lo, hi)
        y = sqrt_point(curve, x, bprime)
        if y is not None:
            return x, y


def find_small_x_point(curve):
    x = 0
    while True:
        y = sqrt_point(curve, x)
        if y is not None:
            return x, y
        x += 1


# ---------------------------------------------------------------------------
# C64 driver
# ---------------------------------------------------------------------------

def c64_verify(transport, labels, curve, r, s, h_bytes, qx, qy):
    c = CURVE[curve]
    nb = c["nbytes"]
    payload = build_be_struct(r, s, int.from_bytes(h_bytes, "big"), qx, qy, nb)
    write_bytes(transport, labels[c["struct"]], payload)
    write_bytes(transport, labels[c["result"]], b"\xFF")
    jsr(transport, labels[c["tramp"]], timeout=c["timeout"])
    res = read_bytes(transport, labels[c["result"]], 1)[0]
    if res not in (0, 1):
        raise RuntimeError(f"result byte {res:#x}: trampoline did not run")
    return res


# ---------------------------------------------------------------------------
# Case model
# ---------------------------------------------------------------------------

class Case:
    """One verify call. spec: None -> expected C from hazmat; 0/1 -> the
    library's documented contract overrides hazmat (non-canonical Q)."""
    __slots__ = ("group", "label", "r", "s", "h", "qx", "qy", "e", "spec",
                 "fast")

    def __init__(self, group, label, r, s, h, qx, qy, e, spec=None,
                 fast=True):
        self.group, self.label = group, label
        self.r, self.s, self.h, self.qx, self.qy, self.e = r, s, h, qx, qy, e
        self.spec = spec
        self.fast = fast


def run_case(suite, transport, labels, curve, case):
    hz = hazmat_verify(curve, case.r, case.s, case.h, case.qx, case.qy)
    exp = 0 if hz is True else 1
    detail = {"hazmat": hz, "r": hex(case.r), "s": hex(case.s),
              "h": case.h.hex(), "qx": hex(case.qx), "qy": hex(case.qy)}
    if case.spec is not None:
        detail["spec"] = ("library contract (FIPS 186-5 / issue #66): "
                          f"C={case.spec}; hazmat said {hz!r}")
        exp = case.spec
    py = None
    if case.e is not None:
        py = py_verify(curve, case.r, case.s, case.e, case.qx, case.qy)
        detail["py_verify"] = py
        if (py is True) != (exp == 0):
            suite.case(f"ecdsa-{curve}/{case.group}",
                       case.label + " -- ORACLE DISAGREEMENT (test bug?)",
                       f"hazmat/spec C={exp}", f"py_verify={py}",
                       detail=detail)
            return
    suite.timed(f"ecdsa-{curve}/{case.group}", case.label,
                lambda: c64_verify(transport, labels, curve, case.r, case.s,
                                   case.h, case.qx, case.qy),
                exp, transport=transport, detail=detail)


# ---------------------------------------------------------------------------
# Case generators (report section 4 item numbers in the group names)
# ---------------------------------------------------------------------------

def cases_for(curve, rng, full):
    c = CURVE[curve]
    n, p, nb = c["n"], c["p"], c["nbytes"]
    nbits = nb * 8
    W = (1 << nbits) - 1
    hfn = c["hfn"]
    G = (c["gx"], c["gy"])

    def H(v):
        return be(v % (1 << nbits), nb)

    d, qx, qy = keygen(curve, rng)
    msg = rng.randbytes(40)
    h = hfn(msg).digest()
    e = int.from_bytes(h, "big")
    k = rng.randrange(1, n)
    r, s = sign_with_k(curve, d, e, k)
    out = []
    A = out.append

    # --- baseline + 8. malleability -----------------------------------
    A(Case("baseline", "valid (hazmat key, manual k)", r, s, h, qx, qy, e))
    A(Case("8-malleability", "(r, n-s) must VERIFY", r, n - s, h, qx, qy, e))

    # --- 2. range gate strictness ---------------------------------------
    for lab, r2, s2, fast in [
            ("r = n", n, s, True), ("s = n", r, n, True),
            ("r = n+1", n + 1, s, True), ("s = n+1", r, n + 1, True),
            ("r = 2^bits-1", W, s, True), ("s = 2^bits-1", r, W, True),
            ("r = 0", 0, s, True), ("s = 0", r, 0, True),
            ("r = n-1 (random sig)", n - 1, s, False),
            ("s = n-1 (random sig)", r, n - 1, False),
            ("r = 1 (random sig)", 1, s, False),
            ("s = 1 (random sig)", r, 1, False)]:
        A(Case("2-range-gate", lab, r2, s2, h, qx, qy, e, fast=fast))
    if r + n <= W:
        A(Case("2-range-gate", "r = r_valid + n (fits width; must NOT reduce)",
               r + n, s, h, qx, qy, e))
    if s + n <= W:
        A(Case("2-range-gate", "s = s_valid + n (fits width; must NOT reduce)",
               r, s + n, h, qx, qy, e))

    # --- 3. h >= n end-to-end (signature built for e2 mod n) ------------
    for lab, e2, fast in [("h = n (== 0 mod n, unreduced)", n, True),
                          ("h = n+1", n + 1, False),
                          ("h = 2^bits-1 (>= n, unreduced)", W, True),
                          ("h = p (field prime as hash)", p, False),
                          ("h = random >= n", n + rng.randrange(W + 1 - n),
                           True),
                          ("h = n-1", n - 1, False),
                          ("h = 1", 1, False),
                          ("h = 2^(bits-1) (top bit only)", 1 << (nbits - 1),
                           False)]:
        k2 = rng.randrange(1, n)
        r2, s2 = sign_with_k(curve, d, e2 % n, k2)
        A(Case("3-h-ge-n", lab, r2, s2, H(e2), qx, qy, e2, fast=fast))
    A(Case("3-h-ge-n", "h = 2^bits-1 with baseline sig (must reject)", r, s,
           H(W), qx, qy, W))
    if e + n <= W:
        A(Case("3-h-ge-n", "h + n (same residue as valid h, baseline sig)",
               r, s, H(e + n), qx, qy, e + n))

    # --- 4. u1 = 0 / h = 0 -----------------------------------------------
    k2 = rng.randrange(1, n)
    r2, s2 = sign_with_k(curve, d, 0, k2)
    A(Case("4-u1-zero", "h = 0 via signing (u1 = 0 path)", r2, s2, H(0),
           qx, qy, 0))
    A(Case("4-u1-zero", "h = 0 with baseline sig (must reject)", r, s, H(0),
           qx, qy, 0))
    for qlabel, Q, fast in [("random Q", (qx, qy), True),
                            ("Q = G", G, False),
                            ("Q = -G", (G[0], (-G[1]) % p), True),
                            ("Q = 2G", affine_add(G, G, curve), False)]:
        rr, ss = h0_signature(curve, rng, Q)
        A(Case("4-u1-zero", f"h=0 constructed sig, {qlabel}", rr, ss, H(0),
               Q[0], Q[1], 0, fast=fast))
    if qx < n:
        A(Case("4-u1-zero", "h=0, (r,s)=(Qx,Qx): u2=1, R=Q, x(R)=r", qx, qx,
               H(0), qx, qy, 0, fast=False))

    # --- 1. Q gate under the h=0 construction (RED when gate removed) ---
    x0, y0 = find_small_x_point(curve)
    rr, ss = h0_signature(curve, rng, (x0, y0))
    A(Case("1-q-gate", f"h=0 sig under canonical Q0=(x={x0}, y0) VALID",
           rr, ss, H(0), x0, y0, 0))
    assert x0 + p <= W
    A(Case("1-q-gate", "same sig, Qx+p (non-canonical) must REJECT",
           rr, ss, H(0), x0 + p, y0, 0, spec=1))
    if y0 + p <= W:
        A(Case("1-q-gate", "same sig, Qy+p (non-canonical) must REJECT",
               rr, ss, H(0), x0, y0 + p, 0, spec=1))
    else:
        # y0 + p does not fit the width for this x0; search a point whose
        # y is small enough (rare -- only in --full, bounded search).
        found = None
        for x in range(1, 4096):
            y = sqrt_point(curve, x)
            if y is not None and min(y, p - y) + p <= W:
                found = (x, min(y, p - y))
                break
        if found and full:
            rr2, ss2 = h0_signature(curve, rng, found)
            A(Case("1-q-gate", f"h=0 sig, Qy+p (x={found[0]}) must REJECT",
                   rr2, ss2, H(0), found[0], found[1] + p, 0, spec=1,
                   fast=False))
    A(Case("1-q-gate", "Q0 = (x0, -y0) VALID under its own h=0 sig",
           *h0_signature(curve, rng, (x0, (-y0) % p)), H(0), x0, (-y0) % p,
           0, fast=False))
    if qy + p <= W:
        A(Case("1-q-gate", "baseline sig, Qy+p must REJECT", r, s, h, qx,
               qy + p, e, spec=1))

    # --- 7. cofactor fallback --------------------------------------------
    xr, yr = find_point_with_x_in(curve, rng, n, p)
    rr = xr - n
    assert 1 <= rr < n
    A(Case("7-cofactor", "Q.x in [n,p), r = Qx-n, s = r, h=0 (u2=1) VALID",
           rr, rr, H(0), xr, yr, 0))
    A(Case("7-cofactor", "negative: r = Qx-n+1 INVALID", rr + 1, rr, H(0),
           xr, yr, 0))
    half = pow(2, -1, n)
    Qh = point_mul(curve, half, (xr, yr))
    A(Case("7-cofactor", "u2=2 lift: Q=(1/2)R, r=Qx(R)-n, s=r/2, h=0 VALID",
           rr, (rr * half) % n, H(0), Qh[0], Qh[1], 0))

    # --- 5. R = infinity --------------------------------------------------
    r3 = rng.randrange(1, n)
    s3 = rng.randrange(1, n)
    e3 = (-r3 * d) % n
    A(Case("5-R-infinity", "u1*G + u2*Q = infinity (h = -r*d mod n) INVALID",
           r3, s3, H(e3), qx, qy, e3))

    # --- 6. u1*G == u2*Q --------------------------------------------------
    u1 = rng.randrange(2, n)
    R2 = scalar_mul_oracle((2 * u1) % n, curve)
    r4 = R2[0] % n
    s4 = (r4 * d * pow(u1, -1, n)) % n
    e4 = (r4 * d) % n
    A(Case("6-same-point", "u1*G == u2*Q (J+J doubling path) VALID",
           r4, s4, H(e4), qx, qy, e4))

    # --- public key edge cases (all gate rejects; 0 s each) ---------------
    for lab, Qx2, Qy2 in [("Q = (0,0)", 0, 0), ("Q = (p, p)", p, p),
                          ("Q = (2^bits-1, 2^bits-1)", W, W),
                          ("Q off-curve (qy+1)", qx, (qy + 1) % p),
                          ("Q = (qx, -qy) i.e. -Q with Q's sig", qx,
                           (-qy) % p)]:
        A(Case("q-edge", lab, r, s, h, Qx2, Qy2, e,
               fast=(lab != "Q = (qx, -qy) i.e. -Q with Q's sig")))
    xb, yb = find_point_with_x_in(curve, rng, 0, p, bprime=c["b"] + 1)
    A(Case("q-edge", "Q on wrong curve (b+1)", r, s, h, xb, yb, e))

    # --- key edge cases with real signatures ------------------------------
    for dd, dl, fast in [(1, "d=1 (Q=G)", False), (2, "d=2", False),
                         (n - 1, "d=n-1 (Q=-G)", True),
                         (n - 2, "d=n-2", False)]:
        qx2, qy2 = scalar_mul_oracle(dd, curve)
        k2 = rng.randrange(1, n)
        r2, s2 = sign_with_k(curve, dd, e, k2)
        A(Case("key-edge", f"valid sig, {dl}", r2, s2, h, qx2, qy2, e,
               fast=fast))

    # --- short r / s, k = 1, k = n-1 ---------------------------------------
    for want in ("r", "s"):
        for _ in range(4000):
            k2 = rng.randrange(1, n)
            r2, s2 = sign_with_k(curve, d, e, k2)
            v = r2 if want == "r" else s2
            if v < (1 << (nbits - 8)):
                A(Case("short-rs", f"valid sig with {want} top byte 0 "
                       f"({want}={v:#x})", r2, s2, h, qx, qy, e,
                       fast=(want == "r")))
                break
    r2, s2 = sign_with_k(curve, d, e, 1)
    A(Case("short-rs", "valid sig with k=1 (r = Gx mod n)", r2, s2, h, qx,
           qy, e))
    r2, s2 = sign_with_k(curve, d, e, n - 1)
    A(Case("short-rs", "valid sig with k=n-1", r2, s2, h, qx, qy, e,
           fast=False))

    # --- random hazmat-signed positives + tampered negatives --------------
    nrand = 4 if full else 1
    for i in range(nrand):
        sk = ec.generate_private_key(c["obj"])
        pn = sk.public_key().public_numbers()
        m = rng.randbytes(rng.randrange(200))
        rr, ss = decode_dss_signature(sk.sign(m, ec.ECDSA(c["hash"])))
        hh = hfn(m).digest()
        ee = int.from_bytes(hh, "big")
        A(Case("random", f"hazmat random valid #{i}", rr, ss, hh, pn.x, pn.y,
               ee))
        bit = 1 << rng.randrange(nbits)
        which = i % 3
        if which == 0:
            A(Case("random", f"hazmat random #{i}, r bit flipped", rr ^ bit,
                   ss, hh, pn.x, pn.y, ee))
        elif which == 1:
            A(Case("random", f"hazmat random #{i}, h bit flipped", rr, ss,
                   be(ee ^ bit, nb), pn.x, pn.y, ee ^ bit))
        else:
            A(Case("random", f"hazmat random #{i}, s bit flipped", rr,
                   ss ^ bit, hh, pn.x, pn.y, ee))
    return out


# ---------------------------------------------------------------------------
# 15. NIST CAVP SigVer with reason codes asserted
# ---------------------------------------------------------------------------

def run_cavp(suite, transport, labels, curve, full):
    c = CURVE[curve]
    p, n, hfn = c["p"], c["n"], c["hfn"]
    path = os.path.join(PROJECT_ROOT, c["sigver"])
    vectors = load_sigver_vectors(path, c["section"])
    if not vectors:
        suite.case(f"cavp-{curve}", f"parse {path}", ">0 vectors", 0)
        return
    subset = select_cavp_subset(vectors, None if full else 5)
    classes = sorted({parse_cavp_result(v["raw_result"])[0]
                      for v in vectors})
    have = sorted({parse_cavp_result(v["raw_result"])[0] for v in subset})
    suite.case(f"cavp-{curve}", "subset covers every Result class present",
               classes, have)
    for i, v in enumerate(subset):
        code, reason = parse_cavp_result(v["raw_result"])
        h = hfn(v["Msg"]).digest()
        exp_from_kat = 0 if code == 0 else 1
        hz = hazmat_verify(curve, v["R"], v["S"], h, v["Qx"], v["Qy"])
        exp_from_hz = 0 if hz is True else 1
        detail = {"result": v["raw_result"], "code": code, "hazmat": hz}
        if exp_from_kat != exp_from_hz:
            suite.case(f"cavp-{curve}", f"CAVP[{i}] {v['raw_result']}: "
                       "hazmat agrees with Result column",
                       exp_from_kat, exp_from_hz, detail=detail)
            continue
        # Structural cross-check of the modification code: every F vector
        # still carries a canonical on-curve Q and in-range r, s (the CAVP
        # modifications are value substitutions, not encoding faults), so
        # a C=1 here must come from the signature equation, not a gate.
        on_curve = (v["Qy"] ** 2 - (v["Qx"] ** 3 - 3 * v["Qx"] + c["b"])) \
            % p == 0 and v["Qx"] < p and v["Qy"] < p
        in_range = 1 <= v["R"] < n and 1 <= v["S"] < n
        suite.case(f"cavp-{curve}", f"CAVP[{i}] {v['raw_result']}: Q on-curve"
                   " and r,s in range (reason is the signature equation)",
                   (True, True), (on_curve, in_range), detail=detail)
        suite.timed(f"cavp-{curve}",
                    f"CAVP[{i}] Result={v['raw_result']} -> C={exp_from_kat}"
                    f" ({reason})",
                    lambda: c64_verify(transport, labels, curve, v["R"],
                                       v["S"], h, v["Qx"], v["Qy"]),
                    exp_from_kat, transport=transport, detail=detail)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    opts = parse_args(sys.argv[1:], USAGE)
    warn_if_vice_running()
    os.chdir(PROJECT_ROOT)
    curves = ["p256", "p384"]
    if "--p384-only" in opts["extra"]:
        curves = ["p384"]
    if "--p256-only" in opts["extra"]:
        curves = ["p256"]
    rng = random.Random(opts["seed"])
    mode = "full" if opts["full"] else "fast"
    print(f"Mode: {mode}")
    print(f"Random seed: {opts['seed']} (reproduce with --seed {opts['seed']})")

    for cv in curves:
        self_check(rng, cv, 2)
    print("  affine group law self-check OK (vs cryptography oracle)")

    build_prg()
    labels = load_labels([
        "ecdsa_verify_256_tramp", "ecdsa_verify_384_tramp",
        "ecdsa_inputs_256", "ecdsa_inputs_384",
        "ecdsa_result_256", "ecdsa_result_384"])

    plan = {cv: [k for k in cases_for(cv, rng, opts["full"])
                 if opts["full"] or k.fast] for cv in curves}
    for cv in curves:
        print(f"  {cv}: {len(plan[cv])} constructed cases")

    suite = Suite("ecdsa-adversarial", strict=opts["strict"],
                  record=opts["record"], verbose=opts["verbose"])
    try:
        with Machine() as m:
            transport = m.transport
            for cv in curves:
                suite.note(f"\n--- {cv}: constructed cases ---")
                for case in plan[cv]:
                    run_case(suite, transport, labels, cv, case)
                suite.note(f"\n--- {cv}: NIST CAVP SigVer (reason codes "
                           f"asserted) ---")
                run_cavp(suite, transport, labels, cv, opts["full"])
    except Exception as e:
        suite.case("harness", "run to completion", "completed",
                   f"aborted: {e!r}")
    ok = suite.summary(seed=opts["seed"], mode=mode)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
