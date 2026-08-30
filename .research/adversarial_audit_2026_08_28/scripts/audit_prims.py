#!/usr/bin/env python3.13
"""Adversarial sweep of field / point / SHA-384 primitives. One VICE boot.

Expected values: Python ints (+ - * % pow), hashlib, and hazmat k*G via
tools.vectors.loader.scalar_mul_oracle (self-checked affine law for k*P).
"""
import hashlib
import secrets
import sys
import time

from audit_common import (Log, boot, shutdown, load_labels, le, be, from_le,
                          set_ptr, flags_of, read_bytes, write_bytes, jsr,
                          SCALAR_BUF, PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)
from tools.vectors import (P256_P, P256_N, P256_B, P256_GX, P256_GY,
                           P384_P, P384_N, P384_B, P384_GX, P384_GY)
from tools.vectors.loader import (scalar_mul_oracle, affine_add, affine_neg,
                                  jacobian_to_affine, INFINITY, self_check)
import random

C = {
    "p256": dict(p=P256_P, n=P256_N, b=P256_B, G=(P256_GX, P256_GY), nb=32,
                 tmp1="fp_tmp1", tmp2="fp_tmp2", tmp3="fp_tmp3", r0="fp_r0",
                 wide="fp_wide", modp="ec_p256", modn="ec_n256",
                 mod_add="fp_mod_add", mod_sub="fp_mod_sub",
                 mod_mul="fp_mod_mul", mod_sqr="fp_mod_sqr",
                 mod_reduce="fp_mod_reduce256", mod_mul_n="fp_mod_mul_n",
                 mod_inv="fp_mod_inv", is_zero="fp_is_zero", cmp="fp_cmp",
                 p1="ec_p1", p2="ec_p2", p3="ec_p3", bx="ec_base_x",
                 by="ec_base_y", dbl="ec_point_double", add="ec_point_add",
                 addjj="ec_point_add_jj", smul="ec_scalar_mul",
                 smulv="ec_scalar_mul_var", j2a="ec_jacobian_to_affine"),
    "p384": dict(p=P384_P, n=P384_N, b=P384_B, G=(P384_GX, P384_GY), nb=48,
                 tmp1="fp384_tmp1", tmp2="fp384_tmp2", tmp3="fp384_tmp3",
                 r0="fp384_r0", wide="fp384_wide", modp="ec_p384",
                 modn="ec_n384", mod_add="fp_mod_add_384",
                 mod_sub="fp_mod_sub_384", mod_mul="fp_mod_mul_384",
                 mod_sqr="fp_mod_sqr_384", mod_reduce="fp_mod_reduce384",
                 mod_mul_n="fp_mod_mul_n_384", mod_inv="fp_mod_inv_384",
                 is_zero="fp_is_zero_384", cmp="fp_cmp_384",
                 p1="ec384_p1", p2="ec384_p2", p3="ec384_p3",
                 bx="ec_base384_x", by="ec_base384_y",
                 dbl="ec_point_double_384", add="ec_point_add_384",
                 addjj="ec_point_add_jj_384", smul="ec_scalar_mul_384",
                 smulv="ec_scalar_mul_var_384",
                 j2a="ec_jacobian_to_affine_384"),
}


class Drv:
    def __init__(self, transport, labels, curve, log):
        self.t, self.L, self.c, self.log = transport, labels, C[curve], log
        self.curve = curve
        self.nb = self.c["nb"]

    # -- field helpers -------------------------------------------------
    def wfe(self, lab, v, n=None):
        write_bytes(self.t, self.L[lab], le(v, n or self.nb))

    def rfe(self, lab, n=None):
        return from_le(read_bytes(self.t, self.L[lab], n or self.nb))

    def ptrs(self, src1=None, src2=None, dst=None, misc=None):
        if src1: set_ptr(self.t, self.L["fp_src1"], self.L[src1])
        if src2: set_ptr(self.t, self.L["fp_src2"], self.L[src2])
        if dst: set_ptr(self.t, self.L["fp_dst"], self.L[dst])
        if misc: set_ptr(self.t, self.L["fp_misc"], self.L[misc])

    def modp(self):
        self.ptrs(misc=self.c["modp"])

    def modn(self):
        self.ptrs(misc=self.c["modn"])

    def binop(self, routine, a, b, dst_is_r0=False, timeout=240.0):
        c = self.c
        self.wfe(c["tmp1"], a)
        self.wfe(c["tmp2"], b)
        self.wfe(c["tmp3"], 0xDEADBEEF)
        self.ptrs(src1=c["tmp1"], src2=c["tmp2"], dst=c["tmp3"])
        jsr(self.t, self.L[c[routine]], timeout=timeout)
        return self.rfe(c["r0"] if dst_is_r0 else c["tmp3"])

    def unop_r0(self, routine, a, timeout=900.0):
        c = self.c
        self.wfe(c["tmp1"], a)
        self.wfe(c["r0"], 0xDEADBEEF)
        self.ptrs(src1=c["tmp1"], dst=c["tmp3"])
        jsr(self.t, self.L[c[routine]], timeout=timeout)
        return self.rfe(c["r0"])

    def reduce(self, wide, timeout=60.0):
        c = self.c
        write_bytes(self.t, self.L[c["wide"]], le(wide, 2 * self.nb))
        self.wfe(c["r0"], 0xDEADBEEF)
        jsr(self.t, self.L[c["mod_reduce"]], timeout=timeout)
        return self.rfe(c["r0"])

    def is_zero(self, a):
        c = self.c
        self.wfe(c["tmp1"], a)
        self.ptrs(src1=c["tmp1"])
        regs = jsr(self.t, self.L[c["is_zero"]], timeout=10.0)
        return regs.get("A"), flags_of(regs)

    def cmp(self, a, b):
        c = self.c
        self.wfe(c["tmp1"], a)
        self.wfe(c["tmp2"], b)
        self.ptrs(src1=c["tmp1"], src2=c["tmp2"])
        regs = jsr(self.t, self.L[c["cmp"]], timeout=10.0)
        return flags_of(regs), regs

    # -- point helpers --------------------------------------------------
    def wjac(self, lab, x, y, z):
        a = self.L[lab]
        write_bytes(self.t, a, le(x, self.nb) + le(y, self.nb) + le(z, self.nb))

    def waff(self, lab, x, y):
        a = self.L[lab]
        write_bytes(self.t, a, le(x, self.nb) + le(y, self.nb))

    def rjac(self, lab):
        d = read_bytes(self.t, self.L[lab], 3 * self.nb)
        nb = self.nb
        return (from_le(d[:nb]), from_le(d[nb:2 * nb]), from_le(d[2 * nb:]))

    def raff(self, lab):
        return jacobian_to_affine(*self.rjac(lab), self.curve)

    def dbl(self, x, y, z=1, timeout=600.0):
        self.wjac(self.c["p1"], x, y, z)
        write_bytes(self.t, self.L[self.c["p3"]], b"\xA5" * (3 * self.nb))
        jsr(self.t, self.L[self.c["dbl"]], timeout=timeout)
        return self.rjac(self.c["p3"])

    def add(self, p1, p2aff, timeout=1200.0):
        self.wjac(self.c["p1"], *p1)
        self.waff(self.c["p2"], *p2aff)
        write_bytes(self.t, self.L[self.c["p3"]], b"\xA5" * (3 * self.nb))
        jsr(self.t, self.L[self.c["add"]], timeout=timeout)
        return self.rjac(self.c["p3"])

    def addjj(self, p1, p2, timeout=1200.0):
        self.wjac(self.c["p1"], *p1)
        self.wjac(self.c["p2"], *p2)
        write_bytes(self.t, self.L[self.c["p3"]], b"\xA5" * (3 * self.nb))
        jsr(self.t, self.L[self.c["addjj"]], timeout=timeout)
        return self.rjac(self.c["p3"])

    def smul(self, k, timeout=3600.0):
        write_bytes(self.t, SCALAR_BUF, be(k, self.nb))
        set_ptr(self.t, self.L["ec_scalar_ptr"], SCALAR_BUF)
        write_bytes(self.t, self.L[self.c["p3"]], b"\xA5" * (3 * self.nb))
        jsr(self.t, self.L[self.c["smul"]], timeout=timeout)
        return self.rjac(self.c["p3"])

    def smulv(self, k, bx, by, timeout=7200.0):
        write_bytes(self.t, SCALAR_BUF, be(k, self.nb))
        set_ptr(self.t, self.L["ec_scalar_ptr"], SCALAR_BUF)
        self.wfe(self.c["bx"], bx)
        self.wfe(self.c["by"], by)
        write_bytes(self.t, self.L[self.c["p3"]], b"\xA5" * (3 * self.nb))
        jsr(self.t, self.L[self.c["smulv"]], timeout=timeout)
        return self.rjac(self.c["p3"])


def lift(P, z, p):
    """Affine -> Jacobian with the given Z."""
    x, y = P
    return ((x * z * z) % p, (y * z * z * z) % p, z)


def kP(curve, k, P):
    n = C[curve]["n"]
    k %= n
    T = INFINITY
    for i in range(k.bit_length() - 1, -1, -1):
        T = affine_add(T, T, curve)
        if (k >> i) & 1:
            T = affine_add(T, P, curve)
    return T


def kG(curve, k):
    k %= C[curve]["n"]
    return INFINITY if k == 0 else scalar_mul_oracle(k, curve)


# ==========================================================================

def field_section(D, log, curve):
    c = D.c
    p, n, nb = c["p"], c["n"], c["nb"]
    W = (1 << (8 * nb)) - 1
    sec = f"field-{curve}"
    D.modp()
    t0 = time.time()

    # --- mod_add / mod_sub with reduced AND non-reduced inputs ---------
    add_cases = [("(p-1)+(p-1)", p - 1, p - 1), ("(p-1)+1", p - 1, 1),
                 ("0+0", 0, 0), ("a+a", 12345678901234567890, 12345678901234567890),
                 ("NONRED p+0", p, 0), ("NONRED p+1", p, 1),
                 ("NONRED (p+1)+(p-1)", p + 1, p - 1),
                 ("NONRED W+W", W, W), ("NONRED W+0", W, 0),
                 ("NONRED W+1", W, 1)]
    for lab, a, b in add_cases:
        got = D.binop("mod_add", a, b)
        exp = (a + b) % p
        v = None if not lab.startswith("NONRED") else ("PASS" if got == exp else "INFO")
        log.case(sec, f"mod_add {lab}", exp, got, verdict=v,
                 detail=None if got == exp else {"a": hex(a), "b": hex(b),
                                                 "got-exp": hex(got - exp)})
    sub_cases = [("0-(p-1)", 0, p - 1), ("0-1", 0, 1), ("1-1", 1, 1),
                 ("(p-1)-(p-1)", p - 1, p - 1),
                 ("NONRED 1-W", 1, W), ("NONRED p-0", p, 0),
                 ("NONRED (p+1)-1", p + 1, 1), ("NONRED W-W", W, W),
                 ("NONRED 0-W", 0, W), ("NONRED 0-p", 0, p)]
    for lab, a, b in sub_cases:
        got = D.binop("mod_sub", a, b)
        exp = (a - b) % p
        v = None if not lab.startswith("NONRED") else ("PASS" if got == exp else "INFO")
        log.case(sec, f"mod_sub {lab}", exp, got, verdict=v,
                 detail=None if got == exp else {"a": hex(a), "b": hex(b)})

    # --- Solinas reduction worst cases (direct wide input) --------------
    limb = (1 << 32) - 1
    lim_cases = [("2^(2w)-1", (1 << (16 * nb)) - 1),
                 ("(p-1)^2", (p - 1) ** 2), ("p*(W)", p * W),
                 ("W*W", W * W), ("p*p", p * p), ("p<<(8nb)", p << (8 * nb)),
                 ("W<<(8nb)", W << (8 * nb)), ("p", p), ("p+1", p + 1),
                 ("2p", 2 * p), ("W", W), ("p-1", p - 1)]
    for i in range(2 * nb // 4):
        lim_cases.append((f"limb{i} all-ones", limb << (32 * i)))
    for i in range(nb // 4, 2 * nb // 4):
        lim_cases.append((f"high limbs {i}.. all ones",
                          ((1 << (16 * nb)) - 1) ^ ((1 << (32 * i)) - 1)))
    for i in range(4):
        lim_cases.append((f"rand wide #{i}", secrets.randbits(16 * nb)))
    for lab, w in lim_cases:
        got = D.reduce(w)
        exp = w % p
        log.case(sec, f"mod_reduce {lab}", exp, got,
                 detail=None if got == exp else {"w": hex(w), "got-exp": hex(got - exp)})

    # --- mod_mul / mod_sqr ---------------------------------------------
    r1 = secrets.randbelow(p)
    r2 = secrets.randbelow(p)
    mul_cases = [("(p-1)*(p-1)", p - 1, p - 1), ("(p-1)*1", p - 1, 1),
                 ("0*(p-1)", 0, p - 1), ("rand*rand", r1, r2),
                 ("rand*(p-1)", r1, p - 1),
                 ("NONRED p*1", p, 1), ("NONRED (p+1)*1", p + 1, 1),
                 ("NONRED W*W", W, W), ("NONRED W*1", W, 1),
                 ("NONRED p*p", p, p), ("NONRED W*(p-1)", W, p - 1)]
    for lab, a, b in mul_cases:
        got = D.binop("mod_mul", a, b, dst_is_r0=True)
        exp = (a * b) % p
        v = None if not lab.startswith("NONRED") else ("PASS" if got == exp else "INFO")
        log.case(sec, f"mod_mul {lab}", exp, got, verdict=v,
                 detail=None if got == exp else {"a": hex(a), "b": hex(b)})
    for lab, a in [("rand", r1), ("p-1", p - 1), ("2^(8nb-1)", 1 << (8 * nb - 1)),
                   ("NONRED W", W), ("NONRED p", p)]:
        sq = D.unop_r0("mod_sqr", a, timeout=240.0)
        mm = D.binop("mod_mul", a, a, dst_is_r0=True)
        exp = (a * a) % p
        v = None if not lab.startswith("NONRED") else ("PASS" if sq == exp else "INFO")
        log.case(sec, f"mod_sqr {lab}", exp, sq, verdict=v)
        log.case(sec, f"mod_sqr vs mod_mul consistency {lab}", mm, sq)

    # --- mod_mul_n (group order) ----------------------------------------
    wv = secrets.randbelow(n)
    muln_cases = [("(n-1)*(n-1)", n - 1, n - 1),
                  ("h=W * w<n (documented ok)", W, wv),
                  ("h=n * w<n", n, wv), ("h=n+1 * w<n", n + 1, wv),
                  ("h=p * w<n", p, wv), ("w<n * h=W (swapped)", wv, W),
                  ("h=W * (n-1)", W, n - 1), ("n*1", n, 1), ("1*n", 1, n),
                  ("n*0", n, 0), ("n * (n-1)", n, n - 1),
                  ("UNDOC both>=n: n*n", n, n),
                  ("UNDOC both>=n: W*W", W, W),
                  ("UNDOC both>=n: (n+1)*(n+1)", n + 1, n + 1),
                  ("UNDOC both>=n: W*(n+1)", W, n + 1)]
    for lab, a, b in muln_cases:
        got = D.binop("mod_mul_n", a, b, timeout=300.0)
        exp = (a * b) % n
        v = None if not lab.startswith("UNDOC") else ("PASS" if got == exp else "INFO")
        log.case(sec, f"mod_mul_n {lab}", exp, got, verdict=v,
                 detail=None if got == exp else {"a": hex(a), "b": hex(b)})

    # --- mod_inv (hangs deferred to the end of the run) ------------------
    D.modp()
    for lab, a in [("p-1", p - 1), ("2", 2), ("2^(8nb-1)", 1 << (8 * nb - 1)),
                   ("rand", r1)]:
        got = D.unop_r0("mod_inv", a, timeout=900.0)
        exp = pow(a, -1, p)
        log.case(sec, f"mod_inv {lab}", exp, got)
    D.modn()
    got = D.unop_r0("mod_inv", n - 1, timeout=900.0)
    log.case(sec, "mod_inv mod n: (n-1)^-1", pow(n - 1, -1, n), got)
    got = D.unop_r0("mod_inv", wv, timeout=900.0)
    log.case(sec, "mod_inv mod n: rand^-1", pow(wv, -1, n), got)
    D.modp()

    # --- is_zero / cmp flag semantics -----------------------------------
    for lab, a, expz in [("0", 0, True), ("1", 1, False),
                         ("2^(8nb-1)", 1 << (8 * nb - 1), False),
                         ("1<<8", 1 << 8, False), ("W", W, False)]:
        A_, (cf, zf) = D.is_zero(a)
        log.case(sec, f"is_zero({lab}) -> Z flag", 1 if expz else 0, zf,
                 detail={"A": A_, "C": cf})
    for lab, a, b in [("a<b", 5, 6), ("a==b", 7, 7), ("a>b", 8, 7),
                      ("p-1 vs p", p - 1, p), ("p vs p", p, p),
                      ("p+1 vs p", p + 1, p), ("W vs 0", W, 0),
                      ("0 vs W", 0, W), ("n vs n", n, n),
                      ("n-1 vs n", n - 1, n), ("n+1 vs n", n + 1, n),
                      ("hi-byte-only 1<<(8nb-8) vs 1", 1 << (8 * nb - 8), 1),
                      ("1 vs 1<<(8nb-8)", 1, 1 << (8 * nb - 8))]:
        (cf, zf), regs = D.cmp(a, b)
        exp = 1 if a >= b else 0
        log.case(sec, f"cmp {lab} -> C", exp, cf, detail={"Z": zf})
        if a == b:
            log.case(sec, f"cmp {lab}: documented 'Z=1 if equal'", 1, zf,
                     verdict="PASS" if zf == 1 else "INFO")
    log.note(f"  field section {curve} took {time.time() - t0:.0f}s")


def point_section(D, log, curve, n_smul, n_smulv):
    c = D.c
    p, n, nb = c["p"], c["n"], c["nb"]
    G = c["G"]
    sec = f"point-{curve}"
    D.modp()
    t0 = time.time()
    P = kG(curve, 3 + secrets.randbelow(n - 4))
    negP = affine_neg(P, curve)
    twoP = affine_add(P, P, curve)
    z = 2 + secrets.randbelow(p - 3)

    # --- mixed add degenerate cases ---------------------------------------
    for lab, p1, p2, exp in [
            ("P(Z=1) + P  (must double)", (P[0], P[1], 1), P, twoP),
            ("lift(P,z) + P  (H==0 with Z!=1)", lift(P, z, p), P, twoP),
            ("P + (-P) -> infinity", (P[0], P[1], 1), negP, INFINITY),
            ("lift(P,z) + (-P) -> infinity", lift(P, z, p), negP, INFINITY),
            ("inf(Z=0,X=Y=garbage) + P -> P", (12345, 6789, 0), P, P),
            ("inf(all zero) + P -> P", (0, 0, 0), P, P),
            ("lift(P,z) + Q random", lift(P, z, p), G, affine_add(P, G, curve)),
            ("P + G", (P[0], P[1], 1), G, affine_add(P, G, curve)),
            ("G + G (double via add)", (G[0], G[1], 1), G, affine_add(G, G, curve))]:
        jac = D.add(p1, p2)
        got = jacobian_to_affine(*jac, curve)
        log.case(sec, f"point_add {lab}", exp, got,
                 detail=None if got == exp else {"jac": [hex(v) for v in jac]})
        if exp == INFINITY:
            log.case(sec, f"point_add {lab}: Z==0 encoding", 0, jac[2],
                     verdict="PASS" if jac[2] == 0 else "INFO")

    # --- double ----------------------------------------------------------
    for lab, pt, exp in [("P Z=1", (P[0], P[1], 1), twoP),
                         ("lift(P,z)", lift(P, z, p), twoP),
                         ("Z=0 garbage -> infinity", (99, 77, 0), INFINITY),
                         ("Z=0 all zero -> infinity", (0, 0, 0), INFINITY),
                         ("X=Y=0,Z=1 (off-curve junk)", (0, 0, 1), None)]:
        jac = D.dbl(*pt)
        got = jacobian_to_affine(*jac, curve)
        if exp is None:
            log.case(sec, f"point_double {lab} (behaviour only)", "n/a",
                     [hex(v) for v in jac], verdict="INFO")
        else:
            log.case(sec, f"point_double {lab}", exp, got)

    # --- J+J -------------------------------------------------------------
    z2 = 2 + secrets.randbelow(p - 3)
    for lab, p1, p2, exp in [
            ("lift(P,z)+lift(P,z2) same point -> 2P", lift(P, z, p), lift(P, z2, p), twoP),
            ("lift(P,z)+lift(-P,z2) -> inf", lift(P, z, p), lift(negP, z2, p), INFINITY),
            ("lift(P,z)+lift(G,z2)", lift(P, z, p), lift(G, z2, p), affine_add(P, G, curve)),
            ("P + inf(Z=0 garbage) -> P", (P[0], P[1], 1), (5, 6, 0), P),
            ("inf(Z=0 garbage) + lift(P,z) -> P", (5, 6, 0), lift(P, z, p), P)]:
        jac = D.addjj(p1, p2)
        got = jacobian_to_affine(*jac, curve)
        log.case(sec, f"point_add_jj {lab}", exp, got,
                 detail=None if got == exp else {"jac": [hex(v) for v in jac]})

    # --- scalar_mul_var (variable base) -----------------------------------
    W = (1 << (8 * nb)) - 1
    sv_cases = [("k=n+1 -> P", n + 1), ("k=n+2 -> 2P (mid-ladder R==P mixed add)", n + 2),
                ("k=2^(8nb)-1", W), ("k=2^(8nb-1) (top bit only)", 1 << (8 * nb - 1)),
                ("k=(n-1)/2", (n - 1) // 2), ("k=(n+1)/2", (n + 1) // 2),
                ("k=n-2", n - 2)]
    sv_cases = sv_cases[:n_smulv]
    for lab, k in sv_cases:
        exp = kP(curve, k, P)
        t1 = time.time()
        jac = D.smulv(k, P[0], P[1])
        got = jacobian_to_affine(*jac, curve)
        log.case(sec, f"scalar_mul_var {lab}", exp, got, dt=time.time() - t1,
                 detail=None if got == exp else {"k": hex(k), "jac": [hex(v) for v in jac]})
    # base at "infinity" (0,0) is not encodable; base off-curve junk: record
    jac = D.smulv(2, 0, 0)
    log.case(sec, "scalar_mul_var k=2, base=(0,0) off-curve (behaviour)", "n/a",
             [hex(v) for v in jac], verdict="INFO")
    # base = -G with k = n-1 -> G
    jac = D.smulv(n - 1, G[0], (-G[1]) % p)
    log.case(sec, "scalar_mul_var k=n-1, base=-G -> G", G,
             jacobian_to_affine(*jac, curve))

    # --- fixed-base comb --------------------------------------------------
    limbs = 8 * nb // 32
    sm_cases = [("k=0 -> inf", 0), ("k=1 -> G", 1), ("k=n -> inf", n),
                ("k=n-1 -> -G", n - 1), ("k=n+1 -> G", n + 1),
                ("k=2^(8nb)-1", W), ("k=2^(8nb-1)", 1 << (8 * nb - 1)),
                ("k=all sub-scalars K_i=1 (idx 255 at col 0)",
                 sum(1 << (32 * i) for i in range(limbs))),
                ("k=all sub-scalars top bit (idx 255 at col 31)",
                 sum(1 << (32 * i + 31) for i in range(limbs))),
                ("k=2^32-1 (K0 all ones)", (1 << 32) - 1),
                ("k=(2^32-1)<<(8nb-32) (top limb all ones)", ((1 << 32) - 1) << (8 * nb - 32)),
                ("k=2 -> 2G", 2), ("k=2^32 -> A2", 1 << 32)]
    sm_cases = sm_cases[:n_smul]
    for lab, k in sm_cases:
        exp = kG(curve, k)
        t1 = time.time()
        jac = D.smul(k)
        got = jacobian_to_affine(*jac, curve)
        log.case(sec, f"scalar_mul(comb) {lab}", exp, got, dt=time.time() - t1,
                 detail=None if got == exp else {"k": hex(k), "jac": [hex(v) for v in jac]})
        if exp == INFINITY:
            log.case(sec, f"scalar_mul(comb) {lab}: Z==0 encoding", 0, jac[2],
                     verdict="PASS" if jac[2] == 0 else "INFO")
    # comb vs var-base agreement on one random k (G as base)
    k = 1 + secrets.randbelow(n - 1)
    a1 = jacobian_to_affine(*D.smul(k), curve)
    a2 = jacobian_to_affine(*D.smulv(k, G[0], G[1]), curve)
    log.case(sec, "comb vs var-base agree on random k (and vs hazmat)",
             kG(curve, k), a1, detail={"k": hex(k)})
    log.case(sec, "var-base(G) vs hazmat on same k", kG(curve, k), a2)
    log.note(f"  point section {curve} took {time.time() - t0:.0f}s")


def sha_section(transport, labels, log):
    sec = "sha384"
    msg_buf = labels["sha384_msg_buf"]

    def init():
        jsr(transport, labels["sha384_init"], timeout=5.0)

    def update(chunk):
        if len(chunk):
            write_bytes(transport, msg_buf, chunk)
        write_bytes(transport, labels["sha_src"], bytes([msg_buf & 0xFF, msg_buf >> 8]))
        write_bytes(transport, labels["sha_len"], bytes([len(chunk) & 0xFF, len(chunk) >> 8]))
        jsr(transport, labels["sha384_update"], timeout=200.0)

    def final():
        jsr(transport, labels["sha384_final"], timeout=60.0)
        return read_bytes(transport, labels["sha384_digest"], 48)

    def oneshot(m):
        init()
        for off in range(0, len(m), 1024):
            update(m[off:off + 1024])
        return final()

    t0 = time.time()
    for L in [0, 1, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127,
              128, 129, 191, 192, 239, 240, 241, 255, 256, 1023, 1024, 1025,
              2048, 2047]:
        m = secrets.token_bytes(L)
        got = oneshot(m)
        log.case(sec, f"len={L}", hashlib.sha384(m).hexdigest(), got.hex())
    # chaining equality: split points incl. 0-length updates
    m = secrets.token_bytes(300)
    for splits in [(0,), (1,), (64,), (100,), (128,), (1, 1, 1), (0, 0),
                   (128, 128), (127, 1), (111, 1), (112, 0, 1), (255, 45)]:
        init()
        off = 0
        for s in splits:
            update(m[off:off + s])
            off += s
        update(m[off:])
        got = final()
        log.case(sec, f"chained updates splits={splits} (300 B)",
                 hashlib.sha384(m).hexdigest(), got.hex())
    # explicit zero-length update alone
    init()
    update(b"")
    log.case(sec, "init; update(len=0); final == sha384(b'')",
             hashlib.sha384(b"").hexdigest(), final().hex())
    # update with len exactly 1024 then 1
    m = secrets.token_bytes(1025)
    init(); update(m[:1024]); update(m[1024:])
    log.case(sec, "1024 + 1 chained", hashlib.sha384(m).hexdigest(), final().hex())
    # behaviour: double final without init (INFO only)
    init(); update(b"abc"); d1 = final(); d2 = final()
    log.case(sec, "final twice without re-init (behaviour)", d1.hex(), d2.hex(),
             verdict="INFO")
    # init idempotent
    init(); update(b"x" * 10); init(); update(b"abc")
    log.case(sec, "re-init discards previous partial data",
             hashlib.sha384(b"abc").hexdigest(), final().hex())
    # 4096 B multi-chunk (blocks crossing 1024-chunk boundary)
    m = secrets.token_bytes(4096 + 37)
    log.case(sec, "len=4133 in 1024-chunks", hashlib.sha384(m).hexdigest(),
             oneshot(m).hex())
    log.note(f"  sha section took {time.time() - t0:.0f}s")


def hang_section(D, log, curve):
    """Cases suspected to hang (inverse of 0 / p, j2a with Z=0). Run last,
    each with a short timeout; a TimeoutError is recorded as HANG."""
    c = D.c
    p = c["p"]
    sec = f"hang-{curve}"
    D.modp()
    for lab, a in [("mod_inv(0)", 0), ("mod_inv(p)", p)]:
        t1 = time.time()
        try:
            got = D.unop_r0("mod_inv", a, timeout=90.0)
            log.case(sec, lab + " (behaviour: no hang)", "n/a", hex(got),
                     verdict="INFO", dt=time.time() - t1)
        except TimeoutError as e:
            log.case(sec, lab, "returns", f"HANG/timeout: {e}", verdict="FAIL",
                     dt=time.time() - t1)
            return False   # transport state unknown; stop
    # jacobian_to_affine with Z=0
    D.wjac(c["p3"], 5, 6, 0)
    t1 = time.time()
    try:
        jsr(D.t, D.L[c["j2a"]], timeout=90.0)
        got = D.rjac(c["p3"])
        log.case(sec, "jacobian_to_affine(Z=0) (behaviour: no hang)", "n/a",
                 [hex(v) for v in got], verdict="INFO", dt=time.time() - t1)
    except TimeoutError as e:
        log.case(sec, "jacobian_to_affine(Z=0)", "returns",
                 f"HANG/timeout: {e}", verdict="FAIL", dt=time.time() - t1)
        return False
    return True


def main():
    args = sys.argv[1:]
    log = Log("prims")
    labels = load_labels()
    rng = random.Random(secrets.randbits(64))
    self_check(rng, "p256", 2)
    self_check(rng, "p384", 2)
    mgr, inst, transport = boot(log)
    try:
        if "--no-sha" not in args:
            log.note("=== SHA-384 ===")
            sha_section(transport, labels, log)
        for curve, n_smul, n_smulv in (("p256", 13, 9), ("p384", 7, 4)):
            if f"--no-{curve}" in args:
                continue
            D = Drv(transport, labels, curve, log)
            log.note(f"=== field {curve} ===")
            field_section(D, log, curve)
            log.note(f"=== points {curve} ===")
            point_section(D, log, curve, n_smul, n_smulv)
        if "--no-hang" not in args:
            log.note("=== hang probes (last) ===")
            D = Drv(transport, labels, "p256", log)
            if hang_section(D, log, "p256"):
                pass
    finally:
        log.summary()
        shutdown(mgr, inst)


if __name__ == "__main__":
    main()
