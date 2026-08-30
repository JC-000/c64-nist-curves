#!/usr/bin/env python3
"""test_prims_adversarial.py -- adversarial field / point / SHA-384 sweep.

Ported from the 2026-08-28 hazmat audit
(.research/adversarial_audit_2026_08_28/report.md, section 4 items 9-14).
Groups, both curves unless noted:

   9. fp_cmp / fp_is_zero: C (cmp) and Z (is_zero) ASSERTED from the
      register dict jsr() returns -- a==b, p vs p, n vs n, n+-1 vs n,
      W vs 0, high-byte-only differences. fp_cmp's "Z=1 if equal" is
      recorded as INFO only: the last flag-setting instruction is `dey`
      (audit F-5); C is the contract and every in-library caller uses C.
  10. fp_mod_inv on 0 and on the modulus itself (mod p AND mod n) and
      ec_jacobian_to_affine on Z=0 / Z=p (the library's own infinity
      encoding) under a per-case timeout. These HUNG before issue #132
      (audit F-1); the guard now returns C=1 with the output zeroed, and
      the rows assert exactly that encoding (plus C=0 on a normal
      inversion / conversion), so a regression of the guard FAILS the
      run. After a hang the transport is recovered (SP restored) so the
      remaining rows still run. They run LAST.
  11. ec_point_add degeneracies: P(Z=1)+P, lift(P,z)+P (H=0 with Z!=1),
      P+(-P), lift(P,z)+(-P), inf(Z=0, garbage X/Y)+P, inf(0,0,0)+P;
      ec_point_double on Z=0 / lifted inputs; ec_point_add_jj same-point,
      negation, infinity operands.
  12. ec_scalar_mul_var k edge set: n+1, n+2 (R==P mixed-add mid-ladder),
      2^bits-1, 2^(bits-1), (n-1)/2, (n+1)/2, n-2; base -G with k=n-1.
  13. Comb k edge set: 0, 1, n, n-1, n+1, 2^bits-1, 2^(bits-1), all
      sub-scalars K_i=1, all K_i top-bit, K0 all-ones, top limb all-ones,
      2, 2^32; comb-vs-var-base agreement on a random k (and vs hazmat).
  14. SHA-384: chained updates split at 0/1/64/100/111/112/127/128/255
      (+ repeated zero-length updates), update(len=0) alone, 1024+1,
      lengths 65/119/120/191/192/239/240/241/2047/2048 and the FIPS
      block boundaries, re-init discards partial data.

Also carried over (cheap, structured, found nothing but pin contracts):
Solinas worst cases into fp_mod_reduce{256,384}; fp_mod_mul / fp_mod_sqr
on full-width inputs (exact for ANY input -- asserted); fp_mod_mul_n
in-contract cases (one operand < n) asserted and both-operands->=n
recorded as INFO (documented precondition, audit F-8); fp_mod_add /
fp_mod_sub with inputs >= p recorded as INFO -- the routines do a single
conditional +-p and the contract is canonical inputs (audit F-6).

Expected values: Python int arithmetic (+ - * % pow), hashlib.sha384,
and hazmat k*G via tools.vectors.loader.scalar_mul_oracle (affine group
law self-checked against it at startup). Nothing from a C64 run.

One VICE boot; all cases batched. Boot pattern = tools/test_points384.py.

Usage:
    python3 tools/test_prims_adversarial.py [--seed N] [--full] [--verbose]
                                            [--strict] [--record out.jsonl]
                                            [--no-sha] [--no-p256] [--no-p384]
                                            [--no-hang]

Exit status is non-zero on any FAIL (the former F-1 red-known rows are
real assertions since issue #132 closed); INFO rows never fail the run.
"""

import hashlib
import os
import random
import sys

from c64_test_harness import read_bytes, write_bytes, jsr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit_common import (  # noqa: E402
    PROJECT_ROOT, SCALAR_BUF, Machine, Suite, be, build_prg, flags_of,
    from_le, le, load_labels, parse_args, set_ptr, warn_if_vice_running,
)

sys.path.insert(0, PROJECT_ROOT)
from tools.vectors import (  # noqa: E402
    P256_P, P256_N, P256_B, P256_GX, P256_GY,
    P384_P, P384_N, P384_B, P384_GX, P384_GY)
from tools.vectors.loader import (  # noqa: E402
    scalar_mul_oracle, affine_add, affine_neg, jacobian_to_affine,
    INFINITY, self_check)

USAGE = __doc__

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
                 smulv="ec_scalar_mul_var", j2a="ec_jacobian_to_affine",
                 ax="ec_affine_x", ay="ec_affine_y"),
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
                 j2a="ec_jacobian_to_affine_384",
                 ax="ec384_affine_x", ay="ec384_affine_y"),
}

# Per-call jsr() timeouts (warp-mode wall seconds; generous, hang = row).
T_FIELD = 240.0
T_INV = 900.0
T_HANG = 90.0
T_DBL = 600.0
T_ADD = 1200.0
T_SMUL = 3600.0
T_SMULV = 7200.0


# ---------------------------------------------------------------------------
# C64 driver
# ---------------------------------------------------------------------------

class Drv:
    def __init__(self, transport, labels, curve):
        self.t, self.L, self.c = transport, labels, C[curve]
        self.curve = curve
        self.nb = self.c["nb"]

    # -- field ------------------------------------------------------------
    def wfe(self, lab, v, n=None):
        write_bytes(self.t, self.L[lab], le(v, n or self.nb))

    def rfe(self, lab, n=None):
        return from_le(read_bytes(self.t, self.L[lab], n or self.nb))

    def ptrs(self, src1=None, src2=None, dst=None, misc=None):
        if src1:
            set_ptr(self.t, self.L["fp_src1"], self.L[src1])
        if src2:
            set_ptr(self.t, self.L["fp_src2"], self.L[src2])
        if dst:
            set_ptr(self.t, self.L["fp_dst"], self.L[dst])
        if misc:
            set_ptr(self.t, self.L["fp_misc"], self.L[misc])

    def modp(self):
        self.ptrs(misc=self.c["modp"])

    def modn(self):
        self.ptrs(misc=self.c["modn"])

    def binop(self, routine, a, b, dst_is_r0=False, timeout=T_FIELD):
        c = self.c
        self.wfe(c["tmp1"], a)
        self.wfe(c["tmp2"], b)
        self.wfe(c["tmp3"], 0xDEADBEEF)
        self.wfe(c["r0"], 0xDEADBEEF)
        self.ptrs(src1=c["tmp1"], src2=c["tmp2"], dst=c["tmp3"])
        jsr(self.t, self.L[c[routine]], timeout=timeout)
        return self.rfe(c["r0"] if dst_is_r0 else c["tmp3"])

    def unop_r0(self, routine, a, timeout=T_INV):
        c = self.c
        self.wfe(c["tmp1"], a)
        self.wfe(c["r0"], 0xDEADBEEF)
        self.ptrs(src1=c["tmp1"], dst=c["tmp3"])
        jsr(self.t, self.L[c[routine]], timeout=timeout)
        return self.rfe(c["r0"])

    def unop_r0_c(self, routine, a, timeout=T_INV):
        """Like unop_r0 but returns (C, r0) -- the issue #132 encoding."""
        c = self.c
        self.wfe(c["tmp1"], a)
        self.wfe(c["r0"], 0xDEADBEEF)
        self.ptrs(src1=c["tmp1"], dst=c["tmp3"])
        regs = jsr(self.t, self.L[c[routine]], timeout=timeout)
        return flags_of(regs)[0], self.rfe(c["r0"])

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
        return flags_of(regs)

    # -- points -----------------------------------------------------------
    def wjac(self, lab, x, y, z):
        write_bytes(self.t, self.L[lab],
                    le(x, self.nb) + le(y, self.nb) + le(z, self.nb))

    def waff(self, lab, x, y):
        write_bytes(self.t, self.L[lab], le(x, self.nb) + le(y, self.nb))

    def rjac(self, lab):
        d = read_bytes(self.t, self.L[lab], 3 * self.nb)
        nb = self.nb
        return (from_le(d[:nb]), from_le(d[nb:2 * nb]), from_le(d[2 * nb:]))

    def _poison_p3(self):
        write_bytes(self.t, self.L[self.c["p3"]], b"\xA5" * (3 * self.nb))

    def dbl(self, x, y, z=1):
        self.wjac(self.c["p1"], x, y, z)
        self._poison_p3()
        jsr(self.t, self.L[self.c["dbl"]], timeout=T_DBL)
        return self.rjac(self.c["p3"])

    def add(self, p1, p2aff):
        self.wjac(self.c["p1"], *p1)
        self.waff(self.c["p2"], *p2aff)
        self._poison_p3()
        jsr(self.t, self.L[self.c["add"]], timeout=T_ADD)
        return self.rjac(self.c["p3"])

    def addjj(self, p1, p2):
        self.wjac(self.c["p1"], *p1)
        self.wjac(self.c["p2"], *p2)
        self._poison_p3()
        jsr(self.t, self.L[self.c["addjj"]], timeout=T_ADD)
        return self.rjac(self.c["p3"])

    def smul(self, k):
        write_bytes(self.t, SCALAR_BUF, be(k, self.nb))
        set_ptr(self.t, self.L["ec_scalar_ptr"], SCALAR_BUF)
        self._poison_p3()
        jsr(self.t, self.L[self.c["smul"]], timeout=T_SMUL)
        return self.rjac(self.c["p3"])

    def smulv(self, k, bx, by):
        write_bytes(self.t, SCALAR_BUF, be(k, self.nb))
        set_ptr(self.t, self.L["ec_scalar_ptr"], SCALAR_BUF)
        self.wfe(self.c["bx"], bx)
        self.wfe(self.c["by"], by)
        self._poison_p3()
        jsr(self.t, self.L[self.c["smulv"]], timeout=T_SMULV)
        return self.rjac(self.c["p3"])

    def j2a(self, x, y, z, timeout=T_HANG):
        """ec_jacobian_to_affine on (x,y,z) -> (C, affine_x, affine_y).
        Outputs are poisoned first so a zeroed result is a real write."""
        self.wjac(self.c["p3"], x, y, z)
        self.wfe(self.c["ax"], 0xDEADBEEF)
        self.wfe(self.c["ay"], 0xDEADBEEF)
        regs = jsr(self.t, self.L[self.c["j2a"]], timeout=timeout)
        return (flags_of(regs)[0], self.rfe(self.c["ax"]),
                self.rfe(self.c["ay"]))


# ---------------------------------------------------------------------------
# Oracle helpers
# ---------------------------------------------------------------------------

def lift(P, z, p):
    x, y = P
    return ((x * z * z) % p, (y * z * z * z) % p, z)


def kP(curve, k, P):
    k %= C[curve]["n"]
    T = INFINITY
    for i in range(k.bit_length() - 1, -1, -1):
        T = affine_add(T, T, curve)
        if (k >> i) & 1:
            T = affine_add(T, P, curve)
    return T


def kG(curve, k):
    k %= C[curve]["n"]
    return INFINITY if k == 0 else scalar_mul_oracle(k, curve)


def to_aff(curve):
    return lambda jac: jacobian_to_affine(*jac, curve)


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def field_section(S, D, curve, rng, full):
    c = D.c
    p, n, nb = c["p"], c["n"], c["nb"]
    W = (1 << (8 * nb)) - 1
    sec = f"field-{curve}"
    t = D.t
    D.modp()

    # --- 9. cmp / is_zero flag semantics ---------------------------------
    for lab, a in [("0", 0), ("1", 1), ("2^(bits-1)", 1 << (8 * nb - 1)),
                   ("1<<8", 1 << 8), ("W", W), ("p", p),
                   ("rand", rng.randrange(1, p))]:
        raw = S.timed(sec + "/9-flags", f"is_zero({lab}) -> Z",
                      lambda a=a: D.is_zero(a), 1 if a == 0 else 0,
                      transport=t, post=lambda r: r[1][1])
        if raw is not None:
            S.case(sec + "/9-flags", f"is_zero({lab}): A (info: first "
                   "non-zero OR-accumulator, not a contract)", "n/a", raw[0],
                   verdict="INFO")
    for lab, a, b in [("a<b", 5, 6), ("a==b", 7, 7), ("a>b", 8, 7),
                      ("p-1 vs p", p - 1, p), ("p vs p", p, p),
                      ("p+1 vs p", p + 1, p), ("W vs 0", W, 0),
                      ("0 vs W", 0, W), ("n vs n", n, n),
                      ("n-1 vs n", n - 1, n), ("n+1 vs n", n + 1, n),
                      ("hi-byte-only: 1<<(bits-8) vs 1", 1 << (8 * nb - 8), 1),
                      ("hi-byte-only: 1 vs 1<<(bits-8)", 1, 1 << (8 * nb - 8)),
                      ("mid-byte-only: 1<<64 vs 1<<65", 1 << 64, 1 << 65),
                      ("rand vs rand", rng.randrange(W), rng.randrange(W))]:
        raw = S.timed(sec + "/9-flags", f"cmp {lab} -> C (1 iff a>=b)",
                      lambda a=a, b=b: D.cmp(a, b), 1 if a >= b else 0,
                      transport=t, post=lambda r: r[0])
        if raw is not None and a == b:
            S.case(sec + "/9-flags", f"cmp {lab}: 'Z=1 if equal' comment "
                   "(audit F-5: not a contract, C is)", 1, raw[1],
                   verdict="PASS" if raw[1] == 1 else "INFO")

    # --- mod_add / mod_sub: canonical asserted, >=p inputs INFO (F-6) ----
    add_cases = [("(p-1)+(p-1)", p - 1, p - 1), ("(p-1)+1", p - 1, 1),
                 ("0+0", 0, 0), ("rand+rand", rng.randrange(p), rng.randrange(p)),
                 ("NONRED p+0", p, 0), ("NONRED p+1", p, 1),
                 ("NONRED (p+1)+(p-1)", p + 1, p - 1),
                 ("NONRED W+W", W, W), ("NONRED W+1", W, 1)]
    sub_cases = [("0-(p-1)", 0, p - 1), ("0-1", 0, 1), ("1-1", 1, 1),
                 ("(p-1)-(p-1)", p - 1, p - 1),
                 ("NONRED 1-W", 1, W), ("NONRED p-0", p, 0),
                 ("NONRED (p+1)-1", p + 1, 1), ("NONRED W-W", W, W),
                 ("NONRED 0-W", 0, W), ("NONRED 0-p", 0, p)]
    for routine, cases, op in (("mod_add", add_cases, lambda a, b: a + b),
                               ("mod_sub", sub_cases, lambda a, b: a - b)):
        for lab, a, b in cases:
            exp = op(a, b) % p
            if not lab.startswith("NONRED"):
                S.timed(sec + "/mod-addsub", f"{routine} {lab}",
                        lambda r=routine, a=a, b=b: D.binop(r, a, b),
                        exp, transport=t, detail={"a": hex(a), "b": hex(b)})
                continue
            try:
                got = D.binop(routine, a, b)
            except Exception as e:
                got = f"EXC: {e!r}"
            S.case(sec + "/mod-addsub", f"{routine} {lab} (inputs >= p: "
                   "outside the canonical-input contract, audit F-6; INFO)",
                   exp, got, verdict="PASS" if got == exp else "INFO",
                   detail={"a": hex(a), "b": hex(b)})

    # --- Solinas reduction worst cases -----------------------------------
    limb = (1 << 32) - 1
    lim = [("2^(2w)-1", (1 << (16 * nb)) - 1), ("(p-1)^2", (p - 1) ** 2),
           ("p*W", p * W), ("W*W", W * W), ("p*p", p * p),
           ("p<<bits", p << (8 * nb)), ("W<<bits", W << (8 * nb)),
           ("p", p), ("p+1", p + 1), ("2p", 2 * p), ("W", W), ("p-1", p - 1)]
    limb_idx = range(2 * nb // 4) if full else \
        [0, nb // 4 - 1, nb // 4, 2 * nb // 4 - 1]
    for i in limb_idx:
        lim.append((f"limb{i} all-ones", limb << (32 * i)))
    for i in (range(nb // 4, 2 * nb // 4) if full else [nb // 4, 2 * nb // 4 - 1]):
        lim.append((f"high limbs {i}.. all ones",
                    ((1 << (16 * nb)) - 1) ^ ((1 << (32 * i)) - 1)))
    for i in range(4 if full else 2):
        lim.append((f"rand wide #{i}", rng.getrandbits(16 * nb)))
    for lab, w in lim:
        S.timed(sec + "/mod-reduce", f"mod_reduce {lab}",
                lambda w=w: D.reduce(w), w % p, transport=t,
                detail={"w": hex(w)})

    # --- mod_mul / mod_sqr: exact for any full-width input (asserted) ----
    r1, r2 = rng.randrange(p), rng.randrange(p)
    for lab, a, b in [("(p-1)*(p-1)", p - 1, p - 1), ("(p-1)*1", p - 1, 1),
                      ("0*(p-1)", 0, p - 1), ("rand*rand", r1, r2),
                      ("p*1 (full-width input)", p, 1),
                      ("(p+1)*1 (full-width input)", p + 1, 1),
                      ("W*W (full-width input)", W, W),
                      ("W*(p-1) (full-width input)", W, p - 1),
                      ("p*p (full-width input)", p, p)]:
        S.timed(sec + "/mod-mul", f"mod_mul {lab}",
                lambda a=a, b=b: D.binop("mod_mul", a, b, dst_is_r0=True),
                (a * b) % p, transport=t, detail={"a": hex(a), "b": hex(b)})
    for lab, a in [("rand", r1), ("p-1", p - 1),
                   ("2^(bits-1)", 1 << (8 * nb - 1)), ("W", W), ("p", p)]:
        S.timed(sec + "/mod-mul", f"mod_sqr {lab}",
                lambda a=a: D.unop_r0("mod_sqr", a, timeout=T_FIELD),
                (a * a) % p, transport=t)

    # --- mod_mul_n: in-contract asserted, both >= n INFO (F-8) -----------
    wv = rng.randrange(1, n)
    for lab, a, b in [("(n-1)*(n-1)", n - 1, n - 1), ("h=W * w<n", W, wv),
                      ("h=n * w<n", n, wv), ("h=n+1 * w<n", n + 1, wv),
                      ("h=p * w<n", p, wv), ("w<n * h=W (swapped)", wv, W),
                      ("W*(n-1)", W, n - 1), ("n*1", n, 1), ("1*n", 1, n),
                      ("n*0", n, 0), ("n*(n-1)", n, n - 1)]:
        S.timed(sec + "/mod-mul-n", f"mod_mul_n {lab}",
                lambda a=a, b=b: D.binop("mod_mul_n", a, b, timeout=300.0),
                (a * b) % n, transport=t, detail={"a": hex(a), "b": hex(b)})
    for lab, a, b in [("n*n", n, n), ("W*W", W, W), ("(n+1)*(n+1)", n + 1, n + 1)]:
        try:
            got = D.binop("mod_mul_n", a, b, timeout=300.0)
        except Exception as e:
            got = f"EXC: {e!r}"
        S.case(sec + "/mod-mul-n", f"mod_mul_n both operands >= n: {lab} "
               "(outside documented precondition; INFO)", (a * b) % n, got,
               verdict="PASS" if got == (a * b) % n else "INFO")

    # --- mod_inv (non-hanging inputs) -------------------------------------
    D.modp()
    inv_cases = [("p-1", p - 1), ("rand", r1)]
    if full:
        inv_cases += [("2", 2), ("2^(bits-1)", 1 << (8 * nb - 1))]
    for lab, a in inv_cases:
        S.timed(sec + "/mod-inv", f"mod_inv({lab}) mod p",
                lambda a=a: D.unop_r0("mod_inv", a), pow(a, -1, p),
                transport=t)
    D.modn()
    S.timed(sec + "/mod-inv", "mod_inv(n-1) mod n",
            lambda: D.unop_r0("mod_inv", n - 1), pow(n - 1, -1, n),
            transport=t)
    if full:
        S.timed(sec + "/mod-inv", "mod_inv(rand) mod n",
                lambda: D.unop_r0("mod_inv", wv), pow(wv, -1, n),
                transport=t)
    D.modp()


def point_section(S, D, curve, rng, full):
    c = D.c
    p, n, nb = c["p"], c["n"], c["nb"]
    G = c["G"]
    W = (1 << (8 * nb)) - 1
    sec = f"point-{curve}"
    t = D.t
    aff = to_aff(curve)
    D.modp()
    P = kG(curve, rng.randrange(3, n - 1))
    negP = affine_neg(P, curve)
    twoP = affine_add(P, P, curve)
    z = rng.randrange(2, p - 1)
    z2 = rng.randrange(2, p - 1)

    # --- 11. mixed add degeneracies ----------------------------------------
    for lab, p1, p2, exp in [
            ("P(Z=1) + P (must double)", (P[0], P[1], 1), P, twoP),
            ("lift(P,z) + P (H==0 with Z!=1)", lift(P, z, p), P, twoP),
            ("P + (-P) -> infinity", (P[0], P[1], 1), negP, INFINITY),
            ("lift(P,z) + (-P) -> infinity", lift(P, z, p), negP, INFINITY),
            ("inf(Z=0, X/Y garbage) + P -> P", (12345, 6789, 0), P, P),
            ("inf(0,0,0) + P -> P", (0, 0, 0), P, P),
            ("lift(P,z) + G", lift(P, z, p), G, affine_add(P, G, curve)),
            ("G + G (double via add)", (G[0], G[1], 1), G,
             affine_add(G, G, curve))]:
        jac = S.timed(sec + "/11-point-add", f"point_add {lab}",
                      lambda p1=p1, p2=p2: D.add(p1, p2), exp, transport=t,
                      post=aff)
        if exp == INFINITY and jac is not None:
            S.case(sec + "/11-point-add", f"point_add {lab}: Z==0 encoding",
                   0, jac[2], verdict="PASS" if jac[2] == 0 else "INFO")

    for lab, pt, exp in [("P Z=1", (P[0], P[1], 1), twoP),
                         ("lift(P,z)", lift(P, z, p), twoP),
                         ("Z=0 garbage -> infinity", (99, 77, 0), INFINITY),
                         ("Z=0 all zero -> infinity", (0, 0, 0), INFINITY)]:
        S.timed(sec + "/11-point-double", f"point_double {lab}",
                lambda pt=pt: D.dbl(*pt), exp, transport=t, post=aff)

    for lab, p1, p2, exp in [
            ("lift(P,z)+lift(P,z2) same point -> 2P", lift(P, z, p),
             lift(P, z2, p), twoP),
            ("lift(P,z)+lift(-P,z2) -> inf", lift(P, z, p), lift(negP, z2, p),
             INFINITY),
            ("lift(P,z)+lift(G,z2)", lift(P, z, p), lift(G, z2, p),
             affine_add(P, G, curve)),
            ("P + inf(Z=0 garbage) -> P", (P[0], P[1], 1), (5, 6, 0), P),
            ("inf(Z=0 garbage) + lift(P,z) -> P", (5, 6, 0), lift(P, z, p), P)]:
        S.timed(sec + "/11-point-add-jj", f"point_add_jj {lab}",
                lambda p1=p1, p2=p2: D.addjj(p1, p2), exp, transport=t,
                post=aff)

    # --- 12. scalar_mul_var k edge set --------------------------------------
    sv = [("k=n+1 -> P", n + 1, True),
          ("k=n+2 -> 2P (mid-ladder R==P mixed add)", n + 2, True),
          ("k=2^bits-1", W, True), ("k=2^(bits-1) (top bit only)",
                                    1 << (8 * nb - 1), False),
          ("k=(n-1)/2", (n - 1) // 2, False), ("k=(n+1)/2", (n + 1) // 2, False),
          ("k=n-2", n - 2, False)]
    for lab, k, fast in sv:
        if not (full or fast):
            continue
        S.timed(sec + "/12-scalar-mul-var", f"scalar_mul_var {lab}",
                lambda k=k: D.smulv(k, P[0], P[1]), kP(curve, k, P),
                transport=t, post=aff, detail={"k": hex(k)})
    S.timed(sec + "/12-scalar-mul-var", "scalar_mul_var k=n-1, base=-G -> G",
            lambda: D.smulv(n - 1, G[0], (-G[1]) % p), G, transport=t,
            post=aff)

    # --- 13. comb k edge set ------------------------------------------------
    limbs = 8 * nb // 32
    sm = [("k=0 -> inf", 0, True), ("k=n -> inf", n, True),
          ("k=n+1 -> G", n + 1, True), ("k=1 -> G", 1, False),
          ("k=n-1 -> -G", n - 1, False), ("k=2^bits-1", W, True),
          ("k=2^(bits-1)", 1 << (8 * nb - 1), False),
          ("k=all sub-scalars K_i=1 (idx 255 at col 0)",
           sum(1 << (32 * i) for i in range(limbs)), True),
          ("k=all sub-scalars top bit (idx 255 at col 31)",
           sum(1 << (32 * i + 31) for i in range(limbs)), False),
          ("k=2^32-1 (K0 all ones)", (1 << 32) - 1, False),
          ("k=(2^32-1)<<(bits-32) (top limb all ones)",
           ((1 << 32) - 1) << (8 * nb - 32), False),
          ("k=2 -> 2G", 2, False), ("k=2^32 -> anchor 2", 1 << 32, False)]
    for lab, k, fast in sm:
        if not (full or fast):
            continue
        exp = kG(curve, k)
        jac = S.timed(sec + "/13-comb", f"scalar_mul(comb) {lab}",
                      lambda k=k: D.smul(k), exp, transport=t, post=aff,
                      detail={"k": hex(k)})
        if exp == INFINITY and jac is not None:
            S.case(sec + "/13-comb", f"scalar_mul(comb) {lab}: Z==0 encoding",
                   0, jac[2], verdict="PASS" if jac[2] == 0 else "INFO")
    k = rng.randrange(1, n)
    exp = kG(curve, k)
    S.timed(sec + "/13-comb", "comb(k) vs hazmat, random k",
            lambda: D.smul(k), exp, transport=t, post=aff, detail={"k": hex(k)})
    S.timed(sec + "/13-comb", "var-base(G, same k) vs hazmat (comb agreement)",
            lambda: D.smulv(k, G[0], G[1]), exp, transport=t, post=aff,
            detail={"k": hex(k)})


def sha_section(S, transport, labels, rng, full):
    sec = "sha384/14"
    msg_buf = labels["sha384_msg_buf"]

    def init():
        jsr(transport, labels["sha384_init"], timeout=5.0)

    def update(chunk):
        if len(chunk):
            write_bytes(transport, msg_buf, chunk)
        set_ptr(transport, labels["sha_src"], msg_buf)
        write_bytes(transport, labels["sha_len"],
                    bytes([len(chunk) & 0xFF, len(chunk) >> 8]))
        jsr(transport, labels["sha384_update"], timeout=200.0)

    def final():
        jsr(transport, labels["sha384_final"], timeout=60.0)
        return read_bytes(transport, labels["sha384_digest"], 48).hex()

    def oneshot(m):
        init()
        for off in range(0, len(m), 1024):
            update(m[off:off + 1024])
        return final()

    def chained(m, splits):
        init()
        off = 0
        for s in splits:
            update(m[off:off + s])
            off += s
        update(m[off:])
        return final()

    lengths = [0, 1, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127,
               128, 129, 191, 192, 239, 240, 241, 255, 256, 1023, 1024, 1025,
               2047, 2048]
    if not full:
        lengths = [0, 1, 56, 64, 65, 111, 112, 119, 120, 128, 191, 192, 239,
                   240, 241, 1024, 1025, 2047, 2048]
    for L in lengths:
        m = rng.randbytes(L)
        S.timed(sec, f"len={L}", lambda m=m: oneshot(m),
                hashlib.sha384(m).hexdigest(), transport=transport)
    m = rng.randbytes(300)
    splits = [(0,), (1,), (64,), (100,), (111,), (112,), (127,), (128,),
              (255,), (0, 0), (1, 1, 1), (128, 128), (127, 1), (112, 0, 1),
              (255, 45)]
    if not full:
        splits = [(0,), (1,), (64,), (100,), (111,), (112,), (127,), (128,),
                  (255,), (0, 0), (112, 0, 1)]
    for sp in splits:
        S.timed(sec, f"chained updates splits={sp} (300 B)",
                lambda sp=sp: chained(m, sp), hashlib.sha384(m).hexdigest(),
                transport=transport)

    def zero_update_alone():
        init()
        update(b"")
        return final()
    S.timed(sec, "init; update(len=0); final == sha384(b'')",
            zero_update_alone, hashlib.sha384(b"").hexdigest(),
            transport=transport)

    m2 = rng.randbytes(1025)
    S.timed(sec, "1024 + 1 chained", lambda: chained(m2, (1024,)),
            hashlib.sha384(m2).hexdigest(), transport=transport)

    def reinit():
        init()
        update(b"x" * 10)
        init()
        update(b"abc")
        return final()
    S.timed(sec, "re-init discards previous partial data", reinit,
            hashlib.sha384(b"abc").hexdigest(), transport=transport)

    m3 = rng.randbytes(4096 + 37)
    S.timed(sec, "len=4133 in 1024-B chunks", lambda: oneshot(m3),
            hashlib.sha384(m3).hexdigest(), transport=transport)


def hang_section(S, D, curve):
    """10. Audit F-1 / issue #132: fp_mod_inv on the residue class 0 and
    ec_jacobian_to_affine on Z=0 used to hang. The guard's documented
    encoding is asserted: C=1 and a zeroed output (fp_r0 / affine x,y)
    for 0, the modulus (mod p and mod n) and Z in {0, p}; C=0 and the
    oracle value on a normal inversion / conversion. Each runs under
    T_HANG and the transport is recovered after a timeout. Runs last."""
    c = D.c
    p, n = c["p"], c["n"]
    gx, gy = c["G"]
    sec = f"hang-{curve}/10-F1"
    NOINV = (1, 0)                       # (C, fp_r0): no inverse
    INF = (1, 0, 0)                      # (C, affine_x, affine_y): infinity

    D.modp()
    S.timed(sec, "fp_mod_inv(0) mod p -> C=1, r0=0 (issue #132 guard)",
            lambda: D.unop_r0_c("mod_inv", 0, timeout=T_HANG), NOINV,
            transport=D.t,
            detail={"note": "binary GCD: u=0 stayed even forever"})
    S.timed(sec, "fp_mod_inv(p) mod p -> C=1, r0=0 (u=p==0 mod p)",
            lambda: D.unop_r0_c("mod_inv", p, timeout=T_HANG), NOINV,
            transport=D.t)
    S.timed(sec, "fp_mod_inv(2) mod p -> C=0, oracle value",
            lambda: D.unop_r0_c("mod_inv", 2, timeout=T_INV),
            (0, pow(2, -1, p)), transport=D.t)
    S.timed(sec, "fp_mod_inv(p-1) mod p -> C=0, oracle value",
            lambda: D.unop_r0_c("mod_inv", p - 1, timeout=T_INV),
            (0, pow(p - 1, -1, p)), transport=D.t)

    D.modn()
    S.timed(sec, "fp_mod_inv(0) mod n -> C=1, r0=0 (issue #132 guard)",
            lambda: D.unop_r0_c("mod_inv", 0, timeout=T_HANG), NOINV,
            transport=D.t)
    S.timed(sec, "fp_mod_inv(n) mod n -> C=1, r0=0 (u=n==0 mod n)",
            lambda: D.unop_r0_c("mod_inv", n, timeout=T_HANG), NOINV,
            transport=D.t)
    S.timed(sec, "fp_mod_inv(n-1) mod n -> C=0, oracle value",
            lambda: D.unop_r0_c("mod_inv", n - 1, timeout=T_INV),
            (0, pow(n - 1, -1, n)), transport=D.t)
    D.modp()

    S.timed(sec, "ec_jacobian_to_affine(Z=0) -> C=1, x=y=0 (infinity)",
            lambda: D.j2a(5, 6, 0), INF, transport=D.t,
            detail={"note": "Z=0 is the library's own infinity encoding"})
    S.timed(sec, "ec_jacobian_to_affine(Z=p) -> C=1, x=y=0 (Z==0 mod p)",
            lambda: D.j2a(5, 6, p), INF, transport=D.t)
    S.timed(sec, "ec_jacobian_to_affine(lift(G,3)) -> C=0, G",
            lambda: D.j2a(*lift((gx, gy), 3, p), timeout=T_INV),
            (0, gx, gy), transport=D.t)
    # Post-probe sanity: the transport must still compute correctly.
    S.timed(sec, "post-probe sanity: mod_inv(2) mod p",
            lambda: D.unop_r0("mod_inv", 2), pow(2, -1, p), transport=D.t)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    opts = parse_args(sys.argv[1:], USAGE)
    warn_if_vice_running()
    os.chdir(PROJECT_ROOT)
    extra = opts["extra"]
    rng = random.Random(opts["seed"])
    mode = "full" if opts["full"] else "fast"
    print(f"Mode: {mode}")
    print(f"Random seed: {opts['seed']} (reproduce with --seed {opts['seed']})")
    curves = [cv for cv in ("p256", "p384") if f"--no-{cv}" not in extra]
    for cv in curves:
        self_check(rng, cv, 2)
    print("  affine group law self-check OK (vs cryptography oracle)")

    build_prg()
    required = ["fp_src1", "fp_src2", "fp_dst", "fp_misc", "ec_scalar_ptr",
                "sha384_init", "sha384_update", "sha384_final",
                "sha384_digest", "sha384_msg_buf", "sha_src", "sha_len"]
    for cv in curves:
        required += [v for k, v in C[cv].items()
                     if isinstance(v, str) and k not in ("G",)]
    labels = load_labels(required)

    suite = Suite("prims-adversarial", strict=opts["strict"],
                  record=opts["record"], verbose=opts["verbose"])
    try:
        with Machine() as m:
            transport = m.transport
            if "--no-sha" not in extra:
                suite.note("\n--- SHA-384 (14) ---")
                sha_section(suite, transport, labels, rng, opts["full"])
            for cv in curves:
                D = Drv(transport, labels, cv)
                suite.note(f"\n--- field {cv} (9 + reduce/mul/mul_n/inv) ---")
                field_section(suite, D, cv, rng, opts["full"])
                suite.note(f"\n--- points {cv} (11, 12, 13) ---")
                point_section(suite, D, cv, rng, opts["full"])
            if "--no-hang" not in extra:
                for cv in curves:
                    suite.note(f"\n--- hang probes {cv} (10, audit F-1; "
                               f"last) ---")
                    hang_section(suite, Drv(transport, labels, cv), cv)
    except Exception as e:
        suite.case("harness", "run to completion", "completed",
                   f"aborted: {e!r}")
    ok = suite.summary(seed=opts["seed"], mode=mode)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
