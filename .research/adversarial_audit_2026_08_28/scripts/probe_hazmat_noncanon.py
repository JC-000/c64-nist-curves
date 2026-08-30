#!/usr/bin/env python3.13
"""Does hazmat/OpenSSL accept non-canonical (x+p) public-key coordinates?"""
import audit_ecdsa as A
from tools.vectors import P256_P, P256_N

for curve in ("p256", "p384"):
    c = A.CURVE[curve]
    p, n, nb = c["p"], c["n"], c["nbytes"]
    x0, y0 = A.find_small_x_point(curve)
    # first x >= 1 on curve (what the suite's find_small_x_point uses)
    x1 = 1
    while True:
        rhs = (pow(x1, 3, p) - 3 * x1 + c["b"]) % p
        y1 = pow(rhs, (p + 1) // 4, p)
        if y1 * y1 % p == rhs:
            break
        x1 += 1
    for (x, y) in [(x0, y0), (x1, y1)]:
        import secrets
        kk = 2 + secrets.randbelow(n - 2)
        R = A.point_mul(curve, kk, (x, y))
        rr = R[0] % n
        ss = (rr * pow(kk, -1, n)) % n
        h0 = bytes(nb)
        print(curve, f"x={x}", "canonical:", A.hazmat_verify(curve, rr, ss, h0, x, y),
              "| x+p:", A.hazmat_verify(curve, rr, ss, h0, x + p, y),
              "| y+p:", A.hazmat_verify(curve, rr, ss, h0, x, y + p)
              if y + p < (1 << (nb * 8)) else "n/a")
    # Also check what the suite's oracle_verify says for x1+p
    from tools.test_ecdsa_verify import oracle_verify, RFC6979_P256, RFC6979_P384
    import hashlib
    vec = RFC6979_P256 if curve == "p256" else RFC6979_P384
    hh = (hashlib.sha256 if curve == "p256" else hashlib.sha384)(vec["msg"]).digest()
    print(curve, "suite oracle_verify(RFC sig, Qx=x1+p):",
          oracle_verify(curve, vec["r"], vec["s"], hh, x1 + p, y1))
