#!/usr/bin/env python3.13
"""Offline check of audit_ecdsa case generation: hazmat vs pure-int verify."""
import sys
import audit_ecdsa as A

for curve in sys.argv[1:] or ["p256", "p384"]:
    n = 0
    dis = 0
    for label, r, s, hb, qx, qy, e in A.cases_for(curve, quick=True):
        exp_c, hz = A.oracle_c(curve, r, s, hb, qx, qy)
        py = A.py_verify(curve, r, s, e, qx, qy)
        flag = "" if (py is True) == (exp_c == 0) else "  <-- DISAGREE"
        if flag:
            dis += 1
        print(f"{curve} C={exp_c} hz={hz!s:>22} py={py!s:>5} {label}{flag}")
        n += 1
    print(f"{curve}: {n} cases, {dis} hazmat/py disagreements")
