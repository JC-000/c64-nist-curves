#!/usr/bin/env python3
"""Fit wall = F + C/f to the 16/48/64 MHz sweep results (issue #69).

F = speed-invariant (DMA-anchored) floor in seconds
C = CPU-scaling work in MHz*s (= millions of cycles)

With three speeds we do a least-squares fit on (1/f, wall) and report
residuals so we can see whether the two-parameter model actually holds
on the C64U (it should if REU DMA wall-cost is clock-invariant).
"""
import sys
import json

# results[name][mhz] = wall seconds (1-MHz-equivalent cyc / 1e6, i.e.
# jiffies*17045/1e6 — the wall-anchored measurement)


def fit(points):
    # least squares for wall = F + C * x where x = 1/f
    n = len(points)
    sx = sum(1.0 / f for f, _ in points)
    sy = sum(w for _, w in points)
    sxx = sum((1.0 / f) ** 2 for f, _ in points)
    sxy = sum(w / f for f, w in points)
    denom = n * sxx - sx * sx
    C = (n * sxy - sx * sy) / denom
    F = (sy - C * sx) / n
    resid = [(f, w, F + C / f - w) for f, w in points]
    return F, C, resid


def main():
    data = json.load(open(sys.argv[1]))
    for name, by_mhz in data.items():
        pts = [(int(m), w) for m, w in by_mhz.items()]
        pts.sort()
        if len(pts) < 2:
            continue
        F, C, resid = fit(pts)
        print(f"{name}:")
        print(f"  floor F = {F:8.2f} s   cpu C = {C:9.1f} Mcy")
        for f, w, r in resid:
            share = F / w * 100 if w else 0
            print(f"    {f:2d} MHz: wall {w:8.2f} s  fit-resid {r:+6.2f} s  "
                  f"floor share {share:5.1f}%")


if __name__ == "__main__":
    main()
