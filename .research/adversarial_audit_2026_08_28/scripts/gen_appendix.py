#!/usr/bin/env python3.13
"""Render every recorded case (all JSONL logs) into a markdown appendix."""
import json
import glob
import os
import sys

AUD = os.path.dirname(os.path.abspath(__file__))
files = [("ecdsa_p256.jsonl", "ECDSA P-256 sweep + mutation (one boot)"),
         ("ecdsa_p384.jsonl", "ECDSA P-384 sweep, trimmed list (one boot)"),
         ("ecdsa_p384_attempt1.jsonl", "ECDSA P-384 untrimmed attempt (stopped early; 4 cases)"),
         ("prims_attempt1.jsonl", "Primitives attempt 1 (SHA-384 + field-p256 + part of point-p256; aborted by a script bug)"),
         ("prims.jsonl", "Primitives rerun (field/point both curves + hang probes; SHA skipped)")]
out = []
tot = {"PASS": 0, "FAIL": 0, "INFO": 0}
for fn, title in files:
    p = os.path.join(AUD, fn)
    if not os.path.exists(p):
        continue
    recs = [json.loads(l) for l in open(p)]
    cases = [r for r in recs if "verdict" in r]
    c = {"PASS": 0, "FAIL": 0, "INFO": 0}
    for r in cases:
        c[r["verdict"]] += 1
        tot[r["verdict"]] += 1
    out.append(f"\n### {title} — `{fn}`\n")
    out.append(f"PASS={c['PASS']} FAIL={c['FAIL']} INFO={c['INFO']}\n")
    out.append("| verdict | section | case | expected | got | s |")
    out.append("|---|---|---|---|---|---|")
    for r in cases:
        e = str(r["expected"])
        g = str(r["got"])
        if len(e) > 40:
            e = e[:37] + "..."
        if len(g) > 40:
            g = g[:37] + "..."
        dt = "" if r.get("dt") is None else f"{r['dt']:.1f}"
        lab = r["label"].replace("|", "\\|")
        out.append(f"| {r['verdict']} | {r['section']} | {lab} | {e} | {g} | {dt} |")
out.insert(0, f"\nTotal recorded cases: PASS={tot['PASS']} FAIL={tot['FAIL']} INFO={tot['INFO']} (sum {sum(tot.values())})\n")
sys.stdout.write("\n".join(out) + "\n")
