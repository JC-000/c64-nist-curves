#!/usr/bin/env python3
"""Generate tools/abi_baseline.json: the exported surface of a RELEASED tag.

`make check-archives` (abi_surface_check) compares the archives of the tree
being built against this file and fails if a name the last release exported
has gone while LIB_NISTCURVES_ABI_VERSION has not moved past the release's
value. Without it, nothing tied the counter to the surface: CLAUDE.md said
check-archives "pins the counter against the source", but no leg read the
counter's value at all, and a removal with the counter left alone passed
every gate (review of the v0.16.0 sqtab removal, mutant sC).

RELEASE CHECKLIST: refresh this baseline right after tagging each release, so
the next release is compared against the one consumers actually pin:

    python3 tools/gen_abi_baseline.py v0.16.0

`make check-release-state` (leg 5) fails until this has been done for the
newest release tag. It reads the "tag" and "commit" this generator records,
and it checks that the commit is still what the tag resolves to.

The generator builds the TAG, not the working tree. It checks the tag out in a
throwaway git worktree, runs the `make` targets that tag's own
`check-archives` rule lists, and reads every member of every built archive
with `ar65 x` + `od65`. The baseline is therefore what that release shipped,
which this tree's sources cannot reproduce. Default configuration only, with
no CONTRACT_DEFINES: the bare §6.5-window names are included, as shipped.

No VICE, no device, no network.
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "tools" / "abi_baseline.json"


def rows_digest(abi, archives):
    """sha256 over the baseline's CONTENT: the ABI value and every archive's
    export rows, canonically serialised. Stored as "rows_sha256" at generation
    time and re-derived by both readers (check_archives.abi_surface_check and
    check_release_state leg 5), so a hand-edited row fails even with "tag" and
    "commit" intact. tag/commit are outside the digest on purpose: each is
    checked against git directly. The ONE canonicalisation, imported by both
    readers rather than restated.

    ACCEPTED LIMIT (review tT2): the digest is self-certifying. It catches an
    edited row, not a deliberate edit that also recomputes rows_sha256 (and
    keeps tag/commit). Re-deriving the rows from the tag, as gen_abi_baseline
    does, is the independent check; the digest makes an accidental or
    one-site edit loud."""
    canon = json.dumps({"abi": int(abi),
                        "archives": {k: sorted(v) for k, v in archives.items()}},
                       sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode:
        sys.exit(f"FAILED: {' '.join(map(str, cmd))}\n{p.stdout}{p.stderr}")
    return p.stdout


def member_exports(obj):
    out = run(["od65", "--dump-exports", str(obj)])
    m = re.search(r"Exports:\s*\n\s*Count:\s*(\d+)", out)
    names = re.findall(r'Name:\s*"([^"]+)"', out)
    if not m or len(names) != int(m.group(1)):
        sys.exit(f"od65 export dump of {obj} is untrustworthy")
    return set(names)


def abi_value(obj):
    out = run(["od65", "--dump-exports", str(obj)])
    m = re.search(r'Name:\s*"LIB_NISTCURVES_ABI_VERSION"(?:.|\n)*?Value:\s*0x([0-9A-Fa-f]+)', out)
    return int(m.group(1), 16) if m else None


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_abi_baseline.py <release-tag>")
    tag = sys.argv[1]
    sha = run(["git", "-C", str(REPO), "rev-parse", f"{tag}^{{commit}}"]).strip()
    tmp = Path(tempfile.mkdtemp(prefix="abi_baseline_"))
    wt = tmp / "wt"
    run(["git", "-C", str(REPO), "worktree", "add", "--detach", str(wt), sha])
    try:
        mk = (wt / "Makefile").read_text()
        m = re.search(r"^check-archives:\s*(.+)$", mk, re.M)
        if not m:
            sys.exit(f"{tag}: Makefile has no check-archives rule to take the "
                     "archive targets from")
        targets = m.group(1).split()
        run(["make", "-C", str(wt), *targets])
        libdir = wt / "build" / "lib"
        archives, abis = {}, set()
        for a in sorted(libdir.glob("*.a")):
            names = [l.strip() for l in run(["ar65", "t", str(a)]).splitlines()
                     if l.strip().endswith(".o")]
            xd = tmp / "x" / a.stem
            xd.mkdir(parents=True)
            run(["ar65", "x", str(a), *names], cwd=xd)
            exp = set()
            for n in names:
                exp |= member_exports(xd / n)
                if n.startswith("lib_version"):
                    v = abi_value(xd / n)
                    if v is not None:
                        abis.add(v)
            if not exp:
                sys.exit(f"{a.name}: no exports read -- refusing an empty row")
            archives[a.name] = sorted(exp)
        if len(abis) != 1:
            sys.exit(f"expected one ABI value across the archives, read {abis}")
        if not archives:
            sys.exit("no archives built -- refusing an empty baseline")
        doc = {
            "_comment": "Generated by tools/gen_abi_baseline.py -- do not edit "
                        "by hand. Refresh after tagging each release.",
            "tag": tag,
            "commit": sha,
            "abi": abis.pop(),
            "archives": archives,
        }
        doc["rows_sha256"] = rows_digest(doc["abi"], archives)
        OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        print(f"wrote {OUT.relative_to(REPO)}: {tag} ({sha[:12]}), ABI "
              f"{doc['abi']}, {len(archives)} archives, "
              f"{sum(len(v) for v in archives.values())} export rows")
    finally:
        subprocess.run(["git", "-C", str(REPO), "worktree", "remove", "--force",
                        str(wt)], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
