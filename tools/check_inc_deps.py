#!/usr/bin/env python3
"""Gate: the Makefile's dependency graph must see `.include`d headers.

Why this exists (issue #178)
----------------------------
Every ca65 recipe named only its `.s`.  The headers those sources
`.include` -- `sqtab_base.inc`, `reu_banks.inc`, `precalc_table.inc`,
`reu_dma_done.inc` at the time of writing -- were prerequisites of
nothing, so editing one (or a `git checkout` that touched only a header)
left `make` / `make lib-*` answering "Nothing to be done" and shipping a
stale object, archive or PRG.  Nothing in the build reported it.

Two smaller defects of the same Makefile ride along:

* `make clean` left the variant test PRGs (`nist-curves-{onchip,nocomb,
  onchip-nocomb}.prg`) and their `labels_*` files behind.
* The CONTRACT_DEFINES staleness stamp ran its `rm` at *parse* time via
  `$(shell ...)`, so even `make -n` with changed knobs deleted every
  object and archive and rewrote the stamp.  A dry run must be side-effect
  free.

How it checks, without touching the real tree
---------------------------------------------
Everything runs in a throwaway copy of `Makefile`, `src/` and `cfg/` under
a temporary directory; the working tree's `build/` is never read or
written.

Populations are DISCOVERED, never hard-coded, and each is asserted
non-empty (an empty population passes every "for all" vacuously):

* includes -- every `.include "x"` directive in `src/*.s`, followed
  transitively through any header that itself includes another.
* objects  -- every object the Makefile builds for its public targets
  (`all`, the three variant PRGs, all twelve `lib*` archives) plus every
  `$(BUILD_DIR)/<name>.o` named anywhere in the Makefile, mapped to its
  source by reading the ca65 command line `make -n -B` prints for it.

Legs
----
0. population   -- includes, objects and the include->object map are all
                   non-empty; every discovered header and every including
                   source reaches >= 1 built object.
1b. classifier  -- the Makefile's dry-run classifier, fed realistic GNU make
                   3.81 and 4.x MAKEFLAGS strings through the
                   MAKEFLAGS_UNDER_TEST seam (`make print-dry-classify`),
                   plus real -n/-q/-t/-k invocations with no seam.
1. precondition -- after a full build, `make -q <every object>` reports
                   up to date.  Without this, leg 3 could pass because
                   objects were stale for some unrelated reason.
2. control      -- `make -n -W src/<x>.s` reassembles every object built
                   from that source.  Proves the -W probe itself works, so
                   a red leg 3 means a missing edge, not a broken probe.
3. inc-deps     -- for every discovered header, `make -n -W src/<x>.inc`
                   reassembles EVERY object (all variants) whose source
                   includes it, directly or transitively.
3b. makefile-dep -- `make -n -W Makefile` reassembles every object: the
                   recipe flags live there.
4. corrupt-d    -- `make clean` succeeds over a planted garbage .d.
   clean        -- after building every PRG and archive, `make clean`
                   leaves no *.o, *.d, *.prg, labels*.txt, *.dbg or lib/,
                   and KEEPS the knob stamp.
   clean-all    -- `make clean all` then `make -q all` is up to date.
   nonbuild     -- `make clean` with changed knobs leaves the stamp alone.
5. dry-run      -- `make -n` / `-q` with CHANGED CONTRACT_DEFINES leave
                   build/ exactly as found (file set, sizes, mtimes, stamp);
                   `-t` may bump mtimes but must not delete, empty or
                   rewrite. `-n` must print a reassembly line for EVERY
                   object a real `make lib` needs; `-q` must answer "stale".
   nonbuild     -- every goal in NON_BUILD_PINNED (pinned here, not read
                   from the Makefile) leaves build/ untouched under
                   changed knobs.
6. real-run     -- a real `make lib` with changed knobs still reassembles
                   and records the new knobs (legs 5 must not be bought by
                   disabling the invalidation).

Opt-in (`make check-inc-deps`), never a prerequisite of `all`.  No VICE,
no device, no network.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = "src"
BUILD = "build"

PUBLIC_TARGETS = [
    "all", "nocomb-prg", "onchip-prg", "onchip-nocomb-prg",
    "lib", "lib-app-owned", "lib-p256-verify", "lib-p384-verify",
    "lib-p384-sha384", "lib-p384-curve", "lib-onchip",
    "lib-p256-verify-onchip", "lib-p384-verify-onchip",
    "lib-p384-curve-onchip", "lib-p256-comb", "lib-p256-comb-onchip",
]

# Goals that build nothing and so must never invalidate build/ (leg 5 / 4d).
# Pinned, not parsed from the Makefile: dropping one from NON_BUILD_GOALS
# must turn a leg red rather than silently shrink the probe set.
NON_BUILD_PINNED = {"clean", "dist", "check-harness-routing", "check-release-notes",
                    "check-release-state", "check-inc-deps", "print-dry-classify"}

# Dry-run classifier table (leg 1b). Each row is a MAKEFLAGS string as GNU
# make 3.81 or 4.x would present it at parse time, fed to the Makefile's
# classifier through the MAKEFLAGS_UNDER_TEST seam, and whether it means a
# dry run (-n / -q / -t). The dangerous direction is a REAL build classified
# as dry: it skips the knob wipe AND the stamp update, so the next build with
# the old knobs answers "Nothing to be done" over objects built with the new.
CLASSIFIER_ROWS = [
    ("", False),                                        # no flags at all
    ("n", True), ("q", True), ("t", True),              # 3.81 / 4.x cluster
    ("kn", True), ("ks", False), ("k", False), ("s", False),
    (" --no-print-directory", False),                   # 3.81: long option only
    (" --no-print-directory -n", True),                 # 3.81: long options FIRST
    (" --no-print-directory -kn", True),
    (" --no-print-directory -s", False),
    ("n --no-print-directory -- CONTRACT_DEFINES=-D\\ X", True),   # 4.x
    ("k -Otarget -I../inc -- CONTRACT_DEFINES=-I\\ ../shared/include", False),
    ("kt -Otarget", True),
    (" -Otarget", False),                               # 4.x: -O arg holds a 't'
    (" -j4 -Otarget --no-print-directory", False),
    (" -I/usr/include -- X=1", False),                  # 4.x: -I path holds an 'n'
    (" -- CONTRACT_DEFINES=-I\\ ../shared/include", False),  # var fragment holds an 'n'
    (" -- CONTRACT_DEFINES=-Dnone\\ -Dq", False),       # dash-led var fragment
    (" --no-print-directory -- X=n", False),
    # A variable fragment that is itself a valid flag cluster: only the
    # stop-at-`--` rule can tell it from a real `-t` / `-n`.
    (" --no-print-directory -- CONTRACT_DEFINES=-D\\ X\\ -t", False),
    (" -- EXTRA=x\\ -n", False),
]
# The same classifier reached through REAL flags (no seam): proves the
# Makefile reads MAKEFLAGS itself when the seam is absent.
CLASSIFIER_REAL = [([], False), (["-n"], True), (["-q"], True), (["-t"], True),
                   (["-k"], False), (["-s", "-k"], False)]
DRY_RE = re.compile(r"^MAKE_DRY_RUN=\[(.*)\]$", re.M)

INCLUDE_RE =re.compile(r'^\s*\.include\s+"([^"]+)"', re.IGNORECASE)
# The ca65 recipe line for one object: `... -o build/X.o src/Y.s`
CA65_LINE_RE = re.compile(
    r'^ca65\b.*\s-o\s+(' + BUILD + r'/[^\s]+\.o)\s+(' + SRC + r'/[^\s]+\.s)\s*$')
OBJ_TOKEN_RE = re.compile(r'\$\(BUILD_DIR\)/([A-Za-z0-9_]+)\.o\b')

failures: list[str] = []


def fail(leg: str, msg: str) -> None:
    failures.append(f"[{leg}] {msg}")
    print(f"FAIL [{leg}] {msg}")


def clean_env() -> dict[str, str]:
    """A make environment that cannot inherit the caller's knobs or flags.

    Run as `make check-inc-deps`, MAKEFLAGS/MAKELEVEL would leak the outer
    invocation's flags (and command-line variables) into every probe.
    """
    env = dict(os.environ)
    for k in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEFILES",
              "CONTRACT_DEFINES", "CONTRACT_ZP_DEFINES", "CA65FLAGS"):
        env.pop(k, None)
    return env


def make(work: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["make", "--no-print-directory", *args], cwd=work,
                          env=clean_env(), capture_output=True, text=True)


def ca65_objects(output: str) -> dict[str, str]:
    """Map object -> source from the ca65 lines in make's output."""
    out: dict[str, str] = {}
    for line in output.splitlines():
        m = CA65_LINE_RE.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def discover_includes(work: Path) -> dict[str, set[str]]:
    """source path -> set of header paths it includes, transitively."""
    direct: dict[str, set[str]] = {}

    def scan(rel: str) -> set[str]:
        if rel in direct:
            return direct[rel]
        direct[rel] = set()
        p = work / rel
        if not p.is_file():
            return direct[rel]
        for line in p.read_text(errors="replace").splitlines():
            m = INCLUDE_RE.match(line)
            if m:
                direct[rel].add(f"{SRC}/{m.group(1)}")
        return direct[rel]

    result: dict[str, set[str]] = {}
    for s in sorted((work / SRC).glob("*.s")):
        rel = f"{SRC}/{s.name}"
        seen: set[str] = set()
        stack = list(scan(rel))
        while stack:
            inc = stack.pop()
            if inc in seen:
                continue
            seen.add(inc)
            stack.extend(scan(inc))
        if seen:
            result[rel] = seen
    return result


def snapshot(d: Path) -> dict[str, tuple[int, int, bytes]]:
    snap = {}
    for p in sorted(d.rglob("*")):
        if p.is_file():
            st = p.stat()
            snap[str(p.relative_to(d))] = (st.st_size, st.st_mtime_ns,
                                           p.read_bytes() if p.name.endswith(".stamp") else b"")
    return snap


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="check_inc_deps_"))
    try:
        work = tmp / "tree"
        work.mkdir()
        # --makefile PATH substitutes a different Makefile into the copy:
        # how the negative test runs the check against the pre-fix file
        # without touching the working tree's own Makefile.
        mk = REPO / "Makefile"
        if len(sys.argv) == 3 and sys.argv[1] == "--makefile":
            mk = Path(sys.argv[2]).resolve()
        elif len(sys.argv) != 1:
            print("usage: check_inc_deps.py [--makefile PATH]", file=sys.stderr)
            return 2
        shutil.copy2(mk, work / "Makefile")
        shutil.copytree(REPO / SRC, work / SRC)
        shutil.copytree(REPO / "cfg", work / "cfg")
        return run(work)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run(work: Path) -> int:
    makefile = (work / "Makefile").read_text()

    # ---- leg 0: populations ---------------------------------------------
    includes = discover_includes(work)
    all_incs = sorted({i for s in includes.values() for i in s})
    print(f"[population] {len(includes)} source(s) with .include, "
          f"{len(all_incs)} header(s): {', '.join(all_incs)}")
    if not includes or not all_incs:
        fail("population", "no .include directive discovered in src/*.s -- "
             "the include scan examined nothing")
    for inc in all_incs:
        if not (work / inc).is_file():
            fail("population", f"{inc} is included but does not exist under {SRC}/")

    token_objs = sorted({f"{BUILD}/{n}.o" for n in OBJ_TOKEN_RE.findall(makefile)})
    dry = make(work, "-n", "-B", *PUBLIC_TARGETS, *token_objs)
    if dry.returncode != 0:
        fail("population", f"`make -n -B` over the public targets failed:\n{dry.stderr}")
    obj_src = ca65_objects(dry.stdout)
    print(f"[population] {len(obj_src)} object(s) mapped to a source "
          f"({len(token_objs)} named in the Makefile text)")
    if not obj_src:
        fail("population", "no ca65 recipe line parsed from `make -n -B` -- "
             "the object scan examined nothing")
    for o in token_objs:
        if o not in obj_src:
            fail("population", f"{o} is named in the Makefile but no ca65 line built it")

    by_src: dict[str, list[str]] = {}
    for o, s in obj_src.items():
        by_src.setdefault(s, []).append(o)

    inc_objs: dict[str, list[str]] = {}
    for s, incs in includes.items():
        objs = by_src.get(s, [])
        if not objs:
            fail("population", f"{s} includes {sorted(incs)} but the Makefile builds no object from it")
        for inc in incs:
            inc_objs.setdefault(inc, []).extend(objs)
    for inc in all_incs:
        if not inc_objs.get(inc):
            fail("population", f"{inc} maps to no built object")
    n_edges = sum(len(v) for v in inc_objs.values())
    print(f"[population] {n_edges} header->object edge(s) to verify")

    if failures:
        return report()

    objs = sorted(obj_src)

    # ---- leg 1b: dry-run classifier -------------------------------------
    cls_bad = 0
    for mf, want in CLASSIFIER_ROWS:
        r = make(work, "print-dry-classify", f"MAKEFLAGS_UNDER_TEST={mf}")
        m = DRY_RE.search(r.stdout)
        if not m:
            cls_bad += 1
            fail("classifier", f"MAKEFLAGS={mf!r}: no MAKE_DRY_RUN line printed -- "
                 f"the print-dry-classify seam is missing")
            continue
        got = bool(m.group(1))
        if got != want:
            cls_bad += 1
            fail("classifier", f"MAKEFLAGS={mf!r} classified "
                 f"{'DRY' if got else 'REAL'} (MAKE_DRY_RUN=[{m.group(1)}]), "
                 f"expected {'DRY' if want else 'REAL'}")
    for flags, want in CLASSIFIER_REAL:
        for extra in ([], ["--no-print-directory"]):
            r = subprocess.run(["make", *extra, *flags, "print-dry-classify"], cwd=work,
                               env=clean_env(), capture_output=True, text=True)
            m = DRY_RE.search(r.stdout)
            got = bool(m and m.group(1))
            if not m or got != want:
                cls_bad += 1
                fail("classifier", f"real `make {' '.join(extra + flags)}` classified "
                     f"{'DRY' if got else 'REAL'} (line: {m.group(0) if m else None}), "
                     f"expected {'DRY' if want else 'REAL'}")
    if not cls_bad:
        print(f"[classifier] PASS: {len(CLASSIFIER_ROWS)} seam row(s) + "
              f"{2 * len(CLASSIFIER_REAL)} real-flag row(s) classified correctly")

    # ---- leg 1: precondition --------------------------------------------
    build = make(work, *PUBLIC_TARGETS, *objs)
    if build.returncode != 0:
        fail("precondition", f"full build failed:\n{build.stdout[-2000:]}\n{build.stderr[-2000:]}")
        return report()
    q = make(work, "-q", *objs)
    if q.returncode != 0:
        fail("precondition", f"`make -q` reports objects out of date right after a full build "
             f"(exit {q.returncode}); legs 2-3 would prove nothing")
        return report()
    print(f"[precondition] PASS: {len(objs)} object(s) up to date after full build")

    # ---- leg 2: control (-W on the .s) -----------------------------------
    for s, s_objs in sorted(by_src.items()):
        r = make(work, "-n", "-W", s, *s_objs)
        rebuilt = set(ca65_objects(r.stdout))
        missing = sorted(set(s_objs) - rebuilt)
        if missing:
            fail("control", f"-W {s} did not reassemble {missing} -- the probe is broken")
    if not any(f.startswith("[control]") for f in failures):
        print(f"[control] PASS: -W <source> reassembles its objects ({len(by_src)} source(s))")

    # ---- leg 3: header dependencies -------------------------------------
    leg3_ok = True
    for inc in all_incs:
        want = sorted(set(inc_objs[inc]))
        r = make(work, "-n", "-W", inc, *want)
        rebuilt = set(ca65_objects(r.stdout))
        missing = [o for o in want if o not in rebuilt]
        if missing:
            leg3_ok = False
            fail("inc-deps", f"touching {inc} leaves {len(missing)}/{len(want)} object(s) "
                 f"up to date: {', '.join(missing)}")
        else:
            print(f"[inc-deps] PASS: {inc} -> {len(want)} object(s) reassembled")
    if leg3_ok:
        print("[inc-deps] PASS")

    # ---- leg 3b: the Makefile itself ------------------------------------
    # Recipe flags live in the Makefile; editing them must reassemble.
    r = make(work, "-n", "-W", "Makefile", *objs)
    missing = [o for o in objs if o not in set(ca65_objects(r.stdout))]
    if missing:
        fail("makefile-dep", f"touching Makefile leaves {len(missing)}/{len(objs)} object(s) "
             f"up to date (e.g. {', '.join(missing[:5])})")
    else:
        print(f"[makefile-dep] PASS: touching Makefile reassembles all {len(objs)} object(s)")

    # ---- leg 4: clean ----------------------------------------------------
    bdir = work / BUILD
    stamp = bdir / ".contract-defines.stamp"

    def stamp_text() -> str | None:
        return stamp.read_text() if stamp.is_file() else None

    # 4a. A corrupt .d must not break the recovery target. `make clean` is
    # what a user reaches for when the build dir is wrong; if it cannot parse
    # the Makefile it cannot recover anything.
    (bdir / "fp256.o.d").write_text("garbage\n")
    c = make(work, "clean")
    if c.returncode != 0:
        fail("corrupt-d", f"`make clean` with a corrupt build/fp256.o.d failed "
             f"(exit {c.returncode}): {c.stderr.strip()[-300:]}")
    else:
        print("[corrupt-d] PASS: `make clean` succeeds over a corrupt .d")
    # Remove the plant ourselves if clean could not, so one red leg does not
    # cascade into every leg after it.
    (bdir / "fp256.o.d").unlink(missing_ok=True)
    if c.returncode != 0:
        make(work, "clean")

    # 4b. Nothing the build makes survives clean -- EXCEPT the knob stamp,
    # which must survive (see 4c).
    leftovers = []
    if bdir.is_dir():
        for p in sorted(bdir.rglob("*")):
            if p.is_dir() and p.name == "lib":
                leftovers.append(str(p.relative_to(work)) + "/")
            elif p.is_file() and (p.suffix in (".o", ".d", ".prg", ".dbg", ".a")
                                  or (p.name.startswith("labels") and p.suffix == ".txt")):
                leftovers.append(str(p.relative_to(work)))
    if leftovers:
        fail("clean", f"`make clean` left {len(leftovers)} build artefact(s): {', '.join(leftovers)}")
    elif stamp_text() is None:
        fail("clean", "`make clean` deleted the knob stamp -- the next build will "
             "treat 'no stamp' as a knob change and reassemble everything twice")
    else:
        print("[clean] PASS: no build artefacts survive `make clean`; knob stamp kept")

    # 4c. `make clean all` followed by `make all` must be a no-op. With the
    # stamp deleted by clean, the second build re-invalidated and reassembled
    # every TU.
    ca = make(work, "clean", "all")
    q = make(work, "-q", "all")
    if ca.returncode != 0:
        fail("clean-all", f"`make clean all` failed: {ca.stderr.strip()[-300:]}")
    elif q.returncode != 0:
        fail("clean-all", "`make clean all` then `make -q all` reports out of date -- "
             "the next `make all` would reassemble everything")
    else:
        print("[clean-all] PASS: `make all` after `make clean all` is a no-op")

    # 4d. `clean` with CHANGED knobs is a non-build goal: it must not rewrite
    # the stamp (a later build with these knobs must still see the change).
    s0 = stamp_text()
    make(work, "clean", "CONTRACT_DEFINES=-D LIB_NISTCURVES_REU_SETTLE_ITER=7")
    if stamp_text() != s0:
        fail("nonbuild", f"`make clean` with changed knobs rewrote the stamp "
             f"{s0!r} -> {stamp_text()!r}")
    else:
        print("[nonbuild] PASS: `make clean` with changed knobs left the stamp alone")

    # ---- leg 5: dry run is side-effect free -----------------------------
    b2 = make(work, "lib", "all")
    if b2.returncode != 0:
        fail("dry-run", f"rebuild before dry-run probe failed:\n{b2.stderr[-2000:]}")
        return report()
    # What a real `make lib` would reassemble from scratch: the -n probe must
    # show ALL of it, not merely "something".
    need_lib = set(ca65_objects(make(work, "-n", "-B", "lib").stdout))
    if not need_lib:
        fail("dry-run", "`make -n -B lib` lists no objects -- nothing to compare against")
    before = snapshot(bdir)
    if not any(k.endswith(".o") for k in before):
        fail("dry-run", "no objects present before the probe -- nothing to protect")

    def sizes(snap):
        return {k: (v[0], v[2]) for k, v in snap.items()}

    # A DIFFERENT knob value per probe: if one probe wrongly rewrites the
    # stamp, the next must still see a changed knob rather than a match.
    probes = (("-n", "CONTRACT_DEFINES=-D LIB_NO_BARE_EXPORTS=1"),
              ("-q", "CONTRACT_DEFINES=-D LIB_SHARED_SQTAB_BASE=0xA000"),
              ("-t", "CONTRACT_DEFINES=-D LIB_NISTCURVES_REU_SETTLE_ITER=5"))
    for flag, knob in probes:
        r = make(work, flag, "lib", knob)
        after = snapshot(bdir)
        # -t legitimately bumps mtimes; it must not delete, empty or rewrite.
        same = (sizes(after) == sizes(before)) if flag == "-t" else (after == before)
        if not same:
            gone = sorted(set(before) - set(after))
            changed = sorted(k for k in set(before) & set(after)
                             if (sizes(before)[k] != sizes(after)[k] if flag == "-t"
                                 else before[k] != after[k]))
            fail("dry-run", f"`make {flag}` with changed CONTRACT_DEFINES mutated build/: "
                 f"{len(gone)} file(s) deleted (e.g. {gone[:4]}), "
                 f"{len(changed)} changed (e.g. {changed[:4]})")
        else:
            print(f"[dry-run] PASS: `make {flag}` with changed knobs left build/ intact")
        before = after
        # Side-effect free must not mean lying: a changed knob makes every
        # object stale, so -n must show EVERY reassembly and -q must say no.
        if flag == "-n":
            shown = set(ca65_objects(r.stdout))
            missing = sorted(need_lib - shown)
            if missing:
                fail("dry-run", f"`make -n lib` with changed knobs hides {len(missing)}/"
                     f"{len(need_lib)} reassembly line(s) a real run would do "
                     f"(e.g. {', '.join(missing[:5])})")
        if flag == "-q" and r.returncode == 0:
            fail("dry-run", "`make -q` with changed knobs answered up to date")

    # Every goal that builds nothing must leave build/ alone under changed
    # knobs. PINNED here, not read from the Makefile's NON_BUILD_GOALS: a
    # goal dropped from that list must turn this red, not shrink the probe.
    # (clean is probed in 4d.) In this throwaway tree tools/ is absent, so
    # the python-backed goals fail fast after parsing -- the parse is where
    # the invalidation lives, and nothing can recurse.
    for i, goal in enumerate(sorted(NON_BUILD_PINNED - {"clean"})):
        make(work, goal, f"CONTRACT_DEFINES=-D LIB_NONBUILD_PROBE_{i}=1")
        after = snapshot(bdir)
        if after != before:
            gone = sorted(set(before) - set(after))
            changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
            fail("nonbuild", f"`make {goal}` with changed knobs mutated build/: "
                 f"{len(gone)} deleted (e.g. {gone[:4]}), {len(changed)} changed (e.g. {changed[:4]})")
            before = after
        else:
            print(f"[nonbuild] PASS: `make {goal}` with changed knobs left build/ untouched")

    # ---- leg 6: a REAL build with changed knobs still invalidates --------
    # Legs 5 must not be bought by disabling the stamp: the real run must
    # reassemble every object it needs and record the new knobs.
    knob = "CONTRACT_DEFINES=-D LIB_NO_BARE_EXPORTS=1"
    r = make(work, "lib", knob)
    rebuilt = set(ca65_objects(r.stdout))
    stamp = (bdir / ".contract-defines.stamp")
    stamp_txt = stamp.read_text() if stamp.is_file() else ""
    if r.returncode != 0:
        fail("real-run", f"`make lib` with changed knobs failed:\n{r.stderr[-1500:]}")
    elif len(rebuilt) < 10 or "LIB_NO_BARE_EXPORTS" not in stamp_txt:
        fail("real-run", f"`make lib` with changed knobs reassembled {len(rebuilt)} object(s) "
             f"and left the stamp as {stamp_txt!r} -- the knob invalidation is gone")
    else:
        print(f"[real-run] PASS: changed knobs reassembled {len(rebuilt)} object(s), stamp updated")

    return report()


def report() -> int:
    if failures:
        print(f"\ncheck-inc-deps: {len(failures)} failure(s)")
        for f in failures:
            print(f"  {f}")
        return 1
    print("\ncheck-inc-deps: all legs PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
