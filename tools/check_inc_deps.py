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
4. clean        -- after building every PRG and archive, `make clean`
                   leaves no *.o, *.d, *.prg, labels*.txt, *.dbg, stamp or
                   lib/.
5. dry-run      -- `make -n`, `make -q`, and a goal that builds nothing
                   (`make dist` with no VERSION), each with CHANGED
                   CONTRACT_DEFINES, leave build/ exactly as they found it
                   (file set, sizes, mtimes, stamp contents); `-n` must
                   still print the rebuild and `-q` must answer "stale".
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

INCLUDE_RE = re.compile(r'^\s*\.include\s+"([^"]+)"', re.IGNORECASE)
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
    c = make(work, "clean")
    if c.returncode != 0:
        fail("clean", f"`make clean` failed:\n{c.stderr}")
    bdir = work / BUILD
    leftovers = []
    if bdir.is_dir():
        for p in sorted(bdir.rglob("*")):
            if p.is_dir() and p.name == "lib":
                leftovers.append(str(p.relative_to(work)) + "/")
            elif p.is_file() and (p.suffix in (".o", ".d", ".prg", ".dbg", ".a", ".stamp")
                                  or (p.name.startswith("labels") and p.suffix == ".txt")):
                leftovers.append(str(p.relative_to(work)))
    if leftovers:
        fail("clean", f"`make clean` left {len(leftovers)} build artefact(s): {', '.join(leftovers)}")
    else:
        print("[clean] PASS: no build artefacts survive `make clean`")

    # ---- leg 5: dry run is side-effect free -----------------------------
    b2 = make(work, "lib", "all")
    if b2.returncode != 0:
        fail("dry-run", f"rebuild before dry-run probe failed:\n{b2.stderr[-2000:]}")
        return report()
    before = snapshot(bdir)
    if not any(k.endswith(".o") for k in before):
        fail("dry-run", "no objects present before the probe -- nothing to protect")
    # A DIFFERENT knob value per probe: if one probe wrongly rewrites the
    # stamp, the next must still see a changed knob rather than a match.
    # The third probe is a goal that builds nothing (`dist` without VERSION
    # exits at its usage check): it must not invalidate build/ either.
    probes = (("-n", "CONTRACT_DEFINES=-D LIB_NO_BARE_EXPORTS=1", "lib"),
              ("-q", "CONTRACT_DEFINES=-D LIB_SHARED_SQTAB_BASE=0xA000", "lib"),
              ("dist", "CONTRACT_DEFINES=-D LIB_NISTCURVES_REU_SETTLE_ITER=9", "dist"))
    for flag, knob, goal in probes:
        args = [goal, knob] if flag == goal else [flag, goal, knob]
        r = make(work, *args)
        after = snapshot(bdir)
        if after != before:
            gone = sorted(set(before) - set(after))
            changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
            fail("dry-run", f"`make {flag}` with changed CONTRACT_DEFINES mutated build/: "
                 f"{len(gone)} file(s) deleted (e.g. {gone[:4]}), "
                 f"{len(changed)} changed (e.g. {changed[:4]})")
            before = after
        else:
            print(f"[dry-run] PASS: `make {flag}` with changed knobs left build/ untouched")
        # Side-effect free must not mean lying: a changed knob still makes
        # every object stale, so -n must show reassembly and -q must say no.
        if flag == "-n" and not ca65_objects(r.stdout):
            fail("dry-run", "`make -n` with changed knobs printed no reassembly -- "
                 "the dry run hides the rebuild a real run would do")
        if flag == "-q" and r.returncode == 0:
            fail("dry-run", "`make -q` with changed knobs answered up to date")

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
