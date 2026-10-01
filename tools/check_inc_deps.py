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

Two related defects of the same Makefile ride along:

* `make clean` left the variant test PRGs (`nist-curves-{onchip,nocomb,
  onchip-nocomb}.prg`) and their `labels_*` files behind.
* The CONTRACT_DEFINES staleness stamp ran its wipe and stamp write at
  *parse* time, so `make -n` deleted the tree and `make -t` recorded the
  new knobs then touched 0-byte artifacts that the next build shipped
  (issue #180). The Makefile now only COMPARES at parse time; the wipe and
  stamp write are the recipe of a phony `knobs-changed` prerequisite, so
  make itself decides whether they run, whatever route its flags took.

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
                   object of every public target; `-q` must answer "stale".
   nonbuild     -- every goal in NON_BUILD_PINNED leaves build/ untouched
                   under changed knobs.
5c. routes      -- real invocations down every route by which flags reach
                   make, judged by outcome (dry: build/ unchanged; touch:
                   nothing deleted/resized, stamp unchanged; real: every
                   object reassembled, archive non-empty, stamp updated --
                   and after dry/touch, the next real build reassembles):
                   env MAKEFLAGS under `make -e` (env-e), command-line
                   MAKEFLAGS (cmdline-makeflags), MAKEFLAGS set inside a
                   MAKEFILES file or an include-wrapper (makeflags-file),
                   MFLAGS defined by a makefile (mflags-file), and the
                   legitimate routes: `$(MAKE) -C` sub-makes under
                   -n/-t/-k/--no-print-directory, the `MAKEFLAGS=` clearing
                   idiom, `-C`, `-j4` (wipe precedes every ca65), and
                   c64-https's `make -s -C <dir> lib-p256-verify` with ZP
                   defines.
5g. partial-failure -- a build that fails part-way (one TU rejects the
                   knob) leaves no old-knob object beside the new stamp,
                   and a retry fails again instead of "Nothing to be done".
5i. force-coverage -- for every object of every public target, every
                   archive and every PRG, `make -n <t>` with changed knobs
                   prints the knob wipe (deterministic; names the output).
   force-direct -- the same 90 outputs, read from make's database
                   (`make -p -q check-release-state`): each must be found,
                   and each must list knobs-changed as a DIRECT
                   prerequisite (archives/PRGs pass the -n rows only
                   transitively, yet the direct edge is load-bearing).
5j. wipe-order  -- with build/ read-only the wipe fails; the retry with the
                   same knob must reassemble everything and the archive must
                   lack bare LIB_VERSION_MAJOR -- pins wipe BEFORE stamp.
5h. artifact-flip -- with the PRG future-dated (a same-second reassembly),
                   a knob still flips the PRG and reverting restores it
                   (issue #144).
5d. q-paths     -- `make -q` on all 12 archives and 4 PRGs: 0 with
                   unchanged knobs, 1 with changed knobs.
6. real-run     -- a real `make lib` with changed knobs reassembles and
                   records the new knobs.

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
import hashlib
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
# Pinned here, not parsed from the Makefile: a goal that started to depend on
# a knob-dependent output (and so on `knobs-changed`) must turn a leg red.
NON_BUILD_PINNED = {"clean", "dist", "check-harness-routing", "check-release-notes",
                    "check-release-state", "check-inc-deps"}

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
              "CONTRACT_DEFINES", "CONTRACT_ZP_DEFINES", "CA65FLAGS",
              "GNUMAKEFLAGS"):
        env.pop(k, None)
    return env


def make(work: Path, *args: str, env_extra: dict[str, str] | None = None,
         ) -> subprocess.CompletedProcess:
    env = clean_env()
    env.update(env_extra or {})
    return subprocess.run(["make", "--no-print-directory", *args], cwd=work,
                          env=env, capture_output=True, text=True)


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
    bdir = work / BUILD
    stamp = bdir / ".contract-defines.stamp"

    def stamp_text() -> str | None:
        return stamp.read_text() if stamp.is_file() else None

    # 4a. A corrupt .d must not break the recovery target. `make clean` is
    # what a user reaches for when the build dir is wrong; if it cannot parse
    # the Makefile it cannot recover anything.
    # Every other goal that builds nothing must at least PARSE over it too
    # (the tools behind the check-* goals are absent from this tree, so only
    # the parse is judged).
    (bdir / "fp256.o.d").write_text("garbage\n")
    for goal in sorted(NON_BUILD_PINNED - {"clean"}):
        g = make(work, goal)
        if "missing separator" in g.stderr:
            fail("corrupt-d", f"`make {goal}` with a corrupt build/fp256.o.d does not "
                 f"parse: {g.stderr.strip()[-160:]}")
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
    # What a real build of every public target would reassemble: the -n probe
    # must show ALL of it, not merely "something".
    need_all = set(ca65_objects(make(work, "-n", "-B", *PUBLIC_TARGETS).stdout))
    if not need_all:
        fail("dry-run", "`make -n -B <public targets>` lists no objects -- nothing to compare against")
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
        r = make(work, flag, *(PUBLIC_TARGETS if flag == "-n" else ["lib"]), knob)
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
            missing = sorted(need_all - shown)
            if missing:
                fail("dry-run", f"`make -n <public targets>` with changed knobs hides {len(missing)}/"
                     f"{len(need_all)} reassembly line(s) a real run would do "
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

    # ---- leg 5c: every route by which flags reach make (issues #178/#180) -
    # The Makefile does not classify flags; make decides whether the
    # knobs-changed recipe runs. These probes drive real invocations down
    # every route found so far and judge only the OUTCOME:
    #   dry   -- build/ byte-for-byte unchanged (file set, sizes, mtimes,
    #            stamp); the next real build with the same knobs still
    #            reassembles everything.
    #   touch -- nothing deleted or resized, stamp unchanged; the next real
    #            build with the same knobs reassembles everything into a
    #            non-empty archive (issue #180's 0-byte archive).
    #   real  -- the run itself reassembles every object of the goal, yields
    #            a non-empty archive, and records the new knobs.
    # "Reassembled" is read from object mtimes, not from output, so a `-s`
    # route is judged the same way.
    goal_archive = {"lib": bdir / "lib" / "nistcurves.a",
                    "lib-p256-verify": bdir / "lib" / "nistcurves-p256-verify.a"}
    need = {g: set(ca65_objects(make(work, "-n", "-B", g).stdout)) for g in goal_archive}
    for g, n in need.items():
        if not n:
            fail("routes", f"`make -n -B {g}` lists no objects -- nothing to judge")
    knob_seq = iter(range(1000))
    wrapper = work / "wrap_submake.mk"
    # `sub` hands the knobs down the way make does (command-line variables
    # travel in MAKEFLAGS); `subclr` uses the flag-clearing idiom, which
    # drops them, so it passes CONTRACT_DEFINES explicitly.
    wrapper.write_text(
        ".PHONY: sub subclr\n"
        f"sub: ; $(MAKE) -C {work} lib\n"
        f"subclr: ; $(MAKE) -C {work} lib MAKEFLAGS= \"CONTRACT_DEFINES=$(CONTRACT_DEFINES)\"\n")
    incl = work / "wrap_include.mk"
    incl.write_text("include Makefile\nMAKEFLAGS += -t\n")

    def reassembled(before, goal):
        after = snapshot(bdir)
        return {o for o in need[goal]
                if o.removeprefix(BUILD + "/") not in before
                or after.get(o.removeprefix(BUILD + "/"), (0, 0))[1]
                != before[o.removeprefix(BUILD + "/")][1]}

    def judge_real(leg, desc, before, goal, knob_name, rc, err):
        got = reassembled(before, goal)
        art = goal_archive[goal]
        size = art.stat().st_size if art.is_file() else -1
        missing = sorted(need[goal] - got)
        if rc != 0 or missing or size <= 0 or knob_name not in (stamp_text() or ""):
            fail(leg, f"{desc}: exit {rc}, {len(missing)}/{len(need[goal])} object(s) "
                 f"not reassembled (e.g. {missing[:3]}), {art.name} {size} B, "
                 f"stamp {stamp_text()!r}; {err.strip()[-160:]!r}")
            return False
        return True

    def route(leg, desc, argv, mode, goal="lib", env_extra=None):
        i = next(knob_seq)
        knob_name = f"LIB_ROUTE_PROBE_{i}"
        knob = f"CONTRACT_DEFINES=-D {knob_name}=1"
        env = clean_env()
        env.update(env_extra or {})
        argv = [a.replace("@KNOB@", knob) for a in argv]
        before = snapshot(bdir)
        s0 = stamp_text()
        r = subprocess.run(argv, cwd=work, env=env, capture_output=True, text=True)
        after = snapshot(bdir)
        ok = True
        if mode == "real":
            ok = judge_real(leg, desc, before, goal, knob_name, r.returncode, r.stderr)
        else:
            gone = sorted(set(before) - set(after))
            resized = sorted(k for k in set(before) & set(after) if before[k][0] != after[k][0])
            moved = sorted(k for k in set(before) & set(after) if before[k] != after[k])
            if gone or resized or stamp_text() != s0 or (mode == "dry" and moved):
                ok = False
                fail(leg, f"{desc} ({mode}): {len(gone)} deleted (e.g. {gone[:3]}), "
                     f"{len(resized)} resized (e.g. {resized[:3]}), {len(moved)} changed, "
                     f"stamp {s0!r} -> {stamp_text()!r}")
            before2 = snapshot(bdir)
            r2 = make(work, goal, knob)
            ok = judge_real(leg, f"after {desc}, the next real `make {goal}` with the same "
                            f"knobs", before2, goal, knob_name, r2.returncode, r2.stderr) and ok
        if ok:
            print(f"[{leg}] PASS: {desc} ({mode})")

    # env MAKEFLAGS under -e reaches parse time raw; make still obeys it.
    for mf, mode in (("--t", "touch"), ("--dr", "dry"), ("--que", "dry"),
                     ("-ntx", "touch"), ("--touch", "touch"), ("--just-print", "dry")):
        route("env-e", f"env MAKEFLAGS={mf!r} `make -e lib`",
              ["make", "-e", "lib", "@KNOB@"], mode, env_extra={"MAKEFLAGS": mf})
    # A command-line MAKEFLAGS is obeyed by 3.81.
    for mf, mode in (("t", "touch"), ("-t", "touch"), ("--t", "touch"),
                     ("kt", "touch"), ("n", "dry"), ("", "real")):
        route("cmdline-makeflags", f"`make lib MAKEFLAGS={mf}`",
              ["make", "lib", f"MAKEFLAGS={mf}", "@KNOB@"], mode)
    # MAKEFLAGS set INSIDE a makefile: obeyed after parsing, invisible to any
    # parse-time look at the flags.
    for label, text in (("+= -t", "MAKEFLAGS += -t\n"), (":= t", "MAKEFLAGS := t\n")):
        mfile = work.parent / f"makeflags_{label[0]}.mk"
        mfile.write_text(text)
        route("makeflags-file", f"MAKEFILES with `MAKEFLAGS {label}`",
              ["make", "lib", "@KNOB@"], "touch", env_extra={"MAKEFILES": str(mfile)})
    route("makeflags-file", "wrapper `include Makefile` + `MAKEFLAGS += -t`",
          ["make", "-f", str(incl), "lib-p256-verify", "@KNOB@"], "touch",
          goal="lib-p256-verify")
    # MFLAGS forged by a makefile: irrelevant to the build, which is real.
    for label, text in (("file", "MFLAGS := -n\n"), ("override", "override MFLAGS := -n\n")):
        mfile = work.parent / f"mflags_{label}.mk"
        mfile.write_text(text)
        route("mflags-file", f"MAKEFILES with `{text.strip()}`",
              ["make", "lib", "@KNOB@"], "real", env_extra={"MAKEFILES": str(mfile)})
    # Legitimate routes.
    for flags, mode in (([], "real"), (["-n"], "dry"), (["-t"], "touch"), (["-k"], "real"),
                        (["--no-print-directory", "-n"], "dry")):
        route("routes", f"`make {' '.join(flags)} -f wrapper sub` ($(MAKE) -C sub-make)",
              ["make", *flags, "-f", str(wrapper), "sub", "@KNOB@"], mode)
    route("routes", "`$(MAKE) -C ... lib MAKEFLAGS=` (flag-clearing idiom)",
          ["make", "-f", str(wrapper), "subclr", "@KNOB@"], "real")
    route("routes", "`make -C <tree> -n lib`", ["make", "-C", str(work), "-n", "lib", "@KNOB@"], "dry")
    route("routes", "`make -j4 lib`", ["make", "-j4", "lib", "@KNOB@"], "real")
    route("routes", "c64-https `make -s -C <dir> lib-p256-verify` + ZP defines",
          ["make", "-s", "-C", str(work), "lib-p256-verify", "@KNOB@",
           "CONTRACT_ZP_DEFINES=-D nistcurves_zp_ptr2=0x60"], "real", goal="lib-p256-verify")

    # -j4 ordering: the wipe must complete before any object recipe runs.
    knob = "CONTRACT_DEFINES=-D LIB_J4_ORDER_PROBE=1"
    r = make(work, "-j4", *PUBLIC_TARGETS, knob)
    lines = r.stdout.splitlines()
    rm_at = next((i for i, ln in enumerate(lines) if ln.startswith(f"rm -f {BUILD}/*.o ")), None)
    first_ca65 = next((i for i, ln in enumerate(lines) if CA65_LINE_RE.match(ln.strip())), None)
    if r.returncode != 0 or rm_at is None or first_ca65 is None or rm_at > first_ca65:
        fail("routes", f"`make -j4` over every public target with changed knobs: exit "
             f"{r.returncode}, wipe at line {rm_at}, first ca65 at line {first_ca65} -- "
             f"the wipe must precede every assembly")
    else:
        print(f"[routes] PASS: -j4 over every public target -- wipe (line {rm_at}) "
              f"precedes the first ca65 (line {first_ca65})")

    # ---- leg 5g: a build that fails part-way cannot strand an old object -
    # Backdate every object, then build with a knob one TU rejects
    # (LIB_SHARED_SQTAB_BASE must be page-aligned: mul_8x8.s's .assert). No
    # backdated (old-knob) object may survive beside the new stamp, and a
    # retry with the same knob must fail again rather than answer "Nothing
    # to be done".
    past = 1_000_000_000
    for p in bdir.glob("*.o"):
        os.utime(p, (past, past))
    bad_knob = "CONTRACT_DEFINES=-D LIB_SHARED_SQTAB_BASE=0x9C01"
    r1 = make(work, "-k", "lib", bad_knob)
    survivors = sorted(p.name for p in bdir.glob("*.o") if p.stat().st_mtime < past + 10)
    r2 = make(work, "lib", bad_knob)
    if r1.returncode == 0:
        fail("partial-failure", "the bad-knob build succeeded -- the probe failed nothing")
    elif survivors:
        fail("partial-failure", f"after a failed build, {len(survivors)} old-knob object(s) "
             f"survive beside stamp {stamp_text()!r} (e.g. {survivors[:4]})")
    elif r2.returncode == 0:
        fail("partial-failure", "a retry with the same bad knob exited 0 -- the failed "
             "build was recorded as done")
    else:
        print("[partial-failure] PASS: failed build left no old-knob object; retry fails again")

    # ---- leg 5i: every knob-dependent output is forced (deterministic) ---
    # For every object of every public target, every archive and every PRG,
    # `make -n <target>` with changed knobs must print the knob wipe. An
    # output left off the KNOB_FORCE list (or an object list whose variable
    # name stops matching *_OBJS / *_OBJECTS) is named here exactly, instead
    # of surfacing only as a -j4 race.
    wipe = f"rm -f {BUILD}/*.o "
    full = make(work, *PUBLIC_TARGETS)
    if full.returncode != 0:
        fail("force-coverage", f"full build failed: {full.stderr.strip()[-300:]}")
    targets = sorted(need_all) + [str(a.relative_to(work)) for a in sorted(
        (bdir / "lib").glob("*.a"))] + [str(p.relative_to(work)) for p in sorted(bdir.glob("*.prg"))]
    if len([t for t in targets if t.endswith(".a")]) != 12 or \
            len([t for t in targets if t.endswith(".prg")]) != 4:
        fail("force-coverage", f"expected 12 archives + 4 PRGs present, found "
             f"{[t for t in targets if not t.endswith('.o')]}")
    unforced = [t for t in targets
                if not any(ln.startswith(wipe) for ln in
                           make(work, "-n", t, "CONTRACT_DEFINES=-D DET=1").stdout.splitlines())]
    if unforced:
        fail("force-coverage", f"{len(unforced)}/{len(targets)} output(s) not forced by a knob "
             f"change (`make -n <t>` prints no wipe): {', '.join(unforced)}")
    else:
        print(f"[force-coverage] PASS: all {len(targets)} output(s) (objects, archives, "
              f"PRGs) are forced by a knob change")

    # The -n rows above pass TRANSITIVELY for archives and PRGs (their member
    # objects are forced), yet the DIRECT prerequisite is load-bearing: 3.81
    # caches an artifact's mtime before the wipe runs, so an artifact without
    # it is neither relinked nor present after a knob change (exit 0). Read
    # make's database (a non-building goal under -q: nothing runs) and require
    # `knobs-changed` among each target's own prerequisites.
    before_db = snapshot(bdir)
    db = make(work, "-p", "-q", "check-release-state", "CONTRACT_DEFINES=-D DET=1").stdout
    if snapshot(bdir) != before_db:
        fail("force-direct", "`make -p -q` mutated build/")
    files = db.split("\n# Files\n", 1)[-1].split("\n# files hash-table stats", 1)[0]
    direct: dict[str, set[str]] = {}
    for ln in files.splitlines():
        m = re.match(r"^([^#\s:][^:=]*?):{1,2}(?!=)\s*(.*)$", ln)
        if m:
            normal = m.group(2).split("|", 1)[0].split()
            for tgt in m.group(1).split():
                direct.setdefault(tgt, set()).update(normal)
    absent = [t for t in targets if t not in direct]
    no_direct = [t for t in targets if t in direct and "knobs-changed" not in direct[t]]
    if absent:
        fail("force-direct", f"{len(absent)}/{len(targets)} target(s) not found in make's "
             f"database -- the parse examined nothing for them: {', '.join(absent[:6])}")
    if no_direct:
        fail("force-direct", f"{len(no_direct)}/{len(targets)} output(s) lack a DIRECT "
             f"knobs-changed prerequisite: {', '.join(no_direct)}")
    if not absent and not no_direct:
        print(f"[force-direct] PASS: all {len(targets)} output(s) found in make's database, "
              f"each with knobs-changed as a direct prerequisite")

    # ---- leg 5j: wipe BEFORE stamp write -- a failed wipe cannot strand ---
    # If the stamp were written before the delete, a delete that fails
    # (read-only build/) would leave stamp == new beside old-knob objects,
    # and the retry would relink them silently. Deterministic: make build/
    # read-only so the rm fails; the stamp FILE stays writable, so only the
    # recipe's order decides. The retry must reassemble everything and the
    # archive's export surface must match the knob (LIB_NO_BARE_EXPORTS=1:
    # no bare LIB_VERSION_MAJOR).
    def bare_exports(arc: Path) -> int:
        """Count of bare LIB_VERSION_MAJOR exports in arc's lib_version.o."""
        if not arc.is_file():
            return -1
        with tempfile.TemporaryDirectory() as xd:
            subprocess.run(["ar65", "x", str(arc.resolve()), "lib_version.o"], cwd=xd,
                           capture_output=True)
            dump = subprocess.run(["od65", "--dump-exports", "lib_version.o"], cwd=xd,
                                  capture_output=True, text=True).stdout
        return len(re.findall(r'Name:\s*"LIB_VERSION_MAJOR"', dump))

    rb = make(work, "lib")
    archive = goal_archive["lib"]
    bare0 = bare_exports(archive)
    knob = "CONTRACT_DEFINES=-D LIB_NO_BARE_EXPORTS=1"
    mode = bdir.stat().st_mode
    try:
        os.chmod(bdir, mode & ~0o222)
        r1 = make(work, "lib", knob)
    finally:
        os.chmod(bdir, mode)
    before = snapshot(bdir)
    r2 = make(work, "lib", knob)
    got = reassembled(before, "lib")
    missing = sorted(need["lib"] - got)
    bare = bare_exports(archive)
    if rb.returncode != 0 or r1.returncode == 0 or bare0 != 1:
        fail("wipe-order", f"setup: base build exit {rb.returncode} with {bare0} bare "
             f"LIB_VERSION_MAJOR export(s) (want 1: the probe's positive control), "
             f"read-only-build/ run exit {r1.returncode} (expected the wipe to fail)")
    elif r2.returncode != 0 or missing or bare != 0:
        fail("wipe-order", f"after a failed wipe, the retry with the same knob: exit "
             f"{r2.returncode}, {len(missing)}/{len(need['lib'])} object(s) not "
             f"reassembled (e.g. {missing[:3]}), bare LIB_VERSION_MAJOR exports in "
             f"nistcurves.a = {bare} (want 0), stamp {stamp_text()!r}")
    else:
        print(f"[wipe-order] PASS: failed wipe -> retry reassembled {len(got)} object(s); "
              f"archive has no bare LIB_VERSION_MAJOR")

    # ---- leg 5h: the LINKED artifact flips (issue #144) -------------------
    # The PRG's mtime is pushed into the future before each knob change, as
    # a same-second reassembly would leave it: only a forced relink can
    # produce the new knob's PRG.

    def prg_after(knob):
        prg = bdir / "nist-curves.prg"
        if prg.is_file():
            fut = prg.stat().st_mtime + 3600
            os.utime(prg, (fut, fut))
        r = make(work, "all", *([knob] if knob else []))
        return hashlib.sha256(prg.read_bytes()).hexdigest() if r.returncode == 0 and prg.is_file() else None

    h0 = prg_after(None)
    h1 = prg_after("CONTRACT_DEFINES=-D LIB_SHARED_SQTAB_BASE=0xA000")
    h2 = prg_after(None)
    if None in (h0, h1, h2) or h1 == h0 or h2 != h0:
        fail("artifact-flip", f"PRG sha default {str(h0)[:12]} -> sqtab knob {str(h1)[:12]} "
             f"-> default {str(h2)[:12]}: the knob must flip the PRG and reverting must "
             f"restore it")
    else:
        print(f"[artifact-flip] PASS: PRG {h0[:12]} -> {h1[:12]} -> {h2[:12]} "
              f"despite a future-dated PRG")

    # ---- leg 5d: -q on every shipped artifact path (issue #180 point 3) --
    # With changed knobs, `make -q <artifact>` must answer "stale" (exit 1)
    # for every archive and PRG, so a consumer's `make -q x || make lib`
    # cannot keep a stale archive. Control: unchanged knobs answer 0.
    full = make(work, *PUBLIC_TARGETS)
    if full.returncode != 0:
        fail("q-paths", f"full build before -q probe failed: {full.stderr[-500:]}")
    arts = sorted((bdir / "lib").glob("*.a")) + sorted(bdir.glob("*.prg"))
    n_a = sum(1 for a in arts if a.suffix == ".a")
    n_p = sum(1 for a in arts if a.suffix == ".prg")
    if n_a != 12 or n_p != 4:
        fail("q-paths", f"expected 12 archives + 4 PRGs, found {n_a} + {n_p}")
    q_bad = 0
    for a in arts:
        rel = str(a.relative_to(work))
        c = make(work, "-q", rel).returncode
        s = make(work, "-q", rel, "CONTRACT_DEFINES=-D LIB_Q_PATH_PROBE=1").returncode
        if c != 0 or s != 1:
            q_bad += 1
            fail("q-paths", f"`make -q {rel}`: unchanged knobs exit {c} (want 0), "
                 f"changed knobs exit {s} (want 1)")
    pkg = [p for p in (bdir / "lib" / "nistcurves.inc",
                       bdir / "lib" / "sqtab_base.inc",
                       bdir / "lib" / "cfg" / "nistcurves-example.cfg") if p.is_file()]
    pkg_q = {str(p.relative_to(work)):
             make(work, "-q", str(p.relative_to(work)),
                  "CONTRACT_DEFINES=-D LIB_Q_PATH_PROBE=1").returncode for p in pkg}
    if not q_bad and arts:
        print(f"[q-paths] PASS: {n_a} archive(s) + {n_p} PRG(s) answer -q 0 unchanged / "
              f"1 with changed knobs; packaging copies (knob-independent, verbatim) "
              f"answer {pkg_q}")

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
