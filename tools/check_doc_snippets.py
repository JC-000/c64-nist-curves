#!/usr/bin/env python3
"""check_doc_snippets.py -- assemble the code blocks in the live docs.

Motivation
----------
Three defects of the same class have shipped and been fixed reactively:
`ca65 --asm-define` where ca65 wants `-D` (c64-lib-contract #50), `.if` on
an imported symbol (#73), and an `APP_OWNED` unresolved external (#100).
All three were copy-pasteable consumer instructions that had been read and
reviewed many times. Reading does not catch this class -- only running the
snippet does. This tool runs them.

Scope
-----
LIVE docs only: API.md, README.md, CLAUDE.md. CHANGELOG.md and
docs/RELEASE_NOTES_*.md are deliberately excluded -- they are frozen history,
and a snippet that was correct for v0.4.0 must not be rewritten to satisfy
today's toolchain.

What gets run
-------------
A fenced block whose info string starts with `asm` / `ca65` / `6502` is
assembled with ca65, VERBATIM. If it assembles, every symbol it imports is
resolved against the symbols the library actually exports -- that is what
catches a snippet importing a name that no longer exists.

Nothing is wrapped. The snippet is written to a .s file exactly as it appears
in the doc and handed to `ca65 --cpu 6502 -I src`. No `.setcpu`, no
`.segment`, no imports are supplied on its behalf. A snippet that does not
assemble on its own is the defect -- "the snippet did not declare what it
needs" is precisely the class above. (Measured when this policy was chosen:
of the 11 asm-tagged blocks then in the docs, 0 would have been rescued by a
scaffolding wrapper, so the wrapper bought nothing but hid the requirement.
ca65 supplies a default segment and takes the CPU from --cpu.)

Nothing is silently dropped
---------------------------
Every block lands in exactly one reported bucket:

  * assembled OK;
  * FAILED;
  * not assembly (sh, bash, make, text, ...) -- counted, listed by language;
  * untagged -- FAILS. An untagged block is precisely how an assembly snippet
    escapes checking, so these are reported individually rather than guessed
    at. The fix is a one-word info string;
  * opted out -- only via an explicit marker on the line before the fence,
    carrying a mandatory reason, and printed with that reason on every run.

Markers (must sit within the two lines above the opening fence):

    <!-- check-docs: skip reason="why this cannot be standalone" -->
    <!-- check-docs: external="app_sym_one, app_sym_two" -->

`external` declares imports the CONSUMER owns (an integration example naming
the caller's own symbols), so they are exempt from export resolution while a
mistyped library symbol still fails. A `check-docs:` comment that parses as
neither is itself an error -- a typo'd marker must not decay into "no marker".

Usage:  python3 tools/check_doc_snippets.py [--verbose]
        make check-docs
"""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"

# Live, maintained docs. NOT CHANGELOG.md / docs/RELEASE_NOTES_*.md -- those
# are frozen history and their snippets describe past releases.
LIVE_DOCS = ["API.md", "README.md", "CLAUDE.md"]

ASM_LANGS = {"asm", "ca65", "6502"}

FENCE_RE = re.compile(r"^(?P<fence>```+)(?P<info>[^\n]*)$")
MARKER_RE = re.compile(r"<!--\s*check-docs:(?P<rest>.*?)-->")
SKIP_RE = re.compile(r"^\s*skip\s+reason=\"(?P<reason>[^\"]+)\"\s*$")
EXTERNAL_RE = re.compile(r"^\s*external=\"(?P<syms>[^\"]+)\"\s*$")


class Block:
    def __init__(self, doc, line, info, body):
        self.doc = doc
        self.line = line
        self.info = info
        self.lang = info.split()[0].lower() if info.split() else ""
        self.body = body
        self.skip_reason = None
        self.external = set()
        self.bad_marker = None

    @property
    def where(self):
        return f"{self.doc}:{self.line}"


def parse_markers(block, lines, fence_idx):
    """Attach check-docs markers found just above the fence."""
    for back in (1, 2):
        idx = fence_idx - back
        if idx < 0:
            break
        line = lines[idx]
        m = MARKER_RE.search(line)
        if m:
            rest = m.group("rest")
            sm = SKIP_RE.match(rest)
            em = EXTERNAL_RE.match(rest)
            if sm:
                block.skip_reason = sm.group("reason")
            elif em:
                block.external = {s.strip() for s in em.group("syms").split(",") if s.strip()}
            else:
                block.bad_marker = line.strip()
            continue
        if line.strip():
            break


def extract(doc_path, doc_name):
    lines = doc_path.read_text().splitlines()
    blocks = []
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i].strip())
        if not m:
            i += 1
            continue
        info = m.group("info").strip()
        fence = m.group("fence")
        fence_idx = i
        start = i + 1
        body = []
        i += 1
        while i < len(lines):
            m2 = FENCE_RE.match(lines[i].strip())
            if m2 and not m2.group("info").strip() and len(m2.group("fence")) >= len(fence):
                break
            body.append(lines[i])
            i += 1
        i += 1
        b = Block(doc_name, start + 1, info, body)
        parse_markers(b, lines, fence_idx)
        blocks.append(b)
    return blocks


def sh(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def library_exports():
    """Every symbol exported by the library's own objects.

    Uses build/*.o -- the object set the standalone PRG links, which spans
    every module including the version / manifest / precalc equate TUs. That
    is the universe a consumer snippet may legitimately import from.
    """
    objs = sorted(BUILD.glob("*.o"))
    if not objs:
        return None
    names = set()
    for o in objs:
        _, out = sh(["od65", "--dump-exports", str(o)])
        names |= set(re.findall(r'Name:\s*"([^"]+)"', out))
    return names


def assemble(block, tmpdir):
    """Assemble the block verbatim. No wrapper, by policy (see module docstring)."""
    stem = f"{block.doc.replace('.', '_')}_{block.line}"
    spath = Path(tmpdir) / f"{stem}.s"
    opath = Path(tmpdir) / f"{stem}.o"
    spath.write_text("\n".join(block.body) + "\n")
    rc, out = sh(["ca65", "--cpu", "6502", "-I", str(ROOT / "src"),
                  "-o", str(opath), str(spath)])
    # Strip the tmp path so output is stable and readable.
    out = out.replace(str(spath), block.where)
    return rc, out, opath


IMPORT_RE = re.compile(r"^\s*\.import(?:zp)?\s+(?P<syms>.+)$", re.IGNORECASE)


def imports_of(obj, body):
    """Symbols the snippet imports.

    Two sources, unioned, because neither alone is complete:

      * od65 on the assembled object -- authoritative for what the code
        actually references;
      * the snippet text -- because ca65 DROPS an import that is never
        referenced, so a stale `.import` line naming a symbol the library no
        longer exports would otherwise assemble clean and slip through. That
        stale line is exactly the kind of rot this tool exists to catch.
    """
    _, out = sh(["od65", "--dump-imports", str(obj)])
    names = set(re.findall(r'Name:\s*"([^"]+)"', out))
    for raw in body:
        line = raw.split(";")[0]
        m = IMPORT_RE.match(line)
        if m:
            names |= {s.strip() for s in m.group("syms").split(",") if s.strip()}
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true",
                    help="print every block's disposition, not just failures")
    ap.add_argument("--doc", action="append", metavar="PATH",
                    help="check this doc instead of the live set "
                         "(repeatable; for testing the checker itself)")
    args = ap.parse_args()

    docs = args.doc if args.doc else LIVE_DOCS

    exports = library_exports()
    if exports is None:
        print("ERROR: no build/*.o found -- run `make` first "
              "(check-docs resolves snippet imports against the built objects)")
        return 2

    blocks = []
    for name in docs:
        p = ROOT / name
        if not p.exists():
            print(f"ERROR: live doc {name} not found")
            return 2
        blocks += extract(p, name)

    failures, opted_out, untagged, checked = [], [], [], []
    bad_markers = []
    non_asm = {}

    with tempfile.TemporaryDirectory() as tmp:
        for b in blocks:
            if b.bad_marker:
                bad_markers.append(b)
                continue
            if b.skip_reason is not None:
                opted_out.append(b)
                continue
            if not b.info:
                untagged.append(b)
                continue
            if b.lang not in ASM_LANGS:
                non_asm.setdefault(b.lang, []).append(b)
                continue

            rc, out, obj = assemble(b, tmp)
            if rc != 0:
                failures.append((b, "does not assemble", out.strip()))
                continue

            unknown = sorted(i for i in imports_of(obj, b.body)
                             if i not in exports and i not in b.external)
            if unknown:
                failures.append(
                    (b, "imports symbols the library does not export",
                     "\n".join(f"  {u}" for u in unknown)
                     + "\n  (if these are the consumer's own symbols, declare them:"
                       "\n   <!-- check-docs: external=\"...\" -->)"))
                continue
            checked.append(b)

    print(f"check_doc_snippets: {len(blocks)} fenced blocks across "
          f"{', '.join(docs)}")
    print(f"  assembled OK    : {len(checked)}")
    print(f"  FAILED          : {len(failures)}")
    print(f"  untagged (FAIL) : {len(untagged)}")
    print(f"  bad marker(FAIL): {len(bad_markers)}")
    print(f"  opted out       : {len(opted_out)}")
    print(f"  not assembly    : {sum(len(v) for v in non_asm.values())}"
          + (f"  ({', '.join(f'{k}={len(v)}' for k, v in sorted(non_asm.items()))})"
             if non_asm else ""))

    if opted_out:
        print("\nOpted out (explicit marker; listed every run so a skip stays visible):")
        for b in opted_out:
            print(f"  {b.where}  reason: {b.skip_reason}")

    if args.verbose:
        if checked:
            print("\nAssembled OK:")
            for b in checked:
                extra = f"  [external: {', '.join(sorted(b.external))}]" if b.external else ""
                print(f"  {b.where}  ({b.lang}){extra}")
        for lang, bs in sorted(non_asm.items()):
            print(f"\nNot assembly ({lang}):")
            for b in bs:
                print(f"  {b.where}")

    if bad_markers:
        print("\nMALFORMED check-docs MARKERS -- a typo'd marker must not "
              "decay into 'no marker':")
        for b in bad_markers:
            print(f"  {b.where}  {b.bad_marker}")

    if untagged:
        print("\nUNTAGGED BLOCKS -- add an info string (```sh / ```asm / ```text).")
        print("An untagged block is how an assembly snippet escapes checking,")
        print("so these fail rather than being guessed at:")
        for b in untagged:
            first = next((l for l in b.body if l.strip()), "")
            print(f"  {b.where}  first line: {first.strip()[:64]!r}")

    if failures:
        print("\nFAILURES:")
        for b, why, detail in failures:
            print(f"\n  {b.where} ({b.lang}) -- {why}")
            for line in detail.splitlines():
                print(f"    {line}")

    ok = not failures and not untagged and not bad_markers
    print("\nDOC SNIPPET CHECK: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
