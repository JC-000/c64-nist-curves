#!/usr/bin/env python3
"""Gate: unreleased work must never pile on top of an untagged release.

Why this exists
---------------
This actually happened, and it is invisible from inside any single file.

`v0.15.0` was fully prepared on a branch — `VERSION` bumped to `0.15.0`,
the `src/lib_version.s` equates bumped, `docs/RELEASE_NOTES_v0.15.0.md`
written, the CHANGELOG `## [0.15.0]` section written — and that branch was
then never PR'd and never tagged.  A later tooling branch was cut from it
by mistake, so an unrelated PR carried the release commit onto `master`.
Master now *declares* `VERSION=0.15.0` while no `v0.15.0` tag exists, and
`[Unreleased]` has since accumulated tooling work sitting **on top of** a
release that was never cut.

Every individual artifact is self-consistent, which is why nothing caught
it: `VERSION`, the equates, the notes and the CHANGELOG section all agree
with each other.  The defect lives in the relationship between the working
tree and the *tag namespace*, and only a check that looks at both sees it.

The consequence is not cosmetic.  Once `[Unreleased]` holds work, cutting
`v0.15.0` from the current tree ships that work under a version whose
release notes do not describe it, and the notes are what a consumer reads
to decide whether to pin.  The alternative — renumbering to `0.16.0` —
silently retires a version number that the CHANGELOG, the notes file and
four version equates all claim exists.  Both outcomes are worse the later
they are discovered.

The invariant
-------------
Let ``X`` be the contents of ``VERSION``.

* The release metadata for ``X`` must be complete or absent as a unit: a
  ``## [X]`` CHANGELOG section **and** ``docs/RELEASE_NOTES_vX.md``.  Half
  of it is a release that was started and abandoned, so the check names
  which half is missing.
* If tag ``vX`` **exists**, ``X`` has shipped and the tree is in normal
  development.  ``[Unreleased]`` may hold anything.  Pass.
* If tag ``vX`` does **not** exist, a release is in flight.
  ``[Unreleased]`` MUST be empty — anything in it is work that landed on
  top of an uncut release.  FAIL, naming what is in there.

What "empty" means here: no content lines between ``## [Unreleased]`` and
the next ``## [`` heading.  Bare ``### Added`` / ``### Changed`` skeleton
subheadings with no entries under them do not count as content — a
scaffold is not unreleased work.  A single bullet does.

Legs
----
0. self-test  -- the section parser, the version parser and the tag probe,
                 each against positive AND negative controls
1. version    -- VERSION exists and parses as MAJOR.MINOR.PATCH
2. metadata   -- CHANGELOG `## [X]` section and RELEASE_NOTES_vX.md, as a unit
3. inflight   -- if tag vX is absent, `[Unreleased]` must be empty
4. equates    -- src/lib_version.s VERSION_MAJOR/_MINOR/_PATCH match VERSION

Leg 4 is a **fast pre-check, not the source of truth.**  ``make
check-archives`` pins the same three equates from the *built objects* (via
``od65``), which is the authoritative gate: it sees the value the linker
will actually hand a consumer, whereas this leg only reads the source
text.  Leg 4 exists so a mismatch is caught in under a second without a
build, and it should never be cited as evidence on its own.

Every leg carries a control so a green result cannot mean "the detector
found nothing because it examines nothing" (see the seven green-but-empty
shapes in .claude/agents/adversarial-reviewer.md lane 4).  The shape most
dangerous here is the second one: a CHANGELOG heading-regex that stops
matching makes leg 3 conclude "`[Unreleased]` is empty" and pass, which is
exactly backwards.  Hence the parser controls in leg 0 and the
population assertions (a CHANGELOG with sections, a non-empty tag list).

Exit 0 on pass, 1 on any failure.  No device, no VICE, no network, no
build.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent

CHANGELOG = REPO / "CHANGELOG.md"
VERSION_FILE = REPO / "VERSION"
LIB_VERSION = REPO / "src" / "lib_version.s"

#: A CHANGELOG release heading. Anchored at `## ` so a `### ` subheading
#: and a trailing `[0.15.0]: https://...` link reference are both excluded
#: -- either would silently truncate a section body and turn leg 3 green.
#: `re.M` is load-bearing for the population control, which `findall`s over
#: the whole document -- without it the anchor binds to the start of the
#: text and the control reported "0 sections parsed" on a healthy CHANGELOG.
#: `section_body` matches line by line and is unaffected either way.
RE_SECTION = re.compile(r"^##\s+\[([^\]]+)\]", re.M)

#: A bare subsection scaffold: `### Added` and nothing else on the line.
#: Dropped from a section body before deciding emptiness.
#:
#: The vocabulary and the `$` anchor are both load-bearing. This was
#: `^#{3,}\s*\S`, which dropped ANY line starting with `###` -- so an entry
#: written as a heading rather than a bullet made `[Unreleased]` read as
#: empty. That is not hypothetical: the v0.15.0 fold itself used
#: `### Tooling — device-traffic altitude (no library change)` as a
#: content heading, so the gate was blind to exactly the idiom this repo
#: writes. Restricting to the Keep-a-Changelog headings, with nothing
#: after them, makes "scaffold" mean scaffold.
RE_SUBHEAD = re.compile(
    r"^#{3,}\s*(?:Added|Changed|Deprecated|Removed|Fixed|Security|Notes)\s*$"
)

#: The three source equates. `.s` comments start with `;`, and the file's
#: own header quotes these names inside comments (a worked `.assert`
#: example), so the pattern requires the assignment form at line start.
RE_EQUATE = re.compile(
    r"^\s*LIB_NISTCURVES_VERSION_(MAJOR|MINOR|PATCH)\s*=\s*(\d+)", re.M
)

RE_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


# --------------------------------------------------------------------------
# Parsers (exercised by leg 0 before they are trusted by legs 2-4)
# --------------------------------------------------------------------------

def section_body(text: str, label: str) -> list[str] | None:
    """Lines under `## [label]`, up to the next `## [` heading.

    Returns None if no such section exists -- distinct from an existing but
    empty section, which returns []. Conflating the two is what would let a
    renamed heading read as "nothing unreleased".
    """
    lines = text.splitlines()
    start = None
    for n, line in enumerate(lines):
        m = RE_SECTION.match(line)
        if m is None:
            continue
        if start is None and m.group(1) == label:
            start = n
        elif start is not None:
            return lines[start + 1 : n]
    if start is None:
        return None
    return lines[start + 1 :]


def content_lines(body: list[str]) -> list[str]:
    """Real entries in a section body: blanks and bare scaffolds dropped."""
    return [l for l in body if l.strip() and not RE_SUBHEAD.match(l)]


class NoGitRepo(Exception):
    """Raised when the tag namespace cannot be read at all.

    This file ships inside the release tarball, which is an extracted
    directory with no ``.git`` and no tags. Leg 3's whole question is
    "does tag vX exist", so outside a repository it has no answer —
    and answering "no" would be the worst of the three options: it
    would report a shipped, tagged release as "in flight". The check
    says so and skips the leg, rather than raising CalledProcessError
    and printing a traceback where it is otherwise careful to produce
    a diagnostic.
    """


def _git_tags(pattern: str | None = None) -> list[str]:
    cmd = ["git", "-C", str(REPO), "tag", "--list"]
    if pattern is not None:
        cmd.append(pattern)
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise NoGitRepo(out.stderr.strip() or "git tag --list failed")
    return [t for t in out.stdout.split() if t]


def tag_exists(tag: str) -> bool:
    return bool(_git_tags(tag))


def all_tags() -> list[str]:
    return _git_tags()


# --------------------------------------------------------------------------
# Leg 0 controls
# --------------------------------------------------------------------------

_CL_WITH_WORK = """\
# Changelog

## [Unreleased]

### Added
- a thing that has not shipped

## [0.14.0] — 2026-09-06
- shipped
"""

_CL_EMPTY = """\
# Changelog

## [Unreleased]

## [0.14.0] — 2026-09-06
- shipped
"""

_CL_SCAFFOLD = """\
# Changelog

## [Unreleased]

### Added
### Changed

## [0.14.0] — 2026-09-06
- shipped
"""

_CL_LAST_SECTION = """\
# Changelog

## [0.14.0] — 2026-09-06
- shipped

## [Unreleased]
- trailing work
"""

_CL_DECOYS = """\
# Changelog

## [Unreleased]

### [Unreleased] not a release heading
Some prose mentioning ## [Unreleased] inline.

## [0.14.0] — 2026-09-06
- shipped

[Unreleased]: https://example.invalid/compare/v0.14.0...HEAD
[0.14.0]: https://example.invalid/releases/tag/v0.14.0
"""


def _self_test() -> list[str]:
    """Positive AND negative controls for every parser a leg depends on."""
    bad: list[str] = []

    def check(name: str, got, want) -> None:
        if got != want:
            bad.append(
                f"parser self-test FAILED: {name} returned {got!r}, "
                f"expected {want!r} -- every leg using it is now vacuous"
            )

    def body(text: str, label: str) -> list[str]:
        """section_body, but a rotted heading regex reports rather than raises.

        Negative-testing this file by breaking RE_SECTION produced a
        TypeError out of content_lines(None) instead of the diagnostic that
        says what broke. A check that crashes does exit non-zero, but it
        tells the reader nothing about which detector rotted -- and the
        rotted-regex case is precisely the one where leg 3 would otherwise
        conclude "nothing unreleased" and pass.
        """
        b = section_body(text, label)
        if b is None:
            bad.append(
                f"parser self-test FAILED: section_body(..., {label!r}) found "
                f"no such section in a control document that definitely "
                f"contains one -- RE_SECTION has rotted, and leg 3 would read "
                f"every CHANGELOG as having nothing unreleased"
            )
            return []
        return b

    # The section parser must distinguish absent / empty / non-empty.
    check("section_body(missing label)",
          section_body(_CL_EMPTY, "9.9.9"), None)
    check("content_lines(unreleased with work)",
          content_lines(body(_CL_WITH_WORK, "Unreleased")),
          ["- a thing that has not shipped"])
    check("content_lines(empty unreleased)",
          content_lines(body(_CL_EMPTY, "Unreleased")), [])
    check("content_lines(scaffold-only unreleased)",
          content_lines(body(_CL_SCAFFOLD, "Unreleased")), [])
    # Unreleased as the final section must not read as empty just because
    # no later `## [` heading terminates it.
    check("content_lines(unreleased last in file)",
          content_lines(body(_CL_LAST_SECTION, "Unreleased")),
          ["- trailing work"])
    # Neither a `###` subheading, inline prose, nor a link reference may
    # open or close a section -- each would truncate the body and turn
    # leg 3 falsely green. The `###` decoy carries prose, so it is CONTENT
    # and must survive: only a bare Keep-a-Changelog heading is scaffold.
    # (This expectation previously dropped it, which is how a permissive
    # RE_SUBHEAD hid a real bypass -- an entry written as a heading read as
    # an empty section.) The prose line surviving proves the section was
    # NOT truncated at it, and the absence of the `[0.14.0]: https://...`
    # link reference proves the body stopped at the real `## [0.14.0]`
    # heading rather than running to end of file.
    check("content_lines(decoy headings and link refs)",
          content_lines(body(_CL_DECOYS, "Unreleased")),
          ["### [Unreleased] not a release heading",
           "Some prose mentioning ## [Unreleased] inline."])
    # The bypass this gate shipped with, pinned: an entry written as a
    # `###` heading rather than a bullet is CONTENT, not scaffold. The
    # v0.15.0 fold used exactly this idiom ("### Tooling — ..."), so a
    # permissive rule was blind to the repo's own writing style.
    check("content_lines(prose-bearing ### is content)",
          content_lines(body(
              "## [Unreleased]\n\n### Added: a real entry, ABI-affecting\n\n"
              "## [0.1.0] — 2020-01-01\n- old\n", "Unreleased")),
          ["### Added: a real entry, ABI-affecting"])
    # ...and the converse, so the fix cannot be "count everything".
    check("content_lines(bare scaffold is still dropped)",
          content_lines(body(
              "## [Unreleased]\n\n### Added\n### Fixed\n\n"
              "## [0.1.0] — 2020-01-01\n- old\n", "Unreleased")),
          [])
    # Known and deliberate limitation, asserted so it cannot drift: trailing
    # `[x]: https://...` link references fall inside the body of whichever
    # section is LAST in the file. Harmless here -- `[Unreleased]` is first
    # in this repo's CHANGELOG, so leg 3 never sees them -- but if the file
    # is ever reordered so `[Unreleased]` is last, leg 3 would read those
    # link refs as unreleased work and fail loudly rather than quietly.
    check("content_lines(last section absorbs trailing link refs)",
          content_lines(body(_CL_DECOYS, "0.14.0")),
          ["- shipped",
           "[Unreleased]: https://example.invalid/compare/v0.14.0...HEAD",
           "[0.14.0]: https://example.invalid/releases/tag/v0.14.0"])
    # A released section is still found by label.
    check("section_body(release label)",
          content_lines(body(_CL_WITH_WORK, "0.14.0")), ["- shipped"])

    # The equate parser, against the real assignment form and against the
    # commented `.assert` example in the same file that must NOT match.
    check("RE_EQUATE(assignment)",
          RE_EQUATE.findall("LIB_NISTCURVES_VERSION_MINOR = 15\n"),
          [("MINOR", "15")])
    check("RE_EQUATE(comment)",
          RE_EQUATE.findall(
              ";   .assert LIB_NISTCURVES_VERSION_MAJOR = 0, lderror\n"), [])

    # The version parser.
    check("RE_VERSION(good)",
          bool(RE_VERSION.match("0.15.0")), True)
    check("RE_VERSION(tag-shaped)",
          bool(RE_VERSION.match("v0.15.0")), False)

    # The tag probe, round-tripped against a tag that really exists and one
    # that cannot. Without this, leg 3's "tag absent" branch could be the
    # verdict of a probe that answers False to everything.
    try:
        tags = all_tags()
    except NoGitRepo as exc:
        # Not a repository (the release tarball is one). Leg 3 is skipped
        # by main(); say so here rather than letting the controls below
        # report a vacuous probe as a defect.
        return bad + [f"SKIP: tag namespace unreadable ({exc})"]
    if not tags:
        bad.append(
            "population is EMPTY: `git tag --list` returned no tags -- leg 3 "
            "would report every release as untagged for a reason that has "
            "nothing to do with the release state (shallow clone? no fetch?)"
        )
    else:
        if not tag_exists(tags[0]):
            bad.append(
                f"tag probe self-test FAILED: tag_exists({tags[0]!r}) is False "
                f"for a tag `git tag --list` just reported -- leg 3 is vacuous"
            )
        if tag_exists("v0.0.0-control-tag-that-must-not-exist"):
            bad.append(
                "tag probe self-test FAILED: tag_exists() returned True for a "
                "tag that cannot exist -- leg 3 would never fire"
            )
    return bad


# --------------------------------------------------------------------------

def main() -> int:
    failures: list[str] = []
    print("=== release-state check (no VICE, no device, no build) ===")

    # --- Leg 0: the parsers themselves ----------------------------------
    controls = _self_test()
    failures.extend(controls)

    # --- Leg 1: VERSION ---------------------------------------------------
    if not VERSION_FILE.exists():
        failures.append("VERSION is missing -- nothing else can be checked")
        print("\nFAIL:")
        for f in failures:
            print(f"  {f}")
        return 1
    version = VERSION_FILE.read_text().strip()
    if not RE_VERSION.match(version):
        failures.append(
            f"VERSION is {version!r}, not MAJOR.MINOR.PATCH -- the tag name "
            f"and the release-notes filename are derived from it"
        )
        print("\nFAIL:")
        for f in failures:
            print(f"  {f}")
        return 1

    tag = f"v{version}"
    notes = REPO / "docs" / f"RELEASE_NOTES_{tag}.md"
    text = CHANGELOG.read_text()

    # Population control: a CHANGELOG with no release sections at all would
    # make legs 2 and 3 report on nothing.
    sections = RE_SECTION.findall(text)
    if not sections:
        failures.append(
            f"population is EMPTY: no `## [...]` sections parsed from "
            f"{CHANGELOG.relative_to(REPO)} -- legs 2 and 3 examined nothing"
        )

    try:
        tagged = tag_exists(tag)
    except NoGitRepo as exc:
        print(f"  git tag {tag} : UNREADABLE -- {exc}")
        print(
            f"\nSKIP — leg 3 needs the tag namespace and this tree is not a\n"
            f"git repository (an extracted release tarball, most likely).\n"
            f"Legs 1, 2 and 4 ran and passed; the in-flight question is\n"
            f"unanswerable here and is NOT being reported as a pass."
        )
        return 0
    print(f"  VERSION        : {version}")
    print(f"  git tag {tag:<8}: {'present' if tagged else 'ABSENT (release in flight)'}")
    print(f"  changelog      : {len(sections)} section(s) parsed")
    print(f"  self-test      : {len(controls)} control failure(s) "
          f"across parser, equate, version and tag probes")

    # --- Leg 2: release metadata, complete or absent as a unit -----------
    section = section_body(text, version)
    have_section = section is not None
    have_notes = notes.exists()
    if have_section != have_notes:
        missing = (
            f"CHANGELOG has no `## [{version}]` section"
            if not have_section
            else f"{notes.relative_to(REPO)} does not exist"
        )
        present = (
            f"{notes.relative_to(REPO)} exists"
            if have_notes
            else f"CHANGELOG has a `## [{version}]` section"
        )
        failures.append(
            f"[metadata] release metadata for {version} is half-written: "
            f"{present}, but {missing}. Write the other half or roll VERSION "
            f"back -- a half-prepared release is how an uncut one hides."
        )
    elif not have_section:
        failures.append(
            f"[metadata] VERSION says {version} but there is no `## [{version}]` "
            f"CHANGELOG section and no {notes.relative_to(REPO)}. Either the "
            f"bump landed without its release metadata, or VERSION is ahead of "
            f"the work."
        )

    # --- Leg 3: the invariant --------------------------------------------
    unreleased = section_body(text, "Unreleased")
    if unreleased is None:
        failures.append(
            f"[inflight] {CHANGELOG.relative_to(REPO)} has no `## [Unreleased]` "
            f"section -- this check cannot tell whether work has piled up, so "
            f"treat its silence as unknown, not as a pass"
        )
    elif not tagged:
        entries = content_lines(unreleased)
        if entries:
            preview = "\n".join(f"      {l.strip()}" for l in entries[:12])
            more = "" if len(entries) <= 12 else \
                f"\n      ... and {len(entries) - 12} more line(s)"
            failures.append(
                f"[inflight] {version} is fully prepared (CHANGELOG section + "
                f"release notes) but tag {tag} does NOT exist, and "
                f"`[Unreleased]` holds {len(entries)} line(s) of work:\n"
                f"{preview}{more}\n"
                f"    That work landed ON TOP of an uncut release. Tagging "
                f"{tag} now would ship it under notes that do not describe it. "
                f"Either cut and tag {tag} from the commit that prepared it, or "
                f"roll the release forward (move the `## [{version}]` section's "
                f"content and `[Unreleased]` into a new version, renaming "
                f"{notes.relative_to(REPO)} and re-bumping VERSION and "
                f"src/lib_version.s)."
            )

    # --- Leg 4: source equates (fast pre-check; check-archives is truth) --
    equates = dict(RE_EQUATE.findall(LIB_VERSION.read_text()))
    want = dict(zip(("MAJOR", "MINOR", "PATCH"), RE_VERSION.match(version).groups()))
    for part, expected in want.items():
        got = equates.get(part)
        if got is None:
            failures.append(
                f"[equates] LIB_NISTCURVES_VERSION_{part} not found in "
                f"{LIB_VERSION.relative_to(REPO)} -- the pattern may have rotted"
            )
        elif got != expected:
            failures.append(
                f"[equates] LIB_NISTCURVES_VERSION_{part} = {got}, but VERSION "
                f"says {expected} (VERSION={version}). `make check-archives` is "
                f"the authoritative gate here (it reads the built object); this "
                f"is the same mismatch seen a build earlier."
            )

    if failures:
        print(f"\nFAIL — {len(failures)} finding(s):\n")
        for f in failures:
            print(f"  {f}")
        return 1

    if tagged:
        print(f"\nPASS — {version} is tagged; `[Unreleased]` is free to accumulate.")
    else:
        print(f"\nPASS — {version} is in flight and `[Unreleased]` is empty.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
