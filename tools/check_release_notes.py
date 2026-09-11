#!/usr/bin/env python3
"""Reject a self-referential tarball hash in the current release notes.

Issue #147. `docs/RELEASE_NOTES_<tag>.md` ships INSIDE the release tarball, so
any SHA256 or byte size those notes claim about that tarball is computed over a
document that does not yet contain the claim. The number is therefore wrong the
moment it is written, and it stays wrong however carefully the release is run:
v0.12.0 carried a stale pair through four rounds of correction, two reviews and
a re-cut, because a wrong hash is the one value in the document whose wrongness
is invisible to a reader. A consumer verifying a download against it concludes
the tarball is corrupt or tampered with -- the worst direction for the error to
point.

The remedy is structural rather than procedural: the hash lives in the
`<tarball>.sha256` sidecar that `tools/build_release.sh` emits, and in the
GitHub Release body, neither of which is inside the hashed artifact. This check
keeps the claim out of the notes, so the "fill in the SHA256" release step
cannot be forgotten -- there is no longer a step to forget.

Scoped to notes from v0.13.0 on, where the convention changed. Earlier notes
keep whatever they say -- v0.12.0's pair is correct as published (verified
against the release asset: 269,692 bytes, 4d635e1f...), and rewriting history
would be churn. What v0.12.0 gets instead is an erratum recording that the
values at the *tag* are the stale pre-#145 pair, so the tag/master divergence
is documented rather than rediscovered.

Negative test: add a `**SHA256:** <64 hex>` line to the current notes and this
check goes red naming that line.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A hash claim is what we forbid; prose that merely mentions the word is fine,
# so match a bolded field label followed by something hash- or size-shaped.
SHA_CLAIM = re.compile(r"^\s*\*\*SHA-?256:?\*\*\s*`?([0-9a-fA-F]{64})`?", re.M)
SIZE_CLAIM = re.compile(r"^\s*\*\*Tarball:?\*\*.*\(\s*[\d,]+\s*bytes\s*\)", re.M)

# A fill-me-in placeholder that survived into the notes. v0.15.0's notes
# carried `REPLACE_TARBALL_SIZE` / `REPLACE_TARBALL_SHA` from the pre-v0.13.0
# convention, when the release procedure still had a "fill in the SHA256"
# step. #147 removed that step precisely so it could not be forgotten -- but
# the placeholders it left behind are an invitation to re-add the self-
# reference by hand, and the two claim patterns above cannot see them because
# a placeholder is not hash-shaped. Caught here instead.
PLACEHOLDER = re.compile(r"^.*\bREPLACE_[A-Z_]+\b.*$", re.M)

# The release where the hash moved out of the notes and into the sidecar.
CONVENTION_FROM = (0, 13, 0)


def _parse(v):
    return tuple(int(x) for x in v.split("."))


def main() -> int:
    version = (ROOT / "VERSION").read_text().strip()
    notes = ROOT / "docs" / f"RELEASE_NOTES_v{version}.md"

    print(f"=== release-notes self-reference check (VERSION={version}) ===")

    if _parse(version) < CONVENTION_FROM:
        print(f"  v{version} predates the v0.13.0 sidecar convention -- not checked")
        return 0

    if not notes.exists():
        # Not a failure: the notes are written during the release, and this
        # check runs on every `make check-docs` including mid-cycle.
        print(f"  no {notes.relative_to(ROOT)} yet -- nothing to check")
        return 0

    text = notes.read_text()
    failures = []

    for m in SHA_CLAIM.finditer(text):
        line = text[: m.start()].count("\n") + 1
        failures.append(
            f"{notes.relative_to(ROOT)}:{line}: claims a SHA256 for the tarball "
            f"these notes ship inside -- self-referential, can never be correct. "
            f"Publish it from the .sha256 sidecar instead (issue #147)."
        )

    for m in SIZE_CLAIM.finditer(text):
        line = text[: m.start()].count("\n") + 1
        failures.append(
            f"{notes.relative_to(ROOT)}:{line}: claims a byte size for the tarball "
            f"these notes ship inside -- same self-reference (issue #147)."
        )

    for m in PLACEHOLDER.finditer(text):
        line = text[: m.start()].count("\n") + 1
        failures.append(
            f"{notes.relative_to(ROOT)}:{line}: unfilled release placeholder "
            f"-- {m.group(0).strip()!r}. Since v0.13.0 the tarball hash and "
            f"size are NOT quoted in the notes at all (issue #147); they live "
            f"in the .sha256 sidecar and the GitHub Release body. Delete the "
            f"placeholder rather than filling it -- filling it is what this "
            f"gate's other two legs reject."
        )

    if failures:
        print("RELEASE NOTES CHECK: FAIL")
        for f in failures:
            print("  - " + f)
        return 1

    print(f"  {notes.relative_to(ROOT)} makes no self-referential tarball claim")
    print("RELEASE NOTES CHECK: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
