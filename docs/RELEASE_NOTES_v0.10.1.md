# c64-nist-curves v0.10.1 — identity correction

**Released:** 2026-08-15
**Tarball:** `c64-nist-curves-v0.10.1.tar.gz` (SIZE_PLACEHOLDER bytes)
**SHA256:** `SHA256_PLACEHOLDER`

PATCH release, zero functional change. **Pin this tag instead of v0.10.0.**

---

## Why this release exists

`v0.10.0` ships content that self-reports as **0.10.1**:
`LIB_NISTCURVES_VERSION_PATCH = 1` carried over from v0.9.1 while the tag
name, `VERSION` file, tarball and release title all said 0.10.0. Caught by
c64-lib-contract #76's ref verification, which held the fleet's wave close on
it. A consumer gating on `PATCH = 0` against that tag fails at link; a tag
that misstates its own identity is exactly what SPEC §1 exists to prevent.

Per the fleet's tags-are-immutable convention (the v0.3.x precedent),
**v0.10.0 is documented as self-misreporting, not moved.** This tag's content
and name agree.

Root cause, stated plainly: a partial version bump (MINOR and ABI edited,
PATCH untouched) passed by a partial check — the release-prep "lockstep
verified" grep never printed the PATCH line, so the blind spot in the check
sat exactly over the bug.

## What changed

- `VERSION` file → 0.10.1, matching the equates v0.10.0 already shipped.
- **New §1 version-identity check in `make check-archives`**: the `VERSION`
  file is compared against all three components read from the **built**
  `lib_version.o` — total and mechanical, so a partial bump can no longer
  pass a partial reading. Negative-tested.

Nothing else. The PRG is byte-identical to v0.10.0 (`18701274…`, 37480 B);
every archive, export, and manifest value is unchanged. Everything in the
[v0.10.0 notes](RELEASE_NOTES_v0.10.0.md) — the namespace wave, ABI 2, the
gated zero-bare surface — applies to this tag verbatim.

## Upgrading

- From v0.9.1: follow the v0.10.0 notes, but pin **v0.10.1**.
- From v0.10.0: retag your pin; expect `LIB_NISTCURVES_VERSION_PATCH = 1`,
  which is now true of both the content *and* the tag name.

## Verification

- `make check-archives` PASS including the new identity check;
  `make check-docs` PASS.
- PRG byte-identical to v0.10.0.
- Tarball reproducible across two independent `make dist` runs.
- Worktree-rebuild byte-identity at the tag: WORKTREE_PLACEHOLDER.
