# c64-nist-curves v0.11.2 — knob-staleness guard; conformant through SPEC v0.10.6

**Released:** 2026-08-15
**Tarball:** `c64-nist-curves-v0.11.2.tar.gz` (SIZE_PLACEHOLDER bytes)
**SHA256:** `SHA256_PLACEHOLDER`

PATCH release. `build/nist-curves.prg` is **byte-identical** to v0.10.0
through v0.11.1 (`18701274…`, 37480 B); no exported symbol changes;
`LIB_NISTCURVES_ABI_VERSION` stays **2**. Aligns the library to the three
same-day upstream SPEC clarifications (v0.10.4 → v0.10.6, themselves
driven by this library's issues #117/#123).

## Knob-staleness guard (SPEC v0.10.5 §6.3 looks-reachable rule)

A make re-invocation with a changed `CONTRACT_DEFINES` /
`CONTRACT_ZP_DEFINES` value used to reuse every stale object and exit 0
with an artifact other than the one requested — the v0.10.5 shape-3
"silent no-op", measured live during the issue #123 repro (`make
lib-p256-verify-onchip CONTRACT_DEFINES=…` answered "Nothing to be
done"). The Makefile now records the flattened knob string in a
parse-time content stamp (`build/.contract-defines.stamp`): a changed
value invalidates every object and archive — the knobs reach every TU,
so all genuinely are stale — while an unchanged value stays fully
incremental. `make check-archives` gains a defines-staleness leg driving
the real make flow (default → changed knob takes effect → revert →
unchanged re-run does not rebuild), negative-tested with the guard
disabled.

**Consumer-visible behavior change (intended):** invoking a `make lib*`
target with a different `CONTRACT_*DEFINES` value than the previous
invocation now triggers a full object rebuild instead of silently
reusing objects built under the old defines. If your integration scripts
alternate define sets, expect the rebuild — the previous behavior was
shipping you the wrong archive.

## Conformance baseline: SPEC v0.10.6, verified clause-by-clause

- **v0.10.4** (member-set axes take a §6.1 target): discharged by
  v0.11.0's `lib-p256-comb` pair — recorded as such upstream.
- **v0.10.5** (looks-reachable rule + checkability note): the staleness
  gap above was our one exposure; our verification gates already use the
  ruling's valid comparands (linked PRG and od65 structural dumps —
  never archive bytes, which carry `ca65` `OPT_DATETIME` stamps).
- **v0.10.6** (§8.3 provider-surface enumeration + gating corollary):
  v0.11.1's issue #123 fix is exactly the prescribed shape — five-symbol
  surface exported by owning archives, imported where referenced by the
  deferring TU; the other three deferral switches un-define nothing that
  archived code references.

## Upgrading from v0.11.1

No symbol, archive-member, or manifest changes. Pin **v0.11.2**. The only
observable difference is the intended rebuild-on-knob-change above.

## Verification

- PRG byte-identical to v0.11.1: `18701274…`, 37480 B.
- `make check-archives` PASS (12 archives; §1 identity at 0.11.2; new
  defines-staleness leg). `make check-docs` PASS.
- Tarball reproducible across two independent `make dist` runs.
- Worktree-rebuild byte-identity at the tag: WORKTREE_PLACEHOLDER
- Tarball builds standalone: TARBALL_BUILD_PLACEHOLDER
