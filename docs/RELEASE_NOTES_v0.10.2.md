# c64-nist-curves v0.10.2 — post-wave conformance + ratchet hardening

**Released:** 2026-08-15
**Tarball:** `c64-nist-curves-v0.10.2.tar.gz` (233,905 bytes)
**SHA256:** `6670bc52d62f24b594dfd6245101c04cef09defec47c3d9e4e14ada5f2ebd407`

PATCH release. `build/nist-curves.prg` is **byte-identical** to v0.10.0/v0.10.1
(`18701274…`, 37480 B); no exported symbol is added, removed, or renamed;
`LIB_NISTCURVES_ABI_VERSION` stays **2**. Bundles the post-wave SPEC
conformance work (v0.10.0 §6.6/§6.7 through v0.10.3) and two new standing
ratchets.

## Footprint deltas, per (profile × variant) — SPEC §6.6 obligation

| archive | profile | `RESIDENT_BYTES` | `COLD_BYTES` |
|---|---|---:|---:|
| `nistcurves-p384-sha384.a` | — | 9000 → **9216** (+216) | 0 (unchanged) |
| `nistcurves-p256-verify-onchip.a` | onchip | 8700 (unchanged) | 240 → **250** (+10) |
| `nistcurves-p384-verify-onchip.a` | onchip | 8300 (unchanged) | 240 → **250** (+10) |
| all other archives | — | unchanged | unchanged |

Both movements are §6.6 safe-direction corrections, not content changes — the
archives' bytes did not move. The old values were round-to-tens artifacts
erring **below** the measured sums (9000 < 9001 measured; 240 < 243 measured),
which is the unsafe direction now that §6.6 defines the consumer contract as
`declared ≤ budget ⟹ actual ≤ budget`. The sha384 value takes the fleet's
next-256-boundary convention; the onchip COLD values keep fine granularity
because the 256-boundary would breach §5's ±5% at that size. A §6.6 fit check
(`declared ≤ budget`) **cannot falsely pass** from these — but it can newly
refuse: a budget inside the new headroom band (9001–9215 B for
`p384-sha384`'s region, 243–249 B for the onchip COLD pair's) goes from
passing to **refused at link**, despite the archive genuinely fitting. That is
the known false-refusal cost of safe-direction round-up, in the safe
direction. If you hit it, loosen the budget to the declared value — the equate
is doing its job.

## What else is in this release

- **§6.7 window guard hardened** (SPEC v0.10.2): the sqtab-window link guard
  now obtains its base **source-level** from the new single shared include
  `src/sqtab_base.inc`, instead of importing `sqtab_lo` — a gated export whose
  scheduled removal at the next MAJOR would have silently disabled the guard.
  Re-proven under all three v0.10.2 conditions, including the new constraint 3
  (fires in **every** configuration that places the table — default and
  `FP_ONCHIP_MUL`).
- **R2 ZP audit as a standing ratchet** (issue #113): every `make
  check-archives` now unions the exported ZP slot *addresses* per variant arm,
  compares against that arm's `ZP_USAGE_BYTES`, and validates that every
  address shared by two exported names is exactly an intended bare→canonical
  §6.5 pair — the case total-only comparison cannot see. The gated
  (`-D LIB_NO_BARE_EXPORTS=1`) build of each arm is audited too. Negative-
  tested against all three drift modes. With this, the fleet's R2 scoreboard
  is complete: x25519 ✅ · polyval ✅ · chacha ✅ · nist ✅.
- **§1 version-identity check**: `check-archives` compares the `VERSION` file
  against all three components read from the built `lib_version.o` — the
  mechanical fix for the v0.10.0 self-misreport.
- **§6.6 consumer footprint-assert worked example** in API.md §8.6.1, covered
  by `make check-docs` so it links against the shipped objects.
- **§8.4 references**: live docs cite the catch-loop clause by its real
  heading (SPEC v0.10.3 promoted it in place).
- **Documentation currency**: CLAUDE.md's adoption paragraph now states the
  actual v0.10.3 surface; PRG size and target count corrected.
- **Tarball completeness**: `src/sqtab_base.inc` added to the release archive
  list (a tarball cut between #111 and this fix would have failed a consumer
  build on the `.include`) — caught by the step-0 pre-tag validation.

## Upgrading from v0.10.1

Every entry point, export, and buffer layout is unchanged. One link-visible
case: a §6.6 fit check whose budget lies inside the new headroom bands
(9001–9215 B against `p384-sha384`, 243–249 B against the onchip-verify COLD
pair) will newly refuse — loosen the budget to the declared value. All other
consumers: no action. Pin **v0.10.2**.

## Verification

- PRG byte-identical to v0.10.1: `18701274…`, 37480 B.
- All ten archives build; `make check-archives` PASS — now including the §1
  identity check, the R2 ZP alias audit, the gated surface, cfg placement,
  and per-archive value pins. `make check-docs` PASS.
- Tarball reproducible across two independent `make dist` runs.
- Worktree-rebuild byte-identity at the tag: PASS (fresh worktree: PRG
  `18701274…` identical; check-archives PASS inside it).
- **Tarball builds standalone**: extracted to a scratch directory, `make`
  produces the byte-identical PRG — completeness proven by construction, not
  by listing. (The first artifact build caught the #115 tarball fix having
  landed in a comment rather than the archive list; the finding check is now
  re-run after every such fix.)
