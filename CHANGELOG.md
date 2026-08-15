# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases: https://github.com/JC-000/c64-nist-curves/releases — tagged
releases track `MAJOR.MINOR.PATCH` and are the supported consumption
points for downstream projects (see `API.md` §8 for the integration
contract).

## [Unreleased]

### Fixed

- **The sqtab window guard no longer depends on a doomed export**
  (SPEC v0.10.2's corrected §6.7). The guard in `src/main.s` compared
  `__MAIN_LAST__` against an **imported** `sqtab_lo` — a gated window export
  scheduled for removal at the next MAJOR, at which point the guard itself
  would have stopped linking. Per the corrected clause it now obtains the base
  **source-level**: a new single shared include (`src/sqtab_base.inc`) holds
  the one `.ifndef`-guarded default, included by both the placing TU
  (`mul_8x8.s`) and the guard TU, so two copies of the default can never
  silently disagree about which window the table occupies.

  Re-proven under v0.10.2's three conditions: boundary exact (409 links,
  410 trips); **fires under `FP_ONCHIP_MUL` too** — the other configuration
  that places the table (the clause's new constraint 3, added precisely
  because a profile-gated guard can pass a firing test while verifying
  nothing); and one `-D LIB_SHARED_SQTAB_BASE=…` relocates table and guard
  together (a base below the image top trips the link immediately).
  PRG byte-identical.

### Changed

- Live doc references to the "§8.0 catch-loop" updated to **§8.4**
  (SPEC v0.10.3: the heading now exists; the clause was promoted in place, so
  every existing §8.4 citation became correct retroactively). The canonical
  `precalc_table.inc` is deliberately untouched, per upstream: its historical
  spelling is recorded and byte-identity across adopters wins.

### Fixed

- **Two §5 footprint values violated SPEC v0.10.0 §6.6's safe-direction MUST**
  (each value ≥ the measured sum for its archive). Both were round-to-tens
  artifacts erring in the unsafe direction — flagged by this library's own
  review question on the §6.6 draft, resolved by the merged rule:

  | archive | equate | was | measured | now |
  |---|---|---:|---:|---:|
  | `p384-sha384.a` | `RESIDENT_BYTES` | 9000 | 9001 | **9216** (next 256-byte boundary, the §6.6 fleet convention; +2.4%) |
  | verify-onchip ×2 | `COLD_BYTES` | 240 | 243 | **250** (≥ measured; the 256-boundary would be +5.3%, outside §5's ±5% at this size) |

  The COLD values previously suspected of wrong-sign rounding (1840/1650/430,
  each ≥ measured) are **correct** under the merged rule: COLD is its own
  budget, so it rounds up like RESIDENT — `declared ≤ budget` implies
  `actual ≤ budget` only when declared ≥ actual.

### Added

- **§6.6 consumer footprint-assert worked example** in API.md §8.6.1, with
  this library's real equates — covered by `make check-docs`, so it links
  against the shipped objects.

- **Release-process obligation recorded** (§6.6): release notes MUST state
  footprint deltas per (profile × variant) — one tag carries several footprint
  pairs, so a single per-version delta is meaningless.

## [0.10.1] — 2026-08-15

> **Identity-correction release.** `v0.10.0` ships content that self-reports
> as 0.10.1: `LIB_NISTCURVES_VERSION_PATCH = 1` carried over from v0.9.1 while
> the tag name, `VERSION` file, tarball and release title all said 0.10.0 —
> caught by lib-contract #76's ref verification, which held the wave close on
> it. A consumer pinning `PATCH = 0` against that tag fails at link, and a tag
> that misstates itself is exactly what §1 exists to prevent.
>
> Per the fleet's tags-are-immutable convention (the v0.3.x precedent),
> `v0.10.0` is **documented as self-misreporting, not moved**. This tag's
> content and name agree; consumers pin **v0.10.1**. Zero functional change —
> the PRG, archives, and every export other than `VERSION`-file alignment are
> identical to v0.10.0.

### Fixed

- `VERSION` file brought to 0.10.1, matching the equates the previous release
  already shipped. The root cause was a partial bump (MINOR and ABI edited,
  PATCH untouched) passed by a partial check (the "lockstep verified" grep
  never printed the PATCH line).

### Added

- **§1 version-identity check in `make check-archives`**: the `VERSION` file
  is compared against all three components read from the **built**
  `lib_version.o`. The comparison is total and mechanical, so a partial bump
  can no longer pass a partial reading. Negative-tested: a mismatched
  `VERSION` file fails the ratchet.


## [0.10.0] — 2026-08-15

> **Namespace-wave release** — closes the fleet's §6.5 rename window as its
> last adopter (lib-contract #76 tracker: polyval v0.6.0, chacha v0.8.0,
> x25519 v0.11.0, nist **this release**), and bundles the full contract
> catch-up from v0.8.4 through v0.9.1. Eight PRs: #99, #101, #102, #103,
> #104, #105, #106, #107.
>
> **`LIB_ABI_VERSION` bumps 1 → 2.** Three exported symbols were removed
> unconditionally (#103): `LIB_SHARED_REU_MUL_BANK`, `_OFFSET`,
> `_BANKS_USED` — the unprefixed §8.2 consumer-input equates that collided
> with `c64-x25519` in any composed link. Their prefixed *output*
> counterparts (`LIB_NISTCURVES_SHARED_REU_MUL_*`, #105) replace what a
> consumer could legitimately want from them. Consumers gating on
> `LIB_NISTCURVES_ABI_VERSION <> 1` fail loudly, as intended.
>
> **`build/nist-curves.prg` changes: 37427 → 37480 B** (#102 restores 53
> bytes the image was short — everything above `$83C6` now loads at its
> linked address). Individual entries below that state "byte-identical"
> describe their own change against its predecessor; #102 is the one
> byte-moving change, validated by the full 1090-check oracle run.
>
> Everything else is additive or gated-additive: bare names deprecated by
> the rename window remain exported **by default** and are suppressed only
> under `-D LIB_NO_BARE_EXPORTS=1`. A consumer that changes nothing links
> exactly as before.

### Changed

- **§6.5 rename-window follow-up (lib-contract #83 + v0.9.1 window items) —
  the last adopter half of the fleet's namespace wave.** Three families take
  canonical library-prefixed names; every bare form remains exported **by
  default** as a same-address alias and is suppressed under
  `-D LIB_NO_BARE_EXPORTS=1`, for removal at the next MAJOR:

  | family | canonical | why |
  |---|---|---|
  | general ZP scratch | `nistcurves_zp_{tmp1,tmp2,ptr1,ptr2}` | §2 registry; the trio collided with x25519's exports until its v0.11.0, and chacha `.importzp`s the bare names — silent cross-library aliasing |
  | multiply buffers | `nistcurves_mul_{dma_lo,dma_hi,cached_a,src2_buf}` | `mul_` is registered to c64-x25519 in the §2 registry |
  | sqtab table labels | *(unchanged names)* — bare **export** gated | v0.9.1: canonical does not mean exported; they derive from consumer input and every §8.1 adopter derives the same two |

  Every in-library reference moved to the canonical names, so a gated archive
  stays link-complete. **Measured: a `-D LIB_NO_BARE_EXPORTS=1` build of
  `nistcurves.a` exports zero bare/deprecated names** — matching x25519
  v0.11.0's surface, which closes the #82/#83 collision families for the
  `c64-https` pair at the gate.

  `build/nist-curves.prg` is **byte-identical** (`18701274…`): the change is
  pure symbol surface; aliases sit at the same addresses.

- **Deprecated-spelling ZP overrides now hard-error, deliberately.** A
  consumer's legacy `-D zp_tmp1=0x40` — which assembled at every earlier tag —
  now fails with `Symbol 'zp_tmp1' is already defined`, because the bare name
  is a fixed alias of the canonical slot rather than the `.ifndef`-guarded
  definition. The canonical spelling (`-D nistcurves_zp_tmp1=0x40`) works and
  is the migration. This diverges from c64-ChaCha20-Poly1305's window shape,
  where the deprecated spelling still moves the canonical slot; both are
  window-conformant, and this library takes the loud one on purpose — the
  quartet was never a documented override knob here (unlike `fp_*`, which is
  documented and unchanged), so the only consumers who can hit it are ones
  guessing at undocumented names, and a hard error beats silently splitting a
  slot across two addresses. Recorded per the PR #107 review; the
  both-behaviors question is tracked upstream as a §6.5/A.4 note.

- `mul_src2_buf_384` keeps its unprefixed name, recorded at its definition
  site: the §2 registry governs the *exported* surface, and it is internal —
  referenced only within `fp384.s`, exported by no object across all ten
  archives. If it is ever exported it takes the prefix at that moment.

- `make check-archives` gains a **gated-surface ratchet**: every gate-owning
  TU is assembled under `-D LIB_NO_BARE_EXPORTS=1` and must export zero
  deprecated bare names. Nothing else checks the gated configuration — the
  default build legitimately exports both spellings — and one ungated
  `.export` quietly re-opens the collision class. Negative-tested.

### Added

- **`make lib-app-owned`** (SPEC §6.3, required of every §8.x-consuming
  library). Builds `build/lib/nistcurves-app-owned.a` — the full member set
  with **all four** deferral switches defined, so a consumer can request
  §8.0's `APP_OWNED` shape without knowing which switches this library has.
  The manifest attests it: `SHARED_PRIMITIVES = $0000` (everything deferred),
  `SHARED_CONSUMES = $0007` (the library still reads all three primitives).
  `reu_mul_init.o` is excluded rather than substituted — under
  `SHARED_REU_MUL_INIT` its entire body is gated out, so the object would ship
  nothing. Verified by linking a consumer that supplies the four primitives.

- **`SHARED_REU_MUL_FETCH`** (SPEC §8.2 fetch deferral, contract v0.9.1).
  `SHARED_REU_MUL_INIT` gates the init body only; the per-row fetch was
  exported unconditionally, so a composed link carried two canonical fetches
  regardless of init deferral. The new switch gates the fetch surface, and
  per §8.1's import-never-stub rule a deferring build imports rather than
  stubbing.

  **The two switches now move together, enforced at assemble time.** Defining
  either alone is rejected with a named `.error`: deferring init while still
  exporting the canonical fetch makes the build an owner of the fetch that is
  not an owner of the primitive, which §8.0's three-state table has no row
  for. Bit `$0002` drops exactly when both are defined.

### Fixed

- **Deferring §8.3 deleted scratch this library's own field arithmetic uses.**
  `poly_prod_lo` / `poly_prod_hi` were defined *inside* the
  `SHARED_CT_MUL_8X8` gate, but they are dual-purpose: `ct_mul_8x8`'s 16-bit
  output when we own the body, **and** ordinary scratch that `fp256.s` /
  `fp384.s` write on the diagonal-squaring path of every `fp_sqr`, entirely
  independent of `ct_mul_8x8`. Any `SHARED_CT_MUL_8X8` build therefore left
  them unresolved.

  Latent since the switch was introduced, and invisible until §6.3's
  `lib-app-owned` target built a deferring archive for the first time — the
  switch existed but had never been exercised. Same shape as the
  `c64-x25519` `mul_src2_buf` overreach contract v0.9.1 corrected: a deferred
  buffer points a library's own field arithmetic at another library's memory.
  They now sit outside the gate; the canonical §8.3 body is untouched, so its
  cross-adopter byte-identity gate is unaffected.

### Changed

- The §6.2 defines-forwarding variables take their contract-normative names:
  `CA65FLAGS` → **`CONTRACT_DEFINES`**, `ZPFLAGS` → **`CONTRACT_ZP_DEFINES`**.
  Mechanism and scoping are unchanged — v0.9.0 adopted both from this
  library's implementation, including the pattern-rule caveat — only the
  spelling moves. Never released under the old names.

### Added

- **Build targets now accept consumer-supplied defines** (c64-lib-contract
  #76 item A.1), via two variables:

  ```sh
  make lib-p256-verify CONTRACT_ZP_DEFINES='-D fp_src1=0x50 -D fp_src2=0x54'
  make lib CONTRACT_DEFINES='-D LIB_SHARED_SQTAB_BASE=0x8800'
  make lib CONTRACT_DEFINES='-D SHARED_SQTAB_INIT -D SHARED_REU_MUL_INIT -D SHARED_CT_MUL_8X8'
  ```

  SPEC §2 states normatively that every ZP slot is `.ifndef`-guarded so a
  consumer "can override the slot via `ca65 -D <slot>=$<addr>`", and §6 tells
  that consumer to obtain the library with `make lib-<variant>`. Those two
  clauses did not meet: the recipes hard-coded their flag lists, so an override
  passed to `make` was **silently discarded** — no error, just the default
  address, surfacing later as a ZP collision.

  Two variables rather than one, because they cannot be the same one.
  `CONTRACT_ZP_DEFINES` reaches only the `src/zp_config.s` recipes: every other TU obtains
  a slot with `.importzp`, and a command-line `-D` of an imported name is a
  hard error (`src/fp256.s(6): Error: Symbol 'fp_src1' is already defined`), so
  forwarding a ZP override everywhere fails the build rather than relocating
  the slot. `zp_config.s` is the sole TU that *defines* the slots, so the
  override belongs there alone and every importer picks the new address up
  through the export. Verified end-to-end: a consumer linking the overridden
  archive resolves `fp_src1` to `$0050`.

  This also delivers #76's item A.2 without new targets — a consumer can build
  the `APP_OWNED` configuration (`SHARED_PRIMITIVES = $0000`,
  `SHARED_CONSUMES = $0007`) by passing the deferral switches to an existing
  target, instead of doing `ar65` member surgery on a shipped archive.

  **Use C-style hex (`0x50`), not ca65's `$50`,** in either variable. A `$`
  traverses make *and* the recipe shell; measured on GNU make + `/bin/sh`,
  `$50` → `0`, `$$50` → `0`, and `$$$$50` → the shell's PID, i.e. a
  plausible-looking address that changes per invocation with no diagnostic from
  make, the shell, ca65 or ld65. `\$$50` and `0x50` are both correct; `0x50`
  needs no escaping and is documented as the form to use.

- **§8.2 prefixed output counterparts** (c64-lib-contract v0.8.5 export
  discipline — the second half of the #82 ruling). This library now exports
  `LIB_NISTCURVES_SHARED_REU_MUL_BANK` / `_OFFSET` / `_BANKS_USED`, so a
  consumer can verify co-linked libraries agree on `reu_mul` placement:

  ```asm
  .import LIB_NISTCURVES_SHARED_REU_MUL_BANK
  .import LIB_X25519_SHARED_REU_MUL_BANK
  .assert LIB_NISTCURVES_SHARED_REU_MUL_BANK = LIB_X25519_SHARED_REU_MUL_BANK, lderror, "co-linked libraries disagree on reu_mul placement"
  ```

  The consumer-*input* equates stay unexported (shipped in the previous
  entry) — those are the unprefixed names that collided.

  **The exported values are the values the code reads**, which the clause makes
  normative and which is the part worth care. They alias
  `LIB_NISTCURVES_REU_BANK_MUL` — the symbol `fp256.s`/`fp384.s` actually load
  into the REU bank register — rather than the `LIB_SHARED_REU_MUL_BANK` knob,
  because **both spellings relocate the table**:

  | override | code reads | exported output |
  |---|---:|---:|
  | *(none)* | `$00` | `$00` |
  | `-D LIB_SHARED_REU_MUL_BANK=3` | `$03` | `$03` |
  | `-D LIB_NISTCURVES_REU_BANK_MUL=5` | `$05` | `$05` |

  Aliasing the knob — which is literally what the SPEC's example snippet shows
  — would publish `$00` in the third row while the code read `$05`: an export
  that certifies nothing, i.e. exactly the defect v0.8.5 cites from
  `c64-x25519`'s pre-#92 form. Reported upstream.

  Pinned present in the four default-profile §8.2-consuming archives and
  negative-tested; the documented consumer assert is covered by
  `make check-docs`, so it cannot ship un-assemblable.

### Fixed

- **§8.2 placement equates no longer exported** (c64-lib-contract #82).
  `LIB_SHARED_REU_MUL_BANK` / `_OFFSET` / `_BANKS_USED` were `.export`ed
  unprefixed. Every §8.2 consumer defines the same three names, so a consumer
  linking two REU adopters got a hard link failure:

  ```
  ld65: Error: Duplicate external identifier: 'LIB_SHARED_REU_MUL_BANKS_USED'
  ```

  Reproduced against `c64-x25519` v0.10.1 — the exact pair `c64-https` ships,
  so this broke a real consumer today.

  They are consumer-supplied placement values: `.ifndef`-guarded and overridden
  with `ca65 -D`, exactly like §8.1's `LIB_SHARED_SQTAB_BASE`, which no adopter
  exports. Dropping the exports changes nothing else — no in-tree importer, no
  object import, no archive pin referenced them.

  Note the contrast with the §3 equates in the same file, which **are** exported
  and should be: those carry the `LIB_NISTCURVES_` prefix, so they sit in this
  library's namespace and cannot collide. The §8.2 names are shared by
  construction.

  Pinned absent from all nine archives so they cannot return. If the contract
  later rules that §8.2 placement should be published rather than library-local,
  that form will be prefixed (`LIB_NISTCURVES_SHARED_REU_MUL_*`) per the #43
  family and is additive — whereas keeping the bare names would have had to be
  undone. Dropping was the reversible direction.

### Fixed

- **`LIB_NISTCURVES_P384_BSS` was `type = bss` while every sibling was `rw`
  (issue #98).** Sitting ahead of four file-emitting segments, it made the
  shipped PRG **53 bytes shorter than its address span**, so everything above
  `$83C6` loaded 53 bytes below the address it was linked for.

  It was benign only by coincidence of two properties nothing enforced: all
  trailing content happened to be zeros, and every affected buffer happened to
  be written before it was read. One non-zero initialiser above `$83C6`, or one
  buffer read before first write, would have turned it into whole-image
  corruption — **silently**, because ld65 warns only when a `bss` segment holds
  *non-zero* data, and these are zero-filled `.res`.

  `build/nist-curves.prg` grows 37427 → **37480 B**, exactly the 53 bytes that
  were missing, and the image now matches its address span exactly (measured
  shortfall 53 → **0**).

- **`make check-archives` now pins the placement class, not just this
  instance.** It fails if any `type = bss` segment precedes a file-emitting one
  in the same memory area. Neither ld65 nor a reviewer reliably catches this —
  the diagnostic is absent for the common zero-filled case — so it is checked
  mechanically. Negative-tested: reintroducing the `bss` declaration trips it
  with a named error.

  (The check's own first version was silently vacuous — its regex matched the
  string `SEGMENTS{}` in a header comment rather than the real block, so it
  inspected nothing while reporting OK. Caught by the negative test, which is
  the only reason it works.)

### Fixed

- **Consumer version-guard snippets did not assemble** (c64-lib-contract #73).
  `API.md` §8.6 and `src/lib_version.s` both published guards using `.if` on an
  `.import`ed symbol. `.if` needs an assembly-time constant and an imported
  symbol has no value until link, so ca65 rejects it outright with
  `Error: Constant expression expected` — the guard never assembled at all
  rather than silently passing. Replaced with `.assert ..., lderror, ...`,
  which defers evaluation to ld65, the first stage that knows the value.
  Verified by extracting the published snippet verbatim, assembling it,
  linking it against the real `lib_version.o`, and confirming it *fires* when
  the required version is raised above what the library exports. The cost is
  that the guard now reports at link rather than assemble time; it still
  reports before anything runs.

  Also corrected an adjacent stale claim that `LIB_NISTCURVES_ABI_VERSION`
  "bumps in lockstep with `LIB_NISTCURVES_VERSION_MAJOR`" — it does not and
  must not pre-1.0 (MAJOR is 0, ABI is 1); it is an independent generation
  counter per SPEC §7.

### Added

- **SPEC §4 load-bearing cfg attribute declarations** (c64-lib-contract
  v0.8.0). Consumers author their own `SEGMENTS{}` block, so every placement
  attribute this library's correctness or timing depends on is now declared
  inline in `src/c64.cfg` with the consequence of getting it wrong. Measured
  on ld65 V2.18 rather than assumed:

  | attribute | dropped | ld65 says |
  |---|---|---|
  | `align = $100` on the two table segments | tables land at `$xx04` | **nothing at all** |
  | `type = rw` → `bss` on a zero-filled segment | 512 bytes vanish | **nothing at all** |
  | `type = rw` → `bss` on non-zero content | image shifts | warns, links anyway |

  Declared: `align = $100` on `SHA384_TABLES` (twelve 256 B rotate LUTs read
  `abs,x` over the full 8-bit range) and on `TABLES` (`mul_dma_lo/hi`, ~1024
  indexed reads per `fp_mul`); `type = rw` on `MUL`/`P256`/`P384_CODE`, which
  are **self-modified at run time** and would produce wrong field results in
  ROM with no diagnostic; `type = rw` on `TABLES`, whose 512-byte DMA landing
  pages must stay contiguous and emitted.

  Deliberately *not* declared, having been checked: `type = ro` on the table
  segments (byte-identical either way), `sha384_k` alignment (it is in
  `SHA384_RODATA`, links unaligned, and is read through a ZP pointer — the
  pre-existing comment claiming otherwise was wrong twice), and any
  constant-time claim for `mul_dma` alignment, since `fp_mul`'s inner loop has
  a documented secret-dependent zero-byte skip and is not constant-time.

- **The sqtab window collision is now a link error.** `sqtab_lo`/`sqtab_hi` are
  an absolute equate (`LIB_SHARED_SQTAB_BASE`, SPEC §8.1), not a segment, so
  ld65 does not know the `$9C00..$9FFF` window exists and will place a segment
  straight over it with **no overlap diagnostic**. That is exactly the
  2026-05-17 failure — silent multiply-table corruption, boot hanging at the
  `$02A7` sentinel. The §8.1 asserts only check the base is well-formed;
  nothing checked that the image does not grow *into* it.

  `src/c64.cfg` now gives MAIN `define = yes`, and `src/main.s` asserts
  `__MAIN_LAST__ <= sqtab_lo` with `lderror`. Measured slack: **409 bytes** —
  409 B of added BSS still links, 410 B trips it, boundary verified exact. The
  guard lives in `main.s` because `main.o` is in no consumer archive; in
  `mul_8x8.s` it would force `define = yes` or an unresolved external on every
  consumer. It cannot rot silently either — remove `define = yes` and `main.o`
  stops linking.

  Consumers author their own memory map and get no protection from this; the
  cfg recommends they add the equivalent assert against their own area's
  `__*_LAST__`.

- Corrected the re-entrancy section's `mul_dma_lo`/`mul_dma_hi` addresses:
  `$7a00`/`$7b00`, not `$7b00`/`$7c00`.

## [0.9.1] — 2026-08-14

### Fixed

- **Re-copied `src/precalc_table.inc` from c64-lib-contract v0.7.4** (upstream
  `9da3aca`), which pins the `_REGION` and `_SHARED` exports `: abs`. Both are
  byte-valued by construction, so ca65 inferred **zeropage** for them while a
  consumer's `.import` defaults to absolute — making SPEC §8.4's own published
  cross-check snippet emit, on every composed build:

  ```
  ld65: Warning: Address size mismatch for 'LIB_NISTCURVES_PRECALC_sqtab_SHARED':
        Exported ... as 'zeropage', import ... as 'absolute'
  ```

  Reproduced against the pre-copy tree and confirmed clean after. Diagnostic
  noise rather than breakage — the link succeeded and both asserts evaluated
  correctly — but the natural consumer reaction is `.import ... : zeropage`,
  which pins a manifest constant to an address size that is an artifact of its
  current value rather than a property of the symbol.

  `_SIZE` remains deliberately unhinted: its address size is value-dependent by
  design, and that is what lets the 131072-byte `reu_mul` table export as `far`
  without the "far but exported absolute" warning. Verified both ways after the
  copy — `sqtab_SIZE` absolute at 1024, `reu_mul_SIZE` far at 131072.

  No symbol, value, or semantic change; every existing `.import` resolves to the
  same value. `build/nist-curves.prg` byte-identical (`78b395b8…`, 37427 B).

  Contract currency note: SPEC also moved to v0.7.3 (§8.x bit constants MUST NOT
  be exported) and v0.7.5 (`ABI_VERSION` defined as an independent generation
  counter starting at 1, resolving the §1/§7 contradiction we filed as
  lib-contract #66). This library is already conformant with both — it never
  exported the bit constants, and v0.9.0 shipped `ABI_VERSION = 1`.

## [0.9.0] — 2026-08-13

> **Manifest-honesty release.** Four issues (#86, #88, #90, #91), all
> concerning what the library *tells* consumers about itself rather than what
> it computes. No cryptographic behaviour changed: 1090/1090 oracle-gated
> checks pass across all six suites.
>
> **Two ABI-surface removals, covered by this one MINOR bump.** 17 exported
> symbols are gone: `proc_port`, `fp_loop` and the four `poly_*` zero-page
> slots (#90), plus 11 RFC 6979 self-test-vector symbols (#91). A consumer
> that imported any of them *from this library* rather than defining it
> locally must now supply its own. **`LIB_ABI_VERSION` bumps `0` → `1`** so
> the breakage gate actually fires: a consumer guarding with
> `.if LIB_NISTCURVES_ABI_VERSION <> 0 / .error` will now fail loudly rather
> than silently linking against a reduced export surface.
>
> That value also corrects a long-standing divergence. SPEC §1/§7 describe
> `LIB_ABI_VERSION` as "matching the MAJOR component", but that cannot hold
> pre-1.0 — §7 equally states breaking changes ride MINOR bumps while the
> contract is in v0.x, so MAJOR stays `0` across exactly the breakage the
> gate exists to catch. Every sibling adopter (c64-x25519,
> c64-ChaCha20-Poly1305, c64-polyval) treats it as an independent generation
> counter starting at `1`, and SPEC §7's own worked example gates on `!= 1`.
> This library shipped `0` from v0.3.0 through v0.8.0 and was the outlier.
>
> **`build/nist-curves.prg` changes: 37683 → 37427 B.** #86, #88 and #90 were
> each byte-identical; #91's deletion of 384 B of dead rodata is what moves
> it (the 256 B net drop reflects 128 B reabsorbed as page-alignment
> padding). This is why the full VICE oracle suites were run for this release
> rather than relying on byte-identity.
>
> **Every §5 manifest equate a consumer reads has changed value** for at
> least one archive — see the per-archive table in `API.md` §8.4. Consumers
> running assemble-time fit checks against `RESIDENT_BYTES` / `COLD_BYTES` /
> `ZP_USAGE_BYTES` / `REU_BANKS_USED` should re-read them; several were
> previously overstated by 1.5–3×, so checks that failed may now pass.
>
> SPEC §13 (network backend ABI, contract v0.6.0) is deliberately not
> adopted — this library has no network surface.

### Removed (issue #91)

> **The RFC 6979 test vectors are retained and test coverage is unchanged.**
> What is removed below is a redundant *second* copy of them that was compiled
> into the shipped library and read by nothing. The vectors the test suite uses
> live in `tools/test_ecdsa_verify.py`, transcribed from the RFC itself
> (Appendix A.2.5 for P-256, A.3.1 for P-384), and are untouched — as is the
> entire `tools/vectors/` NIST corpus and all 8 on-chip curve constants.

- **384 B of duplicated RFC 6979 self-test vectors deleted from `curve256.s`
  (288 B, 9 symbols) and `curve384.s` (96 B, 2 symbols).** They shared
  translation units with the curve parameters, so ld65's whole-member pull
  shipped them into **7 of 9 consumer archives** — the same leak shape as the
  issue #63 test-trampoline export and the `data_test.s` split.

  The on-chip copy was not merely misplaced, it was **dead everywhere**: zero
  importers across all 24 built objects, no reference from any `.s` file, and
  none from the Python tooling. That is by design, not oversight — under the
  project's oracle-driven testing model, expected values must come from an
  external source, and test code never hard-codes values from a previous
  implementation run. Checking the library against constants shipped inside
  that same library would be circular, so the on-chip copy could not have
  served as an audit reference even if something had read it. These constants
  were a fossil of an earlier self-test approach.

  No on-chip power-on self-test exists today. If one is ever added it will need
  vectors resident again; they are recoverable from git history or the RFC, and
  should land as an opt-in object excluded from the default archives rather
  than silently present in seven of nine.

  Deleted outright rather than relocated to a test-only object: relocation
  would have preserved data nothing reads in either place, and would have
  added a `src/*.s` file needing to be paired into both the `Makefile`
  MODULES list and `build_release.sh`'s archive list.

  **ABI-surface change** — 11 exported symbols removed. Fine pre-1.0 under
  SPEC §7 with a MINOR bump; see the issue #90 note above, which this
  release shares a bump with.

- **`COLD_BYTES` refreshed across 8 archives** now those bytes are gone:

  | archive | was | now |
  |---|---:|---:|
  | `nistcurves.a` | 2200 | **1840** |
  | `nistcurves-onchip.a` | 2000 | **1650** |
  | `p256-verify.a` | 720 | **430** |
  | `p256-verify-onchip.a` | 530 | **240** |
  | `p384-verify.a` | 530 | **430** |
  | `p384-verify-onchip.a` | 340 | **240** |
  | `p384-curve.a` | 530 | **430** |
  | `p384-curve-onchip.a` | 340 | **240** |

  `RESIDENT_BYTES` is unchanged — the vectors were already classified COLD,
  not resident.

  The three minimal variants now share a single gate arm. Through issue #90
  `LIB_P256_VERIFY_ONLY` needed its own (720/530 against the P-384 variants'
  530/340), and that 190 B gap was *exactly* the 288-vs-96 B of vectors the
  two curve objects carried. With the vectors gone the gap closes and all
  three measure identically, so the `COLD_BYTES` grouping now matches
  `REU_BANKS_USED`'s instead of deliberately differing from it.

- **`build/nist-curves.prg` changes for the first time in this release
  series**: 37683 → 37427 B. The drop is 256 B rather than the 384 B removed,
  because two page-aligned segments (`align = $100`) reabsorb 128 B as
  padding; the object-level reduction is exactly 288 + 96. Every other change
  in `[Unreleased]` held the PRG byte-identical, so this is the one that
  required the VICE oracle suites to be run rather than argued away.

- `tools/check_archives.py` pins all 11 symbols absent from every archive, so
  dead data cannot re-enter the consumer surface the way the originals did.

### Fixed (issue #88)

- **`nistcurves-p384-sha384.a` advertised resources it does not contain.**
  The archive shipped the default-profile `lib_manifest.o` /
  `precalc_manifest.o`, so it described the whole library rather than
  itself — while containing only `sha384.o`, `data_sha.o`, `zp_config.o`
  and the manifest objects. A new `-D LIB_SHA384_ONLY` variant pair
  (`lib_manifest_sha384.o` / `precalc_manifest_sha384.o`) corrects all
  five claims:

  | Equate | was | now | true content |
  |---|---|---|---|
  | `ZP_USAGE_BYTES` | 31 | 8 | four `.importzp` slots at `$04..$0b` |
  | `REU_BANKS_USED` | `$07` | `$00` | issues no REU DMA |
  | `SHARED_PRIMITIVES` | `$0007` | `$0000` | ships none of the three §8 bodies |
  | `SHARED_CONSUMES` | `$0007` | `$0000` | consumes none |
  | `RESIDENT_BYTES` | 27000 | 9000 | 9001 measured from an ld65 map |
  | `COLD_BYTES` | 1800 | 0 | nothing overlay-able in the SHA path |
  | precalc rows | 5 | 1 | only `sha384_k` exists |

  The two mask claims were the breaking ones. A consumer co-linking this
  archive with a sibling that legitimately owns `sqtab` / `ct_mul_8x8`
  got `shared-primitive double-ownership` from the §8.0 disjointness
  assert on a perfectly valid link, and the v0.5.0 coverage assert
  additionally demanded a §8.2 `reu_mul` provider for a link with no use
  for one. Both masks are now `$0000` rather than absent — the equates
  still export, declaring the §8.0 **non-consumer** state for all three
  primitives.

  `RESIDENT_BYTES` failed *closed* rather than silently: a consumer
  running the §5 fit check was told the archive needs 27 KB resident and
  would refuse to build against a region that comfortably fits the real
  9 KB.

  `ZP_USAGE_BYTES` narrows too, via a `zp_config_sha384.o` built under the
  same switch: `sha384.o` `.importzp`s exactly four slots (`sha_src`,
  `sha_len`, `sha_w_ptr`, `sha_w_ptr2` — 8 bytes at `$04..$0b`) and no
  object in the archive references any other, not even `proc_port`, since
  SHA issues no REU DMA and never banks ROM. Zero page is the scarcest
  resource on a 6502 — with BASIC and KERNAL live, genuinely free ZP on a
  C64 runs to the low tens of bytes — so an archive claiming 32 against a
  real need of 8 can push a consumer's collision check into rejecting an
  integration that would have fit.

  Third instance of the defect shape fixed for the onchip profile in #78
  and for the §8.2 provider in #81.

- **`ZP_USAGE_BYTES` was under-claimed by one byte on every other archive**
  (pre-existing, found while narrowing the SHA figure): declared `31`,
  actually `32`. The itemization in `src/lib_manifest.s` has always summed
  to 32; only the total line was mis-added. Enumerating the slot addresses
  confirms 32 distinct bytes — `$01`, `$02-$03`, `$04-$0b`, `$1a-$1d`,
  `$22-$2d`, `$3b`, `$fb-$fe`. This error ran in the dangerous direction:
  a consumer sizing its allocation against 31 could place a variable in
  the byte the library never admitted to owning and have it silently
  clobbered mid-operation. Over-claiming ZP wastes a scarce resource;
  under-claiming corrupts. Within SPEC §5's ±5% band either way, but the
  band is not the point for a collision check.

- **`tools/check_archives.py` gained §5 manifest *value* pins.** Symbol
  presence alone cannot catch an archive shipping a well-formed manifest
  carrying the wrong numbers — which is exactly how this defect survived
  the #78 and #81 ratchets. The tool now asserts concrete values for
  `REU_BANKS_USED` / `SHARED_PRIMITIVES` / `SHARED_CONSUMES` on the full,
  onchip and SHA archives, plus `RESIDENT_BYTES` / `COLD_BYTES` on the
  SHA archive, and pins the four non-SHA precalc table families as absent
  from it.

- **API.md described the SHA archive as four objects**; it has six. The
  line predated `LIB_CORE_OBJS` gaining the two manifest objects.

### Added

- **§5/§8.0 consumption mask `LIB_NISTCURVES_SHARED_CONSUMES`
  (contract v0.5.0, lib-contract #44).** A clear ownership bit was
  ambiguous: it meant either "deferring consumer — a provider MUST exist
  elsewhere in the link" or "non-consumer — no provider obligation", two
  states with opposite obligations for the composed consumer. This
  library was the demonstrator upstream, since its `SHARED_REU_MUL_INIT`
  deferral build and its `FP_ONCHIP_MUL` profile build both export
  `LIB_NISTCURVES_SHARED_PRIMITIVES = $0005`. The new mask separates
  them:

  | Build configuration | `SHARED_PRIMITIVES` | `SHARED_CONSUMES` |
  |---|---|---|
  | default, standalone | `$0007` | `$0007` |
  | default + `-D SHARED_REU_MUL_INIT` | `$0005` | `$0007` |
  | `-D FP_ONCHIP_MUL` | `$0005` | `$0005` |

  Gating rule: profile switches (`FP_ONCHIP_MUL`) drop a bit from **both**
  masks; `SHARED_*` deferral switches drop it from the **ownership mask
  only**. Two new permanent `.assert`s in `src/lib_manifest.s` pin the
  SPEC subset invariant (`PRIMITIVES & ~CONSUMES = 0`) and the onchip
  §8.2 non-consumption. `FP_ONCHIP_MUL` keeps the §8.3 `ct_mul_8x8` bit
  in both masks even though the issue #71 row generator never calls the
  body at runtime — SPEC §8.0 counts shipping the canonical body as
  consumption, because a co-linked sibling's deferral may depend on it.
  API.md §8.6.1.

- **§1/§5/§8.4 library-prefixed manifest exports (contract v0.7.0,
  lib-contract #43).** `src/lib_version.s` now exports
  `LIB_NISTCURVES_VERSION_MAJOR` / `_MINOR` / `_PATCH` /
  `LIB_NISTCURVES_ABI_VERSION`, and each `LIB_PRECALC_TABLE` invocation
  passes `"NISTCURVES"` so `src/precalc_manifest.s` also exports
  `LIB_NISTCURVES_PRECALC_<name>_{SIZE,REGION,SHARED}`. The unprefixed
  families are identical across every contract adopter, so a consumer
  linking two sibling libraries and importing both manifests got
  `ld65: Duplicate external identifier` — measured upstream between
  `c64-x25519` v0.8.0 and `c64-ChaCha20-Poly1305` v0.6.0 on
  `LIB_PRECALC_sqtab_*`. The bare forms remain exported **by default**
  (as aliases of the prefixed ones, so a release bump cannot drift them)
  and are suppressed build-wide with `-D LIB_NO_BARE_EXPORTS=1`; they are
  removed at contract v1.0. §1's TU-isolation requirement was already
  satisfied — `src/lib_version.s` exports only version equates and the §5
  aggregates already lived in `src/lib_manifest.s`. API.md §8.6/§8.6.1.

- **Archive ratchet coverage for the manifest surface.**
  `tools/check_archives.py` now pins the prefixed version equates and
  both §8.0 masks as present in all nine archives, and both the prefixed
  and bare `*_PRECALC_reu_mul_*` triples as absent from the four
  `FP_ONCHIP_MUL` archives — the manifest-layer mirror of the existing
  issue #81 provider pins.

### Fixed

- **`ca65 --asm-define` is not a real flag (contract v0.7.1,
  lib-contract #50).** ca65 rejects it with `Unknown option:
  --asm-define`; the flag is `-D name[=value]`. The broken spelling
  appeared in 12 places a consumer would copy-paste from — API.md §8.5
  (×6), CLAUDE.md (×2), `src/lib_manifest.s`, `src/mul_8x8.s` (×2),
  `src/reu_config.s`, `docs/precalc-tables.md`. Historical
  `docs/RELEASE_NOTES_v0.*.md` keep the old spelling: they are
  point-in-time records, not instructions.

- **API.md published the boolean `.and` in the §8.0 disjointness assert**
  (contract v0.4.2, lib-contract #41 — never picked up here). ca65's
  `.and` evaluates operands for truthiness, so two correctly *disjoint*
  masks such as `$0005` and `$0002` both test true and the assert fires
  spuriously; the bitwise operator is `&`. A consumer following the old
  snippet got an unexplainable double-ownership error on a valid link.

- **`od65` cannot read `.a` archives**, contrary to the cross-reference
  in `docs/precalc-tables.md` (and to SPEC §8.0's own description —
  reported upstream). It prints `(no xo65 object file)` and exits `0`, so
  a script grepping its output silently sees zero symbols and concludes
  the table is absent. The audit command now dumps
  `build/precalc_manifest.o`, and greps `_PRECALC_` rather than
  `LIB_PRECALC_` so it matches the prefixed and bare forms alike.
  `tools/check_archives.py` was never affected — it resolves each archive
  to its constituent `.o` files from the Makefile.

### Changed

- `src/precalc_table.inc` re-copied byte-for-byte from the canonical
  `c64-lib-contract/precalc_table.inc` (upstream `62a5318`); it gained
  the fifth `lib` argument and `LIB_NO_BARE_EXPORTS` handling. Per SPEC
  §8.0 this file is never edited locally.
- The bare `LIB_VERSION_MAJOR` / `_MINOR` / `_PATCH` exports are now
  tagged `:abs` for consistency with `LIB_ABI_VERSION` and the §5
  aggregates. They are scalar parameters, not addresses, and their small
  values would otherwise be tagged `zeropage` and warn at consumer import
  sites.

### Fixed (issue #90)

- **`RESIDENT_BYTES`/`COLD_BYTES`/`ZP_USAGE_BYTES`/`REU_BANKS_USED`/precalc
  rows were whole-library figures inherited by every minimal archive** —
  the same defect shape issue #88 fixed for `lib-p384-sha384`, now closed
  for the other eight. `src/lib_manifest.s` and `src/precalc_manifest.s`
  previously gated only on `LIB_SHA384_ONLY` / `FP_ONCHIP_MUL`, so the
  three verify/curve archives and their onchip counterparts all inherited
  the full-library numbers regardless of what they actually shipped. Four
  new build gates (`LIB_P256_VERIFY_ONLY`, `LIB_P384_VERIFY_ONLY`,
  `LIB_P384_CURVE_ONLY`, alongside the existing `LIB_SHA384_ONLY`) give
  each of the nine archives its own `lib_manifest_<variant>[_onchip].o` /
  `precalc_manifest_<variant>[_onchip].o` / (for ZP) `zp_config_<variant>.o`.
  Full per-archive table: `API.md` §8.4.

  Two defects were the most consequential because they were **wrong in a
  direction that misleads a consumer's own correctness checks**, not just
  imprecise:

  - `REU_BANKS_USED` was wrong in **6 of 9** archives. The three
    non-onchip verify/curve archives claimed `$07` (all three REU banks)
    despite never linking the Lim-Lee comb objects that are bank 2's only
    consumer — true value `$03`. Their three onchip counterparts claimed
    `$04` despite issuing **no REU DMA at all** — true value `$00`. A
    consumer relocating a sibling library's REU footprint to avoid a
    collision, trusting this equate, would have reserved a bank the
    archive never touches.
  - Precalc-row enumeration was false in **6 of 9** archives, most
    strikingly: `nistcurves-p256-verify.a` — a P-256-only archive with
    zero P-384 code linked in — was advertising a 24 KB
    `lim_lee_comb_p384` REU table it does not contain, alongside its own
    (also absent) `lim_lee_comb_p256` table. This is exactly the audit
    surface c64-lib-contract SPEC §8.0's cross-adopter grep relies on to
    detect duplicate table ownership across sibling libraries; a false
    row doesn't just mis-inform a human reader, it can make a
    completely absent table look like a duplicate-ownership conflict to
    that audit.

  A third defect was a correction to a number `RESIDENT_BYTES`/
  `COLD_BYTES` had used as their shared baseline for every archive,
  independent of the per-variant work: **`COLD_BYTES = 1800` for the
  FULL archive was already 19% low** (measured 2219, re-baselined to
  2200) — outside SPEC §5's ±5% commitment even before any minimal
  archive existed. The prior derivation missed `reu_fetch_mul_row` (20 B,
  exported but uncalled by the library — see the `mul_8x8.s` correction
  below) and 384 B of RFC 6979 self-test vectors carried in
  `curve256.s`/`curve384.s`. Re-measured per archive: `COLD_BYTES` does
  **not** share a figure between a variant's onchip and DMA-profile
  archives (unlike `RESIDENT_BYTES`, which does) — every pair differs by
  the ~186-200 B boot-only `reu_mul_init` body, present in DMA-profile
  archives and absent from onchip ones.

- **`ZP_USAGE_BYTES = 32`, set by PR #89 (issue #88) for every archive
  except SHA-384, was itself wrong by one byte** — found while deriving
  the per-variant figures above. `ec_scalar_ptr` was documented in
  `src/zp_config.s`'s header comment and itemized in `src/lib_manifest.s`
  as a 1-byte "scalar index"; it is actually a 2-byte zero-page pointer
  (`sta ec_scalar_ptr+1` / `lda (ec_scalar_ptr),y` at multiple call sites
  in `ecdsa256.s`/`ecdsa384.s`/`points256_core.s`/`points256_comb.s`/
  `points384_comb.s`/`points384_core.s`). Corrected pre-cleanup total: 33,
  not 32.

- **Three zero-page slot groups were claimed but referenced by no
  archived object at all — `fp_loop` (1 B), `poly_i`/`poly_j`/
  `poly_carry`/`poly_tmp` (4 B, leftover from the pre-§8.3 `mul_8x8` body,
  issue #14), and `proc_port` (1 B).** `poly_i`/`poly_j`/`poly_carry`/
  `poly_tmp` were superseded by the canonical `ct_mul_8x8` body's
  `poly_prod_lo`/`poly_prod_hi` RAM cells (not ZP) and had already been
  silently dropped from every object's import table by ca65 — the
  `.importzp` line in `mul_8x8.s` was dead source, confirmed removing it
  changes zero object bytes. `proc_port` is used only by the never-
  archived `main.s` test/bench driver; it moves to a local equate there
  and is **no longer part of the library's ZP contract in any archive**,
  including the full one. Net: 33 (corrected pre-cleanup total above) − 6
  dead bytes = **27**, the new default figure.

  **This is an ABI-surface change and needs a MINOR version bump before
  release** — unlike the rest of this entry's number corrections, which
  only fix documentation/manifest-equate accuracy, dropping three symbol
  groups from `zp_config.s`'s `.exportzp` means a consumer that had
  imported `proc_port`, `fp_loop`, or any `poly_*` slot from this library
  (rather than defining it locally, as the ROM-banking example in API.md
  §3 always assumed) will no longer resolve. No known consumer does this
  — these were dead/hardware-fixed slots, not part of any documented
  integration path — but it is a real subtraction from the exported
  symbol surface, not merely additive, so it cannot ride on a PATCH bump
  under this project's semver policy.

- **`src/mul_8x8.s` — `reu_fetch_mul_row` was documented as "the REU DMA
  row-fetch helper used by `fp_sqr_384`".** False: `fp_sqr_384` (and
  every other REU-consuming field routine) inlines its own row-fetch
  register writes directly; `reu_fetch_mul_row` has zero callers anywhere
  in the library. It remains exported as a public helper for a consumer
  driving the fetch sequence directly, and is classified `COLD` in the
  §5 footprint accounting for exactly that reason (`CLAUDE.md`,
  `API.md` §8.4.2).

  Issue #91 (filed separately, **not** fixed here): `curve256.o`/
  `curve384.o` ship 288 B / 96 B of RFC 6979 self-test vectors in 7 of 9
  consumer archives — dead weight those archives have no use for. The
  `COLD_BYTES` figures in this release correctly count those bytes as
  cold for the archives' **current** contents; they will need
  re-measuring once #91 splits the vectors into their own object.

## [0.8.0] — 2026-07-28

> Net §5 manifest movement in this release: `LIB_NISTCURVES_COLD_BYTES`
> goes **2500 → 1800** (the two Fixed entries below each re-baselined it
> in sequence — 2500 → 2000 in issue #78, then 2000 → 1800 in issue #81;
> the values quoted per-entry are the intermediate steps, not
> alternatives).

### Fixed

- **FP_ONCHIP_MUL manifest alignment (issue #78):** onchip builds no
  longer claim the §8.2 `reu_mul` ownership bit —
  `LIB_NISTCURVES_SHARED_PRIMITIVES` is `$0005` standalone under the
  profile (was `$0007`), guarded by a permanent `.assert` — and the
  onchip archives no longer enumerate the `reu_mul` precalc table
  (`precalc_manifest_onchip.o`); the `lim_lee_comb_*` rows stay
  (bank `$02` is still used). Matches c64-x25519 PR #73. §5 accounting
  refreshed against v0.7.0 labels: `COLD_BYTES` 2500 → 2000 (the
  generated 1 KB sqtab RAM table is excluded as non-code+rodata; the
  old figure was outside the ±5% band), onchip resident/cold
  28200/1900 → shared 27000/2000. Makefile `.PHONY` gains the four
  onchip lib targets. Default PRG byte-identical.
- **SPEC §8.2 provider now ships in the default-profile archives
  (issue #81):** `reu_mul_init` / `reu_mul_tables_init` moved from the
  never-archived `main.s` into the new `src/reu_mul_init.s`
  (`LIB_NISTCURVES_MUL_CODE`, body still gated on
  `.ifndef SHARED_REU_MUL_INIT`), added to `LIB_MUL_OBJS` so
  `nistcurves.a` and the p256-verify / p384-verify / p384-curve
  archives contain the provider. Before this, API.md §3 made
  `jsr reu_mul_init` mandatory yet **no archive contained the symbol**
  (unresolved external for every archive consumer's boot), and the §8.0
  ownership bit `$0002` claimed by `lib_manifest.o` was untruthful in
  every archive — a sibling library genuinely shipping its §8.2
  provider would trip a consumer's disjointness `.assert` spuriously.
  The FP_ONCHIP_MUL archives and `lib-p384-sha384` deliberately do NOT
  gain the object (the onchip profile never builds or reads the REU
  multiply table; verify-onchip stays zero-REU-DMA). `check_archives.py`
  now ratchets both directions (provider exported + boot-sequence smoke
  link in the four default REU archives; provider absent from the
  sha384 + onchip archives). Standalone PRG: same 37683 B, but not
  byte-identical — the boot window `$081E`–`$0B20` is reordered (test
  trampolines now precede `sqtab_init`; `reu_mul_init` sits between
  `reu_fetch_mul_row` and `fp_copy`) and 8 operand bytes track
  `poly_prod_lo/hi` moving `$0ACE/$0ACF` → `$0A14/$0A15`; everything
  from `fp_copy $0B21` up is address-identical. §5 accounting:
  `COLD_BYTES` 2000 → 1800 — the pre-#81 cold sweep's
  "`$08AE` → `reu_fetch_mul_row`" block silently included ~198 B of
  main.s test trampolines; the new layout moves them out of the swept
  window (recomputed 1812, margin ~0.7%).

### Documentation

- **Post-v0.7.0 docs currency sweep** (issue #77; docs-only, PRG
  byte-identical). API.md §2 memory map regenerated from
  `build/labels.txt` at `f29f66c` — the previous table was ~$3000 stale
  (`mul_dma_lo/hi` are at `$7B00`/`$7C00`, not `$4B00`/`$4C00`); the
  map and the §8.3 consumer restrictions are now symbol-anchored with
  `build/labels.txt` named as authoritative. "Running without an REU"
  made discoverable (README Requirements subsection; API.md §1 target
  platform carve-out; §3/§8.3/§8.5 init + REU-bank obligations now
  profile-conditional per §8.4.2). Stale references fixed: `src/data.s`
  → the split `data_*.s` modules, `points256/384.s` → `_core`/`_comb`,
  ZP footprint aligned to 31 bytes everywhere, version-pin examples
  refreshed to the v0.7.x era, §8.4 PRG byte-identity claim re-scoped
  (37683 B current), §8.4.1 "Shipped in" column extended to the
  `*-onchip` archives, CHANGELOG `[0.4.0]`/`[0.3.0]` link definitions
  added. SPEC §8.0 precalc manifest (`src/precalc_manifest.s`,
  `src/precalc_table.inc`, `docs/precalc-tables.md`) now referenced
  from API.md §8.6.1 and the CLAUDE.md source-file table. README
  benchmark tables carry measurement provenance; the integration
  section now shows the archive-fetch pattern. CLAUDE.md re-entrancy
  addresses and PRG-size line corrected.
- **Turbo/onchip claim scoping (issue #83 part 2; docs-only, PRG
  untouched):** the FP_ONCHIP_MUL floor and crossover figures (22.2 s /
  87% of wall @64 MHz, crossovers ~22 MHz P-256 / ~33 MHz P-384) in
  README, API.md §8.4.2, and CLAUDE.md are now explicitly scoped to
  their C64 Ultimate fw 1.1.0 measurement. Cross-device data from the
  c64-x25519 onchip hardware gate (c64-x25519
  `docs/design/issue_72_onchip_mul.md`) shows the per-row REU DMA stall
  is a firmware/generation-dependent wall-clock constant (~160
  wall-ticks C64U fw 1.1.0 vs ~189 U64E fw 3.14 per 512 B row; 532 cy
  on real-1750/VICE) and that neither Ultimate generation reproduces
  real-1750 1 cy/byte DMA under turbo — so floors and crossovers do
  not transfer across devices or workloads, and "real 1750 +
  accelerator" figures are labeled projections. No numeric claim
  changed.

## [0.7.0] — 2026-07-25

### ECDSA verify public-key validation (issue #66)

- **`ecdsa_verify_256` / `ecdsa_verify_384` now validate the public key
  Q at entry** (FIPS 186-5 §3.3): range check `Qx, Qy ∈ [0, p-1]` plus
  on-curve check `Qy² ≡ Qx³ − 3·Qx + b (mod p)`, sequenced as step 3b
  before the mod-n switch. Non-canonical encodings (`Qx ≥ p` or
  `Qy ≥ p`) and off-curve points return C=1 before any scalar
  multiplication — the ABI's "C=1 on malformed inputs" promise now
  holds for the Q fields, not just r/s. Cost: 2 `fp_cmp` + 3 mod-p
  muls + 4 mod-p add/subs per verify (noise vs the multi-second scalar
  mul phase); no new RAM (reuses the dead `ecdsa_w`/`ecdsa_u1`
  scratch); +512 B PRG (37171 → 37683 B). Both the comb-fast and
  `-D ECDSA_NO_COMB` variants carry the gate (common code before the
  step-7 `.ifdef`). New negative-Q cases (non-canonical x+p encoding,
  off-curve bit-flip, random `Qx ≥ p` / `Qy ≥ p`) added to
  `tools/test_ecdsa_verify.py` for both curves.

### Documentation (issue #65)

- **`fp_mod_mul_n` / `fp_mod_mul_n_384` precondition widened** in the
  routine headers (src/mod256.s, src/mod384.s) from "both operands in
  [0, n−1]" to "at least one operand in [0, n−1]" — the invariant the
  bit-serial reduction actually needs, and the one the ECDSA verify
  `u1 = h·w` step relies on when it passes the unreduced digest `h`
  (adversarially reachable ≥ n for P-256 via ~2³² grinding). Names the
  relying caller and warns future editors not to optimize on a
  both-reduced assumption. Comment-only; PRG byte-identical.

## [0.6.0] — 2026-07-20

### FP_ONCHIP_MUL shape 2 — inline quarter-square row generation (issue #71, 2026-07-20)

- **Turbo profile ~26% faster at every speed.** The per-product
  `jsr ct_mul_8x8` in `og_common` (~134 cy incl. reloads) is replaced by
  an inline non-CT quarter-square (~70 cy/product; SMC-baked `a`,
  X=|a−v| diff index, Y=sum index with sum-page branch). The canonical
  §8.3 `ct_mul_8x8` body is untouched (still used for the per-row
  diagonal product); default PRG byte-identical. Measured same-run A/B
  on C64 Ultimate (16/48/64 MHz, oracle-gated): `ecdsa_verify_256`
  @64 MHz **25.5 → 11.8 s vs the DMA-table default (2.16×)**, @48 MHz
  1.78×; `ecdsa_verify_384` @64 MHz 1.59×. Crossovers drop to ~22 MHz
  (P-256) / ~33 MHz (P-384); the stock-1 MHz penalty shrinks to ~2.5×.
  Oracle suite 35/35. Data: `.research/issue71_shape2_2026_07_20/`.
- **Zero-REU operation runtime-validated.** New `make onchip-nocomb-prg`
  (FP_ONCHIP_MUL + ECDSA_NO_COMB — the `*-verify-onchip` archive
  configuration) plus `C64_NO_REU=1` in `tools/test_ecdsa_verify.py`
  (launches VICE with no REU): full oracle suite **35/35 with no REU in
  the machine**, converting the v0.5.0 link-level zero-REU claim into a
  runtime-proven one.
- **Fixed `tools/ct_mul_brute_check.py`** — silently broken since the
  2026-06-19 §8.3 verbatim adoption: its shim still used the pre-§8.3
  register calling convention (A=a/X=b), so it reported 65535/65536
  mismatches against a correct `mul_8x8` (the observed values were the
  canonical body correctly multiplying stale-baked inputs). Now uses the
  canonical convention (Y=b, caller bakes `smc_sum_a_imm+1` /
  `smc_diff_a_imm+1`): PASS 65536/65536.

## [0.5.0] — 2026-07-20

### FP_ONCHIP_MUL turbo profile (issue #69, 2026-07-20)

- **New build profile: on-chip multiply for accelerated hosts.** REU DMA
  transfers at the ~1 MHz bus rate regardless of CPU turbo, so the
  per-row multiply-table fetch inside `fp_mul`/`fp_sqr` is a
  speed-invariant wall-clock floor. Measured on C64 Ultimate fw 1.1.0
  across a 16/48/64 MHz sweep (`wall = F + C/f` fits, residuals ≤2.6%):
  `ecdsa_verify_256` floor **22.2 s** (87% of 25.5 s wall @64 MHz),
  `ecdsa_verify_384` floor 51.7 s. `-D FP_ONCHIP_MUL` replaces all six
  row-fetch sites with sparse on-chip row generation: per-curve entry
  stubs `gen_mul_row` (fp256.s) / `gen_mul_row_384` (fp384.s) SMC-patch
  the shared `og_common` loop (mul_8x8.s), which computes — via the
  canonical §8.3 `ct_mul_8x8`, body untouched — exactly the
  `mul_dma_lo/hi` entries the inner loops read (one product per staged
  src byte + the squaring diagonal). Inner loops, SMC accumulators, and
  the Wave-8a sparse fast path are byte-identical; **default PRG
  byte-identical** (sha256-verified).
- **Measured, oracle-gated (C64U):** verify_256 @64 MHz 25.5 → 16.0 s
  (**1.60×**), @48 MHz 1.32×; verify_384 @64 MHz 62.0 → 53.7 s (1.15×).
  Onchip residual floor ≈0.3 s — scales 3.94× for a 4× clock. Crossover
  ~30 MHz (P-256) / ~55 MHz (P-384); ~3× slower at stock 1 MHz (profile,
  not replacement). Full oracle ECDSA suite: 35/35 against the onchip
  PRG, including CAVP SigVer negatives.
- **Four new archives** (`make lib-onchip`, `lib-p256-verify-onchip`,
  `lib-p384-verify-onchip`, `lib-p384-curve-onchip`) with profile-aware
  §5 manifest (`lib_manifest_onchip.o`: REU banks `$04`; resident 28200 /
  cold 1900 — sqtab + `ct_mul_8x8` become verify-hot). Verify-onchip
  archives issue **no REU DMA at all**; consumer boot obligation shrinks
  to `sqtab_init` only (no §8.2 `reu_mul` provider). `check_archives.py`
  ratchet extended to all nine archives. API.md §8.4.2 documents the
  profile.
- **Tooling:** `make onchip-prg` variant test PRG;
  `tools/test_ecdsa_verify.py` honors `C64_INIT_TIMEOUT` (onchip
  precompute boots ~3× slower under VICE warp); `bench_u64_common.py`
  allows **64 MHz** turbo (C64 Ultimate fw 1.1.0+; U64E firmware
  rejects it at set time).

### Archive linkability — u1·G no-comb fallback (issue #61, 2026-07-18)

- **Every archive is now link-complete.** The verify / curve archives
  ship `-D ECDSA_NO_COMB` variants of the packaged verifiers
  (`ecdsa256_nocomb.o` / `ecdsa384_nocomb.o`): `u1·G` routes through
  `ec_scalar_mul_var[_384]` seeded at G instead of the excluded Lim-Lee
  comb, so `ecdsa_verify_256` / `ecdsa_verify_384` /
  `ecdsa_verify_with_message_384` link standalone from
  `lib-p256-verify` / `lib-p384-verify` / `lib-p384-curve`. Trade-off:
  no comb boot pass or REU bank-2 residency, but a verify costs roughly
  two variable-base scalar mults (up to ~2× slower). Full archive +
  standalone PRG keep the comb-fast variants; **default PRG
  byte-identical**.
- New `make nocomb-prg` target builds the standalone test PRG with the
  nocomb variants substituted; `tools/test_ecdsa_verify.py` grew
  `C64_PRG_NAME` / `C64_LABELS_NAME` env overrides so the full oracle
  suite runs against it (35/35 on the fallback path).
- `check_archives.py` ratchet flipped: all `KNOWN_EXTERNAL` gaps
  closed, packaged-verifier smokes expect clean links everywhere.
  API.md §8.4.1 rewritten as a comb/no-comb variant table; Makefile
  banner caveats replaced.

### Archive linkability (2026-07-18)

- **`ecdsa_verify_with_message_384` now links from consumer archives
  (issue #63).** The test-only trampoline
  `ecdsa_verify_with_msg_384_tramp` moved from `src/ecdsa384_msg.s` to
  `src/main.s` (the test-driver home, never archived), so
  `ecdsa384_msg.o` no longer imports the test-driver buffers
  `ecdsa_inputs_384` / `ecdsa_result_msg_384`. The wrapper links clean
  from the full `nistcurves.a`; from `lib-p384-curve` it now fails only
  on the comb (`ec_scalar_mul_384`, issue #60/#61 territory), no longer
  on test buffers. `check_archives.py` expectations flipped accordingly
  (nistcurves.a: no gaps). Standalone PRG size unchanged (37171 B; code
  relocated between objects, so addresses shift but the test trampoline
  keeps its exported name and the Python driver is unaffected).

## [0.4.0] — 2026-07-17

### Archive linkability contract + ratchet (issue #60, 2026-07-16)

- **Documented the packaged-verifier archive contract (API.md §8.4.1).**
  The trimmed verify archives exclude the Lim-Lee fixed-base comb by
  design, so the packaged verifiers `ecdsa_verify_256` /
  `ecdsa_verify_384` — which `jsr` the comb (`ec_scalar_mul` /
  `ec_scalar_mul_384`) for the `u1·G` step — are **not linkable from
  those archives alone**. Pre-existing since PR #40; now stated
  explicitly where consumers look (API.md §8.4.1, the Makefile archive
  banner, CLAUDE.md Known issues) with the supported variable-base
  building-block path and the comb add-on link recipe
  (`points256_comb.o` + `data_p256_limlee.o`, or the full `nistcurves.a`)
  plus its boot cost (`ec_precompute_*` ~25 s / ~80 s at 1 MHz) and REU
  bank-2 residency.
- **Blast-radius finding:** verified the P-384 mirror
  (`lib-p384-verify` / `lib-p384-curve`) and additionally found that
  `ecdsa_verify_with_message_384` is unlinkable even from the full
  `nistcurves.a` — its object `ecdsa384_msg.o` carries a *test-only*
  trampoline referencing the test-driver buffers `ecdsa_inputs_384` /
  `ecdsa_result_msg_384` (excluded from every archive). Documented as a
  second gap; tracked in #63 (relocate the test-only trampoline out of
  `ecdsa384_msg.o`).
- **New `tools/check_archives.py` + `make check-archives` target.** A
  contract ratchet: an od65 import/export closure sweep plus `ld65`
  dummy-link smoke tests per archive, checked against a documented
  per-archive allowlist of deliberate gaps. Fails if reality drifts
  *looser* (a new unresolved symbol — regression) or *tighter* (a
  documented gap that unexpectedly resolves — stale docs). Object lists
  are parsed from the Makefile `ar65` recipes (single source of truth),
  not hardcoded. python3 stdlib only; no VICE. Standalone PRG unchanged
  (byte-identical); docs + tooling only.

### Archive slimming (2026-07-16)

- **`lib-p256-verify` BSS trimmed to verify-path-only slots (issue #54,
  −261 B).** `LIB_NISTCURVES_P256_BSS` extent on a consumer link drops
  1573 B → **1312 B**:
  - `fp_tmp1` (32 B) → new `src/data_p256_invref.s` (segment
    `LIB_NISTCURVES_P256_INVREF_BSS`) riding with `inv256.o` — full
    archive + standalone PRG only;
  - `ec_sc_byte` / `ec_sc_mask` (2 B) → `src/data_p256_limlee.s`
    (comb-only scalar-walker state, already excluded from the verify
    archive);
  - `fp_tmp2..4` (96 B) → `src/data_test.s`: referenced by NO .s code,
    but the Python test/bench harness stages field operands there, so
    they move to the test-only object instead of the outright delete
    the issue proposed (consumer-side effect identical);
  - `fp_r1..3`, `fp_inv_iter`, `fp_red_tmp` (131 B) deleted —
    unreferenced by any .s or tool.
  Standalone PRG: 37302 B → 37171 B. Verified: full P-256 field
  (471/471) + point (41/41) + ECDSA-verify suites pass; dummy consumer
  link against the trimmed archive resolves every import on the
  variable-base verify path.
- **Known pre-existing gap (NOT introduced here):** `lib-p256-verify`
  cannot link the packaged `ecdsa_verify_256` — it `jsr`s the fixed-base
  comb `ec_scalar_mul` (u1·G step), which `points256_comb.o` provides
  and the archive excludes by design since #40. Confirmed identical on
  the pre-trim baseline. Tracked separately.

### Tooling / research — REU multiply-table audit (PR #58, 2026-07-16)

- **Committed the REU multiply-table footprint/ROI audit**
  (`.research/reu_mult_audit_2026_05_21/report.md`) and its measurement
  tool `tools/bench_reu_mult.py` (added to the Test-section command
  list). Verdict: keep the 128 KB table (~2× fp_mul speedup vs the
  no-table alternative; REU banks 0–1 are otherwise idle).
- **Corrected the CLAUDE.md per-row DMA-cost claims.** The prior "20
  cycles per row / <1% of fp_mul" figures counted only the register
  setup head. Measured full row fetch is ~542 cy (20 cy setup + ~512 cy
  DMA cycle-steal stall); DMA is ~23% of `fp_mul` / ~18% of
  `fp_mul_384`. The Wave 4c Karatsuba negative-finding passage was
  reworded to match. Docs/tooling only — standalone PRG byte-identical.

### Shared-primitives shape (2026-07-15)

- **§8.3 manifest bit landed + §8.0 conditional mask adopted
  (c64-lib-contract v0.4.0).** `src/lib_manifest.s` now defines
  `LIB_SHARED_PRIMITIVES_CT_MUL_8X8 = $0004` and builds
  `LIB_NISTCURVES_SHARED_PRIMITIVES` in the conditional form required by
  SPEC §8.0 (issue #21): each bit is included iff this build does NOT
  defer that primitive via its migration switch. Standalone build
  exports `$0007` (sqtab | reu_mul | ct_mul_8x8); a build with
  `-D SHARED_CT_MUL_8X8` drops to `$0003`; deferring all three yields
  `$0000` (verified via `od65 --dump-exports`). PRG byte-identical
  (37302 B) — equates only, no runtime impact.

### Shared-primitives shape (2026-06-19)

- **`mul_8x8` body migrated to the canonical `ct_mul_8x8` shape
  (c64-lib-contract issue #14 / §8.3 candidate).** The constant-time
  quarter-square body in `src/mul_8x8.s` is now byte-identical to
  c64-ChaCha20-Poly1305's canonical `ct_mul_8x8` (59 B, sum-first,
  SMC-baked `a` + `b` in Y, `ct_diff_raw`/`ct_sign_mask` scratch),
  replacing the prior register-entry adaptation (A=a/X=b with a
  `tay`/`stx mul_b` preamble + Y-shuttle). This satisfies the
  cross-adopter byte-identity gate `tools/ct_mul_brute_check.py`
  (`chacha vs nist-curves = YES`). `mul_8x8` is retained as a
  back-compat alias of `ct_mul_8x8`; the body is gated on
  `.ifndef SHARED_CT_MUL_8X8` (mirrors §8.1 `SHARED_SQTAB_INIT`).
- **`reu_mul_init` (src/main.s) rewired** to SMC-bake `a` into
  `smc_sum_a_imm+1` / `smc_diff_a_imm+1` once per outer-a iteration and
  pass `b` in Y across the inner loop — chacha's amortized calling
  convention. Boot-only path; no runtime field/point op calls `mul_8x8`.
- No functional or size change: PRG stays 37302 B and all P-256/P-384
  field tests pass. The §8.3 manifest bit (`$0004`) is deferred to a
  follow-up after the contract clause allocates it.

### Shared-primitives shape (c64-lib-contract SPEC v0.3.x, 2026-05-24)

- **§8.2 `reu_mul` promoted to a placement-overridable shared primitive
  (PR #55).** `src/reu_config.s` adds `.ifndef`-guarded
  `LIB_SHARED_REU_MUL_BANK` / `_OFFSET` equates (spec `.assert`s:
  offset `$0000`, bank `< $FE`) plus the derived two-bank mask
  `LIB_SHARED_REU_MUL_BANKS_USED`. The legacy
  `LIB_NISTCURVES_REU_BANK_MUL` stays as a back-compat alias.
  `src/main.s` wraps the `reu_mul_init` body under
  `.ifndef SHARED_REU_MUL_INIT` and exports the SPEC-canonical alias
  `reu_mul_tables_init = reu_mul_init` (safe-to-call-twice). The manifest
  gains `LIB_SHARED_PRIMITIVES_REU_MUL = $0002`, OR-ed into
  `LIB_NISTCURVES_SHARED_PRIMITIVES` alongside the §8.1 sqtab bit.
- **§8.0 step-6 catch-loop enumeration (PR #55).** New
  `src/precalc_table.inc` (copied verbatim from c64-lib-contract so the
  `LIB_PRECALC_TABLE` macro is byte-identical across adopters) and
  `src/precalc_manifest.s` enumerate every precalculated table: the two
  normative shared primitives (sqtab §8.1, reu_mul §8.2) plus three
  library-private tables, with `lim_lee_comb` split per-curve
  (`_p256` 16 KB / `_p384` 24 KB) to match the per-curve verify-archive
  membership. Human-readable rationale in new `docs/precalc-tables.md`
  (authoritative against the manifest; asymmetry blocks adopter PRs).
- **No build-output change:** PRG byte-identical at 37302 B (equates +
  new assemble-only manifest modules; no code growth).

## [0.3.0] — 2026-05-20

### Shared-primitives shape (2026-05-20)

- **`sqtab` migrated to c64-lib-contract SPEC §8.1 placement contract.**
  `sqtab_lo` / `sqtab_hi` in `src/mul_8x8.s` now derive from
  `LIB_SHARED_SQTAB_BASE` — `.ifndef`-guarded with the historical `$9c00`
  default for standalone builds, overridable by consumers linking against
  multiple sqtab-using sibling libs into one PRG via
  `ca65 --asm-define LIB_SHARED_SQTAB_BASE=$<addr>`. Two `.assert` guards
  catch the failure mode that drove the 2026-05-17 `$7800 → $9c00` move
  at assemble time rather than at boot:
  `(LIB_SHARED_SQTAB_BASE & $00ff) = 0` (page-aligned base for cycle-stable
  `abs,x`) and `sqtab_hi = sqtab_lo + $0200` (SMC dispatch's lo→hi delta).
- **`sqtab_init` body gated on `.ifndef SHARED_SQTAB_INIT`.** When a
  consumer defines `SHARED_SQTAB_INIT`, the library's per-lib init body
  (and its scratch) is excluded so a shared-primitives module can supply
  the canonical `mul_tables_init` per SPEC §8.1 without source patching.
  Standalone build behavior unchanged.
- **Manifest equate `LIB_NISTCURVES_SHARED_PRIMITIVES`** added to
  `src/lib_manifest.s` per SPEC §5 + §8.0, OR-composed from the §8.x bit
  constants the library consumes. Currently
  `LIB_SHARED_PRIMITIVES_SQTAB = $0001` only. Lets consumers
  `.assert (LIB_NISTCURVES_SHARED_PRIMITIVES .and LIB_X_SHARED_PRIMITIVES) = 0`
  to catch duplicate ownership at assemble time. Append-only — future §8.x
  primitives get the next free bit.
- **No build-output change.** PRG byte-identical (37302 B); `sqtab_lo`
  still at `$9c00`, `sqtab_hi` still at `$9e00`. Tracking issue
  [JC-000/c64-lib-contract#5](https://github.com/JC-000/c64-lib-contract/issues/5);
  paired with c64-lib-contract PR #6 (SPEC §8 patch) and
  c64-https PR #46 (stub size fix).

### Library packaging (2026-05-20)

- **`c64-lib-contract` SPEC §1 + §3 + §4 + §5 adoption** — landed across
  PRs #43, #45, #46, #48 alongside the §6 work below. The library now
  exposes every contract symbol downstream consumers (c64-https,
  c64-wireguard, future TLS / IPsec clients) need to ingest it without
  patching library sources at integration time:
  - **§1 version equates.** Added the fourth SPEC §1 equate
    `LIB_ABI_VERSION = 0` (matches `LIB_VERSION_MAJOR`; bumps in
    lockstep on breaking exports) to `src/lib_version.s` alongside the
    pre-existing `LIB_VERSION_MAJOR/MINOR/PATCH`. PR #48.
  - **§3 REU symbol contract.** New `src/reu_config.s` exports four
    `.ifndef`-guarded `:abs` equates: `LIB_NISTCURVES_REU_BANK_MUL`
    (`$00`; claims banks MUL and MUL+1 for the 128 KB mul cache),
    `LIB_NISTCURVES_REU_BANK_COMB` (`$02`; Lim-Lee anchors),
    `LIB_NISTCURVES_REU_OFFSET_COMB_P256` (`$0000`),
    `LIB_NISTCURVES_REU_OFFSET_COMB_P384` (`$4000`). Replaces hardcoded
    REU bank/offset literals at every mul-row fetch and comb-table
    stash/fetch site (`main.s`, `mul_8x8.s`, `fp256.s`, `fp384.s`,
    `points256.s`, `points384.s`). Consumer override:
    `ca65 --asm-define LIB_NISTCURVES_REU_BANK_COMB=$05 ...`. PR #43.
  - **§4 segment naming.** Renamed every library `.segment "CODE"` /
    `"RODATA"` / `"DATA"` / `"TABLES"` / `"BSS"` to per-variant
    `LIB_NISTCURVES_*` segments: `LIB_NISTCURVES_P256_CODE` / `_RODATA`,
    `LIB_NISTCURVES_P384_CODE` / `_RODATA` / `_BSS` (for fp384's small
    BSS block), `LIB_NISTCURVES_SHA384_CODE` / `_RODATA` / `_TABLES`,
    `LIB_NISTCURVES_MUL_CODE`, `LIB_NISTCURVES_MAIN_CODE` / `_RODATA`
    (test-driver-only), `LIB_NISTCURVES_TABLES`, `LIB_NISTCURVES_BSS`.
    `src/c64.cfg` gains a SEGMENTS{} alias block so the standalone test
    PRG builds byte-identically. Closes #41. PR #45.
  - **§5 aggregate manifest equates.** New `src/lib_manifest.s` exports
    `LIB_NISTCURVES_REU_BANKS_USED = $07` (bitmask: banks 0+1 mul cache,
    bank 2 comb anchors), `LIB_NISTCURVES_ZP_USAGE_BYTES = 31`,
    `LIB_NISTCURVES_RESIDENT_BYTES = 27000`,
    `LIB_NISTCURVES_COLD_BYTES = 2500`. Consumer cfgs use these for
    assemble-time fit checks against ld65 `__<MEMORY>_SIZE__` symbols
    before kicking off long compile + VICE test cycles. Closes #42.
    PR #46.
  - The PRG and every test pass without change. The adoption is purely
    additive on the public symbol surface (no removals or renames). See
    [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
    adopters.md for the cross-library status table.
- **Per-curve / per-feature `data.s` split + minimal-archive build
  targets** — implementing `c64-lib-contract` SPEC §6 (closes #40).
  The monolithic `src/data.s` is now split into seven self-describing
  files: `data_shared` (mul scratch + page-aligned DMA pages),
  `data_p256` / `data_p256_limlee` (P-256 core / Lim-Lee anchors),
  `data_p384` / `data_p384_limlee` (P-384 mirror),
  `data_sha` (SHA-384 stream state + digest), and `data_test` (the
  test-driver staging buffers `ecdsa_inputs_*` / `sha384_msg_buf`).
  Each file declares its own `LIB_NISTCURVES_*_BSS` segment so a
  consumer pulling a minimal archive does not link in buffers it
  cannot reach. `src/c64.cfg` gains the new segments with
  `optional = yes` so the standalone PRG and full-library archive
  both link unchanged (PRG remains 37,302 bytes loaded at $0801).
- **`points256.s` / `points384.s` split into `_core.s` + `_comb.s`.**
  The core file hosts `ec_point_double`, `ec_point_add` (mixed
  J+affine), `ec_point_add_jj` (full J+J), `ec_scalar_mul_var`
  (variable-base for ECDSA verify), and `ec_jacobian_to_affine`.
  The comb file hosts `ec_precompute_*` and `ec_scalar_mul`
  (Wave 7a h=8 Lim-Lee fixed-base) plus the `sm256_reu_*` /
  `sm384w_*` REU-table stash/fetch helpers, which are only called
  by the comb code. Verify-only consumers exclude the comb file
  and recover ~10 KB of code + 4-6 KB of Lim-Lee anchors per curve.
- **`ecdsa_verify_with_message_384` factored into
  `src/ecdsa384_msg.s`.** The one-shot SHA-384 + verify wrapper
  pulls in the SHA-384 primitives transitively; consumers driving
  streaming SHA themselves (TLS-style multi-buffer transcripts) link
  the bare `ecdsa_verify_384` without dragging in the wrapper.
- **Five new `make lib*` archive targets** (`lib`, `lib-p256-verify`,
  `lib-p384-verify`, `lib-p384-sha384`, `lib-p384-curve`) published
  under `build/lib/nistcurves-*.a`. Each is composed by name from the
  per-curve / per-feature object sets above; see API.md §8.4 for the
  inventory and intended use cases. The pre-existing `make` (no args)
  standalone test PRG target is unaffected and continues to build a
  byte-identical 37,302-byte PRG. `ar65 t build/lib/nistcurves-*.a`
  confirms object counts: full archive ships 26 objects;
  `p256-verify` and `p384-verify` ship 12 each; `p384-curve` ships
  15; `p384-sha384` is the tightest at 4 (no REU / no multiply
  tables, since SHA-384 is self-contained).

### Added (2026-05-19, second wave)

- **Bench coverage for `ec_point_add_jj{,_384}` and `fp_mod_mul_n{,_384}`** —
  four new primitive bench rows so the J+J point-add (load-bearing at
  the ECDSA verify `u1*G + u2*Q` join since PR #34) and the mod-n
  multiply (called twice per verify for `u1 = h*w` and `u2 = r*w`) are
  finally measurable. Four new trampolines in `src/main.s` with marker
  tokens `$8A`/`$8B` (P-256 J+J), `$8C`/`$8D` (P-384 J+J), `$8E`/`$8F`
  (P-256 mod-n mul), `$90`/`$91` (P-384 mod-n mul). New `BENCH_PLAN`
  rows in `tools/bench_p256.py`, `tools/bench_p384.py`,
  `tools/bench_p256_u64.py`, `tools/bench_p384_u64.py`. PRG remains
  37,302 bytes — the four trampolines absorbed cleanly into the
  existing TABLES alignment pad (no new page needed). J+J operand
  setup lifts `(3G, 5G)` to Jacobian with non-trivial Z values so the
  formula must execute the `Z1*Z2` / `Z1^2` / `Z2^2` multiplies it
  would otherwise skip in the mixed-add path; oracle verifier composes
  `affine(3G) + affine(5G)` via the existing library helpers.
  Motivation: the PR #26 + PR #34 measured-vs-predicted retrospective
  showed primitive-bench extrapolation overshot real ECDSA savings by
  10-20×; making the J+J and mod-n-mul primitives directly measurable
  closes one of the gaps that retrospective identified (audit
  Section 8 / `.research/audit_2026_05_18/a4_call_graph.md` §1.3, §1.9).
  Measured @ VICE 1 MHz (cycles/call, 1-MHz-equivalent):

  | Primitive            | P-256 cyc   | P-384 cyc   |
  |----------------------|------------:|------------:|
  | `fp_mod_mul_n`       |     463,624 |   1,036,336 |
  | `ec_point_add_jj`    |   1,295,420 |   2,454,480 |

  Measured @ U64E NTSC (cycles/call, 1-MHz-equivalent wall-clock — see
  CLAUDE.md "Jiffy-clock / REU-DMA wall-clock non-linearity" known
  issue):

  | Primitive            | P-256 @16 MHz | P-256 @48 MHz | P-384 @16 MHz | P-384 @48 MHz |
  |----------------------|--------------:|--------------:|--------------:|--------------:|
  | `fp_mod_mul_n`       |        33,024 |        14,346 |        70,310 |        28,692 |
  | `ec_point_add_jj`    |       168,958 |       122,866 |       284,438 |       194,833 |

  48-MHz speedup is sub-linear (~2.3× for mod-n-mul, ~1.4× for J+J)
  rather than the naïve 3×, because REU DMA fixed-rate dominates the
  bench surface — consistent with the wall-clock non-linearity bound
  documented in CLAUDE.md. Sweep was co-measured (both speeds in one
  invocation) to immunise against the CIA Timer A drift documented at
  48 MHz cross-run.

### Added (2026-05-19)

- **`tools/bench_sha384.py` — VICE 1 MHz SHA-384 per-block bench.**
  New primitive bench that resolves the per-block `sha_compress` cost
  that the U64E turbo bench (`bench_ecdsa_u64.py`) can only bound from
  above at 17,045 1-MHz-equivalent cycles (one jiffy) for short
  messages. Length sweep `{0, 55, 56, 111, 112, 127, 128, 129, 200,
  1024, 4096}` covers SHA-2 padding boundaries (55/56 and 111/112),
  block-boundary transitions (127/128/129), and multi-block
  amortisation (1024, 4096). Oracle gate is `hashlib.sha384` for each
  length. Trampoline at `$C000` (no `src/main.s` edits — reuses
  `bench_start` / `bench_stop`); PRG byte-identical to master at 37,302
  bytes. Measured per-block compress cost = **~517 kcy / block at
  1 MHz** (~30 jiffies), stable across the L=1024 → L=4096 and
  L=0 → L=1024 differencing rows. Resolves the audit Tier-1 #2
  follow-up from `.research/audit_2026_05_18/perf_audit_2026_05_18.md`
  §10 / §11.
- **Bench coverage for `ecdsa_verify_with_message_384`** — the one-shot
  SHA-384 + ECDSA verify wrapper now has a U64E bench row. Added
  `bench_ecdsa_verify_with_msg_384_tramp` to `src/main.s` (marker
  tokens `$88` / `$89`; the 24-byte trampoline is absorbed into the
  existing TABLES alignment pad, so PRG remains 37,302 bytes — exactly
  byte-neutral). Added `setup_ecdsa_verify_with_msg_384` +
  `verify_ecdsa_verify_with_msg_384` + BENCH_PLAN row to
  `tools/bench_ecdsa_u64.py`. Message = RFC 6979 A.3.1 "sample"
  (6 bytes). Oracle gate (`cryptography.hazmat` ECDSA verify on the
  same vector) passed. Measured @ 16 MHz / 48 MHz:

  | Speed   | `ecdsa_verify_384` | `ecdsa_verify_with_msg_384` | Δ (SHA cost) |
  |---------|-------------------:|----------------------------:|-------------:|
  | 16 MHz  | 111,065,220 cyc    | 111,082,265 cyc             | +17,045 cyc (1 jiffy) |
  | 48 MHz  |  80,605,805 cyc    |  80,605,805 cyc             | 0 cyc (sub-jiffy)     |

  SHA-384 hash overhead for a 6-byte message is bounded above by
  17,045 cyc (1-MHz-equivalent) at both speeds, including `sha384_init`
  + `sha384_update` + `sha384_final` (one compress for the padding
  block). The earlier audit-internal estimate of ~1.2 Mcy per
  `sha_compress` block is revised downward by **~70×**; actual compress
  is sub-jiffy at U64E turbo. Resolving the per-block compress cost
  precisely will need a dedicated SHA-384 bench at canonical TLS
  message lengths {0, 55, 56, 111, 112, 200, 1024, 4096 B}, ideally
  run at VICE 1 MHz where one block lands at ~3-9 jiffies (not
  implemented in this PR).

### Fixed (2026-05-19)

- **`tools/bench_p384.py:331` init-sentinel timeout** raised from 180 s
  → 600 s (matching `tools/bench_p256.py:406`). The h=8 Lim-Lee
  precompute boot path takes ~205-246 s at HEAD; the previous 180 s
  ceiling made the tracked bench script broken-at-HEAD without source
  modification. P-256 already used 600 s for the same sentinel and
  passed. The 600 s budget gives ~2.5×-3× headroom over the observed
  init wall time across both VICE and U64E.

### Measured (post-merge retrospective, 2026-05-18)

- **PR #26 and PR #34 ECDSA verify savings are 10-20× smaller than
  predicted.** Both PRs forecast ~800 kcy P-256 / ~1.7 Mcy P-384
  per-verify savings from eliminating `fp_mod_inv` calls (primitive
  bench: ~750 kcy/call). Three-point U64E bench at fw 3.14d (PR #19
  README baseline at `d53971e` / PR #26 build at `460de8f` /
  PR #34 master at `788adc3`):

  | Stage | Predicted | Measured P-256 @16 MHz | Measured P-384 @16 MHz |
  |---|---|---|---|
  | PR #19 → PR #26 | ~800 kcy / ~1700 kcy | −51 kcy (3 jiffies) | −85 kcy (5 jiffies) |
  | PR #26 → PR #34 | ~800 kcy / ~1700 kcy | −17 kcy (1 jiffy) | −102 kcy (6 jiffies) |
  | Combined | ~1.6 Mcy / ~3.4 Mcy | −68 kcy (≈0.16%) | −187 kcy (≈0.17%) |

  Combined RAM cost: ~2 KB PRG + 192 B DATA. RAM-per-cycle-saved is
  dramatically worse than the predictions implied. Likely root cause:
  `fp_mod_inv` is binary GCD with input-sensitive runtime; the Z
  coordinates emerging from `ec_scalar_mul` consistently hit GCD
  fast paths (byte alignment, low Hamming weight, or small magnitude),
  so the eliminated inversions were already cheap in context.

  No code reverted — PR #34 added the `ec_point_add_jj` primitive as
  a useful building block and the sqtab/mul_dma collision fix is
  independently valuable. But the verify-rewiring portion of PR #34
  buys very little measured benefit for its RAM cost.

  **Process change going forward:** any optimization PR that costs
  PRG or DATA bytes must measure on the integrated bench
  (`bench_ecdsa_u64.py`, `bench_p256/p384_u64.py`) before merge and
  cite measured cycles before/after in the PR description. Primitive-
  cost extrapolation is unreliable when the eliminated primitive has
  data-dependent runtime — sibling to the Wave 8a `beq`-removal
  negative finding in the opposite direction. See CLAUDE.md "Negative
  findings" §PR #26+#34 entry for the full lesson.

### Added

- **`ec_point_add_jj` / `ec_point_add_jj_384`** — full Jacobian + Jacobian
  point addition primitives (Bernstein-Lange add-2007-bl, 11M + 5S +
  ~10 add/sub) in `src/points256.s` and `src/points384.s`. Inputs read
  ec_p1 and ec_p2 as full Jacobian points (both Z values consumed,
  unlike the existing `ec_point_add` mixed-add which treats Z2 as 1).
  Result lands in ec_p3. Handles all degenerate cases natively: P1 or
  P2 = infinity (verbatim copy of the other), same projective point
  (tail-call to `ec_point_double`), P1 = -P2 (zero output), both
  infinity. New scratch slot per curve (`ec_jj_tmp` 32 B and
  `ec384_jj_tmp` 48 B in `src/data.s`); existing `ec_t1..t6` cover the
  rest of the formula. Cycle cost is roughly 2x `ec_point_add` (which
  is 7M + 4S mixed-add) — the extra Z2 work is the price for
  eliminating a final inversion in the verify pipeline below.
  Tested via new `test_point_add_jj` / `test_point_add_jj_384` cases
  in `tools/test_points{256,384}.py`: 5 edge cases (P1∞, P2∞, both∞,
  P+P with different Z lifts → 2P, P+(-P) → ∞) + 3 random pairs each
  with independent random Z lifts; oracle = `loader.affine_add` on the
  affine projections.

### Changed

- **ECDSA verify pipeline** (`src/ecdsa256.s`, `src/ecdsa384.s`) — replace
  the final `u1*G + u2*Q` mixed-add (and its preceding affine conversion
  of u1*G) with the new full Jacobian + Jacobian add. Saves one binary-
  GCD inversion + three mod-p multiplies per verify on top of the PR #26
  cofactor-compare landing (which removed the final-point inversion).
  The `@ev_r_from_u1g` short-circuit branch (handling the rare
  u2*Q = infinity case via affine compare of u1*G.x mod n vs r) is
  deleted; the cofactor compare's `r * R.Z² ≡ R.X (mod p)` gate handles
  both Z = 1 and Z ≠ 1 cases uniformly, so it subsumes the special path.
  Replaces `ecdsa_u1g_x` / `ecdsa_u1g_y` (32 + 32 B P-256, 48 + 48 B
  P-384) with `ecdsa_u1g_jac` / `ecdsa384_u1g_jac` (96 B / 144 B) —
  net DATA delta is +96 B for P-256 and +96 B for P-384 (the affine
  pair was 64 B / 96 B; the Jacobian buffer is 96 B / 144 B). Combined
  with the J+J primitives, total PRG delta is +1440 B (35862 → 37302).

### Fixed

- **`sqtab` memory-map collision** (`src/mul_8x8.s`). The quarter-square
  multiply table at the hard-coded equate `sqtab_lo = $7800` had no
  guard against the linker-managed `mul_dma_lo` / `mul_dma_hi` page-
  aligned slots (`src/data.s` TABLES segment) growing into the same
  address as code expanded. The `ec_point_add_jj` primitive's ~1 KB of
  new code pushed `mul_dma_hi` from `$7500` to `$7800`, silently
  aliasing `sqtab_lo` — which `sqtab_init` then clobbered, leaving
  multiply rows zero and hanging the boot sentinel. Same bug shape as
  the PR #27 / w-NAF re-land hang. Surgical fix: move sqtab equates
  to `$9C00` / `$9E00`, ~1 KB of headroom above the current top of
  DATA (~$988A). The SMC-page-delta math in `mul_8x8` is computed
  from the equates so the page-aligned-base constant-time invariant is
  preserved automatically. See the file header comment for the full
  rationale and the page-bump procedure if future growth threatens
  the new address.

- **SHA-384 streaming hash** (`src/sha384.s`, ~970 lines). FIPS 180-4 §6.4
  compression with SHA-384 IV and 48-byte BE truncated output. Streaming
  ABI: `sha384_init` (clear + IV) / `sha384_update` (absorb sha_len bytes
  from sha_src) / `sha384_final` (pad + finalize → sha384_digest). LE
  storage on-chip with byte reversal at the wire boundaries. Self-contained
  module — no REU DMA, no shared field/point scratch. Test coverage:
  `tools/test_sha384.py`, 25/25 against the `hashlib.sha384` oracle (4
  mandatory FIPS 180-4 KATs + 17 boundary-length random + 4 multi-block
  stress including 4 KB). PRG grew 24322 → 32022 B (~7.7 KB; ~1.7 KB of
  that is a test scratch buffer).

- **`ecdsa_verify_with_message_384`** (`src/ecdsa384.s`). One-shot wrapper
  that hashes a contiguous message via the new SHA-384 module, splices the
  digest into a 240-byte caller-owned BE struct (`r | s | h_unused | Qx |
  Qy`), then tail-calls `ecdsa_verify_384`. C=0 valid / C=1 invalid; same
  return convention as the underlying verify. For TLS-style transcripts
  spanning multiple buffers, callers should drive `sha384_init/update*/final`
  directly and call `ecdsa_verify_384` with the digest pre-spliced. New
  tests in `tools/test_ecdsa_verify.py`: 5 positive (random msgs 1/17/100/500/1023 B
  with fresh `cryptography` keypairs) + 2 negative (tampered msg / wrong
  pubkey).

### Changed

- **`read_bytes_verified` integration in field-arithmetic tests.** The
  four single-byte carry/borrow verifier reads inside `c64_fp_add`
  and `c64_fp_sub` in `tools/test_fp256.py` and `tools/test_fp384.py`
  now use `c64_test_harness.read_bytes_verified` rather than plain
  `read_bytes`. Future flakes at those sites will raise
  `FlakeyReadError` (a distinct exception type) instead of silently
  returning corrupted bytes that masquerade as wrong-answer assertion
  failures. Bulk coordinate reads, wide-result reads, and the
  `$02A7` startup sentinel poll are deliberately NOT converted — the
  helper doubles wire traffic per call and is only worth it at
  verifier sites where a flake would silently look like a test bug.
  Requires c64-test-harness PR #89 (`read_bytes_verified` helper) or
  later; older harness installs will fail on the import. Tests still
  pass cleanly: 471/471 (P-256) and 473/473 (P-384).
- **VICE-contention preflight warning** in all eight VICE-targeting
  scripts under `tools/`: `test_fp256.py`, `test_fp384.py`,
  `test_points256.py`, `test_points384.py`, `test_ecdsa_verify.py`,
  `test_inv_fast.py`, `bench_p256.py`, `bench_p384.py`. Each `main()`
  now calls `_warn_if_vice_running()`, which shells out to
  `pgrep -c x64sc` (2 s timeout, all exceptions swallowed) and prints
  a one-line stderr warning when another `x64sc` is already running
  — surfaces the wall-clock-contention pattern that previously
  manifested as spurious per-call timeouts in concurrent test runs.
  Purely observational; never blocks or fails. U64-hardware bench
  tools (`bench_p256_u64.py`, `bench_p384_u64.py`,
  `bench_ecdsa_u64.py`, `bench_u64_common.py`) deliberately skipped —
  those don't drive VICE.
- **API.md v0.1.x → v0.2.x example refresh.** Five sites refreshed
  in §8.1 / §8.5 / §8.6 to suggest the current release as the
  default pin for new consumers: submodule integration example
  (`git checkout v0.2.0` + commit message), bumping example
  (`v0.2.1` placeholder), version-pinning check
  (`LIB_VERSION_MINOR < 2`, error string `"c64-nist-curves v0.2.0 or
  newer is required"`), PATCH-bump example (`v0.2.0 → v0.2.1`), and
  the `c64-https` / `c64-wireguard` "as of" reference. The historical
  release-ledger line in `README.md` is preserved unchanged. No
  library code or ABI changes; documentation only.
- **Doc staleness sweep, post-PR #23.** Five drift fixes accumulated
  across v0.1.0 → v0.2.0 → SHA-384 work. (1) API.md §2 PRG-size cell
  no longer pins a specific byte count — points readers at
  `build/labels.txt` instead. (2) API.md §7 limitations entry on
  scalar multiplication rewritten — `ec_scalar_mul_var[_384]` exists
  as of v0.2.0 and ECDSA-verify is provided; the actual surviving
  limitation is "both scalar-mul paths are non-constant-time, public-input
  only" (the fixed-base comb also branches on comb index and infinity flag).
  (3) CLAUDE.md ECDSA-verify-API buffer accounting refreshed for the +3 B
  `ecdsa_verify_with_message_384` wrapper additions
  (`ecdsa384_msg_struct_ptr` + `ecdsa_result_msg_384`). (4) README.md
  feature-bullet list rejoined (stray blank line removed). (5) README.md
  `## Status` checklist gains rows for packaged ECDSA verify and SHA-384
  streaming hash.

## [0.2.0] — 2026-05-12

### Security

- **Issue #33-class REU register-residue defence** (ported from
  c64-x25519 commit `817f525`). The per-row REU DMA fetch in `fp_mul`
  / `fp_sqr` (256+384) writes only 3 of 8 REU registers per call,
  trusting `reu_reu_lo` (`$DF04`) and `reu_addr_ctrl` (`$DF0A`) remain
  `$00` from `reu_mul_init`'s tail. A caller that touched those two
  registers after boot (e.g. a sibling REU consumer in a composed
  system like the planned `c64-https` / `c64-wireguard` integrations)
  would have caused row fetches to DMA from the wrong REU offset or
  with hold-C64-address mode, silently producing
  deterministic-but-wrong field results. The x25519 sibling reported
  exactly this composition-bug shape under c64-https TLS handshake
  derivation. Defence: defensive `lda #0 / sta reu_reu_lo / sta
  reu_addr_ctrl` at every public entry point that initiates DMA —
  `fp_mul` / `fp_sqr` (×2 curves), `ec_scalar_mul` / `_var` (×2
  curves), `ecdsa_verify_256` / `_384`. ~80 raw bytes of code across
  10 sites; +6 cycles per call (transparent CT-neutral, unconditional
  stores). PRG grows from 24322 → 24578 bytes; +176 of that is
  page-alignment shift on the TABLES segment, not real code. Same bug
  shape and fix as the x25519 sibling.

### Fixed

- **Issue #18 (`fp_sqr_384` hangs in standalone-link consumer builds)** —
  `fp_sqr_384`'s diagonal loop called `reu_fetch_mul_row`, which was
  defined in `src/main.s`. Per `API.md` §8.2, consumers of the math
  library do NOT link `main.s` into their PRG (it is the library's own
  test/bench driver), so the `jsr reu_fetch_mul_row` site resolved to
  an unresolved / garbage target and squaring hung. `fp_mul_384` was
  unaffected because it inlines the REU DMA sequence; `fp_sqr` (P-256)
  also inlines, so this was a P-384-squaring-only asymmetry. Fix:
  relocated `reu_fetch_mul_row` into `src/mul_8x8.s` (its natural home
  as the REU row-fetch helper for the multiply primitive), refreshed
  `src/exports.inc` to reflect the new home, and cleared the
  pre-existing ca65-migration TODO note on this routine. Zero
  algorithm change; PRG size unchanged at 24322 bytes. Covered by the
  existing P-384 point-ops suite (`test_points384.py`), which drives
  `ec_point_double_384 → fp_mod_sqr_384 → fp_sqr_384` and is the
  canonical gate for this issue.

### Added

- Variable-base scalar multiplication: `ec_scalar_mul_var` (P-256),
  `ec_scalar_mul_var_384` (P-384). Left-to-right binary double-and-add
  over 256 / 384 bits. Non-constant-time (public inputs only). Unlocks
  ECDSA verify's `u2 * Q` limb.
- Packaged ECDSA verify with big-endian ABI: `ecdsa_verify_256`
  (160-byte input struct), `ecdsa_verify_384` (240-byte input struct).
  Input pointer in A/X, return via carry flag (`C=0` valid, `C=1`
  invalid). Non-constant-time (TLS verifier context); a constant-time
  variant is NOT provided because it is unnecessary for verify.
- Byte-reversal helpers: `fp_reverse32`, `fp_reverse48`. Exported for
  callers who want to drive the library's native little-endian
  primitives from big-endian wire-format inputs directly.
- Mod-order multiplication primitives: `fp_mod_mul_n`, `fp_mod_mul_n_384`.
  Needed because `fp_mod_mul` hardcodes Solinas mod-p reduction; the
  group-order mod-n reduction uses bit-serial top-down division.
- U64E ECDSA bench tool (`tools/bench_ecdsa_u64.py`) with optional
  DebugCapture integration via the U64E cycle-accurate debug bus-stream
  (UDP :11002). Four bench trampolines added in `src/main.s` emitting
  `$80`..`$87` markers at `$BFFF`.
- Diagnostic reproducer `tools/diag_verify384_turbo.py` for the
  Task #12 `ecdsa_verify_384` turbo timeout investigation.
- Diagnostic reproducers used during the c64-test-harness issue #88
  investigation (flaky `read_bytes` from the binary-monitor protocol;
  fixed upstream by `c64-test-harness` PR #89):
  `tools/diag_fp_mod_add.py`, `tools/diag_fp_mod_add_after_mul.py`,
  `tools/diag_fp_mul.py`, `tools/diag_read_consistency.py`. Each is a
  standalone, single-purpose reproducer that JSRs one library entry
  point with fixed or randomized inputs and compares against the
  Python oracle. Retained as upstream-regression sentinels.
- **Reproducible release tarball builder** (`tools/build_release.sh`,
  invoked via `make dist VERSION=v0.2.0`). Codifies the canonical
  v0.2.0+ vendoring file list and produces a byte-deterministic
  source tarball from a named git tag. SHA256 is printed and must
  match the value recorded in `docs/RELEASE_NOTES_<tag>.md`. Mirrors
  the c64-x25519 sibling's `tools/build_release.sh` recipe (commit
  `535ea7a`).
- NIST CAVP SigVer KAT bundles for P-256 and P-384 (15 vectors each,
  `tools/vectors/nist_p256_sigver.rsp` + `nist_p384_sigver.rsp`)
  consumed by the new `tools/test_ecdsa_verify.py`. Tests run RFC 6979
  A.2.5 / A.3.1 positive vectors, 8 negatives per curve, and a
  configurable slice of the CAVP vectors; all oracle-gated via the
  `cryptography` Python package.

### Fixed

- **LDA-clobbers-Z bug pattern in 144-byte Jacobian copy loops**
  (`ec_scalar_mul_var_384`, issue #17 Task #4). Extension of the
  `LDY #143 / BPL` infinity-fill bug family already documented in
  CLAUDE.md. The variant was a counter/Y-indexing mismatch where
  `LDA abs,y` clobbered the Z flag that a subsequent `BNE` was trying
  to test against a separate counter. Fixed via the X-counter
  countdown pattern `ldx #144 / ... / iny / dex / bne @l`.
- **CPX-clobbers-C bug in `fp_mod_mul_n`** (draft revision, caught
  pre-landing during Task #10). The bit-serial top-down reduction's
  ROL loop used `CPX #0` as the counter test, which clobbered C
  between the `ROL acc` and the conditional subtract. Fixed by
  switching to `DEC` / `DEX` counters, which preserve C and mirror
  the style already used in `fp_mod_mul_n_384`.

Closes #17.

### Added (earlier in [Unreleased], pre-Task #9)

- **`tools/ct_mul_brute_check.py`** — brute-force correctness check for
  the constant-time `mul_8x8`. Exercises all 65 536 `(a, b)` pairs in
  `[0, 255]²` against Python `a * b` and asserts byte equality of the
  16-bit product. Used as the primary validation for the issue #14
  remediation (see below). Uses the canonical `$02A7` init sentinel
  pattern + a 256-byte inner-loop shim at `$C000` for batched reads,
  so the 65 536-pair sweep completes in ~2.5 s of warp-mode runtime
  after the one-time init.

### Fixed

- **Issue #14 (constant-time bug in `mul_8x8`)** — the quarter-square
  8×8→16 multiply primitive at `src/mul_8x8.s` had two secret-dependent
  branches (`bcs :+` at the |a−b| sign test, `beq @s0` at the sum-page
  dispatch) that would leak the high bit of `a−b` and the carry of
  `a+b` via branch-timing on any caller passing secret operands. Both
  branches removed via a branchless port of `ct_mul_8x8` from
  `c64-ChaCha20-Poly1305` v0.3.0 (`src/lib/poly1305_lib.s`, design memo
  `docs/design/ct_mul_8x8.md`). The new implementation uses a sign-mask
  trick for `|a−b|` (`lda #0 / sbc #0` produces `$00` / `$FF` then
  `eor` + `sec / sbc`) and SMC-patches the high byte of two `lda abs,x`
  loads for the sum-page dispatch. All table loads use page-aligned
  bases (`sqtab_lo` at `$7800`, `sqtab_hi` at `$7a00`) so `abs,x` and
  `abs,y` are always 4-cy with no page-cross penalty. Body is
  straight-line with no conditional branches.

  In this project `mul_8x8` has exactly one caller — `reu_mul_init` at
  boot, which walks `(a, b) ∈ [0, 255]²` once to build the REU DMA
  multiply-table cache — so no runtime field or point op is affected.
  All `fp_*` / `ec_*` cycle counts are flat within measurement noise.
  Boot-time impact: +2.8 M cy (≈ +2.8 s on a real C64, lost in the
  ~120 s warp-mode init noise under VICE).

  Per-call cost: 86 cy body + 6 cy caller-side `jsr` = 92 cy at the
  call site (up from ~46–50 cy for the old branchy body). The
  adaptation from the reference's SMC-baked entry to this project's
  register calling convention keeps `a` live in Y across the sum
  block, so the diff block recovers it with a 2-cy `tya` instead of
  a 3-cy `lda mul_a` round-trip — saving 2 cy versus a naive port.
  Validated by a new brute-force test tool
  (`tools/ct_mul_brute_check.py`) that exercises all 65 536 `(a, b)`
  pairs and asserts byte equality against Python `a * b`. All
  existing tests (fp256, fp384, points256 --full, points384 --full,
  ct_mul_brute_check, test_inv_fast) pass.

- **`tools/test_inv_fast.py`** was failing on both baseline and
  post-fix because it used the stale `wait_for_text("READY.")`
  boot-wait pattern; `src/main.s`'s `start:` ends in an infinite
  `jmp main_loop`, so BASIC never regains control and the `READY.`
  prompt never appears. Ported to the canonical `$02A7` init sentinel
  pattern (per CLAUDE.md "Init sentinel pattern" section, same shape
  as `test_fp384.py` / `test_points384.py`). 10/10 `fp_mod_inv_fast`
  tests now pass.

- **`tools/bench_p256.py`** had the same stale
  `wait_for_text("READY.")` pattern. It was working by luck on
  short-init runs but became unreliable once the issue #14 boot-cost
  increase pushed total init past the 180 s text-wait budget. Ported
  to the sentinel pattern to match `bench_p384.py`. Also dropped the
  post-wait `sqtab_init` / `reu_mul_init` re-invocation — the sentinel
  is written after every table build, so the re-init was both
  redundant and would have doubled boot cost under the slower
  ct_mul_8x8.

## [0.1.0] — 2026-04-13

First audited, tagged release. Establishes a consumable library state for
downstream projects (planned: c64-https, c64-wireguard once migrated to ca65).

### Added

- NIST P-256 and P-384 field arithmetic (add, sub, mul, sqr, mod variants, inv)
- Jacobian point double and mixed Jacobian+affine point addition
- Fixed-base scalar multiplication `k * G` via an h=8 Lim-Lee comb over a
  256-entry REU-resident precompute table (Wave 7a)
- Jacobian-to-affine conversion for result export
- REU DMA multiply-table caching with persistent descriptor state (Wave 7b)
- Dedicated squaring with deferred doubling of cross terms (Wave 4e)
- Carry-propagation INC fusion in fp_mul / fp_sqr accumulator spill (Wave 4b)
- Solinas fast reduction with self-modifying dispatch
- Binary GCD inversion with unrolled shift loops
- VIC-II blanking for +20–25% CPU headroom during compute-bound operations
- Ultimate 64 Elite turbo-mode benchmarking via DMA trampoline at 16 / 48 MHz
- Oracle-driven test suite: NIST CAVP KAS-ECC-CDH anchors, `cryptography`
  Python library oracle, unseeded CSPRNG random inputs, correctness-gated
  benchmarks; 1074 total vectors across test_fp256, test_points256 --full,
  test_fp384, test_points384 --full
- Consumer integration reference in API.md §8 (ca65/ld65 target)
- Library version constants exported from src/lib_version.s

### Build and toolchain

- ca65 / ld65 (cc65 toolchain) on 6502; see README.md "Build" section for
  the one-line `make clean && make` invocation
- Multi-object build: 15 modules compiled individually per `src/c64.cfg`

### Notes on scope

- Fixed-base scalar multiplication only. Variable-base `k * P` is not yet
  implemented, which blocks ECDH and ECDSA-verify. Planned for a future
  MINOR bump.
- Not re-entrant. Library calls must be serialized; see API.md §4 for the
  calling contract.
- Consumer programs must accommodate the library's fixed C64 data addresses,
  ZP slots, and REU bank assignments — see API.md §8.3 for the memory map.

### Wave history preceding v0.1.0

- **Wave 4** (landed): width-5 signed wNAF, carry-prop INC fusion (4b),
  deferred-doubling fp_sqr (4e)
- **Wave 4c** (reverted): subtractive Karatsuba at N=32 — see CLAUDE.md
  "Negative findings"
- **Wave 4d** (reverted): CMO98 relative Jacobian doubling for P-256 — see
  CLAUDE.md
- **Wave 5a / 5b** (landed): Lim-Lee h=4 fixed-base comb for P-256 / P-384
- **Wave 5c** (reverted): Meloni / Fay analysis for P-384 — see CLAUDE.md
- **Wave 7a** (landed): Lim-Lee h=8 upgrade (256-entry REU-resident table),
  −48% P-256 / −50% P-384 on scalar_mul vs wNAF-5 baseline
- **Wave 7b** (landed and documented): persistent REU DMA descriptor state,
  <1% per-row DMA overhead inside fp_mul
- **Wave 8a** (reverted): mixed-add audit (moot — already landed),
  fp_add/sub unroll, `beq mul_src2_buf=0` fast-path removal. Reverted after
  A/B diagnostic showed the `beq` was load-bearing for sparse Jacobian
  intermediates. See CLAUDE.md "Negative findings" and .research/wave8a.txt.

### Cumulative scalar_mul performance vs wNAF-5 baseline

| Curve | Baseline (wNAF-5) | v0.1.0 (h=8 comb) | Speedup |
|---|---:|---:|---:|
| P-256 | ~91.9 M cycles | 46.7 M cycles | 1.97× |
| P-384 | ~270.6 M cycles | 131.4 M cycles | 2.06× |

[0.10.1]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.10.1
[0.10.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.10.0
[0.9.1]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.9.1
[0.9.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.9.0
[0.8.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.8.0
[0.7.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.7.0
[0.6.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.6.0
[0.5.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.5.0
[0.4.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.4.0
[0.3.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.3.0
[0.2.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.2.0
[0.1.0]: https://github.com/JC-000/c64-nist-curves/releases/tag/v0.1.0
