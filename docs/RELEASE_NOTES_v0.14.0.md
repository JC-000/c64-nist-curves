# c64-nist-curves v0.14.0 — the settling release against frozen SPEC v1.2.2

**Released:** 2026-09-06
**Tarball:** `c64-nist-curves-v0.14.0.tar.gz`
**Checksum:** published as the `.sha256` release asset and in the GitHub Release
body — deliberately not repeated here, since these notes ship *inside* the
tarball and any hash they claimed would be computed over a document that does
not yet contain it (issue #147).

MINOR. **`LIB_NISTCURVES_ABI_VERSION` 3 → 4** — consumers with an ABI gate must
update it. This closes the last two contract obligations (#153, #154) against
c64-lib-contract **SPEC v1.2.2**, which is frozen.

---

## 1. What a consumer must do

- **Update `.assert LIB_NISTCURVES_ABI_VERSION = 3` to `= 4`.**
- **If you call `reu_fetch_mul_row` directly, pass the row index in `A`.** If
  you relied on presetting `nistcurves_mul_cached_a` and calling with `A`
  undefined, that no longer works — `A` is now authoritative and is stored into
  that byte.
- Nothing else. No symbol was removed or renamed, no value moved, and the
  packaged verifiers are unchanged in behaviour.

## 2. `reu_fetch_mul_row` implements its documented entry convention (#153)

§8.2 has said `A = a` since the clause existed. The body ignored `A` and read a
library-private byte, so a consumer following the contract got whatever row was
last cached, for any value of `A`, silently.

The fleet consequence was worse than the local one. c64-x25519 — the other §8.2
provider — diverged the same way and reads a byte with a **different name**, so
§8.2 fetch deferral could not work between the two adopters at all: both symbols
resolved, the link was clean, and the fetch returned the provider's last-cached
row. Raised as contract#182 rather than patched one-sidedly, which would have
moved which side was wrong instead of fixing the pairing. Upstream ruled both
providers implement `A`, with no ordering between them.

**Why the ABI counter moves but this is not MAJOR.** §7's "changed calling
conventions" bullet governs the *documented* convention, which §8.2 states
identically before and after — what changed is our conformance to it. Its
operative word is *breaking*, and no consumer conforming to the documented
contract can be broken here: one passing `A` is broken today and this fixes
them. The counter still moves because a consumer who reverse-engineered the
cached-byte behaviour **does** break, and the counter is the gate that tells
them to look. Ruled upstream rather than self-ruled.

## 3. §6.1 member isolation (#154, and one found in review)

`zp_config.o` exported the four displaceable bare `zp_*` names beside sixteen
importable `fp_*` / `ec_*` / `sha_*` slots. ld65 links whole members, so a
consumer importing `fp_src1` pulled the member and collided with any sibling
exporting the same four. `src/zp_aliases.s` now carries them alone, across all
six variant arms; no name, value or archive changes, so no §6.5 window is owed.

Adversarial review then found the **same defect in a file created earlier the
same day**: `data_mul_stage.s` held the bare `mul_dma_*` aliases beside
`LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO`/`_HI`, which are §8.2 output equates a
consumer is *told* to import and are not prefixed counterparts of anything
displaceable. Importing one pulled the member and its bare names, and against
c64-x25519 ld65 refused the link. That file had itself been created to fix an
earlier review finding — by *moving* equates rather than splitting them.
**Splitting is the fix; moving is not.** `src/mul_aliases.s` now holds the pair
alone.

Also: three onchip archives exported the canonical `reu_fetch_mul_row` while
publishing `SHARED_PRIMITIVES = $0005` with no reu_mul bit. §8.0 says exporting
a canonical body counts as consuming it, so the mask disclaimed a primitive the
archive advertised — and a composed link failed on a duplicate external *while
§8.0's own disjointness assert passed first*. The export is now gated out under
`FP_ONCHIP_MUL`.

## 4. A hardware instrument that would have lied

**#153 silently broke the §8.2 settle probe**, and it is worth stating because
of the direction it failed in. The device trampoline reached the fetch with
`A = 2`, while the host still selected rows through the byte #153 overwrites.
Every fetch would have returned row 2, and since each is compared against the
expected row, **every settle length would report ~100% corruption** — an
instrument with no discrimination, failing in the direction that looks like a
finding rather than like a fault.

It is the only instrument for the 64 MHz floor this library still calls
unbracketed, and none of its three offline modes can see the fault, because none
runs 6502 code. `tools/bench_reu_mult.py` had the same miss.

The cause was an incomplete caller audit: it covered `src/*.s`, found no callers,
and stopped — never reaching the Python-driven device trampolines, which are
callers in every sense that matters.

## 5. Constant-time invariants that nothing was guaranteeing

Twelve `lderror` asserts now pin the page alignment of the SHA-384 rotate LUTs.
Only the first was aligned by anything that *said so*; the other eleven were
aligned **by derivation** — each table exactly 256 bytes and contiguous — while
the block's own comment asserted the property for all twelve.

A sibling library measured a real constant-time regression from exactly this
shape: a data-TU split moved the block preceding an aligned table, a
secret-indexed read began crossing pages, cycle spread went 0 → 83,342, and
**every functional test stayed green**, because a page-cross changes timing and
not results. All twelve of ours are still aligned; what was missing was any
reason they would stay that way.

## 6. Verification, and which of it is independent

Worth stating explicitly rather than leaving to be inferred: **most of this
library's gates are comparison-shaped, and two comparison-shaped checks are not
independent evidence if they share an extractor.**

- *Comparison-shaped:* `check-archives` (a ratchet by construction), the
  per-variant inventory ratcheted against API.md §8.4.1, and `make dist`
  reproducibility.
- *Not comparison-shaped, and what the picture actually rests on:* the oracle
  suites — known-answer, testing behaviour against NIST CAVP vectors and the
  external `cryptography` package rather than against another run of themselves
  — and PRG byte-identity, which hashes whole files and parses nothing.

Eight check legs were added or repaired, each negative-tested at introduction
with the observed output recorded in-file. Several already existed and could not
fail:

- the §6.2 override leg proved **2 of 12** recipes while claiming to prove the
  wiring, and two real mis-wirings stayed green — one of them §6.2's named
  silent runtime corruption;
- `GATE_TUS` was a hand-maintained roster and had **already gone stale in this
  release**: deriving it from source immediately found `mul_aliases`, added
  hours earlier, which the gated-surface leg had never examined while printing
  a clean "0 bare names";
- `od65` drops symbols of length exactly 24 from whitespace-splitting
  extractors, and the names it drops here are precisely the class a
  "0 bare names" gate counts;
- the §5 footprint basis is now measured against a real link map rather than
  argued, after a sibling library found the same basis under-reporting by up to
  295 bytes.

## 7. Known and disclosed

- **§8.1 says `sqtab_lo`/`sqtab_hi` MUST NOT be exported; the default archive
  still exports them.** Gated under `LIB_NO_BARE_EXPORTS`, additionally
  suppressed in the `SHARED_SQTAB_INIT` deferral arm, and with no in-tree
  importer left — but a §6.5 deprecation window is a schedule, not conformance.
  They go at the next MAJOR.
- **`mul_8x8.o` is not §6.1-conformant, and it is a hard link failure with no
  consumer-side remedy** (issue #155, HIGH). It exports the §8.1 pair, the §8.2
  fetch and the six §8.3 names from one translation unit, dropped by three
  *different* switches — so a consumer owning any one of the three while
  deferring another collides. Measured on the shipped default archive, no
  rebuild and no defines:

      ld65: Error: Duplicate external identifier: 'smc_diff_a_imm'

  `sqtab_init` is exported by only this object, so importing it necessarily
  pulls the member, which arrives defining the whole §8.3 surface. **This was
  filed LOW on the grounds that `LIB_NO_BARE_EXPORTS` repairs it; that is
  wrong** — the define suppresses the bare aliases, not the §8.x canonical
  names, and the collision is unchanged with it set. The only define that helps
  is `-D SHARED_CT_MUL_8X8`, which is a rebuild of the library, and §6.1 bans
  member surgery, so a consumer taking the archive as shipped has no way out.

  c64-x25519 measured the identical shape and spent a tag on it. Not fixed here
  because adding a third TU split on a different axis after adversarial review
  had completed would put unreviewed work into a settling tag; it earns its
  own. **If you own any §8.x primitive and defer another, do not take this
  release** — v0.13.0 and earlier have the same defect.
- **The `check-archives` per-leg audit is incomplete** (issue #142, deliberately
  left open). Every leg added since this work began carries a negative test;
  the legs that predate it do not all have one, and claiming otherwise would be
  the same error the issue is about.
