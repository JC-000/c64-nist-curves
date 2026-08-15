# c64-nist-curves v0.10.0 — Namespace wave

**Released:** 2026-08-15
**Tarball:** `c64-nist-curves-v0.10.0.tar.gz` (228,188 bytes)
**SHA256:** `6cdfdbd410424ebbb0f7b147950baffd4a6fb66b538ecc1ebb8df17ea580200c`

P-256 and P-384 elliptic-curve arithmetic for the Commodore 64, with packaged
ECDSA verification and streaming SHA-384.

---

## What this release is

The release that closes the fleet's §6.5 rename window — this library was the
last adopter (c64-lib-contract #76 tracker: polyval v0.6.0, chacha v0.8.0,
x25519 v0.11.0, **nist this release**) — bundled with the full contract
catch-up from SPEC v0.8.4 through v0.9.1. Eight PRs: #99, #101, #102, #103,
#104, #105, #106, #107.

With this tag, a `-D LIB_NO_BARE_EXPORTS=1` build of every archive exports
**zero** unprefixed names, and the `c64-https` pair (this library × x25519) is
collision-free at tags for both the #82 and #83 symbol families.

## Consumer-visible changes — read these

### 1. `LIB_ABI_VERSION` bumps 1 → 2

Three exported symbols were removed **unconditionally** (#103):

```
LIB_SHARED_REU_MUL_BANK
LIB_SHARED_REU_MUL_OFFSET
LIB_SHARED_REU_MUL_BANKS_USED
```

They were the unprefixed §8.2 consumer-*input* equates; every §8.2 consumer
defines the same three, so exporting them produced
`ld65: Duplicate external identifier` in any composed link (measured against
x25519 — the pair `c64-https` ships). Nothing imported them.

What a consumer could legitimately want from them is replaced by the prefixed
*output* counterparts (#105), whose values are the values the code reads:

```asm
.import LIB_NISTCURVES_SHARED_REU_MUL_BANK      ; = the bank the DMA paths use
.import LIB_NISTCURVES_SHARED_REU_MUL_OFFSET
.import LIB_NISTCURVES_SHARED_REU_MUL_BANKS_USED
```

A consumer gating on `.assert LIB_NISTCURVES_ABI_VERSION = 1, lderror, ...`
fails loudly at link, as intended. Update the gate to `2`.

### 2. The rename window: canonical prefixed names, bare forms gated (#107)

| family | canonical | bare form |
|---|---|---|
| general ZP scratch | `nistcurves_zp_{tmp1,tmp2,ptr1,ptr2}` | same-address alias, exported by default, suppressed under `-D LIB_NO_BARE_EXPORTS=1` |
| multiply buffers | `nistcurves_mul_{dma_lo,dma_hi,cached_a,src2_buf}` | same |
| sqtab labels | names unchanged (`sqtab_lo`/`sqtab_hi` are §8.1-canonical) | bare **export** gated |

**A consumer that changes nothing links exactly as before** — the bare names
remain exported in the default build. A consumer composing this library with
siblings builds everything with `-D LIB_NO_BARE_EXPORTS=1` and uses canonical
names. Bare forms are removed at the next MAJOR.

One behavior change inside the window: a legacy override of an undocumented
bare scratch name (`-D zp_tmp1=0x40`) now **hard-errors**
(`Symbol 'zp_tmp1' is already defined`) instead of working; the canonical
spelling (`-D nistcurves_zp_tmp1=0x40`) is the migration. The documented
override knobs (`fp_*`, `ec_scalar_ptr`, `sha_*`, `LIB_SHARED_SQTAB_BASE`,
REU banks) are untouched.

### 3. New build interface (SPEC §6.2/§6.3)

```sh
make lib CONTRACT_DEFINES='-D LIB_NO_BARE_EXPORTS=1'
make lib-p256-verify CONTRACT_ZP_DEFINES='-D nistcurves_zp_ptr2=0x40'
make lib-app-owned      # §8.0 APP_OWNED shape: owns $0000, consumes $0007
```

Consumer-supplied defines now actually reach the build (previously they were
silently discarded); ZP overrides ride the scoped `CONTRACT_ZP_DEFINES`
because a globally-delivered slot override collides with every `.importzp`
site. Values must be `$`-free — use `0x` hex; the `$` forms are eaten by
make/shell, and one of them silently becomes the shell's PID.

`lib-app-owned` builds the full member set with all four §8.x deferral
switches defined, so an application can own the shared primitives without
`ar65` surgery. A new `SHARED_REU_MUL_FETCH` switch completes §8.2 deferral;
defining either §8.2 switch alone is rejected at assemble time.

### 4. PRG size: 37427 → 37480 B (#102)

`LIB_NISTCURVES_P384_BSS` was `type = bss` while every sibling was `rw`,
making the shipped image 53 bytes shorter than its address span — everything
above `$83C6` loaded 53 bytes low, benign only because the affected bytes were
zeros written before read. Fixed; the image now matches its span exactly.
Validated with the full oracle suite: **1090/1090, zero failures**, across
`test_ecdsa_verify`, `test_fp256/384`, `test_points256/384`, `test_sha384`.

### 5. Hardening and tooling shipped along the way

- The `$9C00` sqtab-window collision — which ld65 cannot see and which
  corrupted the multiply table once before — is now a **link error**
  (`__MAIN_LAST__ <= sqtab_lo`, `lderror`). Measured slack at adoption:
  409 bytes.
- `src/c64.cfg` carries SPEC §4 load-bearing attribute declarations: which
  placements the library's correctness/timing depends on, and what silently
  breaks without them (measured: a dropped `align` and a zero-filled
  `rw`→`bss` flip both link with no diagnostic).
- `make check-docs`: every consumer-facing doc snippet is extracted and
  assembled verbatim; 13 broken snippets fixed the day it landed.
- `make check-archives` grew per-archive manifest **value** pins, a cfg
  placement invariant, and a gated-surface ratchet (a
  `-D LIB_NO_BARE_EXPORTS=1` build must export zero deprecated names).
- Version-guard snippets in the docs now use `.assert`/`lderror` — the
  previously published `.if` form never assembled at all.

## Upgrading from v0.9.1

1. ABI gate: expect `LIB_NISTCURVES_ABI_VERSION = 2`.
2. If you imported `LIB_SHARED_REU_MUL_{BANK,OFFSET,BANKS_USED}` (unlikely —
   they collided in any two-library link), switch to
   `LIB_NISTCURVES_SHARED_REU_MUL_*`.
3. If you passed `-D zp_tmp1=…`-style overrides for the undocumented scratch
   quartet, use the `nistcurves_zp_*` spelling.
4. Composing with sibling libraries: build all with
   `-D LIB_NO_BARE_EXPORTS=1` and import canonical names only.
5. Otherwise no action: every entry point, calling convention and buffer
   layout is unchanged, and the default export surface is a superset of
   v0.9.1's minus only the three colliding equates in (2).

## Verification

- Full oracle suite at the #102 change: **1090/1090** (the only byte-moving
  change in the release).
- All ten `make lib-*` archives build; `make check-archives` PASS
  (closure, provider pins, manifest value pins, cfg placement, gated
  surface); `make check-docs` PASS.
- Gated build of `nistcurves.a`: **zero** bare/deprecated names.
- Tarball reproducibility: two independent `make dist` runs byte-identical.
- **Worktree-rebuild byte-identity** (fleet standard): a clean
  `git worktree` checkout of the tag rebuilds the PRG byte-identical —
  verified at `82e4e5e` (post-squash re-tag) (fresh `git worktree` at the tag: PRG `18701274…` identical, check-archives and check-docs both PASS in the worktree).

## Links

- [`CHANGELOG.md`](../CHANGELOG.md) — per-bullet log with the release banner
- [`API.md`](../API.md) §8.4 — per-archive manifest table; §8.6 — version
  gates
- c64-lib-contract [#76](https://github.com/JC-000/c64-lib-contract/issues/76)
  — the wave tracker this release closes
