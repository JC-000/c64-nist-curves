# c64-nist-curves v0.15.0

P-256 and P-384 elliptic curve arithmetic for the Commodore 64.

**MINOR.** `LIB_NISTCURVES_ABI_VERSION` **stays 4**.

Conformant to **c64-lib-contract SPEC v1.2.2** (frozen), with the two disclosed
exceptions unchanged — see `CLAUDE.md`. One of them, §6.1 member isolation on
`mul_8x8.o`, is **closed by this release**.

---

## Why you want this release

**A consumer performing the documented boot sequence could not link beside a
sibling library that derives the same §8.1 names.** `mul_8x8.o` exported the
displaceable bare `sqtab_lo` / `sqtab_hi` alongside the §8.1 init pair, the
§8.3 provider surface and the §8.2 row fetch. `ld65` links whole members, so
`jsr sqtab_init` — mandatory for any multiply, API.md step 2 — pulled the
member and both names:

```
ld65: Error: Duplicate external identifier: 'sqtab_hi'
```

with **no consumer definition involved anywhere**. The names now live alone in
`src/sqtab_aliases.s`, the shape SPEC 1.2.2 blessed for `zp_aliases.s`.

**This is a relocation, not a removal.** Verified from the built archives: both
names are still exported by the default and onchip archives, and still absent
from app-owned where `SHARED_SQTAB_INIT` gates them out. No §6.5 event; the
window to the next MAJOR is untouched.

## If you build APP_OWNED, you owe two fewer definitions

`nistcurves-app-owned.a` no longer carries `poly_prod_lo` / `poly_prod_hi` as
unresolved externals. `fp_sqr` / `fp_sqr_384` had been borrowing the §8.3
product cells as two bytes of local diagonal scratch — write-then-read within
three instructions, never as the §8.3 product channel — and now use their own
`fp_diag_lo/_hi` and `fp384_diag_lo/_hi`. `mul_8x8_appowned.o` now has zero
exports and zero imports.

The #123 invariant is intact: the cells still travel with the
`SHARED_CT_MUL_8X8` body, because `og_common` under `FP_ONCHIP_MUL` calls the
deferred body for real and must read the provider's cells.

## §5 figures moved for six archives

`check-archives` no longer charges a worst-case 255 B of **pre-segment**
alignment into the measurand — that pad is fixed by the consumer's own
placement and ordering, so the archive cannot know it. Declared figures are
unchanged; the measured side dropped, so the six archives containing
`sha384.o` now show 255 B more headroom.

**`API.md` §6.6 changed with it, and consumers relying on it should re-read
it.** It licensed an `.assert` on "`declared ≤ budget` implies
`actual ≤ budget`", which held only while that charge existed. For those six
archives a consumer reserving one contiguous region can now pay up to 255 B
more than `RESIDENT + COLD`. Either leave ≥ 256 B of headroom, or place the
aligned segment first and assert against your own link map's extents.

## Verification

| | |
|---|---|
| oracle suites | **8/8, 1488 checks, 0 failures** — fp256 479/479, fp384 481/481, points 41/41 each, ecdsa_verify 43/43, sha384 21/21 |
| adversarial suites | 290 + 92 passed, **0 red-known rows** on either |
| hardware | U64E, **10/10 oracle gates at 16 and 48 MHz** — the lane VICE cannot test |
| §8.2 settle probe | arbiter CLEAN 0/100 at +4 cy; all stash and fetch ladders PASS |
| contract gates | `make check-archives` and `make check-docs` both exit 0 |
| PRG | `e975f8e298259803b6e0b2abe23d05ebac143957a6619bdf3da35f5108c3abe6` (37743 B) |

The hardware result is **an upper bound on one device on one day**, not
evidence the §8.2 settle is unnecessary: that device is core 1.4F, the
recorded clean control, and the hazard was observed on **1.4E**. A first-ever
64 MHz probe on a third core (1.49) also came back clean, but its ladders did
not complete and it is **not** recorded as bracketing that clock.

## Gates strengthened

Four ratchet defects were found and fixed, each driven red before being
trusted. In short: the `LIB_NO_BARE_EXPORTS` gate checked only what it
*removed*, never what it *kept*; the gated legs read only the default arm, so
11 of 12 shipped archives went unexamined; the §6.1 sqtab collision had no
standing gate at all; and the §5 measurand billed a consumer-side pad. See
`CHANGELOG.md` for the mutations and their exact failure text.

## Removed

The legacy ACME build path — fourteen `src/*.asm` files and `make build-acme`.
Never shipped in a release tarball, never in any archive, no PRG impact.
Preserved verbatim on the `archive/acme-legacy-build` branch.

---

## Integration

Unchanged from v0.14.0. `make lib-<variant>` + link; no source patching. See
`API.md` §8.2–§8.4 for the archive contract and §8.4.1 for the per-archive
figures — **several of which moved in this release**.

## Tarball

- `c64-nist-curves-v0.15.0.tar.gz` — REPLACE_TARBALL_SIZE bytes
- SHA256: `REPLACE_TARBALL_SHA`

Verify with the shipped `.sha256` sidecar: `shasum -a 256 -c`.
