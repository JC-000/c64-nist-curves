# c64-nist-curves v0.16.0

P-256 and P-384 elliptic curve arithmetic for the Commodore 64.

**MINOR.** `LIB_NISTCURVES_ABI_VERSION` **4 → 5**.

Conformant through **c64-lib-contract SPEC v1.3.0** with **no disclosed
exceptions remaining**. The last one, §8.1's ban on exporting `sqtab_lo` /
`sqtab_hi`, is closed by this release. SPEC v1.3.0 §7 makes this ABI-moving
removal on a pre-1.0 MINOR explicitly conformant, and nothing else in 1.3.0 is
owed by this library.

---

## If you gate on the ABI counter, update it to 5

The bare `sqtab_lo` / `sqtab_hi` exports are gone, from every archive and every
build configuration, and `src/sqtab_aliases.s` is deleted. A consumer that
conformed to the previously documented contract could import them, so this is
a §1/§7 ABI-counter event: **`LIB_NISTCURVES_ABI_VERSION` is now 5.**

A consumer asserting the old value, such as

```
.assert LIB_NISTCURVES_ABI_VERSION = 4, lderror, "..."
```

fails at link against this release and must be updated to `5` when it bumps.
c64-https's `lib_contract_asserts.s` carries exactly that assert.

No in-fleet consumer imports the bare names: c64-https defines its own
`sqtab_lo` / `sqtab_hi` and builds with `SHARED_SQTAB_INIT` +
`LIB_NO_BARE_EXPORTS`, and c64-wireguard does not link this library. So
nothing else needs migrating. If you did import either name, `CHANGELOG.md`
gives the three-line derivation SPEC §8.1 prescribes.

**This is a change of plan.** v0.10.0 through v0.15.0 said the pair would go
"at the next MAJOR". It goes on a MINOR instead, under the semver reading this
library has documented since v0.9.0: while MAJOR is 0, the MINOR position is
the breaking position. SPEC v1.3.0 §7 makes MINOR the breaking position while
MAJOR is 0; nothing is renamed, so §6.5's window does not apply, and §8.1
requires the removal. The export has been gated under `LIB_NO_BARE_EXPORTS`
since v0.10.0. `CHANGELOG.md` sets out the full reasoning.

## Added

- **`LIB_NISTCURVES_SHARED_SQTAB_BASE`**, a prefixed §8.1 output: the base
  the archive's code actually reads the quarter-square table from. It is
  exported in every arm that reads the table. `src/nistcurves.inc` pins a
  consumer's `LIB_SHARED_SQTAB_BASE` against it with `lderror`. The pin is
  narrow: it compares two assemble-time constants and never sees where your
  `sqtab_lo` really is. API.md §8.1 documents the consumer-side
  `.assert sqtab_lo = LIB_NISTCURVES_SHARED_SQTAB_BASE, lderror` that does.
  Additive, so the ABI counter does not move again for it.
- **`make lib*` ships `build/lib/nistcurves_sqtab_base.inc`**, the library's
  single `.ifndef`-guarded default for `LIB_SHARED_SQTAB_BASE`. Now that the
  exports are gone, deriving the names is the only way to get them, and before
  this the include the header recommended existed only in `src/`.

## Example linker config

`cfg/nistcurves-example.cfg`'s SQTAB memory area no longer sets
`define = yes`. Both the area and the segment published `__SQTAB_SIZE__`, so a
consumer placing its table in the segment got `Duplicate external identifier:
'__SQTAB_SIZE__'`. **If you referenced `__SQTAB_START__` or `__SQTAB_LAST__`
from this cfg, they are no longer defined.** The segment's `__SQTAB_LOAD__`,
`__SQTAB_RUN__` and `__SQTAB_SIZE__` remain.

## Header fixes (issue #170)

`nistcurves.inc` declared names some archives do not provide, or declared
them with the wrong address size:

- `reu_fetch_mul_row` is no longer declared under `FP_ONCHIP_MUL`.
- `FP256_SIZE` / `FP384_SIZE` are now `.importzp`. A consumer TU that also
  writes its own `.import FP256_SIZE` now gets `Address size mismatch`;
  delete that line.
- `LIB_NISTCURVES_PRECALC_reu_mul_SIZE` is imported `far`.

## Gates strengthened

New `make check-archives` legs:

- `forbidden_export_check` sweeps every built archive member for names the
  contract forbids in every configuration.
- `forbidden_export_source_scan` reads every source and its transitive
  `.include` closure, so a switch combination the built sweep never samples
  cannot hide an export.
- `sqtab_pin_deferral_check` keeps the export gate and the header's import
  gate in agreement across the deferral × onchip arms.
- The ABI-surface leg requires an ABI bump whenever a name leaves the
  surface recorded for the previous release.

Each was driven red before being trusted. `CHANGELOG.md` has the mutations
and their exact failure text. `make check-release-state` is now tag-aware, so
its baseline leg passes at a tagged commit.

## Build tooling

- **Header edits now rebuild** (issue #178), and changed `CONTRACT_DEFINES`
  no longer destroy or corrupt `build/` under `make -n` / `-q` / `-t`
  (issue #180, which had shipped a 0-byte `nistcurves.a`).
- **`make check-inc-deps` is portable across GNU Make 3.81 and 4.x**
  (PR #184), **contributed by windstalker-arch, with thanks.** On 4.x the
  guard had been both inert and falsely green: 3.81's flag spellings are
  refused or ignored there, and the touch/dry routes never checked an exit
  status. The tool now asks `make --version` which spellings to probe, and
  every route asserts its exit status.
- `tools/test_reu_mul_u64.py` records firmware, device and clock as measured
  from the device in hand, and has a documented exit-status contract
  (issues #172, #173).

## Verification

| | |
|---|---|
| PRG | `e975f8e298259803b6e0b2abe23d05ebac143957a6619bdf3da35f5108c3abe6` (37743 B), **byte-identical to v0.15.0** |
| nocomb / onchip PRGs | `9cd7f7e4…f4fbc2` / `285e161c…30f933`, both 37743 B, unchanged by the version bump |
| contract gates | `make check-archives`, `make check-docs`, `make check-inc-deps` (GNU Make 3.81 and 4.x), `make check-harness-routing`, `make check-release-state`, `make check-release-notes` all exit 0 |

No library code byte moved, so v0.15.0's oracle, adversarial and hardware
results describe these exact PRG bytes. **None of them were re-run for this
cut**, and no device was contacted. What changed is the archive surface:
the `sqtab_aliases.o` member is gone from the ten archives that shipped it,
and `lib_version.o` carries the new version and ABI values. The gates above
check that surface from the built archives.

---

## Integration

Unchanged from v0.15.0 apart from the ABI value: `make lib-<variant>` + link,
no source patching. See `API.md` §8.1 for the sqtab derivation and pin, and
§8.2–§8.4 for the archive contract.

## Tarball

**Tarball:** `c64-nist-curves-v0.16.0.tar.gz`
**Checksum:** published as the `.sha256` release asset and in the GitHub Release
body — deliberately **not** quoted here. These notes ship *inside* that
tarball, so any hash they claimed about it would be computed over a document
that does not yet contain the claim, and would be wrong the moment it was
written (issue #147). Verify a download with the sidecar:
`shasum -a 256 -c c64-nist-curves-v0.16.0.tar.gz.sha256`.
