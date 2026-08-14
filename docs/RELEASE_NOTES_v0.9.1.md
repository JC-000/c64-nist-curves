# c64-nist-curves v0.9.1 — precalc macro address-size fix

**Released:** 2026-08-14
**Tarball:** `c64-nist-curves-v0.9.1.tar.gz` (200,324 bytes)
**SHA256:** `62ac39fbdd790182265783c5babdc6d69f5bc506004196ea6e469d8fd6c3b388`

PATCH release. Doc/macro only — **no symbol, value, or semantic change**, and
`build/nist-curves.prg` is byte-identical to v0.9.0 (`78b395b8…`, 37427 B).

---

## What changed

`src/precalc_table.inc` re-copied verbatim from c64-lib-contract **v0.7.4**
(upstream `9da3aca`), which pins the `LIB_PRECALC_TABLE` macro's `_REGION` and
`_SHARED` exports `: abs`.

Both are byte-valued by construction (`$01`–`$03` and `$00`/`$01`), so ca65
inferred **zeropage** for them while a consumer's `.import` defaults to
absolute. A consumer following SPEC §8.4's own published cross-check snippet
therefore got, on every composed build:

```
ld65: Warning: Address size mismatch for 'LIB_NISTCURVES_PRECALC_sqtab_SHARED':
      Exported ... as 'zeropage', import ... as 'absolute'
```

Reproduced against the pre-copy tree and confirmed clean afterwards.

This was **diagnostic noise, not breakage** — the link succeeded and both
asserts evaluated correctly. It is worth a release because the natural consumer
reaction is to silence it with `.import ... : zeropage`, which pins a manifest
constant to an address size that is an artifact of its current value rather
than a property of the symbol.

### `_SIZE` is deliberately still unhinted

Not an oversight in the upstream fix, and load-bearing for this library:
`_SIZE`'s address size is value-dependent by design, which is what lets the
131072-byte `reu_mul` table export as `far` without the "far but exported
absolute" warning fixed in contract v0.4.1. Verified both ways after the copy:

| export | value | address size |
|---|---:|---|
| `LIB_NISTCURVES_PRECALC_sqtab_REGION` | 1 | absolute |
| `LIB_NISTCURVES_PRECALC_sqtab_SHARED` | 1 | absolute |
| `LIB_NISTCURVES_PRECALC_sqtab_SIZE` | 1024 | absolute |
| `LIB_NISTCURVES_PRECALC_reu_mul_SIZE` | 131072 | **far** |

## Upgrading from v0.9.0

No action required. Every `.import` resolves to the same value; only the
declared address size of `_REGION` / `_SHARED` differs. If you previously added
`: zeropage` to an `.import` of either to silence the warning, remove it — the
plain form is now correct.

## Contract currency

Two further SPEC revisions landed since v0.9.0's adoption baseline. **This
library needs no action for either**, confirmed rather than assumed:

- **v0.7.3** — §8.x per-primitive bit constants MUST NOT be `.export`ed. The
  upstream changelog names `c64-nist-curves` as already conformant; verified,
  we never exported them.
- **v0.7.5** — `LIB_<X>_ABI_VERSION` redefined as an independent generation
  counter starting at `1`, explicitly *not* derived from MAJOR, resolving the
  §1/§7 contradiction reported as
  [lib-contract #66](https://github.com/JC-000/c64-lib-contract/issues/66).
  v0.9.0 already ships `ABI_VERSION = 1`; the SPEC moved to match.

`ABI_VERSION` remains **1** — a PATCH by definition makes no ABI-surface
change.

## Verification

- `build/nist-curves.prg` byte-identical to v0.9.0: `78b395b8…`, 37427 B
- All nine `make lib-*` archives build; `make check-archives` PASS
- Before/after link reproduction of the warning documented above

The VICE oracle suites were not re-run: the PRG is byte-identical to v0.9.0,
which passed 1090/1090, so there is no behaviour to revalidate. Only the
declared address size of two exported manifest equates changed.

## Links

- [`CHANGELOG.md`](../CHANGELOG.md) — per-bullet log
- [`docs/RELEASE_NOTES_v0.9.0.md`](RELEASE_NOTES_v0.9.0.md) — the substantive
  manifest-honesty release this patches
- [PR #96](https://github.com/JC-000/c64-nist-curves/pull/96)
