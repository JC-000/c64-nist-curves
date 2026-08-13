# c64-nist-curves v0.9.0 — Manifest honesty

**Released:** 2026-08-13
**Tarball:** `c64-nist-curves-v0.9.0.tar.gz` (SIZE_PLACEHOLDER bytes)
**SHA256:** `SHA256_PLACEHOLDER`

P-256 and P-384 elliptic-curve arithmetic for the Commodore 64, with packaged
ECDSA verification and streaming SHA-384.

---

## What this release is

Four issues (#86, #88, #90, #91), all about what the library **tells consumers
about itself** rather than what it computes. No cryptographic behaviour
changed — 1090/1090 oracle-gated checks pass across all six suites.

The headline: before this release, of the 45 §5 manifest values a consumer can
read across the nine archives, **only two were correct.** One
`lib_manifest.o` / `precalc_manifest.o` / `zp_config.o` described the whole
library and shipped into every archive, so eight of the nine advertised
resources they do not contain.

## Consumer-visible changes — read these

### 1. Two ABI-surface removals, one MINOR bump

17 exported symbols are gone:

| symbols | why | issue |
|---|---|---|
| `proc_port`, `fp_loop`, `poly_i`, `poly_j`, `poly_carry`, `poly_tmp` | claimed zero page the library never writes; referenced by no archived object | #90 |
| 11 `ecdsa_test_*` RFC 6979 vector symbols | a duplicate copy compiled into the binary that nothing read | #91 |

A consumer that imported any of these **from this library** rather than
defining it locally must now supply its own. For `proc_port` that is a
one-line `proc_port = $01` equate — it is the hardware-fixed 6510 I/O port,
and the library's shipped code never writes it.

> **The `LIB_ABI_VERSION` guard will NOT fire for this.** It stays `0`,
> because SPEC §1/§7 defines it as tracking `LIB_VERSION_MAJOR`, and pre-1.0
> the contract allows breaking changes on a MINOR bump. If your build relies
> on `.if LIB_ABI_VERSION <> 0 / .error` to catch export changes, that guard
> is not sufficient here — check the symbol list above.

**The RFC 6979 test vectors are retained.** #91 removed a redundant *second*
copy that was compiled into the shipped library and read by nothing. The
vectors the test suite uses live in `tools/test_ecdsa_verify.py`, transcribed
from the RFC (Appendix A.2.5 for P-256, A.3.1 for P-384), alongside the full
`tools/vectors/` NIST corpus. All eight on-chip curve constants
(`ec_a`/`b`/`gx`/`gy` × 2 curves) are untouched.

### 2. Every §5 manifest equate changed value for at least one archive

If you run assemble-time fit checks against the manifest, **re-read them** —
several were previously overstated by 1.5–3×, so a check that failed before
may now pass:

| archive | ZP | REU banks | RESIDENT | COLD | precalc rows |
|---|---:|---:|---:|---:|---:|
| `nistcurves.a` | 27 | `$07` | 27000 | 1840 | 5 |
| `nistcurves-onchip.a` | 27 | `$04` | 27000 | 1650 | 4 |
| `nistcurves-p256-verify.a` | 15 | `$03` | 8700 | 430 | 2 |
| `nistcurves-p256-verify-onchip.a` | 15 | `$00` | 8700 | 240 | 1 |
| `nistcurves-p384-verify.a` | 15 | `$03` | 8300 | 430 | 2 |
| `nistcurves-p384-verify-onchip.a` | 15 | `$00` | 8300 | 240 | 1 |
| `nistcurves-p384-curve.a` | 23 | `$03` | 17400 | 430 | 3 |
| `nistcurves-p384-curve-onchip.a` | 23 | `$00` | 17400 | 240 | 2 |
| `nistcurves-p384-sha384.a` | 8 | `$00` | 9000 | 0 | 1 |

Notable corrections:

- **`COLD_BYTES` was wrong for every archive, including the full ones** —
  1800 declared against 2219 measured, 19% low, outside SPEC §5's ±5% band.
- **`REU_BANKS_USED` was wrong for 6 of 9.** The three onchip verify/curve
  archives issue *zero* REU DMA yet claimed bank `$04`; they now correctly
  declare `$00`, matching the REU-less operation API.md §8.4.2 already
  documented.
- **Precalc rows were false in 6 of 9** — a P-256-only verify archive was
  advertising the 24 KB `lim_lee_comb_p384` table to sibling libraries'
  §8.0 disjointness audits.
- **`ZP_USAGE_BYTES` was overstated up to 2.3×**, and the default figure was
  itself wrong by one: `ec_scalar_ptr` is a 2-byte pointer, not the 1-byte
  index its comment claimed. Zero page is the scarcest resource on a 6502,
  so an over-claim can make a consumer's collision check reject an
  integration that would have fit.

### 3. Contract adoption: c64-lib-contract v0.5.0 → v0.7.1 (#86)

- **`LIB_NISTCURVES_SHARED_CONSUMES`** — the required §8.0 companion mask.
  A clear ownership bit was ambiguous between "deferring consumer, needs a
  provider in the link" and "non-consumer, needs none"; this library was the
  demonstrator upstream, since its `SHARED_REU_MUL_INIT` and `FP_ONCHIP_MUL`
  builds both export `$0005` while imposing opposite obligations.
- **Library-prefixed manifest exports** — `LIB_NISTCURVES_VERSION_*` and
  `LIB_NISTCURVES_PRECALC_<name>_*`. The unprefixed forms are identical
  across every adopter, so linking two sibling libraries and importing both
  manifests produced `ld65: Duplicate external identifier`. Bare forms are
  still emitted by default and suppressed with `-D LIB_NO_BARE_EXPORTS=1`;
  they are removed at contract v1.0.
- **`ca65 --asm-define` corrected to `-D`** in 12 consumer-facing doc sites —
  ca65 rejects the former outright.

### 4. PRG size

`build/nist-curves.prg`: **37683 → 37427 B.** #86, #88 and #90 were each
byte-identical; #91's removal of 384 B of dead rodata is what moves it. The
net drop is 256 B because two page-aligned segments reabsorb 128 B as
padding.

## Verification

Because the PRG moved, byte-identity was not available as the argument this
time and the full oracle suites were run:

| suite | result |
|---|---|
| `test_ecdsa_verify` | 43/43 — both curves, RFC 6979 + CAVP SigVer + SHA-384 wrapper |
| `test_fp256` | 471/471 |
| `test_fp384` | 473/473 |
| `test_points256` | 41/41 |
| `test_points384` | 41/41 |
| `test_sha384` | 21/21 |
| **total** | **1090/1090, 0 failed** |

All nine `make lib-*` archives build; `make check-archives` passes with pins
extended to cover all six manifest equates on all nine archives, plus
presence/absence pins for the removed symbols so dead data cannot re-enter
the consumer surface.

## Upgrading from v0.8.0

1. If you `.importzp proc_port` from this library, add
   `proc_port = $01` locally.
2. If you import `fp_loop` or any `poly_*` slot, define it yourself — the
   library never wrote them.
3. If you import any `ecdsa_test_*` symbol, take the vector from RFC 6979
   directly.
4. Re-read any §5 manifest equate you assert on; most changed.
5. Otherwise no action — every entry point, calling convention and buffer
   layout is unchanged.

## Known follow-ups

- No on-chip power-on self-test exists. If one is added it will need vectors
  resident in the binary again; they should land as an opt-in object excluded
  from the default archives rather than silently present in seven of nine,
  which was the #91 defect.
- `make clean` removes `nist-curves.prg` by name only, so stale variant PRGs
  (`-nocomb`, `-onchip`) can linger and a test pointed at one could run
  against a stale binary.

## Links

- [`CHANGELOG.md`](../CHANGELOG.md) — per-bullet log
- [`API.md`](../API.md) §8.4 — per-archive manifest table
- Issues [#86](https://github.com/JC-000/c64-nist-curves/issues/86),
  [#88](https://github.com/JC-000/c64-nist-curves/issues/88),
  [#90](https://github.com/JC-000/c64-nist-curves/issues/90),
  [#91](https://github.com/JC-000/c64-nist-curves/issues/91)
