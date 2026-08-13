# Precalculated tables — c64-nist-curves

This document enumerates every precalculated table shipped by
`c64-nist-curves` that meets the c64-lib-contract SPEC §8.0
("Catch loop: enumeration at adopter intake") floor:

- size ≥ 256 B, AND
- one of: REU-resident, hot-loop-read, or page-aligned.

The list below is **authoritative against the `LIB_PRECALC_TABLE` macro
invocations in `src/precalc_manifest.s`**. The two forms (this doc and
the macro invocations) MUST remain in lock-step — an asymmetry between
them blocks adopter PRs per the intake-reviewer rule in
c64-lib-contract `adopters.md` step 6. To re-audit:

```
od65 --dump-exports build/precalc_manifest.o | grep LIB_PRECALC
grep -n LIB_PRECALC_TABLE src/precalc_manifest.s
```

Both forms must enumerate the same set of `(name, size, region, shared)`
tuples. The doc captures the **rationale** field — which the macro
cannot — so a future audit run can mechanically judge whether each
classification still holds.

## Tables

| Name | Size (B) | Region | Source file | Profiles | Classification | Rationale |
|---|---:|---|---|---|---|---|
| `sqtab` | 1024 | RAM | `src/mul_8x8.s` | All **except** `LIB_SHA384_ONLY` (issue #88): the `lib-p384-sha384` archive carries no field or multiply code, so it enumerates no shared table | Shareable (§8.1 normative) | Two 512-byte byte tables (`sqtab_lo`, `sqtab_hi`) implementing the quarter-square identity `a*b = floor((a+b)^2/4) - floor((a-b)^2/4)`. Bit-identical to the sibling implementations in `c64-x25519`, `c64-ChaCha20-Poly1305`, and the other §8.1 adopters; canonical placement equate is `LIB_SHARED_SQTAB_BASE`. Already adopted per §8.1 (PR #50, master `0b601b9`). |
| `reu_mul` | 131072 | REU | `src/reu_mul_init.s` (init; moved out of the never-archived `src/main.s` by issue #81 so default-profile archives ship the §8.2 provider), `src/mul_8x8.s` (`reu_fetch_mul_row`) | **Default only** — gated out under `FP_ONCHIP_MUL` (issue #78): the onchip profile generates multiply rows on-chip, no onchip archive builds or reads this table, so the macro row is `.ifndef FP_ONCHIP_MUL`-guarded (x25519 PR #73 precedent). Also absent under `LIB_SHA384_ONLY` (issue #88) | Shareable (§8.2 normative) | Two contiguous REU banks (128 KB) of pre-computed `(a, b) -> a*b` rows, 256 rows × 512 bytes each. Byte-identical to `c64-x25519`'s mul table at the default `-D` bank setting (banks `$00`/`$01`); the §8.2 promotion (this PR) lets a consumer linking both libraries supply one base bank via `LIB_SHARED_REU_MUL_BANK` and avoid a wasted 128 KB. |
| `lim_lee_comb_p256` | 16384 | REU | `src/points256_comb.s` (`ec_precompute_256`) | Full archives only (`nistcurves.a`/`nistcurves-onchip.a`) — issue #90: none of the three minimal verify/curve variants (`LIB_P256_VERIFY_ONLY`/`LIB_P384_VERIFY_ONLY`/`LIB_P384_CURVE_ONLY`) ship `points256_comb.o`, so this row is absent from all three, not just `LIB_SHA384_ONLY`. The onchip full archive still populates/reads REU bank `$02` (only the mul banks `$00`/`$01` disappear under onchip). | Curve-specific (P-256) | h=8 Lim-Lee fixed-base scalar-mul anchor table for `secp256r1` at REU bank `$02` offset `$0000`. 256 entries × 64 B (X, Y only — no Z). Specific to the P-256 generator point and curve parameters; not shareable across curves. Built once at boot; only consumed by the fixed-base scalar_mul path in `lib-p256`. Excluded from `lib-p256-verify` archive per `API.md` §8.3. |
| `lim_lee_comb_p384` | 24576 | REU | `src/points384_comb.s` (`ec_precompute_384`) | Full archives only (`nistcurves.a`/`nistcurves-onchip.a`) — issue #90: same as `lim_lee_comb_p256` — none of the three minimal verify/curve variants ships `points384_comb.o` either, including `LIB_P384_CURVE_ONLY` (it ships SHA-384 + the packaged one-shot verify wrapper, not the comb). | Curve-specific (P-384) | h=8 Lim-Lee fixed-base scalar-mul anchor table for `secp384r1` at REU bank `$02` offset `$4000`. 256 entries × 96 B (X, Y only — no Z). Specific to the P-384 generator point and curve parameters; not shareable across curves. Built once at boot; only consumed by the fixed-base scalar_mul path in `lib-p384`. Excluded from `lib-p384-verify` archive per `API.md` §8.3. |
| `sha384_k` | 640 | RODATA | `src/sha384.s` | Full archives, `LIB_P384_CURVE_ONLY` (ships `sha384.o` + the one-shot verify wrapper), and `LIB_SHA384_ONLY` (the only row that variant emits) — issue #90: absent from `LIB_P256_VERIFY_ONLY`/`LIB_P384_VERIFY_ONLY`, neither of which ships `sha384.o` | Algorithm-specific (SHA-384/512) | FIPS 180-4 §4.2.3 K[80] round constants for the SHA-512 compression family (SHA-384 reuses the same K table; only the IV differs). 80 × 8 B little-endian. Could in principle be shared with a future SHA-512 sibling library, but no second adopter exists today (TLS 1.3 secp384r1 pairs with SHA-384 only). Promotion to §8.x would require a second adopter and an audit-confirmed bit-identical table; not pursued in this release. |

Nine build variants of this manifest ship (was three through v0.8.0), one
per archive, each enumerating exactly the tables its archives contain.
Export counts are per-object totals, and each table contributes **six**
symbols since contract v0.7.0 — the prefixed
`LIB_NISTCURVES_PRECALC_<name>_{SIZE,REGION,SHARED}` triple plus the
deprecated bare one:

| Object | Built with | Tables enumerated | Exports |
|---|---|---:|---:|
| `precalc_manifest.o` | (default) | 5 | 30 |
| `precalc_manifest_onchip.o` | `-D FP_ONCHIP_MUL` | 4 — no `reu_mul` | 24 |
| `precalc_manifest_p256verify.o` | `-D LIB_P256_VERIFY_ONLY` | 2 — sqtab, reu_mul | 12 |
| `precalc_manifest_p256verify_onchip.o` | `-D LIB_P256_VERIFY_ONLY -D FP_ONCHIP_MUL` | 1 — sqtab only | 6 |
| `precalc_manifest_p384verify.o` | `-D LIB_P384_VERIFY_ONLY` | 2 — sqtab, reu_mul | 12 |
| `precalc_manifest_p384verify_onchip.o` | `-D LIB_P384_VERIFY_ONLY -D FP_ONCHIP_MUL` | 1 — sqtab only | 6 |
| `precalc_manifest_p384curve.o` | `-D LIB_P384_CURVE_ONLY` | 3 — sqtab, reu_mul, sha384_k | 18 |
| `precalc_manifest_p384curve_onchip.o` | `-D LIB_P384_CURVE_ONLY -D FP_ONCHIP_MUL` | 2 — sqtab, sha384_k | 12 |
| `precalc_manifest_sha384.o` | `-D LIB_SHA384_ONLY` | 1 — `sha384_k` only | 6 |

The `FP_ONCHIP_MUL` profile generates multiply rows on-chip, so the
`reu_mul` table does not exist there (issue #78). The `lib-p384-sha384`
archive carries no field or multiply code at all, so `sha384_k` is the
only precalculated table it has (issue #88) — enumerating the other four
there both described tables the archive lacks and, because this
enumeration is what the §8.0 cross-adopter audit greps, made a SHA-only
link look like a duplicate `sqtab` provider to any sibling that ships a
real one.

## Cross-reference

- `LIB_NISTCURVES_SHARED_PRIMITIVES` (`src/lib_manifest.s`) ORs in the
  ownership bits of the §8 primitives the build actually consumes — the
  mask is profile-aware. Standalone default-profile builds export
  `$0007` (§8.1 sqtab `$0001` | §8.2 reu_mul `$0002` | §8.3 ct_mul_8x8
  `$0004`); `FP_ONCHIP_MUL` builds deliberately omit the §8.2 bit and
  export `$0005` — there is no reu_mul table in that profile to own
  (issue #78, x25519 PR #73 precedent). Each defined `SHARED_*` deferral
  switch additionally drops its bit per SPEC §8.0. Consumers cross-check
  this against sibling libraries' equivalent manifests via the §8.0
  double-ownership `.assert`.
- Tables flagged `PRECALC_SHARED_YES` here are the ones whose
  `*_PRECALC_<name>_*` exports cross-adopters can audit via

  ```sh
  od65 --dump-exports build/precalc_manifest.o | grep _PRECALC_<name>
  ```

  A byte-identical match across two or more adopters is a §8.x promotion
  candidate per the SPEC §8.0 audit triggers.

  Two things to note about that command:

  **Dump the `.o`, not the `.a`.** `od65` reads single ca65 object files
  only; pointed at an archive it reports `(no xo65 object file)` and exits
  `0`, so a script that greps its output silently sees zero symbols and
  concludes the table is absent. (SPEC §8.0 currently describes `od65` as
  reading `.o` and `.a` alike — reported upstream. `tools/check_archives.py`
  is unaffected: it resolves each archive to its constituent `.o` files
  from the Makefile and dumps those.)

  **Grep `_PRECALC_`, not `LIB_PRECALC_`.** Since contract v0.7.0 each
  invocation emits *two* triples — the library-prefixed
  `LIB_NISTCURVES_PRECALC_<name>_*` (canonical) and the deprecated bare
  `LIB_PRECALC_<name>_*` (suppressed by `-D LIB_NO_BARE_EXPORTS=1`,
  removed at contract v1.0). The `_PRECALC_` infix matches both forms
  regardless of which a given adopter still emits.
