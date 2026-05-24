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

| Name | Size (B) | Region | Source file | Classification | Rationale |
|---|---:|---|---|---|---|
| `sqtab` | 1024 | RAM | `src/mul_8x8.s` | Shareable (§8.1 normative) | Two 512-byte byte tables (`sqtab_lo`, `sqtab_hi`) implementing the quarter-square identity `a*b = floor((a+b)^2/4) - floor((a-b)^2/4)`. Bit-identical to the sibling implementations in `c64-x25519`, `c64-ChaCha20-Poly1305`, and the other §8.1 adopters; canonical placement equate is `LIB_SHARED_SQTAB_BASE`. Already adopted per §8.1 (PR #50, master `0b601b9`). |
| `reu_mul` | 131072 | REU | `src/main.s` (init), `src/mul_8x8.s` (`reu_fetch_mul_row`) | Shareable (§8.2 normative) | Two contiguous REU banks (128 KB) of pre-computed `(a, b) -> a*b` rows, 256 rows × 512 bytes each. Byte-identical to `c64-x25519`'s mul table at the default `--asm-define` setting (banks `$00`/`$01`); the §8.2 promotion (this PR) lets a consumer linking both libraries supply one base bank via `LIB_SHARED_REU_MUL_BANK` and avoid a wasted 128 KB. |
| `lim_lee_comb_p256` | 16384 | REU | `src/points256_comb.s` (`ec_precompute_256`) | Curve-specific (P-256) | h=8 Lim-Lee fixed-base scalar-mul anchor table for `secp256r1` at REU bank `$02` offset `$0000`. 256 entries × 64 B (X, Y only — no Z). Specific to the P-256 generator point and curve parameters; not shareable across curves. Built once at boot; only consumed by the fixed-base scalar_mul path in `lib-p256`. Excluded from `lib-p256-verify` archive per `API.md` §8.3. |
| `lim_lee_comb_p384` | 24576 | REU | `src/points384_comb.s` (`ec_precompute_384`) | Curve-specific (P-384) | h=8 Lim-Lee fixed-base scalar-mul anchor table for `secp384r1` at REU bank `$02` offset `$4000`. 256 entries × 96 B (X, Y only — no Z). Specific to the P-384 generator point and curve parameters; not shareable across curves. Built once at boot; only consumed by the fixed-base scalar_mul path in `lib-p384`. Excluded from `lib-p384-verify` archive per `API.md` §8.3. |
| `sha384_k` | 640 | RODATA | `src/sha384.s` | Algorithm-specific (SHA-384/512) | FIPS 180-4 §4.2.3 K[80] round constants for the SHA-512 compression family (SHA-384 reuses the same K table; only the IV differs). 80 × 8 B little-endian. Could in principle be shared with a future SHA-512 sibling library, but no second adopter exists today (TLS 1.3 secp384r1 pairs with SHA-384 only). Promotion to §8.x would require a second adopter and an audit-confirmed bit-identical table; not pursued in this release. |

## Cross-reference

- `LIB_NISTCURVES_SHARED_PRIMITIVES` (`src/lib_manifest.s`) ORs in the §8.1
  + §8.2 ownership bits (`$0001 | $0002 = $0003`). Consumers cross-check
  this against sibling libraries' equivalent manifests via the §8.0
  double-ownership `.assert`.
- Tables flagged `PRECALC_SHARED_YES` here are the ones whose `LIB_PRECALC_<name>_*`
  exports cross-adopters can audit via
  `od65 --dump-exports build/lib/nistcurves.a | grep LIB_PRECALC_<name>`.
  A byte-identical match across two or more adopters is a §8.x promotion
  candidate per the SPEC §8.0 audit triggers.
