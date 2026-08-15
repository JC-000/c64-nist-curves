.setcpu "6502"

; =============================================================================
; precalc_manifest.s - c64-nist-curves precalc-table enumeration
;                      (c64-lib-contract SPEC §8.4 catch-loop)
;
; SPEC §8.4 step-6 requires every adopter to enumerate its precalculated
; tables (size >= 256 B AND one of: REU-resident / hot-loop-read /
; page-aligned) in two forms:
;
;   1. Doc-level in `docs/precalc-tables.md` -- name, size, region,
;      source file, classification, rationale. The rationale field is
;      load-bearing for the cross-adopter audit.
;   2. Assembler-level via the `LIB_PRECALC_TABLE` ca65 macro, which
;      emits per invocation the library-prefixed
;      `LIB_NISTCURVES_PRECALC_<name>_{SIZE,REGION,SHARED}` triple plus
;      -- unless `LIB_NO_BARE_EXPORTS` is defined -- the deprecated bare
;      `LIB_PRECALC_<name>_{SIZE,REGION,SHARED}` triple. Build-time
;      discovery via
;      `od65 --dump-exports build/precalc_manifest.o | grep _PRECALC_`
;      (grep on `_PRECALC_`, not `LIB_PRECALC_`, so both forms match).
;
; Library prefix (SPEC v0.7.0, lib-contract #43): the fifth macro
; argument "NISTCURVES" is the §1/§5 `<X>` for this library and is what
; makes the emitted equates collision-free. The bare forms are identical
; across every adopter, so a consumer linking two libraries and importing
; both manifests hits `ld65: Duplicate external identifier` -- measured
; upstream between c64-x25519 v0.8.0 and c64-ChaCha20-Poly1305 v0.6.0 on
; `LIB_PRECALC_sqtab_*`. The bare triple stays emitted by default so
; existing single-library consumers are unaffected; it is deprecated and
; removed at contract v1.0. A composing consumer suppresses it build-wide
; with `ca65 -D LIB_NO_BARE_EXPORTS=1` and imports the prefixed forms.
;
; Note the table NAME stays unprefixed and normative -- the prefix
; distinguishes the declaring library, never the table -- so the
; cross-adopter audit still resolves one symbol family per §8.x
; primitive.
;
; Both forms are required; asymmetry between them blocks adopter PRs per
; the intake-reviewer-MUST rule in c64-lib-contract `adopters.md` step 6.
;
; Canonical-name discipline: the `name` argument is preserved verbatim by
; the macro (ca65 has no built-in toupper), and the §8.x sub-clauses make
; certain names normative -- "sqtab" (§8.1) and "reu_mul" (§8.2) MUST
; appear unprefixed so the cross-adopter audit `grep _PRECALC_sqtab_SIZE`
; resolves the same symbol family across every adopter's archives.
;
; The library-private tables (`lim_lee_comb_p256`, `lim_lee_comb_p384`,
; `sha384_k`) are not §8.x-normative; their names follow lower_snake_case
; for grep-consistency with the normative entries but are otherwise local
; to this library.
;
; Split rationale (lim_lee_comb_{p256,p384}): the SPEC §8.0 illustrative
; example uses a single `"lim_lee_comb"` entry. We split per-curve because
; (a) the two tables have different sizes (16 KB vs 24 KB) and live at
; different REU offsets per `src/reu_config.s`, (b) the consumer archive
; targets are per-curve (`lib-p256-verify` and `lib-p384-verify` link
; only one comb body), and (c) the per-curve split makes the
; classification rationale in `docs/precalc-tables.md` directly tied
; to the per-curve build target. If a future audit promotes the comb to
; a shared primitive, the names will fold back to a single normative
; canonical form at that point.
; =============================================================================

.include "precalc_table.inc"

; --- Row-presence flags per build configuration (issue #90) -----------------
; Each table's presence depends on the variant switch (if any) AND, for
; reu_mul, the profile switch -- not on LIB_SHA384_ONLY alone as it did
; through v0.8.0. Computed once here, then used to gate each
; LIB_PRECALC_TABLE invocation below, mirroring the _OWN_* / _USE_* flag
; pattern in lib_manifest.s.
;
; Two rows were wrong before this gate existed, in the same shape issue
; #88 fixed for the SHA archive: `lim_lee_comb_p256` / `_p384` were gated
; only on LIB_SHA384_ONLY, and `sha384_k` was emitted unconditionally.
; Correct while `default` and `default+onchip` were the only non-SHA
; archives; false once minimal variants exist that ship neither the comb
; objects nor sha384.o. Since the enumeration is exactly what the SPEC
; §8.0 cross-adopter audit greps, an over-enumerated archive advertises
; itself as a provider of tables it does not carry.

; sqtab: every build that has field arithmetic at all -- i.e. everything
; except LIB_SHA384_ONLY.
.ifdef LIB_SHA384_ONLY
  _HAS_SQTAB = 0
.else
  _HAS_SQTAB = 1
.endif

; reu_mul: field-arithmetic builds that DMA-fetch multiply rows from the
; REU. Not LIB_SHA384_ONLY (no field layer) and not FP_ONCHIP_MUL (rows
; generated on-chip; no onchip archive builds or reads the table, issue
; #78) -- the one row whose presence depends on the profile axis.
.ifdef LIB_SHA384_ONLY
  _HAS_REU_MUL = 0
.elseif .defined(FP_ONCHIP_MUL)
  _HAS_REU_MUL = 0
.else
  _HAS_REU_MUL = 1
.endif

; lim_lee_comb_{p256,p384}: the full archives ship both comb objects;
; the LIB_P256_COMB_ONLY archives (issue #117) ship points256_comb.o
; only, so the two rows gate separately -- one combined flag would have
; the P-256 comb archive advertising the 24 KB P-384 table it does not
; carry, the exact issue #90 bug class the flags exist to prevent.
; LIB_SHA384_ONLY and the three minimal verify/curve variants take the
; ECDSA_NO_COMB verifiers, which route u1*G through the variable-base
; ladder, and never link either comb object (issue #90). Both row sets
; are variant-only: the onchip full/comb archives still populate and
; read REU bank $02.
.if .defined(LIB_SHA384_ONLY) .or .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY) .or .defined(LIB_P384_CURVE_ONLY)
  _HAS_LIMLEE_P256 = 0
  _HAS_LIMLEE_P384 = 0
.elseif .defined(LIB_P256_COMB_ONLY)
  _HAS_LIMLEE_P256 = 1
  _HAS_LIMLEE_P384 = 0
.else
  _HAS_LIMLEE_P256 = 1
  _HAS_LIMLEE_P384 = 1
.endif

; sha384_k: builds that ship sha384.o -- the two full archives,
; LIB_SHA384_ONLY itself, and LIB_P384_CURVE_ONLY (which bundles SHA-384
; plus the packaged ecdsa_verify_with_message_384 wrapper). The two
; *_VERIFY_ONLY variants and the P-256 comb variant (issue #117) do not.
.if .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY) .or .defined(LIB_P256_COMB_ONLY)
  _HAS_SHA384_K = 0
.else
  _HAS_SHA384_K = 1
.endif

.if _HAS_SQTAB
LIB_PRECALC_TABLE "sqtab",             1024,   PRECALC_REGION_RAM,    PRECALC_SHARED_YES, "NISTCURVES"
.endif
.if _HAS_REU_MUL
LIB_PRECALC_TABLE "reu_mul",           131072, PRECALC_REGION_REU,    PRECALC_SHARED_YES, "NISTCURVES"
.endif
.if _HAS_LIMLEE_P256
LIB_PRECALC_TABLE "lim_lee_comb_p256", 16384,  PRECALC_REGION_REU,    PRECALC_SHARED_NO,  "NISTCURVES"
.endif
.if _HAS_LIMLEE_P384
LIB_PRECALC_TABLE "lim_lee_comb_p384", 24576,  PRECALC_REGION_REU,    PRECALC_SHARED_NO,  "NISTCURVES"
.endif
.if _HAS_SHA384_K
LIB_PRECALC_TABLE "sha384_k",          640,    PRECALC_REGION_RODATA, PRECALC_SHARED_NO,  "NISTCURVES"
.endif
