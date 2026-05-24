.setcpu "6502"

; =============================================================================
; precalc_manifest.s - c64-nist-curves precalc-table enumeration
;                      (c64-lib-contract SPEC §8.0 catch-loop)
;
; SPEC §8.0 step-6 requires every adopter to enumerate its precalculated
; tables (size >= 256 B AND one of: REU-resident / hot-loop-read /
; page-aligned) in two forms:
;
;   1. Doc-level in `docs/precalc-tables.md` -- name, size, region,
;      source file, classification, rationale. The rationale field is
;      load-bearing for the cross-adopter audit.
;   2. Assembler-level via the `LIB_PRECALC_TABLE` ca65 macro, which
;      emits three exported equates per invocation
;      (`LIB_PRECALC_<name>_{SIZE,REGION,SHARED}`). Build-time discovery
;      via `od65 --dump-exports build/precalc_manifest.o | grep LIB_PRECALC`.
;
; Both forms are required; asymmetry between them blocks adopter PRs per
; the intake-reviewer-MUST rule in c64-lib-contract `adopters.md` step 6.
;
; Canonical-name discipline: the `name` argument is preserved verbatim by
; the macro (ca65 has no built-in toupper), and the §8.x sub-clauses make
; certain names normative -- "sqtab" (§8.1) and "reu_mul" (§8.2) MUST
; appear unprefixed so the cross-adopter audit `grep LIB_PRECALC_sqtab_SIZE`
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

LIB_PRECALC_TABLE "sqtab",             1024,   PRECALC_REGION_RAM,    PRECALC_SHARED_YES
LIB_PRECALC_TABLE "reu_mul",           131072, PRECALC_REGION_REU,    PRECALC_SHARED_YES
LIB_PRECALC_TABLE "lim_lee_comb_p256", 16384,  PRECALC_REGION_REU,    PRECALC_SHARED_NO
LIB_PRECALC_TABLE "lim_lee_comb_p384", 24576,  PRECALC_REGION_REU,    PRECALC_SHARED_NO
LIB_PRECALC_TABLE "sha384_k",          640,    PRECALC_REGION_RODATA, PRECALC_SHARED_NO
