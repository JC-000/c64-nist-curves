; =============================================================================
; sqtab_base.inc — the SPEC §8.1 sqtab placement default, single shared include
;
; SPEC v0.10.2's §6.7 single-shared-include rule: every TU that needs
; LIB_SHARED_SQTAB_BASE obtains it from THIS file, so there is exactly one
; default in the tree. Two copies of the default can silently disagree,
; leaving the §6.7 window guard checking a different window than the table
; occupies — with no diagnostic, since both TUs would assemble happily.
;
; Consumer override: `ca65 -D LIB_SHARED_SQTAB_BASE=0x8800` (any page-aligned
; address; $9c00 is the default). Because both the placing TU (mul_8x8.s) and
; the guard TU (main.s) include this file and CONTRACT_DEFINES reaches every
; recipe, one -D relocates table and guard together.
;
; Included, not imported: §8.1 (v0.9.1) forbids exporting this equate — every
; adopter derives the same name, so an export is a #82-class collision.
;
; Also SHIPPED: `make lib` copies this file to build/lib/sqtab_base.inc (from
; v0.16.0), because sqtab_lo / sqtab_hi are no longer exported and a consumer
; must derive them from this base in its own TU (see src/nistcurves.inc).
; Keep it self-contained — no other .include, nothing but the guarded default
; — or the shipped copy stops assembling from build/lib alone
; (check-archives' packaging leg assembles it with -I build/lib only).
; =============================================================================
.ifndef LIB_SHARED_SQTAB_BASE
        LIB_SHARED_SQTAB_BASE = $9c00
.endif
