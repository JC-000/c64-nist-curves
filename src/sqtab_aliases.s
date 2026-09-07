.setcpu "6502"

; =============================================================================
; sqtab_aliases.s - the two gated bare §8.1 names `sqtab_lo` / `sqtab_hi`,
;   and NOTHING else (issue #155).
;
; They used to be exported from `mul_8x8.s`, beside the §8.1 init pair, the
; §8.3 provider surface, the §8.2 row fetch and (until this issue) the §8.2
; settle routine. ld65 links whole archive members, so ANY reference into that
; member dragged these two displaceable names into the link with it -- SPEC
; 1.2.2 §6.1 member isolation, in the library-versus-library direction: a
; sibling library deriving the same two canonical names from the same
; LIB_SHARED_SQTAB_BASE collides, with no consumer definition involved
; anywhere.
;
; Chasing the individual pull paths did not work and cannot: the first attempt
; at #155 removed two of them (the settle routine, and fp_sqr's borrow of the
; §8.3 product cells) and the collision survived in every onchip archive via
; `og_common`, and in the default profile via `sqtab_init` itself -- which
; API.md step 2 makes a MANDATORY boot call, so the only consumer the fix
; covered was one that never builds the multiply table and therefore cannot
; compute a correct product. The names have to leave the member; there is no
; set of pull paths to close.
;
; This is the shape SPEC 1.2.2 blessed for `zp_aliases.s` (contract#188) and
; that `mul_aliases.s` already uses. It is a relocation, NOT a removal: the
; names keep their values, stay exported by the same archives, and continue to
; ride the §6.5 window to the next MAJOR. Moving an export between two ARCHIVED
; TUs is not a §6.5 event; moving it to a never-archived TU would be.
;
; Do not add anything to this file. Its whole purpose is that pulling it drags
; nothing else in -- and that nothing else drags IT in.
;
; VALUES ARE DERIVED, NEVER RESTATED: the base comes from the same
; `sqtab_base.inc` every other TU includes, so a consumer's
; `-D LIB_SHARED_SQTAB_BASE=0x<addr>` reaches this TU and `mul_8x8.s` alike and
; the two cannot drift. Never `.import` the base -- §8.1 forbids exporting it.
; =============================================================================

.include "sqtab_base.inc"

sqtab_lo        = LIB_SHARED_SQTAB_BASE             ; 512 B: lo bytes of floor(n^2/4)
sqtab_hi        = LIB_SHARED_SQTAB_BASE + $0200     ; 512 B: hi bytes of floor(n^2/4)

; SPEC §8.1 assemble-time guards, restated here rather than relied upon from
; mul_8x8.s: the TU that PUBLISHES the names is the one that must prove they
; are well-formed, and this TU is built into archives (app-owned) where
; mul_8x8's copy is gated out.
.assert (LIB_SHARED_SQTAB_BASE & $00ff) = 0, error, "sqtab base must be page-aligned (SPEC §8.1)"
.assert sqtab_hi = sqtab_lo + $0200,        error, "sqtab_hi must follow sqtab_lo by $0200 (SPEC §8.1)"

; Same gate as the definition site had. Suppressed by the §6.5 window switch,
; and also when §8.1 is DEFERRED to a canonical provider: the provider derives
; the same two names from the same base, so there the collision is certain
; rather than merely possible.
.if (.not .defined(LIB_NO_BARE_EXPORTS)) .and (.not .defined(SHARED_SQTAB_INIT))
.export sqtab_lo, sqtab_hi
.endif
