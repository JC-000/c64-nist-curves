.setcpu "6502"

; =============================================================================
; zp_aliases.s - deprecated bare `zp_*` aliases of the four general-purpose
; zero-page slots, in a translation unit of their own (issue #154,
; c64-lib-contract #188, ruled at SPEC v1.2.2).
;
; WHY THIS FILE EXISTS
; --------------------
; ld65 links whole archive members. Through v0.13.0 these four aliases were
; exported from `zp_config.o`, the same member that exports sixteen
; importable slots (`fp_src1`, `fp_dst`, `ec_scalar_ptr`, `sha_src`, ...).
; A consumer that imported `fp_src1` therefore pulled the member and, with
; it, four displaceable bare names that collide with any sibling library
; exporting the same spelling -- a §6.1 member-isolation defect, in the
; library-versus-library direction.
;
; SPEC v1.2.2 ruled that §2's "dedicated src/zp_config.s" governs CLAIMED
; SLOTS, and a deprecated bare alias is not one: §2's registry requires
; every exported slot name to carry a registered prefix, which no bare
; `zp_` name does. So §2 never required the alias to live there, and it may
; be exported from a separate translation unit -- provided that TU stays
; ARCHIVED. Moving these to a never-archived TU (main.s, say) would REMOVE
; an exported name from the archives and owe a §6.5 deprecation window plus
; a gate. Moving them to another archived TU owes nothing: name, value and
; archive are all unchanged, and archive members are not consumer-named.
; This object therefore ships in every archive that ships the matching
; `zp_config*.o` -- see the twelve LIB_CORE_*_OBJS lists in the Makefile,
; and the alias-presence leg of tools/check_archives.py which link-proves
; it.
;
; VALUES ARE DERIVED, NEVER RESTATED
; ----------------------------------
; Each alias is an `.importzp` of its canonical `nistcurves_zp_*` counterpart
; re-exported under the bare spelling. The alias has no address of its own:
; ld65 resolves the export from the import, so the two spellings CANNOT
; drift, whatever `CONTRACT_ZP_DEFINES` moves the canonical slot to. That is
; what §2 wanted from a single file, obtained without one.
;
; Consequence for the build (SPEC §6.2): this TU DEFINES no slot, so
; `CONTRACT_ZP_DEFINES` must NOT reach its recipe -- a command-line `-D` of
; an imported name is `Symbol already defined`, a hard error. Only
; `zp_config.s` gets the ZP overrides; the alias follows through the link.
; The Makefile recipes below `zp_config`'s carry that asymmetry deliberately.
;
; VARIANT ARMS
; ------------
; The arms mirror `zp_config.s`'s export block exactly -- same switches, same
; order, same alias subsets -- because each archive's alias surface must
; match the slot surface of the `zp_config*.o` it ships beside:
;
;   LIB_SHA384_ONLY      no bare aliases at all (the SHA archive exports
;                        only sha_src/sha_len/sha_w_ptr/sha_w_ptr2, none of
;                        which has ever had a bare form). This object is
;                        consequently EMPTY in that arm, and is archived
;                        anyway so the object<->archive mapping stays
;                        mechanical; check_archives pins the empty set.
;   LIB_P256_VERIFY_ONLY zp_ptr2
;   LIB_P384_VERIFY_ONLY zp_ptr2   (kept a separate arm from the P-256 one
;                                   for the same reason zp_config.s does:
;                                   the two curves' need is not guaranteed
;                                   to stay identical)
;   LIB_P384_CURVE_ONLY  zp_ptr2
;   LIB_P256_COMB_ONLY   zp_ptr1, zp_ptr2
;   (default)            zp_tmp1, zp_tmp2, zp_ptr1, zp_ptr2
;
; The whole surface is suppressed by `-D LIB_NO_BARE_EXPORTS=1` (SPEC §6.5
; rename window), which also drops the imports -- an object that exports no
; alias must not carry an unresolved external for one. Removed at the next
; MAJOR, at which point this file goes with them.
;
; ZP_USAGE_BYTES IS UNAFFECTED. An alias shares its canonical slot's address
; and claims no additional byte; §5's LIB_NISTCURVES_ZP_USAGE_BYTES counts
; addresses, not names.
; =============================================================================

.ifndef LIB_NO_BARE_EXPORTS

.ifdef LIB_SHA384_ONLY
  ; no bare aliases in this arm -- deliberately empty
.elseif .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY)
  .importzp nistcurves_zp_ptr2
  zp_ptr2 = nistcurves_zp_ptr2
  .exportzp zp_ptr2
.elseif .defined(LIB_P384_CURVE_ONLY)
  .importzp nistcurves_zp_ptr2
  zp_ptr2 = nistcurves_zp_ptr2
  .exportzp zp_ptr2
.elseif .defined(LIB_P256_COMB_ONLY)
  .importzp nistcurves_zp_ptr1, nistcurves_zp_ptr2
  zp_ptr1 = nistcurves_zp_ptr1
  zp_ptr2 = nistcurves_zp_ptr2
  .exportzp zp_ptr1, zp_ptr2
.else
  .importzp nistcurves_zp_tmp1, nistcurves_zp_tmp2
  .importzp nistcurves_zp_ptr1, nistcurves_zp_ptr2
  zp_tmp1 = nistcurves_zp_tmp1
  zp_tmp2 = nistcurves_zp_tmp2
  zp_ptr1 = nistcurves_zp_ptr1
  zp_ptr2 = nistcurves_zp_ptr2
  .exportzp zp_tmp1, zp_tmp2, zp_ptr1, zp_ptr2
.endif

.endif
