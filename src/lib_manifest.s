.setcpu "6502"

; =============================================================================
; lib_manifest.s - c64-nist-curves aggregate ABI manifest (c64-lib-contract §5)
;
; Consumer-facing assemble-time equates that summarize the library's
; resource footprint. Used to gate consumer build attempts before kicking
; off the 30-min compile + VICE test cycle.
;
;   LIB_NISTCURVES_REU_BANKS_USED   - Bitmask of REU bank indices claimed.
;   LIB_NISTCURVES_ZP_USAGE_BYTES   - Total bytes claimed in zero page
;                                     (sum of widths of every .exportzp
;                                     slot in src/zp_config.s).
;   LIB_NISTCURVES_RESIDENT_BYTES   - Approx CPU-RAM-resident footprint
;                                     (library code + rodata that must
;                                     remain in CPU RAM at runtime to
;                                     serve a verify call).
;   LIB_NISTCURVES_COLD_BYTES       - Approx code+rodata footprint that a
;                                     consumer MAY page-overlay (boot-only
;                                     init, reference-only routines, LUTs
;                                     that could be re-loaded on demand).
;
; All values are integer equates. Consumer-side assemble-time `.assert`
; checks compare them against ld65-published `__<MEMORY>_SIZE__` symbols
; (see c64-lib-contract SPEC §5 worked example).
;
; The numbers are approximate -- within ±5% per SPEC §5. Refreshed at each
; release that substantively changes one of them. Build size as of this
; equate refresh: 37683 B PRG (build/nist-curves.prg, v0.7.0 / issue #66).
; =============================================================================


; -----------------------------------------------------------------------------
; REU bank bitmask
; -----------------------------------------------------------------------------
; Derived from the SPEC §3 base-bank equates:
;
;   bank LIB_NISTCURVES_REU_BANK_MUL      = $00  -- mul cache (low half)
;   bank LIB_NISTCURVES_REU_BANK_MUL + 1  = $01  -- mul cache (high half)
;   bank LIB_NISTCURVES_REU_BANK_COMB     = $02  -- Lim-Lee comb anchors
;
; Three contiguous banks claimed at the default layout: $01 | $02 | $04 = $07.
;
; Hard-coded here rather than derived as `(1 << BANK_MUL) | (1 << (BANK_MUL+1))
; | (1 << BANK_COMB)` because ca65 cannot evaluate arithmetic expressions
; over `.import`-ed symbols at assembly time -- imports are unresolved until
; link. A consumer that overrides LIB_NISTCURVES_REU_BANK_MUL or _COMB via
; `ca65 --asm-define` MUST also override LIB_NISTCURVES_REU_BANKS_USED to
; keep the bitmask consistent. The standalone library build uses the default
; layout; the override path is exercised by consumer cfgs.
; -----------------------------------------------------------------------------
; FP_ONCHIP_MUL (issue #69 turbo profile): the field layer computes multiply
; rows on-chip via ct_mul_8x8 and never DMA-fetches from the mul-table
; banks, so only the Lim-Lee comb bank remains claimed ($04). The verify
; archives additionally exclude the comb (ECDSA_NO_COMB, issue #61), so an
; onchip verify archive issues no REU DMA at all -- consumers of those may
; override the mask to $00. (Defensive issue-#33 REU register writes remain
; in the entry points; they are writes to expansion I/O space, harmless
; without an REU, and claim no banks.)
.ifndef LIB_NISTCURVES_REU_BANKS_USED
  .ifdef FP_ONCHIP_MUL
    LIB_NISTCURVES_REU_BANKS_USED = $04
  .else
    LIB_NISTCURVES_REU_BANKS_USED = $07
  .endif
.endif


; -----------------------------------------------------------------------------
; Zero-page usage
; -----------------------------------------------------------------------------
; Sum of widths of every `.exportzp` slot in src/zp_config.s as of this
; equate refresh:
;
;   proc_port                                  1
;   zp_tmp1, zp_tmp2                           2
;   zp_ptr1, zp_ptr2          (2 B each)       4
;   fp_src1..fp_misc          (4 × 2 B ptr)    8
;   fp_carry, fp_loop, fp_mul_i, fp_mul_j      4
;   ec_scalar_ptr                              1
;   poly_i, poly_j, poly_carry, poly_tmp       4
;   sha_src, sha_len          (2 B each)       4
;   sha_w_ptr, sha_w_ptr2     (2 B each)       4
;                                            ---
;                                             31
;
; proc_port ($01) is the 6510 CPU I/O port -- hardware-fixed, but the
; library writes to it (ROM banking around REU access) and exports it,
; so it counts toward the ZP claim from the consumer's collision-check
; perspective.
; -----------------------------------------------------------------------------
.ifndef LIB_NISTCURVES_ZP_USAGE_BYTES
  LIB_NISTCURVES_ZP_USAGE_BYTES = 31
.endif


; -----------------------------------------------------------------------------
; Resident footprint (approx)
; -----------------------------------------------------------------------------
; Library code + rodata that MUST stay in CPU RAM at runtime to serve an
; `ecdsa_verify_256` / `ecdsa_verify_384` call. Summed from build/labels.txt
; address ranges (v0.7.0, 37683 B PRG):
;
;   reu_fetch_mul_row + fp256/mod256/curve256/points256_core
;     + sm256_reu_* comb runtime helpers
;     (reu_fetch_mul_row $0B0D -> ec_precompute_256 $2914)        7687
;   ec_scalar_mul comb evaluate body
;     ($2B7C -> fp_mod_inv_fast $2CC9)                             333
;   fp_reverse32 + ecdsa_verify_256 + fp384/mod384/curve384
;     /points384_core + sm384w_* helpers
;     ($2D38 -> ec_precompute_384 $4C4E)                          7958
;   ec_scalar_mul_384 evaluate + ecdsa_verify_384 +
;     ecdsa_verify_with_message_384
;     ($4ED2 -> sha384_init $541C)                                1354
;   sha384_init + sha384_update + sha384_final + sha_compress
;     + rotr/sigma/shr bodies ($541C -> title_msg $6885)          5225
;   p256 curve constants ec_p256..ec_gy256 ($68A4..$6964)          192
;   p384 curve constants ec_a384..ec_gy384 ($6AA4..$6B64)          192
;   sha384_iv + sha384_k ($6BC4..$6E84)                            704
;   sha rotr LUTs lo_2_tbl..hi_7_tbl ($6F00..$7B00)               3072
;                                                              -------
;                                                                26717
;
; Rounded to 27000 for the ±5% manifest commitment (margin ~1.1%).
; Excludes RW BSS state (fp_*, ec_*, ecdsa_*, sha_state, sha_w, ...)
; AND the runtime-GENERATED sqtab_lo/hi RAM table (1024 B at
; LIB_SHARED_SQTAB_BASE) since SPEC §5 defines RESIDENT_BYTES as
; code+rodata. (The old terminus ecdsa_verify_with_msg_384_tramp $526C
; is dead -- issue #63 moved the trampoline into the never-archived
; main.s, now at $0984.)
; -----------------------------------------------------------------------------
; FP_ONCHIP_MUL: the og_common row generator + gen_mul_row[_384] entry
; stubs (~250 B code) become verify-hot (the generator runs inside every
; fp_mul/fp_sqr) while the six REU row-fetch sites drop out -- a net
; delta inside the rounding above, so both profiles share the 27000
; figure. NOTE: the generated 1 KB sqtab RAM table is verify-hot under
; this profile (the inline quarter-square reads it per product); it is
; excluded from the equate per the generated-RW-state rule above, so
; onchip consumers must budget those 1024 B at LIB_SHARED_SQTAB_BASE
; separately.
.ifndef LIB_NISTCURVES_RESIDENT_BYTES
  LIB_NISTCURVES_RESIDENT_BYTES = 27000
.endif


; -----------------------------------------------------------------------------
; Cold (overlay-able) footprint
; -----------------------------------------------------------------------------
; Library code + rodata that a consumer MAY page-overlay (load on demand
; from REU, kernal-banked RAM, or external storage) without breaking a
; verify call (v0.7.0 labels.txt):
;
;   reu_mul_init + sqtab_init + mul_8x8 body (boot-only path)
;     ($08AE -> reu_fetch_mul_row $0B0D)                           607
;   ec_precompute_256 (boot-only; populates REU bank $02 P-256 half)
;     ($2914 -> ec_scalar_mul $2B7C)                               616
;   ec_precompute_384 (boot-only; populates REU bank $02 P-384 half)
;     ($4C4E -> ec_scalar_mul_384 $4ED2)                           644
;   fp_mod_inv_fast (Fermat addition-chain, reference only --
;     41× slower than mod256 binary GCD; not called at verify time)
;     ($2CC9 -> fp_reverse32 $2D38)                                111
;   fp_inv_exp_p2 (addition-chain step table for fp_mod_inv_fast)
;     ($6A84 -> ec_a384 $6AA4)                                      32
;                                                              -------
;                                                                 2010
;
; The sqtab_lo/hi quarter-square table (1024 B at LIB_SHARED_SQTAB_BASE)
; is deliberately NOT counted: it is runtime-GENERATED RAM state, not
; code+rodata, so it is excluded on the same basis as the RW BSS
; exclusion in RESIDENT above. (Earlier revisions counted it here -- at
; 512 B, which was also half its true size -- putting the declared 2500
; outside the ±5% band under either self-consistent accounting;
; issue #78.)
;
; Plus Lim-Lee anchor RAM (~544 B P-256 affine anchors + ~816 B P-384
; affine anchors) is reclaimable if the consumer drives only
; variable-base scalar mul. That isn't code+rodata though, so it stays
; out of this number per SPEC §5 wording.
;
; Rounded to 2000 for the ±5% manifest commitment (margin ~0.5%).
; -----------------------------------------------------------------------------
; FP_ONCHIP_MUL: the cold set is materially the same blocks -- the
; reu_mul_init path stays cold (and is unnecessary: the profile never
; reads an REU mul table), sqtab_init remains the one mandatory boot
; step, ct_mul_8x8 remains boot/diag-only (the issue #71 row generator
; inlines its own quarter-square). Both profiles share the 2000 figure.
.ifndef LIB_NISTCURVES_COLD_BYTES
  LIB_NISTCURVES_COLD_BYTES = 2000
.endif


; -----------------------------------------------------------------------------
; Shared-primitives ownership bitmask (SPEC §5 + §8.0, conditional form v0.4.0)
; -----------------------------------------------------------------------------
; The library consumes three §8 primitives:
;   - §8.1 sqtab       (bit $0001) - 8x8 quarter-square multiply table
;   - §8.2 reu_mul     (bit $0002) - 128 KB 8x8->16 REU multiplication table
;   - §8.3 ct_mul_8x8  (bit $0004) - constant-time 8x8->16 multiply body
; A consumer linking multiple sibling libs against the same PRG `.assert`s
; on the AND of every adopter's manifest equate being zero to detect
; duplicate ownership at assemble time. See SPEC §8.0 bit allocation
; table; bits are append-only and never reused (a deprecated primitive
; keeps its bit reserved so old consumer cfgs continue to parse).
;
; Per §8.0 (v0.4.0, issue #21) the mask is CONDITIONAL on each primitive's
; deferral switch: a bit is included iff this build does NOT defer that
; primitive to a canonical provider. A build with the switch defined drops
; the bit, so co-linked adopters sharing a primitive end up with disjoint
; masks and the consumer disjointness `.assert` is satisfiable.
;
;   bit    | primitive  | deferral switch
;   $0001  | sqtab      | SHARED_SQTAB_INIT   (src/mul_8x8.s)
;   $0002  | reu_mul    | SHARED_REU_MUL_INIT (src/main.s)
;   $0004  | ct_mul_8x8 | SHARED_CT_MUL_8X8   (src/mul_8x8.s)
; -----------------------------------------------------------------------------
.ifndef LIB_SHARED_PRIMITIVES_SQTAB
  LIB_SHARED_PRIMITIVES_SQTAB = $0001
.endif
.ifndef LIB_SHARED_PRIMITIVES_REU_MUL
  LIB_SHARED_PRIMITIVES_REU_MUL = $0002
.endif
.ifndef LIB_SHARED_PRIMITIVES_CT_MUL_8X8
  LIB_SHARED_PRIMITIVES_CT_MUL_8X8 = $0004
.endif

.ifdef SHARED_SQTAB_INIT
  _OWN_SQTAB      = 0
.else
  _OWN_SQTAB      = LIB_SHARED_PRIMITIVES_SQTAB
.endif
; FP_ONCHIP_MUL (issue #78): the turbo profile OMITS the §8.2 reu_mul bit
; entirely -- the profile does not CONSUME §8.2 at all (fp_mul/fp_sqr
; generate rows on-chip; no onchip archive builds or reads an REU
; multiply table), so there is no reu_mul table to own. Standalone onchip
; mask: $0005 (sqtab $0001 | ct_mul_8x8 $0004). This is deliberately NOT
; expressed via the SHARED_REU_MUL_INIT deferral switch: that switch
; means "a canonical provider elsewhere in the PRG owns the table" (the
; bit moves to another adopter); under FP_ONCHIP_MUL nobody needs to own
; it. Matches the sibling profile in c64-x25519 PR #73, and makes the
; mask consistent with LIB_NISTCURVES_REU_BANKS_USED above, which is
; already profile-aware ($04 -- mul banks dropped -- under onchip).
.ifdef FP_ONCHIP_MUL
  _OWN_REU_MUL    = 0
.else
  .ifdef SHARED_REU_MUL_INIT
    _OWN_REU_MUL    = 0
  .else
    _OWN_REU_MUL    = LIB_SHARED_PRIMITIVES_REU_MUL
  .endif
.endif
.ifdef SHARED_CT_MUL_8X8
  _OWN_CT_MUL_8X8 = 0
.else
  _OWN_CT_MUL_8X8 = LIB_SHARED_PRIMITIVES_CT_MUL_8X8
.endif

.ifndef LIB_NISTCURVES_SHARED_PRIMITIVES
  LIB_NISTCURVES_SHARED_PRIMITIVES = _OWN_SQTAB | _OWN_REU_MUL | _OWN_CT_MUL_8X8
  ; Permanent guard (issue #78, mirrors c64-x25519 PR #73): an onchip
  ; build must never claim §8.2 ownership. Fires at assemble time if a
  ; future edit re-couples _OWN_REU_MUL to the profile switch wrongly.
  .ifdef FP_ONCHIP_MUL
    .assert (LIB_NISTCURVES_SHARED_PRIMITIVES & LIB_SHARED_PRIMITIVES_REU_MUL) = 0, error, "FP_ONCHIP_MUL manifest must not claim the SPEC 8.2 reu_mul ownership bit"
  .endif
.endif


; --- Exports ---
; Force absolute address-size on the exports: the integer-equate values
; can fit in zero-page so ca65 would otherwise tag them as `zeropage` and
; ld65 would warn at every `.import ... ; lda #<sym` import site. These
; symbols are scalar parameters, not actual addresses, so absolute is
; correct. Matches the pattern in src/reu_config.s.
.export LIB_NISTCURVES_REU_BANKS_USED:abs
.export LIB_NISTCURVES_ZP_USAGE_BYTES:abs
.export LIB_NISTCURVES_RESIDENT_BYTES:abs
.export LIB_NISTCURVES_COLD_BYTES:abs
.export LIB_NISTCURVES_SHARED_PRIMITIVES:abs
