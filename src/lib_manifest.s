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
; equate refresh: 37302 B PRG (build/nist-curves.prg).
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
.ifndef LIB_NISTCURVES_REU_BANKS_USED
  LIB_NISTCURVES_REU_BANKS_USED = $07
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
; address ranges (this release):
;
;   reu_fetch_mul_row + fp256/mod256/curve256/points256/ecdsa256
;     (reu_fetch_mul_row $0AFB -> ec_precompute_256 $277B)        7296
;   ec_scalar_mul + ec_scalar_mul_var + ec_jacobian_to_affine
;     ($29E3 -> fp_mod_inv_fast $2CB9)                             726
;   fp_reverse32 + ecdsa_verify_256 + fp384/mod384/curve384
;     /points384/ecdsa384 ($2D28 -> ec_precompute_384 $49CC)      7332
;   ec_scalar_mul_384 + ec_jacobian_to_affine_384 +
;     ecdsa_verify_384 + ecdsa_verify_with_message_384
;     ($4C50 -> ecdsa_verify_with_msg_384_tramp $526C)            1564
;   sha384_init + sha384_update + sha384_final + sha_compress
;     + rotr/sigma/shr bodies ($527A -> title_msg $66E3)          5225
;   p256 curve constants ec_p256..ec_gy256 ($6702..$67C2)          192
;   p384 curve constants ec_a384..ec_gy384 ($6902..$69C2)          192
;   sha384_iv + sha384_k ($6A22..$6D00)                            734
;   sha rotr LUTs lo_2_tbl..hi_7_tbl ($6D00..$7900)               3072
;                                                              -------
;                                                                26333
;
; Rounded to 27000 for the ±5% manifest commitment. Excludes RW BSS
; state (fp_*, ec_*, ecdsa_*, sha_state, sha_w, ...) since SPEC §5
; defines RESIDENT_BYTES as code+rodata.
; -----------------------------------------------------------------------------
.ifndef LIB_NISTCURVES_RESIDENT_BYTES
  LIB_NISTCURVES_RESIDENT_BYTES = 27000
.endif


; -----------------------------------------------------------------------------
; Cold (overlay-able) footprint
; -----------------------------------------------------------------------------
; Library code + rodata that a consumer MAY page-overlay (load on demand
; from REU, kernal-banked RAM, or external storage) without breaking a
; verify call:
;
;   reu_mul_init + sqtab_init + mul_8x8 body (boot-only path)
;     ($08AE -> reu_fetch_mul_row $0AFB)                           589
;   ec_precompute_256 (boot-only; populates REU bank $02 P-256 half)
;     ($277B -> ec_scalar_mul $29E3)                               616
;   ec_precompute_384 (boot-only; populates REU bank $02 P-384 half)
;     ($49CC -> ec_scalar_mul_384 $4C50)                           644
;   fp_mod_inv_fast (Fermat addition-chain, reference only --
;     41× slower than mod256 binary GCD; not called at verify time)
;     ($2CB9 -> fp_reverse32 $2D28)                                111
;   fp_inv_exp_p2 (addition-chain step table for fp_mod_inv_fast)
;     ($68E2 -> ec_a384 $6902)                                      32
;   sqtab_lo + sqtab_hi (quarter-square tables; only read by
;     mul_8x8, which only runs at boot)                            512
;                                                              -------
;                                                                 2504
;
; Plus Lim-Lee anchor RAM (~544 B P-256 affine anchors + ~816 B P-384
; affine anchors) is reclaimable if the consumer drives only
; variable-base scalar mul. That isn't code+rodata though, so it stays
; out of this number per SPEC §5 wording.
;
; Rounded to 2500 for the ±5% manifest commitment.
; -----------------------------------------------------------------------------
.ifndef LIB_NISTCURVES_COLD_BYTES
  LIB_NISTCURVES_COLD_BYTES = 2500
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
