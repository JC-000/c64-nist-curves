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
;   LIB_NISTCURVES_SHARED_PRIMITIVES- §8 primitives OWNED by this build.
;   LIB_NISTCURVES_SHARED_CONSUMES  - §8 primitives CONSUMED by this build
;                                     (v0.5.0 companion mask; see the
;                                     three-state discussion below).
;
; All values are integer equates. Consumer-side assemble-time `.assert`
; checks compare them against ld65-published `__<MEMORY>_SIZE__` symbols
; (see c64-lib-contract SPEC §5 worked example).
;
; The numbers are approximate -- within ±5% per SPEC §5. Refreshed at each
; release that substantively changes one of them. Build size as of this
; equate refresh: 37683 B PRG (build/nist-curves.prg, v0.7.0 / issue #66;
; unchanged by the issue #81 reu_mul_init move -- code reordered, no net
; growth).
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
; `ca65 -D` MUST also override LIB_NISTCURVES_REU_BANKS_USED to keep the
; bitmask consistent. The standalone library build uses the default layout;
; the override path is exercised by consumer cfgs.
; -----------------------------------------------------------------------------
; FP_ONCHIP_MUL (issue #69 turbo profile): the field layer computes multiply
; rows on-chip via ct_mul_8x8 and never DMA-fetches from the mul-table
; banks, so only the Lim-Lee comb bank remains claimed ($04). The verify
; archives additionally exclude the comb (ECDSA_NO_COMB, issue #61), so an
; onchip verify archive issues no REU DMA at all -- consumers of those may
; override the mask to $00. (Defensive issue-#33 REU register writes remain
; in the entry points; they are writes to expansion I/O space, harmless
; without an REU, and claim no banks.)
; LIB_SHA384_ONLY (issue #88): SHA-384 issues no REU DMA whatsoever, so
; the `lib-p384-sha384` archive claims no banks. Before this gate that
; archive shipped the default-profile manifest and advertised $07 --
; three banks it never touches.
; LIB_P256_VERIFY_ONLY / LIB_P384_VERIFY_ONLY / LIB_P384_CURVE_ONLY
; (issue #90): the same over-claim, one step less extreme -- those three
; archives advertised $07 while never touching bank $02. Unlike the two
; gates above, REU truth here depends on BOTH axes (variant AND profile),
; so the new arm carries an inner FP_ONCHIP_MUL check rather than sitting
; flat alongside the profile arm; see the nested form below.
.ifndef LIB_NISTCURVES_REU_BANKS_USED
  .ifdef LIB_SHA384_ONLY
    LIB_NISTCURVES_REU_BANKS_USED = $00
  .elseif .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY) .or .defined(LIB_P384_CURVE_ONLY)
    ; None of the three minimal variants ship points256_comb.o /
    ; points384_comb.o (issue #90) -- they take the ECDSA_NO_COMB
    ; verifiers, which route u1*G through the variable-base ladder -- so
    ; REU bank $02 (LIB_NISTCURVES_REU_BANK_COMB) is never referenced by
    ; any of them. Only the mul-table banks $00/$01 remain, and only in
    ; the DMA profile: all three share this logic, hence one combined arm
    ; rather than three near-duplicates.
    .if .defined(FP_ONCHIP_MUL)
      LIB_NISTCURVES_REU_BANKS_USED = $00
    .else
      LIB_NISTCURVES_REU_BANKS_USED = $03
    .endif
  .elseif .defined(LIB_P256_COMB_ONLY)
    ; Issue #117: the P-256 comb archives ship points256_comb.o, so bank
    ; $02 (LIB_NISTCURVES_REU_BANK_COMB) is claimed in BOTH profiles --
    ; the onchip profile drops only the mul-table banks $00/$01 (its
    ; fp_mul/fp_sqr generate rows on-chip) while ec_precompute_256 /
    ; ec_scalar_mul still populate and DMA-fetch the anchor table. Same
    ; values as the default arm below, stated explicitly so the variant's
    ; REU truth is pinned by check-archives rather than inherited by
    ; fall-through.
    .if .defined(FP_ONCHIP_MUL)
      LIB_NISTCURVES_REU_BANKS_USED = $04
    .else
      LIB_NISTCURVES_REU_BANKS_USED = $07
    .endif
  .elseif .defined(FP_ONCHIP_MUL)
    LIB_NISTCURVES_REU_BANKS_USED = $04
  .else
    LIB_NISTCURVES_REU_BANKS_USED = $07
  .endif
.endif


; -----------------------------------------------------------------------------
; Zero-page usage
; -----------------------------------------------------------------------------
; Sum of widths of every `.exportzp` slot in src/zp_config.s the ACTIVE
; variant exports (issue #90: this used to be one whole-library figure
; that every archive inherited; it is now per-variant). Full-library
; (default-profile) itemization:
;
;   zp_tmp1, zp_tmp2                           2
;   zp_ptr1, zp_ptr2          (2 B each)       4
;   fp_src1..fp_misc          (4 × 2 B ptr)    8
;   fp_carry, fp_mul_i, fp_mul_j               3
;   ec_scalar_ptr             (2 B pointer)    2
;   sha_src, sha_len          (2 B each)       4
;   sha_w_ptr, sha_w_ptr2     (2 B each)       4
;                                            ---
;                                             27
;
; Was declared 31 until issue #88, then 32 through v0.8.0, and both were
; wrong (issue #90). Two independent errors partly cancelled into a
; plausible-looking number: three slot groups were counted despite being
; referenced by NO object in any of the nine shipping archives --
; proc_port (1 B, used only by the never-archived main.s test driver and
; now equated locally there), fp_loop (1 B), and
; poly_i/poly_j/poly_carry/poly_tmp (4 B, leftovers from the pre-§8.3
; mul_8x8 body replaced under issue #14; the current canonical
; ct_mul_8x8 keeps its scratch in plain RAM cells, not ZP) -- while
; ec_scalar_ptr was simultaneously undercounted as 1 byte when it is a
; 2-byte pointer (`sta ec_scalar_ptr+1` in ecdsa256.s/ecdsa384.s, `lda
; (ec_scalar_ptr),y` in all four points*.s files; no call site treats it
; as a 1-byte index). Net: 32 - 6 + 1 = 27, confirmed by summing
; od65 --dump-imports across every object in the default archive.
;
; The under-count half was the dangerous one: a consumer sizing its own
; allocation against a too-small figure can place a variable in a byte
; the library never admitted to owning and have it silently clobbered
; mid-operation. Over-claiming ZP wastes a scarce resource;
; under-claiming corrupts. Both are fixed here.
; -----------------------------------------------------------------------------
; LIB_SHA384_ONLY (issue #88): 8, not 27. The `lib-p384-sha384` archive
; carries no field, point, or multiply code; `sha384.o` `.importzp`s
; exactly four slots and no object in that archive references any other:
;
;   sha_src, sha_len          (2 B each)       4
;   sha_w_ptr, sha_w_ptr2     (2 B each)       4
;                                            ---
;                                              8
;
; src/zp_config.s narrows its `.exportzp` surface to match under the
; same switch, so the equate and the archive's actual export set agree
; and SPEC §5's "sum of all .exportzp slots" definition is satisfied
; literally rather than approximated.
;
; Claiming the full 27 here would not have been a harmless over-estimate.
; Zero page is the scarcest resource on a 6502 -- on a C64 with BASIC and
; KERNAL live the genuinely free bytes number in the low tens -- so
; over-claiming 19 of them can push a consumer's collision check into
; rejecting an integration that would have fit. Fail-closed, exactly
; like the RESIDENT_BYTES overstatement tracked in issue #90.
; -----------------------------------------------------------------------------
; The other three variant gates (issue #90) narrow the same way, each to
; the slot set its archive's objects actually `.importzp`:
;
;   LIB_SHA384_ONLY        ->  8  (sha_src, sha_len, sha_w_ptr, sha_w_ptr2)
;   LIB_P256_VERIFY_ONLY   -> 15  (fp_src1/2/dst/misc, fp_carry, fp_mul_i,
;                                  fp_mul_j, ec_scalar_ptr, zp_ptr2)
;   LIB_P384_VERIFY_ONLY   -> 15  (the same 9 slots -- neither verify
;                                  archive ships the Lim-Lee comb, the
;                                  only user of zp_tmp1/zp_tmp2/zp_ptr1,
;                                  nor sha384.o)
;   LIB_P384_CURVE_ONLY    -> 23  (those 9 + the four sha_* pointers --
;                                  this variant bundles sha384.o and the
;                                  ecdsa_verify_with_message_384 wrapper)
;   (default, either profile) -> 27  (all 16 slots itemized above)
;
; ZP truth does NOT depend on FP_ONCHIP_MUL: measured across all four
; default/onchip archive pairs, each pair has a byte-identical ZP import
; set (the profile changes which REU registers the field layer touches,
; not which ZP scratch it uses). Hence one zp_config object per variant,
; shared by both of that variant's archives, where lib_manifest and
; precalc_manifest need one per variant AND profile.
; -----------------------------------------------------------------------------
.ifndef LIB_NISTCURVES_ZP_USAGE_BYTES
  .ifdef LIB_SHA384_ONLY
    LIB_NISTCURVES_ZP_USAGE_BYTES = 8
  .elseif .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY)
    LIB_NISTCURVES_ZP_USAGE_BYTES = 15
  .elseif .defined(LIB_P384_CURVE_ONLY)
    LIB_NISTCURVES_ZP_USAGE_BYTES = 23
  .elseif .defined(LIB_P256_COMB_ONLY)
    ; Issue #117: the verify set's 9 slots (15 B) plus nistcurves_zp_ptr1
    ; (2 B, the ec_precompute_256 anchor-copy pointer) = 10 slots, 17 B.
    ; zp_tmp1/zp_tmp2 stay out: their only archived user is the P-384
    ; comb's sm384w_calc_reu_offset. Measured by od65 --dump-imports
    ; union over the archive's members; profile-independent like every
    ; other variant.
    LIB_NISTCURVES_ZP_USAGE_BYTES = 17
  .else
    LIB_NISTCURVES_ZP_USAGE_BYTES = 27
  .endif
.endif


; -----------------------------------------------------------------------------
; Resident footprint (approx)
; -----------------------------------------------------------------------------
; Library code + rodata that MUST stay in CPU RAM at runtime to serve an
; `ecdsa_verify_256` / `ecdsa_verify_384` call. Summed from build/labels.txt
; address ranges (v0.7.0, 37683 B PRG):
;
;   reu_fetch_mul_row ($0A53 -> reu_mul_init $0A67; the boot-only
;     reu_mul_init body sits between it and fp256 since issue #81)    20
;     [issue #90 reclassified these 20 B as COLD -- no ca65 source
;      `jsr`s reu_fetch_mul_row -- so they now appear in the COLD
;      derivation instead. Left listed here because the sum below and
;      its 27000 rounding are unaffected at this magnitude.]
;   fp256/mod256/curve256/points256_core
;     + sm256_reu_* comb runtime helpers
;     (fp_copy $0B21 -> ec_precompute_256 $2914)                    7667
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
; -----------------------------------------------------------------------------
; LIB_SHA384_ONLY (issue #88): the `lib-p384-sha384` archive contains only
; sha384.o + data_sha.o + zp_config.o + the three manifest objects, so its
; resident set is the SHA segments alone. Measured by linking a consumer
; that imports sha384_init/update/final against the archive and reading
; the ld65 map:
;
;   LIB_NISTCURVES_SHA384_CODE     $1469    5225
;   LIB_NISTCURVES_SHA384_RODATA   $02C0     704   (sha384_iv + sha384_k)
;   LIB_NISTCURVES_SHA384_TABLES   $0C00    3072   (rotr LUTs, page-aligned)
;                                          ------
;                                            9001
;
; Declared as 9000 (margin 0.01%). LIB_NISTCURVES_SHA384_BSS ($0411 =
; 1041 B of sha_state / sha_w / sha_block_buf / digest) is RW state and
; excluded per SPEC §5, same basis as the main derivation above.
;
; Before this gate the archive inherited the whole-library 27000 -- a 3x
; overstatement, and one that fails CLOSED: a consumer running the §5 fit
; check would be told the archive needs 27 KB resident and refuse to
; build against a region that comfortably fits the real 9 KB.
; -----------------------------------------------------------------------------
; LIB_P256_VERIFY_ONLY / LIB_P384_VERIFY_ONLY / LIB_P384_CURVE_ONLY
; (issue #90): the same inherited overstatement, 1.5x-3.3x for these
; three. Each figure is the sum of the segments the archive's objects
; actually contribute, measured by od65 segment sums cross-validated
; against real `ld65 -m` links of a consumer against the built archive:
;
;   LIB_P256_VERIFY_ONLY  ->  8700  (fp256/mod256/curve256/points256_core
;                                    + ecdsa256_nocomb + mul_8x8; no comb,
;                                    no P-384, no SHA, no inv256)
;   LIB_P384_VERIFY_ONLY  ->  8300  (the P-384 mirror of the above)
;   LIB_P384_CURVE_ONLY   -> 17400  (P-384 verify + sha384.o's ~9 KB of
;                                    code/rodata/rotr LUTs + ecdsa384_msg)
;
; Keyed on variant ALONE, like ZP_USAGE_BYTES and unlike REU_BANKS_USED /
; COLD_BYTES: the four default/onchip archive pairs measure within
; 83-103 B (0.3-1.3%) of each other -- the onchip row generator replaces
; the six REU row-fetch sites at near-parity -- which is inside SPEC §5's
; ±5% band, so each variant shares one figure across both profiles.
; -----------------------------------------------------------------------------
.ifndef LIB_NISTCURVES_RESIDENT_BYTES
  .ifdef LIB_SHA384_ONLY
    ; §6.6 (SPEC v0.10.0): MUST be >= the measured sum. 9000 was < the
    ; measured 9001 -- a round-to-tens artifact erring in the unsafe
    ; direction by one byte. Now the next 256-byte boundary above measured
    ; (the §6.6 fleet convention), +2.4%, inside §5's ±5%.
    LIB_NISTCURVES_RESIDENT_BYTES = 9216
  .elseif .defined(LIB_P256_VERIFY_ONLY)
    LIB_NISTCURVES_RESIDENT_BYTES = 8700
  .elseif .defined(LIB_P384_VERIFY_ONLY)
    LIB_NISTCURVES_RESIDENT_BYTES = 8300
  .elseif .defined(LIB_P384_CURVE_ONLY)
    LIB_NISTCURVES_RESIDENT_BYTES = 17400
  .elseif .defined(LIB_P256_COMB_ONLY)
    ; Issue #117: od65 segment sums (code+rodata) over the archive
    ; members, minus the cold blocks itemized in the COLD arm below:
    ;
    ;   DMA arm    10036 total - 1045 cold = 8991 resident
    ;   onchip arm  9953 total -  859 cold = 9094 resident
    ;
    ; The 103 B profile delta (1.1%) is inside SPEC §5's ±5% band, so
    ; the variant shares one figure across both profiles like every
    ; other variant. §6.6: next 256-byte boundary above the larger
    ; measurement (9094) = 9216, margin +1.3% onchip / +2.5% DMA.
    ; Issue #130 (SPEC v0.13.0 §8.2 completion confirm): +24 B fp256
    ; (inline confirms) + 39 B nistcurves_reu_dma_wait (resident, both
    ; profiles) + 6 B points256_comb -> 9060 DMA / 9163 onchip resident;
    ; 9216 still covers both (+0.6% onchip). Pinned by check-archives.
    LIB_NISTCURVES_RESIDENT_BYTES = 9216
  .else
    LIB_NISTCURVES_RESIDENT_BYTES = 27000
  .endif
.endif


; -----------------------------------------------------------------------------
; Cold (overlay-able) footprint
; -----------------------------------------------------------------------------
; Library code + rodata that a consumer MAY page-overlay (load on demand
; from REU, kernal-banked RAM, or external storage) without breaking a
; verify call (v0.7.0 labels.txt):
;
;   sqtab_init + mul_8x8 body (boot-only path)
;     ($0974 -> reu_fetch_mul_row $0A53)                           223
;   reu_mul_init (src/reu_mul_init.s since issue #81; boot-only
;     §8.2 provider) ($0A67 -> fp_copy $0B21)                      186
;   ec_precompute_256 (boot-only; populates REU bank $02 P-256 half)
;     ($2914 -> ec_scalar_mul $2B7C)                               616
;   ec_precompute_384 (boot-only; populates REU bank $02 P-384 half)
;     ($4C4E -> ec_scalar_mul_384 $4ED2)                           644
;   fp_mod_inv_fast (Fermat addition-chain, reference only --
;     41× slower than mod256 binary GCD; not called at verify time)
;     ($2CC9 -> fp_reverse32 $2D38)                                111
;   fp_inv_exp_p2 (addition-chain step table for fp_mod_inv_fast)
;     ($6A84 -> ec_a384 $6AA4)                                      32
;   reu_fetch_mul_row (issue #90: reclassified from RESIDENT above --
;     no ca65 source `jsr`s it; fp_mul/fp_sqr inline their own three
;     register writes, so nothing on the verify path calls it)
;     ($0A53 -> reu_mul_init $0A67)                                  20
;                                                              -------
;                                                                 1832
;
; Was declared 1800 through v0.8.0, from the 1812 the first six blocks
; sum to. Through issue #90 this block also carried a seventh entry --
; 384 B of RFC 6979 self-test vectors in curve256.s (288) / curve384.s
; (96) -- which pushed the honest total to 2216 and made the declared
; 1800 19% low, outside SPEC §5's ±5% band. Issue #91 deleted those
; vectors outright (nothing referenced them: zero importers across every
; built object, and the test suites take their vectors from the oracle
; and tools/vectors/, never from on-chip constants), so the seventh
; entry is gone and the total returns to the first six blocks plus
; reu_fetch_mul_row's 20.
;
; The re-measurement (od65 segment sums cross-validated against
; `ld65 -m` links, which is why it lands 3 B off this labels.txt address
; sweep) gives 1835; declared 1840 below, margin ~0.3%.
;
; (The pre-#81 derivation's first block, "$08AE -> reu_fetch_mul_row
; $0B0D = 607", was an address-range sweep that silently included the
; ~198 B of main.s test trampolines then sitting between reu_mul_init
; and sqtab_init -- never-archived driver code, not library cold code.
; The #81 layout moves the trampolines out of the swept window, so the
; total drops 2010 -> 1812 with no library code removed.)
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
; -----------------------------------------------------------------------------
; FP_ONCHIP_MUL: the cold set is materially the same blocks minus one --
; sqtab_init remains the one mandatory boot step, ct_mul_8x8 remains
; boot/diag-only (the issue #71 row generator inlines its own
; quarter-square), but the onchip ARCHIVES do not ship reu_mul_init.o at
; all (issue #81), so its ~186-200 B boot-only body drops out. Unlike
; RESIDENT_BYTES that difference does NOT fall inside ±5%: it is 9% on
; the full archive and 26-35% on the minimal ones, so COLD is keyed on
; variant AND profile (nested form below, same shape as
; REU_BANKS_USED), not on variant alone.
;
; The onchip figures describe the onchip ARCHIVES. The standalone onchip
; test PRG (make onchip-prg) links this same manifest object but does
; still contain reu_mul_init, so its true cold set is the DMA-profile
; figure. That PRG is the library's own test/bench driver, not a
; consumer of the §5 contract, so the archive reading is the one the
; equate commits to.
; LIB_SHA384_ONLY (issue #88): nothing in the SHA-384 path is
; overlay-able. There is no boot-only init (the K constants and rotr
; LUTs are rodata, not generated), no reference-only routine, and every
; block the archive ships is read on each sha_compress. The honest
; figure is therefore 0 -- distinct from "not measured", and distinct
; from the 1800 the archive used to inherit, none of whose constituent
; blocks (sqtab_init, reu_mul_init, ec_precompute_*, fp_mod_inv_fast)
; are present in it at all.
; -----------------------------------------------------------------------------
; LIB_P256_VERIFY_ONLY / LIB_P384_VERIFY_ONLY / LIB_P384_CURVE_ONLY
; (issue #90): none of the three ships ec_precompute_* (no comb),
; inv256.o (no fp_mod_inv_fast / fp_inv_exp_p2), or the other curve, so
; their cold set is sqtab_init + ct_mul_8x8 + reu_fetch_mul_row, plus
; reu_mul_init only in the DMA profile:
;
;   variant                | DMA | onchip
;   -----------------------+-----+-------
;   LIB_P256_VERIFY_ONLY   | 430 |  240
;   LIB_P384_VERIFY_ONLY   | 430 |  240
;   LIB_P384_CURVE_ONLY    | 430 |  240
;
; Cross-check: each row's DMA/onchip delta is 190, the reu_mul_init body
; the onchip archives omit (~186-200 B, matching the full archive's
; 1840/1650 split). LIB_P384_CURVE_ONLY equals LIB_P384_VERIFY_ONLY
; because SHA-384 contributes no cold bytes at all (same reasoning as the
; LIB_SHA384_ONLY = 0 note above: its K constants and rotr LUTs are
; rodata read on every sha_compress, not boot-only init).
;
; All three variants now share ONE arm. Through issue #90 they could not:
; LIB_P256_VERIFY_ONLY measured 720/530 against the P-384 variants'
; 530/340, and that 190 B gap was exactly the 288 B vs 96 B of RFC 6979
; self-test vectors the two curve objects carried. Issue #91 deleted
; those vectors, the gap closed, and the three variants now measure
; identically (429 DMA / 243 onchip) -- so this grouping matches
; REU_BANKS_USED's above rather than deliberately differing from it.
; The convergence is a measured outcome, not a tidy-up: if a future
; change gives one variant cold bytes the others lack, split the arm
; again rather than rounding the difference away.
.ifndef LIB_NISTCURVES_COLD_BYTES
  .ifdef LIB_SHA384_ONLY
    LIB_NISTCURVES_COLD_BYTES = 0
  .elseif .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY) .or .defined(LIB_P384_CURVE_ONLY)
    .if .defined(FP_ONCHIP_MUL)
      ; §6.6: MUST be >= measured (243). 240 was under by 3. The 256-byte
      ; fleet convention would be +5.3% here, outside §5's ±5% band at this
      ; size, so this value keeps fine granularity: >= measured, minimal
      ; headroom.
      LIB_NISTCURVES_COLD_BYTES = 250
    .else
      LIB_NISTCURVES_COLD_BYTES = 430
    .endif
  .elseif .defined(LIB_P256_COMB_ONLY)
    ; Issue #117: the verify-variant cold set plus ec_precompute_256
    ; (616 B, boot-only: populates the REU bank $02 P-256 anchor table):
    ;
    ;   DMA:    sqtab_init+ct_mul_8x8 223 + reu_fetch_mul_row 20
    ;           + reu_mul_init 186 + ec_precompute_256 616  = 1045
    ;           (issue #130: reu_fetch_mul_row 23, reu_mul_init 192 -> 1054;
    ;            nistcurves_reu_dma_wait is RESIDENT, not cold)
    ;   onchip: mul_8x8_onchip cold 243 + ec_precompute_256 616 = 859
    ;
    ; The 186 B reu_mul_init delta is 18% -- outside ±5% like every other
    ; variant's DMA/onchip cold split, so COLD stays keyed on variant AND
    ; profile. §6.6: the 256-boundary convention (1280 / 1024) would be
    ; +22% / +19%, outside §5's ±5% band at this size, so these keep fine
    ; granularity: >= measured, minimal headroom (same reasoning as the
    ; minimal variants' 250 figure).
    .if .defined(FP_ONCHIP_MUL)
      LIB_NISTCURVES_COLD_BYTES = 870
    .else
      LIB_NISTCURVES_COLD_BYTES = 1050
    .endif
  .elseif .defined(FP_ONCHIP_MUL)
    LIB_NISTCURVES_COLD_BYTES = 1650
  .else
    LIB_NISTCURVES_COLD_BYTES = 1840
  .endif
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
;   $0002  | reu_mul    | SHARED_REU_MUL_INIT (src/reu_mul_init.s)
;   $0004  | ct_mul_8x8 | SHARED_CT_MUL_8X8   (src/mul_8x8.s)
;
; The §8.2 provider body lives in src/reu_mul_init.s (moved out of the
; never-archived main.s by issue #81) and ships in every default-profile
; REU-consuming archive via the Makefile's LIB_MUL_OBJS, so the $0002
; claim below is backed by an actual provider in each archive that
; carries this manifest. (Before #81 the claim was untruthful for all
; archives: main.o held the only body.)
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

; LIB_SHA384_ONLY (issue #88): the `lib-p384-sha384` archive carries no
; field, point, or multiply code at all -- SHA-384 is self-contained
; (no REU DMA, no shared mul_*/fp_* scratch, callable without
; sqtab_init / reu_mul_init). It therefore consumes NONE of the three §8
; primitives, which is the §8.0 "non-consumer" state for all three bits:
; both masks are $0000 and there is no provider obligation of any kind.
;
; This is a variant gate, not a profile gate, but it behaves like one
; for mask purposes: it drops bits from BOTH masks, never from ownership
; alone. Expressing it through the SHARED_* deferral switches would be
; wrong in exactly the way SPEC §8.0 warns about -- that would zero
; ownership while leaving consumption set, making a consumer of this
; archive hunt for a sqtab / reu_mul / ct_mul_8x8 provider that a
; SHA-only link has no use for.
.ifdef LIB_SHA384_ONLY
  _OWN_SQTAB      = 0
.elseif .defined(SHARED_SQTAB_INIT)
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
.ifdef LIB_SHA384_ONLY
  _OWN_REU_MUL    = 0
.elseif .defined(FP_ONCHIP_MUL)
  _OWN_REU_MUL    = 0
.elseif .defined(SHARED_REU_MUL_INIT)
  ; Contract v0.9.1: bit $0002 drops exactly when BOTH deferral switches are
  ; defined. SHARED_REU_MUL_INIT alone gates the init body while the canonical
  ; fetch is still exported -- an owner of the fetch that is not an owner of
  ; the primitive, a state §8.0's three-state table has no row for. The assert
  ; below rejects that combination outright rather than letting the mask
  ; misreport it.
  _OWN_REU_MUL    = 0
.else
  _OWN_REU_MUL    = LIB_SHARED_PRIMITIVES_REU_MUL
.endif

; SPEC §8.2 (v0.9.1): the two §8.2 deferral switches MUST move together.
; Partial deferral is non-conformant, so it fails at assemble time here rather
; than producing an archive whose §8.0 mask cannot describe it. If split
; ownership is ever genuinely needed it is a §8.0 fourth-state proposal, not a
; silent half-deferral.
.if .defined(SHARED_REU_MUL_INIT) .and (.not .defined(SHARED_REU_MUL_FETCH))
  .error "SHARED_REU_MUL_INIT requires SHARED_REU_MUL_FETCH (SPEC 8.2 v0.9.1: the two switches move together)"
.endif
.if .defined(SHARED_REU_MUL_FETCH) .and (.not .defined(SHARED_REU_MUL_INIT))
  .error "SHARED_REU_MUL_FETCH requires SHARED_REU_MUL_INIT (SPEC 8.2 v0.9.1: the two switches move together)"
.endif
.ifdef LIB_SHA384_ONLY
  _OWN_CT_MUL_8X8 = 0
.elseif .defined(SHARED_CT_MUL_8X8)
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


; -----------------------------------------------------------------------------
; Shared-primitives CONSUMPTION bitmask (SPEC §5 + §8.0, required v0.5.0)
; -----------------------------------------------------------------------------
; Companion to the ownership mask above. A clear OWNERSHIP bit is ambiguous
; on its own -- it means either of two states that impose OPPOSITE
; obligations on the composed consumer (lib-contract #44 / PR #45):
;
;   deferring consumer  -- the build still READS the primitive at runtime.
;                          The composed link MUST contain exactly one owner,
;                          and boot MUST initialize it before first use.
;   non-consumer        -- the primitive is absent from this build config
;                          entirely. No provider obligation at all.
;
; This library is the worked example of the ambiguity: our
; SHARED_REU_MUL_INIT deferral build and our FP_ONCHIP_MUL profile build
; BOTH export LIB_NISTCURVES_SHARED_PRIMITIVES = $0005, while the first
; requires a §8.2 provider in the link and the second requires none.
;
; The consumes bit is set iff this build configuration consumes the
; primitive AT ALL. The distinction from the ownership mask is which
; switches gate it:
;
;   profile / config gates (FP_ONCHIP_MUL)  -- drop the bit from BOTH masks
;   SHARED_* deferral switches              -- drop the bit from the
;                                              OWNERSHIP mask ONLY
;
; Resulting per-config values:
;
;   build config                      | PRIMITIVES | CONSUMES
;   ----------------------------------+------------+----------
;   default, standalone               |   $0007    |  $0007
;   default + SHARED_REU_MUL_INIT     |   $0005    |  $0007
;   FP_ONCHIP_MUL                     |   $0005    |  $0005
;
; §8.1 sqtab and §8.3 ct_mul_8x8 are consumed unconditionally, so neither
; is gated below. Under FP_ONCHIP_MUL sqtab is in fact verify-HOT (the
; issue #71 inline quarter-square reads it per product) where in the
; default profile it is boot-only -- consumed either way.
;
; ct_mul_8x8 under FP_ONCHIP_MUL deserves a note, since the runtime path
; never calls it (the issue #71 row generator inlines its own
; quarter-square; ct_mul_8x8 remains boot/diag-only). SPEC §8.0 is
; explicit that this still counts as consumption: "exporting a
; primitive's canonical body or init per its §8.x clause counts as
; consuming it, even when no runtime path in that build config invokes
; it" -- the body is present, callable, and available for a co-linked
; sibling to defer to. The clause names this library's FP_ONCHIP_MUL
; build as its worked example and warns specifically against resolving
; it by dropping the ownership bit, because a sibling's deferral may
; depend on that body being here.
; -----------------------------------------------------------------------------
; sqtab and ct_mul_8x8 are consumed by every build that carries field
; arithmetic at all, so they are gated only by LIB_SHA384_ONLY (issue
; #88), which removes the field layer entirely.
.ifdef LIB_SHA384_ONLY
  _USE_SQTAB      = 0
  _USE_REU_MUL    = 0
  _USE_CT_MUL_8X8 = 0
.else
  _USE_SQTAB      = LIB_SHARED_PRIMITIVES_SQTAB
  _USE_CT_MUL_8X8 = LIB_SHARED_PRIMITIVES_CT_MUL_8X8
  .ifdef FP_ONCHIP_MUL
    _USE_REU_MUL  = 0
  .else
    _USE_REU_MUL  = LIB_SHARED_PRIMITIVES_REU_MUL
  .endif
.endif

.ifndef LIB_NISTCURVES_SHARED_CONSUMES
  LIB_NISTCURVES_SHARED_CONSUMES = _USE_SQTAB | _USE_REU_MUL | _USE_CT_MUL_8X8
.endif

; Subset invariant (SPEC §8.0, required): a build cannot own a primitive
; it does not consume. Catches the mis-gating that would otherwise ship a
; mask pair claiming provider duty for a primitive this profile compiled
; out -- e.g. re-expressing the onchip §8.2 exclusion through
; SHARED_REU_MUL_INIT (which zeroes ownership but NOT consumption) would
; leave CONSUMES claiming $0002 with no provider, and the consumer-side
; coverage assert would then demand a §8.2 owner in a link that needs
; none.
.assert (LIB_NISTCURVES_SHARED_PRIMITIVES & ~LIB_NISTCURVES_SHARED_CONSUMES) = 0, error, "a build cannot own a primitive it does not consume"

; Permanent profile guard, mirroring the ownership-side assert above: an
; FP_ONCHIP_MUL build consumes no §8.2 reu_mul table, so a consumer
; composing it must not be told to supply a provider for one.
.ifdef FP_ONCHIP_MUL
  .assert (LIB_NISTCURVES_SHARED_CONSUMES & LIB_SHARED_PRIMITIVES_REU_MUL) = 0, error, "FP_ONCHIP_MUL manifest must not claim SPEC 8.2 reu_mul consumption"
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
.export LIB_NISTCURVES_SHARED_CONSUMES:abs
