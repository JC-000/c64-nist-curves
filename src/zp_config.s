.setcpu "6502"

; =============================================================================
; zp_config.s - zero-page allocation for c64-nist-curves math library.
;
; Consumers integrating this library can edit the addresses below to
; avoid collisions with their host program's ZP usage. The library source
; refers to these locations only by symbolic name, so moving an address
; here is sufficient to relocate a slot.
;
; proc_port ($01, hardware-fixed 6510 I/O port) is NOT a library slot.
; ROM banking around REU access is the driving consumer's responsibility
; (see main.s / API.md §3 step 1); no archived library object references
; it (issue #90).
;
; Movable: everything below. Pick any free zero-page bytes; the slots do
; not need to remain contiguous. Full-library (default-profile) usage is
; 27 bytes across 16 slots; minimal archives use fewer -- see the
; per-variant `.exportzp` block below and API.md §8.4. Slots:
;
;   fp_src1/fp_src2/fp_dst/fp_misc : four 2-byte pointers (8 bytes total)
;   fp_carry/fp_mul_i/fp_mul_j : three 1-byte scratch (3 bytes)
;   ec_scalar_ptr  : 2-byte pointer to the scalar currently being processed
;   zp_tmp1/zp_tmp2  : two 1-byte temps
;   zp_ptr1/zp_ptr2  : two 2-byte general-purpose pointers (4 bytes)
;   sha_src/sha_len/sha_w_ptr/sha_w_ptr2 : four 2-byte pointers (8 bytes)
;
; Default layout below mirrors the historical c64-x25519 allocation and
; leaves the BASIC/KERNAL ZP regions free.
; =============================================================================

.segment "ZEROPAGE"

; --- General-purpose pointers / temps ---
.ifndef nistcurves_zp_tmp1
  nistcurves_zp_tmp1  = $02                        ; temp byte
.endif
.ifndef nistcurves_zp_tmp2
  nistcurves_zp_tmp2  = $03                        ; temp byte
.endif
.ifndef nistcurves_zp_ptr1
  nistcurves_zp_ptr1  = $fb                        ; 2-byte pointer
.endif
.ifndef nistcurves_zp_ptr2
  nistcurves_zp_ptr2  = $fd                        ; 2-byte pointer
.endif

; Deprecated bare aliases of the four general-purpose slots (SPEC §2 ZP
; registry, §6.5 rename window; lib-contract #83). Same addresses -- the
; canonical nistcurves_zp_* names above are the definitions. The bare names
; collide across libraries (x25519 exported the same trio until its v0.11.0),
; so they are export-gated below and removed at the next MAJOR.
zp_tmp1 = nistcurves_zp_tmp1
zp_tmp2 = nistcurves_zp_tmp2
zp_ptr1 = nistcurves_zp_ptr1
zp_ptr2 = nistcurves_zp_ptr2

; --- Field arithmetic working variables (shared by P-256 and P-384) ---
.ifndef fp_src1
  fp_src1  = $22                        ; 2-byte pointer to operand 1
.endif
.ifndef fp_src2
  fp_src2  = $24                        ; 2-byte pointer to operand 2
.endif
.ifndef fp_dst
  fp_dst  = $26                         ; 2-byte pointer to destination
.endif
.ifndef fp_misc
  fp_misc  = $28                        ; 2-byte misc pointer (modulus)
.endif
.ifndef fp_carry
  fp_carry  = $2a                       ; carry/borrow byte
.endif
.ifndef fp_mul_i
  fp_mul_i  = $2c                       ; multiply outer index
.endif
.ifndef fp_mul_j
  fp_mul_j  = $2d                       ; multiply inner index
.endif

; --- Scalar multiplication working variables ---
.ifndef ec_scalar_ptr
  ec_scalar_ptr  = $3b                  ; ZP pointer to 32-byte scalar k
.endif

; --- SHA-384 streaming pointers ---
.ifndef sha_src
  sha_src  = $04                        ; 2-byte LE pointer to input bytes
.endif
.ifndef sha_len
  sha_len  = $06                        ; 2-byte LE byte count for one update
.endif
.ifndef sha_w_ptr
  sha_w_ptr  = $08                      ; 2-byte LE scratch ptr into sha_w[]
.endif
.ifndef sha_w_ptr2
  sha_w_ptr2 = $0a                      ; 2-byte LE scratch ptr into sha_w[]
.endif

; --- Exports ---
; LIB_SHA384_ONLY (issue #88): the `lib-p384-sha384` archive contains no
; field, point, or multiply code. `sha384.o` `.importzp`s exactly four
; slots -- sha_src, sha_len, sha_w_ptr, sha_w_ptr2 (8 bytes, contiguous
; at $04..$0b) -- and no object in that archive references any other.
; Exporting the other 12 slots from that archive would claim 19 bytes of
; zero page the SHA path never writes.
;
; That over-claim is NOT harmless on this machine. Zero page is the
; scarcest resource on a 6502, and on a C64 with BASIC and KERNAL live
; the genuinely free bytes number in the low tens -- so a 27-byte claim
; against a real need of 8 can make a consumer's assemble-time collision
; check reject an integration that would have fit comfortably. Same
; fail-closed shape as the RESIDENT_BYTES overstatement in issue #90:
; the consumer is refused a configuration that actually works.
;
; The three minimal curve variants (issue #90) narrow the same way, each
; to the slot set its archive's objects actually `.importzp`:
;
;   LIB_P256_VERIFY_ONLY / LIB_P384_VERIFY_ONLY -- the field/point layer
;     plus the ecdsa*_nocomb verifier: 9 slots, 15 bytes. Neither ships
;     sha384.o, nor the Lim-Lee comb objects -- which are the only
;     archived users of zp_ptr1 (anchor copy in ec_precompute_*) and
;     zp_tmp1/zp_tmp2 (sm384w_calc_reu_offset). The two switches stay
;     separate even though they select the same arm today: the two
;     curves' verify-only ZP need is not guaranteed to stay identical,
;     and splitting a shared switch retroactively would break every
;     consumer that had already adopted it.
;   LIB_P384_CURVE_ONLY -- those 9 plus the four sha_* pointers (this
;     variant bundles sha384.o + ecdsa_verify_with_message_384): 13 slots,
;     23 bytes.
;   LIB_P256_COMB_ONLY (issue #117) -- the P-256 verify set plus the
;     Lim-Lee comb objects and the comb-fast ecdsa256.o: those 9 slots
;     plus nistcurves_zp_ptr1 (the anchor-copy pointer in
;     ec_precompute_256): 10 slots, 17 bytes. NOT zp_tmp1/zp_tmp2 --
;     measured via od65 --dump-imports, the only archived user of those
;     two is the P-384 comb's sm384w_calc_reu_offset, which this
;     P-256-only variant does not ship.
;
; None of these depend on FP_ONCHIP_MUL: the profile changes which REU
; registers the field layer touches, not which ZP scratch it uses, so one
; zp_config object per variant serves both that variant's archives.
;
; The slot DEFINITIONS above stay unconditional -- they are inert
; equates, cost nothing, and keep this file single-source. Only the
; export surface narrows, which is what a consumer's collision check
; and the §5 ZP_USAGE_BYTES equate are computed from.
.ifdef LIB_SHA384_ONLY
  .exportzp sha_src, sha_len, sha_w_ptr, sha_w_ptr2
.elseif .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY)
  .exportzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_mul_i, fp_mul_j
  .exportzp ec_scalar_ptr, nistcurves_zp_ptr2
  .ifndef LIB_NO_BARE_EXPORTS
    .exportzp zp_ptr2
  .endif
.elseif .defined(LIB_P384_CURVE_ONLY)
  .exportzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_mul_i, fp_mul_j
  .exportzp ec_scalar_ptr, nistcurves_zp_ptr2
  .ifndef LIB_NO_BARE_EXPORTS
    .exportzp zp_ptr2
  .endif
  .exportzp sha_src, sha_len, sha_w_ptr, sha_w_ptr2
.elseif .defined(LIB_P256_COMB_ONLY)
  .exportzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_mul_i, fp_mul_j
  .exportzp ec_scalar_ptr, nistcurves_zp_ptr1, nistcurves_zp_ptr2
  .ifndef LIB_NO_BARE_EXPORTS
    .exportzp zp_ptr1, zp_ptr2
  .endif
.else
  .exportzp nistcurves_zp_tmp1, nistcurves_zp_tmp2
  .exportzp nistcurves_zp_ptr1, nistcurves_zp_ptr2
  .ifndef LIB_NO_BARE_EXPORTS
    .exportzp zp_tmp1, zp_tmp2, zp_ptr1, zp_ptr2
  .endif
  .exportzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_mul_i, fp_mul_j
  .exportzp ec_scalar_ptr
  .exportzp sha_src, sha_len, sha_w_ptr, sha_w_ptr2
.endif
