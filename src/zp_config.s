.setcpu "6502"

; =============================================================================
; zp_config.s - zero-page allocation for c64-nist-curves math library.
;
; Consumers integrating this library can edit the addresses below to
; avoid collisions with their host program's ZP usage. The library source
; refers to these locations only by symbolic name, so moving an address
; here is sufficient to relocate a slot.
;
; Immovable:
;   proc_port ($01) - 6510 CPU I/O port, hardware-fixed.
;
; Movable: everything else. Pick any free zero-page bytes; the slots do
; not need to remain contiguous, but the library currently uses roughly
; 16 bytes plus the two 2-byte general pointers. Required slots:
;
;   fp_src1/fp_src2/fp_dst/fp_misc : four 2-byte pointers (8 bytes total)
;   fp_carry/fp_loop/fp_mul_i/fp_mul_j : four 1-byte scratch (4 bytes)
;   ec_scalar_ptr  : 1 byte (scalar index)
;   poly_i..poly_tmp : four 1-byte scratch used by mul_8x8
;   zp_tmp1/zp_tmp2  : two 1-byte temps
;   zp_ptr1/zp_ptr2  : two 2-byte general-purpose pointers (4 bytes)
;
; Default layout below mirrors the historical c64-x25519 allocation and
; leaves the BASIC/KERNAL ZP regions free.
; =============================================================================

.segment "ZEROPAGE"

; --- Immovable (hardware) ---
.ifndef proc_port
  proc_port  = $01                      ; processor port (ROM banking)
.endif

; --- General-purpose pointers / temps ---
.ifndef zp_tmp1
  zp_tmp1  = $02                        ; temp byte
.endif
.ifndef zp_tmp2
  zp_tmp2  = $03                        ; temp byte
.endif
.ifndef zp_ptr1
  zp_ptr1  = $fb                        ; 2-byte pointer
.endif
.ifndef zp_ptr2
  zp_ptr2  = $fd                        ; 2-byte pointer
.endif

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
.ifndef fp_loop
  fp_loop  = $2b                        ; loop counter
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

; --- mul_8x8 working variables ---
.ifndef poly_i
  poly_i  = $1a                         ; inner loop counter
.endif
.ifndef poly_j
  poly_j  = $1b                         ; outer loop counter
.endif
.ifndef poly_carry
  poly_carry  = $1c                     ; carry byte
.endif
.ifndef poly_tmp
  poly_tmp  = $1d                       ; temp
.endif

; --- Exports ---
; LIB_SHA384_ONLY (issue #88): the `lib-p384-sha384` archive contains no
; field, point, or multiply code. `sha384.o` `.importzp`s exactly four
; slots -- sha_src, sha_len, sha_w_ptr, sha_w_ptr2 (8 bytes, contiguous
; at $04..$0b) -- and no object in that archive references any other,
; not even proc_port (SHA does no ROM banking, since it issues no REU
; DMA). Exporting the other 17 slots from that archive would claim 23
; bytes of zero page the SHA path never writes.
;
; That over-claim is NOT harmless on this machine. Zero page is the
; scarcest resource on a 6502, and on a C64 with BASIC and KERNAL live
; the genuinely free bytes number in the low tens -- so a 31-byte claim
; against a real need of 8 can make a consumer's assemble-time collision
; check reject an integration that would have fit comfortably. Same
; fail-closed shape as the RESIDENT_BYTES overstatement in issue #90:
; the consumer is refused a configuration that actually works.
;
; The slot DEFINITIONS above stay unconditional -- they are inert
; equates, cost nothing, and keep this file single-source. Only the
; export surface narrows, which is what a consumer's collision check
; and the §5 ZP_USAGE_BYTES equate are computed from.
.ifdef LIB_SHA384_ONLY
  .exportzp sha_src, sha_len, sha_w_ptr, sha_w_ptr2
.else
  .exportzp proc_port, zp_tmp1, zp_tmp2, zp_ptr1, zp_ptr2
  .exportzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_loop, fp_mul_i, fp_mul_j
  .exportzp ec_scalar_ptr, poly_i, poly_j, poly_carry, poly_tmp
  .exportzp sha_src, sha_len, sha_w_ptr, sha_w_ptr2
.endif
