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
.exportzp proc_port, zp_tmp1, zp_tmp2, zp_ptr1, zp_ptr2
.exportzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_loop, fp_mul_i, fp_mul_j
.exportzp ec_scalar_ptr, poly_i, poly_j, poly_carry, poly_tmp
.exportzp sha_src, sha_len, sha_w_ptr, sha_w_ptr2
