; =============================================================================
; zp_config.asm - zero-page allocation for c64-nist-curves math library.
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

; --- Immovable (hardware) ---
proc_port       = $01           ; processor port (ROM banking)

; --- General-purpose pointers / temps ---
zp_tmp1         = $02           ; temp byte
zp_tmp2         = $03           ; temp byte
zp_ptr1         = $fb           ; 2-byte pointer
zp_ptr2         = $fd           ; 2-byte pointer

; --- Field arithmetic working variables (shared by P-256 and P-384) ---
fp_src1         = $22           ; 2-byte pointer to operand 1
fp_src2         = $24           ; 2-byte pointer to operand 2
fp_dst          = $26           ; 2-byte pointer to destination
fp_misc         = $28           ; 2-byte misc pointer (modulus)
fp_carry        = $2a           ; carry/borrow byte
fp_loop         = $2b           ; loop counter
fp_mul_i        = $2c           ; multiply outer index
fp_mul_j        = $2d           ; multiply inner index

; --- Scalar multiplication working variables ---
ec_scalar_ptr   = $3b           ; ZP pointer to 32-byte scalar k

; --- mul_8x8 working variables ---
poly_i          = $1a           ; inner loop counter
poly_j          = $1b           ; outer loop counter
poly_carry      = $1c           ; carry byte
poly_tmp        = $1d           ; temp
