; =============================================================================
; inv256.asm - Fermat inversion for P-256
;
; Computes fp_r0 = (fp_src1)^(-1) mod p256 using Fermat's little theorem:
;     x^(-1) = x^(p-2) mod p
;
; Method: left-to-right square-and-multiply through the 256-bit exponent
;   p - 2 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
;
; Uses fp_mod_sqr and fp_mod_mul (which require fp_misc to point at ec_p256;
; this routine sets that itself). Input x is saved to fp_tmp1 (persistent base)
; and the running result is kept directly in fp_r0 between iterations.
;
; Cost: 255 modular squarings + 127 modular multiplications
;       (p-2 has 128 one-bits, MSB handled specially = 127 extra muls).
; Clobbers: A, X, Y, fp_src1, fp_src2, fp_misc, fp_tmp1, fp_r0
; =============================================================================

; ----- Exponent p-2 as 32 big-endian bytes (bit 255 = bit 7 of byte 0 here) -----
; We walk this byte-array from byte 0 (MSB end) to byte 31 (LSB end),
; rolling bits out of the top with ASL.
fp_inv_exp_p2:
        !byte $FF, $FF, $FF, $FF, $00, $00, $00, $01
        !byte $00, $00, $00, $00, $00, $00, $00, $00
        !byte $00, $00, $00, $00, $FF, $FF, $FF, $FF
        !byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FD

; Scratch zero-page-like state for the inversion loop
fp_inv_bytepos: !byte 0          ; current byte index into fp_inv_exp_p2 (0..31)
fp_inv_bitcnt:  !byte 0          ; remaining bits to process in current byte (1..8)
fp_inv_curbyte: !byte 0          ; current exponent byte being shifted

fp_mod_inv_fast:
        ; --- Setup: fp_misc = ec_p256 (required by fp_mod_sqr/fp_mod_mul) ---
        lda #<ec_p256
        sta fp_misc
        lda #>ec_p256
        sta fp_misc+1

        ; --- Save input x to fp_tmp1 (persistent base across the chain) ---
        ldy #31
@copy_x:
        lda (fp_src1),y
        sta fp_tmp1,y
        dey
        bpl @copy_x

        ; --- Initialise result in fp_r0 ---
        ; The MSB of p-2 is 1, so initial result = x. We then process bits
        ; 254..0 with square-then-conditional-multiply.
        ldy #31
@copy_r0:
        lda fp_tmp1,y
        sta fp_r0,y
        dey
        bpl @copy_r0

        ; --- Set up bit walker. We skip bit 255 (already absorbed). ---
        lda #0
        sta fp_inv_bytepos
        lda #$FF                ; byte 0 = $FF; pre-shift to drop top bit
        asl                     ; consume bit 7 (bit 255 of exponent)
        sta fp_inv_curbyte
        lda #7                  ; 7 bits remain in byte 0
        sta fp_inv_bitcnt

@next_bit:
        ; Do result = result^2  (mod p):  fp_r0 = fp_r0^2
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        jsr fp_mod_sqr          ; fp_r0 = fp_r0^2 mod p

        ; Shift next exponent bit out of fp_inv_curbyte into C
        asl fp_inv_curbyte
        bcc @skip_mul

        ; bit == 1 : result = result * x  (x is in fp_tmp1)
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        lda #<fp_tmp1
        sta fp_src2
        lda #>fp_tmp1
        sta fp_src2+1
        jsr fp_mod_mul          ; fp_r0 = fp_r0 * fp_tmp1 mod p

@skip_mul:
        dec fp_inv_bitcnt
        bne @next_bit

        ; Current byte exhausted. Advance to next byte if any remain.
        inc fp_inv_bytepos
        lda fp_inv_bytepos
        cmp #32
        beq @done

        ; Load next exponent byte into curbyte, reset bit count to 8.
        tax
        lda fp_inv_exp_p2,x
        sta fp_inv_curbyte
        lda #8
        sta fp_inv_bitcnt
        jmp @next_bit

@done:
        rts
