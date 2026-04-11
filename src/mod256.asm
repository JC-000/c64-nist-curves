; =============================================================================
; mod256.asm - Modular operations for P-256, including Solinas fast reduction
;
; All field elements stored LITTLE-ENDIAN: byte 0 = LSB, byte 31 = MSB.
; =============================================================================

; =============================================================================
; P-256 prime and group order constants (little-endian)
; =============================================================================

; P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
; Big-endian hex: FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
; Little-endian bytes:
ec_p256:
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 0-7   (w0=FFFFFFFF, w1=FFFFFFFF)
        !byte $FF,$FF,$FF,$FF,$00,$00,$00,$00  ; bytes 8-15  (w2=FFFFFFFF, w3=00000000)
        !byte $00,$00,$00,$00,$00,$00,$00,$00  ; bytes 16-23 (w4=00000000, w5=00000000)
        !byte $01,$00,$00,$00,$FF,$FF,$FF,$FF  ; bytes 24-31 (w6=00000001, w7=FFFFFFFF)

; P-256 group order: n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
; Little-endian bytes:
ec_n256:
        !byte $51,$25,$63,$FC,$C2,$CA,$B9,$F3  ; bytes 0-7
        !byte $84,$9E,$17,$A7,$AD,$FA,$E6,$BC  ; bytes 8-15
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF  ; bytes 16-23
        !byte $00,$00,$00,$00,$FF,$FF,$FF,$FF  ; bytes 24-31

; =============================================================================
; fp_mod_add - (fp_dst) = ((fp_src1) + (fp_src2)) mod (fp_misc)
;
; After addition, if carry or result >= modulus, subtract modulus.
; Clobbers: A, X, Y
; =============================================================================
fp_mod_add:
        jsr fp_add
        lda fp_carry
        bne @reduce

        ; Compare dst with modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_cmp
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        bcc @done               ; result < modulus, done

@reduce:
        ; dst -= modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_sub
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
@done:
        rts

; =============================================================================
; fp_mod_sub - (fp_dst) = ((fp_src1) - (fp_src2)) mod (fp_misc)
;
; If borrow, add modulus back.
; Clobbers: A, X, Y
; =============================================================================
fp_mod_sub:
        jsr fp_sub
        lda fp_carry
        beq @done               ; no borrow, done

        ; Underflow: add modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
@done:
        rts

; =============================================================================
; fp_mod_reduce256 - Solinas fast reduction for P-256
;
; Reduces 512-bit fp_wide mod P-256 prime -> fp_r0 (32 bytes, little-endian)
;
; P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
;
; The 64-byte product fp_wide is treated as 16 little-endian 32-bit words:
;   c0  = fp_wide[0..3]    c1  = fp_wide[4..7]    ...   c15 = fp_wide[60..63]
;
; Reduction formula (NIST SP 800-186), values as 8 LE 32-bit words (w0..w7):
;   s1 = (c0,  c1,  c2,  c3,  c4,  c5,  c6,  c7)     lower half
;   s2 = (0,   0,   0,   c11, c12, c13, c14, c15)
;   s3 = (0,   0,   0,   c12, c13, c14, c15, 0)
;   s4 = (c8,  c9,  c10, 0,   0,   0,   c14, c15)
;   s5 = (c9,  c10, c11, c13, c14, c15, c13, c8)
;   s6 = (c11, c12, c13, 0,   0,   0,   c8,  c10)
;   s7 = (c12, c13, c14, c15, 0,   0,   c9,  c11)
;   s8 = (c13, c14, c15, c8,  c9,  c10, 0,   c12)
;   s9 = (c14, c15, 0,   c9,  c10, c11, 0,   c13)
;
;   Result = s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9 (mod p)
;
; Implementation: Work byte-by-byte through the 32 output bytes.
; For each byte position, accumulate contributions from all s-values
; (with appropriate signs and doubling) into a running signed accumulator.
; Propagate carry/borrow across all 32 bytes, then do final reduction.
;
; The accumulator is a signed 16-bit value that handles the worst case of
; multiple additions and subtractions at each byte position.
; =============================================================================

; Macro-like helper: cN means fp_wide[N*4 .. N*4+3] (a 32-bit word).
; Byte b of cN is fp_wide[N*4 + b], where b=0..3.
; Output byte position p corresponds to word index p/4 and byte offset p%4.

fp_mod_reduce256:
        ; Signed 16-bit accumulator: low byte in sol_sum_lo (abs), high byte in Y.
        ; Byte index (0..31) kept in X throughout. Contribution routines preserve
        ; X and Y, updating sol_sum_lo and Y via self-modifying JMP dispatch.

        lda #0
        sta sol_sum_lo
        tay                     ; Y = 0 (signed high byte of accumulator)
        ldx #0                  ; byte index

sol_byte_loop:
        ; --- Add s1[x] = fp_wide[x] (lower half, always present) ---
        clc
        lda sol_sum_lo
        adc fp_wide,x
        sta sol_sum_lo
        bcc +
        iny
+
        ; --- Dispatch to per-byte contribution routine via self-mod JMP ---
        lda sol_jmp_tbl_lo,x
        sta sol_dispatch+1
        lda sol_jmp_tbl_hi,x
        sta sol_dispatch+2
sol_dispatch:
        jmp $0000               ; patched -> sol_bN; returns via jmp sol_after_contrib
sol_after_contrib:
        ; sol_sum_lo + Y now holds the signed 16-bit partial sum for this byte.
        lda sol_sum_lo
        sta fp_r0,x
        ; Carry into next byte: low = old high (Y), high = sign-extend(Y).
        sty sol_sum_lo
        cpy #$80                ; carry = (Y >= $80); sets sign flag too
        lda #0
        bcc +
        lda #$ff                ; Y was negative -> sign-extend to $FF
+
        tay
        inx
        cpx #32
        bcc sol_byte_loop

        ; sol_sum_lo / Y contain the signed overflow beyond byte 31 --
        ; i.e. (Y, sol_sum_lo) is the signed 16-bit overflow.
        lda sol_sum_lo
        sta sol_overflow
        sty sol_overflow+1

@reduce_loop:
        ; Check if overflow is negative -> add p
        lda sol_overflow+1
        bmi @add_p

        ; Check if overflow is positive -> subtract p
        ora sol_overflow
        bne @sub_p

        ; overflow == 0: check if fp_r0 >= p (one final conditional subtraction)
        ldy #31
@cmp_loop:
        lda fp_r0,y
        cmp ec_p256,y
        bcc @reduction_done     ; fp_r0 < p, we're done
        bne @sub_p              ; fp_r0 > p at this byte, subtract
        dey
        bpl @cmp_loop
        ; fp_r0 == p exactly, fall through to subtract

@sub_p:
        ; {sol_overflow, fp_r0} -= {0, ec_p256}
        sec
        ldy #0
        ldx #32
@sub_p_loop:
        lda fp_r0,y
        sbc ec_p256,y
        sta fp_r0,y
        iny
        dex
        bne @sub_p_loop
        ; Propagate borrow into overflow (carry flag from last SBC)
        lda sol_overflow
        sbc #0
        sta sol_overflow
        lda sol_overflow+1
        sbc #0
        sta sol_overflow+1
        jmp @reduce_loop

@add_p:
        ; {sol_overflow, fp_r0} += {0, ec_p256}
        clc
        ldy #0
        ldx #32
@add_p_loop:
        lda fp_r0,y
        adc ec_p256,y
        sta fp_r0,y
        iny
        dex
        bne @add_p_loop
        ; Propagate carry into overflow (carry flag from last ADC)
        lda sol_overflow
        adc #0
        sta sol_overflow
        lda sol_overflow+1
        adc #0
        sta sol_overflow+1
        jmp @reduce_loop

@reduction_done:
        rts

; --- Per-byte contribution accumulator for Solinas reduction ---
; Adds/subtracts the appropriate fp_wide bytes to sol_sum based on sol_byte_idx.
;
; For each output byte position, we know exactly which source bytes contribute.
; We work in terms of fp_wide byte offsets. cN starts at fp_wide[N*4].
;
; The mapping (byte position -> contributions) is derived from the s-value
; definitions. Each 32-bit word cN occupies 4 bytes. For output byte p,
; the word index is p/4 (0..7) and byte offset is p%4 (0..3).
;
; We implement this as a jump table indexed by byte position.

; Jump tables for 32 byte positions (indexed by X = byte idx 0..31).
; Split into parallel lo/hi byte tables so dispatch is a single indexed
; load into the self-modifying sol_dispatch instruction above.
sol_jmp_tbl_lo:
        !byte <sol_b0,  <sol_b1,  <sol_b2,  <sol_b3
        !byte <sol_b4,  <sol_b5,  <sol_b6,  <sol_b7
        !byte <sol_b8,  <sol_b9,  <sol_b10, <sol_b11
        !byte <sol_b12, <sol_b13, <sol_b14, <sol_b15
        !byte <sol_b16, <sol_b17, <sol_b18, <sol_b19
        !byte <sol_b20, <sol_b21, <sol_b22, <sol_b23
        !byte <sol_b24, <sol_b25, <sol_b26, <sol_b27
        !byte <sol_b28, <sol_b29, <sol_b30, <sol_b31
sol_jmp_tbl_hi:
        !byte >sol_b0,  >sol_b1,  >sol_b2,  >sol_b3
        !byte >sol_b4,  >sol_b5,  >sol_b6,  >sol_b7
        !byte >sol_b8,  >sol_b9,  >sol_b10, >sol_b11
        !byte >sol_b12, >sol_b13, >sol_b14, >sol_b15
        !byte >sol_b16, >sol_b17, >sol_b18, >sol_b19
        !byte >sol_b20, >sol_b21, >sol_b22, >sol_b23
        !byte >sol_b24, >sol_b25, >sol_b26, >sol_b27
        !byte >sol_b28, >sol_b29, >sol_b30, >sol_b31

; Macro-like helpers for adding/subtracting an fp_wide byte to the running
; 16-bit signed accumulator. Convention: low byte lives in `sol_sum_lo`,
; high byte lives in the Y register throughout the per-byte contribution
; sequence. X holds the output byte index and must be preserved.

; Add fp_wide[off] to (Y:sol_sum_lo). Clobbers A, flags; updates Y on carry.
!macro sol_add_byte .off {
        clc
        lda sol_sum_lo
        adc fp_wide + .off
        sta sol_sum_lo
        bcc .skip
        iny
.skip:
}

; Add 2 * fp_wide[off] to (Y:sol_sum_lo). Bit 7 of the byte becomes a +1 in Y,
; plus any carry from the low-byte addition.
!macro sol_add2_byte .off {
        lda fp_wide + .off
        asl
        bcc .noinc1
        iny                     ; bit 7 -> +256
.noinc1:
        clc
        adc sol_sum_lo
        sta sol_sum_lo
        bcc .noinc2
        iny
.noinc2:
}

; Subtract fp_wide[off] from (Y:sol_sum_lo). Borrow decrements Y.
!macro sol_sub_byte .off {
        sec
        lda sol_sum_lo
        sbc fp_wide + .off
        sta sol_sum_lo
        bcs .skip
        dey
.skip:
}

; For each byte position, list contributions beyond s1 (which is always added
; in the main loop). Format: +add, ++add_twice, -sub
;
; Derived from the s-value table:
; Output byte p: word_idx = p/4, byte_in_word = p%4
;
; Word 0 (bytes 0-3) of each s-value:
;   s1:w0=c0, s2:w0=0, s3:w0=0, s4:w0=c8, s5:w0=c9
;   s6:w0=c11, s7:w0=c12, s8:w0=c13, s9:w0=c14
;   => +c8 +c9 -c11 -c12 -c13 -c14
;
; Byte 0 (byte 0 of word 0) -> fp_wide offsets: c8[0]=32, c9[0]=36, c11[0]=44, c12[0]=48, c13[0]=52, c14[0]=56

sol_b0: ; +c8[0] +c9[0] -c11[0] -c12[0] -c13[0] -c14[0]
        +sol_add_byte 32        ; c8[0]
        +sol_add_byte 36        ; c9[0]
        +sol_sub_byte 44        ; c11[0]
        +sol_sub_byte 48        ; c12[0]
        +sol_sub_byte 52        ; c13[0]
        +sol_sub_byte 56        ; c14[0]
        jmp sol_after_contrib

sol_b1: ; +c8[1] +c9[1] -c11[1] -c12[1] -c13[1] -c14[1]
        +sol_add_byte 33
        +sol_add_byte 37
        +sol_sub_byte 45
        +sol_sub_byte 49
        +sol_sub_byte 53
        +sol_sub_byte 57
        jmp sol_after_contrib

sol_b2: ; +c8[2] +c9[2] -c11[2] -c12[2] -c13[2] -c14[2]
        +sol_add_byte 34
        +sol_add_byte 38
        +sol_sub_byte 46
        +sol_sub_byte 50
        +sol_sub_byte 54
        +sol_sub_byte 58
        jmp sol_after_contrib

sol_b3: ; +c8[3] +c9[3] -c11[3] -c12[3] -c13[3] -c14[3]
        +sol_add_byte 35
        +sol_add_byte 39
        +sol_sub_byte 47
        +sol_sub_byte 51
        +sol_sub_byte 55
        +sol_sub_byte 59
        jmp sol_after_contrib

; Word 1 (bytes 4-7):
;   s1:w1=c1, s2:w1=0, s3:w1=0, s4:w1=c9, s5:w1=c10
;   s6:w1=c12, s7:w1=c13, s8:w1=c14, s9:w1=c15
;   => +c9 +c10 -c12 -c13 -c14 -c15

sol_b4:
        +sol_add_byte 36        ; c9[0]
        +sol_add_byte 40        ; c10[0]
        +sol_sub_byte 48        ; c12[0]
        +sol_sub_byte 52        ; c13[0]
        +sol_sub_byte 56        ; c14[0]
        +sol_sub_byte 60        ; c15[0]
        jmp sol_after_contrib

sol_b5:
        +sol_add_byte 37
        +sol_add_byte 41
        +sol_sub_byte 49
        +sol_sub_byte 53
        +sol_sub_byte 57
        +sol_sub_byte 61
        jmp sol_after_contrib

sol_b6:
        +sol_add_byte 38
        +sol_add_byte 42
        +sol_sub_byte 50
        +sol_sub_byte 54
        +sol_sub_byte 58
        +sol_sub_byte 62
        jmp sol_after_contrib

sol_b7:
        +sol_add_byte 39
        +sol_add_byte 43
        +sol_sub_byte 51
        +sol_sub_byte 55
        +sol_sub_byte 59
        +sol_sub_byte 63
        jmp sol_after_contrib

; Word 2 (bytes 8-11):
;   s1:w2=c2, s2:w2=0, s3:w2=0, s4:w2=c10, s5:w2=c11
;   s6:w2=c13, s7:w2=c14, s8:w2=c15, s9:w2=0
;   => +c10 +c11 -c13 -c14 -c15

sol_b8:
        +sol_add_byte 40        ; c10[0]
        +sol_add_byte 44        ; c11[0]
        +sol_sub_byte 52        ; c13[0]
        +sol_sub_byte 56        ; c14[0]
        +sol_sub_byte 60        ; c15[0]
        jmp sol_after_contrib

sol_b9:
        +sol_add_byte 41
        +sol_add_byte 45
        +sol_sub_byte 53
        +sol_sub_byte 57
        +sol_sub_byte 61
        jmp sol_after_contrib

sol_b10:
        +sol_add_byte 42
        +sol_add_byte 46
        +sol_sub_byte 54
        +sol_sub_byte 58
        +sol_sub_byte 62
        jmp sol_after_contrib

sol_b11:
        +sol_add_byte 43
        +sol_add_byte 47
        +sol_sub_byte 55
        +sol_sub_byte 59
        +sol_sub_byte 63
        jmp sol_after_contrib

; Word 3 (bytes 12-15):
;   s1:w3=c3, s2:w3=c11, s3:w3=c12, s4:w3=0, s5:w3=c13
;   s6:w3=0, s7:w3=c15, s8:w3=c8, s9:w3=c9
;   => +2*c11 +2*c12 +c13 -c15 -c8 -c9

sol_b12:
        +sol_add2_byte 44       ; 2*c11[0]
        +sol_add2_byte 48       ; 2*c12[0]
        +sol_add_byte 52        ; c13[0]
        +sol_sub_byte 60        ; c15[0]
        +sol_sub_byte 32        ; c8[0]
        +sol_sub_byte 36        ; c9[0]
        jmp sol_after_contrib

sol_b13:
        +sol_add2_byte 45       ; 2*c11[1]
        +sol_add2_byte 49       ; 2*c12[1]
        +sol_add_byte 53        ; c13[1]
        +sol_sub_byte 61        ; c15[1]
        +sol_sub_byte 33        ; c8[1]
        +sol_sub_byte 37        ; c9[1]
        jmp sol_after_contrib

sol_b14:
        +sol_add2_byte 46
        +sol_add2_byte 50
        +sol_add_byte 54
        +sol_sub_byte 62
        +sol_sub_byte 34
        +sol_sub_byte 38
        jmp sol_after_contrib

sol_b15:
        +sol_add2_byte 47
        +sol_add2_byte 51
        +sol_add_byte 55
        +sol_sub_byte 63
        +sol_sub_byte 35
        +sol_sub_byte 39
        jmp sol_after_contrib

; Word 4 (bytes 16-19):
;   s1:w4=c4, s2:w4=c12, s3:w4=c13, s4:w4=0, s5:w4=c14
;   s6:w4=0, s7:w4=0, s8:w4=c9, s9:w4=c10
;   => +2*c12 +2*c13 +c14 -c9 -c10

sol_b16:
        +sol_add2_byte 48       ; 2*c12[0]
        +sol_add2_byte 52       ; 2*c13[0]
        +sol_add_byte 56        ; c14[0]
        +sol_sub_byte 36        ; c9[0]
        +sol_sub_byte 40        ; c10[0]
        jmp sol_after_contrib

sol_b17:
        +sol_add2_byte 49
        +sol_add2_byte 53
        +sol_add_byte 57
        +sol_sub_byte 37
        +sol_sub_byte 41
        jmp sol_after_contrib

sol_b18:
        +sol_add2_byte 50
        +sol_add2_byte 54
        +sol_add_byte 58
        +sol_sub_byte 38
        +sol_sub_byte 42
        jmp sol_after_contrib

sol_b19:
        +sol_add2_byte 51
        +sol_add2_byte 55
        +sol_add_byte 59
        +sol_sub_byte 39
        +sol_sub_byte 43
        jmp sol_after_contrib

; Word 5 (bytes 20-23):
;   s1:w5=c5, s2:w5=c13, s3:w5=c14, s4:w5=0, s5:w5=c15
;   s6:w5=0, s7:w5=0, s8:w5=c10, s9:w5=c11
;   => +2*c13 +2*c14 +c15 -c10 -c11

sol_b20:
        +sol_add2_byte 52       ; 2*c13[0]
        +sol_add2_byte 56       ; 2*c14[0]
        +sol_add_byte 60        ; c15[0]
        +sol_sub_byte 40        ; c10[0]
        +sol_sub_byte 44        ; c11[0]
        jmp sol_after_contrib

sol_b21:
        +sol_add2_byte 53
        +sol_add2_byte 57
        +sol_add_byte 61
        +sol_sub_byte 41
        +sol_sub_byte 45
        jmp sol_after_contrib

sol_b22:
        +sol_add2_byte 54
        +sol_add2_byte 58
        +sol_add_byte 62
        +sol_sub_byte 42
        +sol_sub_byte 46
        jmp sol_after_contrib

sol_b23:
        +sol_add2_byte 55
        +sol_add2_byte 59
        +sol_add_byte 63
        +sol_sub_byte 43
        +sol_sub_byte 47
        jmp sol_after_contrib

; Word 6 (bytes 24-27):
;   s1:w6=c6, s2:w6=c14, s3:w6=c15, s4:w6=c14, s5:w6=c13
;   s6:w6=c8, s7:w6=c9, s8:w6=0, s9:w6=0
;   => +2*c14 +2*c15 +c14 +c13 -c8 -c9
;   = +3*c14 +2*c15 +c13 -c8 -c9

sol_b24:
        +sol_add_byte 56        ; c14[0] (first of three)
        +sol_add_byte 56        ; c14[0] (second)
        +sol_add_byte 56        ; c14[0] (third) = 3*c14[0]
        +sol_add2_byte 60       ; 2*c15[0]
        +sol_add_byte 52        ; c13[0]
        +sol_sub_byte 32        ; c8[0]
        +sol_sub_byte 36        ; c9[0]
        jmp sol_after_contrib

sol_b25:
        +sol_add_byte 57
        +sol_add_byte 57
        +sol_add_byte 57
        +sol_add2_byte 61
        +sol_add_byte 53
        +sol_sub_byte 33
        +sol_sub_byte 37
        jmp sol_after_contrib

sol_b26:
        +sol_add_byte 58
        +sol_add_byte 58
        +sol_add_byte 58
        +sol_add2_byte 62
        +sol_add_byte 54
        +sol_sub_byte 34
        +sol_sub_byte 38
        jmp sol_after_contrib

sol_b27:
        +sol_add_byte 59
        +sol_add_byte 59
        +sol_add_byte 59
        +sol_add2_byte 63
        +sol_add_byte 55
        +sol_sub_byte 35
        +sol_sub_byte 39
        jmp sol_after_contrib

; Word 7 (bytes 28-31):
;   s1:w7=c7, s2:w7=c15, s3:w7=0, s4:w7=c15, s5:w7=c8
;   s6:w7=c10, s7:w7=c11, s8:w7=c12, s9:w7=c13
;   => +2*c15 +c15 +c8 -c10 -c11 -c12 -c13
;   = +3*c15 +c8 -c10 -c11 -c12 -c13

sol_b28:
        +sol_add_byte 60        ; c15[0]
        +sol_add_byte 60        ; c15[0]
        +sol_add_byte 60        ; c15[0] = 3*c15[0]
        +sol_add_byte 32        ; c8[0]
        +sol_sub_byte 40        ; c10[0]
        +sol_sub_byte 44        ; c11[0]
        +sol_sub_byte 48        ; c12[0]
        +sol_sub_byte 52        ; c13[0]
        jmp sol_after_contrib

sol_b29:
        +sol_add_byte 61
        +sol_add_byte 61
        +sol_add_byte 61
        +sol_add_byte 33
        +sol_sub_byte 41
        +sol_sub_byte 45
        +sol_sub_byte 49
        +sol_sub_byte 53
        jmp sol_after_contrib

sol_b30:
        +sol_add_byte 62
        +sol_add_byte 62
        +sol_add_byte 62
        +sol_add_byte 34
        +sol_sub_byte 42
        +sol_sub_byte 46
        +sol_sub_byte 50
        +sol_sub_byte 54
        jmp sol_after_contrib

sol_b31:
        +sol_add_byte 63
        +sol_add_byte 63
        +sol_add_byte 63
        +sol_add_byte 35
        +sol_sub_byte 43
        +sol_sub_byte 47
        +sol_sub_byte 51
        +sol_sub_byte 55
        jmp sol_after_contrib

; Scratch variables for Solinas reduction
sol_acc_lo:      !byte 0
sol_acc_hi:      !byte 0
sol_sum_lo:      !byte 0
sol_sum_hi:      !byte 0
sol_byte_idx:    !byte 0
sol_overflow:    !word 0

; =============================================================================
; fp_mod_mul - fp_r0 = ((fp_src1) * (fp_src2)) mod p256
;
; Calls fp_mul then fp_mod_reduce256.
; Clobbers: A, X, Y
; =============================================================================
fp_mod_mul:
        jsr fp_mul
        jsr fp_mod_reduce256
        rts

; =============================================================================
; fp_mod_sqr - fp_r0 = ((fp_src1)^2) mod p256
;
; Calls fp_sqr then fp_mod_reduce256.
; Clobbers: A, X, Y
; =============================================================================
fp_mod_sqr:
        jsr fp_sqr
        jsr fp_mod_reduce256
        rts

; =============================================================================
; fp_mod_inv - fp_r0 = (fp_src1)^(-1) mod (fp_misc)
;
; Binary extended GCD algorithm.
; Adapted from ecdsa_mod.asm for little-endian, debug prints removed.
; Uses fp_inv_u/v/x1/x2 from data.asm.
; Clobbers: A, X, Y
; =============================================================================
fp_mod_inv:
        ; Save fp_dst
        lda fp_dst
        pha
        lda fp_dst+1
        pha

        ; u = src1
        lda #<fp_inv_u
        sta fp_dst
        lda #>fp_inv_u
        sta fp_dst+1
        jsr fp_copy

        ; v = modulus
        lda fp_misc
        sta fp_src1
        lda fp_misc+1
        sta fp_src1+1
        lda #<fp_inv_v
        sta fp_dst
        lda #>fp_inv_v
        sta fp_dst+1
        jsr fp_copy

        ; x1 = 1 (little-endian: byte 0 = 1, rest = 0)
        lda #<fp_inv_x1
        sta fp_dst
        lda #>fp_inv_x1
        sta fp_dst+1
        jsr fp_zero
        lda #1
        sta fp_inv_x1           ; byte 0 = LSB = 1

        ; x2 = 0
        lda #<fp_inv_x2
        sta fp_dst
        lda #>fp_inv_x2
        sta fp_dst+1
        jsr fp_zero

        ; Restore fp_dst
        pla
        sta fp_dst+1
        pla
        sta fp_dst

@mainlp:
        ; Check u == 1
        lda #<fp_inv_u
        sta fp_src1
        lda #>fp_inv_u
        sta fp_src1+1
        jsr fp_chk_one
        bne +
        jmp @u_one
+
        ; Check v == 1
        lda #<fp_inv_v
        sta fp_src1
        lda #>fp_inv_v
        sta fp_src1+1
        jsr fp_chk_one
        bne +
        jmp @v_one
+

        ; While u is even (bit 0 of byte 0 == 0 in little-endian)
@halfu:
        lda fp_inv_u            ; byte 0 = LSB
        and #1
        beq +
        jmp @halfv
+

        ; Inlined 32-byte shift of fp_inv_u using absolute addressing.
        ; MSB-first ROR chain; clc before first ROR (equivalent to LSR on MSB).
        clc
!for .i, 31, 0 {
        ror fp_inv_u + .i
}

        lda fp_inv_x1           ; byte 0 = LSB
        and #1
        beq @x1ev_nocarry
        ; x1 += mod (in place). mod is (fp_misc) - dynamic, use indirect for src2.
        ; x1 destination is absolute; use absolute addressing for x1 to avoid
        ; indirect fp_src1/fp_dst pointer setup/teardown.
        clc
        ldy #0
        ldx #32
@x1addmod:
        lda fp_inv_x1,y
        adc (fp_misc),y
        sta fp_inv_x1,y
        iny
        dex
        bne @x1addmod
        lda #0
        adc #0                  ; A = carry out (0 or 1)
        lsr                     ; push into 6502 carry flag
        jmp @x1do_shift
@x1ev_nocarry:
        clc
@x1do_shift:
        ; x1 >>= 1, with add-carry shifted into MSB.
        ; Inlined ROR chain on absolute addresses.
!for .i, 31, 0 {
        ror fp_inv_x1 + .i
}
        jmp @halfu

        ; While v is even
@halfv:
        lda fp_inv_v            ; byte 0 = LSB
        and #1
        beq +
        jmp @comp
+

        clc
!for .i, 31, 0 {
        ror fp_inv_v + .i
}

        lda fp_inv_x2           ; byte 0 = LSB
        and #1
        beq @x2ev_nocarry
        clc
        ldy #0
        ldx #32
@x2addmod:
        lda fp_inv_x2,y
        adc (fp_misc),y
        sta fp_inv_x2,y
        iny
        dex
        bne @x2addmod
        lda #0
        adc #0
        lsr
        jmp @x2do_shift
@x2ev_nocarry:
        clc
@x2do_shift:
!for .i, 31, 0 {
        ror fp_inv_x2 + .i
}
        jmp @halfv

@comp:
        ; Compare u vs v
        lda #<fp_inv_u
        sta fp_src1
        lda #>fp_inv_u
        sta fp_src1+1
        lda #<fp_inv_v
        sta fp_src2
        lda #>fp_inv_v
        sta fp_src2+1
        jsr fp_cmp
        bcc @vbig

        ; u >= v: u -= v, x1 -= x2 mod m
        lda #<fp_inv_u
        sta fp_dst
        lda #>fp_inv_u
        sta fp_dst+1
        jsr fp_sub

        lda #<fp_inv_x1
        sta fp_src1
        lda #>fp_inv_x1
        sta fp_src1+1
        lda #<fp_inv_x2
        sta fp_src2
        lda #>fp_inv_x2
        sta fp_src2+1
        lda #<fp_inv_x1
        sta fp_dst
        lda #>fp_inv_x1
        sta fp_dst+1
        jsr fp_mod_sub
        jmp @mainlp

@vbig:
        ; v -= u, x2 -= x1 mod m
        lda #<fp_inv_v
        sta fp_src1
        lda #>fp_inv_v
        sta fp_src1+1
        lda #<fp_inv_u
        sta fp_src2
        lda #>fp_inv_u
        sta fp_src2+1
        lda #<fp_inv_v
        sta fp_dst
        lda #>fp_inv_v
        sta fp_dst+1
        jsr fp_sub

        lda #<fp_inv_x2
        sta fp_src1
        lda #>fp_inv_x2
        sta fp_src1+1
        lda #<fp_inv_x1
        sta fp_src2
        lda #>fp_inv_x1
        sta fp_src2+1
        lda #<fp_inv_x2
        sta fp_dst
        lda #>fp_inv_x2
        sta fp_dst+1
        jsr fp_mod_sub
        jmp @mainlp

@u_one: ; Result = x1
        ldy #31
@cu:
        lda fp_inv_x1,y
        sta fp_r0,y
        dey
        bpl @cu
        rts

@v_one: ; Result = x2
        ldy #31
@cv:
        lda fp_inv_x2,y
        sta fp_r0,y
        dey
        bpl @cv
        rts

; =============================================================================
; fp_chk_one - Check if (fp_src1) == 1 in little-endian
;
; Little-endian: byte 0 should be 1, bytes 1-31 should be 0.
; Z flag set if value == 1.
; Clobbers: A, Y
; =============================================================================
fp_chk_one:
        ldy #0
        lda (fp_src1),y
        cmp #1
        bne @no
        iny
@loop:
        lda (fp_src1),y
        bne @no
        iny
        cpy #32
        bne @loop
        lda #0                  ; set Z flag (equal)
        rts
@no:
        lda #$ff                ; clear Z flag (not equal)
        rts

; =============================================================================
; ec_set_modp - Set fp_misc to point to ec_p256
; Clobbers: A
; =============================================================================
ec_set_modp:
        lda #<ec_p256
        sta fp_misc
        lda #>ec_p256
        sta fp_misc+1
        rts

; =============================================================================
; ec_set_modn - Set fp_misc to point to ec_n256
; Clobbers: A
; =============================================================================
ec_set_modn:
        lda #<ec_n256
        sta fp_misc
        lda #>ec_n256
        sta fp_misc+1
        rts

; =============================================================================
; ec_mulp - Modular multiply mod p, copy result to (fp_dst)
;
; Sets modulus to p256, calls fp_mod_mul, copies fp_r0 to (fp_dst).
; Clobbers: A, X, Y
; =============================================================================
ec_mulp:
        jsr ec_set_modp
        jsr fp_mod_mul
        jmp ec_mulp_copy_result

; =============================================================================
; ec_sqrp - Modular square mod p, copy result to (fp_dst)
;
; Sets modulus to p256, calls fp_mod_sqr, copies fp_r0 to (fp_dst).
; fp_src1 is the operand; fp_src2 is ignored (no aliasing needed).
; Clobbers: A, X, Y
; =============================================================================
ec_sqrp:
        jsr ec_set_modp
        jsr fp_mod_sqr
        ; fall through to copy helper
ec_mulp_copy_result:
        ; Copy fp_r0 to (fp_dst)
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        jsr fp_copy
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        rts
