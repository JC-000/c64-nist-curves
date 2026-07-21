.setcpu "6502"

.segment "LIB_NISTCURVES_P256_CODE"

; Imports from zp_config
.importzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry

; Imports from fp256
.import fp_add, fp_sub, fp_cmp, fp_copy, fp_zero, fp_mul, fp_sqr
.import fp_is_zero, fp_rshift1

; Imports from data
.import fp_wide, fp_r0, fp_inv_u, fp_inv_v, fp_inv_x1, fp_inv_x2

; Exports
.export ec_p256, ec_n256
.export fp_mod_add, fp_mod_sub, fp_mod_reduce256
.export fp_mod_mul, fp_mod_mul_n, fp_mod_sqr, fp_mod_inv, fp_chk_one
.export ec_set_modp, ec_set_modn, ec_mulp, ec_sqrp

; =============================================================================
; P-256 prime and group order constants (little-endian)
; =============================================================================

.segment "LIB_NISTCURVES_P256_RODATA"

ec_p256:
        .byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF
        .byte $FF,$FF,$FF,$FF,$00,$00,$00,$00
        .byte $00,$00,$00,$00,$00,$00,$00,$00
        .byte $01,$00,$00,$00,$FF,$FF,$FF,$FF

ec_n256:
        .byte $51,$25,$63,$FC,$C2,$CA,$B9,$F3
        .byte $84,$9E,$17,$A7,$AD,$FA,$E6,$BC
        .byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF
        .byte $00,$00,$00,$00,$FF,$FF,$FF,$FF

.segment "LIB_NISTCURVES_P256_CODE"

; =============================================================================
; fp_mod_add - (fp_dst) = ((fp_src1) + (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_add:
        jsr fp_add
        lda fp_carry
        bne @reduce

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
        bcc @done

@reduce:
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
; =============================================================================
fp_mod_sub:
        jsr fp_sub
        lda fp_carry
        beq @done

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
; =============================================================================

; Macros for Solinas accumulator

.macro sol_add_byte off
        .local skip
        clc
        lda sol_sum_lo
        adc fp_wide + off
        sta sol_sum_lo
        bcc skip
        iny
skip:
.endmacro

.macro sol_add2_byte off
        .local noinc1, noinc2
        lda fp_wide + off
        asl
        bcc noinc1
        iny
noinc1:
        clc
        adc sol_sum_lo
        sta sol_sum_lo
        bcc noinc2
        iny
noinc2:
.endmacro

.macro sol_sub_byte off
        .local skip
        sec
        lda sol_sum_lo
        sbc fp_wide + off
        sta sol_sum_lo
        bcs skip
        dey
skip:
.endmacro

fp_mod_reduce256:
        lda #0
        sta sol_sum_lo
        tay
        ldx #0

sol_byte_loop:
        clc
        lda sol_sum_lo
        adc fp_wide,x
        sta sol_sum_lo
        bcc :+
        iny
:
        lda sol_jmp_tbl_lo,x
        sta sol_dispatch+1
        lda sol_jmp_tbl_hi,x
        sta sol_dispatch+2
sol_dispatch:
        jmp $0000
sol_after_contrib:
        lda sol_sum_lo
        sta fp_r0,x
        sty sol_sum_lo
        cpy #$80
        lda #0
        bcc :+
        lda #$ff
:
        tay
        inx
        cpx #32
        bcc sol_byte_loop

        lda sol_sum_lo
        sta sol_overflow
        sty sol_overflow+1

@reduce_loop:
        lda sol_overflow+1
        bmi @add_p

        ora sol_overflow
        bne @sub_p

        ldy #31
@cmp_loop:
        lda fp_r0,y
        cmp ec_p256,y
        bcc @reduction_done
        bne @sub_p
        dey
        bpl @cmp_loop

@sub_p:
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
        lda sol_overflow
        sbc #0
        sta sol_overflow
        lda sol_overflow+1
        sbc #0
        sta sol_overflow+1
        jmp @reduce_loop

@add_p:
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
        lda sol_overflow
        adc #0
        sta sol_overflow
        lda sol_overflow+1
        adc #0
        sta sol_overflow+1
        jmp @reduce_loop

@reduction_done:
        rts

; Jump tables for 32 byte positions
sol_jmp_tbl_lo:
        .byte <sol_b0,  <sol_b1,  <sol_b2,  <sol_b3
        .byte <sol_b4,  <sol_b5,  <sol_b6,  <sol_b7
        .byte <sol_b8,  <sol_b9,  <sol_b10, <sol_b11
        .byte <sol_b12, <sol_b13, <sol_b14, <sol_b15
        .byte <sol_b16, <sol_b17, <sol_b18, <sol_b19
        .byte <sol_b20, <sol_b21, <sol_b22, <sol_b23
        .byte <sol_b24, <sol_b25, <sol_b26, <sol_b27
        .byte <sol_b28, <sol_b29, <sol_b30, <sol_b31
sol_jmp_tbl_hi:
        .byte >sol_b0,  >sol_b1,  >sol_b2,  >sol_b3
        .byte >sol_b4,  >sol_b5,  >sol_b6,  >sol_b7
        .byte >sol_b8,  >sol_b9,  >sol_b10, >sol_b11
        .byte >sol_b12, >sol_b13, >sol_b14, >sol_b15
        .byte >sol_b16, >sol_b17, >sol_b18, >sol_b19
        .byte >sol_b20, >sol_b21, >sol_b22, >sol_b23
        .byte >sol_b24, >sol_b25, >sol_b26, >sol_b27
        .byte >sol_b28, >sol_b29, >sol_b30, >sol_b31

; Per-byte contribution routines

sol_b0:
        sol_add_byte 32
        sol_add_byte 36
        sol_sub_byte 44
        sol_sub_byte 48
        sol_sub_byte 52
        sol_sub_byte 56
        jmp sol_after_contrib

sol_b1:
        sol_add_byte 33
        sol_add_byte 37
        sol_sub_byte 45
        sol_sub_byte 49
        sol_sub_byte 53
        sol_sub_byte 57
        jmp sol_after_contrib

sol_b2:
        sol_add_byte 34
        sol_add_byte 38
        sol_sub_byte 46
        sol_sub_byte 50
        sol_sub_byte 54
        sol_sub_byte 58
        jmp sol_after_contrib

sol_b3:
        sol_add_byte 35
        sol_add_byte 39
        sol_sub_byte 47
        sol_sub_byte 51
        sol_sub_byte 55
        sol_sub_byte 59
        jmp sol_after_contrib

sol_b4:
        sol_add_byte 36
        sol_add_byte 40
        sol_sub_byte 48
        sol_sub_byte 52
        sol_sub_byte 56
        sol_sub_byte 60
        jmp sol_after_contrib

sol_b5:
        sol_add_byte 37
        sol_add_byte 41
        sol_sub_byte 49
        sol_sub_byte 53
        sol_sub_byte 57
        sol_sub_byte 61
        jmp sol_after_contrib

sol_b6:
        sol_add_byte 38
        sol_add_byte 42
        sol_sub_byte 50
        sol_sub_byte 54
        sol_sub_byte 58
        sol_sub_byte 62
        jmp sol_after_contrib

sol_b7:
        sol_add_byte 39
        sol_add_byte 43
        sol_sub_byte 51
        sol_sub_byte 55
        sol_sub_byte 59
        sol_sub_byte 63
        jmp sol_after_contrib

sol_b8:
        sol_add_byte 40
        sol_add_byte 44
        sol_sub_byte 52
        sol_sub_byte 56
        sol_sub_byte 60
        jmp sol_after_contrib

sol_b9:
        sol_add_byte 41
        sol_add_byte 45
        sol_sub_byte 53
        sol_sub_byte 57
        sol_sub_byte 61
        jmp sol_after_contrib

sol_b10:
        sol_add_byte 42
        sol_add_byte 46
        sol_sub_byte 54
        sol_sub_byte 58
        sol_sub_byte 62
        jmp sol_after_contrib

sol_b11:
        sol_add_byte 43
        sol_add_byte 47
        sol_sub_byte 55
        sol_sub_byte 59
        sol_sub_byte 63
        jmp sol_after_contrib

sol_b12:
        sol_add2_byte 44
        sol_add2_byte 48
        sol_add_byte 52
        sol_sub_byte 60
        sol_sub_byte 32
        sol_sub_byte 36
        jmp sol_after_contrib

sol_b13:
        sol_add2_byte 45
        sol_add2_byte 49
        sol_add_byte 53
        sol_sub_byte 61
        sol_sub_byte 33
        sol_sub_byte 37
        jmp sol_after_contrib

sol_b14:
        sol_add2_byte 46
        sol_add2_byte 50
        sol_add_byte 54
        sol_sub_byte 62
        sol_sub_byte 34
        sol_sub_byte 38
        jmp sol_after_contrib

sol_b15:
        sol_add2_byte 47
        sol_add2_byte 51
        sol_add_byte 55
        sol_sub_byte 63
        sol_sub_byte 35
        sol_sub_byte 39
        jmp sol_after_contrib

sol_b16:
        sol_add2_byte 48
        sol_add2_byte 52
        sol_add_byte 56
        sol_sub_byte 36
        sol_sub_byte 40
        jmp sol_after_contrib

sol_b17:
        sol_add2_byte 49
        sol_add2_byte 53
        sol_add_byte 57
        sol_sub_byte 37
        sol_sub_byte 41
        jmp sol_after_contrib

sol_b18:
        sol_add2_byte 50
        sol_add2_byte 54
        sol_add_byte 58
        sol_sub_byte 38
        sol_sub_byte 42
        jmp sol_after_contrib

sol_b19:
        sol_add2_byte 51
        sol_add2_byte 55
        sol_add_byte 59
        sol_sub_byte 39
        sol_sub_byte 43
        jmp sol_after_contrib

sol_b20:
        sol_add2_byte 52
        sol_add2_byte 56
        sol_add_byte 60
        sol_sub_byte 40
        sol_sub_byte 44
        jmp sol_after_contrib

sol_b21:
        sol_add2_byte 53
        sol_add2_byte 57
        sol_add_byte 61
        sol_sub_byte 41
        sol_sub_byte 45
        jmp sol_after_contrib

sol_b22:
        sol_add2_byte 54
        sol_add2_byte 58
        sol_add_byte 62
        sol_sub_byte 42
        sol_sub_byte 46
        jmp sol_after_contrib

sol_b23:
        sol_add2_byte 55
        sol_add2_byte 59
        sol_add_byte 63
        sol_sub_byte 43
        sol_sub_byte 47
        jmp sol_after_contrib

sol_b24:
        sol_add_byte 56
        sol_add_byte 56
        sol_add_byte 56
        sol_add2_byte 60
        sol_add_byte 52
        sol_sub_byte 32
        sol_sub_byte 36
        jmp sol_after_contrib

sol_b25:
        sol_add_byte 57
        sol_add_byte 57
        sol_add_byte 57
        sol_add2_byte 61
        sol_add_byte 53
        sol_sub_byte 33
        sol_sub_byte 37
        jmp sol_after_contrib

sol_b26:
        sol_add_byte 58
        sol_add_byte 58
        sol_add_byte 58
        sol_add2_byte 62
        sol_add_byte 54
        sol_sub_byte 34
        sol_sub_byte 38
        jmp sol_after_contrib

sol_b27:
        sol_add_byte 59
        sol_add_byte 59
        sol_add_byte 59
        sol_add2_byte 63
        sol_add_byte 55
        sol_sub_byte 35
        sol_sub_byte 39
        jmp sol_after_contrib

sol_b28:
        sol_add_byte 60
        sol_add_byte 60
        sol_add_byte 60
        sol_add_byte 32
        sol_sub_byte 40
        sol_sub_byte 44
        sol_sub_byte 48
        sol_sub_byte 52
        jmp sol_after_contrib

sol_b29:
        sol_add_byte 61
        sol_add_byte 61
        sol_add_byte 61
        sol_add_byte 33
        sol_sub_byte 41
        sol_sub_byte 45
        sol_sub_byte 49
        sol_sub_byte 53
        jmp sol_after_contrib

sol_b30:
        sol_add_byte 62
        sol_add_byte 62
        sol_add_byte 62
        sol_add_byte 34
        sol_sub_byte 42
        sol_sub_byte 46
        sol_sub_byte 50
        sol_sub_byte 54
        jmp sol_after_contrib

sol_b31:
        sol_add_byte 63
        sol_add_byte 63
        sol_add_byte 63
        sol_add_byte 35
        sol_sub_byte 43
        sol_sub_byte 47
        sol_sub_byte 51
        sol_sub_byte 55
        jmp sol_after_contrib

; Scratch variables for Solinas reduction
sol_acc_lo:      .byte 0
sol_acc_hi:      .byte 0
sol_sum_lo:      .byte 0
sol_sum_hi:      .byte 0
sol_byte_idx:    .byte 0
sol_overflow:    .word 0

; =============================================================================
; fp_mod_mul - fp_r0 = ((fp_src1) * (fp_src2)) mod p256
; =============================================================================
fp_mod_mul:
        jsr fp_mul
        jsr fp_mod_reduce256
        rts

; =============================================================================
; fp_mod_mul_n - (fp_dst) = ((fp_src1) * (fp_src2)) mod ec_n256
;
; Hardcoded to the P-256 group order n. Does NOT use fp_misc.
; Precondition: AT LEAST ONE operand in [0, n-1]; the other may be any
; full-width 256-bit value. Why that suffices: if either factor is < n
; then a*b < 2^256 * n, so the top half of the 512-bit product is
; strictly < n — exactly the initial-remainder invariant the bit-serial
; reduction loop below requires. The loop (256 iterations, top-down)
; then computes the true mod of the full product, so an unreduced
; operand still yields (a mod n)*(b mod n) mod n.
;
; RELYING CALLER: the ECDSA verify u1 = h*w step (ecdsa_verify_256,
; step 5) passes the UNREDUCED digest h — which can be >= n, and that
; region is adversarially reachable with ~2^32 hash grinding since
; n256's top 32 bits are all-1s — with w = s^-1 mod n, which is
; always < n. Do NOT "optimize" this routine on the assumption that
; BOTH operands are < n (e.g. by skipping early compare/subtract
; rounds); that would silently break the legitimate h >= n case.
; See issue #65.
;
; Contract:
;   input:  fp_src1, fp_src2, fp_dst set by caller; at least one of
;           a,b in [0,n-1] (the other may be any 256-bit value).
;   output: result at (fp_dst), 32 bytes LE.
;   clobbers: fp_wide (as scratch), A, X, Y.
; =============================================================================
fp_mod_mul_n:
        jsr fp_mul              ; fp_wide[0..63] = a * b

        ; Bit-serial reduction: treat fp_wide[32..63] as running remainder r.
        ; For i = 255 downto 0:
        ;   r = (r << 1) | bit_i(low half)   (via one 64-byte shift-left)
        ;   if r >= n (including carry-out): r -= n
        lda #0
        sta modn_carry
        sta modn_iter           ; iteration counter (wraps after 256)
@loop:
        ; Shift whole 64-byte fp_wide left by 1. Carry must propagate from
        ; byte N-1 into byte N via ROL, so no C-clobbering instruction (CPX,
        ; CMP, ADC, SBC) can appear between ROLs. DEC/INX/INY preserve C.
        clc
        ldx #0
        lda #64
        sta modn_cnt
@shl_loop:
        rol fp_wide,x
        inx
        dec modn_cnt
        bne @shl_loop
        rol modn_carry          ; capture spill from bit 511

        ; Decide: subtract n from r = fp_wide[32..63] ?
        lda modn_carry
        bne @do_sub             ; overflow past 2^256: definitely >= n

        ; Compare r to n (MSB-first, 32 bytes)
        ldy #31
@cmp_loop:
        lda fp_wide+32,y
        cmp ec_n256,y
        bcc @no_sub
        bne @do_sub
        dey
        bpl @cmp_loop
        ; r == n -> subtract
@do_sub:
        sec
        ldy #0
        ldx #32
@sub_loop:
        lda fp_wide+32,y
        sbc ec_n256,y
        sta fp_wide+32,y
        iny
        dex                     ; DEX preserves C so borrow propagates
        bne @sub_loop
        lda modn_carry
        sbc #0
        sta modn_carry
@no_sub:
        inc modn_iter
        bne @loop               ; wraps 0 -> 255 -> ... -> 0, i.e. 256 iters

        ; Copy r = fp_wide[32..63] to (fp_dst).
        ldy #31
@copy_loop:
        lda fp_wide+32,y
        sta (fp_dst),y
        dey
        bpl @copy_loop
        rts

modn_carry:     .byte 0
modn_iter:      .byte 0
modn_cnt:       .byte 0

; =============================================================================
; fp_mod_sqr - fp_r0 = ((fp_src1)^2) mod p256
; =============================================================================
fp_mod_sqr:
        jsr fp_sqr
        jsr fp_mod_reduce256
        rts

; =============================================================================
; fp_mod_inv - fp_r0 = (fp_src1)^(-1) mod (fp_misc)
; Binary extended GCD algorithm.
; =============================================================================
fp_mod_inv:
        lda fp_dst
        pha
        lda fp_dst+1
        pha

        lda #<fp_inv_u
        sta fp_dst
        lda #>fp_inv_u
        sta fp_dst+1
        jsr fp_copy

        lda fp_misc
        sta fp_src1
        lda fp_misc+1
        sta fp_src1+1
        lda #<fp_inv_v
        sta fp_dst
        lda #>fp_inv_v
        sta fp_dst+1
        jsr fp_copy

        lda #<fp_inv_x1
        sta fp_dst
        lda #>fp_inv_x1
        sta fp_dst+1
        jsr fp_zero
        lda #1
        sta fp_inv_x1

        lda #<fp_inv_x2
        sta fp_dst
        lda #>fp_inv_x2
        sta fp_dst+1
        jsr fp_zero

        pla
        sta fp_dst+1
        pla
        sta fp_dst

@mainlp:
        lda #<fp_inv_u
        sta fp_src1
        lda #>fp_inv_u
        sta fp_src1+1
        jsr fp_chk_one
        bne :+
        jmp @u_one
:
        lda #<fp_inv_v
        sta fp_src1
        lda #>fp_inv_v
        sta fp_src1+1
        jsr fp_chk_one
        bne :+
        jmp @v_one
:

@halfu:
        lda fp_inv_u
        and #1
        beq :+
        jmp @halfv
:

        clc
.repeat 32, i
        ror fp_inv_u + (31 - i)
.endrepeat

        lda fp_inv_x1
        and #1
        beq @x1ev_nocarry
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
        adc #0
        lsr
        jmp @x1do_shift
@x1ev_nocarry:
        clc
@x1do_shift:
.repeat 32, i
        ror fp_inv_x1 + (31 - i)
.endrepeat
        jmp @halfu

@halfv:
        lda fp_inv_v
        and #1
        beq :+
        jmp @comp
:

        clc
.repeat 32, i
        ror fp_inv_v + (31 - i)
.endrepeat

        lda fp_inv_x2
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
.repeat 32, i
        ror fp_inv_x2 + (31 - i)
.endrepeat
        jmp @halfv

@comp:
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

@u_one:
        ldy #31
@cu:
        lda fp_inv_x1,y
        sta fp_r0,y
        dey
        bpl @cu
        rts

@v_one:
        ldy #31
@cv:
        lda fp_inv_x2,y
        sta fp_r0,y
        dey
        bpl @cv
        rts

; =============================================================================
; fp_chk_one - Check if (fp_src1) == 1 in little-endian
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
        lda #0
        rts
@no:
        lda #$ff
        rts

; =============================================================================
; ec_set_modp - Set fp_misc to point to ec_p256
; =============================================================================
ec_set_modp:
        lda #<ec_p256
        sta fp_misc
        lda #>ec_p256
        sta fp_misc+1
        rts

; =============================================================================
; ec_set_modn - Set fp_misc to point to ec_n256
; =============================================================================
ec_set_modn:
        lda #<ec_n256
        sta fp_misc
        lda #>ec_n256
        sta fp_misc+1
        rts

; =============================================================================
; ec_mulp / ec_sqrp - Modular multiply / square mod p, copy result to (fp_dst)
; =============================================================================
ec_mulp:
        jsr ec_set_modp
        jsr fp_mod_mul
        jmp mulp_copy_result

ec_sqrp:
        jsr ec_set_modp
        jsr fp_mod_sqr

mulp_copy_result:
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
