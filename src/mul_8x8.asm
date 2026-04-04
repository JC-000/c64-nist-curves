; =============================================================================
; mul_8x8.asm - Quarter-square 8x8->16 multiply + table init
;
; Quarter-square table: sqtab_lo/hi at $7800-$7BFF (1024 bytes)
; Identity: a*b = floor((a+b)^2/4) - floor((a-b)^2/4)
; =============================================================================

; Quarter-square table addresses (page-aligned for speed)
sqtab_lo        = $7800         ; 512 bytes: low bytes of floor(n^2/4)
sqtab_hi        = $7a00         ; 512 bytes: high bytes of floor(n^2/4)

; =============================================================================
; sqtab_init - Build quarter-square lookup table at $7800-$7BFF
;
; Computes floor(i^2/4) for i = 0..511 using recurrence i^2 = (i-1)^2 + 2i - 1
;
; Clobbers: A, X, Y
; =============================================================================
sqtab_init:
        lda #0
        sta sq_acc              ; accumulator = 0
        sta sq_acc+1
        sta sq_acc+2
        sta sq_i                ; index = 0
        sta sq_i+1

@loop:
        ; Compute f(i) = sq_acc >> 2 (divide by 4)
        lda sq_acc+2
        lsr
        sta sq_sh+2
        lda sq_acc+1
        ror
        sta sq_sh+1
        lda sq_acc
        ror
        sta sq_sh
        lsr sq_sh+2
        ror sq_sh+1
        ror sq_sh

        ; Store in table at index sq_i (0..511)
        ldx sq_i                ; low byte of index
        lda sq_i+1
        beq @pg0
        ; Page 1 (256..511)
        lda sq_sh
        sta sqtab_lo+256,x
        lda sq_sh+1
        sta sqtab_hi+256,x
        jmp @advance
@pg0:
        lda sq_sh
        sta sqtab_lo,x
        lda sq_sh+1
        sta sqtab_hi,x

@advance:
        ; sq_acc += 2*i + 1 (recurrence: (i+1)^2 = i^2 + 2i + 1)
        lda sq_i
        asl
        sta sq_ad
        lda sq_i+1
        rol
        sta sq_ad+1
        inc sq_ad
        bne +
        inc sq_ad+1
+
        clc
        lda sq_acc
        adc sq_ad
        sta sq_acc
        lda sq_acc+1
        adc sq_ad+1
        sta sq_acc+1
        lda sq_acc+2
        adc #0
        sta sq_acc+2

        inc sq_i
        bne +
        inc sq_i+1
+       lda sq_i+1
        cmp #2                  ; check if i reached 512 (0x200)
        beq @done
        jmp @loop
@done:  rts

; Temporaries for sqtab_init
sq_acc: !fill 3, 0              ; 24-bit accumulator for i^2
sq_sh:  !fill 3, 0              ; 24-bit shifted result (i^2 / 4)
sq_ad:  !fill 2, 0              ; 16-bit addition term (2i+1)
sq_i:   !fill 2, 0              ; 16-bit index counter (0..511)

; =============================================================================
; mul_8x8 - 8-bit x 8-bit -> 16-bit multiply using quarter-square table
;
; Input: A = multiplicand, X = multiplier
; Output: poly_prod_lo/hi = A * X (16-bit result)
;
; Uses identity: a*b = sqtab[a+b] - sqtab[|a-b|]
; Clobbers: A, X, Y
; =============================================================================
poly_prod_lo:   !byte 0
poly_prod_hi:   !byte 0

mul_8x8:
        sta mul_a               ; save A
        stx mul_b               ; save X

        ; Compute sum = a + b
        clc
        adc mul_b               ; A = a + b (low byte)
        tax                     ; X = sum low byte
        lda #0
        adc #0                  ; carry -> sum page (0 or 1)
        sta mul_s_pg            ; sum page

        ; Compute |a - b|
        lda mul_a
        sec
        sbc mul_b
        bcs +
        eor #$ff
        adc #1                  ; negate (carry was clear, so ADC adds 1)
+       tay                     ; Y = |a-b| (always page 0, <=255)

        ; sqtab[sum] - sqtab[|diff|]
        lda mul_s_pg
        beq @s0
        ; sum is in page 1 (256..510)
        lda sqtab_lo+256,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi+256,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts
@s0:
        ; sum is in page 0 (0..255)
        lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts

mul_a:          !byte 0
mul_b:          !byte 0
mul_s_pg:       !byte 0
