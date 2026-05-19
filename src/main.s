.setcpu "6502"

; =============================================================================
; main.s - NIST P-256/P-384 elliptic curve optimization harness
;
; Memory layout:
;   $0801-$08FF: BASIC stub + boot
;   $0900+:      code (mul_8x8, fp256, mod256, curve256, points256)
;   $7800-$7BFF: sqtab (quarter-square multiply tables)
; =============================================================================

; --- ZP imports ---
.importzp proc_port, zp_ptr1, fp_misc

; --- Constants imports ---
.import chrout, screen_ram, vic_ctrl1
.importzp jiffy_clock
.import reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi
.import reu_reu_bank, reu_len_lo, reu_len_hi
.import reu_addr_ctrl, reu_command

; --- mul_8x8 imports ---
.import sqtab_init, mul_8x8, poly_prod_lo, poly_prod_hi

; --- data imports ---
.import mul_dma_lo, mul_dma_hi, mul_cached_a

; --- points imports ---
.import ec_precompute_256
.import ec_precompute_384

; --- ecdsa imports (for test trampolines) ---
.import ecdsa_verify_256, ecdsa_verify_384
.import ecdsa_verify_with_message_384
.import ecdsa_inputs_256, ecdsa_inputs_384
.import ecdsa_result_256, ecdsa_result_384, ecdsa_result_msg_384

; --- variable-base scalar-mul imports (for U64E bench trampolines) ---
.import ec_scalar_mul_var, ec_scalar_mul_var_384

.segment "LOADADDR"
        .word $0801              ; CBM PRG load address

.segment "CODE"

; BASIC stub: 10 SYS 2064
basic_stub:
        .word basic_end         ; pointer to next BASIC line
        .word 10                ; line number 10
        .byte $9e               ; SYS token
        .byte "2064"            ; decimal address (must match start label)
        .byte 0                 ; end of line
basic_end:
        .word 0                 ; end of BASIC program

; =============================================================================
; Program entry point
; =============================================================================
start:
        ; bank out BASIC ROM to use $A000-$BFFF as RAM
        lda proc_port
        and #$fe                ; clear bit 0 (LORAM) - bank out BASIC ROM
        sta proc_port

        ; clear screen
        jsr clrscr

        ; display title
        lda #<title_msg
        ldy #>title_msg
        jsr print_string

        ; Initialize quarter-square table
        jsr sqtab_init

        ; Initialize REU multiplication tables
        jsr reu_mul_init

        ; Precompute windowed scalar multiplication tables into REU bank 2
        jsr ec_precompute_256
        jsr ec_precompute_384

        ; display ready message
        lda #<ready_msg
        ldy #>ready_msg
        jsr print_string

        ; Signal test harness that initialization is complete
        lda #$42
        sta $02A7           ; sentinel location (unused area of C64 memory)

        ; Main idle loop - wait for test harness commands
.export main_loop
main_loop:
        jmp main_loop

; =============================================================================
; clrscr - Clear screen
; =============================================================================
.export clrscr
clrscr:
        lda #$20               ; space character
        ldx #0
@loop:
        sta screen_ram,x
        sta screen_ram+$100,x
        sta screen_ram+$200,x
        sta screen_ram+$2e8,x
        inx
        bne @loop
        rts

; =============================================================================
; print_string - Print null-terminated string
; Input: A=low byte, Y=high byte of string address
; =============================================================================
.export print_string
print_string:
        sta zp_ptr1
        sty zp_ptr1+1
        ldy #0
@loop:
        lda (zp_ptr1),y
        beq @done
        jsr chrout
        iny
        bne @loop
@done:
        rts

; =============================================================================
; print_hex_byte - Print A as two hex digits
; =============================================================================
.export print_hex_byte
print_hex_byte:
        pha
        lsr
        lsr
        lsr
        lsr
        jsr print_hex_digit
        pla
        and #$0f
        jsr print_hex_digit
        rts

print_hex_digit:
        cmp #10
        bcs @letter
        clc
        adc #'0'
        jmp chrout
@letter:
        clc
        adc #'A'-10
        jmp chrout

; =============================================================================
; Benchmark timer routines
; =============================================================================

; bench_start - Reset jiffy clock and start timing
.export bench_start
bench_start:
        sei
        lda #0
        sta jiffy_clock
        sta jiffy_clock+1
        sta jiffy_clock+2
        cli
        rts

; bench_stop - Read jiffy clock into bench_ticks (3 bytes)
.export bench_stop
bench_stop:
        sei
        lda jiffy_clock
        sta bench_ticks
        lda jiffy_clock+1
        sta bench_ticks+1
        lda jiffy_clock+2
        sta bench_ticks+2
        cli
        rts

.export bench_ticks
bench_ticks:    .res 3, 0

; =============================================================================
; VIC-II screen blanking for maximum CPU throughput
; Blanking eliminates ~40 stolen cycles/rasterline from VIC-II DMA
; =============================================================================

; vic_blank - Disable VIC-II display (DEN=0) for ~20-25% CPU speedup
.export vic_blank
vic_blank:
        lda vic_ctrl1
        and #$ef               ; clear bit 4 (DEN - Display Enable)
        sta vic_ctrl1
        rts

; vic_unblank - Re-enable VIC-II display (DEN=1)
.export vic_unblank
vic_unblank:
        lda vic_ctrl1
        ora #$10               ; set bit 4
        sta vic_ctrl1
        rts

; =============================================================================
; REU multiplication table routines
; =============================================================================

; =============================================================================
; reu_mul_init - Generate 256 full multiplication rows and stash in REU
;
; For each a = 0..255, computes a*b for b = 0..255 and stashes:
;   256 lo bytes at REU offset a*512
;   256 hi bytes at REU offset a*512+256
;
; Uses mul_dma_lo/mul_dma_hi as staging buffers.
; Uses mul_8x8 (requires sqtab to be initialized first).
; Clobbers: A, X, Y
; =============================================================================
.export reu_mul_init
reu_mul_init:
        lda #0
        sta reu_init_a         ; outer counter (multiplier a)

@outer:
        ; For current a, compute a*b for all b=0..255
        lda #0
        sta reu_init_b         ; inner counter (multiplicand b)

@inner:
        lda reu_init_a
        ldx reu_init_b
        jsr mul_8x8            ; poly_prod_lo/hi = a * b

        ldx reu_init_b
        lda poly_prod_lo
        sta mul_dma_lo,x
        lda poly_prod_hi
        sta mul_dma_hi,x

        inc reu_init_b
        bne @inner             ; loop b = 0..255

        ; Stash lo table (256 bytes) to REU at offset a*512
        lda #<mul_dma_lo
        sta reu_c64_lo
        lda #>mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo         ; REU offset low = 0
        lda reu_init_a
        asl                    ; A = a * 2 (high byte of offset)
        sta reu_reu_hi
        lda #0
        adc #0                 ; carry into bank if a >= 128
        sta reu_reu_bank
        lda #0
        sta reu_len_lo
        lda #1
        sta reu_len_hi         ; length = 256
        lda #0
        sta reu_addr_ctrl      ; both addresses increment
        lda #%10110000         ; execute + autoload + STASH (C64->REU)
        sta reu_command

        ; Stash hi table (256 bytes) to REU at offset a*512+256
        lda #<mul_dma_hi
        sta reu_c64_lo
        lda #>mul_dma_hi
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        lda reu_init_a
        asl                    ; a*2 (carry = bit 7 of a)
        lda #0
        adc #0                 ; bank = a >> 7
        sta reu_reu_bank
        lda reu_init_a
        asl                    ; a*2
        ora #1                 ; +1 for hi page (a*2 is even, so OR works)
        sta reu_reu_hi
        lda #0
        sta reu_len_lo
        lda #1
        sta reu_len_hi         ; length = 256
        lda #0
        sta reu_addr_ctrl
        lda #%10110000         ; execute + autoload + STASH
        sta reu_command

        inc reu_init_a
        beq @init_done         ; if wrapped to 0, done
        jmp @outer
@init_done:
        ; Pre-configure constant REU registers for fetch routine
        lda #<mul_dma_lo
        sta reu_c64_lo
        lda #>mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        sta reu_len_lo
        sta reu_addr_ctrl
        lda #2
        sta reu_len_hi         ; length high = 2 (512 bytes)
        rts

reu_init_a:     .byte 0
reu_init_b:     .byte 0

; =============================================================================
; ECDSA verify test trampolines
;
; The c64-test-harness jsr() helper cannot pass register arguments to a
; subroutine, so we stage the 160-/240-byte ECDSA verify input struct at
; a fixed BSS address (ecdsa_inputs_256 / ecdsa_inputs_384 -- defined in
; data.s) and invoke verify via a trampoline that loads A/X with the
; struct pointer. The trampoline captures the C flag returned by the
; verify routine and stores 0 (valid) or 1 (invalid) into a result byte
; the harness can peek. This keeps the Python driver completely symbolic.
; =============================================================================
.export ecdsa_verify_256_tramp
ecdsa_verify_256_tramp:
        lda #<ecdsa_inputs_256
        ldx #>ecdsa_inputs_256
        jsr ecdsa_verify_256
        lda #0
        rol a                  ; shift C into bit 0 -> A = 0 if C=0, 1 if C=1
        sta ecdsa_result_256
        rts

.export ecdsa_verify_384_tramp
ecdsa_verify_384_tramp:
        lda #<ecdsa_inputs_384
        ldx #>ecdsa_inputs_384
        jsr ecdsa_verify_384
        lda #0
        rol a
        sta ecdsa_result_384
        rts

; =============================================================================
; U64E bench-only trampolines
;
; These wrappers emit a marker byte at $BFFF immediately before and after
; the measured routine.  The U64E debug stream (cycle-accurate bus trace
; on UDP:11002) captures every bus cycle; a Python-side filter keyed on
; "CPU write to $BFFF" pulls the markers out and measures the cycle delta
; between the start and stop tokens.  Marker writes are 4 cycles each,
; negligible against the multi-million-cycle targets (scalar_mul_var and
; ecdsa_verify).  No effect on the shipping PRG because nothing else
; calls these wrappers.
;
; Marker tokens:
;   $80 / $81   ecdsa_verify_256 (start / stop)
;   $82 / $83   ec_scalar_mul_var (P-256, start / stop)
;   $84 / $85   ec_scalar_mul_var_384 (start / stop)
;   $86 / $87   ecdsa_verify_384 (start / stop)
; =============================================================================

BENCH_DBG_MARK = $bfff

.export bench_ecdsa_verify_256_tramp
bench_ecdsa_verify_256_tramp:
        lda #$80
        sta BENCH_DBG_MARK
        lda #<ecdsa_inputs_256
        ldx #>ecdsa_inputs_256
        jsr ecdsa_verify_256
        lda #0
        rol a
        sta ecdsa_result_256
        lda #$81
        sta BENCH_DBG_MARK
        rts

.export bench_ecdsa_verify_384_tramp
bench_ecdsa_verify_384_tramp:
        lda #$86
        sta BENCH_DBG_MARK
        lda #<ecdsa_inputs_384
        ldx #>ecdsa_inputs_384
        jsr ecdsa_verify_384
        lda #0
        rol a
        sta ecdsa_result_384
        lda #$87
        sta BENCH_DBG_MARK
        rts

.export bench_ec_scalar_mul_var_256_tramp
bench_ec_scalar_mul_var_256_tramp:
        lda #$82
        sta BENCH_DBG_MARK
        jsr ec_scalar_mul_var
        lda #$83
        sta BENCH_DBG_MARK
        rts

.export bench_ec_scalar_mul_var_384_tramp
bench_ec_scalar_mul_var_384_tramp:
        lda #$84
        sta BENCH_DBG_MARK
        jsr ec_scalar_mul_var_384
        lda #$85
        sta BENCH_DBG_MARK
        rts

; bench-marker-wrapped trampoline for the one-shot ecdsa_verify_with_message_384
; wrapper. Caller must pre-stage sha_src/sha_len (ZP) at the message and poke
; the message bytes into sha384_msg_buf; the 240 B verify struct at
; ecdsa_inputs_384 may leave the h slot zero (the wrapper overwrites it with
; the computed SHA-384 digest before tail-calling ecdsa_verify_384). Marker
; tokens $88/$89.
.export bench_ecdsa_verify_with_msg_384_tramp
bench_ecdsa_verify_with_msg_384_tramp:
        lda #$88
        sta BENCH_DBG_MARK
        lda #<ecdsa_inputs_384
        ldx #>ecdsa_inputs_384
        jsr ecdsa_verify_with_message_384
        lda #0
        rol a
        sta ecdsa_result_msg_384
        lda #$89
        sta BENCH_DBG_MARK
        rts

; =============================================================================
; Strings
; =============================================================================
.segment "RODATA"

title_msg:
        .byte 147              ; clear screen (PETSCII)
        .byte "NIST P-256/P-384 OPT"
        .byte 13, 0

ready_msg:
        .byte "READY."
        .byte 13, 0
