.setcpu "6502"

; =============================================================================
; main.s - NIST P-256/P-384 elliptic curve optimization harness
;
; Memory layout:
;   $0801-$08FF: BASIC stub + boot
;   $0900+:      code (mul_8x8, fp256, mod256, curve256, points256)
;   $9C00-$9FFF: sqtab (quarter-square multiply tables; SPEC §8.1 equate,
;                LIB_SHARED_SQTAB_BASE -- not a linker segment, see the
;                collision guard below)
; =============================================================================

; --- ZP imports ---
.importzp zp_ptr1, fp_misc

; proc_port ($01, 6510 CPU I/O port) is hardware-fixed and used only by
; this test/bench driver for ROM banking around REU access (never by the
; library itself, issue #90) -- defined locally rather than imported from
; zp_config.s so the library no longer claims/exports it in any archive.
; Codegen is identical either way: `lda proc_port` / `sta proc_port`
; assemble to the same zero-page opcodes whether the symbol resolves via
; import or local equate, so the PRG stays byte-identical.
.ifndef proc_port
  proc_port = $01
.endif

; --- Constants imports ---
.import chrout, screen_ram, vic_ctrl1
.importzp jiffy_clock

; --- mul_8x8 imports ---
.import sqtab_init

; --- sqtab / image-extent collision guard (SPEC §4 placement) ---
; sqtab_lo / sqtab_hi are an absolute equate (LIB_SHARED_SQTAB_BASE), not a
; segment, so ld65 has no idea the 1 KB at $9C00..$9FFF is spoken for and
; will place a segment straight over it with no overlap diagnostic. The
; failure is silent at link time and shows up as a corrupted quarter-square
; table and a boot that never reaches the $02A7 sentinel -- which is exactly
; what happened on 2026-05-17 at the previous $7800 base.
;
; __MAIN_LAST__ comes from `define = yes` on the MAIN memory area in
; src/c64.cfg and is the first address past the last byte actually placed
; (verified: $9A67 against an area that runs to $CFFF, so it tracks placed
; content, not the area size). `lderror` defers evaluation to link time,
; when that extent is finally known.
;
; This guard lives in main.s deliberately. main.o is the standalone
; test/bench driver and is NOT part of any consumer archive (API.md §8.2),
; so importing a cfg-provided symbol here cannot impose `define = yes` --
; or an unresolved external -- on a consumer linking nistcurves*.a against
; their own cfg. It guards this library's own PRG, which is the image that
; has actually collided before. Consumers get the declaration in c64.cfg's
; MEMORY{} block instead; there is no way to assert against a memory map
; we do not author.
;
; Comparing against imported `sqtab_lo` rather than re-deriving the base
; means a `-D LIB_SHARED_SQTAB_BASE=...` override is tracked automatically.
;
; DO NOT make either .import below conditional, weak, or optional. An
; `.assert ..., lderror` whose operands cannot be resolved does NOT fail --
; ld65 downgrades it to `Warning: Cannot evaluate assertion in module
; 'src/main.s', line N` and links anyway, so the guard would silently stop
; guarding while still looking present in the source. What actually stops
; the build today is the unresolved external itself:
;   ld65: Error: 1 unresolved external(s) found - cannot create output file
; i.e. this guard is load-bearing only because `__MAIN_LAST__` is a hard
; import against `define = yes` on MAIN in src/c64.cfg. Remove that cfg
; attribute and the link fails loudly (verified, exit 1, no output file);
; make the import optional instead and the collision goes back to silent.
.import sqtab_lo
.import __MAIN_LAST__
.assert __MAIN_LAST__ <= sqtab_lo, lderror, "image overruns sqtab window (LIB_SHARED_SQTAB_BASE): raise the base or shrink the image -- see src/c64.cfg MEMORY{}"

; --- SPEC §8.2 reu_mul provider (src/reu_mul_init.s; moved out of this
; --- file by issue #81 so the default-profile archives ship it) ---
.import reu_mul_init

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

; --- J+J point-add + mod-n multiply imports (for bench trampolines) ---
.import ec_point_add_jj, ec_point_add_jj_384
.import fp_mod_mul_n, fp_mod_mul_n_384

.segment "LOADADDR"
        .word $0801              ; CBM PRG load address

.segment "LIB_NISTCURVES_MAIN_CODE"

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
; REU multiplication table init (`reu_mul_init` / `reu_mul_tables_init`)
; moved to src/reu_mul_init.s (issue #81): the SPEC §8.2 provider must ship
; in the default-profile consumer archives, and main.s is the never-archived
; test/bench driver. The boot sequence above still calls it via .import.
; =============================================================================

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

; ecdsa_verify_with_msg_384_tramp -- moved here from src/ecdsa384_msg.s
; (issue #63) so the shipping wrapper object stops importing the
; test-driver buffers and links from consumer archives. The Python driver
; pre-pokes ecdsa_inputs_384 (240 B BE struct; h slot may be zero -- the
; wrapper overwrites it), sha384_msg_buf with the message bytes, and ZP
; sha_src / sha_len; result byte mirrors ecdsa_result_384's encoding.
.export ecdsa_verify_with_msg_384_tramp
ecdsa_verify_with_msg_384_tramp:
        lda #<ecdsa_inputs_384
        ldx #>ecdsa_inputs_384
        jsr ecdsa_verify_with_message_384
        lda #0
        rol a                     ; shift C into bit 0
        sta ecdsa_result_msg_384
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

; bench-marker-wrapped trampolines for the full Jacobian + Jacobian point-add
; primitive (Bernstein-Lange add-2007-bl) and the mod-n multiply primitive.
; Both are load-bearing for ECDSA verify (J+J at the u1*G+u2*Q join; mod-n
; mul for u1=h*w / u2=r*w) but were previously absent from the primitive
; bench surface — PR #26 + PR #34's measured-vs-predicted gap motivated
; making them measurable. Caller pre-stages ec_p1/ec_p2 (J+J) or
; fp_src1/fp_src2/fp_dst (mod-n mul); ec_set_modn is NOT needed since
; fp_mod_mul_n hardcodes the curve order pointer at the source-text level.
;
; Marker tokens:
;   $8A / $8B   ec_point_add_jj (P-256)
;   $8C / $8D   ec_point_add_jj_384 (P-384)
;   $8E / $8F   fp_mod_mul_n (P-256)
;   $90 / $91   fp_mod_mul_n_384 (P-384)
.export bench_ec_point_add_jj_tramp
bench_ec_point_add_jj_tramp:
        lda #$8a
        sta BENCH_DBG_MARK
        jsr ec_point_add_jj
        lda #$8b
        sta BENCH_DBG_MARK
        rts

.export bench_ec_point_add_jj_384_tramp
bench_ec_point_add_jj_384_tramp:
        lda #$8c
        sta BENCH_DBG_MARK
        jsr ec_point_add_jj_384
        lda #$8d
        sta BENCH_DBG_MARK
        rts

.export bench_fp_mod_mul_n_tramp
bench_fp_mod_mul_n_tramp:
        lda #$8e
        sta BENCH_DBG_MARK
        jsr fp_mod_mul_n
        lda #$8f
        sta BENCH_DBG_MARK
        rts

.export bench_fp_mod_mul_n_384_tramp
bench_fp_mod_mul_n_384_tramp:
        lda #$90
        sta BENCH_DBG_MARK
        jsr fp_mod_mul_n_384
        lda #$91
        sta BENCH_DBG_MARK
        rts

; =============================================================================
; Strings
; =============================================================================
.segment "LIB_NISTCURVES_MAIN_RODATA"

title_msg:
        .byte 147              ; clear screen (PETSCII)
        .byte "NIST P-256/P-384 OPT"
        .byte 13, 0

ready_msg:
        .byte "READY."
        .byte 13, 0
