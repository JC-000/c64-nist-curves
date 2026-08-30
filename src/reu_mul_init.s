.setcpu "6502"

; =============================================================================
; reu_mul_init.s - SPEC §8.2 reu_mul provider (128 KB REU multiply table init)
;
; Moved out of main.s by issue #81 so the provider ships in the default-
; profile consumer archives (nistcurves.a and the REU-consuming verify /
; curve archives via LIB_MUL_OBJS). main.s is the never-archived test/bench
; driver: while the provider lived there, API.md §3 made `jsr reu_mul_init`
; mandatory yet no archive contained the symbol, and the §8.0 ownership bit
; $0002 claimed by lib_manifest.s was untruthful for every archive.
; Precedent: the issue #18 move of `reu_fetch_mul_row` from main.s into
; mul_8x8.s, for the same class of problem. A separate object (rather than
; mul_8x8.s) keeps the FP_ONCHIP_MUL archives clean without an .ifndef gate
; inside a twice-assembled file: the Makefile simply omits reu_mul_init.o
; from LIB_MUL_ONCHIP_OBJS (the onchip profile never builds or reads the
; REU multiply table; verify-onchip archives contain zero REU DMA code,
; API.md §8.4.2).
; =============================================================================

; The imports live inside the SHARED_REU_MUL_INIT gate below (alongside
; the body) so a deferred build emits an empty object with no dangling
; import records.

; =============================================================================
; reu_mul_init - Generate 256 full multiplication rows and stash in REU
;
; For each a = 0..255, computes a*b for b = 0..255 and stashes:
;   256 lo bytes at REU offset a*512
;   256 hi bytes at REU offset a*512+256
;
; Uses nistcurves_mul_dma_lo/nistcurves_mul_dma_hi as staging buffers.
; Uses mul_8x8 (requires sqtab to be initialized first).
; Clobbers: A, X, Y
;
; SPEC §8.2 migration gate: when a consumer defines SHARED_REU_MUL_INIT,
;   this body is gated out so the consumer's canonical
;   `reu_mul_tables_init` from a shared-primitives module owns the
;   128 KB init. "Safe to call twice" per SPEC §8.2 -- a second call
;   produces the same final REU state, NOT a no-op (the full ~3 s of
;   work runs again). The body is purely write-only against REU + a
;   small bounded scratch (reu_init_a/b), and bottoms out in `mul_8x8`
;   which is itself idempotent on the same (a, b) pair; no side effects
;   beyond the table bytes.
;
;   `reu_mul_tables_init` (below) is the canonical SPEC §8.2 entry
;   point and aliases this body in the standalone (un-gated) build.
;   It resolves to whatever owns the init at link time: this body in
;   standalone, or the consumer's shared-primitives implementation
;   when SHARED_REU_MUL_INIT is defined.
; =============================================================================
.ifndef SHARED_REU_MUL_INIT

; --- Constants imports ---
.import reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi
.import reu_reu_bank, reu_len_lo, reu_len_hi
.import reu_addr_ctrl, reu_command

; --- REU layout contract (SPEC §3) ---
; SPEC §3/§6.2 consumer override (issue #143). CONTRACT_DEFINES reaches
; EVERY TU, so under `-D LIB_NISTCURVES_REU_BANK_MUL=<v>` ca65 defines the symbol here too and an
; unconditional `.import` of the same name is "Symbol ... is already defined"
; -- i.e. the documented override does not assemble at all. Guarding makes
; both arms work: no override -> import reu_config.s's exported default;
; override -> use the -D value, which is the same value reu_config.s exports,
; because the one -D reaches both TUs. Same shape as src/sqtab_base.inc's
; "included, not imported" note.
.ifndef LIB_NISTCURVES_REU_BANK_MUL
.import LIB_NISTCURVES_REU_BANK_MUL
.endif

; --- SPEC v0.13.0 §8.2 DMA completion confirm (issue #130) ---
.import nistcurves_reu_dma_wait

; --- mul_8x8 imports ---
.import mul_8x8, poly_prod_lo, poly_prod_hi
.import smc_sum_a_imm, smc_diff_a_imm

; --- data imports ---
.import nistcurves_mul_dma_lo, nistcurves_mul_dma_hi

.segment "LIB_NISTCURVES_MUL_CODE"

.export reu_mul_init
; SPEC §8.2 canonical entry: alias resolves to the library's body in
; standalone builds. Under the migration switch, the consumer provides
; the canonical name from its shared-primitives module instead.
.export reu_mul_tables_init
reu_mul_tables_init = reu_mul_init
reu_mul_init:
        lda #0
        sta reu_init_a         ; outer counter (multiplier a)

@outer:
        ; SMC-bake `a` into ct_mul_8x8's two immediate slots once per
        ; outer-a iteration (the canonical chacha SMC-baked convention,
        ; §8.3). The inner b-loop then just varies Y = b across 256 calls.
        lda reu_init_a
        sta smc_sum_a_imm+1
        sta smc_diff_a_imm+1

        ; For current a, compute a*b for all b=0..255
        lda #0
        sta reu_init_b         ; inner counter (multiplicand b)

@inner:
        ldy reu_init_b         ; Y = b (ct_mul_8x8 operand)
        jsr mul_8x8            ; poly_prod_lo/hi = a * b

        ldx reu_init_b
        lda poly_prod_lo
        sta nistcurves_mul_dma_lo,x
        lda poly_prod_hi
        sta nistcurves_mul_dma_hi,x

        inc reu_init_b
        bne @inner             ; loop b = 0..255

        ; Stash lo table (256 bytes) to REU at offset a*512
        lda #<nistcurves_mul_dma_lo
        sta reu_c64_lo
        lda #>nistcurves_mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo         ; REU offset low = 0
        lda reu_init_a
        asl                    ; A = a * 2 (high byte of offset)
        sta reu_reu_hi
        lda #<LIB_NISTCURVES_REU_BANK_MUL
        adc #0                 ; bank = MUL_BASE + carry (a >= 128 carries +1)
        sta reu_reu_bank
        lda #0
        sta reu_len_lo
        lda #1
        sta reu_len_hi         ; length = 256
        lda #0
        sta reu_addr_ctrl      ; both addresses increment
        lda #%10110000         ; execute + autoload + STASH (C64->REU)
        sta reu_command
        jsr nistcurves_reu_dma_wait ; SPEC v0.13.0 §8.2 (a)+(b): next stash follows at once

        ; Stash hi table (256 bytes) to REU at offset a*512+256
        lda #<nistcurves_mul_dma_hi
        sta reu_c64_lo
        lda #>nistcurves_mul_dma_hi
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        lda reu_init_a
        asl                    ; a*2 (carry = bit 7 of a)
        lda #<LIB_NISTCURVES_REU_BANK_MUL
        adc #0                 ; bank = MUL_BASE + (a >> 7)
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
        jsr nistcurves_reu_dma_wait ; SPEC v0.13.0 §8.2 (a)+(b): @outer re-stashes immediately

        inc reu_init_a
        beq @init_done         ; if wrapped to 0, done
        jmp @outer
@init_done:
        ; Pre-configure constant REU registers for fetch routine
        lda #<nistcurves_mul_dma_lo
        sta reu_c64_lo
        lda #>nistcurves_mul_dma_lo
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
.endif  ; .ifndef SHARED_REU_MUL_INIT
